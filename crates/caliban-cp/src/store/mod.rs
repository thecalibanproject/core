//! Control-plane state.
//!
//! Two backends behind one [`Backend`] trait, with identical behaviour (see `tests.rs`, which runs
//! the same suite against both):
//! - [`memory::MemoryBackend`] (no `CALIBAN_DATABASE_URL`): seeded from the config file at every
//!   start; changes are lost on restart. For dev/demo.
//! - [`postgres::PgBackend`] (`CALIBAN_DATABASE_URL`): schema from `migrations/`, applied at
//!   startup. The config file seeds the database **once** (first start, empty database); after
//!   that the database is the source of truth for tenants, API keys, BYOK credentials, shared
//!   providers, models, routes, datasources, nodes and ontology. Every other section (`[server]`,
//!   `[security]`, `[cache]`, `[pii]`, `[limits]`, …) always comes from the file.
//!
//! Every mutation is one [`Mutation`] applied atomically by the backend (one Postgres
//! transaction): apply → render the data-plane config → validate → append a hash-chained audit
//! row → commit. An invalid result (e.g. deleting a model a route still uses) rolls back and
//! nothing is written. The store keeps the committed [`State`] as a read cache and republishes the
//! data-plane `Snapshot` from it.
//!
//! Deletes are soft where the row matters for audit: a revoked API key keeps its row
//! (`revoked_at`), a deleted tenant is a tombstone (`status = deleted`, its id is never reused),
//! and deleted datasources and nodes keep their rows (`deleted_at`). Tombstones stay in [`State`]
//! so both backends agree on them, but they are never rendered into the data-plane snapshot and
//! the API treats them as not found. Secrets are the exception: a deleted tenant's BYOK
//! credentials and its data key (DEK) are removed outright, and a deleted datasource's
//! `connection` is wiped.
//!
//! Tenant secrets (BYOK keys, datasource credentials) are sealed under the tenant's DEK, which is
//! stored wrapped by a KEK ([`State::deks`]); see [`crate::keys`] for the hierarchy, the startup
//! migration and KEK rotation.
//!
//! Identity (see [`crate::auth`]): users (created just in time from the identity provider) and
//! role bindings are part of [`State`] and change through audited mutations like everything else.
//! Sessions and pending logins are not in [`State`]: they are read per request straight from the
//! backend. Creating a session (login) or revoking one (logout, an admin revoking a user's
//! sessions) is still a [`Mutation`], so it is atomic with its audit row.

pub mod audit;
pub mod memory;
pub mod postgres;
#[cfg(test)]
mod tests;
pub mod usage;

use crate::auth::rbac::Role;
use audit::{AuditDraft, AuditEntry};
use caliban_config::{
    Config, ConfigHandle, Keyring, ModelEntry, ProviderConfig, RouteConfig, SecretRef, SharedProvider, Snapshot,
    TenantConfig, TenantSealed, WrappedDek,
};
use caliban_meter::RecentUsage;
use caliban_nodes::publish::NodeCaps;
use caliban_ontology::{Element, Ontology, Status};
use caliban_types::{PiiMode, PiiSurrogateScope, ProviderKind, SemanticCacheMode, TrustTier};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    #[default]
    Active,
    /// Tombstone: not rendered into the data plane, not reachable through the API (404), and
    /// the id cannot be reused. Audit rows naming the tenant are kept.
    Deleted,
}

impl TenantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TenantStatus::Active => "active",
            TenantStatus::Deleted => "deleted",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub region: Option<String>,
    pub pii_default: PiiMode,
    /// `tenant` (default): the same value always gets the same surrogate in this tenant, so
    /// pseudonymised requests can hit the cache. `session`: fresh surrogates per request.
    pub pii_surrogate_scope: PiiSurrogateScope,
    /// T2 semantic cache for this tenant (`off` by default; also needs `[cache.semantic] enabled`).
    pub semantic_cache: SemanticCacheMode,
    /// Fraction of the flat `caliban/auto` price billed for a cache hit, in 0..=1. `None`: the
    /// deployment's `[routing] auto_cache_hit_fraction` (default 0.20).
    pub auto_cache_hit_fraction: Option<f64>,
    /// Caps on the budgets of every node version the tenant publishes. `None`: the defaults
    /// ([`NodeCaps::DEFAULT`]).
    pub node_caps: Option<NodeCaps>,
    /// Daily and monthly caps on what the tenant's node runs spend (USD). `None`: no cap.
    pub node_spend_caps: Option<caliban_config::NodeSpendCaps>,
    pub created_at: DateTime<Utc>,
    pub status: TenantStatus,
    pub deleted_at: Option<DateTime<Utc>>,
    /// Extra `TenantConfig` fields from the config file (e.g. quotas), passed through to the
    /// data-plane snapshot unchanged.
    #[serde(skip)]
    pub settings: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ApiKeyRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub prefix: String,
    #[serde(skip)]
    pub hash: String,
    pub created_at: DateTime<Utc>,
    /// Set when the key is revoked. The row is kept for audit; the hash leaves the snapshot.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Node allowlist: the nodes this key may run. `None`: every published node of the tenant;
    /// empty: none.
    pub nodes: Option<Vec<String>>,
    /// Datasource scopes the built-in query tool may read for this key's runs (intersected with
    /// the node's). `None`: every scope of the nodes it runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datasource_scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ProviderKeyRecord {
    pub id: String,
    pub tenant_id: String,
    pub kind: ProviderKind,
    pub label: String,
    pub base_url: Option<String>,
    pub trust_tier: TrustTier,
    pub last4: Option<String>,
    pub cache_salt: bool,
    pub created_at: DateTime<Utc>,
    #[serde(skip)]
    pub secret: Option<StoredSecret>,
}

/// How a tenant provider key is held by the store.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StoredSecret {
    /// A reference from the config file (`{env}`, `{file}`), or a value sealed directly under the
    /// KEK by a release before migration 0008 (re-sealed under the tenant DEK at startup).
    Ref(SecretRef),
    /// Sealed under the tenant's DEK: base64(nonce ‖ ciphertext), the tenant id as associated
    /// data. Rendered into the snapshot as a self-contained [`TenantSealed`] envelope.
    TenantDek(String),
}

/// A tenant's data-encryption key, wrapped by the KEK `wrapped.kek_id`. Destroyed with the tenant.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DekRecord {
    pub wrapped: WrappedDek,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DatasourceRecord {
    pub id: String,
    pub tenant_id: String,
    pub kind: String,
    pub name: String,
    pub status: String,
    pub epoch: u64,
    /// Secrets inside are sealed under the tenant DEK (`{"$sealed": ...}`); the API only ever
    /// returns the redacted form.
    #[serde(serialize_with = "crate::keys::serialize_redacted")]
    pub connection: Value,
    /// Soft delete; deleted datasources are never returned by the API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Where a node version is in its lifecycle: `draft` -> `published` -> `retired`, never back.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    /// Created, editable only by creating another version; not runnable.
    #[default]
    Draft,
    /// Validated against the tenant and shipped to the data plane (sealed); runnable.
    Published,
    /// No longer shipped or runnable; kept for audit.
    Retired,
}

impl NodeState {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeState::Draft => "draft",
            NodeState::Published => "published",
            NodeState::Retired => "retired",
        }
    }
}

/// One immutable version of a node.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NodeRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub version: u32,
    pub spec: Value,
    /// `sha256:<hex>` over the canonical spec JSON (see `caliban_nodes::hash`).
    pub hash: String,
    pub state: NodeState,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
    /// The spec sealed under the tenant's DEK (set when published): what the snapshot ships.
    #[serde(skip)]
    pub sealed_spec: Option<String>,
    /// Soft delete; deleted node versions are never returned by the API, and their version
    /// numbers are not reused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
}

/// A tenant's registered MCP tool server. Registering it is what allows egress to it.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ToolServerRecord {
    pub id: String,
    pub tenant_id: String,
    /// The `server` of `mcp://server/tool#sha256:...` (node-name rules).
    pub name: String,
    pub url: String,
    pub auth: caliban_config::ToolAuth,
    /// Trusted with personal data: PII surrogates in arguments are rehydrated for it.
    pub trusted: bool,
    /// The API key or OAuth client secret, sealed under the tenant DEK (base64 nonce ‖ ciphertext).
    #[serde(skip)]
    pub secret: Option<String>,
    /// Whether a credential is stored (the API shows this, never the credential).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub has_credential: bool,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl ToolServerRecord {
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none()
    }
}

/// Where a tool manifest is in its review.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    /// Seen on the server (or imported); not callable.
    #[default]
    Discovered,
    /// Approved by a human: shipped to the data plane, callable by nodes that pin it.
    Approved,
    /// Approval withdrawn.
    Revoked,
}

impl ToolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ToolStatus::Discovered => "discovered",
            ToolStatus::Approved => "approved",
            ToolStatus::Revoked => "revoked",
        }
    }
}

/// One manifest of a server's tool, as discovered: its pin and the injection scan's findings.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ToolManifestRecord {
    pub id: String,
    pub tenant_id: String,
    pub server: String,
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub pin: String,
    pub findings: Vec<caliban_mcp::scan::Finding>,
    pub status: ToolStatus,
    pub discovered_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub approved_by: Option<String>,
    /// Approved although the scan found something (an explicit decision, audited).
    pub findings_acknowledged: bool,
}

/// The promotion pointer of a node: its live version.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Promotion {
    pub version: u32,
    pub promoted_at: DateTime<Utc>,
    pub promoted_by: String,
}

/// A person or service known from the identity provider, keyed by `(issuer, subject)`. Created
/// just in time on the first login or the first access token.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UserRecord {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl UserRecord {
    /// Audit actor: `display <issuer#subject>`, where display is the email, else the name, else
    /// the subject. The part in angle brackets is the stable identity.
    pub fn actor(&self) -> String {
        let display = self.email.as_deref().or(self.name.as_deref()).unwrap_or(&self.subject);
        format!("{display} <{}#{}>", self.issuer, self.subject)
    }
}

#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// `subject` is a [`UserRecord::id`].
    User,
    /// `subject` is an identity-provider group, as sent in the groups claim.
    Group,
}

impl SubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SubjectKind::User => "user",
            SubjectKind::Group => "group",
        }
    }
}

/// A role granted to a user or a group, deployment-wide (`tenant_id: None`) or for one tenant.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RoleBinding {
    pub id: String,
    pub subject_kind: SubjectKind,
    pub subject: String,
    pub role: Role,
    pub tenant_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

/// A server-side console session. The browser holds the token; only its SHA-256 is stored.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SessionRecord {
    /// Public id (audit rows, revocation), unrelated to the token.
    pub id: String,
    #[serde(skip)]
    pub token_sha256: String,
    pub user_id: String,
    /// The user's identity-provider groups at login.
    pub groups: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// An authorization request in flight (between `/auth/login` and `/auth/callback`). Single use.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingLogin {
    pub state: String,
    /// SHA-256 of the login cookie set on the browser that started the login.
    pub binding_sha256: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_to: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct State {
    /// Model catalogue.
    pub models: Vec<ModelEntry>,
    /// Deployment-wide providers, e.g. on-prem model servers shared by all tenants.
    pub shared_providers: Vec<SharedProvider>,
    /// Includes tombstones (`status = deleted`); see [`State::tenant`].
    pub tenants: Vec<Tenant>,
    /// Includes revoked keys (`revoked_at` set).
    pub api_keys: Vec<ApiKeyRecord>,
    pub provider_keys: Vec<ProviderKeyRecord>,
    /// Tenant → ordered routes (first model preferred, the rest are fallbacks).
    pub routes: BTreeMap<String, Vec<RouteConfig>>,
    /// Includes soft-deleted rows (`deleted_at` set).
    pub datasources: Vec<DatasourceRecord>,
    /// Includes soft-deleted rows (`deleted_at` set).
    pub nodes: Vec<NodeRecord>,
    /// Tenant → node name → its live version.
    pub promotions: BTreeMap<String, BTreeMap<String, Promotion>>,
    /// Includes soft-deleted servers (`deleted_at` set).
    pub tool_servers: Vec<ToolServerRecord>,
    pub tool_manifests: Vec<ToolManifestRecord>,
    pub ontologies: BTreeMap<String, Ontology>,
    /// Tenant → wrapped DEK. Created on the tenant's first secret, destroyed with the tenant.
    pub deks: BTreeMap<String, DekRecord>,
    /// Users known from the identity provider (created just in time).
    pub users: Vec<UserRecord>,
    /// Roles granted through the API (group to role mappings from the config file are not here).
    pub role_bindings: Vec<RoleBinding>,
    /// Sequence number of the last audit row; doubles as the state version.
    pub audit_head: u64,
}

impl State {
    /// Initial state from the config file (the in-memory store, or the first Postgres start).
    pub fn from_config(base: &Config) -> Self {
        let now = audit::now_micros();
        let mut st =
            State { models: base.models.clone(), shared_providers: base.providers.clone(), ..State::default() };
        for t in &base.tenants {
            st.tenants.push(Tenant {
                id: t.id.to_string(),
                name: t.name.clone(),
                region: None,
                pii_default: t.pii_mode.unwrap_or(base.pii.default_mode),
                pii_surrogate_scope: t.pii_surrogate_scope,
                semantic_cache: t.semantic_cache,
                auto_cache_hit_fraction: t.auto_cache_hit_fraction,
                node_caps: None,
                node_spend_caps: None,
                created_at: now,
                status: TenantStatus::Active,
                deleted_at: None,
                settings: tenant_settings(t),
            });
            for (i, h) in t.api_key_hashes.iter().enumerate() {
                st.api_keys.push(ApiKeyRecord {
                    id: format!("key_cfg_{}_{i}", t.id),
                    tenant_id: t.id.to_string(),
                    name: "from config file".into(),
                    prefix: "cal_…".into(),
                    hash: h.to_ascii_lowercase(),
                    created_at: now,
                    revoked_at: None,
                    nodes: None,
                    datasource_scopes: None,
                });
            }
            for p in &t.providers {
                st.provider_keys.push(ProviderKeyRecord {
                    id: p.id.to_string(),
                    tenant_id: t.id.to_string(),
                    kind: p.kind,
                    label: p.id.to_string(),
                    base_url: Some(p.base_url.clone()),
                    trust_tier: p.trust_tier,
                    last4: None,
                    cache_salt: p.cache_salt,
                    created_at: now,
                    secret: p.api_key.clone().map(StoredSecret::Ref),
                });
            }
            if !t.routes.is_empty() {
                st.routes.insert(t.id.to_string(), t.routes.clone());
            }
        }
        st
    }

    /// An active tenant (tombstones are not found).
    pub fn tenant(&self, id: &str) -> Option<&Tenant> {
        self.tenants.iter().find(|t| t.id == id && t.is_active())
    }

    /// Any tenant record, tombstones included (ids are never reused).
    pub fn tenant_record(&self, id: &str) -> Option<&Tenant> {
        self.tenants.iter().find(|t| t.id == id)
    }

    pub fn has_tenant(&self, id: &str) -> bool {
        self.tenant(id).is_some()
    }

    pub fn active_api_key(&self, tenant_id: &str, id: &str) -> Option<&ApiKeyRecord> {
        self.api_keys.iter().find(|k| k.tenant_id == tenant_id && k.id == id && k.is_active())
    }

    pub fn live_datasource(&self, tenant_id: &str, id: &str) -> Option<&DatasourceRecord> {
        self.datasources.iter().find(|d| d.tenant_id == tenant_id && d.id == id && d.is_live())
    }

    pub fn live_node(&self, tenant_id: &str, id: &str) -> Option<&NodeRecord> {
        self.nodes.iter().find(|n| n.tenant_id == tenant_id && n.id == id && n.is_live())
    }

    /// A version of node `name` of the tenant (not deleted).
    pub fn node_version(&self, tenant_id: &str, name: &str, version: u32) -> Option<&NodeRecord> {
        self.nodes.iter().find(|n| n.tenant_id == tenant_id && n.name == name && n.version == version && n.is_live())
    }

    /// Every version of node `name` of the tenant (not deleted), oldest first.
    pub fn node_versions<'a>(&'a self, tenant_id: &'a str, name: &'a str) -> impl Iterator<Item = &'a NodeRecord> + 'a {
        self.nodes.iter().filter(move |n| n.tenant_id == tenant_id && n.name == name && n.is_live())
    }

    /// The live version of node `name`, if it has one.
    pub fn promotion(&self, tenant_id: &str, name: &str) -> Option<&Promotion> {
        self.promotions.get(tenant_id).and_then(|p| p.get(name))
    }

    /// A live tool server of the tenant, by name.
    pub fn tool_server(&self, tenant_id: &str, name: &str) -> Option<&ToolServerRecord> {
        self.tool_servers.iter().find(|s| s.tenant_id == tenant_id && s.name == name && s.is_live())
    }

    /// An approved manifest (`tool` of `server`, with this pin) of a live server of the tenant.
    pub fn approved_tool(&self, tenant_id: &str, server: &str, tool: &str, pin: &str) -> Option<&ToolManifestRecord> {
        self.tool_server(tenant_id, server)?;
        self.tool_manifests.iter().find(|m| {
            m.tenant_id == tenant_id
                && m.server == server
                && m.name == tool
                && m.pin == pin
                && m.status == ToolStatus::Approved
        })
    }

    /// The tenant's node caps (its own, else the defaults).
    pub fn node_caps(&self, tenant_id: &str) -> NodeCaps {
        self.tenant(tenant_id).and_then(|t| t.node_caps).unwrap_or_default()
    }

    pub fn user(&self, id: &str) -> Option<&UserRecord> {
        self.users.iter().find(|u| u.id == id)
    }

    pub fn user_by_subject(&self, issuer: &str, subject: &str) -> Option<&UserRecord> {
        self.users.iter().find(|u| u.issuer == issuer && u.subject == subject)
    }
}

impl Tenant {
    pub fn is_active(&self) -> bool {
        self.status == TenantStatus::Active
    }
}

impl ApiKeyRecord {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

impl DatasourceRecord {
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none()
    }
}

impl NodeRecord {
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none()
    }
}

/// `TenantConfig` fields the store models explicitly; anything else is kept in `settings`.
const TENANT_FIELDS: &[&str] = &[
    "id",
    "name",
    "pii_mode",
    "pii_surrogate_scope",
    "semantic_cache",
    "auto_cache_hit_fraction",
    "api_key_hashes",
    "providers",
    "routes",
    "nodes",
    "api_key_nodes",
    "data_key",
    "node_spend_caps",
    "tool_servers",
    "tools",
    "datasources",
    "ontology",
    "api_key_datasource_scopes",
];

fn tenant_settings(t: &TenantConfig) -> Map<String, Value> {
    match serde_json::to_value(t) {
        Ok(Value::Object(mut m)) => {
            m.retain(|k, v| !TENANT_FIELDS.contains(&k.as_str()) && !v.is_null());
            m
        }
        _ => Map::new(),
    }
}

/// Renders the data-plane config from control-plane state. `base` supplies process settings.
/// Deleted tenants and revoked API keys are left out, so a router stops accepting them on the
/// next snapshot it applies.
pub fn render(base: &Config, st: &State) -> Result<Config, String> {
    let mut cfg = base.clone();
    cfg.models = st.models.clone();
    cfg.providers = st.shared_providers.clone();
    cfg.tenants = st
        .tenants
        .iter()
        .filter(|t| t.is_active())
        .map(|t| {
            let mut providers: Vec<ProviderConfig> = Vec::new();
            for p in st.provider_keys.iter().filter(|p| p.tenant_id == t.id) {
                let Some(base_url) = p.base_url.clone().or_else(|| default_base_url(p.kind)) else { continue };
                let api_key = match &p.secret {
                    None => None,
                    Some(StoredSecret::Ref(r)) => Some(r.clone()),
                    // Self-contained for routers: the DEK travels wrapped, opened with the keyring.
                    Some(StoredSecret::TenantDek(sealed)) => {
                        let d = st.deks.get(&t.id).ok_or_else(|| {
                            format!(
                                "tenant {}: provider key '{}' is sealed under a tenant key that does not exist",
                                t.id, p.id
                            )
                        })?;
                        Some(SecretRef::TenantSealed {
                            tenant_sealed: TenantSealed {
                                tenant: t.id.clone(),
                                kek_id: d.wrapped.kek_id.clone(),
                                wrapped_dek: d.wrapped.wrapped.clone(),
                                sealed: sealed.clone(),
                            },
                        })
                    }
                };
                providers.push(ProviderConfig {
                    id: p.id.as_str().into(),
                    kind: p.kind,
                    base_url,
                    trust_tier: p.trust_tier,
                    api_key,
                    cache_salt: p.cache_salt,
                });
            }
            // Built through serde so fields this crate does not model (in `settings`) pass through.
            let mut obj = t.settings.clone();
            obj.insert("id".into(), json!(t.id));
            obj.insert("name".into(), json!(t.name));
            obj.insert("pii_mode".into(), json!(t.pii_default));
            obj.insert("pii_surrogate_scope".into(), json!(t.pii_surrogate_scope));
            obj.insert("semantic_cache".into(), json!(t.semantic_cache));
            if let Some(f) = t.auto_cache_hit_fraction {
                obj.insert("auto_cache_hit_fraction".into(), json!(f));
            }
            if let Some(c) = t.node_spend_caps {
                obj.insert("node_spend_caps".into(), json!(c));
            }
            obj.insert(
                "api_key_hashes".into(),
                json!(
                    st.api_keys
                        .iter()
                        .filter(|k| k.tenant_id == t.id && k.is_active())
                        .map(|k| &k.hash)
                        .collect::<Vec<_>>()
                ),
            );
            obj.insert("providers".into(), serde_json::to_value(providers).map_err(|e| e.to_string())?);
            obj.insert(
                "routes".into(),
                serde_json::to_value(st.routes.get(&t.id).cloned().unwrap_or_default()).map_err(|e| e.to_string())?,
            );
            render_nodes(st, &t.id, &mut obj)?;
            render_tools(st, &t.id, &mut obj)?;
            serde_json::from_value::<TenantConfig>(Value::Object(obj)).map_err(|e| format!("tenant {}: {e}", t.id))
        })
        .collect::<Result<_, _>>()?;
    Ok(cfg)
}

/// The tenant's published node versions (sealed specs, the live flag), the node allowlists of
/// its API keys, and its wrapped DEK (for workers) once it has released a version. Drafts and
/// retired versions never reach the data plane.
fn render_nodes(st: &State, tenant: &str, obj: &mut Map<String, Value>) -> Result<(), String> {
    let mut nodes = Vec::new();
    for n in st.nodes.iter().filter(|n| n.tenant_id == tenant && n.is_live() && n.state == NodeState::Published) {
        let d = st.deks.get(tenant).ok_or_else(|| {
            format!("tenant {tenant}: node {}@v{} is sealed under a tenant key that does not exist", n.name, n.version)
        })?;
        let sealed = n
            .sealed_spec
            .clone()
            .ok_or_else(|| format!("tenant {tenant}: published node {}@v{} has no sealed spec", n.name, n.version))?;
        nodes.push(caliban_config::PublishedNode {
            name: n.name.clone(),
            version: n.version,
            hash: n.hash.clone(),
            live: st.promotion(tenant, &n.name).is_some_and(|p| p.version == n.version),
            spec: TenantSealed {
                tenant: tenant.to_owned(),
                kek_id: d.wrapped.kek_id.clone(),
                wrapped_dek: d.wrapped.wrapped.clone(),
                sealed,
            },
        });
    }
    let allowlists: BTreeMap<&String, &Vec<String>> = st
        .api_keys
        .iter()
        .filter(|k| k.tenant_id == tenant && k.is_active())
        .filter_map(|k| k.nodes.as_ref().map(|n| (&k.hash, n)))
        .collect();
    // Workers keep opening the journals of runs of retired versions.
    let released = st.nodes.iter().any(|n| n.tenant_id == tenant && n.is_live() && n.state != NodeState::Draft);
    if released && let Some(d) = st.deks.get(tenant) {
        obj.insert("data_key".into(), serde_json::to_value(&d.wrapped).map_err(|e| e.to_string())?);
    }
    if !nodes.is_empty() {
        obj.insert("nodes".into(), serde_json::to_value(nodes).map_err(|e| e.to_string())?);
    }
    if !allowlists.is_empty() {
        obj.insert("api_key_nodes".into(), serde_json::to_value(allowlists).map_err(|e| e.to_string())?);
    }
    let scopes: BTreeMap<&String, &Vec<String>> = st
        .api_keys
        .iter()
        .filter(|k| k.tenant_id == tenant && k.is_active())
        .filter_map(|k| k.datasource_scopes.as_ref().map(|s| (&k.hash, s)))
        .collect();
    if !scopes.is_empty() {
        obj.insert("api_key_datasource_scopes".into(), serde_json::to_value(scopes).map_err(|e| e.to_string())?);
    }
    // The built-in datasource tool needs the datasources (credentials stay sealed) and the
    // approved ontology on the data plane, only when a published node uses it.
    let uses_datasources =
        st.nodes.iter().filter(|n| n.tenant_id == tenant && n.is_live() && n.state == NodeState::Published).any(|n| {
            n.spec["tools"].as_array().is_some_and(|t| t.iter().any(|t| t["ref"] == "builtin://datasource_query"))
        });
    if uses_datasources {
        let ds: Vec<caliban_config::DatasourceConfig> = st
            .datasources
            .iter()
            .filter(|d| d.tenant_id == tenant && d.is_live())
            .map(|d| caliban_config::DatasourceConfig {
                id: d.id.clone(),
                name: d.name.clone(),
                kind: d.kind.clone(),
                connection: d.connection.clone(),
            })
            .collect();
        obj.insert("datasources".into(), serde_json::to_value(ds).map_err(|e| e.to_string())?);
        if let Some(o) = st.ontologies.get(tenant) {
            let approved = Ontology {
                tenant_id: o.tenant_id.clone(),
                version: o.version,
                elements: o.approved().cloned().collect(),
            };
            obj.insert("ontology".into(), serde_json::to_value(approved).map_err(|e| e.to_string())?);
        }
    }
    Ok(())
}

/// The tenant's live tool servers (credentials sealed for the data plane) and approved manifests
/// of those servers.
fn render_tools(st: &State, tenant: &str, obj: &mut Map<String, Value>) -> Result<(), String> {
    let mut servers = Vec::new();
    for s in st.tool_servers.iter().filter(|s| s.tenant_id == tenant && s.is_live()) {
        let credential = match &s.secret {
            None => None,
            Some(sealed) => {
                let d = st.deks.get(tenant).ok_or_else(|| {
                    format!(
                        "tenant {tenant}: tool server '{}' is sealed under a tenant key that does not exist",
                        s.name
                    )
                })?;
                Some(SecretRef::TenantSealed {
                    tenant_sealed: TenantSealed {
                        tenant: tenant.to_owned(),
                        kek_id: d.wrapped.kek_id.clone(),
                        wrapped_dek: d.wrapped.wrapped.clone(),
                        sealed: sealed.clone(),
                    },
                })
            }
        };
        servers.push(caliban_config::ToolServerConfig {
            name: s.name.clone(),
            url: s.url.clone(),
            auth: s.auth.clone(),
            trusted: s.trusted,
            credential,
        });
    }
    let tools: Vec<caliban_config::ApprovedTool> = st
        .tool_manifests
        .iter()
        .filter(|m| {
            m.tenant_id == tenant && m.status == ToolStatus::Approved && st.tool_server(tenant, &m.server).is_some()
        })
        .map(|m| caliban_config::ApprovedTool {
            server: m.server.clone(),
            name: m.name.clone(),
            description: m.description.clone(),
            input_schema: m.input_schema.clone(),
            pin: m.pin.clone(),
        })
        .collect();
    if !servers.is_empty() {
        obj.insert("tool_servers".into(), serde_json::to_value(servers).map_err(|e| e.to_string())?);
    }
    if !tools.is_empty() {
        obj.insert("tools".into(), serde_json::to_value(tools).map_err(|e| e.to_string())?);
    }
    Ok(())
}

/// Render + validate: the invariant every committed state must satisfy.
pub fn check(base: &Config, st: &State) -> Result<(), String> {
    render(base, st)?.validate().map_err(|e| e.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    /// The mutation would make the data-plane config invalid; nothing was written.
    #[error("{0}")]
    Invalid(String),
    #[error("store backend error: {0}")]
    Backend(String),
}

/// Every control-plane write. Applied atomically together with its audit row.
#[derive(Debug, Clone)]
pub enum Mutation {
    CreateTenant(Tenant),
    CreateApiKey(ApiKeyRecord),
    /// Soft revoke: `revoked_at = at`, the row is kept.
    RevokeApiKey {
        tenant_id: String,
        id: String,
        at: DateTime<Utc>,
    },
    /// Tombstones the tenant and, in the same transaction, revokes its API keys, destroys its
    /// BYOK credentials, removes its routes and soft-deletes its datasources and nodes.
    DeleteTenant {
        id: String,
        at: DateTime<Utc>,
    },
    /// Changes an active tenant's settings; `None` keeps the current value.
    UpdateTenant {
        id: String,
        pii_default: Option<PiiMode>,
        pii_surrogate_scope: Option<PiiSurrogateScope>,
        semantic_cache: Option<SemanticCacheMode>,
        /// `Some(None)` clears the override (back to the deployment value).
        auto_cache_hit_fraction: Option<Option<f64>>,
        /// `Some(None)` clears the caps (back to the defaults).
        node_caps: Option<Option<NodeCaps>>,
        /// `Some(None)` clears the spend caps (no cap).
        node_spend_caps: Option<Option<caliban_config::NodeSpendCaps>>,
    },
    CreateProviderKey(ProviderKeyRecord),
    DeleteProviderKey {
        tenant_id: String,
        id: String,
    },
    CreateModel(ModelEntry),
    DeleteModel(String),
    CreateSharedProvider(SharedProvider),
    DeleteSharedProvider(String),
    SetRoutes {
        tenant_id: String,
        routes: Vec<RouteConfig>,
    },
    CreateDatasource(DatasourceRecord),
    SetDatasourceStatus {
        id: String,
        status: String,
    },
    /// Soft delete; the stored `connection` is wiped.
    DeleteDatasource {
        tenant_id: String,
        id: String,
        at: DateTime<Utc>,
    },
    /// A draft. `version` is assigned by the store (latest version for (tenant, name) + 1).
    CreateNode(NodeRecord),
    /// Soft-deletes one node version (a draft or a retired one; published versions are retired
    /// first).
    DeleteNode {
        tenant_id: String,
        id: String,
        at: DateTime<Utc>,
    },
    /// Publishes a draft after publish-time validation against the tenant, with its spec sealed
    /// under the tenant DEK; `promote` also makes it the live version.
    PublishNode {
        tenant_id: String,
        name: String,
        version: u32,
        sealed_spec: String,
        promote: bool,
        at: DateTime<Utc>,
        by: String,
    },
    /// Moves the promotion pointer to a published version (rollback included); its budgets are
    /// checked against the tenant's caps again.
    PromoteNode {
        tenant_id: String,
        name: String,
        version: u32,
        at: DateTime<Utc>,
        by: String,
    },
    /// Retires a published version: it leaves the data plane (and the pointer, if live).
    RetireNode {
        tenant_id: String,
        name: String,
        version: u32,
        at: DateTime<Utc>,
    },
    /// Registers an MCP tool server (its credential already sealed under the tenant DEK).
    CreateToolServer(ToolServerRecord),
    /// Soft-deletes a server: its credential is wiped and its tools leave the data plane.
    DeleteToolServer {
        tenant_id: String,
        name: String,
        at: DateTime<Utc>,
    },
    /// Manifests seen on a server (discovery or import): new pins are added as `discovered`,
    /// known ones are kept as they are.
    RecordToolManifests {
        tenant_id: String,
        server: String,
        manifests: Vec<ToolManifestRecord>,
    },
    /// A human approves one manifest (by pin). With scan findings, only when acknowledged.
    ApproveTool {
        tenant_id: String,
        server: String,
        tool: String,
        pin: String,
        acknowledge_findings: bool,
        at: DateTime<Utc>,
        by: String,
    },
    /// Withdraws the approval of one manifest (by pin).
    RevokeTool {
        tenant_id: String,
        server: String,
        tool: String,
        pin: String,
    },
    /// Upserts elements (e.g. proposals from the bootstrap job) as one new ontology version.
    ProposeOntology {
        tenant_id: String,
        elements: Vec<Element>,
    },
    ReviewOntologyElement {
        id: String,
        status: Status,
    },
    /// Stores a tenant's first DEK (wrapped). Conflict if the tenant already has one.
    CreateDek {
        tenant_id: String,
        dek: DekRecord,
    },
    /// Startup migration or KEK rotation, planned by [`crate::keys::plan`].
    Rekey(Rekey),
    /// A successful login: creates the user (keyed by issuer and subject) or refreshes its email,
    /// name and `last_login_at`, and stores the new session for that user.
    Login {
        user: UserRecord,
        session: SessionRecord,
    },
    /// Revokes one active session of `user_id` (logout).
    Logout {
        session_id: String,
        user_id: String,
        at: DateTime<Utc>,
    },
    /// A user first seen through an access token. Conflict if `(issuer, subject)` is known.
    CreateUser(UserRecord),
    /// Revokes every active session of the user.
    RevokeUserSessions {
        user_id: String,
        at: DateTime<Utc>,
    },
    CreateRoleBinding(RoleBinding),
    DeleteRoleBinding {
        id: String,
    },
    /// Changes nothing; only appends the audit row (failed logins, break-glass use).
    Record(AuditDraft),
}

/// A batch of key changes. Every change names the value it replaces; if any of them changed in
/// the meantime the whole batch is a conflict and nothing is written (the caller replans).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rekey {
    /// `keys.rotate` (operator command) rather than `keys.migrate` (startup).
    pub rotate: bool,
    /// The current KEK: every DEK created or re-wrapped here is wrapped by it.
    pub kek_id: String,
    pub deks: Vec<DekChange>,
    pub provider_secrets: Vec<ProviderSecretChange>,
    pub shared_secrets: Vec<SharedSecretChange>,
    pub datasources: Vec<ConnectionChange>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DekChange {
    pub tenant_id: String,
    /// `None`: a new DEK. `Some`: re-wrapped (same DEK, `created_at` kept).
    pub prev: Option<WrappedDek>,
    pub next: DekRecord,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderSecretChange {
    pub tenant_id: String,
    pub id: String,
    pub prev: StoredSecret,
    pub next: StoredSecret,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SharedSecretChange {
    pub id: String,
    pub prev: SecretRef,
    pub next: SecretRef,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionChange {
    pub tenant_id: String,
    pub id: String,
    pub prev: Value,
    pub next: Value,
}

impl Rekey {
    pub fn is_empty(&self) -> bool {
        self.deks.is_empty()
            && self.provider_secrets.is_empty()
            && self.shared_secrets.is_empty()
            && self.datasources.is_empty()
    }

    /// Audit detail: ids and KEK ids only, never key material.
    pub fn summary(&self) -> Value {
        json!({
            "kek_id": self.kek_id,
            "tenant_keys_created": self.deks.iter().filter(|d| d.prev.is_none()).map(|d| &d.tenant_id).collect::<Vec<_>>(),
            "tenant_keys_rewrapped": self.deks.iter().filter_map(|d| d.prev.as_ref().map(|p| json!({"tenant": d.tenant_id, "from": p.kek_id}))).collect::<Vec<_>>(),
            "provider_keys_resealed": self.provider_secrets.iter().map(|c| format!("{}/{}", c.tenant_id, c.id)).collect::<Vec<_>>(),
            "shared_provider_keys_resealed": self.shared_secrets.iter().map(|c| &c.id).collect::<Vec<_>>(),
            "datasources_sealed": self.datasources.iter().map(|c| &c.id).collect::<Vec<_>>(),
        })
    }
}

impl Mutation {
    /// What goes into the audit log. Never secrets: API keys show the prefix, BYOK keys last4.
    /// `before` is the committed state the mutation applies to (deletes record what they removed).
    pub fn audit(&self, before: &State) -> AuditDraft {
        let d = |tenant: Option<&str>, action, target: &str, detail| AuditDraft {
            tenant_id: tenant.map(str::to_owned),
            action,
            target: Some(target.to_owned()),
            detail,
        };
        match self {
            Mutation::CreateTenant(t) => {
                let mut detail = json!({"name": t.name, "pii_default": t.pii_default, "pii_surrogate_scope": t.pii_surrogate_scope, "semantic_cache": t.semantic_cache});
                if let Some(f) = t.auto_cache_hit_fraction {
                    detail["auto_cache_hit_fraction"] = json!(f);
                }
                d(Some(&t.id), "tenant.create", &t.id, detail)
            }
            Mutation::UpdateTenant {
                id,
                pii_default,
                pii_surrogate_scope,
                semantic_cache,
                auto_cache_hit_fraction,
                node_caps,
                node_spend_caps,
            } => {
                let t = before.tenant(id);
                let mut detail = json!({
                    "pii_default": {"from": t.map(|t| t.pii_default), "to": pii_default},
                    "pii_surrogate_scope": {"from": t.map(|t| t.pii_surrogate_scope), "to": pii_surrogate_scope},
                    "semantic_cache": {"from": t.map(|t| t.semantic_cache), "to": semantic_cache},
                });
                // Only when changed: `to: null` here means "cleared", not "kept".
                if let Some(to) = auto_cache_hit_fraction {
                    detail["auto_cache_hit_fraction"] =
                        json!({"from": t.and_then(|t| t.auto_cache_hit_fraction), "to": to});
                }
                if let Some(to) = node_caps {
                    detail["node_caps"] = json!({"from": t.and_then(|t| t.node_caps), "to": to});
                }
                if let Some(to) = node_spend_caps {
                    detail["node_spend_caps"] = json!({"from": t.and_then(|t| t.node_spend_caps), "to": to});
                }
                d(Some(id), "tenant.update", id, detail)
            }
            Mutation::CreateApiKey(k) => {
                let mut detail = json!({"name": k.name, "prefix": k.prefix});
                if let Some(n) = &k.nodes {
                    detail["nodes"] = json!(n);
                }
                d(Some(&k.tenant_id), "api_key.create", &k.id, detail)
            }
            Mutation::RevokeApiKey { tenant_id, id, .. } => {
                let k = before.active_api_key(tenant_id, id);
                d(
                    Some(tenant_id),
                    "api_key.revoke",
                    id,
                    json!({"name": k.map(|k| &k.name), "prefix": k.map(|k| &k.prefix)}),
                )
            }
            Mutation::DeleteTenant { id, .. } => {
                let ids = |v: Vec<&String>| v.into_iter().cloned().collect::<Vec<_>>();
                d(
                    Some(id),
                    "tenant.delete",
                    id,
                    json!({
                        "api_keys_revoked": ids(before.api_keys.iter().filter(|k| &k.tenant_id == id && k.is_active()).map(|k| &k.id).collect()),
                        "provider_keys_destroyed": ids(before.provider_keys.iter().filter(|p| &p.tenant_id == id).map(|p| &p.id).collect()),
                        "routes_removed": before.routes.get(id).map(|r| r.iter().map(|r| r.intent.clone()).collect::<Vec<_>>()).unwrap_or_default(),
                        "datasources_deleted": ids(before.datasources.iter().filter(|x| &x.tenant_id == id && x.is_live()).map(|x| &x.id).collect()),
                        "nodes_deleted": ids(before.nodes.iter().filter(|x| &x.tenant_id == id && x.is_live()).map(|x| &x.id).collect()),
                        // Crypto-shredding: everything sealed under this key is unreadable without it.
                        "tenant_key_destroyed": before.deks.get(id).map(|d| &d.wrapped.kek_id),
                        "role_bindings_removed": ids(before.role_bindings.iter().filter(|b| b.tenant_id.as_ref() == Some(id)).map(|b| &b.id).collect()),
                    }),
                )
            }
            Mutation::CreateProviderKey(p) => d(
                Some(&p.tenant_id),
                "provider_key.create",
                &p.id,
                json!({"kind": p.kind, "base_url": p.base_url, "trust_tier": p.trust_tier, "last4": p.last4}),
            ),
            Mutation::DeleteProviderKey { tenant_id, id } => d(Some(tenant_id), "provider_key.delete", id, json!({})),
            Mutation::CreateModel(m) => d(
                None,
                "model.create",
                m.id.as_str(),
                json!({"provider": m.provider, "upstream_model": m.upstream_model}),
            ),
            Mutation::DeleteModel(id) => d(None, "model.delete", id, json!({})),
            Mutation::CreateSharedProvider(p) => d(
                None,
                "provider.create",
                p.provider.id.as_str(),
                json!({"kind": p.provider.kind, "base_url": p.provider.base_url, "trust_tier": p.provider.trust_tier,
                       "has_api_key": p.provider.api_key.is_some()}),
            ),
            Mutation::DeleteSharedProvider(id) => d(None, "provider.delete", id, json!({})),
            Mutation::SetRoutes { tenant_id, routes } => d(
                Some(tenant_id),
                "routes.set",
                tenant_id,
                json!({"routes": routes.iter().map(|r| json!({"intent": r.intent, "models": r.models})).collect::<Vec<_>>()}),
            ),
            Mutation::CreateDatasource(ds) => d(
                Some(&ds.tenant_id),
                "datasource.create",
                &ds.id,
                json!({"kind": ds.kind, "name": ds.name, "sealed_secrets": crate::keys::count_sealed(&ds.connection)}),
            ),
            Mutation::SetDatasourceStatus { id, status } => d(None, "datasource.status", id, json!({"status": status})),
            Mutation::DeleteDatasource { tenant_id, id, .. } => {
                let ds = before.live_datasource(tenant_id, id);
                d(
                    Some(tenant_id),
                    "datasource.delete",
                    id,
                    json!({"kind": ds.map(|x| &x.kind), "name": ds.map(|x| &x.name)}),
                )
            }
            Mutation::CreateNode(n) => {
                d(Some(&n.tenant_id), "node.create", &n.id, json!({"name": n.name, "hash": n.hash}))
            }
            Mutation::PublishNode { tenant_id, name, version, promote, .. } => {
                let n = before.node_version(tenant_id, name, *version);
                d(
                    Some(tenant_id),
                    "node.publish",
                    n.map_or(name.as_str(), |n| n.id.as_str()),
                    json!({"name": name, "version": version, "hash": n.map(|n| &n.hash), "promoted": promote,
                           "previous_live": before.promotion(tenant_id, name).map(|p| p.version)}),
                )
            }
            Mutation::PromoteNode { tenant_id, name, version, .. } => {
                let n = before.node_version(tenant_id, name, *version);
                d(
                    Some(tenant_id),
                    "node.promote",
                    n.map_or(name.as_str(), |n| n.id.as_str()),
                    json!({"name": name, "version": version, "hash": n.map(|n| &n.hash),
                           "previous_live": before.promotion(tenant_id, name).map(|p| p.version)}),
                )
            }
            Mutation::RetireNode { tenant_id, name, version, .. } => {
                let n = before.node_version(tenant_id, name, *version);
                d(
                    Some(tenant_id),
                    "node.retire",
                    n.map_or(name.as_str(), |n| n.id.as_str()),
                    json!({"name": name, "version": version, "hash": n.map(|n| &n.hash),
                           "was_live": before.promotion(tenant_id, name).is_some_and(|p| p.version == *version)}),
                )
            }
            Mutation::DeleteNode { tenant_id, id, .. } => {
                let n = before.live_node(tenant_id, id);
                d(
                    Some(tenant_id),
                    "node.delete",
                    id,
                    json!({"name": n.map(|x| &x.name), "version": n.map(|x| x.version)}),
                )
            }
            Mutation::CreateToolServer(s) => d(
                Some(&s.tenant_id),
                "tool_server.create",
                &s.id,
                json!({"name": s.name, "url": s.url, "auth": s.auth, "trusted": s.trusted, "has_credential": s.secret.is_some()}),
            ),
            Mutation::DeleteToolServer { tenant_id, name, .. } => {
                let s = before.tool_server(tenant_id, name);
                d(
                    Some(tenant_id),
                    "tool_server.delete",
                    s.map_or(name.as_str(), |s| s.id.as_str()),
                    json!({"name": name}),
                )
            }
            Mutation::RecordToolManifests { tenant_id, server, manifests } => d(
                Some(tenant_id),
                "tool.discover",
                server,
                json!({"server": server, "manifests": manifests.iter().map(|m| json!({"tool": m.name, "pin": m.pin, "findings": m.findings.len()})).collect::<Vec<_>>()}),
            ),
            Mutation::ApproveTool { tenant_id, server, tool, pin, acknowledge_findings, .. } => {
                let m = before
                    .tool_manifests
                    .iter()
                    .find(|m| &m.tenant_id == tenant_id && &m.server == server && &m.name == tool && &m.pin == pin);
                d(
                    Some(tenant_id),
                    "tool.approve",
                    m.map_or(tool.as_str(), |m| m.id.as_str()),
                    json!({"server": server, "tool": tool, "pin": pin, "findings": m.map(|m| &m.findings),
                           "findings_acknowledged": acknowledge_findings}),
                )
            }
            Mutation::RevokeTool { tenant_id, server, tool, pin } => {
                d(Some(tenant_id), "tool.revoke", tool, json!({"server": server, "tool": tool, "pin": pin}))
            }
            Mutation::ProposeOntology { tenant_id, elements } => d(
                Some(tenant_id),
                "ontology.propose",
                tenant_id,
                json!({"elements": elements.iter().map(|e| e.id.as_str()).collect::<Vec<_>>()}),
            ),
            Mutation::ReviewOntologyElement { id, status } => d(None, "ontology.review", id, json!({"status": status})),
            Mutation::CreateDek { tenant_id, dek } => {
                d(Some(tenant_id), "tenant_key.create", tenant_id, json!({"kek_id": dek.wrapped.kek_id}))
            }
            Mutation::Rekey(r) => AuditDraft {
                tenant_id: None,
                action: if r.rotate { "keys.rotate" } else { "keys.migrate" },
                target: None,
                detail: r.summary(),
            },
            Mutation::Login { user, session } => {
                let known = before.user_by_subject(&user.issuer, &user.subject);
                d(
                    None,
                    "auth.login",
                    known.map_or(&user.id, |u| &u.id),
                    json!({"issuer": user.issuer, "subject": user.subject, "email": user.email, "name": user.name,
                           "session": session.id, "groups": session.groups, "new_user": known.is_none()}),
                )
            }
            Mutation::Logout { session_id, user_id, .. } => {
                d(None, "auth.logout", user_id, json!({"session": session_id}))
            }
            Mutation::CreateUser(u) => d(
                None,
                "user.create",
                &u.id,
                json!({"issuer": u.issuer, "subject": u.subject, "email": u.email, "name": u.name}),
            ),
            Mutation::RevokeUserSessions { user_id, .. } => d(
                None,
                "user.sessions_revoke",
                user_id,
                json!({"email": before.user(user_id).and_then(|u| u.email.as_ref())}),
            ),
            Mutation::CreateRoleBinding(b) => {
                d(b.tenant_id.as_deref(), "role_binding.create", &b.id, binding_detail(before, b))
            }
            Mutation::DeleteRoleBinding { id } => {
                let b = before.role_bindings.iter().find(|b| &b.id == id);
                d(
                    b.and_then(|b| b.tenant_id.as_deref()),
                    "role_binding.delete",
                    id,
                    b.map_or_else(|| json!({}), |b| binding_detail(before, b)),
                )
            }
            Mutation::Record(draft) => draft.clone(),
        }
    }
}

/// What a role binding grants to whom (a user subject also shows the user's email).
fn binding_detail(st: &State, b: &RoleBinding) -> Value {
    let email = match b.subject_kind {
        SubjectKind::User => st.user(&b.subject).and_then(|u| u.email.clone()),
        SubjectKind::Group => None,
    };
    json!({"subject_kind": b.subject_kind, "subject": b.subject, "email": email, "role": b.role, "tenant_id": b.tenant_id})
}

/// Validation hook the backend runs inside the transaction, before the audit row and commit.
pub type Check<'a> = &'a (dyn Fn(&State) -> Result<(), String> + Send + Sync);

#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    /// Full committed state.
    async fn load(&self) -> Result<State, StoreError>;
    /// Audit head (cheap change detection for multi-replica control planes).
    async fn head(&self) -> Result<u64, StoreError>;
    /// Atomically: apply `m`, run `check` on the resulting state, append the audit row, commit.
    /// Returns the committed state.
    async fn apply(&self, actor: &str, m: &Mutation, check: Check<'_>) -> Result<State, StoreError>;
    /// Newest `limit` audit rows, ascending by `seq`.
    async fn audit(&self, limit: usize) -> Result<Vec<AuditEntry>, StoreError>;

    // Sessions and pending logins: per-request reads and housekeeping, not audited. Creating and
    // revoking sessions goes through `apply` (`Login`, `Logout`, `RevokeUserSessions`).

    /// The session whose token hashes to `token_sha256`, revoked or expired ones included.
    async fn session(&self, token_sha256: &str) -> Result<Option<SessionRecord>, StoreError>;
    /// Records activity (idle timeout).
    async fn touch_session(&self, id: &str, at: DateTime<Utc>) -> Result<(), StoreError>;
    /// Sessions of a user that are neither revoked nor expired at `now`.
    async fn active_sessions(&self, user_id: &str, now: DateTime<Utc>) -> Result<Vec<SessionRecord>, StoreError>;
    async fn put_login(&self, login: &PendingLogin) -> Result<(), StoreError>;
    /// Removes and returns the pending login (single use), expired or not.
    async fn take_login(&self, state: &str) -> Result<Option<PendingLogin>, StoreError>;
    /// Deletes sessions and pending logins that expired before `now`. Returns how many.
    async fn purge_auth(&self, now: DateTime<Utc>) -> Result<u64, StoreError>;

    // Router check-ins (split mode): telemetry, not audited.

    /// Upserts a router's check-in (an older `last_seen` never overwrites a newer one).
    async fn put_router(&self, r: &RouterStatus) -> Result<(), StoreError>;
    /// Every router that ever checked in, most recently seen first.
    async fn routers(&self) -> Result<Vec<RouterStatus>, StoreError>;

    // Usage events (see `usage`). A backend without a durable usage log returns `None` and the
    // store keeps events in its in-memory ring.

    /// Stores events not stored before (by `request_id`; ids are unique within `events`) and
    /// returns how many were new.
    async fn insert_usage(&self, _events: &[caliban_meter::UsageEvent]) -> Result<Option<u64>, StoreError> {
        Ok(None)
    }
    /// The newest events and the totals over every event the filter matches.
    async fn usage_report(&self, _f: &usage::UsageFilter) -> Result<Option<usage::UsageReport>, StoreError> {
        Ok(None)
    }

    /// Moves raw usage events older than `days` (whole UTC days) into the daily roll-up, keeping
    /// every total the same. Returns how many events were moved. Backends without a durable usage
    /// log keep nothing to roll up.
    async fn rollup_usage(&self, _days: u32) -> Result<u64, StoreError> {
        Ok(0)
    }

    /// The oldest timestamp a raw usage event may have with this retention (midnight UTC, `days`
    /// days ago, by the database clock); `None` when the backend rolls nothing up.
    async fn usage_boundary(&self, _days: u32) -> Result<Option<DateTime<Utc>>, StoreError> {
        Ok(None)
    }
}

/// What a split-mode router reported on its last snapshot poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterStatus {
    pub router_id: String,
    pub last_seen: DateTime<Utc>,
    /// Version label of the snapshot the router serves.
    pub snapshot_version: String,
    /// KEKs that sealed the secrets of that snapshot.
    pub snapshot_kek_ids: Vec<String>,
    /// The router's keyring, current KEK first.
    pub keyring: Vec<String>,
}

/// A router is reported as active when it checked in within this window (routers poll every
/// `CALIBAN_SNAPSHOT_POLL_SECS`, default 10 s).
pub const ROUTER_ACTIVE_SECS: i64 = 600;
/// While nothing changes, a check-in is written at most this often per router.
const ROUTER_WRITE_EVERY_SECS: i64 = 60;

pub struct Store {
    backend: Arc<dyn Backend>,
    cache: RwLock<Arc<State>>,
    /// Config file: process settings, and the seed for an empty store.
    base: Config,
    pub config: ConfigHandle,
    pub usage: RecentUsage,
    /// Last check-in written per router (throttles writes while nothing changes).
    router_writes: parking_lot::Mutex<std::collections::HashMap<String, RouterStatus>>,
    /// Deduplication of ingested usage events when the backend keeps no usage log (memory).
    memory_usage: usage::MemoryUsage,
    /// Raw usage retention in days (0: forever); see [`Store::rollup_usage`].
    usage_retention_days: std::sync::atomic::AtomicU32,
}

impl Store {
    /// In-memory store seeded from the config file.
    pub fn new(base: Config, config: ConfigHandle, usage: RecentUsage) -> Self {
        let backend = memory::MemoryBackend::seeded(State::from_config(&base));
        let state = backend.state();
        Self::with_backend(Arc::new(backend), state, base, config, usage)
    }

    /// Postgres store: runs migrations, seeds from the config file if the database has never been
    /// seeded, then loads the database state (which wins over the file from then on).
    pub async fn postgres(
        url: &str,
        base: Config,
        config: ConfigHandle,
        usage: RecentUsage,
    ) -> Result<Self, StoreError> {
        let pg = postgres::PgBackend::connect(url).await?;
        Self::open_postgres(pg, base, config, usage).await
    }

    pub async fn open_postgres(
        pg: postgres::PgBackend,
        base: Config,
        config: ConfigHandle,
        usage: RecentUsage,
    ) -> Result<Self, StoreError> {
        pg.migrate().await?;
        if pg.seed_if_empty(&State::from_config(&base)).await? {
            tracing::info!("postgres store was empty: seeded from the config file");
        } else if !base.tenants.is_empty() || !base.models.is_empty() || !base.providers.is_empty() {
            tracing::info!(
                "postgres store already seeded: [[tenants]], [[models]] and [[providers]] in the config file are ignored (the database is the source of truth)"
            );
        }
        let state = pg.load().await?;
        Ok(Self::with_backend(Arc::new(pg), state, base, config, usage))
    }

    fn with_backend(
        backend: Arc<dyn Backend>,
        state: State,
        base: Config,
        config: ConfigHandle,
        usage: RecentUsage,
    ) -> Self {
        let s = Self {
            backend,
            cache: RwLock::new(Arc::new(State::default())),
            base,
            config,
            usage,
            router_writes: parking_lot::Mutex::default(),
            memory_usage: usage::MemoryUsage::new(),
            usage_retention_days: std::sync::atomic::AtomicU32::new(usage::DEFAULT_RETENTION_DAYS),
        };
        s.install(state);
        s
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    pub fn base(&self) -> &Config {
        &self.base
    }

    /// Committed state (read cache).
    pub fn state(&self) -> Arc<State> {
        Arc::clone(&self.cache.read())
    }

    /// Applies one mutation as `actor` and republishes the data-plane snapshot.
    pub async fn apply(&self, actor: &str, m: Mutation) -> Result<Arc<State>, StoreError> {
        let base = &self.base;
        let check = move |st: &State| check(base, st);
        let st = self.backend.apply(actor, &m, &check).await?;
        Ok(self.install(st))
    }

    pub async fn audit(&self, limit: usize) -> Result<Vec<AuditEntry>, StoreError> {
        self.backend.audit(limit).await
    }

    pub async fn session(&self, token_sha256: &str) -> Result<Option<SessionRecord>, StoreError> {
        self.backend.session(token_sha256).await
    }

    pub async fn touch_session(&self, id: &str, at: DateTime<Utc>) -> Result<(), StoreError> {
        self.backend.touch_session(id, at).await
    }

    pub async fn active_sessions(&self, user_id: &str, now: DateTime<Utc>) -> Result<Vec<SessionRecord>, StoreError> {
        self.backend.active_sessions(user_id, now).await
    }

    pub async fn put_login(&self, login: &PendingLogin) -> Result<(), StoreError> {
        self.backend.put_login(login).await
    }

    pub async fn take_login(&self, state: &str) -> Result<Option<PendingLogin>, StoreError> {
        self.backend.take_login(state).await
    }

    pub async fn purge_auth(&self, now: DateTime<Utc>) -> Result<u64, StoreError> {
        self.backend.purge_auth(now).await
    }

    /// Records a router check-in. Written when anything but `last_seen` changed, or at most once
    /// every [`ROUTER_WRITE_EVERY_SECS`] otherwise.
    pub async fn router_checkin(&self, r: RouterStatus) -> Result<(), StoreError> {
        let due = {
            let mut w = self.router_writes.lock();
            let due = w.get(&r.router_id).is_none_or(|last| {
                last.snapshot_version != r.snapshot_version
                    || last.snapshot_kek_ids != r.snapshot_kek_ids
                    || last.keyring != r.keyring
                    || (r.last_seen - last.last_seen).num_seconds() >= ROUTER_WRITE_EVERY_SECS
            });
            if due {
                w.insert(r.router_id.clone(), r.clone());
            }
            due
        };
        if due && let Err(e) = self.backend.put_router(&r).await {
            // Retried on the next poll.
            self.router_writes.lock().remove(&r.router_id);
            return Err(e);
        }
        Ok(())
    }

    /// Stores usage events delivered by a data plane, at most once per `request_id` (see
    /// [`usage`]). Invalid events are counted as rejected and dropped.
    pub async fn ingest_usage(&self, events: Vec<caliban_meter::UsageEvent>) -> Result<usage::Ingested, StoreError> {
        let mut out = usage::Ingested::default();
        let mut ids = std::collections::HashSet::new();
        let mut batch = Vec::with_capacity(events.len());
        let days = self.usage_retention_days.load(std::sync::atomic::Ordering::Relaxed);
        // The database clock: every control-plane replica and the roll-up agree on the boundary.
        let oldest = if days > 0 { self.backend.usage_boundary(days).await? } else { None };
        for e in events {
            if oldest.is_some_and(|b| e.ts < b) {
                // Its day may already be rolled up: a retry could not be told from a new event.
                tracing::warn!(request_id = %e.request_id, ts = %e.ts, "refused a usage event older than the usage retention");
                out.rejected += 1;
            } else if !usage::valid_event(&e) {
                out.rejected += 1;
            } else if !ids.insert(e.request_id.clone()) {
                out.duplicates += 1;
            } else {
                batch.push(e);
            }
        }
        if batch.is_empty() {
            return Ok(out);
        }
        match self.backend.insert_usage(&batch).await? {
            Some(new) => {
                out.accepted += new;
                out.duplicates += batch.len() as u64 - new;
            }
            None => {
                let m = self.memory_usage.ingest(&self.usage, batch).await;
                out.accepted += m.accepted;
                out.duplicates += m.duplicates;
            }
        }
        Ok(out)
    }

    /// Usage events (newest first, at most `limit`) and totals, over `tenants` (`None`: all).
    pub async fn usage_report(
        &self,
        tenants: Option<&[String]>,
        limit: usize,
    ) -> Result<usage::UsageReport, StoreError> {
        let f = usage::UsageFilter { tenants: tenants.map(<[String]>::to_vec), limit, ..Default::default() };
        self.usage_query(&f).await
    }

    /// Usage events and totals matching `f` (tenants, node, run).
    pub async fn usage_query(&self, f: &usage::UsageFilter) -> Result<usage::UsageReport, StoreError> {
        match self.backend.usage_report(f).await? {
            Some(r) => Ok(r),
            None => Ok(usage::MemoryUsage::report(&self.usage, f)),
        }
    }

    /// Usage retention: raw events older than `days` move into the daily roll-up (Postgres; see
    /// [`usage`]). Safe to run on several control planes at once (one at a time does the work).
    pub async fn rollup_usage(&self, days: u32) -> Result<u64, StoreError> {
        if days == 0 {
            return Ok(0);
        }
        self.backend.rollup_usage(days).await
    }

    /// Events older than the raw retention cannot be deduplicated any more (their day was rolled
    /// up): ingestion refuses them.
    pub fn set_usage_retention_days(&self, days: u32) {
        self.usage_retention_days.store(days, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether usage events are kept in the backend (Postgres) rather than the process ring. A
    /// standalone data plane then ships its own events to the store too.
    pub fn durable_usage(&self) -> bool {
        self.backend.name() == "postgres"
    }

    /// Router check-ins, most recently seen first.
    pub async fn routers(&self) -> Result<Vec<RouterStatus>, StoreError> {
        self.backend.routers().await
    }

    /// Reloads from the backend if another control-plane replica committed changes.
    pub async fn refresh(&self) -> Result<bool, StoreError> {
        if self.backend.head().await? == self.cache.read().audit_head {
            return Ok(false);
        }
        let st = self.backend.load().await?;
        self.install(st);
        Ok(true)
    }

    /// Plans and applies a key migration (`rotate = false`, run at control-plane startup) or a
    /// KEK rotation (`rotate = true`, `caliban keys rotate`). Idempotent: when there is nothing to
    /// do, nothing is written or audited. Replans if a concurrent write got in between.
    ///
    /// A rotation is all or nothing: any item it cannot handle (for example a DEK wrapped by a KEK
    /// missing from the keyring) fails it before anything is written. The startup migration
    /// applies what it can and returns the problems.
    pub async fn rekey(
        &self,
        keyring: &Keyring,
        rotate: bool,
        actor: &str,
    ) -> Result<(Rekey, Vec<String>), StoreError> {
        let mut attempts = 0;
        loop {
            self.refresh().await?;
            let (plan, problems) = crate::keys::plan(&self.state(), keyring, rotate);
            if rotate && !problems.is_empty() {
                return Err(StoreError::Invalid(format!("rotation not started: {}", problems.join("; "))));
            }
            if plan.is_empty() {
                return Ok((plan, problems));
            }
            match self.apply(actor, Mutation::Rekey(plan.clone())).await {
                Ok(_) => return Ok((plan, problems)),
                Err(StoreError::Conflict(_)) if attempts < 3 => attempts += 1,
                Err(e) => return Err(e),
            }
        }
    }

    /// Swaps the read cache (never backwards) and republishes the snapshot.
    fn install(&self, st: State) -> Arc<State> {
        let mut cache = self.cache.write();
        if st.audit_head < cache.audit_head {
            return Arc::clone(&cache);
        }
        let st = Arc::new(st);
        *cache = Arc::clone(&st);
        // Held under the cache lock so snapshots are published in state order.
        self.publish(&st);
        st
    }

    /// Re-renders the data-plane snapshot. Fail-static: an invalid render (which `check` should
    /// make impossible) is logged and the previous snapshot keeps serving.
    fn publish(&self, st: &State) {
        match render(&self.base, st).and_then(|c| c.validate().map(|()| c).map_err(|e| e.to_string())) {
            Ok(cfg) => self.config.store(Snapshot::new(cfg, format!("cp-{}", st.audit_head))),
            Err(e) => tracing::error!(error = %e, "rendered config is invalid; keeping previous snapshot"),
        }
    }
}

pub fn default_base_url(kind: ProviderKind) -> Option<String> {
    match kind {
        ProviderKind::Openai => Some("https://api.openai.com/v1".into()),
        ProviderKind::Anthropic => Some("https://api.anthropic.com/v1".into()),
        _ => None,
    }
}

pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::now_v7().simple())
}

pub fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}
