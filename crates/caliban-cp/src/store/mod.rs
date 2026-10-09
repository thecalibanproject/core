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

pub mod audit;
pub mod memory;
pub mod postgres;
#[cfg(test)]
mod tests;

use audit::{AuditDraft, AuditEntry};
use caliban_config::{
    Config, ConfigHandle, Keyring, ModelEntry, ProviderConfig, RouteConfig, SecretRef, SharedProvider, Snapshot,
    TenantConfig, TenantSealed, WrappedDek,
};
use caliban_meter::RecentUsage;
use caliban_ontology::{Element, Ontology, Status};
use caliban_types::{PiiMode, PiiSurrogateScope, ProviderKind, SemanticCacheMode, TrustTier};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;
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

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NodeRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub version: u32,
    pub spec: Value,
    pub created_at: DateTime<Utc>,
    /// Soft delete; deleted node versions are never returned by the API, and their version
    /// numbers are not reused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
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
    pub ontologies: BTreeMap<String, Ontology>,
    /// Tenant → wrapped DEK. Created on the tenant's first secret, destroyed with the tenant.
    pub deks: BTreeMap<String, DekRecord>,
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
            serde_json::from_value::<TenantConfig>(Value::Object(obj)).map_err(|e| format!("tenant {}: {e}", t.id))
        })
        .collect::<Result<_, _>>()?;
    Ok(cfg)
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
    /// `version` is assigned by the store (latest version for (tenant, name) + 1).
    CreateNode(NodeRecord),
    /// Soft-deletes one node version.
    DeleteNode {
        tenant_id: String,
        id: String,
        at: DateTime<Utc>,
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
                d(Some(id), "tenant.update", id, detail)
            }
            Mutation::CreateApiKey(k) => {
                d(Some(&k.tenant_id), "api_key.create", &k.id, json!({"name": k.name, "prefix": k.prefix}))
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
            Mutation::CreateNode(n) => d(Some(&n.tenant_id), "node.create", &n.id, json!({"name": n.name})),
            Mutation::DeleteNode { tenant_id, id, .. } => {
                let n = before.live_node(tenant_id, id);
                d(
                    Some(tenant_id),
                    "node.delete",
                    id,
                    json!({"name": n.map(|x| &x.name), "version": n.map(|x| x.version)}),
                )
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
        }
    }
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
}

pub struct Store {
    backend: Arc<dyn Backend>,
    cache: RwLock<Arc<State>>,
    /// Config file: process settings, and the seed for an empty store.
    base: Config,
    pub config: ConfigHandle,
    pub usage: RecentUsage,
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
        let s = Self { backend, cache: RwLock::new(Arc::new(State::default())), base, config, usage };
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
