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

pub mod audit;
pub mod memory;
pub mod postgres;
#[cfg(test)]
mod tests;

use audit::{AuditDraft, AuditEntry};
use caliban_config::{Config, ConfigHandle, ModelEntry, ProviderConfig, RouteConfig, SecretRef, SharedProvider, Snapshot, TenantConfig};
use caliban_meter::RecentUsage;
use caliban_ontology::{Element, Ontology, Status};
use caliban_types::{PiiMode, ProviderKind, TrustTier};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub region: Option<String>,
    pub pii_default: PiiMode,
    pub created_at: DateTime<Utc>,
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
    pub secret: Option<SecretRef>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DatasourceRecord {
    pub id: String,
    pub tenant_id: String,
    pub kind: String,
    pub name: String,
    pub status: String,
    pub epoch: u64,
    #[serde(skip)]
    pub connection: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NodeRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub version: u32,
    pub spec: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct State {
    /// Model catalogue.
    pub models: Vec<ModelEntry>,
    /// Deployment-wide providers, e.g. on-prem model servers shared by all tenants.
    pub shared_providers: Vec<SharedProvider>,
    pub tenants: Vec<Tenant>,
    pub api_keys: Vec<ApiKeyRecord>,
    pub provider_keys: Vec<ProviderKeyRecord>,
    /// Tenant → ordered routes (first model preferred, the rest are fallbacks).
    pub routes: BTreeMap<String, Vec<RouteConfig>>,
    pub datasources: Vec<DatasourceRecord>,
    pub nodes: Vec<NodeRecord>,
    pub ontologies: BTreeMap<String, Ontology>,
    /// Sequence number of the last audit row; doubles as the state version.
    pub audit_head: u64,
}

impl State {
    /// Initial state from the config file (the in-memory store, or the first Postgres start).
    pub fn from_config(base: &Config) -> Self {
        let now = audit::now_micros();
        let mut st = State { models: base.models.clone(), shared_providers: base.providers.clone(), ..State::default() };
        for t in &base.tenants {
            st.tenants.push(Tenant {
                id: t.id.to_string(),
                name: t.name.clone(),
                region: None,
                pii_default: t.pii_mode.unwrap_or(base.pii.default_mode),
                created_at: now,
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
                    secret: p.api_key.clone(),
                });
            }
            if !t.routes.is_empty() {
                st.routes.insert(t.id.to_string(), t.routes.clone());
            }
        }
        st
    }

    pub fn tenant(&self, id: &str) -> Option<&Tenant> {
        self.tenants.iter().find(|t| t.id == id)
    }

    pub fn has_tenant(&self, id: &str) -> bool {
        self.tenant(id).is_some()
    }
}

/// `TenantConfig` fields the store models explicitly; anything else is kept in `settings`.
const TENANT_FIELDS: &[&str] = &["id", "name", "pii_mode", "api_key_hashes", "providers", "routes"];

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
pub fn render(base: &Config, st: &State) -> Result<Config, String> {
    let mut cfg = base.clone();
    cfg.models = st.models.clone();
    cfg.providers = st.shared_providers.clone();
    cfg.tenants = st
        .tenants
        .iter()
        .map(|t| {
            let providers: Vec<ProviderConfig> = st
                .provider_keys
                .iter()
                .filter(|p| p.tenant_id == t.id)
                .filter_map(|p| {
                    Some(ProviderConfig {
                        id: p.id.as_str().into(),
                        kind: p.kind,
                        base_url: p.base_url.clone().or_else(|| default_base_url(p.kind))?,
                        trust_tier: p.trust_tier,
                        api_key: p.secret.clone(),
                        cache_salt: p.cache_salt,
                    })
                })
                .collect();
            // Built through serde so fields this crate does not model (in `settings`) pass through.
            let mut obj = t.settings.clone();
            obj.insert("id".into(), json!(t.id));
            obj.insert("name".into(), json!(t.name));
            obj.insert("pii_mode".into(), json!(t.pii_default));
            obj.insert(
                "api_key_hashes".into(),
                json!(st.api_keys.iter().filter(|k| k.tenant_id == t.id).map(|k| &k.hash).collect::<Vec<_>>()),
            );
            obj.insert("providers".into(), serde_json::to_value(providers).map_err(|e| e.to_string())?);
            obj.insert("routes".into(), serde_json::to_value(st.routes.get(&t.id).cloned().unwrap_or_default()).map_err(|e| e.to_string())?);
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
    CreateProviderKey(ProviderKeyRecord),
    DeleteProviderKey { tenant_id: String, id: String },
    CreateModel(ModelEntry),
    DeleteModel(String),
    CreateSharedProvider(SharedProvider),
    DeleteSharedProvider(String),
    SetRoutes { tenant_id: String, routes: Vec<RouteConfig> },
    CreateDatasource(DatasourceRecord),
    SetDatasourceStatus { id: String, status: String },
    /// `version` is assigned by the store (latest version for (tenant, name) + 1).
    CreateNode(NodeRecord),
    /// Upserts elements (e.g. proposals from the bootstrap job) as one new ontology version.
    ProposeOntology { tenant_id: String, elements: Vec<Element> },
    ReviewOntologyElement { id: String, status: Status },
}

impl Mutation {
    /// What goes into the audit log. Never secrets: API keys show the prefix, BYOK keys last4.
    pub fn audit(&self) -> AuditDraft {
        let d = |tenant: Option<&str>, action, target: &str, detail| AuditDraft {
            tenant_id: tenant.map(str::to_owned),
            action,
            target: Some(target.to_owned()),
            detail,
        };
        match self {
            Mutation::CreateTenant(t) => d(Some(&t.id), "tenant.create", &t.id, json!({"name": t.name})),
            Mutation::CreateApiKey(k) => d(Some(&k.tenant_id), "api_key.create", &k.id, json!({"name": k.name, "prefix": k.prefix})),
            Mutation::CreateProviderKey(p) => d(
                Some(&p.tenant_id),
                "provider_key.create",
                &p.id,
                json!({"kind": p.kind, "base_url": p.base_url, "trust_tier": p.trust_tier, "last4": p.last4}),
            ),
            Mutation::DeleteProviderKey { tenant_id, id } => d(Some(tenant_id), "provider_key.delete", id, json!({})),
            Mutation::CreateModel(m) => {
                d(None, "model.create", m.id.as_str(), json!({"provider": m.provider, "upstream_model": m.upstream_model}))
            }
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
            Mutation::CreateDatasource(ds) => {
                d(Some(&ds.tenant_id), "datasource.create", &ds.id, json!({"kind": ds.kind, "name": ds.name}))
            }
            Mutation::SetDatasourceStatus { id, status } => d(None, "datasource.status", id, json!({"status": status})),
            Mutation::CreateNode(n) => d(Some(&n.tenant_id), "node.create", &n.id, json!({"name": n.name})),
            Mutation::ProposeOntology { tenant_id, elements } => d(
                Some(tenant_id),
                "ontology.propose",
                tenant_id,
                json!({"elements": elements.iter().map(|e| e.id.as_str()).collect::<Vec<_>>()}),
            ),
            Mutation::ReviewOntologyElement { id, status } => d(None, "ontology.review", id, json!({"status": status})),
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
    pub async fn postgres(url: &str, base: Config, config: ConfigHandle, usage: RecentUsage) -> Result<Self, StoreError> {
        let pg = postgres::PgBackend::connect(url).await?;
        Self::open_postgres(pg, base, config, usage).await
    }

    pub async fn open_postgres(pg: postgres::PgBackend, base: Config, config: ConfigHandle, usage: RecentUsage) -> Result<Self, StoreError> {
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

    fn with_backend(backend: Arc<dyn Backend>, state: State, base: Config, config: ConfigHandle, usage: RecentUsage) -> Self {
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
