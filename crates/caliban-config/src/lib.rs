//! Configuration snapshot for the data plane.
//!
//! In standalone/on-prem mode the snapshot is loaded from a TOML file. In connected mode the
//! control plane renders the same structure and serves it as an Ed25519-signed snapshot that
//! routers poll and verify (see [`signing`]). The data plane
//! only ever reads an immutable `Snapshot` behind an `ArcSwap`, and keeps serving the last good
//! snapshot if a reload fails (fail-static).

mod secret;
pub mod signing;

pub use secret::{Secret, SecretRef, open, process_kek, seal};

use arc_swap::ArcSwap;
use caliban_types::{ModelId, PiiMode, PiiSurrogateScope, ProviderId, ProviderKind, TenantId, TrustTier};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config file {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("parsing config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
    #[error("secret {0}: {1}")]
    Secret(String, String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub pii: PiiConfig,
    /// Deployment-wide model servers (on-prem pools) usable by every tenant unless restricted.
    #[serde(default)]
    pub providers: Vec<SharedProvider>,
    #[serde(default)]
    pub models: Vec<ModelEntry>,
    #[serde(default)]
    pub tenants: Vec<TenantConfig>,
    /// Rate limits and token budgets: deployment defaults plus per-tenant overrides.
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Request-rate and token-budget limits. Every field is optional (`None` = unlimited).
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// GCRA request rate per tenant.
    pub requests_per_minute: Option<u32>,
    /// GCRA request rate per API key (on top of the tenant rate).
    pub key_requests_per_minute: Option<u32>,
    /// Token budget refilling continuously over a minute (reserved: prompt estimate + max_tokens).
    pub tokens_per_minute: Option<u64>,
    /// Token budget per UTC day.
    pub tokens_per_day: Option<u64>,
    /// Spend budget per UTC day (needs model prices).
    pub usd_per_day: Option<f64>,
}

impl Limits {
    /// Field-wise override: `Some` in `over` wins.
    pub fn overlay(&self, over: &Limits) -> Limits {
        Limits {
            requests_per_minute: over.requests_per_minute.or(self.requests_per_minute),
            key_requests_per_minute: over.key_requests_per_minute.or(self.key_requests_per_minute),
            tokens_per_minute: over.tokens_per_minute.or(self.tokens_per_minute),
            tokens_per_day: over.tokens_per_day.or(self.tokens_per_day),
            usd_per_day: over.usd_per_day.or(self.usd_per_day),
        }
    }
}

/// `[limits]` (defaults for every tenant) and `[limits.tenants.<tenant_id>]` (overrides).
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    pub requests_per_minute: Option<u32>,
    pub key_requests_per_minute: Option<u32>,
    pub tokens_per_minute: Option<u64>,
    pub tokens_per_day: Option<u64>,
    pub usd_per_day: Option<f64>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tenants: std::collections::BTreeMap<TenantId, Limits>,
}

impl LimitsConfig {
    pub fn defaults(&self) -> Limits {
        Limits {
            requests_per_minute: self.requests_per_minute,
            key_requests_per_minute: self.key_requests_per_minute,
            tokens_per_minute: self.tokens_per_minute,
            tokens_per_day: self.tokens_per_day,
            usd_per_day: self.usd_per_day,
        }
    }

    /// Effective limits for a tenant.
    pub fn for_tenant(&self, tenant: &TenantId) -> Limits {
        match self.tenants.get(tenant) {
            Some(over) => self.defaults().overlay(over),
            None => self.defaults(),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for (who, l) in std::iter::once(("defaults".to_owned(), self.defaults())).chain(self.tenants.iter().map(|(t, l)| (t.to_string(), l.clone()))) {
            if l.requests_per_minute == Some(0) || l.key_requests_per_minute == Some(0) {
                return Err(ConfigError::Invalid(format!("limits ({who}): requests_per_minute must be > 0 (omit it for unlimited)")));
            }
            if l.usd_per_day.is_some_and(|u| !u.is_finite() || u < 0.0) {
                return Err(ConfigError::Invalid(format!("limits ({who}): usd_per_day must be a non-negative number")));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_router_addr")]
    pub router_addr: String,
    #[serde(default = "default_cp_addr")]
    pub control_plane_addr: String,
    pub web_dir: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { router_addr: default_router_addr(), control_plane_addr: default_cp_addr(), web_dir: None }
    }
}

fn default_router_addr() -> String {
    "0.0.0.0:8080".into()
}
fn default_cp_addr() -> String {
    "0.0.0.0:8081".into()
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EgressPolicy {
    /// Only base_urls declared under tenant providers are reachable.
    #[default]
    DenyByDefault,
    Open,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default)]
    pub egress: EgressPolicy,
    pub admin_token: Option<SecretRef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default = "yes")]
    pub exact_enabled: bool,
    #[serde(default = "default_cache_entries")]
    pub exact_max_entries: u64,
    #[serde(default = "default_cache_ttl")]
    pub exact_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { exact_enabled: true, exact_max_entries: default_cache_entries(), exact_ttl_secs: default_cache_ttl() }
    }
}

fn yes() -> bool {
    true
}
fn default_cache_entries() -> u64 {
    100_000
}
fn default_cache_ttl() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PiiConfig {
    #[serde(default)]
    pub default_mode: PiiMode,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEntry {
    pub id: ModelId,
    /// A shared provider, or a provider the tenant defines itself (BYOK).
    pub provider: ProviderId,
    pub upstream_model: String,
    #[serde(default)]
    pub kind: ModelKind,
    /// Model family (e.g. `qwen3`, `gpt-oss`); decides request/response quirks.
    pub family: Option<String>,
    #[serde(default)]
    pub capabilities: Capabilities,
    pub trust_tier: TrustTier,
    pub licence: Option<String>,
    pub context_window: Option<u32>,
    pub price_in_per_mtok: Option<f64>,
    pub price_out_per_mtok: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub id: TenantId,
    pub name: String,
    pub pii_mode: Option<PiiMode>,
    /// How far reversible surrogates stay the same: `tenant` (default; same value, same
    /// surrogate in every request of the tenant, so pseudonymised requests can hit the cache) or
    /// `session` (fresh surrogates per request, unlinkable, no cache hits for PII requests).
    /// Omitted from the rendered snapshot when it is the default.
    #[serde(default, skip_serializing_if = "PiiSurrogateScope::is_default")]
    pub pii_surrogate_scope: PiiSurrogateScope,
    #[serde(default)]
    pub api_key_hashes: Vec<String>,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    #[default]
    Chat,
    Embedding,
    Rerank,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reasoning {
    /// No reasoning phase.
    #[default]
    None,
    /// Always reasons (e.g. thinking-only checkpoints).
    Always,
    /// Reasoning can be switched on/off per request (e.g. Qwen3 hybrid thinking).
    Hybrid,
}

/// How a request's reasoning preference is passed to the upstream.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningControl {
    #[default]
    None,
    /// `chat_template_kwargs: {"enable_thinking": bool}` (Qwen3 on vLLM/SGLang).
    EnableThinking,
    /// OpenAI-style `reasoning_effort: low|medium|high` (gpt-oss, OpenAI).
    ReasoningEffort,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub tools: bool,
    #[serde(default)]
    pub vision: bool,
    #[serde(default)]
    pub reasoning: Reasoning,
    #[serde(default)]
    pub reasoning_control: ReasoningControl,
    /// The server returns `<think>…</think>` inside `content` (no reasoning parser enabled);
    /// Caliban moves it to `reasoning_content`.
    #[serde(default)]
    pub inline_think_tags: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub id: ProviderId,
    pub kind: ProviderKind,
    pub base_url: String,
    pub trust_tier: TrustTier,
    /// BYOK credential. Optional for keyless local endpoints.
    pub api_key: Option<SecretRef>,
    /// Send a per-tenant `cache_salt` so the engine's prefix cache is not shared across tenants
    /// (vLLM). Only enable for engines that accept the field.
    #[serde(default)]
    pub cache_salt: bool,
}

/// A deployment-wide provider (e.g. an on-prem vLLM pool), optionally restricted to some tenants.
/// Deserialized through [`SharedProviderToml`] so unknown keys (e.g. a `cache_salts` typo) are
/// rejected; serde cannot combine `deny_unknown_fields` with `flatten`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(from = "SharedProviderToml", into = "SharedProviderToml")]
pub struct SharedProvider {
    pub provider: ProviderConfig,
    /// Allow-list of tenants; empty = all tenants.
    pub tenants: Vec<TenantId>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SharedProviderToml {
    id: ProviderId,
    kind: ProviderKind,
    base_url: String,
    trust_tier: TrustTier,
    api_key: Option<SecretRef>,
    #[serde(default)]
    cache_salt: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tenants: Vec<TenantId>,
}

impl From<SharedProviderToml> for SharedProvider {
    fn from(t: SharedProviderToml) -> Self {
        Self {
            provider: ProviderConfig {
                id: t.id,
                kind: t.kind,
                base_url: t.base_url,
                trust_tier: t.trust_tier,
                api_key: t.api_key,
                cache_salt: t.cache_salt,
            },
            tenants: t.tenants,
        }
    }
}

impl From<SharedProvider> for SharedProviderToml {
    fn from(s: SharedProvider) -> Self {
        let p = s.provider;
        Self { id: p.id, kind: p.kind, base_url: p.base_url, trust_tier: p.trust_tier, api_key: p.api_key, cache_salt: p.cache_salt, tenants: s.tenants }
    }
}

impl SharedProvider {
    pub fn allows(&self, tenant: &TenantId) -> bool {
        self.tenants.is_empty() || self.tenants.contains(tenant)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub intent: String,
    /// Ordered candidates: first is preferred, the rest are fallbacks.
    pub models: Vec<ModelId>,
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let s = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::Io { path: path.display().to_string(), source })?;
        Self::from_toml_str(&s)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let models: HashMap<&ModelId, &ModelEntry> = self.models.iter().map(|m| (&m.id, m)).collect();
        if models.len() != self.models.len() {
            return Err(ConfigError::Invalid("duplicate model id".into()));
        }
        let mut shared_ids = std::collections::HashSet::new();
        for p in &self.providers {
            if !shared_ids.insert(&p.provider.id) {
                return Err(ConfigError::Invalid(format!("duplicate shared provider id '{}'", p.provider.id)));
            }
        }
        let mut seen_hashes = std::collections::HashSet::new();
        for t in &self.tenants {
            for h in &t.api_key_hashes {
                if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(ConfigError::Invalid(format!("tenant {}: api_key_hashes must be sha256 hex", t.id)));
                }
                if !seen_hashes.insert(h.as_str()) {
                    return Err(ConfigError::Invalid(format!("api key hash reused across tenants ({})", t.id)));
                }
            }
            for r in &t.routes {
                for m in &r.models {
                    let Some(entry) = models.get(m) else {
                        return Err(ConfigError::Invalid(format!("tenant {} route {}: unknown model {m}", t.id, r.intent)));
                    };
                    let reachable = t.providers.iter().any(|p| p.id == entry.provider)
                        || self.providers.iter().any(|p| p.provider.id == entry.provider && p.allows(&t.id));
                    if !reachable {
                        return Err(ConfigError::Invalid(format!(
                            "tenant {} route {}: model {m} needs provider '{}' which the tenant has not configured",
                            t.id, r.intent, entry.provider
                        )));
                    }
                }
            }
        }
        self.limits.validate()
    }
}

/// Immutable, indexed view of a `Config` used on the hot path.
#[derive(Debug)]
pub struct Snapshot {
    pub config: Config,
    pub version: String,
    by_key_hash: HashMap<String, usize>,
    by_tenant: HashMap<TenantId, usize>,
    models: HashMap<ModelId, usize>,
}

impl Snapshot {
    pub fn new(config: Config, version: impl Into<String>) -> Self {
        let mut by_key_hash = HashMap::new();
        let mut by_tenant = HashMap::new();
        for (i, t) in config.tenants.iter().enumerate() {
            by_tenant.insert(t.id.clone(), i);
            for h in &t.api_key_hashes {
                by_key_hash.insert(h.to_ascii_lowercase(), i);
            }
        }
        let models = config.models.iter().enumerate().map(|(i, m)| (m.id.clone(), i)).collect();
        Self { config, version: version.into(), by_key_hash, by_tenant, models }
    }

    pub fn tenant_by_key_hash(&self, hash: &str) -> Option<&TenantConfig> {
        self.by_key_hash.get(hash).map(|&i| &self.config.tenants[i])
    }

    pub fn tenant(&self, id: &TenantId) -> Option<&TenantConfig> {
        self.by_tenant.get(id).map(|&i| &self.config.tenants[i])
    }

    pub fn model(&self, id: &ModelId) -> Option<&ModelEntry> {
        self.models.get(id).map(|&i| &self.config.models[i])
    }

    /// Resolves a provider for a tenant: the tenant's own (BYOK) provider wins over a shared one
    /// with the same id.
    pub fn provider_for<'a>(&'a self, tenant: &'a TenantConfig, id: &ProviderId) -> Option<&'a ProviderConfig> {
        tenant.providers.iter().find(|p| &p.id == id).or_else(|| {
            self.config.providers.iter().find(|p| &p.provider.id == id && p.allows(&tenant.id)).map(|p| &p.provider)
        })
    }

    /// Models the tenant can reach through its own or shared providers.
    pub fn models_for<'a>(&'a self, tenant: &'a TenantConfig) -> impl Iterator<Item = &'a ModelEntry> + 'a {
        self.config.models.iter().filter(move |m| self.provider_for(tenant, &m.provider).is_some())
    }

    pub fn pii_mode_for(&self, tenant: &TenantConfig) -> PiiMode {
        tenant.pii_mode.unwrap_or(self.config.pii.default_mode)
    }

    pub fn pii_surrogate_scope_for(&self, tenant: &TenantConfig) -> PiiSurrogateScope {
        tenant.pii_surrogate_scope
    }

    /// Effective rate limits / budgets for a tenant (`[limits]` overlaid with its override).
    pub fn limits_for(&self, tenant: &TenantConfig) -> Limits {
        self.config.limits.for_tenant(&tenant.id)
    }
}

/// Shared, hot-swappable snapshot holder.
#[derive(Debug, Clone)]
pub struct ConfigHandle(Arc<ArcSwap<Snapshot>>);

impl ConfigHandle {
    pub fn new(snapshot: Snapshot) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(snapshot)))
    }

    pub fn load(&self) -> Arc<Snapshot> {
        self.0.load_full()
    }

    /// Replace the snapshot. Callers validate before swapping; a failed reload keeps the old one.
    pub fn store(&self, snapshot: Snapshot) {
        self.0.store(Arc::new(snapshot));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../config/caliban.example.toml");

    #[test]
    fn example_config_parses() {
        let cfg = Config::from_toml_str(EXAMPLE).expect("example config must stay valid");
        assert_eq!(cfg.tenants[0].id.as_str(), "acme");
        let snap = Snapshot::new(cfg, "test");
        let acme = snap.tenant(&"acme".into()).unwrap();
        assert!(snap.models_for(acme).count() >= 2);
    }

    const SHARED: &str = r#"
        [[providers]]
        id = "vllm-qwen"
        kind = "openai_compatible"
        base_url = "http://qwen:8000/v1"
        trust_tier = "t0_sovereign"
        cache_salt = true

        [[providers]]
        id = "gpu-b"
        kind = "openai_compatible"
        base_url = "http://b:8000/v1"
        trust_tier = "t0_sovereign"
        tenants = ["globex"]

        [[models]]
        id = "local/qwen"
        provider = "vllm-qwen"
        upstream_model = "Qwen/Qwen3-8B"
        family = "qwen3"
        trust_tier = "t0_sovereign"
        [models.capabilities]
        tools = true
        reasoning = "hybrid"
        reasoning_control = "enable_thinking"

        [[models]]
        id = "local/b"
        provider = "gpu-b"
        upstream_model = "b"
        kind = "embedding"
        trust_tier = "t0_sovereign"

        [[tenants]]
        id = "acme"
        name = "Acme"
          [[tenants.routes]]
          intent = "default"
          models = ["local/qwen"]

        [[tenants]]
        id = "globex"
        name = "Globex"
    "#;

    #[test]
    fn shared_providers_serve_all_tenants_unless_restricted() {
        let snap = Snapshot::new(Config::from_toml_str(SHARED).unwrap(), "t");
        let acme = snap.tenant(&"acme".into()).unwrap();
        let globex = snap.tenant(&"globex".into()).unwrap();
        let ids = |t| snap.models_for(t).map(|m| m.id.to_string()).collect::<Vec<_>>();
        assert_eq!(ids(acme), vec!["local/qwen"]);
        assert_eq!(ids(globex), vec!["local/qwen", "local/b"]);
        let q = snap.model(&"local/qwen".into()).unwrap();
        assert_eq!(q.capabilities.reasoning_control, ReasoningControl::EnableThinking);
        assert!(snap.provider_for(acme, &"vllm-qwen".into()).unwrap().cache_salt);
    }

    #[test]
    fn open_models_example_stays_valid() {
        let cfg = Config::from_toml_str(include_str!("../../../config/open-models.example.toml")).unwrap();
        let snap = Snapshot::new(cfg, "t");
        let t = &snap.config.tenants[0];
        assert!(snap.models_for(t).any(|m| m.kind == ModelKind::Embedding));
        assert!(snap.models_for(t).any(|m| m.capabilities.reasoning_control != ReasoningControl::None));
    }

    #[test]
    fn surrogate_scope_defaults_to_tenant_and_session_is_opt_in() {
        let toml = SHARED.replace("id = \"globex\"\n        name = \"Globex\"", "id = \"globex\"\n        name = \"Globex\"\n        pii_surrogate_scope = \"session\"");
        let snap = Snapshot::new(Config::from_toml_str(&toml).unwrap(), "t");
        let acme = snap.tenant(&"acme".into()).unwrap();
        let globex = snap.tenant(&"globex".into()).unwrap();
        assert_eq!(snap.pii_surrogate_scope_for(acme), PiiSurrogateScope::Tenant);
        assert_eq!(snap.pii_surrogate_scope_for(globex), PiiSurrogateScope::Session);
        // The default is left out of the rendered snapshot (older routers keep parsing it).
        let json = serde_json::to_value(&snap.config.tenants).unwrap();
        assert!(json[0].get("pii_surrogate_scope").is_none());
        assert_eq!(json[1]["pii_surrogate_scope"], "session");
        let bad = toml.replace("pii_surrogate_scope = \"session\"", "pii_surrogate_scope = \"global\"");
        assert!(Config::from_toml_str(&bad).is_err());
    }

    #[test]
    fn typos_in_shared_providers_are_rejected() {
        let bad = SHARED.replace("cache_salt = true", "cache_salts = true");
        assert!(Config::from_toml_str(&bad).unwrap_err().to_string().contains("cache_salts"));
    }

    #[test]
    fn route_to_restricted_shared_provider_is_rejected() {
        let bad = SHARED.replace(r#"models = ["local/qwen"]"#, r#"models = ["local/b"]"#);
        assert!(Config::from_toml_str(&bad).unwrap_err().to_string().contains("has not configured"));
    }

    #[test]
    fn route_to_unconfigured_provider_is_rejected() {
        let bad = r#"
            [[models]]
            id = "m"
            provider = "p"
            upstream_model = "x"
            trust_tier = "t3_public"

            [[tenants]]
            id = "t"
            name = "T"
              [[tenants.routes]]
              intent = "default"
              models = ["m"]
        "#;
        let err = Config::from_toml_str(bad).unwrap_err();
        assert!(err.to_string().contains("has not configured"));
    }

    #[test]
    fn limits_defaults_and_tenant_overrides() {
        let cfg = format!(
            "{SHARED}\n[limits]\nrequests_per_minute = 600\ntokens_per_day = 1000000\n[limits.tenants.globex]\nrequests_per_minute = 5\nusd_per_day = 2.5\n"
        );
        let snap = Snapshot::new(Config::from_toml_str(&cfg).unwrap(), "t");
        let acme = snap.limits_for(snap.tenant(&"acme".into()).unwrap());
        let globex = snap.limits_for(snap.tenant(&"globex".into()).unwrap());
        assert_eq!((acme.requests_per_minute, acme.tokens_per_day, acme.usd_per_day), (Some(600), Some(1_000_000), None));
        assert_eq!((globex.requests_per_minute, globex.tokens_per_day, globex.usd_per_day), (Some(5), Some(1_000_000), Some(2.5)));
        // Configs without [limits] still parse (unlimited).
        assert_eq!(Config::from_toml_str(SHARED).unwrap().limits, LimitsConfig::default());
        let zero = format!("{SHARED}\n[limits]\nrequests_per_minute = 0\n");
        assert!(Config::from_toml_str(&zero).unwrap_err().to_string().contains("must be > 0"));
    }
}
