//! Configuration snapshot for the data plane.
//!
//! In standalone/on-prem mode the snapshot is loaded from a TOML file. In connected mode the
//! control plane renders the same structure and serves it as an Ed25519-signed snapshot that
//! routers poll and verify (see [`signing`]). The data plane
//! only ever reads an immutable `Snapshot` behind an `ArcSwap`, and keeps serving the last good
//! snapshot if a reload fails (fail-static).

mod secret;
pub mod signing;

pub use secret::{
    Dek, KEK_ENV, KEK_PREVIOUS_ENV, Keyring, Secret, SecretRef, TenantSealed, WrappedDek, kek_id, open, process_kek,
    process_keyring, seal,
};

use arc_swap::ArcSwap;
use caliban_types::{
    ModelId, PiiMode, PiiSurrogateScope, ProviderId, ProviderKind, SemanticCacheMode, TenantId, TrustTier,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
    /// `caliban/auto` routing: Stage-1 kNN, per-intent quality floors, the flat auto price.
    /// Omitted from the rendered snapshot when empty, so older routers keep parsing it.
    #[serde(default, skip_serializing_if = "RoutingConfig::is_empty")]
    pub routing: RoutingConfig,
}

/// `[routing]`: how `caliban/auto` picks a model (see `caliban-route`).
///
/// Stage 1 (embedding kNN over labelled exemplars) is on when `embedding_model` names a catalogue
/// embedding model reachable through a shared (deployment) provider. Without it, or when kNN
/// abstains, times out or fails, the keyword rules decide the intent. A floor for an intent turns on
/// cheapest-above-floor selection for that intent; without one the tenant's route order is kept.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    /// Catalogue embedding model used to embed prompts and exemplars (same vector space).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<ModelId>,
    /// `name@version` of the ml `embedder` artifact this model corresponds to. A calibration
    /// artifact that `requires` an embedder is only applied when this matches it exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedder_artifact: Option<String>,
    /// Prefix added to every text before embedding (e.g. `"query: "` for E5-family models).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_prefix: Option<String>,
    /// Latency budget for embed + kNN, in ms (default 25). Over budget = rules fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_ms: Option<u64>,
    /// kNN overrides. Precedence: these, then the calibration artifact, then built-in defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Minimum calibrated vote share of the winning intent; below it kNN abstains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abstain_threshold: Option<f64>,
    /// Minimum gap between the top two intents' vote shares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub margin_threshold: Option<f64>,
    /// Minimum top-1 cosine similarity; below it the prompt is out of scope (abstain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oos_threshold: Option<f64>,
    /// Ship the built-in exemplar set (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_exemplars: Option<bool>,
    /// Extra exemplar files in the ml intent dataset format (JSON encoding).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exemplar_files: Vec<String>,
    /// Extra deployment-wide exemplars: intent → utterances.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub exemplars: BTreeMap<String, Vec<String>>,
    /// ml `intent_head` artifact directory (kNN calibration: temperature, thresholds, OOS gate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_dir: Option<String>,
    /// ml `router_profile` artifact directory (UniRoute per-cluster model quality; cluster = intent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_dir: Option<String>,
    /// Directory for cached exemplar embeddings, keyed by embedding model and exemplar set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exemplar_cache_dir: Option<String>,
    /// Quality floor per intent, in 0..=1. `"*"` applies to intents without their own floor.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub floors: BTreeMap<String, f64>,
    /// Quality per model per intent, in 0..=1 (overrides the router profile).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quality: BTreeMap<ModelId, BTreeMap<String, f64>>,
    /// Flat price of `caliban/auto`, metered next to the routed model's real cost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_price_in_per_mtok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_price_out_per_mtok: Option<f64>,
    /// Fraction of the flat `caliban/auto` price billed when a cache tier (T1 exact or T2
    /// semantic) answers: no model is called. In 0..=1; unset means
    /// [`DEFAULT_AUTO_CACHE_HIT_FRACTION`]. A tenant's `auto_cache_hit_fraction` overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_cache_hit_fraction: Option<f64>,
    /// Per-tenant overrides and exemplars.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tenants: BTreeMap<TenantId, TenantRouting>,
}

/// `[routing.tenants.<tenant_id>]`.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TenantRouting {
    /// Floors that override `[routing.floors]` for this tenant.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub floors: BTreeMap<String, f64>,
    /// The tenant's own exemplars (intent → utterances); only this tenant's requests see them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub exemplars: BTreeMap<String, Vec<String>>,
    /// `false` turns Stage-1 kNN off for this tenant (rules only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub knn: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_price_in_per_mtok: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_price_out_per_mtok: Option<f64>,
}

impl RoutingConfig {
    pub fn is_empty(&self) -> bool {
        self == &RoutingConfig::default()
    }

    /// Quality floor for an intent: tenant intent, tenant `*`, global intent, global `*`.
    pub fn floor_for(&self, tenant: &TenantId, intent: &str) -> Option<f64> {
        let t = self.tenants.get(tenant);
        t.and_then(|t| t.floors.get(intent))
            .or_else(|| t.and_then(|t| t.floors.get("*")))
            .or_else(|| self.floors.get(intent))
            .or_else(|| self.floors.get("*"))
            .copied()
    }

    /// Flat `caliban/auto` price (in, out per million tokens) for a tenant, if any.
    pub fn auto_price_for(&self, tenant: &TenantId) -> (Option<f64>, Option<f64>) {
        let t = self.tenants.get(tenant);
        (
            t.and_then(|t| t.auto_price_in_per_mtok).or(self.auto_price_in_per_mtok),
            t.and_then(|t| t.auto_price_out_per_mtok).or(self.auto_price_out_per_mtok),
        )
    }

    pub fn knn_enabled_for(&self, tenant: &TenantId) -> bool {
        self.embedding_model.is_some() && self.tenants.get(tenant).and_then(|t| t.knn).unwrap_or(true)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let unit = |what: String, v: f64| {
            if v.is_finite() && (0.0..=1.0).contains(&v) {
                Ok(())
            } else {
                Err(ConfigError::Invalid(format!("routing: {what} must be in 0..=1")))
            }
        };
        let price = |what: &str, v: Option<f64>| match v {
            Some(p) if !p.is_finite() || p < 0.0 => {
                Err(ConfigError::Invalid(format!("routing: {what} must be a non-negative number")))
            }
            _ => Ok(()),
        };
        if self.budget_ms.is_some_and(|b| b == 0 || b > 10_000) {
            return Err(ConfigError::Invalid("routing: budget_ms must be in 1..=10000".into()));
        }
        if self.k == Some(0) {
            return Err(ConfigError::Invalid("routing: k must be >= 1".into()));
        }
        if self.temperature.is_some_and(|t| !t.is_finite() || t <= 0.0) {
            return Err(ConfigError::Invalid("routing: temperature must be > 0".into()));
        }
        for (what, v) in [("abstain_threshold", self.abstain_threshold), ("margin_threshold", self.margin_threshold)] {
            if let Some(v) = v {
                unit(what.into(), v)?;
            }
        }
        if self.oos_threshold.is_some_and(|v| !v.is_finite() || !(-1.0..=1.0).contains(&v)) {
            return Err(ConfigError::Invalid("routing: oos_threshold is a cosine similarity in -1..=1".into()));
        }
        if let Some(e) = &self.embedder_artifact
            && e.split_once('@').is_none_or(|(n, v)| n.is_empty() || v.is_empty())
        {
            return Err(ConfigError::Invalid("routing: embedder_artifact must be name@version".into()));
        }
        for (intent, f) in &self.floors {
            unit(format!("floors.{intent}"), *f)?;
        }
        for (model, per_intent) in &self.quality {
            for (intent, q) in per_intent {
                unit(format!("quality.{model}.{intent}"), *q)?;
            }
        }
        price("auto_price_in_per_mtok", self.auto_price_in_per_mtok)?;
        price("auto_price_out_per_mtok", self.auto_price_out_per_mtok)?;
        if let Some(f) = self.auto_cache_hit_fraction {
            unit("auto_cache_hit_fraction".into(), f)?;
        }
        for (tenant, t) in &self.tenants {
            for (intent, f) in &t.floors {
                unit(format!("tenants.{tenant}.floors.{intent}"), *f)?;
            }
            price("auto_price_in_per_mtok", t.auto_price_in_per_mtok)?;
            price("auto_price_out_per_mtok", t.auto_price_out_per_mtok)?;
        }
        for (intent, us) in self.exemplars.iter().chain(self.tenants.values().flat_map(|t| t.exemplars.iter())) {
            if !valid_intent_id(intent) {
                return Err(ConfigError::Invalid(format!(
                    "routing: invalid intent id {intent:?} (lower snake case, dotted for domain.action)"
                )));
            }
            if us.iter().any(|u| u.trim().is_empty()) {
                return Err(ConfigError::Invalid(format!("routing: empty exemplar under intent {intent}")));
            }
        }
        Ok(())
    }
}

/// Fraction of the flat `caliban/auto` price billed for a cache hit when neither the deployment
/// (`[routing] auto_cache_hit_fraction`) nor the tenant sets one. The pricing decision (reference
/// architecture, section 9) put it in the 10 to 25% range; config accepts 0..=1.
pub const DEFAULT_AUTO_CACHE_HIT_FRACTION: f64 = 0.20;

/// Intent ids follow ml's route-registry convention: `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`.
pub fn valid_intent_id(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|seg| {
            let mut c = seg.chars();
            c.next().is_some_and(|f| f.is_ascii_lowercase())
                && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        })
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

/// Where quota state lives.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QuotaStoreKind {
    /// In this router process only (exact for a single router).
    #[default]
    Memory,
    /// Shared by every router through Valkey (`CALIBAN_VALKEY_URL`), with an in-memory
    /// fallback per router while Valkey is unreachable.
    Valkey,
}

impl QuotaStoreKind {
    fn is_memory(&self) -> bool {
        *self == Self::Memory
    }
}

/// `[limits]` (defaults for every tenant) and `[limits.tenants.<tenant_id>]` (overrides).
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// `memory` (default) or `valkey`. Read when a router starts; changing it needs a restart.
    #[serde(default, skip_serializing_if = "QuotaStoreKind::is_memory")]
    pub store: QuotaStoreKind,
    /// Valkey key namespace (default `caliban`), so several deployments can share one Valkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valkey_key_prefix: Option<String>,
    /// Upper bound on each Valkey quota call in milliseconds (default 30); past it the router
    /// limits locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valkey_timeout_ms: Option<u64>,
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
        if let Some(p) = &self.valkey_key_prefix
            && (p.is_empty()
                || p.len() > 64
                || !p.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':')))
        {
            return Err(ConfigError::Invalid(
                "limits: valkey_key_prefix must be 1-64 characters of [A-Za-z0-9_.:-]".into(),
            ));
        }
        if self.valkey_timeout_ms.is_some_and(|t| t == 0 || t > 1000) {
            return Err(ConfigError::Invalid("limits: valkey_timeout_ms must be between 1 and 1000".into()));
        }
        for (who, l) in std::iter::once(("defaults".to_owned(), self.defaults()))
            .chain(self.tenants.iter().map(|(t, l)| (t.to_string(), l.clone())))
        {
            if l.requests_per_minute == Some(0) || l.key_requests_per_minute == Some(0) {
                return Err(ConfigError::Invalid(format!(
                    "limits ({who}): requests_per_minute must be > 0 (omit it for unlimited)"
                )));
            }
            if l.tokens_per_minute == Some(0) {
                return Err(ConfigError::Invalid(format!(
                    "limits ({who}): tokens_per_minute must be > 0 (omit it for unlimited)"
                )));
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    #[serde(default)]
    pub egress: EgressPolicy,
    /// Bootstrap admin token (`CALIBAN_ADMIN_TOKEN`). With SSO configured it is the break-glass
    /// credential: every use is logged and audited as `break_glass`.
    pub admin_token: Option<SecretRef>,
    /// `false` turns the bootstrap token off once SSO works (the control plane then ignores it).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub break_glass: bool,
    /// `[security.oidc]`: single sign-on for the web console and the admin API against the
    /// customer's own identity provider. Control plane only: never sent to routers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcConfig>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self { egress: EgressPolicy::default(), admin_token: None, break_glass: true, oidc: None }
    }
}

/// `[security.oidc]`: OpenID Connect against the customer's identity provider (Keycloak,
/// Microsoft Entra ID, Okta, ADFS, Authentik, Dex, ...). The control plane is a confidential
/// client using the authorization code flow with PKCE and keeps sessions server-side. Nothing but
/// `issuer` (discovery, JWKS, token endpoint) is ever contacted.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// Exactly as the provider reports it in `.well-known/openid-configuration` (`iss`).
    pub issuer: String,
    pub client_id: String,
    /// `{ env = "..." }`, `{ file = "..." }` or `{ sealed = "..." }`. Absent: public client (PKCE
    /// only), for providers that allow it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<SecretRef>,
    /// The console's public callback URL, registered at the provider:
    /// `https://<console host>/auth/callback`. Its origin is the console origin (CSRF checks), and
    /// an `https` URL makes session cookies `Secure` with the `__Host-` prefix.
    pub redirect_url: String,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    /// Claim holding the user's groups (dotted path for nested claims, e.g.
    /// `realm_access.roles`). Groups map to roles through `role_mappings` and stored bindings.
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Audience required in access tokens sent as `Authorization: Bearer` to the admin API (CI,
    /// scripts). Absent: only browser sessions and the break-glass token are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_audience: Option<String>,
    /// Absolute session lifetime.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    /// A session unused for this long ends.
    #[serde(default = "default_session_idle")]
    pub session_idle_secs: u64,
    /// Tolerance for `exp`, `nbf` and `iat`.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: u64,
    /// How long the provider's signing keys are cached. An unknown key id refetches sooner.
    #[serde(default = "default_jwks_cache")]
    pub jwks_cache_secs: u64,
    /// PEM bundle of extra CA certificates for the provider (internal PKI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    /// Where the provider sends the browser after logout. Default: the console root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_logout_redirect_url: Option<String>,
    /// Group to role mappings (`[[security.oidc.role_mappings]]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_mappings: Vec<RoleMapping>,
}

/// Grants `role` to members of `group`. Tenant roles (`tenant_admin`, `developer`, `viewer`,
/// `billing`) need `tenant`; deployment roles (`owner`, `admin`, `auditor`) must not have one.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleMapping {
    pub group: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
}

fn default_oidc_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}
fn default_groups_claim() -> String {
    "groups".into()
}
fn default_session_ttl() -> u64 {
    8 * 3600
}
fn default_session_idle() -> u64 {
    3600
}
fn default_clock_skew() -> u64 {
    60
}
fn default_jwks_cache() -> u64 {
    3600
}
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_true(b: &bool) -> bool {
    *b
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
    /// T2 semantic cache (`[cache.semantic]`). Left out of the rendered snapshot when it is the
    /// default, so routers that predate it keep accepting snapshots.
    #[serde(default, skip_serializing_if = "SemanticCacheConfig::is_default")]
    pub semantic: SemanticCacheConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            exact_enabled: true,
            exact_max_entries: default_cache_entries(),
            exact_ttl_secs: default_cache_ttl(),
            semantic: SemanticCacheConfig::default(),
        }
    }
}

/// Where T2 entries live.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SemanticStoreKind {
    /// Qdrant over its REST API (`qdrant_url`, or `CALIBAN_QDRANT_URL`). Shared by every router.
    #[default]
    Qdrant,
    /// Brute-force in-process store: one router, lost on restart. For development and tests.
    Memory,
}

/// `[cache.semantic]`: the T2 semantic cache. It answers a request with the response to an earlier,
/// semantically similar request **of the same tenant** (same model, same system prompt, history and
/// parameters; only the last user message may differ). Off unless `enabled` here **and**
/// `semantic_cache = "on"` on the tenant. Threshold policy: see `caliban_cache::semantic::policy`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SemanticCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub store: SemanticStoreKind,
    /// Qdrant REST endpoint (port 6333). `CALIBAN_QDRANT_URL` takes precedence.
    pub qdrant_url: Option<String>,
    /// Qdrant API key, e.g. `{ env = "CALIBAN_QDRANT_API_KEY" }`. When unset, the
    /// `CALIBAN_QDRANT_API_KEY` environment variable is used if present.
    pub qdrant_api_key: Option<SecretRef>,
    /// Collections are named `{prefix}_{embedding model}_{dimension}`.
    #[serde(default = "default_collection_prefix")]
    pub collection_prefix: String,
    /// Catalogue id of the embedding model (`kind = "embedding"`) used for cache keys. Each tenant
    /// must reach it through its own or a shared provider; otherwise T2 is skipped for that tenant.
    pub embedding_model: Option<ModelId>,
    /// Starting per-entry cosine threshold; entries only go below it after verified-correct
    /// matches. Unset: [`SEM_THRESHOLD_WITH_DEFAULT_PREFIX`] (0.91) with the default
    /// `query_prefix`, [`SEM_THRESHOLD`] (0.95) without a prefix or with another one. Read it with
    /// [`SemanticCacheConfig::threshold`] or [`Config::semantic_cache_settings`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f32>,
    /// Learned thresholds never go below this. Unset: 0.91 with the default `query_prefix`, 0.93
    /// otherwise (never above `threshold`). Read it with [`SemanticCacheConfig::min_threshold`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_threshold: Option<f32>,
    /// Matches in `[threshold - grey_band, threshold)` are answered fresh and the fresh answer is
    /// compared with the cached one in the background; agreement lowers the entry's threshold.
    #[serde(default = "default_sem_grey_band")]
    pub grey_band: f32,
    /// Error budget: the highest acceptable share of wrong answers among semantic hits. When the
    /// sampled error rate of a tenant goes above it, that tenant's thresholds tighten.
    #[serde(default = "default_sem_max_error_rate")]
    pub max_error_rate: f32,
    /// Share of would-be hits answered fresh instead and used to verify the cached answer.
    #[serde(default = "default_sem_verify_rate")]
    pub verify_rate: f32,
    /// Answers whose embeddings have at least this cosine count as "the same answer".
    #[serde(default = "default_sem_answer_similarity")]
    pub verify_answer_similarity: f32,
    /// Requests with `temperature` above this are not semantically cached (temperature unset counts
    /// as the provider default, i.e. sampling). `caliban.cache = "semantic"` on a request opts in
    /// regardless of temperature.
    #[serde(default = "default_sem_max_temperature")]
    pub max_temperature: f64,
    #[serde(default = "default_sem_ttl")]
    pub ttl_secs: u64,
    /// Total time allowed for embedding plus vector search before the request goes on as a miss.
    #[serde(default = "default_sem_budget")]
    pub lookup_budget_ms: u64,
    /// Timeout of one embedding call (the lookup budget still applies on the request path; a
    /// slower embedding is kept for the insert after the upstream answers).
    #[serde(default = "default_sem_embed_timeout")]
    pub embed_timeout_ms: u64,
    /// Instruction prepended to the prompt before it is embedded for the cache. Unset:
    /// [`DEFAULT_SEM_QUERY_PREFIX`], the Qwen3-Embedding query instruction calibrated in the AWS
    /// runs, when `embedding_model` is of family `qwen3-embedding` (no prefix for other
    /// embedders); `""` turns it off; any other text replaces it. Read it with
    /// [`SemanticCacheConfig::effective_query_prefix`] or [`Config::semantic_cache_settings`]. With the default prefix and
    /// `threshold = min_threshold = 0.91`, the second AWS run measured 24 of 36 paraphrases hit and
    /// 0 of 38 near-misses (against 14 of 36 without a prefix at 0.95 / 0.93;
    /// `bench/RESULTS-aws-2026-10b.md`). Entries embedded with another prefix are never compared
    /// (the prefix is part of the key). Unless it equals `[routing] query_prefix`, a request that
    /// is routed by kNN and looked up here embeds its prompt twice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_prefix: Option<String>,
}

impl Default for SemanticCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            store: SemanticStoreKind::default(),
            qdrant_url: None,
            qdrant_api_key: None,
            collection_prefix: default_collection_prefix(),
            embedding_model: None,
            threshold: None,
            min_threshold: None,
            grey_band: default_sem_grey_band(),
            max_error_rate: default_sem_max_error_rate(),
            verify_rate: default_sem_verify_rate(),
            verify_answer_similarity: default_sem_answer_similarity(),
            max_temperature: default_sem_max_temperature(),
            ttl_secs: default_sem_ttl(),
            lookup_budget_ms: default_sem_budget(),
            embed_timeout_ms: default_sem_embed_timeout(),
            query_prefix: None,
        }
    }
}

/// Default `[cache.semantic] query_prefix`: the query instruction Qwen3-Embedding expects, worded
/// for "the same question" (`bench/RESULTS-aws-2026-10.md` and `-10b.md`).
pub const DEFAULT_SEM_QUERY_PREFIX: &str =
    "Instruct: Given a user question, retrieve questions that ask exactly the same thing\nQuery: ";
/// Catalogue `family` of the Qwen3-Embedding models, for which [`DEFAULT_SEM_QUERY_PREFIX`] is the
/// default.
pub const QWEN3_EMBEDDING_FAMILY: &str = "qwen3-embedding";
/// Default `threshold` and `min_threshold` with [`DEFAULT_SEM_QUERY_PREFIX`].
pub const SEM_THRESHOLD_WITH_DEFAULT_PREFIX: f32 = 0.91;
/// Default `threshold` without a prefix, or with a prefix of your own (not calibrated).
pub const SEM_THRESHOLD: f32 = 0.95;
/// Default `min_threshold` without a prefix, or with a prefix of your own: below 0.93 the false
/// hits doubled without a prefix in the first AWS run.
pub const SEM_MIN_THRESHOLD: f32 = 0.93;

impl SemanticCacheConfig {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The instruction prepended before embedding, for an embedding model of catalogue `family`:
    /// when unset, [`DEFAULT_SEM_QUERY_PREFIX`] for [`QWEN3_EMBEDDING_FAMILY`] models (the only
    /// embedder it is written and calibrated for) and none for others; none when set to `""`.
    pub fn effective_query_prefix(&self, family: Option<&str>) -> Option<&str> {
        match self.query_prefix.as_deref() {
            None if family == Some(QWEN3_EMBEDDING_FAMILY) => Some(DEFAULT_SEM_QUERY_PREFIX),
            None | Some("") => None,
            Some(p) => Some(p),
        }
    }

    /// Whether the thresholds calibrated for [`DEFAULT_SEM_QUERY_PREFIX`] apply.
    fn calibrated_prefix(&self, family: Option<&str>) -> bool {
        self.effective_query_prefix(family) == Some(DEFAULT_SEM_QUERY_PREFIX)
    }

    /// Starting per-entry threshold (see the field) for an embedding model of `family`.
    pub fn threshold(&self, family: Option<&str>) -> f32 {
        self.threshold.unwrap_or(if self.calibrated_prefix(family) {
            SEM_THRESHOLD_WITH_DEFAULT_PREFIX
        } else {
            SEM_THRESHOLD
        })
    }

    /// Floor of learned thresholds (see the field) for an embedding model of `family`. When unset
    /// it never exceeds `threshold`.
    pub fn min_threshold(&self, family: Option<&str>) -> f32 {
        self.min_threshold.unwrap_or_else(|| {
            let d = if self.calibrated_prefix(family) { SEM_THRESHOLD_WITH_DEFAULT_PREFIX } else { SEM_MIN_THRESHOLD };
            d.min(self.threshold(family))
        })
    }

    /// `CALIBAN_QDRANT_URL`, then `qdrant_url`.
    pub fn resolved_qdrant_url(&self) -> Option<String> {
        std::env::var("CALIBAN_QDRANT_URL").ok().filter(|u| !u.trim().is_empty()).or_else(|| self.qdrant_url.clone())
    }

    /// `qdrant_api_key`, then `CALIBAN_QDRANT_API_KEY`.
    pub fn resolved_qdrant_api_key(&self) -> Result<Option<String>, ConfigError> {
        match &self.qdrant_api_key {
            Some(r) => r
                .resolve()
                .map(|s| Some(s.expose().to_owned()))
                .map_err(|e| ConfigError::Secret("cache.semantic.qdrant_api_key".into(), e.to_string())),
            None => Ok(std::env::var("CALIBAN_QDRANT_API_KEY").ok().filter(|k| !k.is_empty())),
        }
    }

    fn validate(&self, models: &HashMap<&ModelId, &ModelEntry>) -> Result<(), ConfigError> {
        let unit = |name: &str, v: f32| {
            if v.is_finite() && (0.0..=1.0).contains(&v) {
                Ok(())
            } else {
                Err(ConfigError::Invalid(format!("cache.semantic.{name} must be in [0, 1]")))
            }
        };
        let family = self.embedding_model.as_ref().and_then(|m| models.get(m)).and_then(|e| e.family.as_deref());
        unit("threshold", self.threshold(family))?;
        unit("min_threshold", self.min_threshold(family))?;
        unit("grey_band", self.grey_band)?;
        unit("max_error_rate", self.max_error_rate)?;
        unit("verify_rate", self.verify_rate)?;
        unit("verify_answer_similarity", self.verify_answer_similarity)?;
        if self.min_threshold(family) > self.threshold(family) {
            return Err(ConfigError::Invalid("cache.semantic.min_threshold must be <= threshold".into()));
        }
        if !self.max_temperature.is_finite() || self.max_temperature < 0.0 {
            return Err(ConfigError::Invalid("cache.semantic.max_temperature must be a non-negative number".into()));
        }
        if self.collection_prefix.is_empty()
            || !self.collection_prefix.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ConfigError::Invalid(
                "cache.semantic.collection_prefix must be non-empty [A-Za-z0-9_-]".into(),
            ));
        }
        if let Some(m) = &self.embedding_model {
            match models.get(m) {
                Some(e) if e.kind == ModelKind::Embedding => {}
                Some(_) => {
                    return Err(ConfigError::Invalid(format!(
                        "cache.semantic.embedding_model '{m}' is not an embedding model"
                    )));
                }
                None => {
                    return Err(ConfigError::Invalid(format!("cache.semantic.embedding_model: unknown model '{m}'")));
                }
            }
        } else if self.enabled {
            return Err(ConfigError::Invalid("cache.semantic.enabled needs cache.semantic.embedding_model".into()));
        }
        Ok(())
    }
}

fn default_collection_prefix() -> String {
    "caliban_semcache".into()
}
fn default_sem_grey_band() -> f32 {
    0.03
}
fn default_sem_max_error_rate() -> f32 {
    0.02
}
fn default_sem_verify_rate() -> f32 {
    0.05
}
fn default_sem_answer_similarity() -> f32 {
    0.90
}
fn default_sem_max_temperature() -> f64 {
    0.3
}
fn default_sem_ttl() -> u64 {
    86_400
}
fn default_sem_budget() -> u64 {
    50
}
fn default_sem_embed_timeout() -> u64 {
    2_000
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
    /// Price of prompt tokens read from the provider's prompt cache (OpenAI `cached_tokens`,
    /// Anthropic `cache_read_input_tokens`). Unset: `price_in_per_mtok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_cache_read_per_mtok: Option<f64>,
    /// Price of prompt tokens written to the provider's prompt cache (Anthropic
    /// `cache_creation_input_tokens`, default 5-minute TTL). Unset: `price_in_per_mtok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_cache_write_per_mtok: Option<f64>,
    /// Price of cache writes with Anthropic's 1-hour TTL (`cache_creation.ephemeral_1h_input_tokens`).
    /// Unset: `price_cache_write_per_mtok`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_cache_write_1h_per_mtok: Option<f64>,
}

impl ModelEntry {
    /// True when any prompt-cache price is configured.
    pub fn has_cache_prices(&self) -> bool {
        self.price_cache_read_per_mtok.is_some()
            || self.price_cache_write_per_mtok.is_some()
            || self.price_cache_write_1h_per_mtok.is_some()
    }

    fn validate_prices(&self) -> Result<(), ConfigError> {
        for (what, v) in [
            ("price_cache_read_per_mtok", self.price_cache_read_per_mtok),
            ("price_cache_write_per_mtok", self.price_cache_write_per_mtok),
            ("price_cache_write_1h_per_mtok", self.price_cache_write_1h_per_mtok),
        ] {
            if v.is_some_and(|p| !p.is_finite() || p < 0.0) {
                return Err(ConfigError::Invalid(format!("model {}: {what} must be a non-negative number", self.id)));
            }
        }
        Ok(())
    }
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
    /// T2 semantic cache for this tenant: `off` (default) or `on`. Also needs
    /// `[cache.semantic] enabled`. Omitted from the rendered snapshot when it is the default.
    #[serde(default, skip_serializing_if = "SemanticCacheMode::is_default")]
    pub semantic_cache: SemanticCacheMode,
    /// Overrides `[routing] auto_cache_hit_fraction` for this tenant: the fraction of the flat
    /// `caliban/auto` price billed for a cache hit, in 0..=1. Omitted when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_cache_hit_fraction: Option<f64>,
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
    /// The server rejects `stream_options` (some older OpenAI-compatible servers and proxies).
    /// Caliban then does not ask for usage on streams, and meters them from an estimate
    /// (`usage_source: "estimated"`). Omitted from the rendered snapshot when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rejects_stream_options: bool,
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
        Self {
            id: p.id,
            kind: p.kind,
            base_url: p.base_url,
            trust_tier: p.trust_tier,
            api_key: p.api_key,
            cache_salt: p.cache_salt,
            tenants: s.tenants,
        }
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

/// `[cache.semantic]` values that depend on the embedding model (see
/// [`Config::semantic_cache_settings`]).
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticCacheSettings {
    /// Instruction prepended before embedding; `None` embeds the prompt as is.
    pub query_prefix: Option<String>,
    pub threshold: f32,
    pub min_threshold: f32,
}

impl Config {
    /// The semantic cache's effective `query_prefix`, `threshold` and `min_threshold`, with the
    /// defaults of its embedding model's catalogue family.
    pub fn semantic_cache_settings(&self) -> SemanticCacheSettings {
        let c = &self.cache.semantic;
        let family = c
            .embedding_model
            .as_ref()
            .and_then(|id| self.models.iter().find(|m| &m.id == id))
            .and_then(|m| m.family.as_deref());
        SemanticCacheSettings {
            query_prefix: c.effective_query_prefix(family).map(str::to_owned),
            threshold: c.threshold(family),
            min_threshold: c.min_threshold(family),
        }
    }

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
        for m in &self.models {
            m.validate_prices()?;
        }
        let mut shared_ids = std::collections::HashSet::new();
        for p in &self.providers {
            if !shared_ids.insert(&p.provider.id) {
                return Err(ConfigError::Invalid(format!("duplicate shared provider id '{}'", p.provider.id)));
            }
        }
        let mut seen_hashes = std::collections::HashSet::new();
        for t in &self.tenants {
            if t.auto_cache_hit_fraction.is_some_and(|f| !f.is_finite() || !(0.0..=1.0).contains(&f)) {
                return Err(ConfigError::Invalid(format!("tenant {}: auto_cache_hit_fraction must be in 0..=1", t.id)));
            }
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
                        return Err(ConfigError::Invalid(format!(
                            "tenant {} route {}: unknown model {m}",
                            t.id, r.intent
                        )));
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
        self.cache.semantic.validate(&models)?;
        self.limits.validate()?;
        self.routing.validate()
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

    /// Whether the T2 semantic cache applies to this tenant (deployment switch and tenant opt-in).
    pub fn semantic_cache_for(&self, tenant: &TenantConfig) -> bool {
        self.config.cache.semantic.enabled && tenant.semantic_cache == SemanticCacheMode::On
    }

    /// Fraction of the flat `caliban/auto` price billed for a cache hit: the tenant's override,
    /// else `[routing] auto_cache_hit_fraction`, else [`DEFAULT_AUTO_CACHE_HIT_FRACTION`].
    pub fn auto_cache_hit_fraction_for(&self, tenant: &TenantConfig) -> f64 {
        tenant
            .auto_cache_hit_fraction
            .or(self.config.routing.auto_cache_hit_fraction)
            .unwrap_or(DEFAULT_AUTO_CACHE_HIT_FRACTION)
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

    /// The commented `[security.oidc]` block of the example, switched on, is valid as written.
    #[test]
    fn example_sso_block_parses() {
        let mut on = false;
        let text: String = EXAMPLE
            .lines()
            .map(|l| {
                if l.starts_with("# [security.oidc]") {
                    on = true;
                }
                // Settings and tables are switched on; prose comments stay comments.
                let body = l.strip_prefix("# ").or(l.strip_prefix('#')).unwrap_or(l);
                let setting = body.is_empty() || body.starts_with('[') || body.contains(" = ");
                let out = if on && setting { body } else { l };
                if l.starts_with("# tenant = ") {
                    on = false;
                }
                format!("{out}\n")
            })
            .collect();
        let cfg = Config::from_toml_str(&text).unwrap();
        let oidc = cfg.security.oidc.expect("block switched on");
        assert_eq!(oidc.client_secret, Some(SecretRef::Env { env: "CALIBAN_OIDC_CLIENT_SECRET".into() }));
        assert_eq!(oidc.role_mappings.len(), 2);
        assert_eq!(oidc.role_mappings[1].tenant.as_deref(), Some("acme"));
        assert!(cfg.security.break_glass);
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
        let c = snap.config.semantic_cache_settings();
        assert_eq!(c.query_prefix.as_deref(), Some(DEFAULT_SEM_QUERY_PREFIX), "Qwen3-Embedding: prefix on");
        assert_eq!((c.threshold, c.min_threshold), (0.91, 0.91));
    }

    /// The opt-in blocks of the open-models example (`[routing]` and the cache `query_prefix`)
    /// are valid once uncommented, with the calibrated values.
    #[test]
    fn open_models_example_opt_in_blocks_are_valid() {
        let src = include_str!("../../../config/open-models.example.toml");
        let mut out = String::new();
        let mut in_routing = false;
        for line in src.lines() {
            if line.starts_with("# [routing]") {
                in_routing = true;
            } else if in_routing && !line.starts_with('#') {
                in_routing = false;
            }
            let uncomment = (in_routing && !line.starts_with("# #")) || line.starts_with("# query_prefix = ");
            out.push_str(if uncomment { &line[2..] } else { line });
            out.push('\n');
        }
        let cfg = Config::from_toml_str(&out).unwrap();
        let r = &cfg.routing;
        assert_eq!(r.embedding_model.as_ref().map(ModelId::as_str), Some("local/qwen3-embedding-0.6b"));
        assert_eq!(
            r.query_prefix.as_deref(),
            Some("Instruct: Given a user request, identify the type of task it asks for\nQuery: ")
        );
        assert_eq!(
            (r.k, r.temperature, r.abstain_threshold, r.oos_threshold),
            (Some(5), Some(0.1), Some(0.6), Some(0.64))
        );
        assert_eq!(cfg.cache.semantic.query_prefix.as_deref(), Some(DEFAULT_SEM_QUERY_PREFIX));
        assert_eq!(cfg.semantic_cache_settings().threshold, 0.91);
    }

    #[test]
    fn surrogate_scope_defaults_to_tenant_and_session_is_opt_in() {
        let toml = SHARED.replace(
            "id = \"globex\"\n        name = \"Globex\"",
            "id = \"globex\"\n        name = \"Globex\"\n        pii_surrogate_scope = \"session\"",
        );
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
    fn semantic_cache_defaults_validation_and_tenant_switch() {
        let c = SemanticCacheConfig::default();
        assert!(!c.enabled);
        let q = Some(QWEN3_EMBEDDING_FAMILY);
        assert_eq!(
            (c.effective_query_prefix(q), c.threshold(q), c.min_threshold(q), c.lookup_budget_ms, c.store),
            (Some(DEFAULT_SEM_QUERY_PREFIX), 0.91, 0.91, 50, SemanticStoreKind::Qdrant)
        );
        // Other embedders: the instruction is Qwen3-Embedding's, so no prefix and the
        // conservative defaults of the unprefixed run.
        for f in [None, Some("bge")] {
            assert_eq!((c.effective_query_prefix(f), c.threshold(f), c.min_threshold(f)), (None, 0.95, 0.93));
        }
        // Prefix off, or a prefix of your own (not calibrated): 0.95 / 0.93. Explicit values win.
        let sem = |extra: &str| -> SemanticCacheConfig { toml::from_str(extra).unwrap() };
        let off = sem("query_prefix = \"\"");
        assert_eq!((off.effective_query_prefix(q), off.threshold(q), off.min_threshold(q)), (None, 0.95, 0.93));
        let own = sem("query_prefix = \"query: \"");
        assert_eq!(
            (own.effective_query_prefix(None), own.threshold(q), own.min_threshold(q)),
            (Some("query: "), 0.95, 0.93)
        );
        let set = sem("threshold = 0.97\nmin_threshold = 0.92");
        assert_eq!((set.threshold(q), set.min_threshold(q)), (0.97, 0.92));
        assert_eq!(sem("query_prefix = \"\"\nthreshold = 0.9").min_threshold(q), 0.9, "unset floor never above it");
        // Unset values stay out of the rendered snapshot, so routers apply the same defaults.
        let json = serde_json::to_value(&c).unwrap();
        assert!(json.get("threshold").is_none() && json.get("query_prefix").is_none());
        let on = |extra: &str| format!("{SHARED}\n[cache.semantic]\nenabled = true\n{extra}");
        let cfg = Config::from_toml_str(&on("embedding_model = \"local/b\"\nstore = \"memory\"")).unwrap();
        assert_eq!(cfg.cache.semantic.store, SemanticStoreKind::Memory);
        assert!(
            Config::from_toml_str(&on("")).unwrap_err().to_string().contains("needs cache.semantic.embedding_model")
        );
        assert!(
            Config::from_toml_str(&on("embedding_model = \"local/qwen\""))
                .unwrap_err()
                .to_string()
                .contains("not an embedding model")
        );
        assert!(
            Config::from_toml_str(&on("embedding_model = \"nope\"")).unwrap_err().to_string().contains("unknown model")
        );
        let bad = on("embedding_model = \"local/b\"\nthreshold = 0.8\nmin_threshold = 0.9");
        assert!(Config::from_toml_str(&bad).unwrap_err().to_string().contains("min_threshold"));
        assert!(Config::from_toml_str(&on("embedding_model = \"local/b\"\nthreshold = 1.5")).is_err());
        assert!(Config::from_toml_str(&on("embedding_model = \"local/b\"\ntreshold = 0.9")).is_err(), "typos rejected");

        // Tenant switch: off by default and left out of the snapshot; on needs the deployment switch.
        let toml = on("embedding_model = \"local/b\"").replace(
            "id = \"globex\"\n        name = \"Globex\"",
            "id = \"globex\"\n        name = \"Globex\"\n        semantic_cache = \"on\"",
        );
        let snap = Snapshot::new(Config::from_toml_str(&toml).unwrap(), "t");
        assert!(!snap.semantic_cache_for(snap.tenant(&"acme".into()).unwrap()));
        assert!(snap.semantic_cache_for(snap.tenant(&"globex".into()).unwrap()));
        let json = serde_json::to_value(&snap.config.tenants).unwrap();
        assert!(json[0].get("semantic_cache").is_none());
        let cache = serde_json::to_value(&Config::from_toml_str(SHARED).unwrap().cache).unwrap();
        assert!(cache.get("semantic").is_none(), "default section left out of snapshots");
        assert_eq!(serde_json::to_value(&snap.config.cache).unwrap()["semantic"]["enabled"], true);
        assert_eq!(json[1]["semantic_cache"], "on");
        let off =
            Snapshot::new(Config::from_toml_str(&toml.replace("enabled = true", "enabled = false")).unwrap(), "t");
        assert!(!off.semantic_cache_for(off.tenant(&"globex".into()).unwrap()), "deployment switch wins");
    }

    #[test]
    fn routing_section_parses_validates_and_is_omitted_when_empty() {
        // The commented [routing] block of the example config, uncommented, must stay valid.
        let block: String = EXAMPLE
            .lines()
            .skip_while(|l| !l.starts_with("# [routing]"))
            .take_while(|l| l.starts_with('#'))
            .map(|l| format!("{}\n", l.trim_start_matches('#').trim_start()))
            .collect();
        assert!(block.contains("embedding_model"));
        let cfg = Config::from_toml_str(&format!("{block}\n{SHARED}")).unwrap();
        let r = &cfg.routing;
        assert_eq!(r.budget_ms, Some(25));
        let acme: TenantId = "acme".into();
        assert_eq!(r.floor_for(&acme, "code"), Some(0.9));
        assert_eq!(r.floor_for(&"globex".into(), "code"), Some(0.8));
        assert_eq!(r.floor_for(&"globex".into(), "chat"), None);
        assert_eq!(r.auto_price_for(&acme), (Some(3.0), Some(12.0)));
        assert!(r.knn_enabled_for(&acme));
        // Wildcard floor.
        let wild = Config::from_toml_str(&format!("[routing.floors]\n\"*\" = 0.6\n{SHARED}")).unwrap();
        assert_eq!(wild.routing.floor_for(&acme, "anything"), Some(0.6));
        // Out-of-range values and bad intent ids are rejected.
        for bad in [
            "[routing.floors]\ncode = 1.5",
            "[routing]\nbudget_ms = 0",
            "[routing]\nk = 0",
            "[routing.tenants.acme.exemplars]\n\"Bad Id\" = [\"x\"]",
            "[routing]\nembedder_artifact = \"nover\"",
            "[routing]\nauto_price_in_per_mtok = -1.0",
        ] {
            assert!(Config::from_toml_str(&format!("{bad}\n{SHARED}")).is_err(), "{bad}");
        }
        // Empty routing is left out of rendered snapshots, so older routers keep parsing them.
        let json = serde_json::to_value(Config::from_toml_str(SHARED).unwrap()).unwrap();
        assert!(json.get("routing").is_none());
        assert!(valid_intent_id("finance.invoice_triage") && !valid_intent_id("Finance") && !valid_intent_id("a..b"));
    }

    #[test]
    fn auto_cache_hit_fraction_defaults_overrides_and_validation() {
        let globex = |extra: &str| {
            SHARED.replace(
                "id = \"globex\"\n        name = \"Globex\"",
                &format!("id = \"globex\"\n        name = \"Globex\"\n        {extra}"),
            )
        };
        let fraction = |toml: &str, tenant: &str| {
            let snap = Snapshot::new(Config::from_toml_str(toml).unwrap(), "t");
            snap.auto_cache_hit_fraction_for(snap.tenant(&tenant.into()).unwrap())
        };
        // Built-in default, then the deployment value, then the tenant override.
        assert!((fraction(SHARED, "acme") - DEFAULT_AUTO_CACHE_HIT_FRACTION).abs() < f64::EPSILON);
        assert!((DEFAULT_AUTO_CACHE_HIT_FRACTION - 0.2).abs() < f64::EPSILON);
        let deployment =
            format!("[routing]\nauto_cache_hit_fraction = 0.25\n{}", globex("auto_cache_hit_fraction = 0.1"));
        assert!((fraction(&deployment, "acme") - 0.25).abs() < f64::EPSILON);
        assert!((fraction(&deployment, "globex") - 0.1).abs() < f64::EPSILON);
        // Zero (hits are free) and one (hits cost the full flat price) are allowed.
        assert!(fraction(&globex("auto_cache_hit_fraction = 0.0"), "globex").abs() < f64::EPSILON);
        assert!((fraction(&globex("auto_cache_hit_fraction = 1.0"), "globex") - 1.0).abs() < f64::EPSILON);
        // Out of range, deployment-wide or per tenant, is rejected.
        for bad in [
            format!("[routing]\nauto_cache_hit_fraction = 1.5\n{SHARED}"),
            format!("[routing]\nauto_cache_hit_fraction = -0.1\n{SHARED}"),
            globex("auto_cache_hit_fraction = 2.0"),
            globex("auto_cache_hit_fraction = -1.0"),
        ] {
            assert!(Config::from_toml_str(&bad).unwrap_err().to_string().contains("auto_cache_hit_fraction"), "{bad}");
        }
        // Unset is left out of rendered snapshots (older routers keep parsing them).
        let json =
            serde_json::to_value(Config::from_toml_str(&globex("auto_cache_hit_fraction = 0.1")).unwrap()).unwrap();
        assert!(json.get("routing").is_none());
        assert!(json["tenants"][0].get("auto_cache_hit_fraction").is_none());
        assert_eq!(json["tenants"][1]["auto_cache_hit_fraction"], 0.1);
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
        assert_eq!(
            (acme.requests_per_minute, acme.tokens_per_day, acme.usd_per_day),
            (Some(600), Some(1_000_000), None)
        );
        assert_eq!(
            (globex.requests_per_minute, globex.tokens_per_day, globex.usd_per_day),
            (Some(5), Some(1_000_000), Some(2.5))
        );
        // Configs without [limits] still parse (unlimited).
        assert_eq!(Config::from_toml_str(SHARED).unwrap().limits, LimitsConfig::default());
        let zero = format!("{SHARED}\n[limits]\nrequests_per_minute = 0\n");
        assert!(Config::from_toml_str(&zero).unwrap_err().to_string().contains("must be > 0"));
        let zero = format!("{SHARED}\n[limits.tenants.acme]\ntokens_per_minute = 0\n");
        assert!(Config::from_toml_str(&zero).unwrap_err().to_string().contains("tokens_per_minute must be > 0"));
    }

    #[test]
    fn limits_store_selection() {
        let l = Config::from_toml_str(SHARED).unwrap().limits;
        assert_eq!((l.store, l.valkey_key_prefix, l.valkey_timeout_ms), (QuotaStoreKind::Memory, None, None));
        // The defaults are not serialized, so snapshots stay readable by routers that predate them.
        assert!(!serde_json::to_string(&LimitsConfig::default()).unwrap().contains("store"));

        let cfg = format!(
            "{SHARED}\n[limits]\nstore = \"valkey\"\nvalkey_key_prefix = \"prod-eu:caliban\"\nvalkey_timeout_ms = 40\n"
        );
        let l = Config::from_toml_str(&cfg).unwrap().limits;
        assert_eq!(
            (l.store, l.valkey_key_prefix.as_deref(), l.valkey_timeout_ms),
            (QuotaStoreKind::Valkey, Some("prod-eu:caliban"), Some(40))
        );
        assert!(serde_json::to_string(&l).unwrap().contains(r#""store":"valkey""#));

        for bad in [
            "store = \"redis\"",
            "valkey_key_prefix = \"a{b}\"",
            "valkey_key_prefix = \"\"",
            "valkey_timeout_ms = 0",
            "valkey_timeout_ms = 5000",
        ] {
            assert!(Config::from_toml_str(&format!("{SHARED}\n[limits]\n{bad}\n")).is_err(), "{bad}");
        }
    }

    #[test]
    fn cache_prices_parse_validate_and_are_omitted_when_unset() {
        let model = |extra: &str| {
            format!(
                "[[models]]\nid = \"ext/m\"\nprovider = \"vllm-qwen\"\nupstream_model = \"m\"\ntrust_tier = \"t2_contracted\"\nprice_in_per_mtok = 3.0\nprice_out_per_mtok = 15.0\n{extra}\n"
            )
        };
        let cfg = Config::from_toml_str(&format!(
            "{SHARED}\n{}",
            model("price_cache_read_per_mtok = 0.3\nprice_cache_write_per_mtok = 3.75\nprice_cache_write_1h_per_mtok = 6.0\n[models.capabilities]\nrejects_stream_options = true")
        ))
        .unwrap();
        let m = cfg.models.iter().find(|m| m.id.as_str() == "ext/m").unwrap();
        assert_eq!(
            (m.price_cache_read_per_mtok, m.price_cache_write_per_mtok, m.price_cache_write_1h_per_mtok),
            (Some(0.3), Some(3.75), Some(6.0))
        );
        assert!(m.has_cache_prices() && m.capabilities.rejects_stream_options);
        for bad in [
            "price_cache_read_per_mtok = -0.1",
            "price_cache_write_per_mtok = nan",
            "price_cache_write_1h_per_mtok = -1.0",
        ] {
            assert!(Config::from_toml_str(&format!("{SHARED}\n{}", model(bad))).is_err(), "{bad}");
        }
        // Unset fields stay out of the rendered snapshot, so routers that predate them still parse it.
        let cfg = Config::from_toml_str(&format!("{SHARED}\n{}", model(""))).unwrap();
        let m = cfg.models.iter().find(|m| m.id.as_str() == "ext/m").unwrap();
        let v = serde_json::to_value(m).unwrap();
        assert!(
            v.get("price_cache_read_per_mtok").is_none() && v["capabilities"].get("rejects_stream_options").is_none(),
            "{v}"
        );
        assert!(!m.has_cache_prices());
    }
}
