//! Data plane (`caliban router`): OpenAI- and Anthropic-compatible API on :8080.
//!
//! Request lifecycle (docs/architecture/caliban-reference-architecture.md §4):
//! auth → quota (GCRA rate + token reservation) → parse to IR → route → PII protect (per
//! destination trust tier) → exact cache → provider call with fallbacks (BYOK) →
//! stream/rehydrate → translate to the client's dialect → meter + settle → OTel GenAI span.
//!
//! TODO: semantic cache, ontology grounding, nodes, Prometheus metrics, `Idempotency-Key`.

mod auth;
mod chat;
mod embeddings;
mod error;
mod limits;
mod messages;
mod pipeline;
mod quirks;
mod rerank;
mod route_embed;
mod stream;
pub mod telemetry;
#[cfg(test)]
mod tests;

pub use error::{ApiError, Dialect};

use axum::Router;
use axum::routing::{get, post};
use caliban_cache::ExactCache;
use caliban_config::ConfigHandle;
use caliban_meter::UsageSink;
use caliban_meter::quota::{InMemoryQuota, QuotaStore};
use caliban_pii::{PiiEngine, SurrogateKeys};
use caliban_providers::Providers;
use std::sync::Arc;
use std::time::Duration;
use axum::http::{HeaderName, Method, header};
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

/// Max request body (bytes). Long-context requests are large; images should go via URLs.
const MAX_BODY: usize = 32 * 1024 * 1024;

pub struct Gateway {
    pub config: ConfigHandle,
    pub router: caliban_route::Router,
    pub pii: PiiEngine,
    pub cache: ExactCache,
    pub providers: Providers,
    pub usage: Arc<dyn UsageSink>,
    /// Rate limits and token budgets (`[limits]`). In-memory: exact per router process.
    pub quota: Arc<dyn QuotaStore>,
    /// Derives per-tenant `cache_salt` values. Derived from `CALIBAN_KEK` when set so all routers
    /// of a deployment agree; otherwise random per process.
    pub salt_key: [u8; 32],
    /// Derives per-tenant PII surrogate keys (HKDF over `CALIBAN_KEK`, tenant id as info), so all
    /// routers of a deployment produce the same surrogates; random per process without a KEK.
    pub pii_keys: SurrogateKeys,
}

impl Gateway {
    pub fn new(config: ConfigHandle, usage: Arc<dyn UsageSink>) -> Self {
        let c = config.load().config.cache.clone();
        Self {
            config,
            router: caliban_route::Router::default(),
            pii: PiiEngine::default(),
            cache: ExactCache::new(c.exact_max_entries, Duration::from_secs(c.exact_ttl_secs)),
            providers: Providers::default(),
            usage,
            quota: Arc::new(InMemoryQuota::new()),
            salt_key: salt_key(),
            pii_keys: pii_keys(),
        }
    }

    /// Builds the `caliban/auto` routing assets (exemplar index, calibration, router profile) for
    /// the current snapshot and waits for it. Call once at startup; config changes are picked up
    /// in the background on the next request.
    pub async fn warm_router(&self) {
        let snap = self.config.load();
        if self.router.needs_refresh(&snap) {
            route_embed::refresh(self, &snap).await;
        }
    }

    /// Replaces the quota store (e.g. a shared Valkey store for multi-router deployments).
    pub fn with_quota(mut self, quota: Arc<dyn QuotaStore>) -> Self {
        self.quota = quota;
        self
    }
}

/// Browser SDKs authenticate with a bearer key (no cookies), so any origin may call the API;
/// the `x-caliban-*` headers are exposed so clients can read routing/cache/PII metadata.
fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static("x-api-key"),
            HeaderName::from_static("anthropic-version"),
            HeaderName::from_static("anthropic-beta"),
            HeaderName::from_static("traceparent"),
        ])
        .expose_headers([
            header::RETRY_AFTER,
            HeaderName::from_static("request-id"),
            HeaderName::from_static("x-caliban-ratelimit-scope"),
            HeaderName::from_static("x-caliban-request-id"),
            HeaderName::from_static("x-caliban-routed-model"),
            HeaderName::from_static("x-caliban-intent"),
            HeaderName::from_static("x-caliban-cache"),
            HeaderName::from_static("x-caliban-pii-entities"),
            HeaderName::from_static("x-caliban-cost-usd"),
        ])
}

fn salt_key() -> [u8; 32] {
    match caliban_config::process_kek() {
        Ok(kek) => blake3::derive_key("caliban 2026 tenant cache_salt v1", kek),
        Err(_) => {
            let mut k = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut k);
            k
        }
    }
}

fn pii_keys() -> SurrogateKeys {
    match caliban_config::process_kek() {
        Ok(kek) => SurrogateKeys::from_kek(kek),
        Err(_) => SurrogateKeys::random(),
    }
}

pub fn app(gw: Arc<Gateway>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat::chat_completions))
        .route("/v1/messages", post(messages::messages))
        .route("/v1/messages/count_tokens", post(messages::count_tokens))
        .route("/v1/embeddings", post(embeddings::embeddings))
        .route("/v1/rerank", post(rerank::rerank))
        .route("/v1/models", get(chat::list_models))
        .route("/healthz", get(health))
        .layer(RequestBodyLimitLayer::new(MAX_BODY))
        .layer(cors())
        .layer(TraceLayer::new_for_http())
        .with_state(gw)
}

async fn health(axum::extract::State(gw): axum::extract::State<Arc<Gateway>>) -> axum::Json<serde_json::Value> {
    let snap = gw.config.load();
    axum::Json(serde_json::json!({ "status": "ok", "mode": "router", "config_version": snap.version }))
}
