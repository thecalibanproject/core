//! Data plane (`caliban router`): OpenAI- and Anthropic-compatible API on :8080.
//!
//! Request lifecycle (docs/architecture/caliban-reference-architecture.md §4):
//! auth → quota (GCRA rate + token reservation) → parse to IR → route → PII protect (per
//! destination trust tier) → T1 exact cache → T2 semantic cache → provider call with fallbacks
//! (BYOK) → stream/rehydrate → translate to the client's dialect → meter + settle → OTel GenAI span.
//!
//! TODO: ontology grounding, nodes, Prometheus metrics, `Idempotency-Key`.

mod auth;
mod chat;
pub mod embedder;
mod embeddings;
mod error;
mod limits;
mod messages;
mod pipeline;
mod quirks;
mod rerank;
mod semantic;
mod stream;
pub mod telemetry;
#[cfg(test)]
mod tests;

pub use error::{ApiError, Dialect};
pub use limits::quota_store;

use axum::Router;
use axum::routing::{get, post};
use caliban_cache::ExactCache;
use caliban_cache::semantic::{MemoryStore, QdrantStore, SemanticCache, VectorStore};
use caliban_config::{SemanticCacheConfig, SemanticStoreKind};
use caliban_types::Embedder;
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
    /// T2 semantic cache; `None` when no store is configured (`[cache.semantic]`).
    pub semantic: Option<Arc<SemanticCache>>,
    /// Embeddings for internal consumers (semantic cache, kNN routing): the tenant's embedding
    /// model through its provider ([`embedder::ProviderEmbedder`]).
    pub embedder: Arc<dyn Embedder>,
    pub providers: Arc<Providers>,
    pub usage: Arc<dyn UsageSink>,
    /// Rate limits and token budgets (`[limits]`). In-memory by default (exact per router
    /// process); `store = "valkey"` shares them across routers (see [`quota_store`]).
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
        let providers = Arc::new(Providers::default());
        let embedder = Arc::new(embedder::ProviderEmbedder::new(
            config.clone(),
            Arc::clone(&providers),
            embedder::DEFAULT_LRU_ENTRIES,
            Duration::from_millis(c.semantic.embed_timeout_ms),
            embedder::DEFAULT_MAX_BATCH,
        ));
        Self {
            config,
            router: caliban_route::Router::default(),
            pii: PiiEngine::default(),
            cache: ExactCache::new(c.exact_max_entries, Duration::from_secs(c.exact_ttl_secs)),
            semantic: semantic_cache(&c.semantic),
            embedder,
            providers,
            usage,
            quota: Arc::new(InMemoryQuota::new()),
            salt_key: salt_key(),
            pii_keys: pii_keys(),
        }
    }

    /// Replaces the T2 store (tests, or a store built elsewhere).
    pub fn with_semantic_store(mut self, store: Arc<dyn VectorStore>) -> Self {
        let prefix = self.config.load().config.cache.semantic.collection_prefix.clone();
        self.semantic = Some(Arc::new(SemanticCache::new(store, prefix)));
        self
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
            HeaderName::from_static("x-caliban-cache"),
            HeaderName::from_static("x-caliban-cache-tier"),
            HeaderName::from_static("x-caliban-pii-entities"),
            HeaderName::from_static("x-caliban-cost-usd"),
        ])
}

/// Builds the T2 store from `[cache.semantic]` at start-up. The store exists whenever it can be
/// reached, even if the cache is disabled, so a later snapshot can switch it on; whether a request
/// uses it is decided per request from the current snapshot.
fn semantic_cache(c: &SemanticCacheConfig) -> Option<Arc<SemanticCache>> {
    let store: Arc<dyn VectorStore> = match c.store {
        SemanticStoreKind::Memory => {
            tracing::info!("semantic cache store: in-memory (this router only, lost on restart)");
            Arc::new(MemoryStore::default())
        }
        SemanticStoreKind::Qdrant => {
            let Some(url) = c.resolved_qdrant_url() else {
                if c.enabled {
                    tracing::warn!("cache.semantic is enabled but no Qdrant URL is set (CALIBAN_QDRANT_URL or cache.semantic.qdrant_url); semantic cache off");
                }
                return None;
            };
            if url.trim_end_matches('/').ends_with(":6334") {
                tracing::warn!(%url, "6334 is Qdrant's gRPC port; Caliban uses the REST API (default port 6333)");
            }
            let key = match c.resolved_qdrant_api_key() {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!(error = %e, "semantic cache off: Qdrant API key could not be resolved");
                    return None;
                }
            };
            match QdrantStore::new(&url, key) {
                Ok(s) => {
                    tracing::info!(%url, "semantic cache store: qdrant");
                    Arc::new(s)
                }
                Err(e) => {
                    tracing::error!(error = %e, "semantic cache off: Qdrant client");
                    return None;
                }
            }
        }
    };
    Some(Arc::new(SemanticCache::new(store, c.collection_prefix.clone())))
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
    // A degraded quota store does not fail the probe: limits are then enforced locally.
    axum::Json(serde_json::json!({ "status": "ok", "mode": "router", "config_version": snap.version, "quota": gw.quota.status() }))
}
