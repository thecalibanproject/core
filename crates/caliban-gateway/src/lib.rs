//! Data plane (`caliban router`): OpenAI- and Anthropic-compatible API on :8080.
//!
//! Request lifecycle (docs/architecture/caliban-reference-architecture.md §4):
//! auth → quota (GCRA rate + token reservation) → parse to IR → route → PII protect (per
//! destination trust tier) → T1 exact cache → T2 semantic cache → provider call with fallbacks
//! (BYOK) → stream/rehydrate → translate to the client's dialect → meter + settle → OTel GenAI span.
//!
//! `Idempotency-Key` on the inference POSTs: see [`idempotency`].
//!
//! Node runs (`/v1/nodes/{name}/runs`, `/v1/runs/{id}`): see [`nodes`].
//!
//! TODO: ontology grounding, Prometheus metrics.

mod auth;
mod chat;
pub mod embedder;
mod embeddings;
mod error;
mod idempotency;
mod limits;
mod messages;
mod metering;
#[cfg(test)]
mod metering_tests;
pub mod nodes;
#[cfg(test)]
mod nodes_tests;
mod passthrough;
pub mod pii_pool;
mod pipeline;
pub mod purge;
mod quirks;
mod rerank;
mod route_embed;
mod semantic;
mod stream;
pub mod telemetry;
#[cfg(test)]
mod tests;
pub mod tools;

pub use auth::{InternalCaller, NodeTag};
pub use error::{ApiError, Dialect};
pub use limits::{idempotency_store, quota_store};

use axum::Router;
use axum::http::{HeaderName, Method, header};
use axum::routing::{get, post};
use caliban_cache::ExactCache;
use caliban_cache::semantic::{MemoryStore, QdrantStore, SemanticCache, VectorStore};
use caliban_config::ConfigHandle;
use caliban_config::{SemanticCacheConfig, SemanticStoreKind};
use caliban_meter::UsageSink;
use caliban_meter::idempotency::{IdempotencyStore, MemoryIdempotency};
use caliban_meter::quota::{InMemoryQuota, QuotaStore};
use caliban_pii::{PiiEngine, SurrogateKeys};
use caliban_providers::Providers;
use caliban_types::Embedder;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

/// Max request body (bytes). Long-context requests are large; images should go via URLs.
pub(crate) const MAX_BODY: usize = 32 * 1024 * 1024;

pub struct Gateway {
    pub config: ConfigHandle,
    pub router: caliban_route::Router,
    /// PII detectors. Set with [`Gateway::with_pii`], which also starts the worker pool when the
    /// engine has a heavy detector (the NER model).
    pub pii: Arc<PiiEngine>,
    /// Dedicated workers for heavy PII engines (see [`pii_pool`]); `None` runs PII inline.
    pub pii_pool: Option<pii_pool::PiiPool>,
    pub cache: ExactCache,
    /// T2 semantic cache; `None` when no store is configured (`[cache.semantic]`).
    pub semantic: Option<Arc<SemanticCache>>,
    /// The one embedder for internal consumers ([`embedder::ProviderEmbedder`]): the semantic cache
    /// embeds through the tenant's route to its model, kNN routing through the shared provider only
    /// (`embed_shared`); both share its LRU.
    pub embedder: Arc<dyn Embedder>,
    pub providers: Arc<Providers>,
    pub usage: Arc<dyn UsageSink>,
    /// Rate limits and token budgets (`[limits]`). In-memory by default (exact per router
    /// process); `store = "valkey"` shares them across routers (see [`quota_store`]).
    pub quota: Arc<dyn QuotaStore>,
    /// `Idempotency-Key` records (see [`idempotency`]). In-memory by default; Valkey with
    /// `[limits] store = "valkey"` (see [`idempotency_store`]).
    pub idempotency: Arc<dyn IdempotencyStore>,
    /// Derives per-tenant `cache_salt` values. Derived from `CALIBAN_KEK` when set so all routers
    /// of a deployment agree; otherwise random per process.
    pub salt_key: [u8; 32],
    /// Derives per-tenant PII surrogate keys (HKDF over `CALIBAN_KEK`, tenant id as info), so all
    /// routers of a deployment produce the same surrogates; random per process without a KEK.
    pub pii_keys: SurrogateKeys,
    /// Models already warned about (cache tokens reported, no cache prices); once per process.
    cache_price_warned: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Node runs: executed here or forwarded to workers ([`Gateway::set_nodes`]); unset: the
    /// run API answers 503.
    nodes: std::sync::OnceLock<nodes::NodeRuns>,
}

impl Gateway {
    pub fn new(config: ConfigHandle, usage: Arc<dyn UsageSink>) -> Self {
        let c = config.load().config.cache.clone();
        metering::warn_missing_cache_prices_at_startup(&config.load());
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
            pii: Arc::new(PiiEngine::default()),
            pii_pool: None,
            cache: ExactCache::new(c.exact_max_entries, Duration::from_secs(c.exact_ttl_secs)),
            semantic: semantic_cache(&c.semantic),
            embedder,
            providers,
            usage,
            quota: Arc::new(InMemoryQuota::new()),
            idempotency: Arc::new(MemoryIdempotency::default()),
            salt_key: salt_key(),
            pii_keys: pii_keys(),
            cache_price_warned: Default::default(),
            nodes: std::sync::OnceLock::new(),
        }
    }

    /// Replaces the T2 store (tests, or a store built elsewhere).
    pub fn with_semantic_store(mut self, store: Arc<dyn VectorStore>) -> Self {
        let prefix = self.config.load().config.cache.semantic.collection_prefix.clone();
        self.semantic = Some(Arc::new(SemanticCache::new(store, prefix)));
        self
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

    /// Replaces the PII engine. An engine with a heavy detector ([`PiiEngine::is_heavy`], the
    /// NER model) runs on a dedicated worker pool sized by `pool`, with its bounded queue and
    /// overflow policy; a light engine runs inline and `pool` is ignored.
    pub fn with_pii(mut self, engine: PiiEngine, pool: pii_pool::PiiPoolOptions) -> Self {
        self.pii_pool = engine.is_heavy().then(|| pii_pool::PiiPool::new(pool));
        self.pii = Arc::new(engine);
        self
    }

    /// Replaces the quota store (e.g. a shared Valkey store for multi-router deployments).
    pub fn with_quota(mut self, quota: Arc<dyn QuotaStore>) -> Self {
        self.quota = quota;
        self
    }

    /// Replaces the `Idempotency-Key` store (e.g. the shared Valkey store).
    pub fn with_idempotency(mut self, store: Arc<dyn IdempotencyStore>) -> Self {
        self.idempotency = store;
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
            HeaderName::from_static("x-caliban-cache-tier"),
            HeaderName::from_static("x-caliban-pii-entities"),
            HeaderName::from_static("x-caliban-cost-usd"),
            HeaderName::from_static("x-caliban-billed-usd"),
            HeaderName::from_static(idempotency::REPLAYED),
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
                    tracing::warn!(
                        "cache.semantic is enabled but no Qdrant URL is set (CALIBAN_QDRANT_URL or cache.semantic.qdrant_url); semantic cache off"
                    );
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
    // Billed endpoints honour `Idempotency-Key`.
    let billed = Router::new()
        .route("/v1/chat/completions", post(chat::chat_completions))
        .route("/v1/messages", post(messages::messages))
        .route("/v1/embeddings", post(embeddings::embeddings))
        .route("/v1/rerank", post(rerank::rerank))
        .route_layer(axum::middleware::from_fn_with_state(Arc::clone(&gw), idempotency::middleware));
    Router::new()
        .merge(billed)
        .merge(nodes::routes())
        .route("/v1/messages/count_tokens", post(messages::count_tokens))
        .route("/v1/models", get(chat::list_models))
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
        .layer(RequestBodyLimitLayer::new(MAX_BODY))
        .layer(cors())
        .layer(TraceLayer::new_for_http())
        .with_state(gw)
}

pub(crate) async fn health(
    axum::extract::State(gw): axum::extract::State<Arc<Gateway>>,
) -> axum::Json<serde_json::Value> {
    let snap = gw.config.load();
    // A degraded quota store does not fail the probe: limits are then enforced locally. Neither
    // do usage WAL drops; they are reported under `usage_wal` (absent without a WAL).
    let mut body = serde_json::json!({
        "status": "ok",
        "mode": "router",
        "config_version": snap.version,
        // The KEKs that sealed the secrets of the snapshot being served (split mode; see
        // `caliban keys status`).
        "snapshot": { "version": snap.version, "kek_ids": snap.kek_ids },
        "quota": gw.quota.status(),
    });
    // Usage sinks: `usage_wal` (with a WAL), `usage_shipping` (split mode).
    for (k, v) in gw.usage.status() {
        body[k] = v;
    }
    axum::Json(body)
}

/// Prometheus text format: the snapshot being served (version and KEK ids as labels) and the
/// usage sinks' counters. No tenant data. Unauthenticated, like `/healthz`.
pub(crate) async fn metrics(
    axum::extract::State(gw): axum::extract::State<Arc<Gateway>>,
) -> impl axum::response::IntoResponse {
    let snap = gw.config.load();
    let label = |v: &str| v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
    let mut out = format!(
        "# HELP caliban_snapshot_info The config snapshot being served; kek_ids lists the KEKs that sealed its secrets.\n\
         # TYPE caliban_snapshot_info gauge\n\
         caliban_snapshot_info{{version=\"{}\",kek_ids=\"{}\"}} 1\n",
        label(&snap.version),
        label(&snap.kek_ids.join(","))
    );
    gw.usage.metrics(&mut out);
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], out)
}
