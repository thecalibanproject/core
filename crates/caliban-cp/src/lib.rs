//! Control plane (`caliban control-plane`, :8081): admin API under `/api/v1` and the web console.
//!
//! Admin auth ([`auth`]): OIDC single sign-on (console sessions and bearer access tokens) with
//! role-based access on every route, and the bootstrap token (`CALIBAN_ADMIN_TOKEN`) as break-glass.
//! Every mutation goes through [`store::Store::apply`] (one transaction + one hash-chained audit
//! row). Split deployments: routers poll `GET /api/v1/snapshot` (router token, not the admin
//! token) for an Ed25519-signed config snapshot.

pub mod auth;
mod evals;
pub mod introspect;
pub mod keys;
mod models;
mod nodes;
mod ontology;
pub mod rag;
mod runs;
pub mod store;
pub mod tools;

use auth::Principal;
use auth::rbac::Perm;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use caliban_config::signing::{SnapshotPayload, SnapshotSigner, config_digest};
use caliban_config::{Keyring, RouteConfig, SecretRef};
use caliban_nodes::publish::NodeCaps;
use caliban_ontology::Status;
use caliban_types::{PiiMode, PiiSurrogateScope, ProviderKind, SemanticCacheMode, TrustTier, hash_api_key};
use parking_lot::Mutex;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use store::audit::{now_micros, verify_chain};
use store::{
    ApiKeyRecord, DatasourceRecord, Mutation, ProviderKeyRecord, Store, StoreError, StoredSecret, Tenant, TenantStatus,
    new_id, slug,
};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

pub struct ControlPlane {
    pub store: Store,
    /// Break-glass bootstrap token; `None` when disabled.
    admin_token: Option<String>,
    /// Single sign-on; `None` = token mode (the bootstrap token is the only way in).
    oidc: Option<Arc<auth::oidc::Oidc>>,
    mode: &'static str,
    signer: Option<SnapshotSigner>,
    router_token: Option<String>,
    exported: Mutex<Option<Arc<Exported>>>,
    /// KEK keyring (`CALIBAN_KEK`, `CALIBAN_KEK_PREVIOUS`); without it secrets cannot be stored.
    keyring: Option<Arc<Keyring>>,
    /// The MCP client for tool discovery and the tool token key (JWKS).
    tools: Option<Arc<tools::ToolsSetup>>,
    /// The node run journal (console run endpoints): the database's, shared with workers, or a
    /// standalone process's in-memory one. `None`: those endpoints answer 503.
    journal: Option<Arc<dyn caliban_nodes::journal::Journal>>,
    /// The retrieval document registry (shared with the workers that index it). `None`: the
    /// retrieval endpoints answer 503.
    rag: Option<Arc<dyn caliban_rag::store::RagStore>>,
    /// Datasource introspection (the ontology bootstrap) and the jobs this process ran.
    introspector: Arc<dyn introspect::Introspector>,
}

/// The last signed snapshot, re-served while the rendered config is unchanged.
struct Exported {
    digest: String,
    etag: String,
    version: String,
    body: String,
}

impl ControlPlane {
    /// `admin_token` is the bootstrap (break-glass) token; empty disables it.
    pub fn new(store: Store, admin_token: String, mode: &'static str) -> Self {
        Self {
            store,
            admin_token: Some(admin_token).filter(|t| !t.is_empty()),
            oidc: None,
            mode,
            signer: None,
            router_token: None,
            exported: Mutex::new(None),
            keyring: None,
            tools: None,
            journal: None,
            rag: None,
            introspector: Arc::new(introspect::MongoIntrospector),
        }
    }

    /// How datasources are introspected (default: the MongoDB connector).
    #[must_use]
    pub fn with_introspector(mut self, i: Arc<dyn introspect::Introspector>) -> Self {
        self.introspector = i;
        self
    }

    pub(crate) fn introspector(&self) -> Arc<dyn introspect::Introspector> {
        Arc::clone(&self.introspector)
    }

    /// The retrieval document registry the admin API writes.
    #[must_use]
    pub fn with_rag(mut self, rag: Option<Arc<dyn caliban_rag::store::RagStore>>) -> Self {
        self.rag = rag;
        self
    }

    pub fn rag(&self) -> Option<Arc<dyn caliban_rag::store::RagStore>> {
        self.rag.clone()
    }

    /// The node run journal the console endpoints read.
    #[must_use]
    pub fn with_journal(mut self, journal: Option<Arc<dyn caliban_nodes::journal::Journal>>) -> Self {
        self.journal = journal;
        self
    }

    pub fn journal(&self) -> Option<Arc<dyn caliban_nodes::journal::Journal>> {
        self.journal.clone()
    }

    /// The MCP client used for tool discovery (default: the system resolver, no loopback) and
    /// the tool token key whose JWKS the control plane publishes.
    #[must_use]
    pub fn with_tools(mut self, tools: tools::ToolsSetup) -> Self {
        self.tools = Some(Arc::new(tools));
        self
    }

    pub(crate) fn tools(&self) -> Arc<tools::ToolsSetup> {
        static DEFAULT: std::sync::OnceLock<Arc<tools::ToolsSetup>> = std::sync::OnceLock::new();
        self.tools.clone().unwrap_or_else(|| {
            Arc::clone(DEFAULT.get_or_init(|| {
                Arc::new(tools::ToolsSetup {
                    client: Arc::new(caliban_mcp::client::McpClient::system(
                        caliban_mcp::egress::EgressPolicy::default(),
                    )),
                    signer: None,
                })
            }))
        })
    }

    /// Enables OIDC single sign-on.
    #[must_use]
    pub fn with_oidc(mut self, oidc: Option<auth::oidc::Oidc>) -> Self {
        self.oidc = oidc.map(Arc::new);
        self
    }

    /// `false` refuses the bootstrap token (`security.break_glass = false`).
    #[must_use]
    pub fn with_break_glass(mut self, enabled: bool) -> Self {
        if !enabled {
            self.admin_token = None;
        }
        self
    }

    /// Enables storing tenant and shared secrets (sealed under keys from this keyring).
    #[must_use]
    pub fn with_keyring(mut self, keyring: Option<Arc<Keyring>>) -> Self {
        self.keyring = keyring;
        self
    }

    pub(crate) fn keyring(&self, what: &str) -> ApiResult<&Keyring> {
        self.keyring.as_deref().ok_or_else(|| bad(format!("cannot store {what}: CALIBAN_KEK is not set")))
    }

    /// Resolves a secret reference with this control plane's keyring.
    pub(crate) fn resolve(&self, r: &SecretRef) -> Result<caliban_config::Secret, String> {
        match &self.keyring {
            Some(k) => r.resolve_with(k),
            None => r.resolve(),
        }
        .map_err(|e| e.to_string())
    }

    /// Enables `GET /api/v1/snapshot` for remote routers.
    #[must_use]
    pub fn with_snapshots(mut self, signer: Option<SnapshotSigner>, router_token: Option<String>) -> Self {
        self.signer = signer;
        self.router_token = router_token.filter(|t| !t.is_empty());
        self
    }
}

pub(crate) type Cp = Arc<ControlPlane>;

/// Polls the store for commits made by other control-plane replicas (Postgres) and republishes.
pub fn spawn_refresh(cp: Cp, every: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match cp.store.refresh().await {
                Ok(true) => tracing::info!(version = %cp.store.config.load().version, "reloaded control-plane state"),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, "store refresh failed; serving cached state"),
            }
        }
    })
}

/// Usage retention (Postgres store): hourly, raw usage events older than `days` move into the
/// daily roll-up; totals stay the same. Several control planes may run it; one does the work.
pub fn spawn_usage_retention(cp: Cp, days: u32, every: Duration) -> tokio::task::JoinHandle<()> {
    cp.store.set_usage_retention_days(days);
    tokio::spawn(async move {
        if days == 0 {
            return;
        }
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match cp.store.rollup_usage(days).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(events = n, days, "rolled up usage events past retention"),
                Err(e) => tracing::warn!(error = %e, "usage roll-up failed; retrying later"),
            }
        }
    })
}

/// Drains the control plane's own entries of the shared outboxes (the node journal's and the
/// retrieval registry's) into the audit chain every `every`. Each write drains at once; this
/// catches entries a control plane left behind (it stopped between the write and the drain),
/// since workers ship only the data plane's decisions.
pub fn spawn_audit_drain(cp: Cp, every: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Some(j) = cp.journal()
                && let Err(e) = runs::drain_audit(&cp, &j).await
            {
                tracing::warn!(error = %e.1, "draining the node journal's audit outbox failed; retrying later");
            }
            if let Some(r) = cp.rag()
                && let Err(e) = rag::drain(&cp, &r).await
            {
                tracing::warn!(error = %e.1, "draining the retrieval registry's audit outbox failed; retrying later");
            }
        }
    })
}

pub(crate) struct ApiError(pub(crate) StatusCode, pub(crate) String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let kind = match self.0 {
            StatusCode::UNAUTHORIZED => "authentication_error",
            StatusCode::FORBIDDEN => "permission_error",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::CONFLICT => "conflict",
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY | StatusCode::PAYLOAD_TOO_LARGE => {
                "invalid_request_error"
            }
            StatusCode::SERVICE_UNAVAILABLE => "unavailable",
            _ => "internal_error",
        };
        (self.0, Json(json!({ "error": { "message": self.1, "type": kind, "code": null } }))).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound(what) => not_found(&what),
            StoreError::Conflict(m) => ApiError(StatusCode::CONFLICT, m),
            StoreError::Invalid(m) => ApiError(StatusCode::UNPROCESSABLE_ENTITY, m),
            StoreError::Rejected(e) => ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
            StoreError::Backend(m) => {
                tracing::error!(error = %m, "store backend error");
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "store error".into())
            }
        }
    }
}

/// For deletes: a change the rendered config rejects means something still references the item.
pub(crate) fn still_referenced(e: StoreError, what: &str) -> ApiError {
    match e {
        StoreError::Invalid(m) => ApiError(StatusCode::CONFLICT, format!("{what} is still referenced: {m}")),
        other => other.into(),
    }
}

pub(crate) fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

pub(crate) fn not_found(what: &str) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, format!("{what} not found"))
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;

pub fn app(cp: Cp, web_dir: Option<&str>) -> Router {
    let api = Router::new()
        .route("/tenants", get(list_tenants).post(create_tenant))
        .route("/tenants/{tenant_id}", get(get_tenant).patch(update_tenant).delete(delete_tenant))
        .route("/tenants/{tenant_id}/api-keys", get(list_api_keys).post(create_api_key))
        .route("/tenants/{tenant_id}/api-keys/{key_id}", delete(revoke_api_key).patch(update_api_key))
        .route("/tenants/{tenant_id}/provider-keys", get(list_provider_keys).post(create_provider_key))
        .route("/tenants/{tenant_id}/provider-keys/{key_id}", delete(delete_provider_key))
        .route("/tenants/{tenant_id}/routes", get(get_routes).put(put_routes))
        .route("/tenants/{tenant_id}/datasources/{id}", delete(delete_datasource))
        .route("/tenants/{tenant_id}/nodes/{id}", delete(nodes::delete_node))
        .route("/tenants/{tenant_id}/nodes/{id}/versions", get(nodes::list_versions).post(nodes::create_version))
        .route("/tenants/{tenant_id}/nodes/{id}/versions/{version}", get(nodes::get_version))
        .route("/tenants/{tenant_id}/nodes/{id}/versions/{version}/publish", post(nodes::publish))
        .route("/tenants/{tenant_id}/nodes/{id}/versions/{version}/retire", post(nodes::retire))
        .route("/tenants/{tenant_id}/nodes/{id}/promote", post(nodes::promote))
        .route("/tenants/{tenant_id}/nodes/{id}/diff", get(nodes::diff))
        .route(
            "/tenants/{tenant_id}/nodes/{id}/versions/{version}/golden-set",
            get(evals::get_golden).put(evals::put_golden).delete(evals::delete_golden),
        )
        .route("/tenants/{tenant_id}/nodes/{id}/versions/{version}/evals", post(evals::start))
        .route("/tenants/{tenant_id}/nodes/{id}/versions/{version}/gate", get(evals::get_gate))
        .route("/tenants/{tenant_id}/nodes/{id}/eval-policy", get(evals::get_policy).put(evals::put_policy))
        .route("/tenants/{tenant_id}/eval-key", get(evals::get_eval_key))
        .route("/tenants/{tenant_id}/eval-key/rotate", post(evals::rotate_eval_key))
        .route("/tenants/{tenant_id}/evals", get(evals::list))
        .route("/tenants/{tenant_id}/evals/{id}", get(evals::get))
        .route("/tenants/{tenant_id}/evals/{id}/cancel", post(evals::cancel))
        .route("/tenants/{tenant_id}/tool-servers", get(tools::list_servers).post(tools::create_server))
        .route("/tenants/{tenant_id}/tool-servers/{server}", delete(tools::delete_server).patch(tools::update_server))
        .route("/tenants/{tenant_id}/tool-servers/{server}/discover", post(tools::discover))
        .route("/tenants/{tenant_id}/tool-servers/{server}/tools", get(tools::list_tools).post(tools::import))
        .route("/tenants/{tenant_id}/tool-servers/{server}/tools/{tool}/approve", post(tools::approve))
        .route("/tenants/{tenant_id}/tool-servers/{server}/tools/{tool}/revoke", post(tools::revoke))
        .route("/tenants/{tenant_id}/rag/collections", get(rag::list_collections).post(rag::create_collection))
        .route("/tenants/{tenant_id}/rag/models", get(rag::models))
        .route(
            "/tenants/{tenant_id}/rag/collections/{collection}",
            get(rag::get_collection).delete(rag::delete_collection),
        )
        .route(
            "/tenants/{tenant_id}/rag/collections/{collection}/documents",
            get(rag::list_documents)
                .post(rag::ingest)
                .layer(axum::extract::DefaultBodyLimit::max(rag::INGEST_MAX_BYTES)),
        )
        .route(
            "/tenants/{tenant_id}/rag/collections/{collection}/documents/{doc_id}",
            get(rag::get_document).delete(rag::delete_document),
        )
        .route("/tenants/{tenant_id}/rag/collections/{collection}/documents/{doc_id}/release", post(rag::release))
        .route("/tenants/{tenant_id}/runs", get(runs::list))
        .route("/tenants/{tenant_id}/runs/{id}", get(runs::get))
        .route("/tenants/{tenant_id}/runs/{id}/input", post(runs::answer))
        .route("/tenants/{tenant_id}/runs/{id}/cancel", post(runs::cancel))
        .route("/tenants/{tenant_id}/inbox", get(runs::inbox))
        .route("/tenants/{tenant_id}/node-spend", get(runs::spend))
        .route("/models", get(models::list_models).post(models::create_model))
        .route("/models/{*id}", delete(models::delete_model))
        .route("/providers", get(models::list_providers).post(models::create_provider))
        .route("/providers/{id}", delete(models::delete_provider))
        .route("/providers/{id}/health", get(models::provider_health))
        .route("/providers/{id}/discover", post(models::discover))
        .route("/datasources", get(list_datasources).post(create_datasource))
        .route("/datasources/{id}/introspect", post(introspect_datasource))
        .route("/ontology", get(get_ontology))
        .route("/ontology/elements/{id}/review", post(review_element))
        .route("/tenants/{tenant_id}/intents", get(list_intents))
        .route("/tenants/{tenant_id}/intents/{intent}", axum::routing::put(put_intent).delete(delete_intent))
        .route("/tenants/{tenant_id}/ontology", get(get_tenant_ontology))
        .route("/tenants/{tenant_id}/ontology/proposals", post(propose_ontology))
        .route("/datasources/{id}/introspection", get(get_introspection))
        .route("/tenants/{tenant_id}/ontology/review", post(review_batch))
        .route("/tenants/{tenant_id}/ontology/elements/{id}/review", post(review_tenant_element))
        .route("/nodes", get(nodes::list_nodes).post(nodes::create_node))
        .route("/usage", get(usage))
        .route("/audit", get(audit))
        .route("/keys/status", get(keys_status))
        .route("/roles", get(auth::admin::roles))
        .route("/users", get(auth::admin::list_users))
        .route("/users/{id}/sessions", delete(auth::admin::revoke_sessions))
        .route("/role-bindings", get(auth::admin::list_bindings).post(auth::admin::create_binding))
        .route("/role-bindings/{id}", delete(auth::admin::delete_binding))
        // Authentication and the route's permission (auth::rbac::ROUTES; no entry = denied).
        .route_layer(middleware::from_fn_with_state(Arc::clone(&cp), auth::authorize))
        // Router token, not the admin token: a compromised router cannot administer.
        .route("/snapshot", get(snapshot))
        .route("/usage/ingest", post(ingest_usage).layer(axum::extract::DefaultBodyLimit::max(INGEST_MAX_BYTES)))
        .route("/audit/ingest", post(ingest_audit))
        .route("/health", get(health));

    let mut app = Router::new()
        .nest("/api/v1", api)
        .route("/.well-known/caliban-tool-jwks.json", get(tools::jwks))
        .merge(auth::handlers::routes());
    if let Some(dir) = web_dir {
        // SPA: unknown paths fall back to index.html for client-side routing.
        let index = format!("{dir}/index.html");
        app = app.fallback_service(ServeDir::new(dir).not_found_service(ServeFile::new(index)));
    }
    app.layer(TraceLayer::new_for_http()).with_state(cp)
}

fn bearer_is(headers: &HeaderMap, expected: &str) -> bool {
    !expected.is_empty()
        && headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| auth::constant_time_eq(t.trim().as_bytes(), expected.as_bytes()))
}

async fn health(State(cp): State<Cp>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": cp.mode,
        "store": cp.store.backend_name(),
        "config_version": cp.store.config.load().version,
    }))
}

// ───────────────────────────── signed snapshot (split mode) ─────────────────────────────

async fn snapshot(State(cp): State<Cp>, headers: HeaderMap) -> Response {
    let (Some(token), Some(signer)) = (cp.router_token.as_deref(), cp.signer.as_ref()) else {
        return ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "split mode is not enabled: set CALIBAN_ROUTER_TOKEN and CALIBAN_SNAPSHOT_SIGNING_KEY on the control plane"
                .into(),
        )
        .into_response();
    };
    if !bearer_is(&headers, token) {
        return ApiError(StatusCode::UNAUTHORIZED, "invalid router token".into()).into_response();
    }
    record_checkin(&cp, &headers).await;
    // Pick up commits from other control-plane replicas (one cheap query on Postgres).
    if let Err(e) = cp.store.refresh().await {
        tracing::warn!(error = %e, "store refresh failed; exporting cached state");
    }
    let snap = cp.store.config.load();
    let mut config = snap.config.clone();
    // Routers never need the admin credential reference or the SSO settings.
    config.security.admin_token = None;
    config.security.oidc = None;
    config.security.break_glass = true;
    let digest = config_digest(&config);
    let etag = format!("\"{}\"", &digest[..32]);
    let not_modified = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim().trim_start_matches("W/") == etag));
    if not_modified {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }
    let exported = {
        let mut cached = cp.exported.lock();
        match cached.as_ref().filter(|e| e.digest == digest) {
            Some(e) => Arc::clone(e),
            None => {
                let issued_at_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or_default();
                // The KEKs a router needs to open this snapshot's secrets; routers report them
                // back, so `keys status` can tell when a retired KEK is no longer served.
                let kek_ids = caliban_config::sealed_kek_ids(&config, cp.keyring.as_deref());
                let payload = SnapshotPayload { version: snap.version.clone(), issued_at_ms, config, kek_ids };
                let signed = match signer.sign(&payload) {
                    Ok(s) => s,
                    Err(e) => return ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
                };
                let e = Arc::new(Exported {
                    digest,
                    etag: etag.clone(),
                    version: snap.version.clone(),
                    body: serde_json::to_string(&signed).unwrap_or_default(),
                });
                *cached = Some(Arc::clone(&e));
                e
            }
        }
    };
    let mut resp = (StatusCode::OK, exported.body.clone()).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(v) = HeaderValue::from_str(&exported.etag) {
        h.insert(header::ETAG, v);
    }
    if let Ok(v) = HeaderValue::from_str(&exported.version) {
        h.insert("x-caliban-snapshot-version", v);
    }
    resp
}

/// Records what the polling router serves (see `caliban_config::signing::checkin`). Routers of
/// older releases send no id and are not recorded. A failed write is logged; the poll succeeds.
async fn record_checkin(cp: &ControlPlane, headers: &HeaderMap) {
    use caliban_config::signing::checkin;
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::trim);
    let Some(router_id) = get(checkin::ROUTER_ID).filter(|id| valid_router_id(id)) else { return };
    let list = |name: &str| -> Vec<String> {
        get(name)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .take(16)
                    .map(|s| s.chars().take(64).collect())
                    .collect()
            })
            .unwrap_or_default()
    };
    let r = store::RouterStatus {
        router_id: router_id.to_owned(),
        last_seen: chrono::Utc::now(),
        snapshot_version: get(checkin::SNAPSHOT_VERSION).unwrap_or_default().chars().take(64).collect(),
        snapshot_kek_ids: list(checkin::SNAPSHOT_KEK_IDS),
        keyring: list(checkin::KEYRING),
    };
    if let Err(e) = cp.store.router_checkin(r).await {
        tracing::warn!(error = %e, router = router_id, "cannot record router check-in");
    }
}

/// Router ids: 1 to 128 characters of `[A-Za-z0-9._:-]`.
fn valid_router_id(id: &str) -> bool {
    (1..=128).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

/// `caliban keys status` over the API: which KEK wraps each tenant data key, whether the retired
/// keys are still needed by stored data, and which routers still serve a snapshot sealed under one.
async fn keys_status(State(cp): State<Cp>) -> ApiResult<Json<Value>> {
    let mut out = keys::status(&cp.store.state(), cp.keyring.as_deref());
    let routers = cp.store.routers().await?;
    keys::add_routers(&mut out, &routers, cp.keyring.as_deref(), chrono::Utc::now());
    Ok(Json(out))
}

// ───────────────────────────── audit ─────────────────────────────

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

/// Newest entries first. `chain_verified` re-checks the hashes and links of the returned window.
async fn audit(State(cp): State<Cp>, Query(q): Query<AuditQuery>) -> ApiResult<Json<Value>> {
    let mut entries = cp.store.audit(q.limit.unwrap_or(100).clamp(1, 1000)).await?;
    let verified = verify_chain(&entries).is_ok();
    let head = entries.last().map(|e| json!({ "seq": e.seq, "hash": e.hash }));
    entries.reverse();
    Ok(Json(json!({ "entries": entries, "head": head, "chain_verified": verified })))
}

// ───────────────────────────── tenants & keys ─────────────────────────────

#[derive(Deserialize, Default)]
struct TenantList {
    #[serde(default)]
    include_deleted: bool,
}

/// Active tenants; `?include_deleted=true` adds tombstones (`status: deleted`).
async fn list_tenants(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Query(q): Query<TenantList>,
) -> Json<Vec<Value>> {
    let visible = p.visible(Perm::TenantRead);
    Json(
        cp.store
            .state()
            .tenants
            .iter()
            .filter(|t| (q.include_deleted || t.is_active()) && visible.contains(&t.id))
            .map(|t| tenant_view(t, &p))
            .collect(),
    )
}

/// A tenant as `p` may see it. The PII detectors (`pii_patterns`, `pii_dictionary`, which may
/// hold staff or customer names) are shown only to callers who may change them (`tenant.write`);
/// everyone gets their counts (`pii_patterns_count`, `pii_dictionary_count`).
fn tenant_view(t: &Tenant, p: &Principal) -> Value {
    let mut v = serde_json::to_value(t).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert("pii_patterns_count".into(), json!(t.pii_patterns.len()));
        o.insert("pii_dictionary_count".into(), json!(t.pii_dictionary.len()));
        if !p.allows(Perm::TenantWrite, Some(&t.id)) {
            o.remove("pii_patterns");
            o.remove("pii_dictionary");
        }
    }
    v
}

#[derive(Deserialize)]
struct TenantCreate {
    name: String,
    region: Option<String>,
    pii_default: Option<PiiMode>,
    pii_surrogate_scope: Option<PiiSurrogateScope>,
    pii_on_sovereign: Option<bool>,
    pii_patterns: Option<Vec<caliban_config::PiiPattern>>,
    pii_dictionary: Option<Vec<caliban_config::PiiTerm>>,
    semantic_cache: Option<SemanticCacheMode>,
    auto_cache_hit_fraction: Option<f64>,
    node_caps: Option<NodeCaps>,
    node_spend_caps: Option<caliban_config::NodeSpendCaps>,
    node_routes: Option<std::collections::BTreeMap<String, String>>,
}

async fn create_tenant(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Json(body): Json<TenantCreate>,
) -> ApiResult<(StatusCode, Json<Tenant>)> {
    let id = slug(&body.name);
    if id.is_empty() {
        return Err(bad("name must contain letters or digits"));
    }
    if let Some(c) = &body.node_caps {
        c.validate().map_err(bad)?;
    }
    if let Some(c) = &body.node_spend_caps {
        c.validate().map_err(bad)?;
    }
    if let Some(r) = &body.node_routes {
        caliban_config::check_node_routes(r).map_err(bad)?;
    }
    store::memory::check_pii_detectors(
        body.pii_patterns.as_deref().unwrap_or_default(),
        body.pii_dictionary.as_deref().unwrap_or_default(),
    )
    .map_err(|e| bad(e.to_string()))?;
    let t = Tenant {
        id,
        name: body.name,
        region: body.region,
        pii_default: body.pii_default.unwrap_or(cp.store.base().pii.default_mode),
        pii_surrogate_scope: body.pii_surrogate_scope.unwrap_or_default(),
        pii_on_sovereign: body.pii_on_sovereign.unwrap_or(false),
        pii_patterns: body.pii_patterns.unwrap_or_default(),
        pii_dictionary: body.pii_dictionary.unwrap_or_default(),
        intents: std::collections::BTreeMap::new(),
        semantic_cache: body.semantic_cache.unwrap_or_default(),
        auto_cache_hit_fraction: body.auto_cache_hit_fraction,
        node_caps: body.node_caps,
        node_spend_caps: body.node_spend_caps,
        node_routes: body.node_routes,
        created_at: now_micros(),
        status: TenantStatus::Active,
        deleted_at: None,
        settings: serde_json::Map::new(),
    };
    cp.store.apply(&p.actor, Mutation::CreateTenant(t.clone())).await?;
    Ok((StatusCode::CREATED, Json(t)))
}

async fn get_tenant(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
) -> ApiResult<Json<Value>> {
    cp.store.state().tenant(&tenant_id).map(|t| Json(tenant_view(t, &p))).ok_or_else(|| not_found("tenant"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantUpdate {
    pii_default: Option<PiiMode>,
    pii_surrogate_scope: Option<PiiSurrogateScope>,
    /// The PII mode also applies to sovereign and attested models (default false).
    pii_on_sovereign: Option<bool>,
    /// The tenant's own PII patterns (replaced; `[]` clears them).
    pii_patterns: Option<Vec<caliban_config::PiiPattern>>,
    /// The tenant's PII dictionary (replaced; `[]` clears it).
    pii_dictionary: Option<Vec<caliban_config::PiiTerm>>,
    semantic_cache: Option<SemanticCacheMode>,
    /// Absent: kept. `null`: cleared (the deployment value applies). A number in 0..=1: set.
    #[serde(default, deserialize_with = "present")]
    auto_cache_hit_fraction: Option<Option<f64>>,
    /// Caps on the budgets of the node versions the tenant publishes. Absent: kept. `null`:
    /// cleared (the defaults apply).
    #[serde(default, deserialize_with = "present")]
    node_caps: Option<Option<NodeCaps>>,
    /// Daily and monthly caps on the tenant's node spend (USD). Absent: kept. `null`: no cap.
    #[serde(default, deserialize_with = "present")]
    node_spend_caps: Option<Option<caliban_config::NodeSpendCaps>>,
    /// Intents `caliban/auto` hands to nodes (`{"triage": "node/triage"}`). Absent: kept. `null`:
    /// cleared (the config file's `[routing.tenants.<id>.routes]` still apply).
    #[serde(default, deserialize_with = "present")]
    node_routes: Option<Option<std::collections::BTreeMap<String, String>>>,
}

/// Tells an explicit `null` (`Some(None)`) from an absent field (`None`, with `#[serde(default)]`).
pub(crate) fn present<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// Changes a tenant's PII, cache and cache-hit billing settings (absent fields are kept). Audited;
/// routers pick it up with the next snapshot.
async fn update_tenant(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
    Json(body): Json<TenantUpdate>,
) -> ApiResult<Json<Tenant>> {
    let m = Mutation::UpdateTenant {
        id: tenant_id.clone(),
        pii_default: body.pii_default,
        pii_surrogate_scope: body.pii_surrogate_scope,
        pii_on_sovereign: body.pii_on_sovereign,
        pii_patterns: body.pii_patterns,
        pii_dictionary: body.pii_dictionary,
        semantic_cache: body.semantic_cache,
        auto_cache_hit_fraction: body.auto_cache_hit_fraction,
        node_caps: body.node_caps,
        node_spend_caps: body.node_spend_caps,
        node_routes: body.node_routes,
    };
    let st = cp.store.apply(&p.actor, m).await?;
    st.tenant(&tenant_id).cloned().map(Json).ok_or_else(|| not_found("tenant"))
}

/// Tombstones the tenant: revokes its API keys, destroys its BYOK credentials, removes its routes
/// and soft-deletes its datasources and nodes, in one audited transaction. The tenant leaves the
/// data-plane snapshot. A repeat delete is a 404, like every other delete.
async fn delete_tenant(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
) -> ApiResult<StatusCode> {
    cp.store.apply(&p.actor, Mutation::DeleteTenant { id: tenant_id.clone(), at: now_micros() }).await?;
    // Its document collections go too (their content was sealed under the key just destroyed);
    // workers drop the vectors.
    if let Some(r) = cp.rag()
        && let Err(e) = r.delete_tenant(&tenant_id, chrono::Utc::now()).await
    {
        tracing::error!(error = %e, tenant = %tenant_id, "deleting the tenant's document collections failed");
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn ensure_tenant(cp: &ControlPlane, id: &str) -> ApiResult<()> {
    if cp.store.state().has_tenant(id) { Ok(()) } else { Err(not_found("tenant")) }
}

#[derive(Deserialize, Default)]
struct ApiKeyList {
    #[serde(default)]
    include_revoked: bool,
}

/// Active keys; `?include_revoked=true` adds revoked ones (with `revoked_at`).
async fn list_api_keys(
    State(cp): State<Cp>,
    Path(tenant_id): Path<String>,
    Query(q): Query<ApiKeyList>,
) -> ApiResult<Json<Vec<ApiKeyRecord>>> {
    ensure_tenant(&cp, &tenant_id)?;
    let st = cp.store.state();
    Ok(Json(
        st.api_keys
            .iter()
            .filter(|k| k.tenant_id == tenant_id && (q.include_revoked || k.is_active()))
            .cloned()
            .collect(),
    ))
}

/// Soft revoke: the row is kept with `revoked_at`, and the key's hash leaves the data-plane
/// snapshot (standalone: immediately; split mode: on the router's next snapshot poll).
async fn revoke_api_key(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, key_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    refuse_eval_key(&cp, &tenant_id, &key_id)?;
    cp.store.apply(&p.actor, Mutation::RevokeApiKey { tenant_id, id: key_id, at: now_micros() }).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The eval key is managed by the control plane: `409` on the customer key endpoints.
fn refuse_eval_key(cp: &Cp, tenant_id: &str, key_id: &str) -> ApiResult<()> {
    let st = cp.store.state();
    if st.api_keys.iter().any(|k| k.tenant_id == tenant_id && k.id == key_id && k.is_eval()) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "this is the tenant's eval key, managed by the control plane: rotate it with \
             POST /api/v1/tenants/{tenant_id}/eval-key/rotate (it is revoked with the tenant)"
                .into(),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiKeyUpdate {
    /// Node allowlist. Absent: kept. `null`: every published node of the tenant. A list: only
    /// those (`[]`: none). Needs `nodes.run` on the tenant.
    #[serde(default, deserialize_with = "present")]
    nodes: Option<Option<Vec<String>>>,
    /// Datasource scopes. Absent: kept. `null`: every scope of the nodes the key runs.
    #[serde(default, deserialize_with = "present")]
    datasource_scopes: Option<Option<Vec<String>>>,
}

/// Changes a key's node allowlist and datasource scopes after creation (audited as
/// `api_key.update` with the old and new values). Routers pick it up with the next snapshot.
async fn update_api_key(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, key_id)): Path<(String, String)>,
    Json(body): Json<ApiKeyUpdate>,
) -> ApiResult<Json<ApiKeyRecord>> {
    if body.nodes.is_some() && !p.allows(Perm::NodesRun, Some(&tenant_id)) {
        return Err(auth::forbidden("changing an API key's node access needs the nodes.run permission"));
    }
    refuse_eval_key(&cp, &tenant_id, &key_id)?;
    let m = Mutation::UpdateApiKey {
        tenant_id: tenant_id.clone(),
        id: key_id.clone(),
        nodes: body.nodes,
        datasource_scopes: body.datasource_scopes,
    };
    let st = cp.store.apply(&p.actor, m).await?;
    st.active_api_key(&tenant_id, &key_id).cloned().map(Json).ok_or_else(|| not_found("api key"))
}

#[derive(Deserialize, Default)]
struct ApiKeyCreate {
    name: Option<String>,
    /// Node allowlist: the nodes the key may run. Absent: every published node of the tenant;
    /// `[]`: none. Granting node access needs `nodes.run` on the tenant.
    nodes: Option<Vec<String>>,
    /// Datasource scopes (`<datasource>.<object>:read`) the built-in query tool may read for this
    /// key's runs, intersected with each node's. Absent: every scope of the nodes it runs.
    datasource_scopes: Option<Vec<String>>,
}

async fn create_api_key(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
    body: Option<Json<ApiKeyCreate>>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let body = body.map(|b| b.0).unwrap_or_default();
    // A key cannot be given rights its creator does not hold: without `nodes.run`, the key runs
    // no nodes.
    let nodes = if p.allows(Perm::NodesRun, Some(&tenant_id)) {
        body.nodes
    } else if body.nodes.as_ref().is_some_and(|n| !n.is_empty()) {
        return Err(auth::forbidden("granting node access to an API key needs the nodes.run permission"));
    } else {
        Some(vec![])
    };
    let key = generate_api_key();
    let rec = ApiKeyRecord {
        id: new_id("key"),
        tenant_id,
        name: body.name.unwrap_or_else(|| "default".into()),
        prefix: key.chars().take(8).collect(),
        hash: hash_api_key(&key),
        created_at: now_micros(),
        revoked_at: None,
        nodes,
        datasource_scopes: body.datasource_scopes,
        purpose: None,
    };
    cp.store.apply(&p.actor, Mutation::CreateApiKey(rec.clone())).await?;
    let mut v = serde_json::to_value(&rec).unwrap_or_default();
    v["key"] = Value::String(key);
    Ok((StatusCode::CREATED, Json(v)))
}

/// `cal_` + 32 random bytes in hex.
pub fn generate_api_key() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    format!("cal_{}", hex::encode(b))
}

async fn list_provider_keys(
    State(cp): State<Cp>,
    Path(tenant_id): Path<String>,
) -> ApiResult<Json<Vec<ProviderKeyRecord>>> {
    ensure_tenant(&cp, &tenant_id)?;
    Ok(Json(cp.store.state().provider_keys.iter().filter(|k| k.tenant_id == tenant_id).cloned().collect()))
}

#[derive(Deserialize)]
struct ProviderKeyCreate {
    kind: ProviderKind,
    label: String,
    provider_id: Option<String>,
    base_url: Option<String>,
    api_key: Option<String>,
    trust_tier: TrustTier,
    #[serde(default)]
    cache_salt: bool,
}

async fn create_provider_key(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
    Json(body): Json<ProviderKeyCreate>,
) -> ApiResult<(StatusCode, Json<ProviderKeyRecord>)> {
    ensure_tenant(&cp, &tenant_id)?;
    if body.base_url.is_none() && store::default_base_url(body.kind).is_none() {
        return Err(bad("base_url is required for this provider kind"));
    }
    let id = body.provider_id.as_deref().map_or_else(|| slug(&body.label), slug);
    // Sealed under the tenant's DEK before it reaches the store: plaintext is never persisted or
    // audited.
    let (secret, last4) = match body.api_key.as_deref().filter(|k| !k.is_empty()) {
        Some(k) => {
            let keyring = cp.keyring("provider keys")?;
            let dek = keys::tenant_dek(&cp.store, keyring, &tenant_id, &p.actor).await?;
            let last4: String = k.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
            (Some(StoredSecret::TenantDek(dek.seal(&tenant_id, k))), Some(last4))
        }
        None => (None, None),
    };
    let rec = ProviderKeyRecord {
        id,
        tenant_id,
        kind: body.kind,
        label: body.label,
        base_url: body.base_url,
        trust_tier: body.trust_tier,
        last4,
        cache_salt: body.cache_salt,
        created_at: now_micros(),
        secret,
    };
    cp.store.apply(&p.actor, Mutation::CreateProviderKey(rec.clone())).await?;
    Ok((StatusCode::CREATED, Json(rec)))
}

async fn delete_provider_key(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, key_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    // The sealed ciphertext is dropped with the row. Copies in backups stay sealed under the
    // tenant DEK, which is destroyed with the tenant (see `keys`).
    cp.store
        .apply(&p.actor, Mutation::DeleteProviderKey { tenant_id, id: key_id })
        .await
        .map_err(|e| still_referenced(e, "provider key"))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_routes(State(cp): State<Cp>, Path(tenant_id): Path<String>) -> ApiResult<Json<Vec<RouteConfig>>> {
    ensure_tenant(&cp, &tenant_id)?;
    Ok(Json(cp.store.state().routes.get(&tenant_id).cloned().unwrap_or_default()))
}

#[derive(Deserialize)]
struct RoutesPut {
    routes: Vec<RouteConfig>,
}

/// Replaces the tenant's routes. Rejected (422) if a route names a model the tenant cannot reach.
async fn put_routes(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
    Json(body): Json<RoutesPut>,
) -> ApiResult<Json<Vec<RouteConfig>>> {
    let st =
        cp.store.apply(&p.actor, Mutation::SetRoutes { tenant_id: tenant_id.clone(), routes: body.routes }).await?;
    Ok(Json(st.routes.get(&tenant_id).cloned().unwrap_or_default()))
}

// ───────────────────────────── datasources & ontology ─────────────────────────────

#[derive(Deserialize)]
struct TenantFilter {
    tenant_id: Option<String>,
}

async fn list_datasources(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Query(f): Query<TenantFilter>,
) -> Json<Vec<DatasourceRecord>> {
    let st = cp.store.state();
    let visible = p.visible(Perm::DatasourcesRead);
    Json(
        st.datasources
            .iter()
            .filter(|d| d.is_live() && f.tenant_id.as_ref().is_none_or(|t| &d.tenant_id == t))
            .filter(|d| visible.contains(&d.tenant_id))
            .cloned()
            .collect(),
    )
}

#[derive(Deserialize)]
struct DatasourceCreate {
    tenant_id: String,
    kind: String,
    name: String,
    connection: Value,
}

const DATASOURCE_KINDS: &[&str] = &[
    "mongodb",
    "postgres",
    "mysql",
    "sqlserver",
    "snowflake",
    "bigquery",
    "clickhouse",
    "elasticsearch",
    "rest_openapi",
    "s3_parquet",
    "mcp",
];

async fn create_datasource(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Json(body): Json<DatasourceCreate>,
) -> ApiResult<(StatusCode, Json<DatasourceRecord>)> {
    if !DATASOURCE_KINDS.contains(&body.kind.as_str()) {
        return Err(bad(format!("unsupported datasource kind '{}'", body.kind)));
    }
    // `rag.<collection>:read` scopes name document collections, not a datasource.
    if body.name.eq_ignore_ascii_case(caliban_nodes::RAG_SCOPE) {
        return Err(bad("'rag' is reserved (rag.<collection>:read scopes name document collections)"));
    }
    keys::reject_reserved(&body.connection).map_err(bad)?;
    ensure_tenant(&cp, &body.tenant_id)?;
    // Credentials (password fields, URIs with a password, tokens, ...) are sealed under the
    // tenant's DEK like BYOK keys; `{env}`/`{file}` references are kept as references.
    let connection = if keys::needs_sealing(&body.connection) {
        let keyring = cp.keyring("datasource credentials")?;
        let dek = keys::tenant_dek(&cp.store, keyring, &body.tenant_id, &p.actor).await?;
        keys::seal_connection(&body.connection, &body.tenant_id, &dek)
    } else {
        body.connection
    };
    let rec = DatasourceRecord {
        id: new_id("ds"),
        tenant_id: body.tenant_id,
        kind: body.kind,
        name: body.name,
        status: "pending".into(),
        epoch: 0,
        connection,
        deleted_at: None,
    };
    cp.store.apply(&p.actor, Mutation::CreateDatasource(rec.clone())).await?;
    Ok((StatusCode::CREATED, Json(rec)))
}

/// Soft delete scoped to the tenant: the row is kept for audit, its stored connection is wiped.
async fn delete_datasource(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    cp.store.apply(&p.actor, Mutation::DeleteDatasource { tenant_id, id, at: now_micros() }).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/datasources/{id}/introspect`: starts the ontology bootstrap (see [`introspect`]).
/// `202` with the job; `409` while one runs for the datasource.
async fn introspect_datasource(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let ds = cp
        .store
        .state()
        .datasources
        .iter()
        .find(|d| d.id == id && d.is_live())
        .cloned()
        .ok_or_else(|| not_found("datasource"))?;
    if ds.kind != "mongodb" {
        return Err(ApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("datasource kind '{}' has no introspection yet (only mongodb)", ds.kind),
        ));
    }
    if cp.store.state().introspections.get(&id).is_some_and(|j| j.running_at(chrono::Utc::now())) {
        return Err(ApiError(StatusCode::CONFLICT, "an introspection of this datasource is running".into()));
    }
    // Credentials: sealed under the tenant's data key, opened here only for the connector.
    let connection = if keys::needs_opening(&ds.connection) {
        let keyring = cp.keyring("datasource credentials")?;
        let dek = keys::tenant_dek(&cp.store, keyring, &ds.tenant_id, &p.actor).await?;
        caliban_config::open_sealed_values(&ds.connection, &ds.tenant_id, &dek)
            .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("the connection cannot be opened: {e}")))?
    } else {
        ds.connection.clone()
    };
    let connection = introspect::resolve_references(&connection)
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("the connection's references: {e}")))?;
    let job = introspect::Job {
        id: new_id("job"),
        datasource_id: id,
        tenant_id: ds.tenant_id.clone(),
        status: "running".into(),
        objects: 0,
        proposed: 0,
        skipped: 0,
        version: None,
        error: None,
        started_at: chrono::Utc::now(),
        finished_at: None,
    };
    // Stored: every replica sees it, and a second start (here or on another replica) is refused.
    cp.store.apply(&p.actor, Mutation::RecordIntrospection(job.clone())).await?;
    tokio::spawn(introspect::run(Arc::clone(&cp), job.clone(), connection, ds.kind));
    Ok((StatusCode::ACCEPTED, Json(json!({"job_id": job.id, "job": job}))))
}

/// `GET /api/v1/datasources/{id}/introspection`: the newest introspection job of the datasource,
/// whichever control plane ran it (`404` when none).
async fn get_introspection(State(cp): State<Cp>, Path(id): Path<String>) -> ApiResult<Json<introspect::Job>> {
    let st = cp.store.state();
    st.introspections
        .get(&id)
        .map(|j| Json(j.clone().as_of(chrono::Utc::now())))
        .ok_or_else(|| not_found("introspection job"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposals {
    elements: Vec<caliban_ontology::Element>,
    #[serde(default)]
    acknowledge_breaking: bool,
}

/// `POST /api/v1/tenants/{t}/ontology/proposals` `{"elements": [...]}`: elements written as
/// `proposed` (one version), for a human to review; for proposals made outside Caliban (an
/// exported model, a curated file). An element whose spec, name and description are unchanged is
/// skipped whatever status it carries, so re-posting a reviewed element keeps the decision on it.
/// A changed element goes back to `proposed`, which withdraws an approved one until it is approved
/// again: refused when that breaks a published node version, unless `acknowledge_breaking`.
async fn propose_ontology(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
    Json(b): Json<Proposals>,
) -> Result<(StatusCode, Json<Value>), ontology::OntologyError> {
    ensure_tenant(&cp, &tenant_id)?;
    if b.elements.is_empty() || b.elements.len() > 5000 {
        return Err(bad("elements: 1 to 5000").into());
    }
    let mut seen = std::collections::HashSet::new();
    for e in &b.elements {
        if e.id.is_empty() || e.id.len() > 200 || !seen.insert(e.id.clone()) {
            return Err(bad(format!("element id '{}' is empty, too long or repeated", e.id)).into());
        }
    }
    let st = cp.store.state();
    let (write, skipped, breaking) = ontology::proposals(&st, &tenant_id, b.elements);
    if !breaking.is_empty() && !b.acknowledge_breaking {
        return Err(ontology::refuse(
            "proposing changes to approved elements withdraws them, and published node versions query them",
            breaking,
        ));
    }
    let version = if write.is_empty() {
        st.ontologies.get(&tenant_id).map_or(0, |o| o.version)
    } else {
        let n = write.len();
        let st = cp
            .store
            .apply(&p.actor, Mutation::ProposeOntology { tenant_id: tenant_id.clone(), elements: write })
            .await?;
        tracing::debug!(tenant = %tenant_id, proposed = n, "ontology proposals written");
        st.ontologies.get(&tenant_id).map_or(0, |o| o.version)
    };
    let proposed = seen.len() - skipped;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({"tenant_id": tenant_id, "version": version, "proposed": proposed, "skipped": skipped, "breaking": breaking}),
        ),
    ))
}

async fn get_ontology(
    State(cp): State<Cp>,
    Query(f): Query<TenantFilter>,
) -> ApiResult<Json<caliban_ontology::Ontology>> {
    let tenant = f.tenant_id.ok_or_else(|| bad("tenant_id is required"))?;
    ensure_tenant(&cp, &tenant)?;
    let st = cp.store.state();
    Ok(Json(st.ontologies.get(&tenant).cloned().unwrap_or_else(|| caliban_ontology::Ontology {
        tenant_id: tenant,
        version: 0,
        elements: vec![],
    })))
}

// ───────────────────────────── caliban/auto intents ─────────────────────────────

/// Limits on a tenant's own intents (kNN exemplars).
const MAX_INTENTS: usize = 100;
const MAX_EXEMPLARS: usize = 200;
const MAX_EXEMPLAR_CHARS: usize = 2000;

/// `GET /api/v1/tenants/{t}/intents`: the tenant's `caliban/auto` intents as routers see them, with
/// where each comes from (`config`: the file's `[routing.tenants.<id>.exemplars]`; `api`: set
/// here) and the node it hands to, if any.
async fn list_intents(State(cp): State<Cp>, Path(tenant_id): Path<String>) -> ApiResult<Json<Value>> {
    ensure_tenant(&cp, &tenant_id)?;
    let st = cp.store.state();
    let t = st.tenant(&tenant_id).ok_or_else(|| not_found("tenant"))?;
    let base = cp.store.base();
    let file = base.routing.tenants.get(&tenant_id.as_str().into());
    let snap = cp.store.config.load();
    let rendered = snap.config.routing.tenants.get(&tenant_id.as_str().into());
    let routes = file.map(|f| f.routes.clone()).unwrap_or_default();
    let node_routes = t.node_routes.clone().unwrap_or_default();
    let mut out = Vec::new();
    for (intent, ex) in rendered.map(|r| r.exemplars.clone()).unwrap_or_default() {
        let source = if t.intents.contains_key(&intent) { "api" } else { "config" };
        let node = node_routes.get(&intent).or_else(|| routes.get(&intent));
        out.push(json!({"intent": intent, "exemplars": ex, "source": source, "node": node}));
    }
    let removed: Vec<&String> = t.intents.iter().filter(|(_, ex)| ex.is_empty()).map(|(i, _)| i).collect();
    Ok(Json(json!({"tenant_id": tenant_id, "intents": out, "removed": removed})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentBody {
    exemplars: Vec<String>,
}

fn valid_intent(i: &str) -> bool {
    (1..=64).contains(&i.len())
        && i.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.')
        && i != "pinned"
}

/// `PUT /api/v1/tenants/{t}/intents/{intent}` `{"exemplars": [...]}`: the tenant's exemplars for
/// the intent, over the config file's (an empty list removes a file intent for the tenant).
/// Audited (`tenant.intent.set`, with counts, not the texts); routers rebuild their kNN index with
/// the next snapshot, without a restart.
async fn put_intent(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, intent)): Path<(String, String)>,
    Json(b): Json<IntentBody>,
) -> ApiResult<Json<Value>> {
    ensure_tenant(&cp, &tenant_id)?;
    if !valid_intent(&intent) {
        return Err(bad("intent: 1 to 64 characters of [a-z0-9_.-] ('pinned' is reserved)"));
    }
    let mut ex: Vec<String> = Vec::new();
    for e in b.exemplars {
        let e = e.trim().to_owned();
        if e.is_empty() || e.chars().count() > MAX_EXEMPLAR_CHARS {
            return Err(bad(format!("an exemplar is 1 to {MAX_EXEMPLAR_CHARS} characters")));
        }
        if !ex.contains(&e) {
            ex.push(e);
        }
    }
    if ex.len() > MAX_EXEMPLARS {
        return Err(bad(format!("at most {MAX_EXEMPLARS} exemplars per intent")));
    }
    let st = cp.store.state();
    let t = st.tenant(&tenant_id).ok_or_else(|| not_found("tenant"))?;
    if !t.intents.contains_key(&intent) && t.intents.len() >= MAX_INTENTS {
        return Err(bad(format!("at most {MAX_INTENTS} intents per tenant")));
    }
    let m =
        Mutation::SetTenantIntent { tenant_id: tenant_id.clone(), intent: intent.clone(), exemplars: Some(ex.clone()) };
    let st = cp.store.apply(&p.actor, m).await?;
    // Routers serve the change once their `/healthz` `routing.version` reaches this version.
    let version = format!("cp-{}", st.audit_head);
    Ok(Json(
        json!({"tenant_id": tenant_id, "intent": intent, "exemplars": ex, "source": "api", "config_version": version}),
    ))
}

/// `DELETE /api/v1/tenants/{t}/intents/{intent}`: drops the tenant's own exemplars of the intent
/// (the config file's, if any, apply again). `404` when it has none.
async fn delete_intent(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, intent)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    ensure_tenant(&cp, &tenant_id)?;
    cp.store.apply(&p.actor, Mutation::SetTenantIntent { tenant_id, intent, exemplars: None }).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/tenants/{t}/ontology`: the same as `GET /api/v1/ontology?tenant_id=`.
async fn get_tenant_ontology(
    State(cp): State<Cp>,
    Path(tenant_id): Path<String>,
) -> ApiResult<Json<caliban_ontology::Ontology>> {
    get_ontology(State(cp), Query(TenantFilter { tenant_id: Some(tenant_id) })).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    decision: String,
    /// Required on `POST /api/v1/ontology/elements/{id}/review`: element ids are per tenant.
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    /// Go ahead although published node versions query the element (see [`ontology`]).
    #[serde(default)]
    acknowledge_breaking: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewDecision {
    id: String,
    decision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewBatch {
    decisions: Vec<ReviewDecision>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
    #[serde(default)]
    acknowledge_breaking: bool,
}

fn decision_status(d: &str) -> ApiResult<Status> {
    match d {
        "approve" => Ok(Status::Approved),
        "reject" => Ok(Status::Rejected),
        "deprecate" => Ok(Status::Deprecated),
        _ => Err(bad("decision must be 'approve', 'reject' or 'deprecate'")),
    }
}

/// Applies review decisions to the tenant's ontology as one version. Refused with `409` when they
/// would break published node versions and `acknowledge_breaking` is not set.
async fn review(
    cp: &Cp,
    p: &Principal,
    tenant_id: &str,
    decisions: Vec<(String, Status)>,
    acknowledge_breaking: bool,
) -> Result<Json<Value>, ontology::OntologyError> {
    ensure_tenant(cp, tenant_id)?;
    if decisions.is_empty() || decisions.len() > 1000 {
        return Err(bad("decisions: 1 to 1000").into());
    }
    let breaking = ontology::breaking(&cp.store.state(), tenant_id, &decisions);
    if !breaking.is_empty() && !acknowledge_breaking {
        return Err(ontology::refuse(
            "these decisions withdraw approved elements that published node versions query",
            breaking,
        ));
    }
    let ids: Vec<String> = decisions.iter().map(|(id, _)| id.clone()).collect();
    let m = Mutation::ReviewOntology { tenant_id: tenant_id.to_owned(), decisions };
    let st = cp.store.apply(&p.actor, m).await?;
    let o = st.ontologies.get(tenant_id).ok_or_else(|| not_found("ontology element"))?;
    let elements: Vec<&caliban_ontology::Element> = o.elements.iter().filter(|e| ids.contains(&e.id)).collect();
    Ok(Json(json!({"tenant_id": tenant_id, "version": o.version, "elements": elements, "breaking": breaking})))
}

/// `POST /api/v1/tenants/{t}/ontology/review` `{"decisions": [{"id", "decision"}], "acknowledge_breaking"?}`.
async fn review_batch(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
    Json(b): Json<ReviewBatch>,
) -> Result<Json<Value>, ontology::OntologyError> {
    let decisions =
        b.decisions.iter().map(|d| Ok((d.id.clone(), decision_status(&d.decision)?))).collect::<ApiResult<Vec<_>>>()?;
    review(&cp, &p, &tenant_id, decisions, b.acknowledge_breaking).await
}

/// One element's decision, as a batch of one; answers the element.
async fn review_one(
    cp: &Cp,
    p: &Principal,
    tenant_id: &str,
    id: String,
    r: &Review,
) -> Result<Json<Value>, ontology::OntologyError> {
    let status = decision_status(&r.decision)?;
    let out = review(cp, p, tenant_id, vec![(id.clone(), status)], r.acknowledge_breaking).await?;
    let mut e = out.0["elements"].get(0).cloned().ok_or_else(|| not_found("ontology element"))?;
    e["version"] = out.0["version"].clone();
    e["breaking"] = out.0["breaking"].clone();
    Ok(Json(e))
}

async fn review_tenant_element(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, id)): Path<(String, String)>,
    Json(r): Json<Review>,
) -> Result<Json<Value>, ontology::OntologyError> {
    review_one(&cp, &p, &tenant_id, id, &r).await
}

/// `POST /api/v1/ontology/elements/{id}/review`: needs `tenant_id` in the body (element ids are
/// per tenant; the permission check reads it there too).
async fn review_element(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Json(r): Json<Review>,
) -> Result<Json<Value>, ontology::OntologyError> {
    let tenant_id = r.tenant_id.clone().ok_or_else(|| {
        bad("tenant_id is required: element ids are per tenant (or use /api/v1/tenants/{tenant_id}/ontology/elements/{id}/review)")
    })?;
    review_one(&cp, &p, &tenant_id, id, &r).await
}

// ───────────────────────────── usage ─────────────────────────────

#[derive(Deserialize)]
struct UsageQuery {
    tenant_id: Option<String>,
    limit: Option<usize>,
    /// Only the model calls of this node's runs.
    node: Option<String>,
    /// Only the model calls of this run.
    run_id: Option<String>,
    /// Events at or after this time (RFC 3339).
    from: Option<chrono::DateTime<chrono::Utc>>,
    /// Events before this time.
    to: Option<chrono::DateTime<chrono::Utc>>,
}

/// Usage events (newest first) and totals; without `tenant_id`, over the tenants the caller sees.
/// With the Postgres store they come from `usage_event` (every router's events, every replica);
/// with the memory store from this process's ring.
async fn usage(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Query(q): Query<UsageQuery>,
) -> ApiResult<Json<Value>> {
    let tenants: Option<Vec<String>> = match (p.visible(Perm::UsageRead), q.tenant_id) {
        (auth::rbac::Visible::All, None) => None,
        (auth::rbac::Visible::All, Some(t)) => Some(vec![t]),
        (auth::rbac::Visible::Only(set), None) => Some(set.into_iter().collect()),
        (auth::rbac::Visible::Only(set), Some(t)) => Some(set.into_iter().filter(|v| *v == t).collect()),
    };
    if let (Some(from), Some(to)) = (q.from, q.to)
        && from >= to
    {
        return Err(bad("from must be before to"));
    }
    let f = store::usage::UsageFilter {
        tenants,
        node: q.node,
        run_id: q.run_id,
        limit: q.limit.unwrap_or(100).min(1000),
        from: q.from,
        to: q.to,
    };
    let report = cp.store.usage_query(&f).await?;
    Ok(Json(json!(report)))
}

#[derive(Deserialize)]
struct UsageIngest {
    /// The sending router (for logs).
    #[serde(default)]
    router_id: Option<String>,
    events: Vec<caliban_meter::UsageEvent>,
}

/// Most events accepted in one ingest call, and the body size that fits them.
const INGEST_MAX_EVENTS: usize = 5_000;
const INGEST_MAX_BYTES: usize = 16 << 20;

/// `POST /api/v1/usage/ingest`: a split-mode router delivers usage events (router token, like the
/// snapshot). Stored at most once per `request_id`, so retries never double-bill; invalid events
/// are counted as `rejected` and dropped (retrying them cannot help).
async fn ingest_usage(State(cp): State<Cp>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let Some(token) = cp.router_token.as_deref() else {
        return ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "split mode is not enabled: set CALIBAN_ROUTER_TOKEN on the control plane".into(),
        )
        .into_response();
    };
    if !bearer_is(&headers, token) {
        return ApiError(StatusCode::UNAUTHORIZED, "invalid router token".into()).into_response();
    }
    let batch: UsageIngest = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return bad(format!("invalid usage batch: {e}")).into_response(),
    };
    if batch.events.len() > INGEST_MAX_EVENTS {
        return ApiError(StatusCode::PAYLOAD_TOO_LARGE, format!("at most {INGEST_MAX_EVENTS} events per batch"))
            .into_response();
    }
    let n = batch.events.len();
    match cp.store.ingest_usage(batch.events).await {
        Ok(r) => {
            tracing::debug!(router = ?batch.router_id, events = n, accepted = r.accepted, duplicates = r.duplicates, "usage ingested");
            if r.rejected > 0 {
                tracing::warn!(router = ?batch.router_id, rejected = r.rejected, "refused invalid usage events");
            }
            Json(json!(r)).into_response()
        }
        // The router keeps the batch and retries.
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[derive(Deserialize)]
struct AuditIngest {
    #[serde(default)]
    router_id: Option<String>,
    events: Vec<caliban_nodes::journal::AuditEvent>,
}

/// `POST /api/v1/audit/ingest`: a worker delivers decisions made on the data plane (human answers,
/// approvals and denials of tainted writes, cancellations, eval results), with the router token.
/// Each is recorded in the hash-chained audit log once (by its id), so retries are harmless. Only
/// [`caliban_nodes::journal::WORKER_AUDIT_ACTIONS`] are accepted: the control plane's own actions
/// (`rag.*`, golden sets, promotion bars, eval starts) are refused here, so a compromised router
/// cannot forge them; they are counted as `rejected`.
async fn ingest_audit(State(cp): State<Cp>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let Some(token) = cp.router_token.as_deref() else {
        return ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "split mode is not enabled: set CALIBAN_ROUTER_TOKEN on the control plane".into(),
        )
        .into_response();
    };
    if !bearer_is(&headers, token) {
        return ApiError(StatusCode::UNAUTHORIZED, "invalid router token".into()).into_response();
    }
    let batch: AuditIngest = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return bad(format!("invalid audit batch: {e}")).into_response(),
    };
    if batch.events.len() > 1000 {
        return ApiError(StatusCode::PAYLOAD_TOO_LARGE, "at most 1000 events per batch".into()).into_response();
    }
    let (events, forged): (Vec<_>, Vec<_>) = batch
        .events
        .into_iter()
        .partition(|e| caliban_nodes::journal::WORKER_AUDIT_ACTIONS.contains(&e.action.as_str()));
    for e in &forged {
        tracing::warn!(router = ?batch.router_id, action = %e.action, id = %e.id, tenant = %e.tenant_id,
            "refused an audit event a router may not deliver");
    }
    match cp.store.ingest_audit(events).await {
        Ok(mut r) => {
            r.rejected += forged.len() as u64;
            tracing::debug!(router = ?batch.router_id, accepted = r.accepted, duplicates = r.duplicates, "audit events ingested");
            Json(json!(r)).into_response()
        }
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::Request;
    use caliban_config::signing::{SnapshotVerifier, generate_signing_key};
    use caliban_config::{Config, ConfigHandle, Snapshot};
    use caliban_meter::RecentUsage;
    use tower::ServiceExt;

    /// The test keyring (an obviously fake KEK).
    fn test_ring() -> Keyring {
        Keyring::new([7; 32], [])
    }

    fn cp_with(keyring: Option<Keyring>) -> Cp {
        let cfg = Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
        let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
        Arc::new(
            ControlPlane::new(Store::new(cfg, handle, RecentUsage::default()), "admin-secret".into(), "standalone")
                .with_keyring(keyring.map(Arc::new)),
        )
    }

    fn cp() -> Cp {
        cp_with(Some(test_ring()))
    }

    async fn call(app: &Router, method: &str, uri: &str, body: Option<Value>, auth: bool) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(uri).header("content-type", "application/json");
        if auth {
            req = req.header("authorization", "Bearer admin-secret");
        }
        let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
        let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn admin_auth_is_required() {
        let app = app(cp(), None);
        assert_eq!(call(&app, "GET", "/api/v1/tenants", None, false).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, "GET", "/api/v1/audit", None, false).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, "GET", "/api/v1/health", None, false).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn minted_api_key_reaches_the_data_plane_snapshot() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        let (s, t) = call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex Inc"})), true).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(t["id"], "globex-inc");
        let (s, _) = call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex Inc"})), true).await;
        assert_eq!(s, StatusCode::CONFLICT);
        let (s, k) = call(&app, "POST", "/api/v1/tenants/globex-inc/api-keys", Some(json!({"name": "ci"})), true).await;
        assert_eq!(s, StatusCode::CREATED);
        let key = k["key"].as_str().unwrap();
        assert!(key.starts_with("cal_"));
        let snap = c.store.config.load();
        assert_eq!(snap.tenant_by_key_hash(&hash_api_key(key)).unwrap().id.as_str(), "globex-inc");
        // The plaintext key is never listed again.
        let (_, list) = call(&app, "GET", "/api/v1/tenants/globex-inc/api-keys", None, true).await;
        assert!(list[0].get("key").is_none() && list[0].get("hash").is_none());
        // Audited, newest first, chain intact, no key material.
        let (s, a) = call(&app, "GET", "/api/v1/audit?limit=10", None, true).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(a["chain_verified"], true);
        assert_eq!(a["entries"][0]["action"], "api_key.create");
        assert_eq!(a["entries"][1]["action"], "tenant.create");
        assert!(!a.to_string().contains(&key[4..]));
    }

    #[tokio::test]
    async fn surrogate_scope_is_a_per_tenant_opt_in() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        let (s, t) = call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"})), true).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(t["pii_surrogate_scope"], "tenant", "tenant scope by default");
        let (s, t) = call(
            &app,
            "POST",
            "/api/v1/tenants",
            Some(json!({"name": "Initech", "pii_surrogate_scope": "session"})),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(t["pii_surrogate_scope"], "session");

        let (s, t) =
            call(&app, "PATCH", "/api/v1/tenants/globex", Some(json!({"pii_surrogate_scope": "session"})), true).await;
        assert_eq!(s, StatusCode::OK, "{t}");
        assert_eq!(
            (t["pii_surrogate_scope"].as_str(), t["pii_default"].as_str()),
            (Some("session"), Some("reversible"))
        );
        let snap = c.store.config.load();
        assert_eq!(snap.pii_surrogate_scope_for(snap.tenant(&"globex".into()).unwrap()), PiiSurrogateScope::Session);
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=1", None, true).await;
        assert_eq!(a["entries"][0]["action"], "tenant.update");
        assert_eq!(a["entries"][0]["detail"]["pii_surrogate_scope"], json!({"from": "tenant", "to": "session"}));

        let (s, _) =
            call(&app, "PATCH", "/api/v1/tenants/globex", Some(json!({"pii_surrogate_scope": "global"})), true).await;
        assert!(s.is_client_error());
        let (s, _) = call(&app, "PATCH", "/api/v1/tenants/globex", Some(json!({"name": "x"})), true).await;
        assert!(s.is_client_error(), "only PII settings can be patched");
        let (s, _) = call(&app, "PATCH", "/api/v1/tenants/nobody", Some(json!({"pii_default": "mask"})), true).await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // The tenant's own PII patterns and dictionary: checked, audited (terms counted, not
        // recorded), shipped in the snapshot.
        let detectors = json!({"pii_patterns": [{"label": "NATIONAL_ID", "pattern": "\\bLB-\\d{4}-\\d{4}-\\d\\b"}],
                               "pii_dictionary": [{"term": "Cedar Valley Clinic", "label": "ORG"}]});
        let (s, t) = call(&app, "PATCH", "/api/v1/tenants/globex", Some(detectors), true).await;
        assert_eq!(s, StatusCode::OK, "{t}");
        assert_eq!(t["pii_patterns"][0]["label"], "NATIONAL_ID");
        let snap = c.store.config.load();
        let g = snap.tenant(&"globex".into()).unwrap();
        assert_eq!((g.pii_patterns.len(), g.pii_dictionary.len()), (1, 1));
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=1", None, true).await;
        assert_eq!(a["entries"][0]["detail"]["pii_dictionary"], json!({"terms_from": 0, "terms_to": 1}));
        assert!(!a.to_string().contains("Cedar Valley"), "dictionary terms stay out of the audit log");
        for bad in [
            json!({"pii_patterns": [{"label": "X", "pattern": "("}]}),
            json!({"pii_patterns": [{"label": "X", "pattern": ".*"}]}),
            json!({"pii_dictionary": [{"term": "a", "label": "ORG"}]}),
        ] {
            let (s, v) = call(&app, "PATCH", "/api/v1/tenants/globex", Some(bad.clone()), true).await;
            assert!(s.is_client_error(), "{bad}: {v}");
        }
        let (s, t) = call(&app, "PATCH", "/api/v1/tenants/globex", Some(json!({"pii_patterns": []})), true).await;
        assert_eq!((s, t["pii_patterns"].as_array().map(Vec::len)), (StatusCode::OK, Some(0)));
    }

    #[tokio::test]
    async fn semantic_cache_is_a_per_tenant_opt_in() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        let (s, t) = call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"})), true).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(t["semantic_cache"], "off", "off by default");
        let (s, t) =
            call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Initech", "semantic_cache": "on"})), true).await;
        assert_eq!((s, t["semantic_cache"].as_str()), (StatusCode::CREATED, Some("on")));

        let (s, t) = call(&app, "PATCH", "/api/v1/tenants/globex", Some(json!({"semantic_cache": "on"})), true).await;
        assert_eq!(s, StatusCode::OK, "{t}");
        assert_eq!((t["semantic_cache"].as_str(), t["pii_surrogate_scope"].as_str()), (Some("on"), Some("tenant")));
        let snap = c.store.config.load();
        assert_eq!(snap.tenant(&"globex".into()).unwrap().semantic_cache, SemanticCacheMode::On);
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=1", None, true).await;
        assert_eq!(a["entries"][0]["action"], "tenant.update");
        assert_eq!(a["entries"][0]["detail"]["semantic_cache"], json!({"from": "off", "to": "on"}));
        let (s, _) =
            call(&app, "PATCH", "/api/v1/tenants/globex", Some(json!({"semantic_cache": "maybe"})), true).await;
        assert!(s.is_client_error());
    }

    #[tokio::test]
    async fn auto_cache_hit_fraction_is_a_per_tenant_override() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        let (s, t) = call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"})), true).await;
        assert_eq!(s, StatusCode::CREATED);
        assert!(t["auto_cache_hit_fraction"].is_null(), "unset: the deployment value applies");
        let body = json!({"name": "Initech", "auto_cache_hit_fraction": 0.15});
        let (s, t) = call(&app, "POST", "/api/v1/tenants", Some(body), true).await;
        assert_eq!((s, t["auto_cache_hit_fraction"].as_f64()), (StatusCode::CREATED, Some(0.15)));

        let patch = |v: Value| call(&app, "PATCH", "/api/v1/tenants/globex", Some(v), true);
        let (s, t) = patch(json!({"auto_cache_hit_fraction": 0.1})).await;
        assert_eq!((s, t["auto_cache_hit_fraction"].as_f64()), (StatusCode::OK, Some(0.1)), "{t}");
        let snap = c.store.config.load();
        assert_eq!(snap.tenant(&"globex".into()).unwrap().auto_cache_hit_fraction, Some(0.1));
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=1", None, true).await;
        assert_eq!(a["entries"][0]["detail"]["auto_cache_hit_fraction"], json!({"from": null, "to": 0.1}));
        // Absent keeps it; other settings do not touch it.
        let (_, t) = patch(json!({"semantic_cache": "on"})).await;
        assert_eq!(t["auto_cache_hit_fraction"].as_f64(), Some(0.1));
        // Out of range is rejected and nothing changes.
        for bad in [json!(1.5), json!(-0.1), json!("20%")] {
            let (s, e) = patch(json!({"auto_cache_hit_fraction": bad})).await;
            assert!(s.is_client_error(), "{bad}: {s} {e}");
        }
        assert_eq!(c.store.state().tenant("globex").unwrap().auto_cache_hit_fraction, Some(0.1));
        // null clears the override.
        let (s, t) = patch(json!({"auto_cache_hit_fraction": null})).await;
        assert_eq!(s, StatusCode::OK);
        assert!(t["auto_cache_hit_fraction"].is_null());
        assert!(c.store.config.load().tenant(&"globex".into()).unwrap().auto_cache_hit_fraction.is_none());
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=1", None, true).await;
        assert_eq!(a["entries"][0]["detail"]["auto_cache_hit_fraction"], json!({"from": 0.1, "to": null}));
    }

    #[tokio::test]
    async fn usage_totals_show_auto_billing_and_cache_savings() {
        use caliban_meter::{UsageEvent, UsageSink};
        let c = cp();
        let app = app(Arc::clone(&c), None);
        let ev = |id: &str, extra: Value| -> UsageEvent {
            let mut v = json!({
                "request_id": id, "tenant_id": "acme", "model": "ext/gpt", "intent": "chat", "prompt_tokens": 0,
                "completion_tokens": 0, "cached_prompt_tokens": 0, "tokens_saved": 0, "cache": "miss",
                "pii_entities": 0, "cost_usd": 0.0, "latency_ms": 1, "ts": "2026-10-09T12:00:00Z"
            });
            v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            serde_json::from_value(v).unwrap()
        };
        let auto = |extra: Value| {
            let mut v = json!({"requested_model": "caliban/auto"});
            v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            v
        };
        for e in [
            // An auto miss: billed the full flat price.
            ev("r1", auto(json!({"routed_model_cost_usd": 0.4, "flat_price_usd": 1.0, "billed_usd": 1.0}))),
            // An auto hit at 20%: routed cost 0, the saving is the other 80%.
            ev(
                "r2",
                auto(json!({"cache": "hit", "cache_tier": "exact", "routed_model_cost_usd": 0.0,
                            "flat_price_usd": 1.0, "billed_usd": 0.2, "saved_usd": 0.8})),
            ),
            // An auto event written before cache-hit billing: billed the flat price.
            ev("r3", auto(json!({"routed_model_cost_usd": 0.1, "flat_price_usd": 0.5}))),
            // A pinned-model hit: the avoided model cost.
            ev("r4", json!({"requested_model": "ext/gpt", "cache": "hit", "cache_tier": "semantic", "saved_usd": 0.3})),
        ] {
            c.store.usage.record(e).await;
        }
        let (s, u) = call(&app, "GET", "/api/v1/usage", None, true).await;
        assert_eq!(s, StatusCode::OK);
        let t = &u["totals"];
        let close = |k: &str, want: f64| {
            assert!((t[k].as_f64().unwrap() - want).abs() < 1e-12, "{k}: {} vs {want}", t[k]);
        };
        assert_eq!((t["auto_requests"].as_u64(), t["auto_cache_hits"].as_u64()), (Some(3), Some(1)));
        assert_eq!(t["cache_hits"], 2);
        close("flat_price_usd", 2.5);
        close("billed_usd", 1.0 + 0.2 + 0.5);
        close("routed_model_cost_usd", 0.5);
        close("margin_usd", 1.7 - 0.5);
        close("auto_saved_usd", 0.8);
        close("saved_usd", 0.8 + 0.3);
    }

    #[tokio::test]
    async fn usage_events_report_their_stage_timings() {
        use caliban_meter::{UsageEvent, UsageSink};
        let c = cp();
        let app = app(Arc::clone(&c), None);
        let timings = json!({"auth_ms": 0.1, "route_ms": 2.5, "embed_ms": 2.0, "pii_ms": 0.4, "cache_ms": 0.05,
                             "upstream_ms": 80.0, "upstream_total_ms": 300.0, "total_ms": 304.0});
        let ev: UsageEvent = serde_json::from_value(json!({
            "request_id": "t1", "tenant_id": "acme", "model": "ext/gpt", "intent": "chat", "prompt_tokens": 1,
            "completion_tokens": 1, "cached_prompt_tokens": 0, "tokens_saved": 0, "cache": "miss",
            "pii_entities": 0, "cost_usd": 0.0, "latency_ms": 304, "ts": "2026-10-09T12:00:00Z", "timings": timings
        }))
        .unwrap();
        c.store.usage.record(ev).await;
        let (s, u) = call(&app, "GET", "/api/v1/usage", None, true).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(u["events"][0]["timings"], timings, "{u}");
    }

    #[tokio::test]
    async fn empty_usd_totals_are_positive_zero() {
        assert!(std::iter::empty::<f64>().sum::<f64>().is_sign_negative(), "the pitfall usd_total avoids");
        assert!(store::usage::usd_total(std::iter::empty()).is_sign_positive());
        let app = app(cp(), None);
        let (s, u) = call(&app, "GET", "/api/v1/usage", None, true).await;
        assert_eq!(s, StatusCode::OK);
        let usd = ["cost_usd", "saved_usd", "flat_price_usd", "billed_usd", "auto_saved_usd", "routed_model_cost_usd"];
        for k in usd.into_iter().chain(["margin_usd"]) {
            let v = &u["totals"][k];
            assert!(v.as_f64().is_some_and(|x| x == 0.0 && x.is_sign_positive()), "{k}: {v}");
            assert_eq!(serde_json::to_string(v).unwrap(), "0.0", "{k}");
        }
    }

    #[tokio::test]
    async fn invalid_node_spec_is_rejected() {
        let app = app(cp(), None);
        let spec = json!({"kind": "agent", "prompt": {"system": "x"}, "model_policy": {},
                          "tools": [{"ref": "mcp://erp/x", "effect": "read"}],
                          "budgets": {"steps": 3, "tokens": 100, "wall_clock_s": 10}});
        let (s, e) =
            call(&app, "POST", "/api/v1/nodes", Some(json!({"tenant_id": "acme", "name": "n", "spec": spec})), true)
                .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{e}");
    }

    #[tokio::test]
    async fn routes_are_validated_and_published() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        let (s, _) = call(
            &app,
            "PUT",
            "/api/v1/tenants/acme/routes",
            Some(json!({"routes": [{"intent": "x", "models": ["nope/none"]}]})),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        let routes = json!({"routes": [{"intent": "default", "models": ["local/qwen3-8b"]}]});
        let (s, r) = call(&app, "PUT", "/api/v1/tenants/acme/routes", Some(routes), true).await;
        assert_eq!(s, StatusCode::OK, "{r}");
        let snap = c.store.config.load();
        let acme = snap.tenant(&"acme".into()).unwrap();
        assert_eq!(acme.routes.len(), 1);
        assert_eq!(acme.routes[0].models[0].as_str(), "local/qwen3-8b");
        // Deleting the provider the route needs is refused, and nothing changes.
        let (s, _) = call(&app, "DELETE", "/api/v1/tenants/acme/provider-keys/local-llm", None, true).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(c.store.state().provider_keys.iter().any(|p| p.id == "local-llm"));
    }

    /// The error envelope every failed admin call returns.
    fn is_error(v: &Value, kind: &str) -> bool {
        v["error"]["type"] == kind && v["error"]["message"].is_string()
    }

    #[tokio::test]
    async fn revoked_api_key_leaves_the_snapshot_and_is_audited() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"})), true).await;
        let (_, k) = call(&app, "POST", "/api/v1/tenants/globex/api-keys", Some(json!({"name": "ci"})), true).await;
        let (key, id) = (k["key"].as_str().unwrap().to_owned(), k["id"].as_str().unwrap().to_owned());
        let hash = hash_api_key(&key);
        assert!(c.store.config.load().tenant_by_key_hash(&hash).is_some());

        let uri = format!("/api/v1/tenants/globex/api-keys/{id}");
        assert_eq!(call(&app, "DELETE", &uri, None, false).await.0, StatusCode::UNAUTHORIZED);
        // Unknown key, or a key of another tenant: 404 in the standard envelope.
        let (s, e) = call(&app, "DELETE", "/api/v1/tenants/globex/api-keys/key_nope", None, true).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert!(is_error(&e, "not_found"), "{e}");
        assert_eq!(
            call(&app, "DELETE", &format!("/api/v1/tenants/acme/api-keys/{id}"), None, true).await.0,
            StatusCode::NOT_FOUND
        );
        assert!(c.store.config.load().tenant_by_key_hash(&hash).is_some(), "failed revokes change nothing");

        let (s, body) = call(&app, "DELETE", &uri, None, true).await;
        assert_eq!((s, body), (StatusCode::NO_CONTENT, Value::Null));
        // Standalone: the data plane shares this handle, so the very next request sees it.
        assert!(c.store.config.load().tenant_by_key_hash(&hash).is_none());
        // Idempotency: a repeat revoke is a 404 (the key is no longer active).
        assert_eq!(call(&app, "DELETE", &uri, None, true).await.0, StatusCode::NOT_FOUND);

        // Hidden from the default listing, kept (with revoked_at) for audit.
        let (_, list) = call(&app, "GET", "/api/v1/tenants/globex/api-keys", None, true).await;
        assert_eq!(list, json!([]));
        let (_, list) = call(&app, "GET", "/api/v1/tenants/globex/api-keys?include_revoked=true", None, true).await;
        assert_eq!(list[0]["id"], id.as_str());
        assert!(list[0]["revoked_at"].is_string() && list[0].get("hash").is_none());

        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=5", None, true).await;
        assert_eq!(a["chain_verified"], true);
        let e = &a["entries"][0];
        assert_eq!(
            (&e["action"], &e["actor"], &e["tenant_id"], &e["target"]),
            (&json!("api_key.revoke"), &json!("break_glass"), &json!("globex"), &json!(id))
        );
        assert_eq!(e["detail"], json!({"name": "ci", "prefix": &key[..8]}));
        assert!(!a.to_string().contains(&key[8..]));
    }

    #[tokio::test]
    async fn an_api_key_allowlist_changes_after_creation_and_is_audited() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"})), true).await;
        let (_, k) = call(&app, "POST", "/api/v1/tenants/globex/api-keys", Some(json!({"name": "ci"})), true).await;
        let (key, id) = (k["key"].as_str().unwrap().to_owned(), k["id"].as_str().unwrap().to_owned());
        let hash = hash_api_key(&key);
        let uri = format!("/api/v1/tenants/globex/api-keys/{id}");
        let nodes = |c: &Cp| c.store.config.load().tenant(&"globex".into()).unwrap().api_key_nodes.get(&hash).cloned();
        assert_eq!(nodes(&c), None, "no allowlist: every node");
        let body = json!({"nodes": ["triage"], "datasource_scopes": ["crm.customers:read"]});
        let (s, v) = call(&app, "PATCH", &uri, Some(body), true).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!((&v["nodes"], &v["datasource_scopes"]), (&json!(["triage"]), &json!(["crm.customers:read"])));
        assert_eq!(nodes(&c), Some(vec!["triage".to_owned()]), "the data plane sees it at once");
        // Absent fields are kept; null lifts the restriction.
        let (_, v) = call(&app, "PATCH", &uri, Some(json!({"nodes": null})), true).await;
        assert_eq!((&v["nodes"], &v["datasource_scopes"]), (&Value::Null, &json!(["crm.customers:read"])));
        assert_eq!(nodes(&c), None);
        let (s, _) = call(&app, "PATCH", &uri, Some(json!({"nodes": ["Not A Name"]})), true).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            call(&app, "PATCH", &uri, Some(json!({"bogus": 1})), true).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let other = "/api/v1/tenants/globex/api-keys/key_nope";
        assert_eq!(call(&app, "PATCH", other, Some(json!({"nodes": []})), true).await.0, StatusCode::NOT_FOUND);
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=5", None, true).await;
        assert_eq!(a["chain_verified"], true);
        let e = &a["entries"][0];
        assert_eq!((&e["action"], &e["target"]), (&json!("api_key.update"), &json!(id)));
        assert_eq!(e["detail"]["nodes"], json!({"from": ["triage"], "to": null}));
        assert_eq!(a["entries"][1]["detail"]["datasource_scopes"], json!({"from": null, "to": ["crm.customers:read"]}));
    }

    #[tokio::test]
    async fn deleting_a_tenant_tombstones_it_and_cascades() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        for _ in 0..2 {
            call(&app, "POST", "/api/v1/tenants/acme/api-keys", Some(json!({})), true).await;
        }
        let seeded: Vec<String> = c.store.config.load().tenant(&"acme".into()).unwrap().api_key_hashes.clone();
        assert!(seeded.len() >= 2);
        let (_, ds) = call(&app, "POST", "/api/v1/datasources", Some(json!({"tenant_id": "acme", "kind": "mongodb", "name": "sales", "connection": {"uri": "mongodb://u:p@h"}})), true).await;
        assert_eq!(call(&app, "DELETE", "/api/v1/tenants/nobody", None, true).await.0, StatusCode::NOT_FOUND);

        assert_eq!(call(&app, "DELETE", "/api/v1/tenants/acme", None, true).await.0, StatusCode::NO_CONTENT);
        let snap = c.store.config.load();
        assert!(snap.tenant(&"acme".into()).is_none());
        assert!(seeded.iter().all(|h| snap.tenant_by_key_hash(h).is_none()), "every key of the tenant is revoked");
        let st = c.store.state();
        assert!(st.provider_keys.iter().all(|p| p.tenant_id != "acme"));
        assert!(!st.routes.contains_key("acme"));
        assert!(st.datasources.iter().all(|d| d.deleted_at.is_some() && d.connection == json!({})));

        // The tombstone is a 404 everywhere, hidden from the list unless asked for.
        assert_eq!(call(&app, "GET", "/api/v1/tenants/acme", None, true).await.0, StatusCode::NOT_FOUND);
        assert_eq!(call(&app, "GET", "/api/v1/tenants/acme/api-keys", None, true).await.0, StatusCode::NOT_FOUND);
        assert_eq!(call(&app, "GET", "/api/v1/tenants/acme/routes", None, true).await.0, StatusCode::NOT_FOUND);
        assert_eq!(
            call(&app, "POST", "/api/v1/tenants/acme/api-keys", Some(json!({})), true).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(call(&app, "GET", "/api/v1/datasources?tenant_id=acme", None, true).await.1, json!([]));
        let ds_id = ds["id"].as_str().unwrap();
        assert_eq!(
            call(&app, "POST", &format!("/api/v1/datasources/{ds_id}/introspect"), None, true).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(call(&app, "GET", "/api/v1/tenants", None, true).await.1, json!([]));
        let (_, all) = call(&app, "GET", "/api/v1/tenants?include_deleted=true", None, true).await;
        assert_eq!((&all[0]["id"], &all[0]["status"]), (&json!("acme"), &json!("deleted")));
        assert!(all[0]["deleted_at"].is_string());
        // Repeat delete: 404. The id cannot be reused.
        assert_eq!(call(&app, "DELETE", "/api/v1/tenants/acme", None, true).await.0, StatusCode::NOT_FOUND);
        let (s, e) = call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Acme"})), true).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(is_error(&e, "conflict"), "{e}");

        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=20", None, true).await;
        assert_eq!(a["chain_verified"], true);
        let del = a["entries"].as_array().unwrap().iter().find(|e| e["action"] == "tenant.delete").unwrap();
        assert_eq!((&del["actor"], &del["target"]), (&json!("break_glass"), &json!("acme")));
        assert_eq!(del["detail"]["datasources_deleted"], json!([ds_id]));
        // The tenant's earlier audit rows are still there.
        assert!(
            a["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "datasource.create" && e["tenant_id"] == "acme")
        );
    }

    #[tokio::test]
    async fn datasource_and_node_deletes_are_tenant_scoped() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"})), true).await;
        let (_, ds) = call(
            &app,
            "POST",
            "/api/v1/datasources",
            Some(json!({"tenant_id": "acme", "kind": "postgres", "name": "erp", "connection": {}})),
            true,
        )
        .await;
        let spec = json!({"kind": "agent", "prompt": {"system": "x"}, "model_policy": {}, "tools": [],
                          "budgets": {"steps": 3, "tokens": 100, "wall_clock_s": 10}});
        let (s, n) = call(
            &app,
            "POST",
            "/api/v1/nodes",
            Some(json!({"tenant_id": "acme", "name": "triage", "spec": spec})),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{n}");
        for (kind, id) in [("datasources", ds["id"].as_str().unwrap()), ("nodes", n["id"].as_str().unwrap())] {
            let own = format!("/api/v1/tenants/acme/{kind}/{id}");
            assert_eq!(call(&app, "DELETE", &own, None, false).await.0, StatusCode::UNAUTHORIZED);
            let (s, e) = call(&app, "DELETE", &format!("/api/v1/tenants/globex/{kind}/{id}"), None, true).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{kind}: another tenant's id");
            assert!(is_error(&e, "not_found"));
            assert_eq!(
                call(&app, "DELETE", &format!("/api/v1/tenants/acme/{kind}/nope"), None, true).await.0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(call(&app, "DELETE", &own, None, true).await.0, StatusCode::NO_CONTENT);
            assert_eq!(call(&app, "DELETE", &own, None, true).await.0, StatusCode::NOT_FOUND, "{kind}: repeat delete");
            assert_eq!(call(&app, "GET", &format!("/api/v1/{kind}?tenant_id=acme"), None, true).await.1, json!([]));
        }
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=2", None, true).await;
        let actions: Vec<&str> =
            a["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
        assert_eq!(actions, ["node.delete", "datasource.delete"]);
        assert_eq!(a["entries"][0]["detail"], json!({"name": "triage", "version": 1}));
    }

    #[tokio::test]
    async fn tenant_secrets_are_sealed_under_the_tenant_key() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        let ring = test_ring();
        call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"})), true).await;
        assert!(!c.store.state().deks.contains_key("globex"), "created on the first secret");

        // ── BYOK: first key creates the tenant's DEK (audited), the second reuses it ──
        let byok = |label: &str, key: &str| json!({"kind": "openai", "label": label, "api_key": key, "trust_tier": "t2_contracted"});
        let (s, k) = call(
            &app,
            "POST",
            "/api/v1/tenants/globex/provider-keys",
            Some(byok("OpenAI", "sk-test-globex-9876")),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{k}");
        assert_eq!(k["last4"], "9876");
        assert!(!k.to_string().contains("sk-test-globex"), "{k}");
        let dek = c.store.state().deks.get("globex").cloned().expect("globex has a data key");
        assert_eq!(dek.wrapped.kek_id, ring.current_id());
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=3", None, true).await;
        assert_eq!(a["entries"][0]["action"], "provider_key.create");
        assert_eq!(a["entries"][1]["action"], "tenant_key.create");
        assert_eq!(a["entries"][1]["detail"], json!({"kek_id": ring.current_id()}));
        let (s, _) = call(
            &app,
            "POST",
            "/api/v1/tenants/globex/provider-keys",
            Some(byok("Second", "sk-test-globex-5555")),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(c.store.state().deks.get("globex"), Some(&dek), "one key per tenant");
        // The data plane gets an envelope it opens with the keyring; the plaintext is nowhere.
        let snap = c.store.config.load();
        let t = snap.tenant(&"globex".into()).unwrap();
        let key = t.providers.iter().find(|p| p.id.as_str() == "openai").unwrap().api_key.clone().unwrap();
        assert!(matches!(key, SecretRef::TenantSealed { .. }));
        assert_eq!(key.resolve_with(&ring).unwrap().expose(), "sk-test-globex-9876");
        assert!(key.resolve_with(&Keyring::new([8; 32], [])).is_err(), "another deployment's KEK opens nothing");
        let wire = serde_json::to_string(&snap.config).unwrap();
        assert!(!wire.contains("sk-test-globex"));
        // Split mode: the config travels as JSON; a router parses it and opens the envelope.
        let routed = Snapshot::new(serde_json::from_str::<Config>(&wire).unwrap(), "router");
        let t = routed.tenant(&"globex".into()).unwrap();
        let key = t.providers.iter().find(|p| p.id.as_str() == "openai").unwrap().api_key.clone().unwrap();
        assert_eq!(key.resolve_with(&ring).unwrap().expose(), "sk-test-globex-9876");

        // ── datasources: credentials sealed, responses redacted, references kept ──
        let conn = json!({"uri": "mongodb://app:hunter2@db:27017/sales", "password": "hunter2",
                          "api_key": {"env": "SALES_KEY"}, "database": "sales"});
        let (s, ds) = call(
            &app,
            "POST",
            "/api/v1/datasources",
            Some(json!({"tenant_id": "globex", "kind": "mongodb", "name": "sales", "connection": conn})),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{ds}");
        let view = json!({"uri": "mongodb://app:****@db:27017/sales", "password": "****",
                          "api_key": {"env": "SALES_KEY"}, "database": "sales"});
        assert_eq!(ds["connection"], view);
        let (_, list) = call(&app, "GET", "/api/v1/datasources?tenant_id=globex", None, true).await;
        assert_eq!(list[0]["connection"], view);
        assert!(!list.to_string().contains("hunter2"));
        let st = c.store.state();
        let stored = &st.datasources.iter().find(|d| d.tenant_id == "globex").unwrap().connection;
        assert!(!stored.to_string().contains("hunter2"), "sealed at rest");
        let open = ring.unwrap_dek("globex", &dek.wrapped).unwrap();
        assert_eq!(keys::open_connection(stored, "globex", &open).unwrap(), conn);
        let (s, _) = call(
            &app,
            "POST",
            "/api/v1/datasources",
            Some(json!({"tenant_id": "globex", "kind": "mongodb", "name": "x", "connection": {"password": {"$sealed": "AAAA"}}})),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "clients cannot send pre-sealed values");

        // ── deleting the tenant destroys its data key ──
        assert_eq!(call(&app, "DELETE", "/api/v1/tenants/globex", None, true).await.0, StatusCode::NO_CONTENT);
        assert!(!c.store.state().deks.contains_key("globex"));
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=50", None, true).await;
        assert_eq!(a["entries"][0]["detail"]["tenant_key_destroyed"], json!(ring.current_id()));
        assert!(!a.to_string().contains("hunter2") && !a.to_string().contains("sk-test-globex"));
        assert_eq!(call(&app, "DELETE", "/api/v1/tenants/globex", None, true).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn secrets_need_a_kek() {
        let app = app(cp_with(None), None);
        let byok = json!({"kind": "openai", "label": "x", "api_key": "sk-test-0000", "trust_tier": "t2_contracted"});
        let (s, e) = call(&app, "POST", "/api/v1/tenants/acme/provider-keys", Some(byok), true).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(e["error"]["message"].as_str().unwrap().contains("CALIBAN_KEK"));
        let ds = |conn: Value| json!({"tenant_id": "acme", "kind": "postgres", "name": "erp", "connection": conn});
        assert_eq!(
            call(&app, "POST", "/api/v1/datasources", Some(ds(json!({"password": "x"}))), true).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(&app, "POST", "/api/v1/datasources", Some(ds(json!({"password": {"env": "ERP_PW"}}))), true).await.0,
            StatusCode::CREATED,
            "references need no key"
        );
    }

    #[tokio::test]
    async fn snapshot_endpoint_signs_and_supports_etags() {
        let (seed, public) = generate_signing_key();
        let base = cp();
        let cfg = base.store.base().clone();
        let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
        let c = Arc::new(
            ControlPlane::new(Store::new(cfg, handle, RecentUsage::default()), "admin-secret".into(), "control-plane")
                .with_snapshots(Some(SnapshotSigner::from_b64(&seed).unwrap()), Some("router-secret".into())),
        );
        let app = app(Arc::clone(&c), None);
        let get = |auth: &'static str, etag: Option<String>| {
            let app = app.clone();
            async move {
                let mut req = Request::builder().uri("/api/v1/snapshot").header("authorization", auth);
                if let Some(e) = etag {
                    req = req.header("if-none-match", e);
                }
                let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
                let status = resp.status();
                let etag = resp.headers().get("etag").map(|v| v.to_str().unwrap().to_owned());
                let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
                (status, etag, bytes)
            }
        };
        // The admin token is not a router token, and vice versa.
        assert_eq!(get("Bearer admin-secret", None).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, "GET", "/api/v1/tenants", None, false).await.0, StatusCode::UNAUTHORIZED);
        let (s, etag, body) = get("Bearer router-secret", None).await;
        assert_eq!(s, StatusCode::OK);
        let signed: caliban_config::signing::SignedSnapshot = serde_json::from_slice(&body).unwrap();
        let payload = SnapshotVerifier::from_b64_list(&public).unwrap().verify(&signed).unwrap();
        assert!(payload.config.security.admin_token.is_none());
        assert_eq!(payload.config.tenants[0].id.as_str(), "acme");
        // Unchanged → 304; a mutation → new ETag.
        assert_eq!(get("Bearer router-secret", etag.clone()).await.0, StatusCode::NOT_MODIFIED);
        call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Initech"})), true).await;
        let (s, etag2, _) = get("Bearer router-secret", etag.clone()).await;
        assert_eq!(s, StatusCode::OK);
        assert_ne!(etag, etag2);

        // Split mode: a revoked key is gone from the next signed snapshot a router fetches.
        let (_, k) = call(&app, "POST", "/api/v1/tenants/initech/api-keys", Some(json!({})), true).await;
        let hash = hash_api_key(k["key"].as_str().unwrap());
        let verify = |body: &[u8]| {
            let signed: caliban_config::signing::SignedSnapshot = serde_json::from_slice(body).unwrap();
            SnapshotVerifier::from_b64_list(&public).unwrap().verify(&signed).unwrap()
        };
        let (_, etag3, body) = get("Bearer router-secret", None).await;
        assert!(Snapshot::new(verify(&body).config, "t").tenant_by_key_hash(&hash).is_some());
        let uri = format!("/api/v1/tenants/initech/api-keys/{}", k["id"].as_str().unwrap());
        assert_eq!(call(&app, "DELETE", &uri, None, true).await.0, StatusCode::NO_CONTENT);
        let (s, etag4, body) = get("Bearer router-secret", etag3.clone()).await;
        assert_eq!(s, StatusCode::OK, "a revoke changes the snapshot (no 304)");
        assert_ne!(etag3, etag4);
        let payload = verify(&body);
        assert!(Snapshot::new(payload.config.clone(), "t").tenant_by_key_hash(&hash).is_none());
        // A deleted tenant leaves the snapshot entirely.
        assert_eq!(call(&app, "DELETE", "/api/v1/tenants/initech", None, true).await.0, StatusCode::NO_CONTENT);
        let (_, _, body) = get("Bearer router-secret", etag4).await;
        assert!(verify(&body).config.tenants.iter().all(|t| t.id.as_str() != "initech"));
    }

    #[tokio::test]
    async fn routers_may_deliver_only_the_data_planes_audit_actions() {
        let base = cp();
        let cfg = base.store.base().clone();
        let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
        let (seed, _) = generate_signing_key();
        let c = Arc::new(
            ControlPlane::new(Store::new(cfg, handle, RecentUsage::default()), "admin-secret".into(), "control-plane")
                .with_snapshots(Some(SnapshotSigner::from_b64(&seed).unwrap()), Some("router-secret".into())),
        );
        let app = app(Arc::clone(&c), None);
        let ev = |id: &str, action: &str| {
            json!({"id": id, "tenant_id": "acme", "actor": "api_key:abc", "action": action,
                   "target": "triage", "detail": {}, "at": "2026-10-12T08:00:00Z"})
        };
        let batch = json!({"router_id": "r1", "events": [
            ev("run_1/answer", "node.run.answer"),
            ev("run_1/cancel", "node.run.cancel"),
            // What a compromised router could try to forge: the control plane's own actions.
            ev("cp/rag.collection.delete/x", "rag.collection.delete"),
            ev("cp/rag.document.release/x", "rag.document.release"),
            ev("cp/golden", "node.golden_set.update"),
            ev("cp/bar", "node.eval_policy.update"),
            ev("cp/start", "node.eval.start"),
            ev("forged", "tenant.delete"),
        ]});
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/audit/ingest")
                    .header("authorization", "Bearer router-secret")
                    .header("content-type", "application/json")
                    .body(Body::from(batch.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let r: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap()).unwrap();
        assert_eq!((r["accepted"].as_u64(), r["rejected"].as_u64()), (Some(2), Some(6)), "{r}");
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=20", None, true).await;
        let actions: Vec<&str> = a["entries"].as_array().unwrap().iter().filter_map(|e| e["action"].as_str()).collect();
        assert!(actions.contains(&"node.run.answer") && actions.contains(&"node.run.cancel"), "{actions:?}");
        assert!(
            !actions.iter().any(|a| a.starts_with("rag.") || a.starts_with("node.golden") || *a == "node.eval.start")
        );
        assert!(!actions.contains(&"node.eval_policy.update") && !actions.contains(&"tenant.delete"), "{actions:?}");
        // The control plane itself still records its own actions (its outbox drains).
        let own = caliban_nodes::journal::AuditEvent {
            id: "cp/golden".into(),
            tenant_id: "acme".into(),
            actor: "user:jo".into(),
            action: "node.golden_set.update".into(),
            target: Some("triage".into()),
            detail: json!({}),
            at: chrono::Utc::now(),
        };
        assert_eq!(c.store.ingest_audit(vec![own]).await.unwrap().accepted, 1);
    }

    /// e2e gap 5: element ids are per tenant. Two tenants with an element `Service`: a review
    /// names the tenant and touches only its element; a batch is one version.
    #[tokio::test]
    async fn ontology_reviews_are_scoped_to_the_tenant_and_batched() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"})), true).await;
        let el = |id: &str| -> caliban_ontology::Element {
            serde_json::from_value(
                json!({"id": id, "name": id, "description": null, "synonyms": [], "status": "proposed",
                "provenance": "introspect", "confidence": 0.9, "kind": "glossary_term",
                "spec": {"phrase": id, "maps_to": "x"}}),
            )
            .unwrap()
        };
        for t in ["acme", "globex"] {
            let m = Mutation::ProposeOntology { tenant_id: t.into(), elements: vec![el("Service"), el("Slot")] };
            c.store.apply("test", m).await.unwrap();
        }
        // The legacy route needs the tenant.
        let (s, v) =
            call(&app, "POST", "/api/v1/ontology/elements/Service/review", Some(json!({"decision": "approve"})), true)
                .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        let body = json!({"decision": "approve", "tenant_id": "globex"});
        let (s, v) = call(&app, "POST", "/api/v1/ontology/elements/Service/review", Some(body), true).await;
        assert_eq!(
            (s, v["status"].as_str(), v["version"].as_u64()),
            (StatusCode::OK, Some("approved"), Some(2)),
            "{v}"
        );
        let status = |t: &str| {
            let st = c.store.state();
            st.ontologies[t].elements.iter().map(|e| (e.id.clone(), e.status)).collect::<Vec<_>>()
        };
        assert_eq!(status("acme")[0].1, Status::Proposed, "acme's Service is untouched");
        // A batch on the tenant route: one version for both decisions.
        let batch =
            json!({"decisions": [{"id": "Service", "decision": "approve"}, {"id": "Slot", "decision": "reject"}]});
        let (s, v) = call(&app, "POST", "/api/v1/tenants/acme/ontology/review", Some(batch), true).await;
        assert_eq!((s, v["version"].as_u64()), (StatusCode::OK, Some(2)), "{v}");
        assert_eq!(status("acme"), [("Service".into(), Status::Approved), ("Slot".into(), Status::Rejected)]);
        assert_eq!(c.store.state().ontologies["globex"].version, 2);
        // An id the tenant does not have is a 404, even if another tenant has it.
        let (s, _) = call(
            &app,
            "POST",
            "/api/v1/tenants/acme/ontology/elements/Other/review",
            Some(json!({"decision": "approve"})),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, o) = call(&app, "GET", "/api/v1/tenants/globex/ontology", None, true).await;
        assert_eq!((s, o["version"].as_u64()), (StatusCode::OK, Some(2)));
    }

    /// e2e gap 1: introspection writes proposals reachable through the public API (no psql).
    #[tokio::test]
    async fn introspection_proposes_the_ontology_through_the_api() {
        struct Fake(std::sync::Mutex<Vec<Value>>);
        #[async_trait::async_trait]
        impl introspect::Introspector for Fake {
            async fn snapshot(
                &self,
                kind: &str,
                ds: &str,
                connection: Value,
            ) -> Result<caliban_connect::SchemaSnapshot, String> {
                assert_eq!(kind, "mongodb");
                self.0.lock().unwrap().push(connection);
                let f = |path: &str, ty: &str| json!({"path": path, "types": [ty], "presence": 1.0, "is_array": false});
                serde_json::from_value(json!({"datasource": ds, "objects": [
                    {"name": "services", "estimated_rows": 9, "kind": "collection", "sampled": 9, "indexes": [],
                     "fields": [f("_id", "string"), f("name", "string"), f("specialty", "string"), f("price_usd", "double")]}
                ]}))
                .map_err(|e| e.to_string())
            }
        }
        let fake = Arc::new(Fake(std::sync::Mutex::new(vec![])));
        let base = cp();
        let cfg = base.store.base().clone();
        let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
        let c = Arc::new(
            ControlPlane::new(Store::new(cfg, handle, RecentUsage::default()), "admin-secret".into(), "standalone")
                .with_keyring(Some(Arc::new(test_ring())))
                .with_introspector(fake.clone()),
        );
        let app = app(Arc::clone(&c), None);
        let body = json!({"tenant_id": "acme", "kind": "mongodb", "name": "market",
                          "connection": {"uri": "mongodb://reader:s3cret@db:27017", "database": "marketplace"}});
        let (s, ds) = call(&app, "POST", "/api/v1/datasources", Some(body), true).await;
        assert_eq!(s, StatusCode::CREATED, "{ds}");
        let id = ds["id"].as_str().unwrap().to_owned();
        let run = |app: Router, id: String| async move {
            let (s, v) = call(&app, "POST", &format!("/api/v1/datasources/{id}/introspect"), None, true).await;
            assert_eq!(s, StatusCode::ACCEPTED, "{v}");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                let (_, j) = call(&app, "GET", &format!("/api/v1/datasources/{id}/introspection"), None, true).await;
                if j["status"] != "running" {
                    return j;
                }
                assert!(std::time::Instant::now() < deadline, "the job did not end: {j}");
                tokio::task::yield_now().await;
            }
        };
        let j = run(app.clone(), id.clone()).await;
        assert_eq!((j["status"].as_str(), j["objects"].as_u64()), (Some("succeeded"), Some(1)), "{j}");
        assert!(j["proposed"].as_u64().unwrap() >= 4, "{j}");
        // The connector got the credentials opened; the API never shows them.
        assert_eq!(fake.0.lock().unwrap()[0]["uri"], "mongodb://reader:s3cret@db:27017");
        let (_, d) = call(&app, "GET", "/api/v1/datasources?tenant_id=acme", None, true).await;
        assert!(!d.to_string().contains("s3cret"));
        assert_eq!(d.as_array().unwrap().iter().find(|x| x["id"] == id.as_str()).unwrap()["status"], "ready");
        // The proposals, through the public API, then a review.
        let (_, o) = call(&app, "GET", "/api/v1/tenants/acme/ontology", None, true).await;
        let ids: Vec<&str> = o["elements"].as_array().unwrap().iter().filter_map(|e| e["id"].as_str()).collect();
        assert!(ids.contains(&"Service") && ids.contains(&"Service.specialty"), "{ids:?}");
        assert!(o["elements"].as_array().unwrap().iter().all(|e| e["status"] == "proposed"));
        let v1 = o["version"].as_u64().unwrap();
        let batch = json!({"decisions": [{"id": "Service", "decision": "approve"}]});
        call(&app, "POST", "/api/v1/tenants/acme/ontology/review", Some(batch), true).await;
        // A re-run finds nothing new and never overwrites a decision: no version.
        let j = run(app.clone(), id.clone()).await;
        assert_eq!((j["status"].as_str(), j["proposed"].as_u64()), (Some("succeeded"), Some(0)), "{j}");
        let (_, o) = call(&app, "GET", "/api/v1/tenants/acme/ontology", None, true).await;
        assert_eq!(o["version"].as_u64(), Some(v1 + 1), "only the review made a version");
        let service = o["elements"].as_array().unwrap().iter().find(|e| e["id"] == "Service").unwrap().clone();
        assert_eq!(service["status"], "approved");
        // Proposals made elsewhere (an exported model) through the API too.
        let el = json!({"id": "price_total", "name": "Total price", "description": null, "synonyms": [], "status": "approved",
            "provenance": "human", "confidence": null, "kind": "glossary_term", "spec": {"phrase": "total price", "maps_to": "x"}});
        let (s, v) =
            call(&app, "POST", "/api/v1/tenants/acme/ontology/proposals", Some(json!({"elements": [el]})), true).await;
        assert_eq!((s, v["proposed"].as_u64()), (StatusCode::CREATED, Some(1)), "{v}");
        let (_, o) = call(&app, "GET", "/api/v1/tenants/acme/ontology", None, true).await;
        let p = o["elements"].as_array().unwrap().iter().find(|e| e["id"] == "price_total").unwrap().clone();
        assert_eq!(p["status"], "proposed", "a proposal is always proposed, whatever it says");
        // Re-posting reviewed elements unchanged (status may be left out) keeps the decisions and
        // makes no version; a changed one goes back to proposed.
        let batch = json!({"decisions": [{"id": "price_total", "decision": "approve"}]});
        call(&app, "POST", "/api/v1/tenants/acme/ontology/review", Some(batch), true).await;
        let mut same = el.clone();
        same.as_object_mut().unwrap().remove("status");
        let elements = json!({"elements": [same.clone(), service.clone()]});
        let (s, v) = call(&app, "POST", "/api/v1/tenants/acme/ontology/proposals", Some(elements), true).await;
        assert_eq!((s, v["proposed"].as_u64(), v["skipped"].as_u64()), (StatusCode::CREATED, Some(0), Some(2)), "{v}");
        let (_, o2) = call(&app, "GET", "/api/v1/tenants/acme/ontology", None, true).await;
        assert_eq!(o2["version"], v["version"]);
        let status = |o: &Value, id: &str| {
            o["elements"].as_array().unwrap().iter().find(|e| e["id"] == id).unwrap()["status"].clone()
        };
        assert_eq!((status(&o2, "price_total"), status(&o2, "Service")), (json!("approved"), json!("approved")));
        same["spec"]["maps_to"] = json!("orders.total");
        let (s, v) =
            call(&app, "POST", "/api/v1/tenants/acme/ontology/proposals", Some(json!({"elements": [same]})), true)
                .await;
        assert_eq!(
            (s, v["proposed"].as_u64(), v["breaking"].as_array().map(Vec::len)),
            (StatusCode::CREATED, Some(1), Some(0)),
            "{v}"
        );
        let (_, o3) = call(&app, "GET", "/api/v1/tenants/acme/ontology", None, true).await;
        assert_eq!(status(&o3, "price_total"), "proposed");
        assert_eq!(o3["version"].as_u64(), o2["version"].as_u64().map(|v| v + 1));
        // Kinds without an introspection lane are refused.
        let pg = json!({"tenant_id": "acme", "kind": "postgres", "name": "erp", "connection": {}});
        let (_, ds) = call(&app, "POST", "/api/v1/datasources", Some(pg), true).await;
        let (s, _) =
            call(&app, "POST", &format!("/api/v1/datasources/{}/introspect", ds["id"].as_str().unwrap()), None, true)
                .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// e2e gap 2: a tenant's caliban/auto intents and exemplars at runtime, over the config file's.
    #[tokio::test]
    async fn tenant_intents_are_managed_at_runtime_over_the_config_file() {
        let toml = format!(
            "{}\n[routing.tenants.acme]\nexemplars = {{ \"legal.review\" = [\"review this NDA clause\"] }}\n",
            include_str!("../../../config/caliban.example.toml")
        );
        let cfg = Config::from_toml_str(&toml).unwrap();
        let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
        let c = Arc::new(
            ControlPlane::new(
                Store::new(cfg, handle.clone(), RecentUsage::default()),
                "admin-secret".into(),
                "standalone",
            )
            .with_keyring(Some(Arc::new(test_ring()))),
        );
        let app = app(Arc::clone(&c), None);
        let ex = |h: &ConfigHandle, i: &str| {
            h.load().config.routing.tenants.get(&"acme".into()).and_then(|t| t.exemplars.get(i).cloned())
        };
        // The file's intent, as the bootstrap.
        let (_, l) = call(&app, "GET", "/api/v1/tenants/acme/intents", None, true).await;
        assert_eq!(
            (l["intents"][0]["intent"].as_str(), l["intents"][0]["source"].as_str()),
            (Some("legal.review"), Some("config"))
        );
        // A new intent, shipped in the snapshot routers read (no restart).
        let body = json!({"exemplars": ["my chest hurts since tuesday", "fever and cough for days", " fever and cough for days "]});
        let (s, v) = call(&app, "PUT", "/api/v1/tenants/acme/intents/triage", Some(body), true).await;
        assert_eq!((s, v["exemplars"].as_array().map(Vec::len)), (StatusCode::OK, Some(2)), "{v}");
        assert_eq!(ex(&handle, "triage").map(|v| v.len()), Some(2));
        // The snapshot version that carries it (routers report it in `/healthz` `routing.version`).
        assert_eq!(v["config_version"].as_str(), Some(handle.load().version.as_str()));
        // Overriding the file's intent, then removing it for this tenant, then back to the file's.
        let (s, _) =
            call(&app, "PUT", "/api/v1/tenants/acme/intents/legal.review", Some(json!({"exemplars": []})), true).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(ex(&handle, "legal.review"), None, "an empty list removes the file's intent");
        let (_, l) = call(&app, "GET", "/api/v1/tenants/acme/intents", None, true).await;
        assert_eq!(l["removed"], json!(["legal.review"]));
        assert_eq!(
            call(&app, "DELETE", "/api/v1/tenants/acme/intents/legal.review", None, true).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(ex(&handle, "legal.review").map(|v| v.len()), Some(1));
        assert_eq!(
            call(&app, "DELETE", "/api/v1/tenants/acme/intents/legal.review", None, true).await.0,
            StatusCode::NOT_FOUND
        );
        // Audited with counts, never the texts.
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=5", None, true).await;
        assert!(
            a["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "tenant.intent.set" && e["detail"]["exemplars"] == 2)
        );
        assert!(!a.to_string().contains("chest hurts"), "exemplar texts stay out of the audit log");
        // Checked.
        for (intent, body) in [
            ("Bad Name", json!({"exemplars": ["x"]})),
            ("pinned", json!({"exemplars": ["x"]})),
            ("ok", json!({"exemplars": [""]})),
        ] {
            let (s, _) = call(
                &app,
                "PUT",
                &format!("/api/v1/tenants/acme/intents/{}", intent.replace(' ', "%20")),
                Some(body),
                true,
            )
            .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{intent}");
        }
    }
}
