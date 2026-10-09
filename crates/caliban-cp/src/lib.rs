//! Control plane (`caliban control-plane`, :8081): admin API under `/api/v1` and the web console.
//!
//! Admin auth is a bootstrap bearer token (`CALIBAN_ADMIN_TOKEN`). TODO: OIDC + RBAC.
//! Every mutation goes through [`store::Store::apply`] (one transaction + one hash-chained audit
//! row). Split deployments: routers poll `GET /api/v1/snapshot` (router token, not the admin
//! token) for an Ed25519-signed config snapshot.

mod models;
pub mod store;

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use caliban_config::signing::{SnapshotPayload, SnapshotSigner, config_digest};
use caliban_config::{RouteConfig, SecretRef, process_kek, seal};
use caliban_nodes::NodeSpec;
use caliban_ontology::Status;
use caliban_types::{PiiMode, PiiSurrogateScope, ProviderKind, TrustTier, hash_api_key};
use parking_lot::Mutex;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use store::audit::{now_micros, verify_chain};
use store::{ApiKeyRecord, DatasourceRecord, Mutation, NodeRecord, ProviderKeyRecord, Store, StoreError, Tenant, TenantStatus, new_id, slug};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

/// Audit actor for requests authenticated with the bootstrap admin token.
pub(crate) const ADMIN_ACTOR: &str = "admin";

pub struct ControlPlane {
    pub store: Store,
    admin_token: String,
    mode: &'static str,
    signer: Option<SnapshotSigner>,
    router_token: Option<String>,
    exported: Mutex<Option<Arc<Exported>>>,
}

/// The last signed snapshot, re-served while the rendered config is unchanged.
struct Exported {
    digest: String,
    etag: String,
    version: String,
    body: String,
}

impl ControlPlane {
    pub fn new(store: Store, admin_token: String, mode: &'static str) -> Self {
        Self { store, admin_token, mode, signer: None, router_token: None, exported: Mutex::new(None) }
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

pub(crate) struct ApiError(pub(crate) StatusCode, pub(crate) String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let kind = match self.0 {
            StatusCode::UNAUTHORIZED => "authentication_error",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::CONFLICT => "conflict",
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => "invalid_request_error",
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
        .route("/tenants/{tenant_id}/api-keys/{key_id}", delete(revoke_api_key))
        .route("/tenants/{tenant_id}/provider-keys", get(list_provider_keys).post(create_provider_key))
        .route("/tenants/{tenant_id}/provider-keys/{key_id}", delete(delete_provider_key))
        .route("/tenants/{tenant_id}/routes", get(get_routes).put(put_routes))
        .route("/tenants/{tenant_id}/datasources/{id}", delete(delete_datasource))
        .route("/tenants/{tenant_id}/nodes/{id}", delete(delete_node))
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
        .route("/nodes", get(list_nodes).post(create_node))
        .route("/usage", get(usage))
        .route("/audit", get(audit))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&cp), require_admin))
        // Router token, not the admin token: a compromised router cannot administer.
        .route("/snapshot", get(snapshot))
        .route("/health", get(health));

    let mut app = Router::new().nest("/api/v1", api);
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
            .is_some_and(|t| constant_time_eq(t.trim().as_bytes(), expected.as_bytes()))
}

async fn require_admin(State(cp): State<Cp>, req: Request, next: Next) -> Response {
    if !bearer_is(req.headers(), &cp.admin_token) {
        return ApiError(StatusCode::UNAUTHORIZED, "invalid admin token".into()).into_response();
    }
    next.run(req).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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
            "split mode is not enabled: set CALIBAN_ROUTER_TOKEN and CALIBAN_SNAPSHOT_SIGNING_KEY on the control plane".into(),
        )
        .into_response();
    };
    if !bearer_is(&headers, token) {
        return ApiError(StatusCode::UNAUTHORIZED, "invalid router token".into()).into_response();
    }
    // Pick up commits from other control-plane replicas (one cheap query on Postgres).
    if let Err(e) = cp.store.refresh().await {
        tracing::warn!(error = %e, "store refresh failed; exporting cached state");
    }
    let snap = cp.store.config.load();
    let mut config = snap.config.clone();
    // Routers never need the admin credential reference.
    config.security.admin_token = None;
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
                let payload = SnapshotPayload { version: snap.version.clone(), issued_at_ms, config };
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
async fn list_tenants(State(cp): State<Cp>, Query(q): Query<TenantList>) -> Json<Vec<Tenant>> {
    Json(cp.store.state().tenants.iter().filter(|t| q.include_deleted || t.is_active()).cloned().collect())
}

#[derive(Deserialize)]
struct TenantCreate {
    name: String,
    region: Option<String>,
    pii_default: Option<PiiMode>,
    pii_surrogate_scope: Option<PiiSurrogateScope>,
}

async fn create_tenant(State(cp): State<Cp>, Json(body): Json<TenantCreate>) -> ApiResult<(StatusCode, Json<Tenant>)> {
    let id = slug(&body.name);
    if id.is_empty() {
        return Err(bad("name must contain letters or digits"));
    }
    let t = Tenant {
        id,
        name: body.name,
        region: body.region,
        pii_default: body.pii_default.unwrap_or(cp.store.base().pii.default_mode),
        pii_surrogate_scope: body.pii_surrogate_scope.unwrap_or_default(),
        created_at: now_micros(),
        status: TenantStatus::Active,
        deleted_at: None,
        settings: serde_json::Map::new(),
    };
    cp.store.apply(ADMIN_ACTOR, Mutation::CreateTenant(t.clone())).await?;
    Ok((StatusCode::CREATED, Json(t)))
}

async fn get_tenant(State(cp): State<Cp>, Path(tenant_id): Path<String>) -> ApiResult<Json<Tenant>> {
    cp.store.state().tenant(&tenant_id).cloned().map(Json).ok_or_else(|| not_found("tenant"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantUpdate {
    pii_default: Option<PiiMode>,
    pii_surrogate_scope: Option<PiiSurrogateScope>,
}

/// Changes a tenant's PII settings (absent fields are kept). Audited; routers pick it up with the
/// next snapshot.
async fn update_tenant(State(cp): State<Cp>, Path(tenant_id): Path<String>, Json(body): Json<TenantUpdate>) -> ApiResult<Json<Tenant>> {
    let m = Mutation::UpdateTenantPii { id: tenant_id.clone(), pii_default: body.pii_default, pii_surrogate_scope: body.pii_surrogate_scope };
    let st = cp.store.apply(ADMIN_ACTOR, m).await?;
    st.tenant(&tenant_id).cloned().map(Json).ok_or_else(|| not_found("tenant"))
}

/// Tombstones the tenant: revokes its API keys, destroys its BYOK credentials, removes its routes
/// and soft-deletes its datasources and nodes, in one audited transaction. The tenant leaves the
/// data-plane snapshot. A repeat delete is a 404, like every other delete.
async fn delete_tenant(State(cp): State<Cp>, Path(tenant_id): Path<String>) -> ApiResult<StatusCode> {
    cp.store.apply(ADMIN_ACTOR, Mutation::DeleteTenant { id: tenant_id, at: now_micros() }).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn ensure_tenant(cp: &ControlPlane, id: &str) -> ApiResult<()> {
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
    Ok(Json(st.api_keys.iter().filter(|k| k.tenant_id == tenant_id && (q.include_revoked || k.is_active())).cloned().collect()))
}

/// Soft revoke: the row is kept with `revoked_at`, and the key's hash leaves the data-plane
/// snapshot (standalone: immediately; split mode: on the router's next snapshot poll).
async fn revoke_api_key(State(cp): State<Cp>, Path((tenant_id, key_id)): Path<(String, String)>) -> ApiResult<StatusCode> {
    cp.store.apply(ADMIN_ACTOR, Mutation::RevokeApiKey { tenant_id, id: key_id, at: now_micros() }).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
struct ApiKeyCreate {
    name: Option<String>,
}

async fn create_api_key(
    State(cp): State<Cp>,
    Path(tenant_id): Path<String>,
    body: Option<Json<ApiKeyCreate>>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let key = generate_api_key();
    let rec = ApiKeyRecord {
        id: new_id("key"),
        tenant_id,
        name: body.and_then(|b| b.0.name).unwrap_or_else(|| "default".into()),
        prefix: key.chars().take(8).collect(),
        hash: hash_api_key(&key),
        created_at: now_micros(),
        revoked_at: None,
    };
    cp.store.apply(ADMIN_ACTOR, Mutation::CreateApiKey(rec.clone())).await?;
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

async fn list_provider_keys(State(cp): State<Cp>, Path(tenant_id): Path<String>) -> ApiResult<Json<Vec<ProviderKeyRecord>>> {
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
    Path(tenant_id): Path<String>,
    Json(body): Json<ProviderKeyCreate>,
) -> ApiResult<(StatusCode, Json<ProviderKeyRecord>)> {
    ensure_tenant(&cp, &tenant_id)?;
    if body.base_url.is_none() && store::default_base_url(body.kind).is_none() {
        return Err(bad("base_url is required for this provider kind"));
    }
    let id = body.provider_id.as_deref().map_or_else(|| slug(&body.label), slug);
    // Sealed before it reaches the store: plaintext is never persisted or audited.
    let (secret, last4) = match body.api_key.as_deref().filter(|k| !k.is_empty()) {
        Some(k) => {
            let kek = process_kek().map_err(|e| bad(format!("cannot store provider keys: {e}")))?;
            let last4: String = k.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
            (Some(SecretRef::Sealed { sealed: seal(kek, k) }), Some(last4))
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
    cp.store.apply(ADMIN_ACTOR, Mutation::CreateProviderKey(rec.clone())).await?;
    Ok((StatusCode::CREATED, Json(rec)))
}

async fn delete_provider_key(State(cp): State<Cp>, Path((tenant_id, key_id)): Path<(String, String)>) -> ApiResult<StatusCode> {
    // The sealed ciphertext is dropped with the row; with per-tenant DEKs (TODO) deleting the DEK
    // crypto-shreds every copy.
    cp.store
        .apply(ADMIN_ACTOR, Mutation::DeleteProviderKey { tenant_id, id: key_id })
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
async fn put_routes(State(cp): State<Cp>, Path(tenant_id): Path<String>, Json(body): Json<RoutesPut>) -> ApiResult<Json<Vec<RouteConfig>>> {
    let st = cp.store.apply(ADMIN_ACTOR, Mutation::SetRoutes { tenant_id: tenant_id.clone(), routes: body.routes }).await?;
    Ok(Json(st.routes.get(&tenant_id).cloned().unwrap_or_default()))
}

// ───────────────────────────── datasources & ontology ─────────────────────────────

#[derive(Deserialize)]
struct TenantFilter {
    tenant_id: Option<String>,
}

async fn list_datasources(State(cp): State<Cp>, Query(f): Query<TenantFilter>) -> Json<Vec<DatasourceRecord>> {
    let st = cp.store.state();
    Json(st.datasources.iter().filter(|d| d.is_live() && f.tenant_id.as_ref().is_none_or(|t| &d.tenant_id == t)).cloned().collect())
}

#[derive(Deserialize)]
struct DatasourceCreate {
    tenant_id: String,
    kind: String,
    name: String,
    connection: Value,
}

const DATASOURCE_KINDS: &[&str] = &[
    "mongodb", "postgres", "mysql", "sqlserver", "snowflake", "bigquery", "clickhouse", "elasticsearch", "rest_openapi",
    "s3_parquet", "mcp",
];

async fn create_datasource(State(cp): State<Cp>, Json(body): Json<DatasourceCreate>) -> ApiResult<(StatusCode, Json<DatasourceRecord>)> {
    if !DATASOURCE_KINDS.contains(&body.kind.as_str()) {
        return Err(bad(format!("unsupported datasource kind '{}'", body.kind)));
    }
    // TODO: seal secrets inside `connection` (passwords, URIs with credentials) like BYOK keys.
    let rec = DatasourceRecord {
        id: new_id("ds"),
        tenant_id: body.tenant_id,
        kind: body.kind,
        name: body.name,
        status: "pending".into(),
        epoch: 0,
        connection: body.connection,
        deleted_at: None,
    };
    cp.store.apply(ADMIN_ACTOR, Mutation::CreateDatasource(rec.clone())).await?;
    Ok((StatusCode::CREATED, Json(rec)))
}

/// Soft delete scoped to the tenant: the row is kept for audit, its stored connection is wiped.
async fn delete_datasource(State(cp): State<Cp>, Path((tenant_id, id)): Path<(String, String)>) -> ApiResult<StatusCode> {
    cp.store.apply(ADMIN_ACTOR, Mutation::DeleteDatasource { tenant_id, id, at: now_micros() }).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn introspect_datasource(State(cp): State<Cp>, Path(id): Path<String>) -> ApiResult<(StatusCode, Json<Value>)> {
    // TODO: run the bootstrap job (introspect → profile → mine query log → LLM proposals) via
    // caliban-connect, writing `proposed` ontology elements (Mutation::ProposeOntology).
    cp.store.apply(ADMIN_ACTOR, Mutation::SetDatasourceStatus { id, status: "introspecting".into() }).await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "job_id": new_id("job") }))))
}

async fn get_ontology(State(cp): State<Cp>, Query(f): Query<TenantFilter>) -> ApiResult<Json<caliban_ontology::Ontology>> {
    let tenant = f.tenant_id.ok_or_else(|| bad("tenant_id is required"))?;
    ensure_tenant(&cp, &tenant)?;
    let st = cp.store.state();
    Ok(Json(st.ontologies.get(&tenant).cloned().unwrap_or_else(|| caliban_ontology::Ontology {
        tenant_id: tenant,
        version: 0,
        elements: vec![],
    })))
}

#[derive(Deserialize)]
struct Review {
    decision: String,
    #[allow(dead_code)]
    note: Option<String>,
}

async fn review_element(State(cp): State<Cp>, Path(id): Path<String>, Json(r): Json<Review>) -> ApiResult<Json<Value>> {
    let status = match r.decision.as_str() {
        "approve" => Status::Approved,
        "reject" => Status::Rejected,
        _ => return Err(bad("decision must be 'approve' or 'reject'")),
    };
    // Any reviewed change publishes a new ontology version (cache keys include it).
    let st = cp.store.apply(ADMIN_ACTOR, Mutation::ReviewOntologyElement { id: id.clone(), status }).await?;
    st.ontologies
        .values()
        .find_map(|o| o.elements.iter().find(|e| e.id == id))
        .map(|e| Json(serde_json::to_value(e).unwrap_or_default()))
        .ok_or_else(|| not_found("ontology element"))
}

// ───────────────────────────── nodes & usage ─────────────────────────────

async fn list_nodes(State(cp): State<Cp>, Query(f): Query<TenantFilter>) -> Json<Vec<NodeRecord>> {
    let st = cp.store.state();
    Json(st.nodes.iter().filter(|n| n.is_live() && f.tenant_id.as_ref().is_none_or(|t| &n.tenant_id == t)).cloned().collect())
}

/// Soft-deletes one node version, scoped to the tenant. Its version number is not reused.
async fn delete_node(State(cp): State<Cp>, Path((tenant_id, id)): Path<(String, String)>) -> ApiResult<StatusCode> {
    cp.store.apply(ADMIN_ACTOR, Mutation::DeleteNode { tenant_id, id, at: now_micros() }).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct NodeCreate {
    tenant_id: String,
    name: String,
    spec: Value,
}

async fn create_node(State(cp): State<Cp>, Json(body): Json<NodeCreate>) -> ApiResult<(StatusCode, Json<NodeRecord>)> {
    ensure_tenant(&cp, &body.tenant_id)?;
    let spec: NodeSpec =
        serde_json::from_value(body.spec.clone()).map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("invalid node spec: {e}")))?;
    spec.validate().map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let id = new_id("node");
    let rec = NodeRecord {
        id: id.clone(),
        tenant_id: body.tenant_id,
        name: body.name,
        version: 0,
        spec: body.spec,
        created_at: now_micros(),
        deleted_at: None,
    };
    let st = cp.store.apply(ADMIN_ACTOR, Mutation::CreateNode(rec)).await?;
    let created = st.nodes.iter().find(|n| n.id == id).cloned().ok_or_else(|| not_found("node"))?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Deserialize)]
struct UsageQuery {
    tenant_id: Option<String>,
    limit: Option<usize>,
}

async fn usage(State(cp): State<Cp>, Query(q): Query<UsageQuery>) -> Json<Value> {
    let events = cp.store.usage.snapshot(q.tenant_id.as_deref(), q.limit.unwrap_or(100).min(1000));
    let all = cp.store.usage.snapshot(q.tenant_id.as_deref(), usize::MAX);
    let totals = json!({
        "requests": all.len(),
        "prompt_tokens": all.iter().map(|e| e.prompt_tokens).sum::<u64>(),
        "completion_tokens": all.iter().map(|e| e.completion_tokens).sum::<u64>(),
        "cache_hits": all.iter().filter(|e| e.cache == caliban_types::CacheStatus::Hit).count(),
        "tokens_saved": all.iter().map(|e| e.tokens_saved + e.cached_prompt_tokens).sum::<u64>(),
        "cost_usd": all.iter().filter_map(|e| e.cost_usd).sum::<f64>(),
        // caliban/auto: flat price billed vs the routed models' real cost, over events with both.
        "auto_requests": all.iter().filter(|e| e.requested_model.as_deref() == Some("caliban/auto")).count(),
        "flat_price_usd": all.iter().filter(|e| e.margin_usd().is_some()).filter_map(|e| e.flat_price_usd).sum::<f64>(),
        "routed_model_cost_usd": all.iter().filter(|e| e.margin_usd().is_some()).filter_map(|e| e.routed_model_cost_usd).sum::<f64>(),
        "margin_usd": all.iter().filter_map(caliban_meter::UsageEvent::margin_usd).sum::<f64>(),
    });
    Json(json!({ "events": events, "totals": totals }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use caliban_config::signing::{SnapshotVerifier, generate_signing_key};
    use caliban_config::{Config, ConfigHandle, Snapshot};
    use caliban_meter::RecentUsage;
    use tower::ServiceExt;

    fn cp() -> Cp {
        let cfg = Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
        let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
        Arc::new(ControlPlane::new(Store::new(cfg, handle, RecentUsage::default()), "admin-secret".into(), "standalone"))
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
        let (s, t) = call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Initech", "pii_surrogate_scope": "session"})), true).await;
        assert_eq!(s, StatusCode::CREATED);
        assert_eq!(t["pii_surrogate_scope"], "session");

        let (s, t) = call(&app, "PATCH", "/api/v1/tenants/globex", Some(json!({"pii_surrogate_scope": "session"})), true).await;
        assert_eq!(s, StatusCode::OK, "{t}");
        assert_eq!((t["pii_surrogate_scope"].as_str(), t["pii_default"].as_str()), (Some("session"), Some("reversible")));
        let snap = c.store.config.load();
        assert_eq!(snap.pii_surrogate_scope_for(snap.tenant(&"globex".into()).unwrap()), PiiSurrogateScope::Session);
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=1", None, true).await;
        assert_eq!(a["entries"][0]["action"], "tenant.update");
        assert_eq!(a["entries"][0]["detail"]["pii_surrogate_scope"], json!({"from": "tenant", "to": "session"}));

        let (s, _) = call(&app, "PATCH", "/api/v1/tenants/globex", Some(json!({"pii_surrogate_scope": "global"})), true).await;
        assert!(s.is_client_error());
        let (s, _) = call(&app, "PATCH", "/api/v1/tenants/globex", Some(json!({"name": "x"})), true).await;
        assert!(s.is_client_error(), "only PII settings can be patched");
        let (s, _) = call(&app, "PATCH", "/api/v1/tenants/nobody", Some(json!({"pii_default": "mask"})), true).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_node_spec_is_rejected() {
        let app = app(cp(), None);
        let spec = json!({"kind": "agent", "prompt": {"system": "x"}, "model_policy": {},
                          "tools": [{"ref": "mcp://erp/x", "effect": "read"}],
                          "budgets": {"steps": 3, "tokens": 100, "wall_clock_s": 10}});
        let (s, e) = call(&app, "POST", "/api/v1/nodes", Some(json!({"tenant_id": "acme", "name": "n", "spec": spec})), true).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{e}");
    }

    #[tokio::test]
    async fn routes_are_validated_and_published() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        let (s, _) =
            call(&app, "PUT", "/api/v1/tenants/acme/routes", Some(json!({"routes": [{"intent": "x", "models": ["nope/none"]}]})), true).await;
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
        assert_eq!(call(&app, "DELETE", &format!("/api/v1/tenants/acme/api-keys/{id}"), None, true).await.0, StatusCode::NOT_FOUND);
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
        assert_eq!((&e["action"], &e["actor"], &e["tenant_id"], &e["target"]), (&json!("api_key.revoke"), &json!("admin"), &json!("globex"), &json!(id)));
        assert_eq!(e["detail"], json!({"name": "ci", "prefix": &key[..8]}));
        assert!(!a.to_string().contains(&key[8..]));
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
        assert_eq!(call(&app, "POST", "/api/v1/tenants/acme/api-keys", Some(json!({})), true).await.0, StatusCode::NOT_FOUND);
        assert_eq!(call(&app, "GET", "/api/v1/datasources?tenant_id=acme", None, true).await.1, json!([]));
        let ds_id = ds["id"].as_str().unwrap();
        assert_eq!(call(&app, "POST", &format!("/api/v1/datasources/{ds_id}/introspect"), None, true).await.0, StatusCode::NOT_FOUND);
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
        assert_eq!((&del["actor"], &del["target"]), (&json!("admin"), &json!("acme")));
        assert_eq!(del["detail"]["datasources_deleted"], json!([ds_id]));
        // The tenant's earlier audit rows are still there.
        assert!(a["entries"].as_array().unwrap().iter().any(|e| e["action"] == "datasource.create" && e["tenant_id"] == "acme"));
    }

    #[tokio::test]
    async fn datasource_and_node_deletes_are_tenant_scoped() {
        let c = cp();
        let app = app(Arc::clone(&c), None);
        call(&app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"})), true).await;
        let (_, ds) = call(&app, "POST", "/api/v1/datasources", Some(json!({"tenant_id": "acme", "kind": "postgres", "name": "erp", "connection": {}})), true).await;
        let spec = json!({"kind": "agent", "prompt": {"system": "x"}, "model_policy": {}, "tools": [],
                          "budgets": {"steps": 3, "tokens": 100, "wall_clock_s": 10}});
        let (s, n) = call(&app, "POST", "/api/v1/nodes", Some(json!({"tenant_id": "acme", "name": "triage", "spec": spec})), true).await;
        assert_eq!(s, StatusCode::CREATED, "{n}");
        for (kind, id) in [("datasources", ds["id"].as_str().unwrap()), ("nodes", n["id"].as_str().unwrap())] {
            let own = format!("/api/v1/tenants/acme/{kind}/{id}");
            assert_eq!(call(&app, "DELETE", &own, None, false).await.0, StatusCode::UNAUTHORIZED);
            let (s, e) = call(&app, "DELETE", &format!("/api/v1/tenants/globex/{kind}/{id}"), None, true).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{kind}: another tenant's id");
            assert!(is_error(&e, "not_found"));
            assert_eq!(call(&app, "DELETE", &format!("/api/v1/tenants/acme/{kind}/nope"), None, true).await.0, StatusCode::NOT_FOUND);
            assert_eq!(call(&app, "DELETE", &own, None, true).await.0, StatusCode::NO_CONTENT);
            assert_eq!(call(&app, "DELETE", &own, None, true).await.0, StatusCode::NOT_FOUND, "{kind}: repeat delete");
            assert_eq!(call(&app, "GET", &format!("/api/v1/{kind}?tenant_id=acme"), None, true).await.1, json!([]));
        }
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=2", None, true).await;
        let actions: Vec<&str> = a["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
        assert_eq!(actions, ["node.delete", "datasource.delete"]);
        assert_eq!(a["entries"][0]["detail"], json!({"name": "triage", "version": 1}));
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
}
