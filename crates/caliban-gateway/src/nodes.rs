//! Node runs on the data plane (P3 M2): the minimal run API, the bridge from the node executor to
//! this gateway's request pipeline, and forwarding from routers to workers.
//!
//! **Run API** (tenant API keys; the key must be allowed to run the node, see
//! `TenantConfig::key_may_run`):
//! - `POST /v1/nodes/{name}/runs` `{"input": ..., "version"?: N, "async"?: bool, "wait_s"?: s}`:
//!   sync by default (waits until the run ends or waits for a human, at most
//!   `CALIBAN_NODE_SYNC_WAIT_SECS`, then answers `202` with the run so far); `"async": true`
//!   answers `202` at once. `Idempotency-Key` returns the run the first request created.
//! - `GET /v1/runs/{id}`: status, output, awaited question, budget, steps.
//! - `POST /v1/runs/{id}/input` `{"answer": ..., "step"?: id}`: answers a human step.
//!
//! **Where runs execute.** Standalone: in this process ([`NodeRuns::Local`]). Split mode: routers
//! hold no database, so they forward run requests to a worker ([`NodeRuns::Forward`], configured
//! worker URLs, a shared worker token); a worker is a gateway with a journal ([`worker_app`]).
//!
//! **Model calls stay in the pipeline.** The executor's model calls ([`GatewayModels`]) are
//! dispatched in-process through this gateway's own HTTP router (`/v1/chat/completions`, with
//! the run's tenant and invoking API key as an [`InternalCaller`] request extension, which the
//! network cannot set): PII, both caches, routing (`caliban/auto` included), quotas, metering,
//! usage shipping and tracing apply exactly as to client traffic, with no network hop. Each call
//! carries `Idempotency-Key: caliban-node-<hash(run id, step id)>`, so a step replayed after a
//! worker died gets the stored response instead of paying twice.

use crate::auth::{self, InternalCaller, NodeTag};
use crate::{Gateway, idempotency};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use caliban_config::{ConfigHandle, Dek, Keyring};
use caliban_nodes::NodeSpec;
use caliban_nodes::executor::{
    CallCtx, ExecError, Executor, ExecutorOptions, ModelClient, ModelError, ModelReply, NodeSource, ResolvedNode,
    RunView, StartRun, TenantPolicy, ToolRegistry,
};
use caliban_nodes::journal::{Delivered, Journal, RunStatus};
use caliban_nodes::seal::{DekSealer, Sealer};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tower::ServiceExt;

/// Header a router sends a worker; the worker refuses run requests without it.
pub const WORKER_TOKEN_HEADER: &str = "x-caliban-worker-token";

/// How this data plane serves node runs.
pub enum NodeRuns {
    /// Executes runs in this process (standalone, worker).
    Local(LocalRuns),
    /// Forwards run requests to workers (split-mode router).
    Forward(Forwarder),
}

pub struct LocalRuns {
    pub executor: Arc<Executor>,
    /// Longest a sync run request waits before answering `202`.
    pub sync_wait: Duration,
}

impl Gateway {
    /// Enables the run API (once; later calls are ignored).
    pub fn set_nodes(&self, runs: NodeRuns) {
        if self.nodes.set(runs).is_err() {
            tracing::warn!("node runs were already configured");
        }
    }

    pub fn nodes(&self) -> Option<&NodeRuns> {
        self.nodes.get()
    }
}

// ───────────────────────────── executor bridges ─────────────────────────────

/// The executor's model calls, through this gateway's pipeline (see the module docs).
pub struct GatewayModels {
    gw: Weak<Gateway>,
}

impl GatewayModels {
    pub fn new(gw: &Arc<Gateway>) -> Self {
        Self { gw: Arc::downgrade(gw) }
    }
}

#[async_trait::async_trait]
impl ModelClient for GatewayModels {
    async fn chat(&self, ctx: &CallCtx, mut body: Value) -> Result<ModelReply, ModelError> {
        let gw = self.gw.upgrade().ok_or_else(|| ModelError::Unavailable("the gateway is shutting down".into()))?;
        let key_hash = ctx
            .invoker_key_hash
            .clone()
            .ok_or_else(|| ModelError::Rejected("the run has no invoking API key".into()))?;
        if let Some(o) = body.as_object_mut() {
            o.insert("stream".into(), Value::Bool(false));
        }
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::CONTENT_TYPE, "application/json")
            .header(idempotency::HEADER, &ctx.idempotency_key)
            .body(Body::from(body.to_string()))
            .map_err(|e| ModelError::Rejected(e.to_string()))?;
        let node = NodeTag { node: ctx.node.clone(), version: ctx.node_version, run_id: ctx.run_id.clone() };
        req.extensions_mut().insert(InternalCaller { tenant: ctx.tenant.clone(), key_hash, node: Some(node) });
        let resp = crate::app(gw).oneshot(req).await.map_err(|e| ModelError::Unavailable(e.to_string()))?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), crate::MAX_BODY)
            .await
            .map_err(|e| ModelError::Unavailable(format!("reading the response: {e}")))?;
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if !status.is_success() {
            let msg = v.pointer("/error/message").and_then(Value::as_str).unwrap_or("no detail").to_owned();
            let code = v.pointer("/error/code").and_then(Value::as_str).unwrap_or_default();
            let msg = format!("{status}: {msg}");
            if status == StatusCode::TOO_MANY_REQUESTS {
                // A tenant quota: the run sleeps in the journal until it resets.
                let secs = headers
                    .get(header::RETRY_AFTER)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(1);
                return Err(ModelError::Throttled { retry_after: Duration::from_secs(secs), message: msg });
            }
            // Busy: the same step is still in flight (a worker died during the call); its stored
            // response is ready when it ends.
            let transient =
                status.is_server_error() || (status == StatusCode::CONFLICT && code == "idempotency_key_in_use");
            return Err(if transient { ModelError::Unavailable(msg) } else { ModelError::Rejected(msg) });
        }
        let message = v
            .pointer("/choices/0/message")
            .cloned()
            .ok_or_else(|| ModelError::Rejected("the response has no message".into()))?;
        let u = |k: &str| v.pointer(&format!("/usage/{k}")).and_then(Value::as_u64).unwrap_or(0);
        // Priced like the metering prices it: the flat caliban/auto price (cache hits discounted)
        // or the pinned model's price.
        let usd = ["x-caliban-billed-usd", "x-caliban-cost-usd"]
            .iter()
            .find_map(|h| headers.get(*h).and_then(|h| h.to_str().ok()).and_then(|s| s.parse::<f64>().ok()))
            .unwrap_or(0.0);
        let replayed = headers.get(idempotency::REPLAYED).is_some();
        Ok(ModelReply { message, tokens: u("prompt_tokens") + u("completion_tokens"), usd, replayed })
    }
}

/// Published node versions from the snapshot, opened with the keyring and checked against their
/// content hash.
pub struct SnapshotNodes {
    config: ConfigHandle,
    keyring: Arc<Keyring>,
}

impl SnapshotNodes {
    pub fn new(config: ConfigHandle, keyring: Arc<Keyring>) -> Self {
        Self { config, keyring }
    }
}

impl NodeSource for SnapshotNodes {
    fn resolve(&self, tenant: &str, name: &str, version: Option<u32>) -> Result<ResolvedNode, String> {
        let snap = self.config.load();
        let t = snap.tenant(&tenant.into()).ok_or("unknown tenant")?;
        let n = t.node(name, version).ok_or_else(|| match version {
            Some(v) => format!("node {name}@v{v} is not published"),
            None => format!("node {name} has no live (promoted) version"),
        })?;
        let text = n.open_spec(&self.keyring).map_err(|e| format!("node {name}@v{}: {e}", n.version))?;
        let value: Value = serde_json::from_str(&text).map_err(|e| format!("node {name}@v{}: {e}", n.version))?;
        if caliban_nodes::hash::content_hash(&value) != n.hash {
            return Err(format!("node {name}@v{}: the spec does not match its hash", n.version));
        }
        let spec: NodeSpec = serde_json::from_value(value).map_err(|e| format!("node {name}@v{}: {e}", n.version))?;
        Ok(ResolvedNode { name: n.name.clone(), version: n.version, hash: n.hash.clone(), spec: Arc::new(spec) })
    }

    fn tenant_policy(&self, tenant: &str) -> TenantPolicy {
        let snap = self.config.load();
        let Some(t) = snap.tenant(&tenant.into()) else { return TenantPolicy::default() };
        TenantPolicy { spend: t.node_spend_caps.unwrap_or_default() }
    }
}

/// Seals run data with the tenant's data key from the snapshot (`data_key`), opened with the
/// keyring.
pub fn snapshot_sealer(config: ConfigHandle, keyring: Arc<Keyring>) -> Arc<dyn Sealer> {
    Arc::new(DekSealer::new(move |tenant: &str| -> Result<Arc<Dek>, String> {
        let snap = config.load();
        let wrapped = snap
            .tenant(&tenant.into())
            .and_then(|t| t.data_key.clone())
            .ok_or_else(|| format!("tenant {tenant} has no data key in the snapshot"))?;
        keyring.unwrap_dek(tenant, &wrapped).map(Arc::new)
    }))
}

/// The executor of a standalone process or a worker: model calls through `gw`, specs and data
/// keys from its snapshot.
pub fn local_executor(
    gw: &Arc<Gateway>,
    journal: Arc<dyn Journal>,
    tools: Arc<dyn ToolRegistry>,
    keyring: Arc<Keyring>,
    worker_id: String,
    opts: ExecutorOptions,
) -> Arc<Executor> {
    Arc::new(Executor::new(
        journal,
        Arc::new(GatewayModels::new(gw)),
        tools,
        Arc::new(SnapshotNodes::new(gw.config.clone(), Arc::clone(&keyring))),
        snapshot_sealer(gw.config.clone(), keyring),
        worker_id,
        opts,
    ))
}

// ───────────────────────────── run API ─────────────────────────────

fn error(status: StatusCode, kind: &str, code: Option<&str>, message: impl Into<String>) -> Response {
    let body = json!({"error": {"message": message.into(), "type": kind, "code": code}});
    (status, axum::Json(body)).into_response()
}

fn exec_error(e: ExecError) -> Response {
    match e {
        ExecError::NotFound(m) => error(StatusCode::NOT_FOUND, "not_found", Some("node_not_found"), m),
        ExecError::Invalid(m) => error(StatusCode::BAD_REQUEST, "invalid_request_error", Some("invalid_input"), m),
        ExecError::KeyReused => error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request_error",
            Some("idempotency_key_reused"),
            "this Idempotency-Key was used for a different run request",
        ),
        ExecError::Conflict(m) => error(StatusCode::CONFLICT, "invalid_request_error", None, m),
        ExecError::Internal(m) => {
            tracing::error!(error = %m, "node run error");
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", None, "node run error")
        }
    }
}

fn unauthenticated() -> Response {
    error(StatusCode::UNAUTHORIZED, "authentication_error", None, "invalid or missing API key")
}

fn not_enabled() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        Some("nodes_not_enabled"),
        "node runs are not enabled on this data plane (standalone needs CALIBAN_KEK; split-mode routers need CALIBAN_WORKER_URLS)",
    )
}

fn forbidden_node(name: &str) -> Response {
    error(
        StatusCode::FORBIDDEN,
        "permission_error",
        Some("node_not_allowed"),
        format!("this API key may not run node '{name}'"),
    )
}

fn view_response(status: StatusCode, v: &RunView, replayed: bool) -> Response {
    let mut resp = (status, axum::Json(v)).into_response();
    if let Ok(loc) = HeaderValue::from_str(&format!("/v1/runs/{}", v.id)) {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    if replayed {
        resp.headers_mut().insert(idempotency::REPLAYED, HeaderValue::from_static("true"));
    }
    resp
}

/// `200` once the run has ended; `202` while it runs or waits.
fn run_status(v: &RunView) -> StatusCode {
    if v.status.is_terminal() { StatusCode::OK } else { StatusCode::ACCEPTED }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunCreate {
    #[serde(default)]
    input: Value,
    version: Option<u32>,
    #[serde(default, rename = "async")]
    is_async: bool,
    /// Wait at most this long (seconds) for a sync run; capped by the server.
    wait_s: Option<f64>,
    /// Lowers the version's budget for this run (`steps`, `tokens`, `usd`, `wall_clock_s`).
    budget: Option<caliban_nodes::executor::RunBudget>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunInput {
    answer: Value,
    step: Option<String>,
}

async fn create_run(
    State(gw): State<Arc<Gateway>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    req: Request,
) -> Response {
    let (allowed, tenant, key_hash) = {
        let snap = gw.config.load();
        let Ok(c) = auth::caller(&snap, &headers) else { return unauthenticated() };
        (c.tenant.key_may_run(&c.key_hash, &name), c.tenant.id.to_string(), c.key_hash)
    };
    if !allowed {
        return forbidden_node(&name);
    }
    let runs = match gw.nodes() {
        None => return not_enabled(),
        Some(NodeRuns::Forward(f)) => return f.forward(req).await,
        Some(NodeRuns::Local(l)) => l,
    };
    let Ok(body) = axum::body::to_bytes(req.into_body(), crate::MAX_BODY).await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request_error", None, "request body too large");
    };
    let rc: RunCreate = match serde_json::from_slice(&body) {
        Ok(rc) => rc,
        Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", None, format!("invalid body: {e}")),
    };
    let idempotency = match headers.get(idempotency::HEADER) {
        None => None,
        Some(v) => match v.to_str().ok().map(str::trim).filter(|k| (1..=255).contains(&k.len())) {
            Some(k) => Some((k.to_owned(), idempotency::fingerprint("POST", &format!("/v1/nodes/{name}/runs"), &body))),
            None => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    Some("invalid_idempotency_key"),
                    "Idempotency-Key must be 1 to 255 visible ASCII characters",
                );
            }
        },
    };
    let start = StartRun {
        tenant: tenant.clone(),
        node: name,
        version: rc.version,
        input: rc.input,
        invoker: format!("api_key:{}", &key_hash[..key_hash.len().min(12)]),
        invoker_key_hash: Some(key_hash),
        idempotency,
        budget: rc.budget,
    };
    let (run, new) = match runs.executor.create(start).await {
        Ok(x) => x,
        Err(e) => return exec_error(e),
    };
    if !rc.is_async {
        if run.status == RunStatus::Pending {
            runs.executor.spawn_run(run.id.clone());
        }
        let wait = rc.wait_s.map_or(runs.sync_wait, |s| Duration::from_secs_f64(s.max(0.0))).min(runs.sync_wait);
        if let Err(e) = runs.executor.wait(&tenant, &run.id, Instant::now() + wait).await {
            return exec_error(e);
        }
    }
    match runs.executor.view(&tenant, &run.id).await {
        Ok(Some(v)) => view_response(if rc.is_async { StatusCode::ACCEPTED } else { run_status(&v) }, &v, !new),
        Ok(None) => exec_error(ExecError::Internal("the run vanished".into())),
        Err(e) => exec_error(e),
    }
}

/// The caller and the run, for the routes on an existing run (forwarded by routers).
#[allow(clippy::result_large_err)] // the error is the response itself
async fn existing<'a>(
    gw: &'a Gateway,
    headers: &HeaderMap,
    id: &str,
) -> Result<(&'a LocalRuns, RunView, String), Response> {
    let (tenant, key_hash) = {
        let snap = gw.config.load();
        let c = auth::caller(&snap, headers).map_err(|_| unauthenticated())?;
        (c.tenant.id.to_string(), c.key_hash)
    };
    let runs = match gw.nodes() {
        None => return Err(not_enabled()),
        Some(NodeRuns::Forward(_)) => return Err(StatusCode::MISDIRECTED_REQUEST.into_response()),
        Some(NodeRuns::Local(l)) => l,
    };
    let not_found = || error(StatusCode::NOT_FOUND, "not_found", Some("run_not_found"), "run not found");
    let v = runs.executor.view(&tenant, id).await.map_err(exec_error)?.ok_or_else(not_found)?;
    let snap = gw.config.load();
    let allowed = snap.tenant(&tenant.as_str().into()).is_some_and(|t| t.key_may_run(&key_hash, &v.node));
    if !allowed {
        return Err(forbidden_node(&v.node));
    }
    Ok((runs, v, tenant))
}

async fn get_run(State(gw): State<Arc<Gateway>>, Path(id): Path<String>, req: Request) -> Response {
    if let Some(NodeRuns::Forward(f)) = gw.nodes() {
        return forward_authenticated(&gw, f, req).await;
    }
    match existing(&gw, req.headers(), &id).await {
        Ok((_, v, _)) => view_response(StatusCode::OK, &v, false),
        Err(r) => r,
    }
}

async fn run_input(State(gw): State<Arc<Gateway>>, Path(id): Path<String>, req: Request) -> Response {
    if let Some(NodeRuns::Forward(f)) = gw.nodes() {
        return forward_authenticated(&gw, f, req).await;
    }
    let (runs, _, tenant) = match existing(&gw, req.headers(), &id).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(body) = axum::body::to_bytes(req.into_body(), crate::MAX_BODY).await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request_error", None, "request body too large");
    };
    let input: RunInput = match serde_json::from_slice(&body) {
        Ok(i) => i,
        Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", None, format!("invalid body: {e}")),
    };
    match runs.executor.deliver_input(&tenant, &id, input.step.as_deref(), &input.answer).await {
        Ok(Delivered::Accepted) => {
            // Resumed here at once (another worker would pick it up at its next poll).
            runs.executor.spawn_run(id.clone());
            match runs.executor.view(&tenant, &id).await {
                Ok(Some(v)) => view_response(StatusCode::ACCEPTED, &v, false),
                Ok(None) => error(StatusCode::NOT_FOUND, "not_found", Some("run_not_found"), "run not found"),
                Err(e) => exec_error(e),
            }
        }
        Ok(Delivered::NotAwaiting) => error(
            StatusCode::CONFLICT,
            "invalid_request_error",
            Some("run_not_awaiting_input"),
            "the run is not waiting for input (or not for this step)",
        ),
        Ok(Delivered::NotFound) => error(StatusCode::NOT_FOUND, "not_found", Some("run_not_found"), "run not found"),
        Err(e) => exec_error(e),
    }
}

/// Routers authenticate the API key before forwarding (workers check it again, and the node
/// allowlist against the run).
async fn forward_authenticated(gw: &Gateway, f: &Forwarder, req: Request) -> Response {
    if auth::caller(&gw.config.load(), req.headers()).is_err() {
        return unauthenticated();
    }
    f.forward(req).await
}

/// The run routes (merged into the data-plane app).
pub(crate) fn routes() -> Router<Arc<Gateway>> {
    Router::new()
        .route("/v1/nodes/{name}/runs", post(create_run))
        .route("/v1/runs/{id}", get(get_run))
        .route("/v1/runs/{id}/input", post(run_input))
}

// ───────────────────────────── split mode ─────────────────────────────

/// A split-mode router's side: run requests go to a worker (`CALIBAN_WORKER_URLS`), round-robin,
/// trying the next worker when one cannot be reached. Workers share the Postgres journal, so any
/// worker can answer for any run.
pub struct Forwarder {
    workers: Vec<String>,
    token: String,
    client: reqwest::Client,
    next: AtomicUsize,
}

impl Forwarder {
    /// `timeout` bounds a forwarded request: longer than the workers' sync wait.
    pub fn new(workers: Vec<String>, token: String, timeout: Duration) -> Result<Self, String> {
        let workers: Vec<String> =
            workers.into_iter().map(|w| w.trim().trim_end_matches('/').to_owned()).filter(|w| !w.is_empty()).collect();
        if workers.is_empty() {
            return Err("no worker URL".into());
        }
        if token.is_empty() {
            return Err("the worker token is empty".into());
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { workers, token, client, next: AtomicUsize::new(0) })
    }

    pub async fn forward(&self, req: Request) -> Response {
        let (parts, body) = req.into_parts();
        let Ok(body) = axum::body::to_bytes(body, crate::MAX_BODY).await else {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request_error", None, "request body too large");
        };
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let mut last = String::new();
        for i in 0..self.workers.len() {
            let base = &self.workers[(start + i) % self.workers.len()];
            let mut rb = self
                .client
                .request(parts.method.clone(), format!("{base}{path}"))
                .header(WORKER_TOKEN_HEADER, &self.token)
                .body(body.clone());
            for name in
                [header::AUTHORIZATION.as_str(), "x-api-key", idempotency::HEADER, "content-type", "traceparent"]
            {
                if let Some(v) = parts.headers.get(name) {
                    rb = rb.header(name, v.clone());
                }
            }
            match rb.send().await {
                Ok(resp) => return relay(resp).await,
                // Not reached at all: the next worker may be up. Anything else (a timeout once the
                // request was sent) is not retried: the first worker may already be running it.
                Err(e) if e.is_connect() => last = format!("{base}: {e}"),
                Err(e) => {
                    return error(
                        StatusCode::BAD_GATEWAY,
                        "upstream_error",
                        Some("worker_error"),
                        format!("{base}: {e}"),
                    );
                }
            }
        }
        tracing::warn!(error = %last, "no node worker reachable");
        error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", Some("no_worker"), "no node worker is reachable")
    }
}

async fn relay(resp: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = Response::builder().status(status);
    for name in ["content-type", "location", idempotency::REPLAYED, "retry-after"] {
        if let Some(v) = resp.headers().get(name)
            && let (Ok(n), Ok(v)) = (HeaderName::try_from(name), HeaderValue::from_bytes(v.as_bytes()))
        {
            out = out.header(n, v);
        }
    }
    let bytes: Bytes = resp.bytes().await.unwrap_or_default();
    out.body(Body::from(bytes)).unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

/// A worker's HTTP surface: the run API (requests must carry the worker token, as routers send
/// it), `/healthz` and `/metrics`. Workers do not serve the inference API.
pub fn worker_app(gw: Arc<Gateway>, token: String) -> Router {
    let token = Arc::new(token);
    let guarded = routes().route_layer(axum::middleware::from_fn(move |req: Request, next: Next| {
        let token = Arc::clone(&token);
        async move {
            let ok = req
                .headers()
                .get(WORKER_TOKEN_HEADER)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|t| !token.is_empty() && constant_time_eq(t.as_bytes(), token.as_bytes()));
            if ok {
                next.run(req).await
            } else {
                error(
                    StatusCode::UNAUTHORIZED,
                    "authentication_error",
                    Some("worker_token"),
                    "invalid or missing worker token",
                )
            }
        }
    }));
    Router::new()
        .merge(guarded)
        .route("/healthz", get(crate::health))
        .route("/metrics", get(crate::metrics))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(crate::MAX_BODY))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(gw)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
