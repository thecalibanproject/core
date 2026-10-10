//! Node runs on the data plane (P3 M2): the bridge from the node executor to this gateway's
//! request pipeline, and forwarding from routers to workers. The run API itself is in
//! [`crate::runs`].
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

use crate::auth::{InternalCaller, NodeTag};
use crate::runs::{RunError, error};
use crate::{Gateway, idempotency};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use caliban_config::{ConfigHandle, Dek, Keyring};
use caliban_nodes::NodeSpec;
use caliban_nodes::executor::{
    CallCtx, Executor, ExecutorOptions, ModelClient, ModelError, ModelReply, NodeSource, ResolvedNode, TenantPolicy,
    ToolRegistry,
};
use caliban_nodes::journal::Journal;
use caliban_nodes::seal::{DekSealer, Sealer};
use futures::StreamExt;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
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
        let (prompt_tokens, completion_tokens) = (u("prompt_tokens"), u("completion_tokens"));
        Ok(ModelReply {
            message,
            tokens: prompt_tokens + completion_tokens,
            prompt_tokens,
            completion_tokens,
            usd,
            replayed,
        })
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
    gw.set_keyring(Arc::clone(&keyring));
    Arc::new(
        Executor::new(
            journal,
            Arc::new(GatewayModels::new(gw)),
            tools,
            Arc::new(SnapshotNodes::new(gw.config.clone(), Arc::clone(&keyring))),
            snapshot_sealer(gw.config.clone(), keyring),
            worker_id,
            opts,
        )
        .with_data_guard(Arc::new(crate::tools::PiiGuard::new(gw))),
    )
}

// ───────────────────────────── split mode ─────────────────────────────

/// A split-mode router's side: run requests go to a worker (`CALIBAN_WORKER_URLS`), round-robin,
/// trying the next worker when one cannot be reached. Workers share the Postgres journal, so any
/// worker can answer for any run.
pub struct Forwarder {
    workers: Vec<String>,
    token: String,
    /// Bounded by `timeout` (sync requests).
    client: reqwest::Client,
    /// No overall timeout (event streams last as long as the run).
    streams: reqwest::Client,
    next: AtomicUsize,
    sync_wait: Duration,
}

/// Request headers a router passes on to a worker.
const FORWARDED: [&str; 7] =
    ["authorization", "x-api-key", idempotency::HEADER, "content-type", "traceparent", "last-event-id", "accept"];

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
        let build = |t: Option<Duration>| {
            let b = reqwest::Client::builder().connect_timeout(Duration::from_secs(5));
            match t {
                Some(t) => b.timeout(t),
                None => b,
            }
            .build()
            .map_err(|e| e.to_string())
        };
        Ok(Self {
            workers,
            token,
            client: build(Some(timeout))?,
            streams: build(None)?,
            next: AtomicUsize::new(0),
            sync_wait: timeout.saturating_sub(Duration::from_secs(30)).max(Duration::from_secs(1)),
        })
    }

    /// How long a synchronous caller on the router waits for a run.
    pub fn sync_wait(&self) -> Duration {
        self.sync_wait
    }

    /// Sends a request to the next worker in turn (moving on while one cannot be reached), with
    /// the client's authentication headers from `headers` and `extra` internal headers. A non-2xx
    /// answer is returned as the worker's error.
    pub(crate) async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &HeaderMap,
        extra: &[(&str, String)],
        body: Option<String>,
        stream: bool,
    ) -> Result<reqwest::Response, RunError> {
        let resp = self.try_workers(method, path, headers, extra, body.map(Bytes::from), stream).await?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        let e = &v["error"];
        Err(RunError {
            status,
            kind: match status {
                StatusCode::UNAUTHORIZED => "authentication_error",
                StatusCode::FORBIDDEN => "permission_error",
                StatusCode::NOT_FOUND => "not_found",
                StatusCode::TOO_MANY_REQUESTS => "rate_limit_error",
                s if s.is_client_error() => "invalid_request_error",
                _ => "upstream_error",
            },
            code: e["code"].as_str().map(str::to_owned),
            message: e["message"].as_str().unwrap_or("the worker refused the request").to_owned(),
        })
    }

    async fn try_workers(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &HeaderMap,
        extra: &[(&str, String)],
        body: Option<Bytes>,
        stream: bool,
    ) -> Result<reqwest::Response, RunError> {
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let mut last = String::new();
        let client = if stream { &self.streams } else { &self.client };
        for i in 0..self.workers.len() {
            let base = &self.workers[(start + i) % self.workers.len()];
            let mut rb =
                client.request(method.clone(), format!("{base}{path}")).header(WORKER_TOKEN_HEADER, &self.token);
            if let Some(b) = &body {
                rb = rb.body(b.clone());
            }
            for name in FORWARDED {
                if let Some(v) = headers.get(name) {
                    rb = rb.header(name, v.clone());
                }
            }
            if body.is_some() && headers.get(header::CONTENT_TYPE).is_none() {
                rb = rb.header(header::CONTENT_TYPE, "application/json");
            }
            for (k, v) in extra {
                rb = rb.header(*k, v);
            }
            match rb.send().await {
                Ok(resp) => return Ok(resp),
                // Not reached at all: the next worker may be up. Anything else (a timeout once the
                // request was sent) is not retried: the first worker may already be running it.
                Err(e) if e.is_connect() => last = format!("{base}: {e}"),
                Err(e) => {
                    return Err(RunError::new(
                        StatusCode::BAD_GATEWAY,
                        "upstream_error",
                        Some("worker_error"),
                        format!("{base}: {e}"),
                    ));
                }
            }
        }
        tracing::warn!(error = %last, "no node worker reachable");
        Err(RunError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            Some("no_worker"),
            "no node worker is reachable",
        ))
    }

    /// Forwards a client's request as it is and relays the answer (event streams as they come).
    pub async fn forward(&self, req: Request) -> Response {
        let (parts, body) = req.into_parts();
        let Ok(body) = axum::body::to_bytes(body, crate::MAX_BODY).await else {
            return error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request_error", None, "request body too large");
        };
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
        let stream = parts.uri.path().ends_with("/events")
            || parts
                .headers
                .get(header::ACCEPT)
                .is_some_and(|a| a.to_str().is_ok_and(|a| a.contains("text/event-stream")))
            || serde_json::from_slice::<Value>(&body).is_ok_and(|v| v["stream"] == true);
        let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
        match self.try_workers(method, &path, &parts.headers, &[], Some(body), stream).await {
            Ok(resp) => relay(resp).await,
            Err(e) => e.into_response(),
        }
    }
}

async fn relay(resp: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = Response::builder().status(status);
    for name in
        ["content-type", "location", idempotency::REPLAYED, "retry-after", crate::runs::RUN_ID_HEADER, "cache-control"]
    {
        if let Some(v) = resp.headers().get(name)
            && let (Ok(n), Ok(v)) = (HeaderName::try_from(name), HeaderValue::from_bytes(v.as_bytes()))
        {
            out = out.header(n, v);
        }
    }
    let sse = resp.headers().get(header::CONTENT_TYPE).is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"));
    let body = if sse {
        Body::from_stream(resp.bytes_stream().map(|r| r.map_err(std::io::Error::other)))
    } else {
        Body::from(resp.bytes().await.unwrap_or_default())
    };
    out.body(body).unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

/// A worker's HTTP surface: the run API (requests must carry the worker token, as routers send
/// it), `/healthz` and `/metrics`. Workers do not serve the inference API.
pub fn worker_app(gw: Arc<Gateway>, token: String) -> Router {
    let token = Arc::new(token);
    let guarded = crate::runs::routes().route_layer(axum::middleware::from_fn(move |mut req: Request, next: Next| {
        let token = Arc::clone(&token);
        async move {
            let ok = req
                .headers()
                .get(WORKER_TOKEN_HEADER)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|t| !token.is_empty() && constant_time_eq(t.as_bytes(), token.as_bytes()));
            if ok {
                req.extensions_mut().insert(crate::runs::FromRouter);
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
