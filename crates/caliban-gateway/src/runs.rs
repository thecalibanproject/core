//! The run API (P3 M2 and M5), and the run client the chat shortcut, the MCP server and
//! `caliban/auto` use.
//!
//! **Run API** (tenant API keys; the key must be allowed to run the node, see
//! `TenantConfig::key_may_run`):
//! - `POST /v1/nodes/{name}/runs` `{"input": ..., "version"?: N, "async"?: bool, "stream"?: bool,
//!   "wait_s"?: s, "budget"?: {...}}`: sync by default (waits until the run ends or waits for a
//!   human, at most `CALIBAN_NODE_SYNC_WAIT_SECS`, then answers `202` with the run so far);
//!   `"async": true` answers `202` at once; `"stream": true` answers with the run's events (SSE)
//!   until it ends or waits for a human. `Idempotency-Key` returns the run the first request
//!   created.
//! - `GET /v1/runs`: the tenant's runs the key may see (its node allowlist), newest first, with
//!   filters and a cursor.
//! - `GET /v1/runs/{id}`: status, output, awaited question, budget, usage, steps.
//! - `GET /v1/runs/{id}/events`: the run's events (SSE) from the journal, resumable with
//!   `Last-Event-ID` (or `?after=`) on any worker.
//! - `POST /v1/runs/{id}/input` `{"answer": ..., "step"?: id}`: answers a human step.
//! - `POST /v1/runs/{id}/cancel`: cancels the run (durable: a running run stops at its next step
//!   boundary on whichever worker runs it).
//!
//! **Events.** Each SSE event is `id: <n>`, `event: <type>`, `data: {"id", "type", "run_id",
//! "at", "data", "run"?}`. Types: `run.created`, `step.started`, `step.finished` (vertex, kind,
//! status, tokens, cost so far, taint labels; never step content), `run.input_required` (the
//! question), `run.sleeping`, `run.input_received`, `run.cancel_requested`, `run.finished`. The
//! last event of a stream (`run.finished`, or `run.input_required` while the run waits) carries the
//! run as `GET /v1/runs/{id}` shows it, in `run`.

use crate::auth;
use crate::nodes::{Forwarder, LocalRuns, NodeRuns};
use crate::{Gateway, idempotency};
use axum::Router;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use caliban_nodes::executor::{ExecError, Executor, RunBudget, RunSummary, RunView, StartRun, render_event};
use caliban_nodes::journal::{Cancelled, Delivered, RunQuery, RunStatus, event};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use futures::stream::BoxStream;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The run a response is about (chat shortcut, streams): readable by SDKs from the headers.
pub const RUN_ID_HEADER: &str = "caliban-run-id";
/// Internal (router to worker, never from clients): what started the run (`auto:<intent>`).
pub(crate) const ORIGIN_HEADER: &str = "x-caliban-run-origin";
/// Internal (router to worker): refuse the run with `429 node_over_budget` when the tenant's
/// spend caps leave no room for it, instead of creating it.
pub(crate) const CHECK_SPEND_HEADER: &str = "x-caliban-check-spend";

/// Set on requests that carried the worker token (a router's): only those may use the internal
/// headers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FromRouter;

// ───────────────────────────── errors ─────────────────────────────

/// A run error as the run API answers it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RunError {
    pub status: StatusCode,
    pub kind: &'static str,
    pub code: Option<String>,
    pub message: String,
}

impl RunError {
    pub(crate) fn new(status: StatusCode, kind: &'static str, code: Option<&str>, message: impl Into<String>) -> Self {
        Self { status, kind, code: code.map(str::to_owned), message: message.into() }
    }
}

impl IntoResponse for RunError {
    fn into_response(self) -> Response {
        let body = json!({"error": {"message": self.message, "type": self.kind, "code": self.code}});
        (self.status, axum::Json(body)).into_response()
    }
}

pub(crate) fn error(
    status: StatusCode,
    kind: &'static str,
    code: Option<&str>,
    message: impl Into<String>,
) -> Response {
    RunError::new(status, kind, code, message).into_response()
}

pub(crate) fn exec_error(e: ExecError) -> RunError {
    match e {
        ExecError::NotFound(m) => RunError::new(StatusCode::NOT_FOUND, "not_found", Some("node_not_found"), m),
        ExecError::Invalid(m) => {
            RunError::new(StatusCode::BAD_REQUEST, "invalid_request_error", Some("invalid_input"), m)
        }
        ExecError::KeyReused => RunError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_request_error",
            Some("idempotency_key_reused"),
            "this Idempotency-Key was used for a different run request",
        ),
        ExecError::Conflict(m) => RunError::new(StatusCode::CONFLICT, "invalid_request_error", None, m),
        ExecError::OverBudget(m) => {
            RunError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limit_error", Some("node_over_budget"), m)
        }
        ExecError::Internal(m) => {
            tracing::error!(error = %m, "node run error");
            RunError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", None, "node run error")
        }
    }
}

pub(crate) fn unauthenticated() -> RunError {
    RunError::new(StatusCode::UNAUTHORIZED, "authentication_error", None, "invalid or missing API key")
}

pub(crate) fn not_enabled() -> RunError {
    RunError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        Some("nodes_not_enabled"),
        "node runs are not enabled on this data plane (standalone needs CALIBAN_KEK; split-mode routers need CALIBAN_WORKER_URLS)",
    )
}

pub(crate) fn forbidden_node(name: &str) -> RunError {
    RunError::new(
        StatusCode::FORBIDDEN,
        "permission_error",
        Some("node_not_allowed"),
        format!("this API key may not run node '{name}'"),
    )
}

fn run_not_found() -> RunError {
    RunError::new(StatusCode::NOT_FOUND, "not_found", Some("run_not_found"), "run not found")
}

/// `api_key:<first 12 hex characters of the key's hash>`: who did something, in the journal and
/// the audit log.
pub(crate) fn key_actor(key_hash: &str) -> String {
    format!("api_key:{}", &key_hash[..key_hash.len().min(12)])
}

// ───────────────────────────── the caller ─────────────────────────────

/// An authenticated caller of the run API.
#[derive(Debug, Clone)]
pub(crate) struct Caller {
    pub tenant: String,
    pub key_hash: String,
    /// The node allowlist of the key (`None`: every node).
    pub nodes: Option<Vec<String>>,
}

impl Caller {
    pub(crate) fn from_headers(gw: &Gateway, headers: &HeaderMap) -> Result<Self, RunError> {
        let snap = gw.config.load();
        let c = auth::caller(&snap, headers).map_err(|_| unauthenticated())?;
        Ok(Self {
            tenant: c.tenant.id.to_string(),
            nodes: c.tenant.api_key_nodes.get(&c.key_hash).cloned(),
            key_hash: c.key_hash,
        })
    }

    pub(crate) fn may_run(&self, node: &str) -> bool {
        self.nodes.as_ref().is_none_or(|n| n.iter().any(|x| x == node))
    }

    pub(crate) fn actor(&self) -> String {
        key_actor(&self.key_hash)
    }
}

// ───────────────────────────── following a run ─────────────────────────────

/// A run's rendered events, as the SSE stream carries them (see the module docs).
pub(crate) type Events = BoxStream<'static, Value>;

/// The events of a run executed by `ex`'s journal after `after`, until the run ends or waits for a
/// human (or `deadline`). Events written by this process wake the stream at once; others are seen
/// at the next poll.
pub(crate) fn follow(
    ex: Arc<Executor>,
    tenant: String,
    run_id: String,
    after: u64,
    deadline: Option<Instant>,
) -> Events {
    struct St {
        ex: Arc<Executor>,
        tenant: String,
        run_id: String,
        cursor: u64,
        queue: VecDeque<Value>,
        done: bool,
        deadline: Option<Instant>,
    }
    const PAGE: usize = 200;
    impl St {
        /// Reads what is new; `false` when nothing was.
        async fn fetch(&mut self) -> Result<bool, String> {
            let evs = self.ex.events(&self.tenant, &self.run_id, self.cursor, PAGE).await.map_err(|e| e.to_string())?;
            let n = evs.len();
            for (i, e) in evs.iter().enumerate() {
                self.cursor = e.seq;
                let mut v = render_event(self.ex.sealer().as_ref(), &self.tenant, e, true);
                let last = i + 1 == n && n < PAGE;
                let end = match e.kind.as_str() {
                    event::RUN_FINISHED => true,
                    event::RUN_INPUT_REQUIRED if last => true,
                    _ => false,
                };
                if end {
                    let view = self.ex.view(&self.tenant, &self.run_id).await.map_err(|e| e.to_string())?;
                    // Still waiting for this question (not answered meanwhile): the stream ends here.
                    let still = view.as_ref().is_some_and(|r| {
                        r.status.is_terminal() || (r.status == RunStatus::InputRequired && r.last_event == e.seq)
                    });
                    if still {
                        v["run"] = json!(view);
                        self.queue.push_back(v);
                        self.done = true;
                        return Ok(true);
                    }
                }
                self.queue.push_back(v);
            }
            Ok(n > 0)
        }
    }
    let st = St { ex, tenant, run_id, cursor: after, queue: VecDeque::new(), done: false, deadline };
    futures::stream::unfold(st, |mut st| async move {
        loop {
            if let Some(v) = st.queue.pop_front() {
                return Some((v, st));
            }
            if st.done {
                return None;
            }
            let ex = Arc::clone(&st.ex);
            let written = ex.event_written();
            tokio::pin!(written);
            written.as_mut().enable();
            match st.fetch().await {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => {
                    st.done = true;
                    return Some((json!({"type": "error", "run_id": st.run_id, "data": {"message": e}}), st));
                }
            }
            if st.deadline.is_some_and(|d| Instant::now() >= d) {
                return None;
            }
            let wait = st.deadline.map_or(ex.poll_interval(), |d| ex.poll_interval().min(d - Instant::now()));
            tokio::select! {
                () = &mut written => {}
                () = tokio::time::sleep(wait) => {}
            }
        }
    })
    .boxed()
}

/// The SSE response of a run's events.
fn sse(events: Events, run_id: &str) -> Response {
    let stream = events.map(|v| {
        let mut e = Event::default().data(v.to_string());
        if let Some(id) = v.get("id").and_then(Value::as_u64) {
            e = e.id(id.to_string());
        }
        if let Some(t) = v.get("type").and_then(Value::as_str) {
            e = e.event(t);
        }
        Ok::<_, std::convert::Infallible>(e)
    });
    let mut resp = Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))).into_response();
    if let Ok(v) = HeaderValue::from_str(run_id) {
        resp.headers_mut().insert(RUN_ID_HEADER, v);
    }
    resp
}

/// The run a stream ended with (`run` of its last event), if it ended with one.
pub(crate) fn final_run(ev: &Value) -> Option<&Value> {
    ev.get("run").filter(|r| r.is_object())
}

// ───────────────────────────── the run client ─────────────────────────────

/// Where this data plane's runs go: executed here, or forwarded to workers. The chat shortcut,
/// the MCP server and `caliban/auto` go through it, so they work the same in standalone and split
/// mode.
pub(crate) enum Runs<'a> {
    Local(&'a LocalRuns),
    Forward(&'a Forwarder),
}

/// What a client of [`Runs::start`] asks for.
#[derive(Debug, Clone, Default)]
pub(crate) struct Start {
    pub node: String,
    pub version: Option<u32>,
    pub input: Value,
    /// Chat messages mapped to the node's input by the executor (instead of `input`).
    pub chat: Option<Vec<Value>>,
    pub budget: Option<RunBudget>,
    pub origin: Option<String>,
    pub check_spend: bool,
}

impl<'a> Runs<'a> {
    pub(crate) fn of(gw: &'a Gateway) -> Option<Self> {
        Some(match gw.nodes()? {
            NodeRuns::Local(l) => Runs::Local(l),
            NodeRuns::Forward(f) => Runs::Forward(f),
        })
    }

    /// The longest a synchronous caller waits (chat without streaming, MCP `tools/call`).
    pub(crate) fn sync_wait(&self) -> Duration {
        match self {
            Runs::Local(l) => l.sync_wait,
            Runs::Forward(f) => f.sync_wait(),
        }
    }

    /// Starts a run as `caller` (`auth`: the client's authentication headers, for a worker) and
    /// follows its events. Returns the run id and the version it runs.
    pub(crate) async fn start(
        &self,
        caller: &Caller,
        auth: &HeaderMap,
        s: Start,
    ) -> Result<(String, u32, Events), RunError> {
        match self {
            Runs::Local(l) => {
                let start = StartRun {
                    tenant: caller.tenant.clone(),
                    node: s.node,
                    version: s.version,
                    input: s.input,
                    chat: s.chat,
                    invoker: caller.actor(),
                    invoker_key_hash: Some(caller.key_hash.clone()),
                    idempotency: None,
                    budget: s.budget,
                    origin: s.origin,
                    check_spend: s.check_spend,
                };
                let (run, _) = l.executor.create(start).await.map_err(exec_error)?;
                if run.status == RunStatus::Pending {
                    l.executor.spawn_run(run.id.clone());
                }
                let ev = follow(Arc::clone(&l.executor), caller.tenant.clone(), run.id.clone(), 0, None);
                Ok((run.id, run.version, ev))
            }
            Runs::Forward(f) => {
                let mut body = json!({"input": s.input, "stream": true});
                if let Some(m) = s.chat {
                    body["chat"] = json!({"messages": m});
                    body.as_object_mut().map(|o| o.remove("input"));
                }
                if let Some(v) = s.version {
                    body["version"] = json!(v);
                }
                if let Some(b) = s.budget {
                    body["budget"] =
                        json!({"steps": b.steps, "tokens": b.tokens, "usd": b.usd, "wall_clock_s": b.wall_clock_s});
                }
                let mut extra = vec![];
                if let Some(o) = &s.origin {
                    extra.push((ORIGIN_HEADER, o.clone()));
                }
                if s.check_spend {
                    extra.push((CHECK_SPEND_HEADER, "true".to_owned()));
                }
                let path = format!("/v1/nodes/{}/runs", s.node);
                let resp = f.send(reqwest::Method::POST, &path, auth, &extra, Some(body.to_string()), true).await?;
                let h = |n: &str| resp.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
                let run_id = h(RUN_ID_HEADER);
                let version = h(crate::node_chat::ROUTE_HEADER)
                    .rsplit_once("@v")
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or_default();
                Ok((run_id, version, worker_events(resp)))
            }
        }
    }

    /// The run as `GET /v1/runs/{id}` shows it.
    pub(crate) async fn view(&self, caller: &Caller, auth: &HeaderMap, run_id: &str) -> Result<Value, RunError> {
        match self {
            Runs::Local(l) => {
                let v = l.executor.view(&caller.tenant, run_id).await.map_err(exec_error)?.ok_or_else(run_not_found)?;
                if !caller.may_run(&v.node) {
                    return Err(forbidden_node(&v.node));
                }
                Ok(json!(v))
            }
            Runs::Forward(f) => {
                let resp = f.send(reqwest::Method::GET, &format!("/v1/runs/{run_id}"), auth, &[], None, false).await?;
                resp.json().await.map_err(|e| {
                    RunError::new(StatusCode::BAD_GATEWAY, "upstream_error", Some("worker_error"), e.to_string())
                })
            }
        }
    }

    /// Cancels a run the caller may see.
    pub(crate) async fn cancel(&self, caller: &Caller, auth: &HeaderMap, run_id: &str) -> Result<(), RunError> {
        match self {
            Runs::Local(l) => {
                self.view(caller, auth, run_id).await?;
                l.executor.cancel(&caller.tenant, run_id, &caller.actor()).await.map_err(exec_error)?;
                Ok(())
            }
            Runs::Forward(f) => f
                .send(reqwest::Method::POST, &format!("/v1/runs/{run_id}/cancel"), auth, &[], Some("{}".into()), false)
                .await
                .map(|_| ()),
        }
    }

    /// Answers the human step the run waits for and follows the events that come after. With
    /// `node`, the run must be a run of that node.
    pub(crate) async fn answer(
        &self,
        caller: &Caller,
        auth: &HeaderMap,
        run_id: &str,
        node: Option<&str>,
        answer: Value,
    ) -> Result<(Value, Events), RunError> {
        let before = self.deliver(caller, auth, run_id, node, answer).await?;
        // Every event the answer causes comes after the run's last event before it.
        let after = before["last_event"].as_u64().unwrap_or(0);
        match self {
            Runs::Local(l) => {
                let ev = follow(Arc::clone(&l.executor), caller.tenant.clone(), run_id.to_owned(), after, None);
                Ok((before, ev))
            }
            Runs::Forward(f) => {
                let path = format!("/v1/runs/{run_id}/events?after={after}");
                let resp = f.send(reqwest::Method::GET, &path, auth, &[], None, true).await?;
                Ok((before, worker_events(resp)))
            }
        }
    }

    /// Answers the human step the run waits for; returns the run as it was just before.
    pub(crate) async fn deliver(
        &self,
        caller: &Caller,
        auth: &HeaderMap,
        run_id: &str,
        node: Option<&str>,
        answer: Value,
    ) -> Result<Value, RunError> {
        let before = self.view(caller, auth, run_id).await?;
        if let Some(n) = node
            && before["node"].as_str() != Some(n)
        {
            return Err(RunError::new(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                Some("run_of_another_node"),
                format!("run {run_id} is a run of node '{}', not '{n}'", before["node"].as_str().unwrap_or_default()),
            ));
        }
        let not_waiting = || {
            RunError::new(
                StatusCode::CONFLICT,
                "invalid_request_error",
                Some("run_not_awaiting_input"),
                format!(
                    "run {run_id} is not waiting for input (status {})",
                    before["status"].as_str().unwrap_or("unknown")
                ),
            )
        };
        if before["status"] != "input_required" {
            return Err(not_waiting());
        }
        match self {
            Runs::Local(l) => {
                let by = caller.actor();
                match l
                    .executor
                    .deliver_input(&caller.tenant, run_id, None, &answer, Some(&by))
                    .await
                    .map_err(exec_error)?
                {
                    Delivered::Accepted => l.executor.spawn_run(run_id.to_owned()),
                    Delivered::NotAwaiting => return Err(not_waiting()),
                    Delivered::NotFound => return Err(run_not_found()),
                }
            }
            Runs::Forward(f) => {
                let body = json!({"answer": answer}).to_string();
                f.send(reqwest::Method::POST, &format!("/v1/runs/{run_id}/input"), auth, &[], Some(body), false)
                    .await?;
            }
        }
        Ok(before)
    }
}

/// A worker's SSE answer as rendered events.
fn worker_events(resp: reqwest::Response) -> Events {
    let mut parser = caliban_ir::sse::SseParser::default();
    resp.bytes_stream()
        .flat_map(move |chunk| {
            let out: Vec<Value> = match chunk {
                Ok(b) => parser.push(&b).iter().filter_map(|d| serde_json::from_str(d).ok()).collect(),
                Err(e) => {
                    vec![json!({"type": "error", "data": {"message": format!("reading the worker's events: {e}")}})]
                }
            };
            futures::stream::iter(out)
        })
        .boxed()
}

// ───────────────────────────── handlers ─────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunCreate {
    #[serde(default)]
    input: Value,
    /// Chat messages instead of `input`, mapped to the node's input (see `caliban_nodes::chat`).
    chat: Option<ChatInput>,
    version: Option<u32>,
    #[serde(default, rename = "async")]
    is_async: bool,
    /// Answer with the run's events (SSE) until it ends or waits for a human.
    #[serde(default)]
    stream: bool,
    /// Wait at most this long (seconds) for a sync run; capped by the server.
    wait_s: Option<f64>,
    /// Lowers the version's budget for this run (`steps`, `tokens`, `usd`, `wall_clock_s`).
    budget: Option<RunBudget>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatInput {
    messages: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunInput {
    answer: Value,
    step: Option<String>,
}

fn view_response(status: StatusCode, v: &RunView, replayed: bool) -> Response {
    let mut resp = (status, axum::Json(v)).into_response();
    if let Ok(loc) = HeaderValue::from_str(&format!("/v1/runs/{}", v.id)) {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    if let Ok(id) = HeaderValue::from_str(&v.id) {
        resp.headers_mut().insert(RUN_ID_HEADER, id);
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

fn local(gw: &Gateway) -> Result<&LocalRuns, RunError> {
    match gw.nodes() {
        None => Err(not_enabled()),
        Some(NodeRuns::Forward(_)) => {
            Err(RunError::new(StatusCode::MISDIRECTED_REQUEST, "invalid_request_error", None, ""))
        }
        Some(NodeRuns::Local(l)) => Ok(l),
    }
}

async fn create_run(State(gw): State<Arc<Gateway>>, Path(name): Path<String>, req: Request) -> Response {
    let caller = match Caller::from_headers(&gw, req.headers()) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !caller.may_run(&name) {
        return forbidden_node(&name).into_response();
    }
    let runs = match gw.nodes() {
        None => return not_enabled().into_response(),
        Some(NodeRuns::Forward(f)) => return f.forward(req).await,
        Some(NodeRuns::Local(l)) => l,
    };
    let internal = req.extensions().get::<FromRouter>().is_some();
    let headers = req.headers().clone();
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
    let header = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let start = StartRun {
        tenant: caller.tenant.clone(),
        node: name,
        version: rc.version,
        input: rc.input,
        chat: rc.chat.map(|c| c.messages),
        invoker: caller.actor(),
        invoker_key_hash: Some(caller.key_hash.clone()),
        idempotency,
        budget: rc.budget,
        origin: if internal { header(ORIGIN_HEADER) } else { None },
        check_spend: internal && header(CHECK_SPEND_HEADER).as_deref() == Some("true"),
    };
    let (run, new) = match runs.executor.create(start).await {
        Ok(x) => x,
        Err(e) => return exec_error(e).into_response(),
    };
    if rc.stream {
        if run.status == RunStatus::Pending {
            runs.executor.spawn_run(run.id.clone());
        }
        let ev = follow(Arc::clone(&runs.executor), caller.tenant, run.id.clone(), 0, None);
        let mut resp = sse(ev, &run.id);
        if let Ok(v) = HeaderValue::from_str(&format!("node/{}@v{}", run.node, run.version)) {
            resp.headers_mut().insert(crate::node_chat::ROUTE_HEADER, v);
        }
        if let Ok(loc) = HeaderValue::from_str(&format!("/v1/runs/{}", run.id)) {
            resp.headers_mut().insert(header::LOCATION, loc);
        }
        if !new {
            resp.headers_mut().insert(idempotency::REPLAYED, HeaderValue::from_static("true"));
        }
        return resp;
    }
    if !rc.is_async {
        if run.status == RunStatus::Pending {
            runs.executor.spawn_run(run.id.clone());
        }
        let wait = rc.wait_s.map_or(runs.sync_wait, |s| Duration::from_secs_f64(s.max(0.0))).min(runs.sync_wait);
        if let Err(e) = runs.executor.wait(&caller.tenant, &run.id, Instant::now() + wait).await {
            return exec_error(e).into_response();
        }
    }
    match runs.executor.view(&caller.tenant, &run.id).await {
        Ok(Some(v)) => view_response(if rc.is_async { StatusCode::ACCEPTED } else { run_status(&v) }, &v, !new),
        Ok(None) => exec_error(ExecError::Internal("the run vanished".into())).into_response(),
        Err(e) => exec_error(e).into_response(),
    }
}

/// The caller and the run, for the routes on an existing run.
async fn existing<'a>(
    gw: &'a Gateway,
    headers: &HeaderMap,
    id: &str,
) -> Result<(&'a LocalRuns, RunView, Caller), RunError> {
    let caller = Caller::from_headers(gw, headers)?;
    let runs = local(gw)?;
    let v = runs.executor.view(&caller.tenant, id).await.map_err(exec_error)?.ok_or_else(run_not_found)?;
    if !caller.may_run(&v.node) {
        return Err(forbidden_node(&v.node));
    }
    Ok((runs, v, caller))
}

async fn get_run(State(gw): State<Arc<Gateway>>, Path(id): Path<String>, req: Request) -> Response {
    if let Some(NodeRuns::Forward(f)) = gw.nodes() {
        return forward_authenticated(&gw, f, req).await;
    }
    match existing(&gw, req.headers(), &id).await {
        Ok((_, v, _)) => view_response(StatusCode::OK, &v, false),
        Err(r) => r.into_response(),
    }
}

async fn run_input(State(gw): State<Arc<Gateway>>, Path(id): Path<String>, req: Request) -> Response {
    if let Some(NodeRuns::Forward(f)) = gw.nodes() {
        return forward_authenticated(&gw, f, req).await;
    }
    let (runs, _, caller) = match existing(&gw, req.headers(), &id).await {
        Ok(x) => x,
        Err(r) => return r.into_response(),
    };
    let Ok(body) = axum::body::to_bytes(req.into_body(), crate::MAX_BODY).await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request_error", None, "request body too large");
    };
    let input: RunInput = match serde_json::from_slice(&body) {
        Ok(i) => i,
        Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", None, format!("invalid body: {e}")),
    };
    // Who answered: journaled with the answer and audited (approvals of tainted writes included).
    let by = caller.actor();
    match runs.executor.deliver_input(&caller.tenant, &id, input.step.as_deref(), &input.answer, Some(&by)).await {
        Ok(Delivered::Accepted) => {
            // Resumed here at once (another worker would pick it up at its next poll).
            runs.executor.spawn_run(id.clone());
            match runs.executor.view(&caller.tenant, &id).await {
                Ok(Some(v)) => view_response(StatusCode::ACCEPTED, &v, false),
                Ok(None) => run_not_found().into_response(),
                Err(e) => exec_error(e).into_response(),
            }
        }
        Ok(Delivered::NotAwaiting) => error(
            StatusCode::CONFLICT,
            "invalid_request_error",
            Some("run_not_awaiting_input"),
            "the run is not waiting for input (or not for this step)",
        ),
        Ok(Delivered::NotFound) => run_not_found().into_response(),
        Err(e) => exec_error(e).into_response(),
    }
}

async fn cancel_run(State(gw): State<Arc<Gateway>>, Path(id): Path<String>, req: Request) -> Response {
    if let Some(NodeRuns::Forward(f)) = gw.nodes() {
        return forward_authenticated(&gw, f, req).await;
    }
    let (runs, _, caller) = match existing(&gw, req.headers(), &id).await {
        Ok(x) => x,
        Err(r) => return r.into_response(),
    };
    let status = match runs.executor.cancel(&caller.tenant, &id, &caller.actor()).await {
        Ok(Cancelled::Ended | Cancelled::AlreadyEnded(RunStatus::Cancelled)) => StatusCode::OK,
        Ok(Cancelled::Requested) => StatusCode::ACCEPTED,
        Ok(Cancelled::AlreadyEnded(s)) => {
            return error(
                StatusCode::CONFLICT,
                "invalid_request_error",
                Some("run_already_ended"),
                format!("the run already ended ({})", s.as_str()),
            );
        }
        Ok(Cancelled::NotFound) => return run_not_found().into_response(),
        Err(e) => return exec_error(e).into_response(),
    };
    match runs.executor.view(&caller.tenant, &id).await {
        Ok(Some(v)) => view_response(status, &v, false),
        Ok(None) => run_not_found().into_response(),
        Err(e) => exec_error(e).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct EventsQuery {
    after: Option<u64>,
}

async fn run_events(
    State(gw): State<Arc<Gateway>>,
    Path(id): Path<String>,
    Query(q): Query<EventsQuery>,
    req: Request,
) -> Response {
    if let Some(NodeRuns::Forward(f)) = gw.nodes() {
        return forward_authenticated(&gw, f, req).await;
    }
    let (runs, _, caller) = match existing(&gw, req.headers(), &id).await {
        Ok(x) => x,
        Err(r) => return r.into_response(),
    };
    // `Last-Event-ID` (an SSE client reconnecting) wins over `?after=`.
    let last = req.headers().get("last-event-id").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok());
    let after = last.or(q.after).unwrap_or(0);
    sse(follow(Arc::clone(&runs.executor), caller.tenant, id.clone(), after, None), &id)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    node: Option<String>,
    /// Comma-separated statuses.
    status: Option<String>,
    created_after: Option<DateTime<Utc>>,
    created_before: Option<DateTime<Utc>>,
    limit: Option<usize>,
    cursor: Option<String>,
}

/// The page cursor: the last run of a page, as `<created_at in ns>_<run id>`.
pub fn encode_cursor(at: DateTime<Utc>, id: &str) -> String {
    format!("{}_{id}", at.timestamp_nanos_opt().unwrap_or_default())
}

pub fn decode_cursor(c: &str) -> Option<(DateTime<Utc>, String)> {
    let (ns, id) = c.split_once('_')?;
    Some((DateTime::from_timestamp_nanos(ns.parse().ok()?), id.to_owned()))
}

/// A run listing query from `?node=&status=&created_after=&created_before=&limit=&cursor=`
/// (shared with the control plane).
pub fn run_query(
    tenant: &str,
    nodes: Option<Vec<String>>,
    node: Option<String>,
    status: Option<&str>,
    created: (Option<DateTime<Utc>>, Option<DateTime<Utc>>),
    limit: Option<usize>,
    cursor: Option<&str>,
) -> Result<RunQuery, String> {
    let statuses = match status {
        None => vec![],
        Some(s) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| RunStatus::parse(s).ok_or_else(|| format!("unknown status '{s}'")))
            .collect::<Result<_, _>>()?,
    };
    let before = match cursor {
        None => None,
        Some(c) => Some(decode_cursor(c).ok_or("invalid cursor")?),
    };
    Ok(RunQuery {
        tenant: tenant.to_owned(),
        nodes,
        node,
        statuses,
        created_after: created.0,
        created_before: created.1,
        before,
        limit: limit.unwrap_or(50).clamp(1, 200),
    })
}

async fn list_runs(State(gw): State<Arc<Gateway>>, req: Request) -> Response {
    if let Some(NodeRuns::Forward(f)) = gw.nodes() {
        return forward_authenticated(&gw, f, req).await;
    }
    let caller = match Caller::from_headers(&gw, req.headers()) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let runs = match local(&gw) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let q: ListQuery = match Query::try_from_uri(req.uri()) {
        Ok(Query(q)) => q,
        Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", None, e.body_text()),
    };
    let query = match run_query(
        &caller.tenant,
        caller.nodes.clone(),
        q.node,
        q.status.as_deref(),
        (q.created_after, q.created_before),
        q.limit,
        q.cursor.as_deref(),
    ) {
        Ok(q) => q,
        Err(e) => return error(StatusCode::BAD_REQUEST, "invalid_request_error", None, e),
    };
    match runs.executor.list(&query).await {
        Ok(page) => {
            let next =
                (page.len() == query.limit).then(|| page.last().map(|r| encode_cursor(r.created_at, &r.id))).flatten();
            let data: Vec<RunSummary> = page.iter().map(RunSummary::of).collect();
            axum::Json(json!({"object": "list", "data": data, "next_cursor": next})).into_response()
        }
        Err(e) => exec_error(e).into_response(),
    }
}

/// Routers authenticate the API key before forwarding (workers check it again, and the node
/// allowlist against the run).
pub(crate) async fn forward_authenticated(gw: &Gateway, f: &Forwarder, req: Request) -> Response {
    if auth::caller(&gw.config.load(), req.headers()).is_err() {
        return unauthenticated().into_response();
    }
    f.forward(req).await
}

/// The run routes (merged into the data-plane app and the worker app).
pub(crate) fn routes() -> Router<Arc<Gateway>> {
    Router::new()
        .route("/v1/nodes/{name}/runs", post(create_run))
        .route("/v1/runs", get(list_runs))
        .route("/v1/runs/{id}", get(get_run))
        .route("/v1/runs/{id}/input", post(run_input))
        .route("/v1/runs/{id}/cancel", post(cancel_run))
        .route("/v1/runs/{id}/events", get(run_events))
}
