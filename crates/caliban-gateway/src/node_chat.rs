//! Nodes behind the chat APIs: `model: "node/<name>"` (or `"node/<name>@v<N>"` for a published
//! version) on `/v1/chat/completions` and `/v1/messages` runs the node, so existing OpenAI and
//! Anthropic SDK users need no new client. `caliban/auto` hands requests to nodes through the same
//! path (`crate::pipeline`).
//!
//! - **Input**: the conversation's messages, mapped to the node's input as
//!   [`caliban_nodes::chat`] says (the node's input schema, else the last user message's text).
//! - **Answer**: the node's output as the assistant message (text as is, other JSON compact).
//!   `finish_reason` (OpenAI) / `stop_reason` (Anthropic): `stop` / `end_turn` when the run
//!   succeeded, `length` / `max_tokens` when it ended on its budget (partial output), and
//!   `input_required` when it waits for a human: the question is the assistant message.
//! - **The run**: `Caliban-Run-Id` response header, and a `caliban` object in the body (`run_id`,
//!   `status`, `node`, `version`, `awaiting`, `cost_usd`) that the SDKs keep as an extra field.
//! - **Continuing** a run that waits for a human: send the next request with header
//!   `Caliban-Run-Id: <run id>` and the answer as the last user message (JSON objects, booleans and
//!   numbers are passed as JSON, anything else as text). The response is the rest of the run.
//! - **Usage** is the sum of the run's model calls so far.
//! - **Streams** (`"stream": true`): a first chunk carrying the run id, comments (OpenAI) or
//!   `ping` events (Anthropic) while steps run, then the answer as a content delta and the finish
//!   reason, in the client's dialect.
//! - A run that fails or is cancelled is an error (`502 node_run_failed`, `409 node_run_cancelled`);
//!   a non-streaming request whose run is still going after `CALIBAN_NODE_SYNC_WAIT_SECS` answers
//!   `504 node_run_timeout` (the run continues; follow it with `GET /v1/runs/{id}`).

use crate::Gateway;
use crate::error::Dialect;
use crate::runs::{Caller, Events, RUN_ID_HEADER, RunError, Runs, Start, final_run};
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use caliban_ir::ChatRequest;
use caliban_nodes::chat::{answer_from_text, output_text};
use futures::StreamExt;
use serde_json::{Value, json};
use std::sync::Arc;

/// Response header naming the path a request took: `node/<name>@v<N>`, or `model:<id>` when
/// `caliban/auto` answered with a model.
pub const ROUTE_HEADER: &str = "x-caliban-route";
/// Why `caliban/auto` did not hand the request to a node (when the tenant maps intents to nodes).
pub const ROUTE_FALLBACK_HEADER: &str = "x-caliban-route-fallback";

/// A node a chat request names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub name: String,
    pub version: Option<u32>,
}

/// `node/<name>` or `node/<name>@v<N>`; `None` for any other model.
pub(crate) fn parse_target(model: &str) -> Option<Result<Target, String>> {
    let rest = model.strip_prefix("node/")?;
    let (name, version) = match rest.split_once('@') {
        None => (rest, None),
        Some((n, v)) => match v.strip_prefix('v').and_then(|v| v.parse::<u32>().ok()) {
            Some(v) => (n, Some(v)),
            None => return Some(Err(format!("model '{model}': the version is written @v<N>, e.g. node/{n}@v3"))),
        },
    };
    if name.is_empty() {
        return Some(Err("model 'node/': name the node, e.g. node/triage".into()));
    }
    Some(Ok(Target { name: name.to_owned(), version }))
}

/// The error of a node chat request, in the client's dialect.
pub(crate) fn dialect_error(dialect: Dialect, e: RunError) -> Response {
    match dialect {
        Dialect::OpenAi => e.into_response(),
        Dialect::Anthropic => {
            let kind = match e.status {
                StatusCode::UNAUTHORIZED => "authentication_error",
                StatusCode::FORBIDDEN => "permission_error",
                StatusCode::NOT_FOUND => "not_found_error",
                StatusCode::TOO_MANY_REQUESTS => "rate_limit_error",
                s if s.is_client_error() => "invalid_request_error",
                _ => "api_error",
            };
            (e.status, axum::Json(caliban_ir::anthropic::error_body(kind, &e.message))).into_response()
        }
    }
}

fn bad(message: impl Into<String>) -> RunError {
    RunError::new(StatusCode::BAD_REQUEST, "invalid_request_error", Some("invalid_request"), message)
}

/// The chat handlers' entry: `Some(response)` when the request names a node.
pub(crate) async fn maybe_handle(
    gw: &Arc<Gateway>,
    headers: &HeaderMap,
    body: &Bytes,
    dialect: Dialect,
    internal: bool,
) -> Option<Response> {
    // Cheap test first: most chat requests do not name a node.
    if !body.windows(6).any(|w| w == b"\"node/") {
        return None;
    }
    let v: Value = serde_json::from_slice(body).ok()?;
    let target = parse_target(v.get("model")?.as_str()?)?;
    Some(match handle(gw, headers, &v, dialect, internal, target).await {
        Ok(r) => r,
        Err(e) => dialect_error(dialect, e),
    })
}

async fn handle(
    gw: &Arc<Gateway>,
    headers: &HeaderMap,
    v: &Value,
    dialect: Dialect,
    internal: bool,
    target: Result<Target, String>,
) -> Result<Response, RunError> {
    if internal {
        return Err(bad("a node's model calls cannot run nodes: use a node:// tool or a subnode vertex"));
    }
    let target = target.map_err(bad)?;
    let caller = Caller::from_headers(gw, headers)?;
    if !caller.may_run(&target.name) {
        return Err(crate::runs::forbidden_node(&target.name));
    }
    let req = parse_chat(v, dialect)?;
    let runs = Runs::of(gw).ok_or_else(crate::runs::not_enabled)?;
    respond(
        &runs,
        &caller,
        headers,
        &req,
        dialect,
        NodeChat { target, origin: None, check_spend: false, headers: vec![] },
    )
    .await
}

pub(crate) fn parse_chat(v: &Value, dialect: Dialect) -> Result<ChatRequest, RunError> {
    match dialect {
        Dialect::OpenAi => ChatRequest::from_openai_json(&serde_json::to_vec(v).unwrap_or_default())
            .map_err(|e| bad(format!("invalid request: {e}"))),
        Dialect::Anthropic => {
            caliban_ir::anthropic::to_chat_request(v).map_err(|e| bad(format!("invalid request: {e}")))
        }
    }
}

/// How a chat request runs a node.
pub(crate) struct NodeChat {
    pub target: Target,
    /// `auto:<intent>` when `caliban/auto` chose the node.
    pub origin: Option<String>,
    /// Refuse (`node_over_budget`) rather than start a run the tenant's spend caps leave no room for.
    pub check_spend: bool,
    /// Extra response headers (routing facts).
    pub headers: Vec<(HeaderName, String)>,
}

/// Starts (or continues, with `Caliban-Run-Id`) a run for a chat request and answers in the
/// client's dialect. An error before anything is sent is returned as is (so `caliban/auto` can
/// fall back to a model).
pub(crate) async fn respond(
    runs: &Runs<'_>,
    caller: &Caller,
    auth: &HeaderMap,
    req: &ChatRequest,
    dialect: Dialect,
    nc: NodeChat,
) -> Result<Response, RunError> {
    let continued = auth.get(RUN_ID_HEADER).and_then(|v| v.to_str().ok()).map(str::trim).filter(|v| !v.is_empty());
    let (run_id, version, events) = match continued {
        Some(id) => {
            let text = req
                .last_user_text()
                .filter(|t| !t.trim().is_empty())
                .ok_or_else(|| bad("continuing a run: put the answer in the last user message"))?;
            let (before, ev) = runs.answer(caller, auth, id, Some(&nc.target.name), answer_from_text(&text)).await?;
            (id.to_owned(), before["version"].as_u64().and_then(|v| u32::try_from(v).ok()).unwrap_or_default(), ev)
        }
        None => {
            let messages: Vec<Value> =
                req.messages.iter().map(|m| json!({"role": m.role, "content": m.content})).collect();
            let start = Start {
                node: nc.target.name.clone(),
                version: nc.target.version,
                chat: Some(messages),
                origin: nc.origin.clone(),
                check_spend: nc.check_spend,
                ..Start::default()
            };
            runs.start(caller, auth, start).await?
        }
    };
    let mut extra = nc.headers;
    if let Ok(v) = HeaderValue::from_str(&run_id) {
        extra.push((HeaderName::from_static(RUN_ID_HEADER), v.to_str().unwrap_or_default().to_owned()));
    }
    if req.stream {
        let usage = dialect == Dialect::Anthropic || crate::metering::client_wants_stream_usage(&req.extra);
        let label = format!("node/{}@v{version}", nc.target.name);
        return Ok(stream(events, dialect, run_id, label, usage, extra));
    }
    let wait = runs.sync_wait();
    let run = match tokio::time::timeout(wait, last_run(events)).await {
        Ok(r) => r.map_err(|m| RunError::new(StatusCode::BAD_GATEWAY, "upstream_error", Some("node_run_error"), m))?,
        Err(_) => {
            return Err(RunError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "timeout_error",
                Some("node_run_timeout"),
                format!(
                    "run {run_id} is still going after {} s; it continues: follow it with GET /v1/runs/{run_id}",
                    wait.as_secs()
                ),
            ));
        }
    };
    ended_badly(&run)?;
    let body = match dialect {
        Dialect::OpenAi => openai_body(&run),
        Dialect::Anthropic => anthropic_body(&run),
    };
    let mut resp = (StatusCode::OK, axum::Json(body)).into_response();
    add_headers(resp.headers_mut(), &run, extra);
    Ok(resp)
}

/// Waits for the event that carries the run's final state.
async fn last_run(mut events: Events) -> Result<Value, String> {
    while let Some(e) = events.next().await {
        if e["type"] == "error" {
            return Err(e["data"]["message"].as_str().unwrap_or("the run's events failed").to_owned());
        }
        if let Some(r) = final_run(&e) {
            return Ok(r.clone());
        }
    }
    Err("the run's event stream ended before the run did".into())
}

/// Failed and cancelled runs are errors.
fn ended_badly(run: &Value) -> Result<(), RunError> {
    let id = run["id"].as_str().unwrap_or_default();
    match run["status"].as_str() {
        Some("failed") => Err(RunError::new(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            Some("node_run_failed"),
            format!("node run {id} failed: {}", run["error"].as_str().unwrap_or("no detail")),
        )),
        Some("cancelled") => Err(RunError::new(
            StatusCode::CONFLICT,
            "invalid_request_error",
            Some("node_run_cancelled"),
            format!("node run {id} was cancelled"),
        )),
        _ => Ok(()),
    }
}

fn add_headers(h: &mut HeaderMap, run: &Value, extra: Vec<(HeaderName, String)>) {
    let mut set = |n: HeaderName, v: &str| {
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(n, v);
        }
    };
    set(HeaderName::from_static(ROUTE_HEADER), &label(run));
    if let Some(s) = run["status"].as_str() {
        set(HeaderName::from_static("x-caliban-run-status"), s);
    }
    for (n, v) in extra {
        set(n, &v);
    }
}

/// `node/<name>@v<N>`.
pub(crate) fn label(run: &Value) -> String {
    format!("node/{}@v{}", run["node"].as_str().unwrap_or_default(), run["version"].as_u64().unwrap_or_default())
}

/// The assistant's text and the OpenAI finish reason of a run that stopped.
fn answer(run: &Value) -> (String, &'static str) {
    match run["status"].as_str() {
        Some("input_required") => {
            (run["awaiting"]["question"].as_str().unwrap_or_default().to_owned(), "input_required")
        }
        Some("budget_exhausted") => (output_text(&run["output"]), "length"),
        _ => (output_text(&run["output"]), "stop"),
    }
}

fn anthropic_reason(openai: &str) -> &'static str {
    match openai {
        "input_required" => "input_required",
        "length" => "max_tokens",
        _ => "end_turn",
    }
}

/// The `caliban` object of a response.
fn caliban_field(run: &Value) -> Value {
    let mut c = json!({
        "run_id": run["id"],
        "status": run["status"],
        "node": run["node"],
        "version": run["version"],
        "cost_usd": run["cost_usd"],
    });
    if let Some(a) = run.get("awaiting").filter(|a| a.is_object()) {
        c["awaiting"] = json!({"step": a["step"]});
    }
    if let Some(s) = run.get("stop_reason").filter(|s| s.is_string()) {
        c["stop_reason"] = s.clone();
    }
    c
}

fn usage(run: &Value) -> (u64, u64) {
    (run["usage"]["prompt_tokens"].as_u64().unwrap_or(0), run["usage"]["completion_tokens"].as_u64().unwrap_or(0))
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn openai_body(run: &Value) -> Value {
    let (text, finish) = answer(run);
    let (p, c) = usage(run);
    json!({
        "id": format!("chatcmpl-{}", run["id"].as_str().unwrap_or_default()),
        "object": "chat.completion",
        "created": now(),
        "model": label(run),
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": finish}],
        "usage": {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c},
        "caliban": caliban_field(run),
    })
}

fn anthropic_body(run: &Value) -> Value {
    let (text, finish) = answer(run);
    let (p, c) = usage(run);
    json!({
        "id": format!("msg_{}", run["id"].as_str().unwrap_or_default()),
        "type": "message",
        "role": "assistant",
        "model": label(run),
        "content": [{"type": "text", "text": text}],
        "stop_reason": anthropic_reason(finish),
        "stop_sequence": null,
        "usage": {"input_tokens": p, "output_tokens": c},
        "caliban": caliban_field(run),
    })
}

/// The streamed answer: the run id first, keep-alives while steps run, then the answer.
fn stream(
    events: Events,
    dialect: Dialect,
    run_id: String,
    label: String,
    include_usage: bool,
    extra: Vec<(HeaderName, String)>,
) -> Response {
    let id = match dialect {
        Dialect::OpenAi => format!("chatcmpl-{run_id}"),
        Dialect::Anthropic => format!("msg_{run_id}"),
    };
    let created = now();
    let chunk = {
        let (id, label) = (id.clone(), label.clone());
        move |delta: Value, finish: Value, extra: Option<(&str, Value)>| {
            let mut c = json!({"id": id, "object": "chat.completion.chunk", "created": created, "model": label,
                               "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]});
            if let Some((k, v)) = extra {
                c[k] = v;
            }
            format!("data: {c}\n\n")
        }
    };
    let first = match dialect {
        Dialect::OpenAi => chunk(
            json!({"role": "assistant", "content": ""}),
            Value::Null,
            Some(("caliban", json!({"run_id": run_id}))),
        ),
        Dialect::Anthropic => caliban_ir::anthropic::sse_event(&json!({
            "type": "message_start",
            "message": {"id": id, "type": "message", "role": "assistant", "model": label, "content": [],
                        "stop_reason": null, "stop_sequence": null, "usage": {"input_tokens": 0, "output_tokens": 0},
                        "caliban": {"run_id": run_id}}
        })),
    };
    let error = move |message: &str| match dialect {
        Dialect::OpenAi => format!("data: {}\n\n", json!({"error": {"message": message, "type": "upstream_error"}})),
        Dialect::Anthropic => {
            caliban_ir::anthropic::sse_event(&caliban_ir::anthropic::error_body("api_error", message))
        }
    };
    let rid = run_id.clone();
    let body = futures::stream::once(async move { first })
        .chain(
            futures::stream::unfold((events, false), move |(mut events, done)| {
                let (chunk, rid) = (chunk.clone(), rid.clone());
                async move {
                    if done {
                        return None;
                    }
                    let Some(e) = events.next().await else {
                        let msg = format!("the run's events ended early; follow run {rid} with GET /v1/runs/{rid}");
                        return Some((error(&msg), (events, true)));
                    };
                    if e["type"] == "error" {
                        let m = e["data"]["message"].as_str().unwrap_or("the run's events failed").to_owned();
                        return Some((error(&m), (events, true)));
                    }
                    let Some(run) = final_run(&e).cloned() else {
                        // Keep the connection alive while steps run.
                        let note = match dialect {
                            Dialect::OpenAi => format!(
                                ": {} {}\n\n",
                                e["type"].as_str().unwrap_or("event"),
                                e["data"]["step"].as_str().unwrap_or_default()
                            ),
                            Dialect::Anthropic => caliban_ir::anthropic::sse_event(&json!({"type": "ping"})),
                        };
                        return Some((note, (events, false)));
                    };
                    if let Err(err) = ended_badly(&run) {
                        return Some((error(&err.message), (events, true)));
                    }
                    let (text, finish) = answer(&run);
                    let (p, c) = usage(&run);
                    let out = match dialect {
                        Dialect::OpenAi => {
                            let mut s = chunk(json!({"content": text}), Value::Null, None);
                            s.push_str(&chunk(json!({}), json!(finish), Some(("caliban", caliban_field(&run)))));
                            if include_usage {
                                let mut u = serde_json::from_str::<Value>(
                                    chunk(json!({}), Value::Null, None).trim_start_matches("data: ").trim(),
                                )
                                .unwrap_or_default();
                                u["choices"] = json!([]);
                                u["usage"] = json!({"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c});
                                s.push_str(&format!("data: {u}\n\n"));
                            }
                            s.push_str("data: [DONE]\n\n");
                            s
                        }
                        Dialect::Anthropic => [
                            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
                            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
                            json!({"type": "content_block_stop", "index": 0}),
                            json!({"type": "message_delta", "delta": {"stop_reason": anthropic_reason(finish), "stop_sequence": null},
                                   "usage": {"input_tokens": p, "output_tokens": c}, "caliban": caliban_field(&run)}),
                            json!({"type": "message_stop"}),
                        ]
                        .iter()
                        .map(caliban_ir::anthropic::sse_event)
                        .collect(),
                    };
                    Some((out, (events, true)))
                }
            }),
        )
        .map(|s| Ok::<_, std::io::Error>(Bytes::from(s)));
    let mut resp = Response::new(Body::from_stream(body));
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    if let Ok(v) = HeaderValue::from_str(&label) {
        h.insert(ROUTE_HEADER, v);
    }
    for (n, v) in extra {
        if let Ok(v) = HeaderValue::from_str(&v) {
            h.insert(n, v);
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_models_parse() {
        assert_eq!(parse_target("node/triage"), Some(Ok(Target { name: "triage".into(), version: None })));
        assert_eq!(parse_target("node/triage@v3"), Some(Ok(Target { name: "triage".into(), version: Some(3) })));
        assert!(parse_target("node/triage@3").unwrap().is_err());
        assert!(parse_target("node/").unwrap().is_err());
        assert_eq!(parse_target("caliban/auto"), None);
    }
}
