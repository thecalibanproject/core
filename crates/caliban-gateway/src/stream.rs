//! Streaming responses (request lifecycle stages 11–13).
//!
//! - [`openai_shaped`]: an OpenAI-chunk upstream stream (OpenAI-compatible servers, or Anthropic
//!   translated by the provider adapter). Inline `<think>` is split and surrogates are restored
//!   with hold-back buffers, then the chunks are re-encoded for the client: OpenAI chunks, or
//!   Anthropic events (`message_start`, `content_block_*`, `message_delta`, `message_stop`).
//! - [`native_anthropic`]: an Anthropic event stream passed through to an Anthropic client, with
//!   surrogates restored per content block (`text_delta`, `thinking_delta`, `input_json_delta`).
//!
//! Both end by metering the request and settling its quota reservation, also when the client
//! disconnects (dropping the upstream stream cancels the provider request).

use crate::error::Dialect;
use crate::pipeline::{Outcome, caliban_headers, finish};
use crate::quirks::{self, ThinkSplitter};
use crate::{Gateway, telemetry};
use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use caliban_ir::Usage;
use caliban_ir::anthropic::{self, AnthropicUsage, OpenAiToAnthropicStream};
use caliban_ir::sse::SseParser;
use caliban_meter::quota::Settlement;
use caliban_pii::{Rehydrator, StreamingRehydrator};
use caliban_providers::ProviderError;
use futures::StreamExt;
use futures::stream::BoxStream;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{Instrument, Span};

type Upstream = BoxStream<'static, Result<Bytes, ProviderError>>;

fn sse_response(o: &Outcome, rx: mpsc::Receiver<Result<Bytes, std::io::Error>>) -> Response {
    let mut resp = Response::new(Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)));
    *resp.status_mut() = StatusCode::OK;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    caliban_headers(h, o);
    resp
}

/// Re-encodes (already rewritten) OpenAI chunks in the client's dialect.
enum Encoder {
    OpenAi,
    Anthropic(Box<OpenAiToAnthropicStream>),
}

impl Encoder {
    fn new(dialect: Dialect, model: &str) -> Self {
        match dialect {
            Dialect::OpenAi => Encoder::OpenAi,
            Dialect::Anthropic => Encoder::Anthropic(Box::new(OpenAiToAnthropicStream::new(model))),
        }
    }

    fn chunk(&mut self, v: &Value) -> String {
        match self {
            Encoder::OpenAi => format!("data: {v}\n\n"),
            Encoder::Anthropic(t) => t.push(v).iter().map(anthropic::sse_event).collect(),
        }
    }

    /// Upstream data that is not JSON: passed through to OpenAI clients, dropped otherwise.
    fn raw(&mut self, data: &str) -> String {
        match self {
            Encoder::OpenAi => format!("data: {data}\n\n"),
            Encoder::Anthropic(_) => String::new(),
        }
    }

    fn done(&mut self, usage: Usage) -> String {
        match self {
            Encoder::OpenAi => "data: [DONE]\n\n".to_owned(),
            Encoder::Anthropic(t) => t.finish(usage).iter().map(anthropic::sse_event).collect(),
        }
    }

    fn error(&mut self, message: &str) -> String {
        match self {
            Encoder::OpenAi => {
                let err = json!({"error": {"message": message, "type": "upstream_error"}});
                format!("data: {err}\n\n")
            }
            Encoder::Anthropic(t) => t.error(message).iter().map(anthropic::sse_event).collect(),
        }
    }
}

/// Per-choice streaming state: optional `<think>` splitter and one rehydrator per text field.
#[derive(Default)]
struct ChoiceState {
    think: Option<ThinkSplitter>,
    content: Option<StreamingRehydrator>,
    reasoning: Option<StreamingRehydrator>,
    reasoning_key: Option<&'static str>,
}

impl ChoiceState {
    fn new(rh: Option<&Arc<Rehydrator>>, think: bool) -> Self {
        Self {
            think: think.then(ThinkSplitter::default),
            content: rh.map(|r| r.streaming()),
            reasoning: rh.map(|r| r.streaming()),
            reasoning_key: None,
        }
    }

    /// Processes one delta; returns `(reasoning, content)` to emit.
    fn push(&mut self, reasoning_in: Option<&str>, content_in: Option<&str>, finished: bool) -> (String, String) {
        let mut reasoning = reasoning_in.unwrap_or_default().to_owned();
        let mut content = content_in.unwrap_or_default().to_owned();
        if let Some(t) = &mut self.think {
            let (r, c) = t.push(&content);
            reasoning.push_str(&r);
            content = c;
            if finished {
                let (r, c) = t.finish();
                reasoning.push_str(&r);
                content.push_str(&c);
            }
        }
        if let Some(st) = &mut self.reasoning {
            reasoning = st.push(&reasoning);
            if finished {
                reasoning.push_str(&st.finish());
            }
        }
        if let Some(st) = &mut self.content {
            content = st.push(&content);
            if finished {
                content.push_str(&st.finish());
            }
        }
        (reasoning, content)
    }

    fn flush(&mut self) -> (String, String) {
        self.push(None, None, true)
    }
}

/// Splits inline `<think>` and restores surrogates in streamed deltas, holding back text that may
/// be a partial tag or surrogate. TODO: tool-call argument deltas.
fn transform_chunk(v: &mut Value, choices: &mut BTreeMap<u64, ChoiceState>, rh: Option<&Arc<Rehydrator>>, think: bool) {
    let Some(list) = v.get_mut("choices").and_then(Value::as_array_mut) else { return };
    for c in list {
        let idx = c.get("index").and_then(Value::as_u64).unwrap_or(0);
        let finished = c.get("finish_reason").is_some_and(|f| !f.is_null());
        let st = choices.entry(idx).or_insert_with(|| ChoiceState::new(rh, think));
        let delta = c.as_object_mut().map(|o| o.entry("delta").or_insert_with(|| Value::Object(Map::new())));
        let Some(delta) = delta.and_then(Value::as_object_mut) else { continue };
        let rkey = quirks::reasoning_key(delta);
        if delta.contains_key(rkey) {
            st.reasoning_key = Some(rkey);
        }
        let content_in = delta.get("content").and_then(Value::as_str).map(str::to_owned);
        let reasoning_in = delta.get(rkey).and_then(Value::as_str).map(str::to_owned);
        let (r, content) = st.push(reasoning_in.as_deref(), content_in.as_deref(), finished);
        if content_in.is_some() || !content.is_empty() {
            delta.insert("content".into(), Value::String(content));
        }
        if reasoning_in.is_some() || !r.is_empty() {
            let key = st.reasoning_key.unwrap_or("reasoning_content");
            delta.insert(key.into(), Value::String(r));
        }
    }
}

/// Output text bytes in a chunk (content, reasoning, tool arguments), for usage estimates.
fn delta_bytes(v: &Value) -> u64 {
    let mut n = 0;
    for c in v.get("choices").and_then(Value::as_array).into_iter().flatten() {
        let Some(d) = c.get("delta") else { continue };
        for k in ["content", "reasoning_content", "reasoning"] {
            n += d.get(k).and_then(Value::as_str).map_or(0, str::len);
        }
        for tc in d.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
            n += tc.pointer("/function/arguments").and_then(Value::as_str).map_or(0, str::len);
        }
    }
    n as u64
}

/// Flushes held-back text of every choice, then ends the stream in the client's dialect.
fn tail(choices: &mut BTreeMap<u64, ChoiceState>, last_id: &Value, model_id: &str, enc: &mut Encoder, usage: Usage) -> String {
    let mut out = String::new();
    for (idx, st) in choices.iter_mut() {
        let (r, c) = st.flush();
        if r.is_empty() && c.is_empty() {
            continue;
        }
        let mut delta = Map::new();
        if !r.is_empty() {
            delta.insert(st.reasoning_key.unwrap_or("reasoning_content").into(), Value::String(r));
        }
        if !c.is_empty() {
            delta.insert("content".into(), Value::String(c));
        }
        let chunk = json!({
            "id": last_id, "object": "chat.completion.chunk", "model": model_id,
            "choices": [{"index": idx, "delta": delta, "finish_reason": null}]
        });
        out.push_str(&enc.chunk(&chunk));
    }
    out.push_str(&enc.done(usage));
    out
}

pub(crate) fn openai_shaped(
    gw: Arc<Gateway>,
    outcome: Outcome,
    mut upstream: Upstream,
    rehydrator: Option<Arc<Rehydrator>>,
    think: bool,
    mut settlement: Settlement,
    upstream_span: Span,
) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let resp = sse_response(&outcome, rx);
    let model_id = outcome.model.id.to_string();
    let transform = rehydrator.is_some() || think;
    let span = outcome.span.clone();
    settlement.set_in_flight(true);

    let task = async move {
        let mut parser = SseParser::default();
        let mut choices: BTreeMap<u64, ChoiceState> = BTreeMap::new();
        let mut enc = Encoder::new(outcome.dialect, &model_id);
        let mut usage = Usage::default();
        let mut last_chunk_id = Value::Null;
        let mut streamed = 0u64;
        let (mut ended, mut client_gone) = (false, false);
        'outer: while let Some(item) = upstream.next().await {
            let bytes = match item {
                Ok(b) => b,
                Err(e) => {
                    telemetry::record_error(&upstream_span, e.kind());
                    let _ = tx.send(Ok(Bytes::from(enc.error(&e.to_string())))).await;
                    ended = true;
                    break;
                }
            };
            for data in parser.push(&bytes) {
                let out = if data == "[DONE]" {
                    ended = true;
                    tail(&mut choices, &last_chunk_id, &model_id, &mut enc, usage)
                } else {
                    match serde_json::from_str::<Value>(&data) {
                        Ok(mut v) => {
                            if let Some(u) = Usage::from_openai(&v) {
                                usage = u;
                            }
                            if let Some(m) = v.get("model").and_then(Value::as_str) {
                                upstream_span.record("gen_ai.response.model", m);
                            }
                            last_chunk_id = v.get("id").cloned().unwrap_or(Value::Null);
                            if v.get("model").is_some() {
                                v["model"] = Value::String(model_id.clone());
                            }
                            if transform {
                                transform_chunk(&mut v, &mut choices, rehydrator.as_ref(), think);
                            }
                            streamed += delta_bytes(&v);
                            enc.chunk(&v)
                        }
                        Err(_) => enc.raw(&data),
                    }
                };
                if !out.is_empty() && tx.send(Ok(Bytes::from(out))).await.is_err() {
                    // Client went away: dropping `upstream` cancels the provider request.
                    tracing::info!(request_id = %outcome.request_id, "client disconnected mid-stream");
                    client_gone = true;
                    break 'outer;
                }
                if ended {
                    break 'outer;
                }
            }
        }
        if !ended && !client_gone {
            // Upstream closed without `[DONE]`: flush held-back text and end the message properly.
            let _ = tx.send(Ok(Bytes::from(tail(&mut choices, &last_chunk_id, &model_id, &mut enc, usage)))).await;
        }
        drop(tx);
        drop(upstream);
        telemetry::record_usage(&upstream_span, usage);
        drop(upstream_span);
        finish(&gw, &outcome, usage, 0, settlement, streamed).await;
    };
    tokio::spawn(task.instrument(span));
    resp
}

/// Per-block rehydration state for native Anthropic streams.
struct BlockState {
    delta_type: String,
    field: &'static str,
    rehydrator: StreamingRehydrator,
}

pub(crate) fn native_anthropic(
    gw: Arc<Gateway>,
    outcome: Outcome,
    mut upstream: Upstream,
    rehydrator: Option<Arc<Rehydrator>>,
    mut settlement: Settlement,
    upstream_span: Span,
) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let resp = sse_response(&outcome, rx);
    let model_id = outcome.model.id.to_string();
    let span = outcome.span.clone();
    settlement.set_in_flight(true);

    let task = async move {
        let mut parser = SseParser::default();
        let mut usage = AnthropicUsage::default();
        let mut blocks: HashMap<u64, BlockState> = HashMap::new();
        let mut streamed = 0u64;
        'outer: while let Some(item) = upstream.next().await {
            let bytes = match item {
                Ok(b) => b,
                Err(e) => {
                    telemetry::record_error(&upstream_span, e.kind());
                    let ev = anthropic::error_body("api_error", &e.to_string());
                    let _ = tx.send(Ok(Bytes::from(anthropic::sse_event(&ev)))).await;
                    break;
                }
            };
            for data in parser.push(&bytes) {
                let mut out = String::new();
                match serde_json::from_str::<Value>(&data) {
                    Err(_) => out.push_str(&format!("data: {data}\n\n")),
                    Ok(mut ev) => {
                        usage.observe(&ev);
                        let index = ev.get("index").and_then(Value::as_u64).unwrap_or(0);
                        match ev.get("type").and_then(Value::as_str) {
                            Some("message_start") => {
                                if let Some(m) = ev.pointer_mut("/message/model") {
                                    if let Some(up) = m.as_str() {
                                        upstream_span.record("gen_ai.response.model", up);
                                    }
                                    *m = Value::String(model_id.clone());
                                }
                            }
                            Some("content_block_delta") => {
                                let delta_type = ev.pointer("/delta/type").and_then(Value::as_str).unwrap_or_default().to_owned();
                                let field = match delta_type.as_str() {
                                    "text_delta" => Some("text"),
                                    "thinking_delta" => Some("thinking"),
                                    "input_json_delta" => Some("partial_json"),
                                    _ => None,
                                };
                                if let Some(field) = field
                                    && let Some(Value::String(s)) = ev.get_mut("delta").and_then(|d| d.get_mut(field))
                                {
                                    streamed += s.len() as u64;
                                    if let Some(rh) = &rehydrator {
                                        let st = blocks
                                            .entry(index)
                                            .or_insert_with(|| BlockState { delta_type: delta_type.clone(), field, rehydrator: rh.streaming() });
                                        *s = st.rehydrator.push(s);
                                        if s.is_empty() {
                                            continue; // everything held back for now
                                        }
                                    }
                                }
                            }
                            Some("content_block_stop") => {
                                if let Some(mut st) = blocks.remove(&index) {
                                    let rest = st.rehydrator.finish();
                                    if !rest.is_empty() {
                                        let mut delta = Map::new();
                                        delta.insert("type".into(), Value::String(st.delta_type));
                                        delta.insert(st.field.into(), Value::String(rest));
                                        out.push_str(&anthropic::sse_event(&json!({"type": "content_block_delta", "index": index, "delta": delta})));
                                    }
                                }
                            }
                            _ => {}
                        }
                        out.push_str(&anthropic::sse_event(&ev));
                    }
                }
                if tx.send(Ok(Bytes::from(out))).await.is_err() {
                    tracing::info!(request_id = %outcome.request_id, "client disconnected mid-stream");
                    break 'outer;
                }
            }
        }
        drop(tx);
        drop(upstream);
        let usage = usage.usage();
        telemetry::record_usage(&upstream_span, usage);
        drop(upstream_span);
        finish(&gw, &outcome, usage, 0, settlement, streamed).await;
    };
    tokio::spawn(task.instrument(span));
    resp
}
