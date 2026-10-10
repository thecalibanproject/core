//! Streaming responses (request lifecycle stages 11–13).
//!
//! - [`openai_shaped`]: an OpenAI-chunk upstream stream (OpenAI-compatible servers, or Anthropic
//!   translated by the provider adapter). Inline `<think>` is split and surrogates are restored
//!   with hold-back buffers, then the chunks are re-encoded for the client: OpenAI chunks, or
//!   Anthropic events (`message_start`, `content_block_*`, `message_delta`, `message_stop`).
//! - [`native_anthropic`]: an Anthropic event stream passed through to an Anthropic client, with
//!   surrogates restored per content block (`text_delta`, `thinking_delta`, `input_json_delta`).
//!
//! Chunks whose text needs no change go out as the upstream sent them, with only the model name
//! rewritten byte-wise (see [`crate::passthrough`]); the rest take the general `Value` path.
//!
//! Both end by metering the request and settling its quota reservation, also when the client
//! disconnects (dropping the upstream stream cancels the provider request).

use crate::error::Dialect;
use crate::metering;
use crate::pipeline::{Outcome, caliban_headers, finish};
use crate::quirks::{self, ThinkSplitter};
use crate::semantic::StreamCapture;
use crate::{Gateway, passthrough, telemetry};
use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use bytes::{BufMut, BytesMut};
use caliban_ir::Usage;
use caliban_ir::anthropic::{self, AnthropicUsage, OpenAiToAnthropicStream};
use caliban_ir::sse::SseParser;
use caliban_meter::quota::Settlement;
use caliban_pii::{Rehydrator, StreamingRehydrator};
use caliban_providers::ProviderError;
use futures::StreamExt;
use futures::stream::BoxStream;
use serde_json::{Map, Value, json};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::task::Poll;
use tokio::sync::mpsc;
use tracing::{Instrument, Span};

type Upstream = BoxStream<'static, Result<Bytes, ProviderError>>;

/// Initial capacity of a stream's output buffer. Batches are split off it, so consecutive
/// batches share one allocation until it is used up.
const BATCH_CAPACITY: usize = 16 * 1024;
/// Upper bound for one body frame: ready upstream reads are merged up to this size.
const MAX_BATCH: usize = 64 * 1024;

#[cfg(test)]
thread_local! {
    /// Test switch: take the general path for every chunk (see the equivalence tests below).
    static FORCE_GENERAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the byte-level passthrough may be used (always, outside tests).
fn passthrough_enabled() -> bool {
    #[cfg(test)]
    return !FORCE_GENERAL.with(std::cell::Cell::get);
    #[cfg(not(test))]
    true
}

/// Compact JSON into `out` (no intermediate `String`).
fn write_json(out: &mut BytesMut, v: &Value) {
    // Writing a `Value` into memory cannot fail.
    let _ = serde_json::to_writer(out.writer(), v);
}

/// `event: <type>\ndata: <json>\n\n`, as [`anthropic::sse_event`], into `out`.
fn write_sse_event(out: &mut BytesMut, ev: &Value) {
    out.extend_from_slice(b"event: ");
    out.extend_from_slice(ev.get("type").and_then(Value::as_str).unwrap_or("message").as_bytes());
    out.extend_from_slice(b"\ndata: ");
    write_json(out, ev);
    out.extend_from_slice(b"\n\n");
}

/// How long a stream's response headers wait for its first frame. Sent together, headers and
/// first frame leave in one write, so with Nagle on (`CALIBAN_TCP_NODELAY=0`) the first token
/// cannot wait for the client's delayed ACK of a headers-only segment. An upstream that is slower
/// than this to send its first event gets its headers first, as before.
const FIRST_FRAME_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// A streamed body, returned once its first frame is ready (or after [`FIRST_FRAME_WAIT`]).
pub(crate) async fn body_after_first_frame(mut rx: mpsc::Receiver<Result<Bytes, std::io::Error>>) -> Body {
    let first = tokio::time::timeout(FIRST_FRAME_WAIT, rx.recv()).await.ok().flatten();
    let rest = tokio_stream::wrappers::ReceiverStream::new(rx);
    match first {
        Some(f) => Body::from_stream(futures::stream::once(std::future::ready(f)).chain(rest)),
        None => Body::from_stream(rest),
    }
}

/// Headers of a streamed response, set before the stream task takes the outcome.
fn sse_headers(o: &Outcome) -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    caliban_headers(&mut h, o);
    h
}

/// The streamed response, returned once its first frame is ready (or after [`FIRST_FRAME_WAIT`]).
async fn sse_response(headers: axum::http::HeaderMap, rx: mpsc::Receiver<Result<Bytes, std::io::Error>>) -> Response {
    let mut resp = Response::new(body_after_first_frame(rx).await);
    *resp.status_mut() = StatusCode::OK;
    *resp.headers_mut() = headers;
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

    /// [`Self::chunk`] written straight into the batch buffer.
    fn chunk_into(&mut self, v: &Value, out: &mut BytesMut) {
        match self {
            Encoder::OpenAi => {
                out.extend_from_slice(b"data: ");
                write_json(out, v);
                out.extend_from_slice(b"\n\n");
            }
            Encoder::Anthropic(t) => t.push(v).iter().for_each(|ev| write_sse_event(out, ev)),
        }
    }

    /// Upstream data that is not JSON: passed through to OpenAI clients, dropped otherwise.
    fn raw_into(&mut self, data: &str, out: &mut BytesMut) {
        if let Encoder::OpenAi = self {
            out.extend_from_slice(b"data: ");
            out.extend_from_slice(data.as_bytes());
            out.extend_from_slice(b"\n\n");
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

/// A request's rehydrators: for text, and with JSON-escaped originals for tool-call arguments
/// (which are JSON text themselves).
#[derive(Clone)]
struct Restore {
    text: Arc<Rehydrator>,
    json: Arc<Rehydrator>,
}

impl Restore {
    fn new(rh: Option<&Arc<Rehydrator>>) -> Option<Self> {
        rh.map(|r| Self { text: Arc::clone(r), json: Arc::new(r.for_json()) })
    }
}

/// Per-choice streaming state: optional `<think>` splitter, one rehydrator per text field and one
/// per tool call (by tool-call index) for its argument deltas.
#[derive(Default)]
struct ChoiceState {
    think: Option<ThinkSplitter>,
    content: Option<StreamingRehydrator>,
    reasoning: Option<StreamingRehydrator>,
    reasoning_key: Option<&'static str>,
    json: Option<Arc<Rehydrator>>,
    tools: BTreeMap<u64, StreamingRehydrator>,
}

impl ChoiceState {
    fn new(rh: Option<&Restore>, think: bool) -> Self {
        Self {
            think: think.then(ThinkSplitter::default),
            content: rh.map(|r| r.text.streaming()),
            reasoning: rh.map(|r| r.text.streaming()),
            reasoning_key: None,
            json: rh.map(|r| Arc::clone(&r.json)),
            tools: BTreeMap::new(),
        }
    }

    /// Restores surrogates in the tool-call argument deltas of `delta`, holding back what may be
    /// the start of a surrogate (a surrogate split across deltas is restored whole). When the
    /// choice finishes, what is still held back is appended to this delta's tool calls.
    fn push_tool_args(&mut self, delta: &mut Map<String, Value>, finished: bool) {
        let Some(json) = &self.json else { return };
        if let Some(calls) = delta.get_mut("tool_calls").and_then(Value::as_array_mut) {
            for (pos, tc) in calls.iter_mut().enumerate() {
                let idx = tc.get("index").and_then(Value::as_u64).unwrap_or(pos as u64);
                if let Some(Value::String(a)) = tc.pointer_mut("/function/arguments") {
                    *a = self.tools.entry(idx).or_insert_with(|| json.streaming()).push(a);
                }
            }
        }
        if finished {
            for (idx, rest) in self.flush_tools() {
                append_tool_args(delta, idx, rest);
            }
        }
    }

    /// Held-back argument text of every tool call, by tool-call index (non-empty only).
    fn flush_tools(&mut self) -> Vec<(u64, String)> {
        std::mem::take(&mut self.tools)
            .into_iter()
            .map(|(idx, mut st)| (idx, st.finish()))
            .filter(|(_, rest)| !rest.is_empty())
            .collect()
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

/// Appends `rest` to the arguments of tool call `idx` in `delta` (adding the entry if needed).
fn append_tool_args(delta: &mut Map<String, Value>, idx: u64, rest: String) {
    let calls = delta.entry("tool_calls").or_insert_with(|| Value::Array(Vec::new()));
    if !calls.is_array() {
        *calls = Value::Array(Vec::new());
    }
    let Some(calls) = calls.as_array_mut() else { return };
    let pos = calls.iter().position(|tc| tc.get("index").and_then(Value::as_u64) == Some(idx));
    match pos.map(|p| &mut calls[p]) {
        Some(tc) => {
            if let Some(o) = tc.as_object_mut() {
                let f = o.entry("function").or_insert_with(|| json!({}));
                if let Some(f) = f.as_object_mut() {
                    match f.get_mut("arguments") {
                        Some(Value::String(a)) => a.push_str(&rest),
                        _ => {
                            f.insert("arguments".into(), Value::String(rest));
                        }
                    }
                }
            }
        }
        None => calls.push(json!({"index": idx, "function": {"arguments": rest}})),
    }
}

/// Splits inline `<think>` and restores surrogates in streamed deltas (content, reasoning and
/// tool-call arguments), holding back text that may be a partial tag or surrogate.
fn transform_chunk(v: &mut Value, choices: &mut BTreeMap<u64, ChoiceState>, rh: Option<&Restore>, think: bool) {
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
        set_delta_text(delta, st.reasoning_key, content_in.is_some(), reasoning_in.is_some(), r, content);
        st.push_tool_args(delta, finished);
    }
}

/// Writes the transformed texts back into a delta: a field is set when the upstream sent it or
/// when there is text for it (released hold-back).
fn set_delta_text(
    delta: &mut Map<String, Value>,
    reasoning_key: Option<&'static str>,
    had_content: bool,
    had_reasoning: bool,
    r: String,
    content: String,
) {
    if had_content || !content.is_empty() {
        delta.insert("content".into(), Value::String(content));
    }
    if had_reasoning || !r.is_empty() {
        delta.insert(reasoning_key.unwrap_or("reasoning_content").into(), Value::String(r));
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
fn tail(
    choices: &mut BTreeMap<u64, ChoiceState>,
    last_id: &Value,
    model_id: &str,
    enc: &mut Encoder,
    usage: Usage,
) -> String {
    let mut out = String::new();
    for (idx, st) in choices.iter_mut() {
        let (r, c) = st.flush();
        let tools = st.flush_tools();
        if r.is_empty() && c.is_empty() && tools.is_empty() {
            continue;
        }
        let mut delta = Map::new();
        for (i, rest) in tools {
            append_tool_args(&mut delta, i, rest);
        }
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

#[allow(clippy::too_many_arguments)] // one call site per path; a params struct would only move the list
pub(crate) async fn openai_shaped(
    gw: Arc<Gateway>,
    outcome: Outcome,
    mut upstream: Upstream,
    rehydrator: Option<Arc<Rehydrator>>,
    think: bool,
    mut settlement: Settlement,
    upstream_span: Span,
    mut capture: Option<StreamCapture>,
) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let headers = sse_headers(&outcome);
    let model_id = outcome.model.id.to_string();
    let transform = rehydrator.is_some() || think;
    let restore = Restore::new(rehydrator.as_ref());
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
        let (mut usage_seen, mut errored) = (false, false);
        // Passthrough (see `passthrough`): when nothing in a chunk's text changes, it goes out as
        // received with only `model` replaced, without a `Value` round trip.
        let fast = !transform && capture.is_none() && matches!(enc, Encoder::OpenAi) && passthrough_enabled();
        // With surrogates to restore (no `<think>` splitting), single-choice content deltas are
        // edited in place: only the `content` string is rewritten, and only when it changes.
        let fast_rehydrate = rehydrator.is_some()
            && !think
            && capture.is_none()
            && matches!(enc, Encoder::OpenAi)
            && passthrough_enabled();
        // Raw `id` of the last chunk handled in place (`last_chunk_id` is parsed only on change).
        let mut last_id_raw: Option<String> = None;
        let model_json = serde_json::to_string(&model_id).unwrap_or_default();
        let mut model_recorded = false;
        let mut out = BytesMut::with_capacity(BATCH_CAPACITY);
        let (mut upstream_done, mut sent_any) = (false, false);
        'outer: while let Some(item) = upstream.next().await {
            // Events of one upstream read, and of any further reads already waiting, leave in one
            // write (one channel message, one body frame). Nothing waits for data that has not
            // arrived, so no latency is added.
            let mut item = Some(item);
            while let Some(it) = item.take() {
                let bytes = match it {
                    Ok(b) => b,
                    Err(e) => {
                        telemetry::record_error(&upstream_span, e.kind());
                        out.extend_from_slice(enc.error(&e.to_string()).as_bytes());
                        let _ = tx.send(Ok(out.split().freeze())).await;
                        if let Some(c) = capture.as_mut() {
                            c.abandon();
                        }
                        ended = true;
                        errored = true;
                        break 'outer;
                    }
                };
                parser.push_each(&bytes, |data| {
                    if ended {
                        return;
                    }
                    if data == "[DONE]" {
                        ended = true;
                        out.extend_from_slice(
                            tail(&mut choices, &last_chunk_id, &model_id, &mut enc, usage).as_bytes(),
                        );
                        return;
                    }
                    // Usage chunks take the general path, which owns usage extraction and
                    // stripping. A `"usage": null` member is cut out byte-wise for clients that
                    // did not ask for usage (see `metering::strip_usage`).
                    if fast
                        && let Some(c) = passthrough::scan_openai(data)
                        && !c.usage
                        && (outcome.client_usage || !c.has_usage_key || c.null_usage_member.is_some())
                    {
                        if !model_recorded && let Some(Ok(m)) = c.model_raw.map(serde_json::from_str::<Cow<'_, str>>) {
                            upstream_span.record("gen_ai.response.model", m.as_ref());
                            model_recorded = true;
                        }
                        streamed += c.delta_bytes;
                        passthrough::write_openai(&mut out, data, &c, &model_json, !outcome.client_usage);
                        return;
                    }
                    if fast_rehydrate
                        && let Some(d) = passthrough::scan_openai_delta(data)
                        && d.choice.as_ref().is_none_or(|c| c.tool_bytes == 0)
                        && !d.chunk.usage
                        && (outcome.client_usage || !d.chunk.has_usage_key || d.chunk.null_usage_member.is_some())
                    {
                        if !model_recorded
                            && let Some(Ok(m)) = d.chunk.model_raw.map(serde_json::from_str::<Cow<'_, str>>)
                        {
                            upstream_span.record("gen_ai.response.model", m.as_ref());
                            model_recorded = true;
                        }
                        if last_id_raw.as_deref() != Some(d.id_raw.unwrap_or("null")) {
                            last_chunk_id = d.id_raw.and_then(|r| serde_json::from_str(r).ok()).unwrap_or(Value::Null);
                            last_id_raw = Some(d.id_raw.unwrap_or("null").to_owned());
                        }
                        let Some(ch) = &d.choice else {
                            // No choices: nothing to restore, no output text.
                            passthrough::write_openai(&mut out, data, &d.chunk, &model_json, !outcome.client_usage);
                            return;
                        };
                        let st = choices.entry(ch.index).or_insert_with(|| ChoiceState::new(restore.as_ref(), think));
                        let content_in = ch.content.as_ref().map(|(_, s)| s.as_ref());
                        let (r, content) = st.push(None, content_in, false);
                        streamed += ch.tool_bytes + content.len() as u64;
                        if r.is_empty() && (content_in.is_some() || content.is_empty()) {
                            let replaced = match &ch.content {
                                Some((range, s)) if *s != content => {
                                    Some((range.clone(), serde_json::to_string(&content).unwrap_or_default()))
                                }
                                _ => None,
                            };
                            passthrough::write_openai_with(
                                &mut out,
                                data,
                                &d.chunk,
                                &model_json,
                                !outcome.client_usage,
                                replaced,
                            );
                        } else if let Ok(mut v) = serde_json::from_str::<Value>(data) {
                            // Held-back text released without a field to carry it (never seen in
                            // practice): add the field, as `transform_chunk` would.
                            if v.get("model").is_some() {
                                v["model"] = Value::String(model_id.clone());
                            }
                            if !outcome.client_usage {
                                metering::strip_usage(&mut v);
                            }
                            if let Some(delta) = v.pointer_mut("/choices/0/delta").and_then(Value::as_object_mut) {
                                set_delta_text(delta, st.reasoning_key, content_in.is_some(), false, r, content);
                            }
                            enc.chunk_into(&v, &mut out);
                        }
                        return;
                    }
                    last_id_raw = None;
                    match serde_json::from_str::<Value>(data) {
                        Ok(mut v) => {
                            if let Some(u) = Usage::from_openai(&v) {
                                usage = u;
                                usage_seen = true;
                            }
                            if !model_recorded && let Some(m) = v.get("model").and_then(Value::as_str) {
                                upstream_span.record("gen_ai.response.model", m);
                                model_recorded = true;
                            }
                            last_chunk_id = v.get("id").cloned().unwrap_or(Value::Null);
                            if v.get("model").is_some() {
                                v["model"] = Value::String(model_id.clone());
                            }
                            if let Some(c) = capture.as_mut() {
                                c.openai_chunk(&v);
                            }
                            // Usage is always requested upstream; a client that did not ask gets none.
                            let usage_only = !outcome.client_usage && metering::strip_usage(&mut v);
                            if transform {
                                transform_chunk(&mut v, &mut choices, restore.as_ref(), think);
                            }
                            streamed += delta_bytes(&v);
                            if !usage_only {
                                enc.chunk_into(&v, &mut out);
                            }
                        }
                        Err(_) => enc.raw_into(data, &mut out),
                    }
                });
                // The first bytes leave at once (time to first byte); later reads that are
                // already waiting are merged.
                if ended || out.len() >= MAX_BATCH || !sent_any {
                    break;
                }
                match futures::poll!(upstream.next()) {
                    Poll::Ready(Some(next)) => item = Some(next),
                    Poll::Ready(None) => upstream_done = true,
                    Poll::Pending => {}
                }
            }
            sent_any |= !out.is_empty();
            if !out.is_empty() && tx.send(Ok(out.split().freeze())).await.is_err() {
                // Client went away: dropping `upstream` cancels the provider request.
                tracing::info!(request_id = %outcome.request_id, "client disconnected mid-stream");
                client_gone = true;
                if let Some(c) = capture.as_mut() {
                    c.abandon();
                }
                break 'outer;
            }
            if ended || upstream_done {
                break 'outer;
            }
        }
        if !ended && !client_gone {
            // Upstream closed without `[DONE]`: flush held-back text and end the message properly.
            let _ = tx.send(Ok(Bytes::from(tail(&mut choices, &last_chunk_id, &model_id, &mut enc, usage)))).await;
        }
        drop(tx);
        drop(upstream);
        // Provider usage when the stream ran to completion with a usage report; otherwise
        // estimated (client disconnect, upstream error, no usage sent).
        let complete = usage_seen && !client_gone && !errored;
        let metered = metering::stream_end(usage_seen.then_some(usage), complete, outcome.est_prompt_tokens, streamed);
        telemetry::record_usage(&upstream_span, metered.usage);
        drop(upstream_span);
        if let Some(c) = capture {
            c.finish(usage);
        }
        finish(&gw, &outcome, metered, 0, settlement).await;
    };
    tokio::spawn(task.instrument(span));
    sse_response(headers, rx).await
}

/// Per-block rehydration state for native Anthropic streams.
struct BlockState {
    delta_type: String,
    field: &'static str,
    rehydrator: StreamingRehydrator,
}

pub(crate) async fn native_anthropic(
    gw: Arc<Gateway>,
    outcome: Outcome,
    mut upstream: Upstream,
    rehydrator: Option<Arc<Rehydrator>>,
    mut settlement: Settlement,
    upstream_span: Span,
    mut capture: Option<StreamCapture>,
) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    let headers = sse_headers(&outcome);
    let model_id = outcome.model.id.to_string();
    let span = outcome.span.clone();
    settlement.set_in_flight(true);

    let task = async move {
        let mut parser = SseParser::default();
        let mut usage = AnthropicUsage::default();
        let mut blocks: HashMap<u64, BlockState> = HashMap::new();
        let mut streamed = 0u64;
        // Passthrough (see `passthrough`): without surrogates to restore or a capture, content
        // block events go out as received.
        let fast = rehydrator.is_none() && capture.is_none() && passthrough_enabled();
        let restore = Restore::new(rehydrator.as_ref());
        let mut out = BytesMut::with_capacity(BATCH_CAPACITY);
        let (mut upstream_done, mut sent_any) = (false, false);
        'outer: while let Some(item) = upstream.next().await {
            // One write for this read and any reads already waiting (see `openai_shaped`).
            let mut item = Some(item);
            while let Some(it) = item.take() {
                let bytes = match it {
                    Ok(b) => b,
                    Err(e) => {
                        telemetry::record_error(&upstream_span, e.kind());
                        let ev = anthropic::error_body("api_error", &e.to_string());
                        write_sse_event(&mut out, &ev);
                        let _ = tx.send(Ok(out.split().freeze())).await;
                        if let Some(c) = capture.as_mut() {
                            c.abandon();
                        }
                        break 'outer;
                    }
                };
                parser.push_each(&bytes, |data| {
                    if fast && let Some(ev) = passthrough::scan_anthropic(data) {
                        streamed += ev.delta_bytes;
                        passthrough::write_anthropic(&mut out, data, &ev);
                        return;
                    }
                    let mut ev = match serde_json::from_str::<Value>(data) {
                        Ok(ev) => ev,
                        Err(_) => {
                            out.extend_from_slice(b"data: ");
                            out.extend_from_slice(data.as_bytes());
                            out.extend_from_slice(b"\n\n");
                            return;
                        }
                    };
                    usage.observe(&ev);
                    if let Some(c) = capture.as_mut() {
                        c.anthropic_event(&ev);
                    }
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
                            let delta_type =
                                ev.pointer("/delta/type").and_then(Value::as_str).unwrap_or_default().to_owned();
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
                                if let Some(rh) = &restore {
                                    // `partial_json` is JSON text: originals go in JSON-escaped.
                                    let rh = if field == "partial_json" { &rh.json } else { &rh.text };
                                    let st = blocks.entry(index).or_insert_with(|| BlockState {
                                        delta_type: delta_type.clone(),
                                        field,
                                        rehydrator: rh.streaming(),
                                    });
                                    *s = st.rehydrator.push(s);
                                    if s.is_empty() {
                                        return; // everything held back for now
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
                                    write_sse_event(
                                        &mut out,
                                        &json!({"type": "content_block_delta", "index": index, "delta": delta}),
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                    write_sse_event(&mut out, &ev);
                });
                if out.len() >= MAX_BATCH || !sent_any {
                    break;
                }
                match futures::poll!(upstream.next()) {
                    Poll::Ready(Some(next)) => item = Some(next),
                    Poll::Ready(None) => upstream_done = true,
                    Poll::Pending => {}
                }
            }
            sent_any |= !out.is_empty();
            if !out.is_empty() && tx.send(Ok(out.split().freeze())).await.is_err() {
                tracing::info!(request_id = %outcome.request_id, "client disconnected mid-stream");
                if let Some(c) = capture.as_mut() {
                    c.abandon();
                }
                break 'outer;
            }
            if upstream_done {
                break 'outer;
            }
        }
        drop(tx);
        drop(upstream);
        // `message_start` gives the provider's input and cache tokens, `message_delta` the final
        // output tokens; without the latter (disconnect, error) output is estimated.
        let metered = metering::stream_end(
            usage.has_input().then(|| usage.usage()),
            usage.is_complete(),
            outcome.est_prompt_tokens,
            streamed,
        );
        let usage = usage.usage();
        telemetry::record_usage(&upstream_span, metered.usage);
        drop(upstream_span);
        if let Some(c) = capture {
            c.finish(usage);
        }
        finish(&gw, &outcome, metered, 0, settlement).await;
    };
    tokio::spawn(task.instrument(span));
    sse_response(headers, rx).await
}

#[cfg(test)]
mod tests {
    //! The passthrough and the general path must produce the same client stream: the same events,
    //! each with the same JSON value (key order and escaping may differ), and the same usage.
    use super::*;
    use crate::error::Dialect;
    use caliban_config::{Config, ConfigHandle, Snapshot};
    use caliban_meter::RecentUsage;
    use caliban_types::{CacheStatus, ModelId, RequestId};
    use futures::StreamExt;
    use std::time::Instant;

    /// OpenAI-shaped upstream events (the payload of one `data:` field each).
    const OPENAI: &[&str] = &[
        r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"up-model","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}"#,
        r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"up-model","choices":[{"index":0,"delta":{"content":"héllo 世界 🎉"},"finish_reason":null}],"usage":null}"#,
        r#"{"usage":null,"id":"c1","model":"up-model","choices":[{"index":0,"delta":{"content":"usage first"}}]}"#,
        r#"{"id":"c1","model":"up-model","us\u0061ge":null,"choices":[{"index":0,"delta":{"content":"escaped usage key"}}]}"#,
        r#"{"id":"c1","model":"up-model","choices":[{"index":0,"delta":{"content":"say \"hi\"\\n\n\u00e9\ud83c\udf89 </think>"},"finish_reason":null}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"keys in another order"}}],"model":"up-model","id":"c1"}"#,
        r#"{ "id" : "c1" , "model" : "up-model" , "choices" : [ { "index" : 0 , "delta" : { "content" : "spaced" } } ] }"#,
        r#"{"id":"c1","model":"we\"ird\\mo\u0064el","choices":[{"index":0,"delta":{"content":"escaped model"}}]}"#,
        r#"{"id":"c1","model":null,"choices":[{"index":0,"delta":{"content":"null model"}}]}"#,
        r#"{"id":"c1","choices":[{"index":0,"delta":{"content":"no model"}}]}"#,
        r#"{"id":"c1","model":"up-model","x":1.5e3,"choices":[{"index":0,"delta":{"reasoning_content":"thinking…"}}]}"#,
        r#"{"id":"c1","model":"up-model","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"t1","type":"function","function":{"name":"f","arguments":"{\"q\": \"x\"}"}}]}}]}"#,
        r#"{"id":"c1","model":"up-model","choices":[{"index":0,"delta":{"tool_calls":null,"content":null}}]}"#,
        r#"{"id":"c1","model":"up-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":null}"#,
        r#"{"id":"c1","model":"up-model","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3}}}"#,
        r#"{"error":{"message":"boom \"x\"","type":"server_error"}}"#,
        r#"[1,2]"#,
        r#"not json at all"#,
    ];

    fn openai_upstream_bytes() -> String {
        let mut s = String::from(": keep-alive comment\n\n");
        for (i, d) in OPENAI.iter().enumerate() {
            if i == 3 {
                // A multi-line data field (joined with `\n` by the parser).
                s.push_str("data: {\"id\":\"c1\",\"model\":\"up-model\",\ndata: \"choices\":[{\"index\":0,\"delta\":{\"content\":\"two lines\"}}]}\n\n");
            }
            s.push_str("data: ");
            s.push_str(d);
            s.push_str("\n\n");
        }
        s.push_str("data: [DONE]\n\n");
        s
    }

    const ANTHROPIC: &[(&str, &str)] = &[
        (
            "message_start",
            r#"{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-up","content":[],"usage":{"input_tokens":12,"output_tokens":1,"cache_read_input_tokens":3}}}"#,
        ),
        ("ping", r#"{"type":"ping"}"#),
        (
            "content_block_start",
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}"#,
        ),
        (
            "content_block_delta",
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hmm \"quoted\" é"}}"#,
        ),
        ("content_block_stop", r#"{"type":"content_block_stop","index":0}"#),
        (
            "content_block_start",
            r#"{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}"#,
        ),
        (
            "content_block_delta",
            r#"{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"héllo 世界 🎉\n\u00e9"}}"#,
        ),
        (
            "content_block_delta",
            r#"{"index":1,"delta":{"text":"keys reordered","type":"text_delta"},"type":"content_block_delta"}"#,
        ),
        (
            "content_block_delta",
            r#"{"type":"content\u005fblock_delta","index":1,"delta":{"type":"text_delta","text":"escaped type"}}"#,
        ),
        ("content_block_stop", r#"{"type":"content_block_stop","index":1}"#),
        (
            "content_block_start",
            r#"{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"t1","name":"f","input":{}}}"#,
        ),
        (
            "content_block_delta",
            r#"{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"q\": 1"}}"#,
        ),
        ("content_block_stop", r#"{"type":"content_block_stop","index":2}"#),
        ("message_delta", r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":9}}"#),
        ("message_stop", r#"{"type":"message_stop"}"#),
        ("error", r#"{"type":"error","error":{"type":"overloaded_error","message":"busy \"now\""}}"#),
    ];

    fn anthropic_upstream_bytes() -> String {
        let mut s = String::new();
        for (name, d) in ANTHROPIC {
            s.push_str(&format!("event: {name}\ndata: {d}\n\n"));
        }
        s.push_str("data: not json\n\n");
        s
    }

    /// Splits of the upstream bytes into reads: all at once, per event, and in small pieces
    /// (which also cuts multi-byte characters).
    fn splits(bytes: &str) -> Vec<Vec<Bytes>> {
        let b = bytes.as_bytes();
        let per_event: Vec<Bytes> =
            bytes.split_inclusive("\n\n").map(|e| Bytes::copy_from_slice(e.as_bytes())).collect();
        vec![vec![Bytes::copy_from_slice(b)], per_event, b.chunks(7).map(Bytes::copy_from_slice).collect()]
    }

    fn gateway() -> (Arc<Gateway>, RecentUsage) {
        let toml = r#"
[[models]]
id = "ext/mock"
provider = "p"
upstream_model = "up-model"
trust_tier = "t2_contracted"
"#;
        let usage = RecentUsage::default();
        let cfg = Config::from_toml_str(toml).unwrap();
        (Arc::new(Gateway::new(ConfigHandle::new(Snapshot::new(cfg, "test")), Arc::new(usage.clone()))), usage)
    }

    fn outcome(gw: &Gateway, dialect: Dialect, client_usage: bool) -> Outcome {
        Outcome {
            request_id: RequestId::new(),
            tenant_id: "t".into(),
            model: gw.config.load().model(&ModelId::from("ext/mock")).unwrap().clone(),
            intent: "chat".into(),
            cache: CacheStatus::Miss,
            cache_tier: None,
            pii_entities: 0,
            started: Instant::now(),
            dialect,
            span: Span::none(),
            est_prompt_tokens: 0,
            route: None,
            client_usage,
            node: None,
            auto_fallback: None,
        }
    }

    /// Client-visible events: `(event name, data)`, data as JSON when it parses.
    fn client_events(body: &str) -> Vec<(Option<String>, Result<Value, String>)> {
        body.split("\n\n")
            .filter(|e| !e.is_empty())
            .map(|e| {
                let mut name = None;
                let mut data = None;
                for l in e.lines() {
                    if let Some(n) = l.strip_prefix("event: ") {
                        name = Some(n.to_owned());
                    } else if let Some(d) = l.strip_prefix("data: ") {
                        assert!(data.is_none(), "one data line per event: {e:?}");
                        data = Some(d.to_owned());
                    } else {
                        panic!("unexpected line {l:?}");
                    }
                }
                let data = data.expect("data line");
                (name, serde_json::from_str(&data).map_err(|_| data))
            })
            .collect()
    }

    async fn run(native: bool, general: bool, client_usage: bool, reads: Vec<Bytes>) -> (String, (u64, u64, u64)) {
        run_with(native, general, client_usage, None, reads).await
    }

    async fn run_with(
        native: bool,
        general: bool,
        client_usage: bool,
        rh: Option<Arc<Rehydrator>>,
        reads: Vec<Bytes>,
    ) -> (String, (u64, u64, u64)) {
        FORCE_GENERAL.with(|f| f.set(general));
        let (gw, usage) = gateway();
        let upstream: Upstream = futures::stream::iter(reads.into_iter().map(Ok)).boxed();
        let resp = if native {
            native_anthropic(
                Arc::clone(&gw),
                outcome(&gw, Dialect::Anthropic, true),
                upstream,
                rh,
                Settlement::none(),
                Span::none(),
                None,
            )
            .await
        } else {
            openai_shaped(
                Arc::clone(&gw),
                outcome(&gw, Dialect::OpenAi, client_usage),
                upstream,
                rh,
                false,
                Settlement::none(),
                Span::none(),
                None,
            )
            .await
        };
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        // The usage event is recorded after the body ends.
        let mut ev = None;
        for _ in 0..200 {
            if let Some(e) = usage.snapshot(None, 1).pop() {
                ev = Some(e);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        FORCE_GENERAL.with(|f| f.set(false));
        let ev = ev.expect("usage event recorded");
        (String::from_utf8(body.to_vec()).unwrap(), (ev.prompt_tokens, ev.completion_tokens, ev.cached_prompt_tokens))
    }

    /// The response is handed to hyper only once the first frame is ready, so headers and first
    /// frame leave in one write; a slow upstream gets its headers after `FIRST_FRAME_WAIT`.
    #[tokio::test]
    async fn headers_wait_for_the_first_frame() {
        use axum::body::HttpBody as _;
        for (delay_ms, ready) in [(30u64, true), (400, false)] {
            let (gw, _) = gateway();
            let first = Bytes::from(format!("data: {}\n\ndata: [DONE]\n\n", OPENAI[1]));
            let upstream: Upstream = futures::stream::once(async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                Ok(first)
            })
            .boxed();
            let started = Instant::now();
            let resp = openai_shaped(
                Arc::clone(&gw),
                outcome(&gw, Dialect::OpenAi, false),
                upstream,
                None,
                false,
                Settlement::none(),
                Span::none(),
                None,
            )
            .await;
            let waited = started.elapsed();
            let mut body = resp.into_body();
            let polled = futures::future::poll_fn(|cx| {
                std::task::Poll::Ready(std::pin::Pin::new(&mut body).poll_frame(cx).is_ready())
            })
            .await;
            assert_eq!(polled, ready, "first frame ready with the headers (upstream delay {delay_ms} ms)");
            if ready {
                assert!(waited >= std::time::Duration::from_millis(delay_ms), "{waited:?}");
            } else {
                assert!(waited < std::time::Duration::from_millis(delay_ms), "{waited:?}");
            }
        }
    }

    #[tokio::test]
    async fn openai_passthrough_matches_the_general_path() {
        for client_usage in [true, false] {
            for reads in splits(&openai_upstream_bytes()) {
                let (fast, fast_usage) = run(false, false, client_usage, reads.clone()).await;
                let (general, general_usage) = run(false, true, client_usage, reads).await;
                assert_eq!(client_events(&fast), client_events(&general), "client_usage={client_usage}");
                assert_eq!(fast_usage, general_usage);
                assert_eq!(fast_usage, (11, 7, 3), "metered either way");
                let evs = client_events(&fast);
                // Every event, the multi-line one and [DONE]; without client usage, the usage-only
                // chunk is dropped and no chunk carries `usage`.
                assert_eq!(evs.len(), OPENAI.len() + 2 - usize::from(!client_usage));
                let objects: Vec<&Value> = evs.iter().filter_map(|(_, d)| d.as_ref().ok()).collect();
                assert_eq!(objects.iter().any(|v| v.get("usage").is_some()), client_usage);
                // Every chunk that had a model now carries the gateway's model id.
                assert!(objects.iter().filter(|v| v.get("model").is_some()).all(|v| v["model"] == "ext/mock"));
                assert_eq!(evs.last().unwrap().1, Err("[DONE]".to_owned()));
                // The passthrough keeps the upstream's escapes; the general path re-serialises
                // (so both paths really ran). Key order is no proof: with serde_json's
                // `preserve_order` (enabled in some builds) the general path keeps it too.
                assert!(fast.contains(r#"\u00e9\ud83c\udf89"#), "passed through as received");
                assert!(!general.contains(r#"\u00e9"#));
            }
        }
    }

    #[tokio::test]
    async fn anthropic_passthrough_matches_the_general_path() {
        for reads in splits(&anthropic_upstream_bytes()) {
            let (fast, fast_usage) = run(true, false, true, reads.clone()).await;
            let (general, general_usage) = run(true, true, true, reads).await;
            assert_eq!(client_events(&fast), client_events(&general));
            assert_eq!(fast_usage, general_usage);
            assert_eq!(fast_usage, (15, 9, 3));
            let evs = client_events(&fast);
            assert_eq!(evs.len(), ANTHROPIC.len() + 1);
            assert_eq!(evs[0].1.as_ref().unwrap()["message"]["model"], "ext/mock");
            assert!(fast.contains(r#"\n\u00e9"}}"#), "passed through as received");
            assert!(!general.contains(r#"\u00e9"#));
            for ((name, _), (want, _)) in evs.iter().zip(ANTHROPIC) {
                assert_eq!(name.as_deref(), Some(*want));
            }
        }
    }

    /// Restoring surrogates in place gives the same stream as `transform_chunk`: surrogates split
    /// across chunks, escapes, finishing, reasoning, several choices, chunks without a delta.
    #[tokio::test]
    async fn rehydrating_passthrough_matches_the_general_path() {
        let mut vault = caliban_pii::Vault::new(b"k");
        let sur = vault.surrogate_for(&caliban_pii::EntityType::Email, "jane@acme.com");
        let rh = Arc::new(Rehydrator::new(&vault));
        let j = |s: &str| serde_json::to_string(s).unwrap();
        let (a, b) = sur.split_at(sur.len() / 2);
        let chunk = |delta: String| {
            format!(
                r#"{{"id":"c1","model":"up","choices":[{{"index":0,"delta":{delta},"finish_reason":null}}],"usage":null}}"#
            )
        };
        let events = vec![
            chunk(r#"{"role":"assistant","content":""}"#.into()),
            chunk(format!(r#"{{"content":{}}}"#, j(&format!("Write to {a}")))),
            chunk(format!(r#"{{"content":{}}}"#, j(&format!("{b} \"now\" é 🎉")))),
            chunk(r#"{"content":"\u0041 plain text, nothing held"}"#.into()),
            format!(r#"{{"choices":[{{"delta":{{"content":{}}}}}],"model":"up","id":"c2"}}"#, j(&format!("again {sur} and {a}"))),
            chunk(r#"{"content":null}"#.into()),
            chunk(r#"{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":1}"}}]}"#.into()),
            chunk(format!(r#"{{"reasoning_content":{}}}"#, j(&format!("thinking about {sur}")))),
            r#"{"id":"c1","model":"up","choices":[{"index":0,"delta":{"content":"a"}},{"index":1,"delta":{"content":"b"}}]}"#.into(),
            r#"{"id":"c1","model":"up","choices":[{"index":0}]}"#.into(),
            r#"{"id":"c1","model":"up","choices":[]}"#.into(),
            format!(r#"{{"id":"c1","model":"up","choices":[{{"index":0,"delta":{{"content":{}}},"finish_reason":"stop"}}]}}"#, j(&format!(" end {b}"))),
            r#"{"id":"c1","model":"up","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":4}}"#.into(),
        ];
        let mut body: String = events.iter().map(|e| format!("data: {e}\n\n")).collect();
        body.push_str("data: [DONE]\n\n");
        for client_usage in [true, false] {
            for reads in splits(&body) {
                let (fast, fu) = run_with(false, false, client_usage, Some(Arc::clone(&rh)), reads.clone()).await;
                let (general, gu) = run_with(false, true, client_usage, Some(Arc::clone(&rh)), reads).await;
                assert_eq!(
                    client_events(&fast),
                    client_events(&general),
                    "client_usage={client_usage}\nfast:\n{fast}\ngeneral:\n{general}"
                );
                assert_eq!(fu, gu);
                assert!(!fast.contains(&sur), "every surrogate restored:\n{fast}");
                assert!(fast.contains("Write to "), "{fast}");
                let in_place = r#"{"id":"c1","model":"ext/mock","choices":[{"index":0,"delta":{"content":"\u0041 plain text, nothing held"},"finish_reason":null}]"#;
                assert!(fast.contains(in_place), "edited in place:\n{fast}");
                assert!(!general.contains(r#"\u0041"#), "the general path re-serialises");
                let restored = r#"{"id":"c1","model":"ext/mock","choices":[{"index":0,"delta":{"content":"jane@acme.com \"now\" é 🎉"},"finish_reason":null}]"#;
                assert!(fast.contains(restored), "content rewritten in place:\n{fast}");
            }
        }
    }

    /// Runs an OpenAI-shaped upstream for a client of `dialect` and returns the client body.
    async fn run_openai_for(dialect: Dialect, general: bool, rh: Arc<Rehydrator>, reads: Vec<Bytes>) -> String {
        FORCE_GENERAL.with(|f| f.set(general));
        let (gw, _) = gateway();
        let upstream: Upstream = futures::stream::iter(reads.into_iter().map(Ok)).boxed();
        let resp = openai_shaped(
            Arc::clone(&gw),
            outcome(&gw, dialect, true),
            upstream,
            Some(rh),
            false,
            Settlement::none(),
            Span::none(),
            None,
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        FORCE_GENERAL.with(|f| f.set(false));
        String::from_utf8(body.to_vec()).unwrap()
    }

    /// Surrogates in streamed tool-call arguments are restored like content, also when split
    /// across argument deltas, and originals that need JSON escaping keep the arguments valid JSON.
    #[tokio::test]
    async fn tool_call_argument_deltas_are_rehydrated() {
        let mut vault = caliban_pii::Vault::new(b"k");
        let email = vault.surrogate_for(&caliban_pii::EntityType::Email, "jane@acme.com");
        let name = vault.surrogate_for(&caliban_pii::EntityType::Person, "Jane \"JJ\" O'Neil");
        let rh = Arc::new(Rehydrator::new(&vault));
        let j = |s: &str| serde_json::to_string(s).unwrap();
        // The arguments as the model writes them, in surrogate form.
        let args = format!(r#"{{"to": "{email}", "name": "{name}", "cc": ["{email}"]}}"#);
        let want = json!({"to": "jane@acme.com", "name": "Jane \"JJ\" O'Neil", "cc": ["jane@acme.com"]});
        let start = args.find(&email).unwrap();
        let mut cuts: Vec<(usize, usize)> = (1..email.len()).map(|k| (start + k, start + email.len() + 3)).collect();
        cuts.push((5, args.len() - 2));
        for (c1, c2) in cuts {
            let (p1, rest) = args.split_at(c1);
            let (p2, p3) = rest.split_at(c2 - c1);
            let chunk = |delta: String, finish: &str| {
                format!(
                    r#"{{"id":"c1","model":"up","choices":[{{"index":0,"delta":{delta},"finish_reason":{finish}}}]}}"#
                )
            };
            let tc = |args: &str, head: bool| {
                let prefix = if head { r#""id":"call_1","type":"function","# } else { "" };
                let f = if head {
                    format!(r#"{{"name":"send","arguments":{}}}"#, j(args))
                } else {
                    format!(r#"{{"arguments":{}}}"#, j(args))
                };
                format!(r#"{{"tool_calls":[{{"index":0,{prefix}"function":{f}}}]}}"#)
            };
            let events = [
                chunk(r#"{"role":"assistant","content":null}"#.into(), "null"),
                chunk(tc(p1, true), "null"),
                chunk(tc(p2, false), "null"),
                chunk(tc(p3, false), "null"),
                chunk("{}".into(), r#""tool_calls""#),
            ];
            let mut body: String = events.iter().map(|e| format!("data: {e}\n\n")).collect();
            body.push_str("data: [DONE]\n\n");
            for reads in splits(&body) {
                for general in [false, true] {
                    let out = run_openai_for(Dialect::OpenAi, general, Arc::clone(&rh), reads.clone()).await;
                    let got: String = events_json(&out)
                        .iter()
                        .flat_map(|v| {
                            v.pointer("/choices/0/delta/tool_calls")
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default()
                        })
                        .filter_map(|tc| tc.pointer("/function/arguments").and_then(Value::as_str).map(str::to_owned))
                        .collect();
                    let parsed: Value = serde_json::from_str(&got).unwrap_or_else(|e| panic!("{e}: {got}\n{out}"));
                    assert_eq!(parsed, want, "cuts {c1},{c2}, general={general}\n{out}");
                    assert!(!out.contains(&email), "{out}");
                }
                // Anthropic client: the same arguments as `input_json_delta` events.
                let out = run_openai_for(Dialect::Anthropic, true, Arc::clone(&rh), reads.clone()).await;
                let got: String = events_json(&out)
                    .iter()
                    .filter(|v| v.pointer("/delta/type").and_then(Value::as_str) == Some("input_json_delta"))
                    .filter_map(|v| v.pointer("/delta/partial_json").and_then(Value::as_str).map(str::to_owned))
                    .collect();
                assert_eq!(serde_json::from_str::<Value>(&got).unwrap(), want, "{out}");
            }
        }
    }

    /// Native Anthropic streams: `input_json_delta` pieces get the same treatment.
    #[tokio::test]
    async fn native_anthropic_input_json_deltas_are_rehydrated() {
        let mut vault = caliban_pii::Vault::new(b"k");
        let email = vault.surrogate_for(&caliban_pii::EntityType::Email, "jane@acme.com");
        let name = vault.surrogate_for(&caliban_pii::EntityType::Person, "Jane \"JJ\" O'Neil");
        let rh = Arc::new(Rehydrator::new(&vault));
        let args = format!(r#"{{"to": "{email}", "name": "{name}"}}"#);
        let start = args.find(&email).unwrap();
        for cut in [start + 1, start + email.len() / 2, start + email.len() - 1] {
            let ev = |v: Value| anthropic::sse_event(&v);
            let mut body = ev(
                json!({"type": "message_start", "message": {"id": "m", "type": "message", "role": "assistant", "model": "up", "content": [], "usage": {"input_tokens": 3, "output_tokens": 1}}}),
            );
            body.push_str(&ev(json!({"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "t", "name": "send", "input": {}}})));
            for piece in [&args[..cut], &args[cut..]] {
                body.push_str(&ev(json!({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": piece}})));
            }
            body.push_str(&ev(json!({"type": "content_block_stop", "index": 0})));
            body.push_str(&ev(
                json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 9}}),
            ));
            body.push_str(&ev(json!({"type": "message_stop"})));
            for reads in splits(&body) {
                let (out, _) = run_with(true, true, true, Some(Arc::clone(&rh)), reads).await;
                let got: String = events_json(&out)
                    .iter()
                    .filter_map(|v| v.pointer("/delta/partial_json").and_then(Value::as_str).map(str::to_owned))
                    .collect();
                let parsed: Value = serde_json::from_str(&got).unwrap_or_else(|e| panic!("{e}: {got}"));
                assert_eq!(parsed, json!({"to": "jane@acme.com", "name": "Jane \"JJ\" O'Neil"}), "cut {cut}");
            }
        }
    }

    fn events_json(body: &str) -> Vec<Value> {
        body.lines().filter_map(|l| l.strip_prefix("data: ")).filter_map(|d| serde_json::from_str(d).ok()).collect()
    }

    /// Per chunk: the passthrough's output and byte count equal the general path's, for any
    /// gateway model id (escaping included).
    #[test]
    fn passthrough_chunk_equals_general_chunk() {
        let mut fast = 0;
        for model_id in ["ext/mock", r#"we"ird\id é"#, "\u{1}ctl"] {
            let model_json = serde_json::to_string(model_id).unwrap();
            for client_usage in [true, false] {
                for data in OPENAI {
                    let Some(c) = passthrough::scan_openai(data) else { continue };
                    // The same conditions as `openai_shaped`.
                    if c.usage || !(client_usage || !c.has_usage_key || c.null_usage_member.is_some()) {
                        continue;
                    }
                    fast += 1;
                    let mut out = BytesMut::new();
                    passthrough::write_openai(&mut out, data, &c, &model_json, !client_usage);
                    let out = std::str::from_utf8(&out).unwrap();
                    let got: Value =
                        serde_json::from_str(out.strip_prefix("data: ").unwrap().strip_suffix("\n\n").unwrap())
                            .unwrap();
                    let mut want: Value = serde_json::from_str(data).unwrap();
                    if want.get("model").is_some() {
                        want["model"] = Value::String(model_id.to_owned());
                    }
                    if !client_usage {
                        assert!(!crate::metering::strip_usage(&mut want));
                    }
                    assert_eq!(got, want, "{data}");
                    assert_eq!(c.delta_bytes, delta_bytes(&want), "{data}");
                }
            }
        }
        assert!(fast >= 3 * 2 * 11, "most of the corpus takes the passthrough ({fast})");
    }
}
