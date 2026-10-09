//! Mock upstream provider: OpenAI Chat Completions (JSON and SSE), Anthropic Messages (JSON and
//! SSE), embeddings and model listing.
//!
//! It is built to make gateway measurements clean:
//! - **Fixed latency** (`latency`, default 0) before the response starts, and an optional delay
//!   between stream chunks, so "overhead" is gateway time, not upstream jitter.
//! - **Deterministic usage**: token counts are a pure function of the request (see
//!   [`prompt_tokens`] and [`completion_tokens`]), so the gateway's metering can be compared with
//!   the "provider bill" exactly. Every billed request is recorded in [`Bill`] form.
//! - **Echo replies** (`"You said: <last user text>"`), so PII tests can check what the upstream
//!   received (surrogates) and what the client got back (rehydrated).
//! - **Simulated provider-side prompt caches**, scoped like the real thing: OpenAI-compatible
//!   prefix caches are keyed by `cache_salt` (vLLM) or, without a salt, by the credential; the
//!   Anthropic cache by `x-api-key`. A repeat reports `cached_tokens` /
//!   `cache_read_input_tokens`, which is what a cross-tenant timing or `cached_tokens` probe
//!   would look for.
//! - Upstream model `mock-fail-500` always answers 500 (for fallback tests; not billed).
//!
//! Recording (request log, bills, prefix cache) is optional so the benchmark path does no
//! bookkeeping.

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Mock behaviour.
#[derive(Debug, Clone)]
pub struct MockConfig {
    /// Delay before the response (or the first stream chunk) is sent.
    pub latency: Duration,
    /// Delay between stream chunks.
    pub chunk_delay: Duration,
    /// Characters per streamed text delta.
    pub chunk_chars: usize,
    /// Keep a request log, provider bills and the simulated prompt caches.
    pub record: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self { latency: Duration::ZERO, chunk_delay: Duration::ZERO, chunk_chars: 4, record: true }
    }
}

/// One request as the upstream saw it.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub path: String,
    /// `authorization` header (OpenAI-compatible BYOK credential).
    pub auth: Option<String>,
    /// `x-api-key` header (Anthropic BYOK credential).
    pub x_api_key: Option<String>,
    pub body: Value,
    /// What the provider bills for this request (`None`: not billed, e.g. a 500).
    pub bill: Option<Bill>,
}

impl Entry {
    /// The credential the request was made with, whichever header carried it.
    pub fn credential(&self) -> Option<&str> {
        self.auth.as_deref().map(|a| a.trim_start_matches("Bearer ")).or(self.x_api_key.as_deref())
    }

    /// Text of the last user message (string or text parts).
    pub fn last_user_text(&self) -> String {
        last_user_text(&self.body)
    }
}

/// Provider-side usage for one request, in the provider's own terms. For OpenAI-compatible
/// upstreams `input_tokens` includes `cache_read_tokens`; for Anthropic it excludes both cache
/// fields (Anthropic's convention), which is why [`Bill::total_prompt_tokens`] exists.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct Bill {
    pub anthropic: bool,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_tokens: u64,
    /// The part of `cache_creation_tokens` written with the 1-hour TTL (`cache_control.ttl = "1h"`).
    pub cache_creation_1h_tokens: u64,
}

impl Bill {
    /// Every prompt token the provider processed (cached or not).
    pub fn total_prompt_tokens(&self) -> u64 {
        if self.anthropic {
            self.input_tokens + self.cache_read_tokens + self.cache_creation_tokens
        } else {
            self.input_tokens
        }
    }
}

#[derive(Default)]
struct Recorder {
    log: Vec<Entry>,
    /// (scope, prompt hash) pairs seen: the simulated provider prompt cache.
    prefix_cache: HashSet<(String, String)>,
}

struct Shared {
    cfg: MockConfig,
    rec: Mutex<Recorder>,
}

/// A running mock bound to a local port.
#[derive(Clone)]
pub struct Mock {
    pub addr: SocketAddr,
    shared: Arc<Shared>,
}

impl Mock {
    /// Starts the mock on `addr` (use port 0 for an ephemeral port) on the current runtime.
    pub async fn start(addr: &str, cfg: MockConfig) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared { cfg, rec: Mutex::new(Recorder::default()) });
        let app = router(Arc::clone(&shared));
        tokio::spawn(async move {
            let listener = axum::serve::ListenerExt::tap_io(listener, |tcp| {
                let _ = tcp.set_nodelay(true);
            });
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { addr, shared })
    }

    /// `http://127.0.0.1:port/v1`, the provider `base_url`.
    pub fn base_url(&self) -> String {
        format!("http://{}/v1", self.addr)
    }

    pub fn log(&self) -> Vec<Entry> {
        self.shared.rec.lock().log.clone()
    }

    pub fn len(&self) -> usize {
        self.shared.rec.lock().log.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn last(&self) -> Option<Entry> {
        self.shared.rec.lock().log.last().cloned()
    }

    /// Clears the request log (the simulated prompt caches are kept).
    pub fn clear_log(&self) {
        self.shared.rec.lock().log.clear();
    }
}

fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat))
        .route("/v1/messages", post(messages))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/models", get(models))
        .route("/__mock/log", get(dump_log))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(shared)
}

type St = State<Arc<Shared>>;

fn header(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
}

fn text_of(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter(|p| p.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

pub fn last_user_text(body: &Value) -> String {
    body.get("messages")
        .and_then(Value::as_array)
        .and_then(|m| m.iter().rev().find(|m| m.get("role").and_then(Value::as_str) == Some("user")))
        .map(|m| text_of(&m["content"]))
        .unwrap_or_default()
}

/// Deterministic prompt size: 8 + one token per 4 bytes of every message's text (+ the
/// Anthropic `system` field). Not a tokenizer; only has to be a pure function of the request.
pub fn prompt_tokens(body: &Value) -> u64 {
    let mut bytes = 0usize;
    if let Some(sys) = body.get("system") {
        bytes += text_of(sys).len();
    }
    for m in body.get("messages").and_then(Value::as_array).into_iter().flatten() {
        bytes += text_of(&m["content"]).len() + 4;
    }
    8 + (bytes as u64).div_ceil(4)
}

/// Deterministic completion size: one token per whitespace-separated word, plus one.
pub fn completion_tokens(reply: &str) -> u64 {
    reply.split_whitespace().count() as u64 + 1
}

fn reply_text(body: &Value) -> String {
    format!("You said: {}", last_user_text(body))
}

fn prompt_hash(body: &Value) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(body.get("system").map(Value::to_string).unwrap_or_default());
    h.update(body.get("messages").map(Value::to_string).unwrap_or_default());
    hex::encode(h.finalize())
}

fn chunks(text: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    chars.chunks(n.max(1)).map(|c| c.iter().collect()).collect()
}

fn json_resp(v: &Value) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], v.to_string()).into_response()
}

/// SSE response whose frames are sent with `delay` between them.
fn sse(frames: Vec<String>, delay: Duration) -> Response {
    let stream = futures::stream::unfold(frames.into_iter(), move |mut it| async move {
        let next = it.next()?;
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        Some((Ok::<_, std::io::Error>(Bytes::from(next)), it))
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from_stream(stream))
        .unwrap_or_default()
}

async fn wait(cfg: &MockConfig) {
    if !cfg.latency.is_zero() {
        tokio::time::sleep(cfg.latency).await;
    }
}

async fn chat(State(s): St, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    let model = body.get("model").cloned().unwrap_or(Value::Null);
    let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let include_usage = body.pointer("/stream_options/include_usage").and_then(Value::as_bool).unwrap_or(false);
    let auth = header(&headers, "authorization");
    if model == "mock-fail-500" {
        if s.cfg.record {
            s.rec.lock().log.push(Entry {
                path: "/v1/chat/completions".into(),
                auth,
                x_api_key: None,
                body,
                bill: None,
            });
        }
        return (StatusCode::INTERNAL_SERVER_ERROR, r#"{"error":{"message":"mock failure"}}"#).into_response();
    }
    let text = reply_text(&body);
    let prompt = prompt_tokens(&body);
    let completion = completion_tokens(&text);
    let mut cached = 0;
    if s.cfg.record {
        let mut rec = s.rec.lock();
        // vLLM-style prefix cache: salted requests are isolated by salt; unsalted ones share a
        // cache per credential (or globally when keyless).
        let scope = match body.get("cache_salt").and_then(Value::as_str) {
            Some(salt) => format!("salt:{salt}"),
            None => format!("cred:{}", auth.clone().unwrap_or_default()),
        };
        if !rec.prefix_cache.insert((scope, prompt_hash(&body))) {
            cached = prompt.saturating_sub(4);
        }
        let bill = Bill {
            anthropic: false,
            input_tokens: prompt,
            output_tokens: completion,
            cache_read_tokens: cached,
            cache_creation_tokens: 0,
            cache_creation_1h_tokens: 0,
        };
        rec.log.push(Entry {
            path: "/v1/chat/completions".into(),
            auth,
            x_api_key: None,
            body: body.clone(),
            bill: Some(bill),
        });
    }
    let usage = json!({
        "prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion,
        "prompt_tokens_details": {"cached_tokens": cached}
    });
    wait(&s.cfg).await;
    if stream {
        let mut frames = Vec::new();
        let pieces = chunks(&text, s.cfg.chunk_chars);
        for (i, p) in pieces.iter().enumerate() {
            let delta = if i == 0 { json!({"role": "assistant", "content": p}) } else { json!({"content": p}) };
            let c = json!({"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 0, "model": model,
                           "choices": [{"index": 0, "delta": delta, "finish_reason": null}]});
            frames.push(format!("data: {c}\n\n"));
        }
        let end = json!({"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 0, "model": model,
                         "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]});
        frames.push(format!("data: {end}\n\n"));
        if include_usage {
            let u = json!({"id": "chatcmpl-mock", "object": "chat.completion.chunk", "created": 0, "model": model, "choices": [], "usage": usage});
            frames.push(format!("data: {u}\n\n"));
        }
        frames.push("data: [DONE]\n\n".into());
        return sse(frames, s.cfg.chunk_delay);
    }
    json_resp(&json!({
        "id": "chatcmpl-mock", "object": "chat.completion", "created": 0, "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": usage
    }))
}

/// Tokens of the cacheable prefix: everything up to and including the last block that carries
/// `cache_control` (system and messages, in order). 0 when the request has no breakpoint.
fn anthropic_cacheable_tokens(body: &Value) -> u64 {
    let mut bytes = 0usize;
    let mut upto = 0usize;
    let mut visit = |v: &Value, extra: usize| {
        let mut parts: Vec<&Value> = Vec::new();
        match v {
            Value::Array(a) => parts.extend(a.iter()),
            other => parts.push(other),
        }
        for p in parts {
            bytes += match p {
                Value::String(s) => s.len(),
                o => o.get("text").and_then(Value::as_str).map_or(0, str::len),
            };
            if p.get("cache_control").is_some() {
                upto = bytes;
            }
        }
        bytes += extra;
    };
    if let Some(sys) = body.get("system") {
        visit(sys, 0);
    }
    for m in body.get("messages").and_then(Value::as_array).into_iter().flatten() {
        visit(&m["content"], 4);
    }
    (upto as u64).div_ceil(4)
}

async fn messages(State(s): St, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    let model = body.get("model").cloned().unwrap_or(Value::Null);
    let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);
    let key = header(&headers, "x-api-key");
    let text = reply_text(&body);
    let total = prompt_tokens(&body);
    let output = completion_tokens(&text);
    let cacheable = anthropic_cacheable_tokens(&body).min(total);
    let one_hour = anthropic_last_breakpoint_ttl(&body).as_deref() == Some("1h");
    let (mut read, mut created) = (0, 0);
    if s.cfg.record {
        let mut rec = s.rec.lock();
        if cacheable > 0 {
            let scope = format!("anthropic:{}", key.clone().unwrap_or_default());
            if rec.prefix_cache.insert((scope, prompt_hash(&body))) {
                created = cacheable;
            } else {
                read = cacheable;
            }
        }
        let bill = Bill {
            anthropic: true,
            input_tokens: total - read - created,
            output_tokens: output,
            cache_read_tokens: read,
            cache_creation_tokens: created,
            cache_creation_1h_tokens: if one_hour { created } else { 0 },
        };
        rec.log.push(Entry {
            path: "/v1/messages".into(),
            auth: header(&headers, "authorization"),
            x_api_key: key,
            body: body.clone(),
            bill: Some(bill),
        });
    }
    let input = total - read - created;
    let created_1h = if one_hour { created } else { 0 };
    let usage = json!({"input_tokens": input, "cache_read_input_tokens": read, "cache_creation_input_tokens": created,
        "cache_creation": {"ephemeral_5m_input_tokens": created - created_1h, "ephemeral_1h_input_tokens": created_1h}});
    wait(&s.cfg).await;
    if stream {
        let ev = |e: Value| format!("event: {}\ndata: {e}\n\n", e["type"].as_str().unwrap_or("message"));
        let mut frames = vec![
            ev(
                json!({"type": "message_start", "message": {"id": "msg_mock", "type": "message", "role": "assistant", "model": model, "content": [],
                      "stop_reason": null, "stop_sequence": null,
                      "usage": with_output(&usage, 1)}}),
            ),
            ev(json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})),
        ];
        for p in chunks(&text, s.cfg.chunk_chars) {
            frames.push(ev(
                json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}}),
            ));
        }
        frames.push(ev(json!({"type": "content_block_stop", "index": 0})));
        frames.push(ev(json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"output_tokens": output}})));
        frames.push(ev(json!({"type": "message_stop"})));
        return sse(frames, s.cfg.chunk_delay);
    }
    json_resp(&json!({
        "id": "msg_mock", "type": "message", "role": "assistant", "model": model,
        "content": [{"type": "text", "text": text}], "stop_reason": "end_turn", "stop_sequence": null,
        "usage": with_output(&usage, output)
    }))
}

fn with_output(usage: &Value, output: u64) -> Value {
    let mut u = usage.clone();
    u["output_tokens"] = json!(output);
    u
}

/// The `ttl` of the last `cache_control` breakpoint (system, then messages), if any.
fn anthropic_last_breakpoint_ttl(body: &Value) -> Option<String> {
    let mut ttl = None;
    let mut visit = |v: &Value| {
        let parts: Vec<&Value> = match v {
            Value::Array(a) => a.iter().collect(),
            other => vec![other],
        };
        for p in parts {
            if let Some(cc) = p.get("cache_control") {
                ttl = Some(cc.get("ttl").and_then(Value::as_str).unwrap_or("5m").to_owned());
            }
        }
    };
    if let Some(sys) = body.get("system") {
        visit(sys);
    }
    for m in body.get("messages").and_then(Value::as_array).into_iter().flatten() {
        visit(&m["content"]);
    }
    ttl
}

async fn embeddings(State(s): St, headers: HeaderMap, body: Bytes) -> Response {
    let body: Value = serde_json::from_slice(&body).unwrap_or_default();
    let n = match body.get("input") {
        Some(Value::Array(a)) => a.len(),
        _ => 1,
    };
    if s.cfg.record {
        s.rec.lock().log.push(Entry {
            path: "/v1/embeddings".into(),
            auth: header(&headers, "authorization"),
            x_api_key: None,
            body: body.clone(),
            bill: None,
        });
    }
    wait(&s.cfg).await;
    let data: Vec<Value> =
        (0..n).map(|i| json!({"object": "embedding", "index": i, "embedding": [0.1, 0.2, 0.3]})).collect();
    json_resp(
        &json!({"object": "list", "model": body["model"], "data": data, "usage": {"prompt_tokens": 5, "total_tokens": 5}}),
    )
}

async fn models() -> Response {
    json_resp(&json!({"object": "list", "data": [{"id": "mock-ext", "object": "model"}]}))
}

async fn dump_log(State(s): St) -> Response {
    let rec = s.rec.lock();
    json_resp(&serde_json::to_value(&rec.log).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_is_a_pure_function_of_the_request() {
        let b = json!({"messages": [{"role": "user", "content": "hello world"}]});
        assert_eq!(prompt_tokens(&b), 8 + 4); // (11 + 4) bytes → 4 tokens
        assert_eq!(completion_tokens("You said: hello world"), 5);
    }

    #[test]
    fn anthropic_cacheable_prefix_stops_at_last_breakpoint() {
        let b = json!({"system": [{"type": "text", "text": "aaaaaaaa", "cache_control": {"type": "ephemeral"}}],
                       "messages": [{"role": "user", "content": "bbbb"}]});
        assert_eq!(anthropic_cacheable_tokens(&b), 2);
        assert_eq!(anthropic_cacheable_tokens(&json!({"messages": [{"role": "user", "content": "x"}]})), 0);
    }
}
