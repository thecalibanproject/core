//! End-to-end tests of the gateway app against an in-process mock upstream that speaks both
//! OpenAI Chat Completions and Anthropic Messages.

use crate::{Gateway, app, telemetry};
use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use caliban_config::{Config, ConfigHandle, Snapshot};
use caliban_meter::RecentUsage;
use caliban_meter::quota::InMemoryQuota;
use caliban_pii::{EntityType, SurrogateKeys, Vault};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const PII: &str = "Email jane.doe@acme.com about the plan";
const EMAIL: &str = "jane.doe@acme.com";

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<(String, HeaderMap, Value)>>>);

impl Log {
    fn last(&self) -> (String, HeaderMap, Value) {
        self.0.lock().unwrap().last().cloned().expect("upstream was called")
    }
}

fn text_of(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts.iter().filter_map(|p| p.get("text").and_then(Value::as_str)).collect::<Vec<_>>().join(" "),
        _ => String::new(),
    }
}

fn last_user_text(b: &Value) -> String {
    b["messages"].as_array().and_then(|m| m.iter().rev().find(|m| m["role"] == "user")).map(|m| text_of(&m["content"])).unwrap_or_default()
}

fn pieces(text: &str) -> Vec<String> {
    text.chars().collect::<Vec<_>>().chunks(3).map(|c| c.iter().collect()).collect()
}

fn sse(body: String) -> Response {
    Response::builder().header("content-type", "text/event-stream").body(Body::from(body)).unwrap()
}

fn openai_reply(b: &Value) -> Response {
    let text = format!("You said: {}", last_user_text(b));
    let usage = json!({"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19});
    let model = b["model"].clone();
    if b["stream"] == true {
        let mut out = String::new();
        for p in pieces(&text) {
            let c = json!({"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [{"index": 0, "delta": {"content": p}, "finish_reason": null}]});
            out.push_str(&format!("data: {c}\n\n"));
        }
        let end = json!({"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": usage});
        out.push_str(&format!("data: {end}\n\ndata: [DONE]\n\n"));
        return sse(out);
    }
    let message = if b.get("tools").and_then(Value::as_array).is_some_and(|t| !t.is_empty()) {
        let name = b["tools"][0]["function"]["name"].clone();
        json!({"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": name, "arguments": "{\"city\":\"Paris\"}"}}]})
    } else {
        json!({"role": "assistant", "content": text})
    };
    let finish = if message.get("tool_calls").is_some() { "tool_calls" } else { "stop" };
    Json(json!({"id": "x", "object": "chat.completion", "model": model, "choices": [{"index": 0, "message": message, "finish_reason": finish}], "usage": usage})).into_response()
}

fn anthropic_reply(b: &Value) -> Response {
    let text = format!("You said: {}", last_user_text(b));
    if b["stream"] == true {
        let mut evs = vec![
            json!({"type": "message_start", "message": {"id": "msg_up", "type": "message", "role": "assistant", "model": b["model"], "content": [], "usage": {"input_tokens": 12, "output_tokens": 1}}}),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ];
        evs.extend(pieces(&text).into_iter().map(|p| json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}})));
        evs.push(json!({"type": "content_block_stop", "index": 0}));
        evs.push(json!({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": null}, "usage": {"output_tokens": 7}}));
        evs.push(json!({"type": "message_stop"}));
        return sse(evs.iter().map(caliban_ir::anthropic::sse_event).collect());
    }
    Json(json!({"id": "msg_up", "type": "message", "role": "assistant", "model": b["model"], "content": [{"type": "text", "text": text}],
                "stop_reason": "end_turn", "stop_sequence": null, "usage": {"input_tokens": 12, "output_tokens": 7}}))
    .into_response()
}

async fn mock_upstream() -> (String, Log) {
    let log = Log::default();
    let (l1, l2) = (log.clone(), log.clone());
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(move |h: HeaderMap, Json(b): Json<Value>| async move {
                l1.0.lock().unwrap().push(("chat".into(), h, b.clone()));
                openai_reply(&b)
            }),
        )
        .route(
            "/v1/messages",
            post(move |h: HeaderMap, Json(b): Json<Value>| async move {
                l2.0.lock().unwrap().push(("messages".into(), h, b.clone()));
                anthropic_reply(&b)
            }),
        )
        // Embeddings (not logged): the semantic tests' bag-of-words vectors.
        .route(
            "/v1/embeddings",
            post(|Json(b): Json<Value>| async move {
                let data: Vec<Value> = b["input"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .enumerate()
                    .map(|(i, t)| json!({"object": "embedding", "index": i, "embedding": semantic::bow(t.as_str().unwrap_or_default())}))
                    .collect();
                Json(json!({"object": "list", "data": data}))
            }),
        );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (format!("http://{addr}/v1"), log)
}

fn hash(k: &str) -> String {
    caliban_types::hash_api_key(k)
}

async fn setup() -> (Router, Log, Arc<InMemoryQuota>) {
    setup_with_keys(None).await
}

/// `keys`: the PII surrogate keyring, as derived from a deployment's `CALIBAN_KEK`.
async fn setup_with_keys(keys: Option<SurrogateKeys>) -> (Router, Log, Arc<InMemoryQuota>) {
    let (base, log) = mock_upstream().await;
    let key_file = std::env::temp_dir().join(format!("caliban-gw-test-anthropic-{}", std::process::id()));
    std::fs::write(&key_file, "sk-ant-test").unwrap();
    let toml = format!(
        r#"
[[models]]
id = "ext/mock"
provider = "mockext"
upstream_model = "mock-external"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0

[[models]]
id = "anth/claude"
provider = "anth"
upstream_model = "claude-test"
trust_tier = "t2_contracted"

[[models]]
id = "local/mock"
provider = "mocklocal"
upstream_model = "mock-local"
trust_tier = "t0_sovereign"

[[tenants]]
id = "acme"
name = "Acme"
api_key_hashes = ["{acme}"]
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  [[tenants.providers]]
  id = "anth"
  kind = "anthropic"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  api_key = {{ file = "{key}" }}
  [[tenants.providers]]
  id = "mocklocal"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t0_sovereign"

[[tenants]]
id = "globex"
name = "Globex"
api_key_hashes = ["{globex}"]
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"

[[tenants]]
id = "solo"
name = "Solo"
pii_surrogate_scope = "session"
api_key_hashes = ["{solo}"]
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"

[[tenants]]
id = "limited"
name = "Limited"
api_key_hashes = ["{limited}"]
  [[tenants.providers]]
  id = "mocklocal"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t0_sovereign"

[[tenants]]
id = "budget"
name = "Budget"
api_key_hashes = ["{budget}"]
  [[tenants.providers]]
  id = "mocklocal"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t0_sovereign"

[limits.tenants.limited]
requests_per_minute = 1

[limits.tenants.budget]
tokens_per_day = 2000
"#,
        acme = hash("cal_acme"),
        globex = hash("cal_globex"),
        solo = hash("cal_solo"),
        limited = hash("cal_limited"),
        budget = hash("cal_budget"),
        key = key_file.display(),
    );
    let cfg = Config::from_toml_str(&toml).unwrap();
    let quota = Arc::new(InMemoryQuota::new());
    let mut gw = Gateway::new(ConfigHandle::new(Snapshot::new(cfg, "test")), Arc::new(RecentUsage::default())).with_quota(quota.clone());
    if let Some(k) = keys {
        gw.pii_keys = k;
    }
    (app(Arc::new(gw)), log, quota)
}

async fn call(app: &Router, path: &str, auth: (&str, &str), body: Value) -> (StatusCode, HeaderMap, String) {
    let req = Request::post(path)
        .header(auth.0, auth.1)
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .header("anthropic-beta", "test-beta-1")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    (parts.status, parts.headers, String::from_utf8(bytes.to_vec()).unwrap())
}

const ANTH: (&str, &str) = ("x-api-key", "cal_acme");
const BEARER: (&str, &str) = ("authorization", "Bearer cal_acme");

fn events(body: &str) -> Vec<Value> {
    body.lines().filter_map(|l| l.strip_prefix("data: ")).filter_map(|d| serde_json::from_str(d).ok()).collect()
}

fn streamed_text(evs: &[Value]) -> String {
    evs.iter().filter(|e| e["type"] == "content_block_delta").filter_map(|e| e["delta"]["text"].as_str()).collect()
}

#[tokio::test]
async fn anthropic_client_on_openai_upstream() {
    let (app, log, _) = setup().await;
    let body = json!({"model": "ext/mock", "max_tokens": 100, "temperature": 0.5,
        "system": [{"type": "text", "text": "Be nice."}, {"type": "text", "text": "Be brief."}],
        "messages": [{"role": "user", "content": PII}]});
    let (status, h, out) = call(&app, "/v1/messages", ANTH, body).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["type"], "message");
    assert_eq!(v["model"], "ext/mock");
    assert_eq!(v["content"][0]["text"], format!("You said: {PII}"), "rehydrated");
    assert_eq!(v["stop_reason"], "end_turn");
    assert_eq!(v["usage"]["output_tokens"], 7);
    assert!(h.contains_key("request-id"));
    assert_eq!(h["x-caliban-pii-entities"], "1");

    let (path, _, sent) = log.last();
    assert_eq!(path, "chat");
    assert_eq!(sent["messages"][0], json!({"role": "system", "content": "Be nice.\n\nBe brief."}));
    assert!(!sent.to_string().contains(EMAIL), "upstream saw surrogates only: {sent}");
    assert_eq!(sent["max_tokens"], 100);
    assert_eq!(sent["model"], "mock-external");
}

#[tokio::test]
async fn anthropic_client_streams_events_from_openai_upstream() {
    let (app, _, _) = setup().await;
    let body = json!({"model": "ext/mock", "max_tokens": 100, "stream": true, "messages": [{"role": "user", "content": [{"type": "text", "text": PII}]}]});
    let (status, h, out) = call(&app, "/v1/messages", ANTH, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["content-type"], "text/event-stream");
    assert!(out.starts_with("event: message_start\n"), "{out}");
    let evs = events(&out);
    let types: Vec<&str> = evs.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(&types[..3], ["message_start", "ping", "content_block_start"]);
    assert_eq!(&types[types.len() - 3..], ["content_block_stop", "message_delta", "message_stop"]);
    assert_eq!(streamed_text(&evs), format!("You said: {PII}"), "surrogates split across chunks are restored");
    let md = evs.iter().find(|e| e["type"] == "message_delta").unwrap();
    assert_eq!(md["delta"]["stop_reason"], "end_turn");
    assert_eq!(md["usage"]["output_tokens"], 7);
    assert_eq!(evs[0]["message"]["model"], "ext/mock");
}

#[tokio::test]
async fn anthropic_tool_use_through_openai_upstream() {
    let (app, log, _) = setup().await;
    let body = json!({"model": "ext/mock", "max_tokens": 100,
        "tools": [{"name": "get_weather", "description": "Weather", "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}}],
        "tool_choice": {"type": "auto"},
        "messages": [{"role": "user", "content": "Weather in Paris?"}]});
    let (status, _, out) = call(&app, "/v1/messages", ANTH, body).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["stop_reason"], "tool_use");
    assert_eq!(v["content"][0], json!({"type": "tool_use", "id": "call_1", "name": "get_weather", "input": {"city": "Paris"}}));
    let (_, _, sent) = log.last();
    assert_eq!(sent["tools"][0]["function"]["name"], "get_weather");
    assert_eq!(sent["tool_choice"], "auto");
}

#[tokio::test]
async fn anthropic_native_passthrough_keeps_cache_control_and_protects_text() {
    let (app, log, _) = setup().await;
    let body = json!({"model": "anth/claude", "max_tokens": 50,
        "system": [{"type": "text", "text": "Long shared context", "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": [{"type": "text", "text": PII, "cache_control": {"type": "ephemeral"}}]}]});
    let (status, h, out) = call(&app, "/v1/messages", ANTH, body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["content"][0]["text"], format!("You said: {PII}"));
    assert_eq!(v["model"], "anth/claude");
    assert_eq!(h["x-caliban-pii-entities"], "1");
    let (path, uh, sent) = log.last();
    assert_eq!(path, "messages");
    assert_eq!(uh["x-api-key"], "sk-ant-test", "tenant's BYOK key");
    assert_eq!(uh["anthropic-beta"], "test-beta-1");
    assert!(uh.get("authorization").is_none(), "the client's Caliban key never goes upstream");
    assert_eq!(sent["model"], "claude-test");
    assert_eq!(sent["system"][0]["cache_control"]["type"], "ephemeral");
    assert_eq!(sent["messages"][0]["content"][0]["cache_control"]["type"], "ephemeral");
    assert!(!sent.to_string().contains(EMAIL), "{sent}");

    let mut body = body;
    body["stream"] = json!(true);
    let (status, _, out) = call(&app, "/v1/messages", ANTH, body).await;
    assert_eq!(status, StatusCode::OK);
    let evs = events(&out);
    assert_eq!(evs[0]["message"]["model"], "anth/claude");
    assert_eq!(streamed_text(&evs), format!("You said: {PII}"));
    assert_eq!(evs.last().unwrap()["type"], "message_stop");
}

#[tokio::test]
async fn openai_client_on_anthropic_provider() {
    let (app, log, _) = setup().await;
    let body = json!({"model": "anth/claude", "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "hello"}]});
    let (status, _, out) = call(&app, "/v1/chat/completions", BEARER, body).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["choices"][0]["message"]["content"], "You said: hello");
    assert_eq!(v["model"], "anth/claude");
    assert_eq!(v["usage"]["completion_tokens"], 7);
    let (path, _, sent) = log.last();
    assert_eq!(path, "messages");
    assert_eq!(sent["system"], "sys");
    assert_eq!(sent["max_tokens"], caliban_ir::anthropic::DEFAULT_MAX_TOKENS);

    let body = json!({"model": "anth/claude", "stream": true, "messages": [{"role": "user", "content": "streamed"}]});
    let (_, _, out) = call(&app, "/v1/chat/completions", BEARER, body).await;
    let text: String = events(&out).iter().filter_map(|c| c["choices"][0]["delta"]["content"].as_str()).collect();
    assert_eq!(text, "You said: streamed");
    assert!(out.trim_end().ends_with("data: [DONE]"));
}

#[tokio::test]
async fn errors_are_anthropic_shaped_on_messages() {
    let (app, _, _) = setup().await;
    let (status, _, out) = call(&app, "/v1/messages", ("x-api-key", "cal_wrong"), json!({"model": "ext/mock", "max_tokens": 1, "messages": []})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v, json!({"type": "error", "error": {"type": "authentication_error", "message": "invalid or missing API key"}}));
    let (status, _, out) = call(&app, "/v1/messages", ANTH, json!({"model": "ext/mock", "messages": [{"role": "user", "content": "x"}]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["error"]["type"], "invalid_request_error");
    let (status, _, out) = call(&app, "/v1/messages", ANTH, json!({"model": "ext/mock", "max_tokens": 5, "messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["error"]["type"], "permission_error");
}

#[tokio::test]
async fn count_tokens_is_approximate() {
    let (app, _, _) = setup().await;
    let (status, _, out) = call(&app, "/v1/messages/count_tokens", ANTH, json!({"model": "ext/mock", "system": "abcd", "messages": [{"role": "user", "content": "abcdefgh"}]})).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), json!({"input_tokens": 3 + 4 + 1 + 4 + 2}));
}

#[tokio::test]
async fn request_rate_limit_returns_429_in_both_dialects() {
    let (app, _, _) = setup().await;
    let chat = json!({"model": "local/mock", "messages": [{"role": "user", "content": "hi"}]});
    let (status, _, _) = call(&app, "/v1/chat/completions", ("authorization", "Bearer cal_limited"), chat.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, h, out) = call(&app, "/v1/chat/completions", ("authorization", "Bearer cal_limited"), chat).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let ra: u64 = h["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&ra), "{ra}");
    assert_eq!(h["x-caliban-ratelimit-scope"], "requests_per_minute");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["error"]["type"], "rate_limited");
    assert_eq!(v["error"]["code"], "requests_per_minute");

    let (status, h, out) = call(&app, "/v1/messages", ("x-api-key", "cal_limited"), json!({"model": "local/mock", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(h.contains_key("retry-after"));
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["error"]["type"], "rate_limit_error");
}

#[tokio::test]
async fn token_budget_reserves_then_settles_actual_usage() {
    let (app, _, quota) = setup().await;
    let auth = ("authorization", "Bearer cal_budget");
    // Reserves ~1500 + prompt estimate, settles to the 19 tokens the upstream reported.
    let (status, _, _) = call(&app, "/v1/chat/completions", auth, json!({"model": "local/mock", "max_tokens": 1500, "messages": [{"role": "user", "content": "hi"}]})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(quota.day_usage("budget").0, 19);
    // Streams settle too (usage from the final chunk).
    let (status, _, _) = call(&app, "/v1/chat/completions", auth, json!({"model": "local/mock", "stream": true, "max_tokens": 100, "messages": [{"role": "user", "content": "hi"}]})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(quota.day_usage("budget").0, 38);
    // 38 used + 1990 requested + prompt > 2000.
    let (status, h, out) = call(&app, "/v1/chat/completions", auth, json!({"model": "local/mock", "max_tokens": 1990, "messages": [{"role": "user", "content": "hi"}]})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{out}");
    assert_eq!(h["x-caliban-ratelimit-scope"], "tokens_per_day");
    assert_eq!(quota.day_usage("budget").0, 38, "a rejected request reserves nothing");
}

// ───────────────────────────── tracing ─────────────────────────────

mod capture {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::layer::Context;
    use tracing_subscriber::registry::LookupSpan;

    /// (span or event name, field, value) for everything the OTLP layer would see.
    #[derive(Clone, Default)]
    pub struct Capture(pub Arc<Mutex<Vec<(String, String, String)>>>);

    struct V<'a>(&'a Capture, String);

    impl Visit for V<'_> {
        fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
            self.0.0.lock().unwrap().push((self.1.clone(), f.name().to_owned(), format!("{v:?}").trim_matches('"').to_owned()));
        }
        fn record_str(&mut self, f: &Field, v: &str) {
            self.0.0.lock().unwrap().push((self.1.clone(), f.name().to_owned(), v.to_owned()));
        }
    }

    impl<S: Subscriber + for<'a> LookupSpan<'a>> tracing_subscriber::Layer<S> for Capture {
        fn on_new_span(&self, attrs: &Attributes<'_>, _: &Id, _: Context<'_, S>) {
            attrs.record(&mut V(self, attrs.metadata().name().to_owned()));
        }
        fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
            let name = ctx.span(id).map(|s| s.name().to_owned()).unwrap_or_default();
            values.record(&mut V(self, name));
        }
        fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
            event.record(&mut V(self, format!("event:{}", event.metadata().target())));
        }
    }
}

/// Process-wide capture subscriber with the exporter's filter. Global rather than thread-scoped:
/// scoped dispatchers race tracing's callsite-interest cache when tests run in parallel. As a
/// bonus, the no-content check below then covers the spans of every test in this binary.
fn global_capture() -> &'static capture::Capture {
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    static CAP: std::sync::OnceLock<capture::Capture> = std::sync::OnceLock::new();
    CAP.get_or_init(|| {
        let cap = capture::Capture::default();
        let sub = tracing_subscriber::registry().with(cap.clone().with_filter(telemetry::export_filter()));
        tracing::subscriber::set_global_default(sub).expect("no other global subscriber in tests");
        cap
    })
}

#[tokio::test]
async fn genai_spans_carry_attributes_but_never_content() {
    let cap = global_capture();
    let (app, log, _) = setup().await;
    let (status, _, _) = call(&app, "/v1/chat/completions", BEARER, json!({"model": "ext/mock", "messages": [{"role": "user", "content": PII}]})).await;
    assert_eq!(status, StatusCode::OK);
    let upstream_text = last_user_text(&log.last().2);
    let (status, _, _) = call(&app, "/v1/messages", ANTH, json!({"model": "anth/claude", "max_tokens": 9, "stream": true, "messages": [{"role": "user", "content": PII}]})).await;
    assert_eq!(status, StatusCode::OK);
    // A failing request too (error attributes, no content).
    call(&app, "/v1/chat/completions", BEARER, json!({"model": "ext/mock", "messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]})).await;

    let seen = cap.0.lock().unwrap().clone();
    assert!(!seen.is_empty(), "spans were captured");
    for (span, field, value) in &seen {
        for needle in [EMAIL, "You said", "about the plan", upstream_text.as_str(), "AKIA"] {
            assert!(!value.contains(needle), "content leaked into {span}.{field} = {value}");
        }
    }
    let has = |span: &str, field: &str, value: &str| seen.iter().any(|(s, f, v)| s == span && f == field && v == value);
    let root = "gen_ai.request";
    assert!(has(root, "otel.name", "chat ext/mock"));
    assert!(has(root, "gen_ai.operation.name", "chat"));
    assert!(has(root, "gen_ai.request.model", "ext/mock"));
    assert!(has(root, "gen_ai.response.model", "ext/mock"));
    assert!(has(root, "gen_ai.provider.name", "openai_compatible"));
    assert!(has(root, "gen_ai.usage.input_tokens", "12"));
    assert!(has(root, "gen_ai.usage.output_tokens", "7"));
    assert!(has(root, "caliban.tenant", "acme"));
    assert!(has(root, "caliban.cache", "bypass"));
    assert!(has(root, "caliban.pii.entities", "1"));
    assert!(has(root, "caliban.route.intent", "pinned"));
    assert!(has(root, "caliban.route.stage", "rules"));
    assert!(has(root, "otel.name", "chat anth/claude"));
    assert!(has(root, "gen_ai.provider.name", "anthropic"));
    assert!(has(root, "caliban.dialect", "anthropic"));
    assert!(has(root, "error.type", "policy_violation"));
    assert!(has("upstream", "otel.name", "chat mock-external"));
    assert!(has("upstream", "otel.kind", "client"));
    assert!(has("upstream", "gen_ai.response.model", "mock-external"));
    assert!(has("upstream", "caliban.native", "true"));
    assert!(has("pii", "caliban.pii.entities", "1"));
    assert!(has("route", "caliban.route.candidates", "1"));
}

// ───────────────────────── PII surrogate scopes and the exact cache ─────────────────────────

const GLOBEX: (&str, &str) = ("authorization", "Bearer cal_globex");
const SOLO: (&str, &str) = ("authorization", "Bearer cal_solo");
const TEST_KEK: [u8; 32] = *b"caliban-test-kek-32-bytes-long!!";

fn chat_body(text: &str) -> Value {
    json!({"model": "ext/mock", "temperature": 0, "messages": [{"role": "user", "content": text}]})
}

fn upstream_calls(log: &Log) -> usize {
    log.0.lock().unwrap().len()
}

fn reply_text(out: &str) -> String {
    let v: Value = serde_json::from_str(out).unwrap();
    v["choices"][0]["message"]["content"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn tenant_scope_repeated_pii_prompt_hits_the_cache() {
    let (app, log, _) = setup().await;
    let (status, h, out) = call(&app, "/v1/chat/completions", BEARER, chat_body(PII)).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(h["x-caliban-cache"], "miss");
    assert_eq!(reply_text(&out), format!("You said: {PII}"));
    let first = last_user_text(&log.last().2);
    assert!(!first.contains(EMAIL), "{first}");
    let calls = upstream_calls(&log);

    // Same PII, same tenant, new request: same surrogates, so the same protected body.
    let (status, h, out) = call(&app, "/v1/chat/completions", BEARER, chat_body(PII)).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(h["x-caliban-cache"], "hit");
    assert_eq!(upstream_calls(&log), calls, "served from cache");
    assert_eq!(reply_text(&out), format!("You said: {PII}"), "cached answer rehydrated with this request's vault");

    // Same value inside a different prompt: same surrogate upstream.
    call(&app, "/v1/chat/completions", BEARER, chat_body(&format!("Is {EMAIL} still valid?"))).await;
    let surrogate = first.strip_prefix("Email ").and_then(|r| r.strip_suffix(" about the plan")).unwrap();
    assert!(last_user_text(&log.last().2).contains(surrogate));

    // Anthropic clients: the OpenAI-shaped entry is translated and rehydrated on a hit.
    let body = json!({"model": "ext/mock", "max_tokens": 100, "temperature": 0, "messages": [{"role": "user", "content": PII}]});
    let (_, h, _) = call(&app, "/v1/messages", ANTH, body.clone()).await;
    assert_eq!(h["x-caliban-cache"], "miss", "max_tokens makes it another upstream body");
    let (status, h, out) = call(&app, "/v1/messages", ANTH, body).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(h["x-caliban-cache"], "hit");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["content"][0]["text"], format!("You said: {PII}"));
}

#[tokio::test]
async fn tenant_scope_cache_never_crosses_tenants() {
    let (app, log, _) = setup().await;
    let (_, h, _) = call(&app, "/v1/chat/completions", BEARER, chat_body(PII)).await;
    assert_eq!(h["x-caliban-cache"], "miss");
    let acme_sent = last_user_text(&log.last().2);
    let calls = upstream_calls(&log);

    let (status, h, out) = call(&app, "/v1/chat/completions", GLOBEX, chat_body(PII)).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(h["x-caliban-cache"], "miss", "another tenant never sees acme's entry");
    assert_eq!(upstream_calls(&log), calls + 1);
    let globex_sent = last_user_text(&log.last().2);
    assert!(!globex_sent.contains(EMAIL));
    assert_ne!(globex_sent, acme_sent, "different tenants, different surrogates");
    assert_eq!(reply_text(&out), format!("You said: {PII}"));

    let (_, h, _) = call(&app, "/v1/chat/completions", GLOBEX, chat_body(PII)).await;
    assert_eq!(h["x-caliban-cache"], "hit");
}

#[tokio::test]
async fn session_scope_gives_fresh_surrogates_and_bypasses_the_cache() {
    let (app, log, _) = setup().await;
    let (_, h, out) = call(&app, "/v1/chat/completions", SOLO, chat_body(PII)).await;
    assert_eq!(h["x-caliban-cache"], "bypass");
    assert_eq!(reply_text(&out), format!("You said: {PII}"));
    let first = last_user_text(&log.last().2);
    let (_, h, out) = call(&app, "/v1/chat/completions", SOLO, chat_body(PII)).await;
    assert_eq!(h["x-caliban-cache"], "bypass");
    assert_eq!(reply_text(&out), format!("You said: {PII}"));
    let second = last_user_text(&log.last().2);
    assert!(!first.contains(EMAIL) && !second.contains(EMAIL));
    assert_ne!(first, second, "a new surrogate per request");

    // Without PII, session-scope tenants still use the cache.
    call(&app, "/v1/chat/completions", SOLO, chat_body("hello there")).await;
    let (_, h, _) = call(&app, "/v1/chat/completions", SOLO, chat_body("hello there")).await;
    assert_eq!(h["x-caliban-cache"], "hit");

    // Streaming rehydration with per-request surrogates.
    let body = json!({"model": "ext/mock", "stream": true, "messages": [{"role": "user", "content": PII}]});
    let (status, _, out) = call(&app, "/v1/chat/completions", SOLO, body).await;
    assert_eq!(status, StatusCode::OK);
    let text: String = out
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .filter_map(|d| serde_json::from_str::<Value>(d).ok())
        .filter_map(|c| c["choices"][0]["delta"]["content"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(text, format!("You said: {PII}"));
}

#[tokio::test]
async fn tenant_scope_streaming_is_rehydrated() {
    let (app, log, _) = setup().await;
    let body = json!({"model": "ext/mock", "stream": true, "messages": [{"role": "user", "content": PII}]});
    let (status, _, out) = call(&app, "/v1/chat/completions", BEARER, body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let text = |out: &str| -> String {
        out.lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|d| serde_json::from_str::<Value>(d).ok())
            .filter_map(|c| c["choices"][0]["delta"]["content"].as_str().map(str::to_owned))
            .collect()
    };
    assert_eq!(text(&out), format!("You said: {PII}"));
    let first = last_user_text(&log.last().2);
    let (_, _, out) = call(&app, "/v1/chat/completions", BEARER, body).await;
    assert_eq!(text(&out), format!("You said: {PII}"));
    assert_eq!(last_user_text(&log.last().2), first, "stable surrogate across streamed requests");
}

/// Split mode: two routers that share only `CALIBAN_KEK` send byte-identical protected requests.
#[tokio::test]
async fn routers_sharing_the_kek_send_identical_surrogates() {
    let (a, log_a, _) = setup_with_keys(Some(SurrogateKeys::from_kek(&TEST_KEK))).await;
    let (b, log_b, _) = setup_with_keys(Some(SurrogateKeys::from_kek(&TEST_KEK))).await;
    call(&a, "/v1/chat/completions", BEARER, chat_body(PII)).await;
    call(&b, "/v1/chat/completions", BEARER, chat_body(PII)).await;
    let (sa, sb) = (log_a.last().2, log_b.last().2);
    assert!(!sa.to_string().contains(EMAIL));
    assert_eq!(sa, sb);
    let (c, log_c, _) = setup_with_keys(Some(SurrogateKeys::from_kek(&[1; 32]))).await;
    call(&c, "/v1/chat/completions", BEARER, chat_body(PII)).await;
    assert_ne!(last_user_text(&log_c.last().2), last_user_text(&sa), "another KEK, other surrogates");
}

/// Two different values that share a surrogate in one tenant (small formats make this possible
/// across requests) produce the same protected request, so the second hits the first's cache
/// entry. The entry is stored pseudonymised and rehydrated with the second request's own vault,
/// so the second caller never sees the first caller's value.
#[tokio::test]
async fn cache_hit_after_a_cross_request_collision_never_leaks_the_other_value() {
    let keys = SurrogateKeys::from_kek(&TEST_KEK);
    let acme = keys.tenant_key("acme");
    let surrogate = |ip: &str| Vault::new(&acme).surrogate_for(&EntityType::IpAddress, ip);
    // 762 possible IP surrogates: a colliding pair turns up within a few dozen addresses.
    let mut seen = std::collections::HashMap::new();
    let (ip1, ip2) = (0..=255u32)
        .flat_map(|x| (1..=254u32).map(move |y| format!("10.9.{x}.{y}")))
        .find_map(|ip| seen.insert(surrogate(&ip), ip.clone()).map(|prev| (prev, ip)))
        .expect("collision in a 762-address pool");

    let (app, log, _) = setup_with_keys(Some(keys)).await;
    let (_, h, out) = call(&app, "/v1/chat/completions", BEARER, chat_body(&format!("ping {ip1} now"))).await;
    assert_eq!(h["x-caliban-cache"], "miss");
    assert_eq!(reply_text(&out), format!("You said: ping {ip1} now"));
    assert_eq!(last_user_text(&log.last().2), format!("ping {} now", surrogate(&ip1)));

    let (_, h, out) = call(&app, "/v1/chat/completions", BEARER, chat_body(&format!("ping {ip2} now"))).await;
    assert_eq!(h["x-caliban-cache"], "hit", "byte-identical protected request");
    let text = reply_text(&out);
    assert_eq!(text, format!("You said: ping {ip2} now"));
    assert!(!text.contains(&ip1), "{text}");
}

#[tokio::test]
async fn native_anthropic_cache_hit_is_rehydrated() {
    let (app, log, _) = setup().await;
    let body = json!({"model": "anth/claude", "max_tokens": 50, "temperature": 0, "messages": [{"role": "user", "content": PII}]});
    let (_, h, out) = call(&app, "/v1/messages", ANTH, body.clone()).await;
    assert_eq!(h["x-caliban-cache"], "miss", "{out}");
    assert_eq!(log.last().0, "messages");
    let calls = upstream_calls(&log);
    let (status, h, out) = call(&app, "/v1/messages", ANTH, body).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(h["x-caliban-cache"], "hit");
    assert_eq!(upstream_calls(&log), calls);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["content"][0]["text"], format!("You said: {PII}"));
    assert_eq!(v["model"], "anth/claude");
}

// ───────────────────────── T2 semantic cache ─────────────────────────

mod semantic {
    use super::*;
    use caliban_cache::semantic::{
        Candidate, EntryPayload, EntryStats, MemoryStore, SearchQuery, StoreError, VectorStore,
    };
    use caliban_meter::UsageEvent;
    use caliban_types::{CacheStatus, CacheTier, EmbedError, Embedder, ModelId, TenantId};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// Bag-of-words over alphabetic words only (digits, emails and other tokens are ignored, so
    /// prompts that differ only in such tokens embed identically and only the guards separate
    /// them), with per-text overrides.
    #[derive(Default)]
    pub(super) struct FakeEmbedder {
        pub overrides: Mutex<HashMap<String, Vec<f32>>>,
        pub calls: AtomicUsize,
        pub delay: Duration,
        pub fail: bool,
    }

    pub(super) const DIM: usize = 64;

    pub(super) fn bow(text: &str) -> Vec<f32> {
        let mut v = vec![0.0f32; DIM];
        for w in text.split(|c: char| c.is_whitespace() || matches!(c, ',' | '?' | '!' | ';' | ':')) {
            let w = w.trim_end_matches('.');
            if !w.is_empty() && w.chars().all(char::is_alphabetic) {
                let h = blake3::hash(w.to_lowercase().as_bytes());
                v[h.as_bytes()[0] as usize % DIM] += 1.0;
            }
        }
        v[DIM - 1] += 0.01; // never all-zero
        v
    }

    /// Unit vector with cosine `c` to `e0`, tilted towards `e_axis` (`axis` > 0).
    pub(super) fn at(c: f32, axis: usize) -> Vec<f32> {
        let mut v = vec![0.0f32; DIM];
        v[0] = c;
        v[axis] = (1.0 - c * c).sqrt();
        v
    }

    #[async_trait::async_trait]
    impl Embedder for FakeEmbedder {
        async fn embed(&self, _: &TenantId, _: &ModelId, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            if self.fail {
                return Err(EmbedError::Upstream("down".into()));
            }
            let o = self.overrides.lock().unwrap();
            Ok(texts.iter().map(|t| o.get(t).cloned().unwrap_or_else(|| bow(t))).collect())
        }
    }

    /// Store wrapper that adds latency to searches.
    struct SlowStore(MemoryStore, Duration);

    #[async_trait::async_trait]
    impl VectorStore for SlowStore {
        async fn search(&self, q: &SearchQuery<'_>) -> Result<Vec<Candidate>, StoreError> {
            tokio::time::sleep(self.1).await;
            self.0.search(q).await
        }
        async fn upsert(&self, c: &str, id: &str, v: &[f32], p: &EntryPayload) -> Result<(), StoreError> {
            self.0.upsert(c, id, v, p).await
        }
        async fn update_stats(&self, c: &str, t: &str, id: &str, s: &EntryStats, th: f32) -> Result<(), StoreError> {
            self.0.update_stats(c, t, id, s, th).await
        }
        async fn delete_expired(&self, c: &str, now: i64) -> Result<(), StoreError> {
            self.0.delete_expired(c, now).await
        }
        async fn delete_tenant(&self, c: &str, t: &str) -> Result<(), StoreError> {
            self.0.delete_tenant(c, t).await
        }
        async fn list_collections(&self) -> Result<Vec<String>, StoreError> {
            self.0.list_collections().await
        }
    }

    pub(super) struct Sem {
        pub app: Router,
        pub log: Log,
        pub store: Arc<MemoryStore>,
        pub embedder: Arc<FakeEmbedder>,
        pub usage: RecentUsage,
    }

    pub(super) struct Opts {
        pub verify_rate: f32,
        pub budget_ms: u64,
        pub embedder: FakeEmbedder,
        pub slow_store: Option<Duration>,
        pub keys: Option<SurrogateKeys>,
        /// Use a real Qdrant instead of the in-memory store.
        pub qdrant: Option<String>,
        /// Use the gateway's `ProviderEmbedder` (against the mock's `/v1/embeddings`, or
        /// `embed_base` when set).
        pub real_embedder: bool,
        pub embed_base: Option<String>,
        pub prefix: String,
    }

    impl Default for Opts {
        fn default() -> Self {
            Self {
                verify_rate: 0.0,
                budget_ms: 2000,
                embedder: FakeEmbedder::default(),
                slow_store: None,
                keys: None,
                qdrant: None,
                real_embedder: false,
                embed_base: None,
                prefix: "caliban_semcache".into(),
            }
        }
    }

    pub(super) async fn setup(o: Opts) -> Sem {
        let (base, log) = mock_upstream().await;
        let key_file = std::env::temp_dir().join(format!("caliban-gw-test-sem-{}", std::process::id()));
        std::fs::write(&key_file, "sk-ant-test").unwrap();
        let toml = format!(
            r#"
[cache.semantic]
enabled = true
store = "memory"
embedding_model = "local/embed"
verify_rate = {verify_rate}
lookup_budget_ms = {budget}
collection_prefix = "{prefix}"

[[models]]
id = "ext/mock"
provider = "mockext"
upstream_model = "mock-external"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0

[[models]]
id = "anth/claude"
provider = "anth"
upstream_model = "claude-test"
trust_tier = "t2_contracted"

[[models]]
id = "local/embed"
provider = "mocklocal"
upstream_model = "embed"
kind = "embedding"
trust_tier = "t0_sovereign"

[[providers]]
id = "mocklocal"
kind = "openai_compatible"
base_url = "{embed_base}"
trust_tier = "t0_sovereign"

[[tenants]]
id = "acme"
name = "Acme"
semantic_cache = "on"
api_key_hashes = ["{acme}"]
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  [[tenants.providers]]
  id = "anth"
  kind = "anthropic"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  api_key = {{ file = "{key}" }}

[[tenants]]
id = "globex"
name = "Globex"
semantic_cache = "on"
api_key_hashes = ["{globex}"]
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"

[[tenants]]
id = "solo"
name = "Solo"
semantic_cache = "on"
pii_surrogate_scope = "session"
api_key_hashes = ["{solo}"]
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"

[[tenants]]
id = "limited"
name = "Semantic off"
api_key_hashes = ["{limited}"]
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"
"#,
            verify_rate = o.verify_rate,
            budget = o.budget_ms,
            prefix = o.prefix,
            embed_base = o.embed_base.clone().unwrap_or_else(|| base.clone()),
            acme = hash("cal_acme"),
            globex = hash("cal_globex"),
            solo = hash("cal_solo"),
            limited = hash("cal_limited"),
            key = key_file.display(),
        );
        let cfg = Config::from_toml_str(&toml).unwrap();
        let usage = RecentUsage::default();
        let store = Arc::new(MemoryStore::default());
        let vs: Arc<dyn VectorStore> = match (o.slow_store, &o.qdrant) {
            (Some(d), _) => Arc::new(SlowStore(MemoryStore::default(), d)),
            (None, Some(url)) => Arc::new(caliban_cache::semantic::QdrantStore::new(url, None).unwrap()),
            (None, None) => store.clone(),
        };
        let mut gw = Gateway::new(ConfigHandle::new(Snapshot::new(cfg, "test")), Arc::new(usage.clone())).with_semantic_store(vs);
        let embedder = Arc::new(o.embedder);
        if !o.real_embedder {
            gw.embedder = embedder.clone();
        }
        if let Some(k) = o.keys {
            gw.pii_keys = k;
        }
        Sem { app: app(Arc::new(gw)), log, store, embedder, usage }
    }

    pub(super) async fn wait_entries(store: &MemoryStore, n: usize) {
        for _ in 0..200 {
            if store.len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("expected {n} semantic entries, have {}", store.len());
    }

    /// Lets background tasks (inserts, verifications) run.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    fn q(text: &str) -> Value {
        json!({"model": "ext/mock", "temperature": 0.2, "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": text}]})
    }

    fn last_event(u: &RecentUsage) -> UsageEvent {
        u.snapshot(None, 1).remove(0)
    }

    const LIMITED: (&str, &str) = ("authorization", "Bearer cal_limited");

    #[tokio::test]
    async fn rephrased_question_is_a_semantic_hit_and_metered() {
        let s = setup(Opts::default()).await;
        let (status, h, out) = call(&s.app, "/v1/chat/completions", BEARER, q("What is the capital of France?")).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(h["x-caliban-cache"], "miss");
        assert!(h.get("x-caliban-cache-tier").is_none());
        wait_entries(&s.store, 1).await;
        let calls = upstream_calls(&s.log);

        let (status, h, out) = call(&s.app, "/v1/chat/completions", BEARER, q("what is the capital of france")).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(h["x-caliban-cache"], "hit", "SDKs keep seeing hit | miss | bypass");
        assert_eq!(h["x-caliban-cache-tier"], "semantic");
        assert_eq!(h["x-caliban-cost-usd"], "0.00000000");
        assert_eq!(upstream_calls(&s.log), calls, "served from T2");
        assert_eq!(reply_text(&out), "You said: What is the capital of France?", "the cached answer");

        let e = last_event(&s.usage);
        assert_eq!((e.cache, e.cache_tier), (CacheStatus::Hit, Some(CacheTier::Semantic)));
        assert_eq!((e.prompt_tokens, e.completion_tokens, e.tokens_saved), (0, 0, 19));
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!((json["cache"].as_str(), json["cache_tier"].as_str()), (Some("hit"), Some("semantic")));
        settle().await;
        assert_eq!(s.store.entries()[0].2.stats.hits, 1, "hit counted on the entry");
    }

    #[tokio::test]
    async fn tenant_b_never_gets_tenant_a_entry_for_an_identical_prompt() {
        let s = setup(Opts::default()).await;
        call(&s.app, "/v1/chat/completions", BEARER, q("What is our refund policy?")).await;
        wait_entries(&s.store, 1).await;
        let calls = upstream_calls(&s.log);
        let (status, h, _) = call(&s.app, "/v1/chat/completions", GLOBEX, q("What is our refund policy?")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["x-caliban-cache"], "miss", "identical prompt, other tenant");
        assert_eq!(upstream_calls(&s.log), calls + 1);
        wait_entries(&s.store, 2).await;
        let tenants: std::collections::BTreeSet<String> = s.store.entries().into_iter().map(|(_, _, p)| p.tenant_id).collect();
        assert_eq!(tenants.into_iter().collect::<Vec<_>>(), ["acme", "globex"]);
        // Each tenant now hits only its own entry.
        let (_, h, _) = call(&s.app, "/v1/chat/completions", GLOBEX, q("what is our refund policy")).await;
        assert_eq!(h["x-caliban-cache-tier"], "semantic");
        assert_eq!(last_event(&s.usage).tenant_id, "globex");
    }

    #[tokio::test]
    async fn context_params_numbers_and_people_must_match_exactly() {
        let s = setup(Opts::default()).await;
        call(&s.app, "/v1/chat/completions", BEARER, q("Summarise revenue for 2025")).await;
        wait_entries(&s.store, 1).await;
        // Same vector (the fake ignores numbers), different number: the slot guard keeps them apart.
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, q("Summarise revenue for 2026")).await;
        assert_eq!(h["x-caliban-cache"], "miss");
        // Another system prompt.
        let mut other_sys = q("Summarise revenue for 2025");
        other_sys["messages"][0]["content"] = json!("Be verbose.");
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, other_sys).await;
        assert_eq!(h["x-caliban-cache"], "miss", "system prompt is part of the context hash");
        // Another temperature.
        let mut other_temp = q("Summarise revenue for 2025");
        other_temp["temperature"] = json!(0.1);
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, other_temp).await;
        assert_eq!(h["x-caliban-cache"], "miss", "params are part of the context hash");
        // Earlier turns.
        let mut follow_up = q("Summarise revenue for 2025");
        follow_up["messages"] = json!([{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}, {"role": "user", "content": "Summarise revenue for 2025"}]);
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, follow_up).await;
        assert_eq!(h["x-caliban-cache"], "miss", "history is part of the context hash");
        // Same prompt again: hit.
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, q("summarise revenue for 2025")).await;
        assert_eq!(h["x-caliban-cache-tier"], "semantic");

        // People: the fake embeds both identically (emails are ignored); the surrogate guard
        // keeps an answer about jane from being served for john.
        let (_, _, out) = call(&s.app, "/v1/chat/completions", BEARER, q(PII)).await;
        assert_eq!(reply_text(&out), format!("You said: {PII}"));
        settle().await;
        let n = s.store.len();
        let other = PII.replace(EMAIL, "john.roe@initech.com");
        let (_, h, out) = call(&s.app, "/v1/chat/completions", BEARER, q(&other)).await;
        assert_eq!(h["x-caliban-cache"], "miss");
        assert_eq!(reply_text(&out), format!("You said: {other}"));
        wait_entries(&s.store, n + 1).await;
        // The same person again: hit, rehydrated with this request's own vault.
        let (_, h, out) = call(&s.app, "/v1/chat/completions", BEARER, q(&PII.replace("Email", "email"))).await;
        assert_eq!(h["x-caliban-cache-tier"], "semantic");
        assert_eq!(reply_text(&out), format!("You said: {PII}"));
        // Stored entries hold surrogates only.
        for (_, _, p) in s.store.entries() {
            assert!(!p.response.contains(EMAIL) && !p.response.contains("john.roe"), "{}", p.response);
        }
    }

    #[tokio::test]
    async fn eligibility_rules() {
        let s = setup(Opts::default()).await;
        // Sampling temperature: neither tier applies.
        let mut hot = q("Write a poem about rain");
        hot["temperature"] = json!(1.0);
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, hot.clone()).await;
        assert_eq!(h["x-caliban-cache"], "bypass");
        let mut unset = q("Write a poem about rain");
        unset.as_object_mut().unwrap().remove("temperature");
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, unset).await;
        assert_eq!(h["x-caliban-cache"], "bypass", "unset temperature means sampling");
        // ... unless the request opts in.
        hot["caliban"] = json!({"cache": "semantic"});
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, hot.clone()).await;
        assert_eq!(h["x-caliban-cache"], "miss");
        wait_entries(&s.store, 1).await;
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, hot).await;
        assert_eq!(h["x-caliban-cache-tier"], "semantic");
        // caliban.cache = exact or off: no T2.
        for mode in ["exact", "off"] {
            let mut b = q("write a poem about rain");
            b["caliban"] = json!({"cache": mode});
            let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, b).await;
            assert_ne!(h.get("x-caliban-cache-tier").map(|v| v.to_str().unwrap()), Some("semantic"), "{mode}");
        }
        // Tools, or a tool result in the history.
        let mut tools = q("Weather in Paris?");
        tools["tools"] = json!([{"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object"}}}]);
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, tools).await;
        assert_eq!(h["x-caliban-cache"], "bypass");
        let mut tool_result = q("thanks");
        tool_result["messages"] = json!([{"role": "user", "content": "weather?"}, {"role": "assistant", "content": null, "tool_calls": [{"id": "c", "type": "function", "function": {"name": "w", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "c", "content": "sunny"}, {"role": "user", "content": "thanks"}]);
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, tool_result).await;
        assert_eq!(h["x-caliban-cache"], "bypass");
        // Tenant without the opt-in.
        let (_, h, _) = call(&s.app, "/v1/chat/completions", LIMITED, q("Write a poem about rain")).await;
        assert_eq!(h["x-caliban-cache"], "bypass");
        // Session-scoped surrogates with PII: never stored (could never hit).
        let n = s.store.len();
        let (_, h, _) = call(&s.app, "/v1/chat/completions", SOLO, q(PII)).await;
        assert_eq!(h["x-caliban-cache"], "bypass");
        settle().await;
        assert_eq!(s.store.len(), n);
    }

    #[tokio::test]
    async fn streams_replay_hits_and_streamed_misses_are_cached() {
        let s = setup(Opts::default()).await;
        let stream_text = |out: &str| -> String {
            out.lines()
                .filter_map(|l| l.strip_prefix("data: "))
                .filter_map(|d| serde_json::from_str::<Value>(d).ok())
                .filter_map(|c| c["choices"][0]["delta"]["content"].as_str().map(str::to_owned))
                .collect()
        };
        // A streamed miss is captured and cached.
        let mut b = q(PII);
        b["stream"] = json!(true);
        let (status, h, out) = call(&s.app, "/v1/chat/completions", BEARER, b.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["x-caliban-cache"], "miss");
        assert_eq!(stream_text(&out), format!("You said: {PII}"));
        wait_entries(&s.store, 1).await;
        let stored = &s.store.entries()[0].2;
        assert!(!stored.response.contains(EMAIL), "captured before rehydration: {}", stored.response);
        let calls = upstream_calls(&s.log);

        // Non-streaming hit on the streamed entry.
        let (_, h, out) = call(&s.app, "/v1/chat/completions", BEARER, q(PII)).await;
        assert_eq!(h["x-caliban-cache-tier"], "semantic");
        assert_eq!(reply_text(&out), format!("You said: {PII}"));
        // Streaming hit (rephrased): replayed as SSE, rehydrated, usage chunk included, [DONE].
        b["messages"][1]["content"] = json!(PII.to_lowercase());
        let (status, h, out) = call(&s.app, "/v1/chat/completions", BEARER, b).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["content-type"], "text/event-stream");
        assert_eq!(h["x-caliban-cache-tier"], "semantic");
        assert_eq!(stream_text(&out), format!("You said: {PII}"));
        assert!(out.trim_end().ends_with("data: [DONE]"));
        assert_eq!(upstream_calls(&s.log), calls);
        settle().await;
        let e = last_event(&s.usage);
        assert_eq!((e.cache_tier, e.prompt_tokens, e.tokens_saved), (Some(CacheTier::Semantic), 0, 19), "replayed stream is metered as a hit");

        // Anthropic client on an OpenAI-shaped upstream: stream replay as Anthropic events.
        let ab = json!({"model": "ext/mock", "max_tokens": 64, "temperature": 0, "messages": [{"role": "user", "content": "Name three primary colours"}]});
        call(&s.app, "/v1/messages", ANTH, ab.clone()).await;
        wait_entries(&s.store, 2).await;
        let mut ab = ab;
        ab["stream"] = json!(true);
        ab["messages"][0]["content"] = json!("name three primary colours.");
        let (_, h, out) = call(&s.app, "/v1/messages", ANTH, ab).await;
        let entries: Vec<_> = s.store.entries().into_iter().map(|(_, id, p)| (id, p.route, p.partition, p.stats)).collect();
        assert_eq!(h.get("x-caliban-cache-tier").map(|v| v.to_str().unwrap()), Some("semantic"), "{h:?} {entries:?}");
        let evs = events(&out);
        assert_eq!(streamed_text(&evs), "You said: Name three primary colours");
        assert_eq!(evs.last().unwrap()["type"], "message_stop");
    }

    #[tokio::test]
    async fn native_anthropic_entries_are_stored_pseudonymised_and_replayed() {
        let s = setup(Opts::default()).await;
        let body = json!({"model": "anth/claude", "max_tokens": 50, "temperature": 0.2, "messages": [{"role": "user", "content": PII}]});
        let (_, h, out) = call(&s.app, "/v1/messages", ANTH, body.clone()).await;
        assert_eq!(h["x-caliban-cache"], "miss", "{out}");
        wait_entries(&s.store, 1).await;
        assert!(!s.store.entries()[0].2.response.contains(EMAIL));
        let calls = upstream_calls(&s.log);
        let (_, h, out) = call(&s.app, "/v1/messages", ANTH, body.clone()).await;
        assert_eq!(h["x-caliban-cache-tier"], "semantic");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["content"][0]["text"], format!("You said: {PII}"));
        let mut b = body;
        b["stream"] = json!(true);
        let (_, h, out) = call(&s.app, "/v1/messages", ANTH, b).await;
        assert_eq!(h["x-caliban-cache-tier"], "semantic");
        let evs = events(&out);
        assert_eq!(streamed_text(&evs), format!("You said: {PII}"));
        assert_eq!(evs[0]["message"]["model"], "anth/claude");
        assert_eq!(evs.last().unwrap()["type"], "message_stop");
        assert_eq!(upstream_calls(&s.log), calls);
    }

    #[tokio::test]
    async fn exact_hits_report_the_exact_tier() {
        let s = setup(Opts::default()).await;
        let mut b = q("Define latency");
        b["temperature"] = json!(0);
        call(&s.app, "/v1/chat/completions", BEARER, b.clone()).await;
        wait_entries(&s.store, 1).await;
        assert_eq!(s.embedder.calls.load(Ordering::SeqCst), 1, "one embedding serves the T2 lookup and the insert");
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, b).await;
        assert_eq!((h["x-caliban-cache"].to_str().unwrap(), h["x-caliban-cache-tier"].to_str().unwrap()), ("hit", "exact"));
        assert_eq!(last_event(&s.usage).cache_tier, Some(CacheTier::Exact));
        settle().await;
        assert_eq!(s.embedder.calls.load(Ordering::SeqCst), 1, "a T1 hit embeds nothing");
    }

    #[tokio::test]
    async fn slow_or_failing_dependencies_are_a_miss_within_the_budget() {
        // Embedder slower than the 60 ms budget.
        let s = setup(Opts { budget_ms: 60, embedder: FakeEmbedder { delay: Duration::from_millis(400), ..Default::default() }, ..Default::default() }).await;
        let t0 = Instant::now();
        let (status, h, _) = call(&s.app, "/v1/chat/completions", BEARER, q("Explain HNSW")).await;
        let took = t0.elapsed();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["x-caliban-cache"], "miss");
        assert!(took < Duration::from_millis(350), "did not wait for the embedder: {took:?}");
        // The late embedding is still used to cache the answer.
        wait_entries(&s.store, 1).await;
        assert_eq!(s.embedder.calls.load(Ordering::SeqCst), 1, "one embedding for lookup and insert");

        // Embedder down.
        let s = setup(Opts { embedder: FakeEmbedder { fail: true, ..Default::default() }, ..Default::default() }).await;
        let (status, h, _) = call(&s.app, "/v1/chat/completions", BEARER, q("Explain HNSW")).await;
        assert_eq!((status, h["x-caliban-cache"].to_str().unwrap()), (StatusCode::OK, "miss"));
        settle().await;
        assert!(s.store.is_empty());

        // Vector store slower than the budget.
        let s = setup(Opts { budget_ms: 60, slow_store: Some(Duration::from_millis(400)), ..Default::default() }).await;
        let t0 = Instant::now();
        let (status, h, _) = call(&s.app, "/v1/chat/completions", BEARER, q("Explain HNSW")).await;
        assert_eq!((status, h["x-caliban-cache"].to_str().unwrap()), (StatusCode::OK, "miss"));
        assert!(t0.elapsed() < Duration::from_millis(350));
    }

    #[tokio::test]
    async fn grey_zone_agreement_lowers_an_entry_threshold() {
        let s = setup(Opts::default()).await;
        let prompts = ["alpha question", "beta question", "gamma question", "delta question"];
        {
            let mut o = s.embedder.overrides.lock().unwrap();
            // cos to "alpha": 0.93, 0.935 and 0.94, in orthogonal directions (far from each other).
            o.insert(prompts[0].into(), at(1.0, 10));
            o.insert(prompts[1].into(), at(0.93, 1));
            o.insert(prompts[2].into(), at(0.935, 2));
            o.insert(prompts[3].into(), at(0.94, 3));
            // Every answer embeds the same: the judge calls them equivalent.
            for p in prompts {
                o.insert(format!("You said: {p}"), at(1.0, 9));
            }
        }
        call(&s.app, "/v1/chat/completions", BEARER, q(prompts[0])).await;
        wait_entries(&s.store, 1).await;
        let alpha = s.store.entries()[0].1.clone();
        let stats = || s.store.entries().into_iter().find(|(_, id, _)| *id == alpha).unwrap().2;

        // 0.93 and 0.935: grey zone, answered fresh, verified correct.
        for (i, p) in prompts[1..3].iter().enumerate() {
            let (_, h, out) = call(&s.app, "/v1/chat/completions", BEARER, q(p)).await;
            assert_eq!(h["x-caliban-cache"], "miss");
            assert_eq!(reply_text(&out), format!("You said: {p}"), "fresh answer");
            wait_entries(&s.store, 2 + i).await;
            settle().await;
        }
        let st = stats();
        assert_eq!((st.stats.verified_ok, st.stats.lowest_ok), (2, Some(0.93)));
        assert!((st.threshold - 0.93).abs() < 1e-3, "{}", st.threshold);
        // 0.94 is now served from alpha's entry (it was below the starting 0.95).
        let (_, h, out) = call(&s.app, "/v1/chat/completions", BEARER, q(prompts[3])).await;
        assert_eq!(h["x-caliban-cache-tier"], "semantic");
        assert_eq!(reply_text(&out), "You said: alpha question");
    }

    #[tokio::test]
    async fn a_verified_wrong_answer_raises_the_entry_threshold() {
        let s = setup(Opts { verify_rate: 1.0, ..Default::default() }).await;
        {
            let mut o = s.embedder.overrides.lock().unwrap();
            o.insert("first prompt".into(), at(1.0, 10));
            o.insert("second prompt".into(), at(0.97, 1));
            o.insert("You said: first prompt".into(), at(1.0, 5));
            o.insert("You said: second prompt".into(), at(0.0, 6)); // orthogonal: a different answer
        }
        call(&s.app, "/v1/chat/completions", BEARER, q("first prompt")).await;
        wait_entries(&s.store, 1).await;
        let first = s.store.entries()[0].1.clone();
        // 0.97 >= 0.95 would hit; verify_rate = 1 explores instead and finds a different answer.
        let (_, h, out) = call(&s.app, "/v1/chat/completions", BEARER, q("second prompt")).await;
        assert_eq!(h["x-caliban-cache"], "miss");
        assert_eq!(reply_text(&out), "You said: second prompt");
        wait_entries(&s.store, 2).await;
        settle().await;
        let p = s.store.entries().into_iter().find(|(_, id, _)| *id == first).unwrap().2;
        assert_eq!((p.stats.verified_bad, p.stats.highest_bad), (1, Some(0.97)));
        assert!((p.threshold - 0.975).abs() < 1e-3, "{}", p.threshold);
    }
}

/// Added latency of T2 on a miss, end to end through the gateway: real `ProviderEmbedder` (HTTP to
/// the mock's `/v1/embeddings`, or to a real embedding server at `CALIBAN_TEST_EMBED_URL`; LRU
/// cold) and a real Qdrant. Skipped unless `CALIBAN_TEST_QDRANT_URL` is set; run with
/// `--release -- --nocapture` for meaningful numbers.
#[tokio::test]
async fn semantic_miss_latency_against_qdrant() {
    use semantic::{Opts, setup};
    use std::time::{Duration, Instant};
    let Some(url) = std::env::var("CALIBAN_TEST_QDRANT_URL").ok().filter(|u| !u.is_empty()) else {
        eprintln!("CALIBAN_TEST_QDRANT_URL not set; skipping");
        return;
    };
    let prefix = format!("calgw_{}", uuid::Uuid::new_v4().simple());
    let embed_base = std::env::var("CALIBAN_TEST_EMBED_URL").ok().filter(|u| !u.is_empty());
    eprintln!("embedding server: {}", embed_base.as_deref().unwrap_or("mock (bag of words)"));
    let s = setup(Opts { qdrant: Some(url.clone()), real_embedder: true, embed_base, budget_ms: 50, prefix: prefix.clone(), ..Default::default() }).await;
    // Eight pseudo-random words and a unique number per prompt: the numeric-slot guard keeps every
    // measured request a miss (a real model may still find gibberish prompts similar), while the
    // embedding and the filtered search run in full.
    let words = |i: usize, tag: &str| -> String {
        let w: Vec<String> = (0..8).map(|j| blake3::hash(format!("{tag}-{i}-{j}").as_bytes()).as_bytes()[..6].iter().map(|b| char::from(b'a' + b % 26)).collect()).collect();
        format!("{} {i}", w.join(" "))
    };
    let body = |i: usize, tag: &str| json!({"model": "ext/mock", "temperature": 0.2, "messages": [{"role": "user", "content": words(i, tag)}]});
    // Warm up connections and create the collection.
    for i in 0..20 {
        call(&s.app, "/v1/chat/completions", BEARER, body(i, "warm")).await;
        call(&s.app, "/v1/chat/completions", ("authorization", "Bearer cal_limited"), body(i, "warm")).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let n = 300;
    let mut on = Vec::new();
    let mut off = Vec::new();
    for i in 0..n {
        let t0 = Instant::now();
        let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, body(i, "measure")).await;
        on.push(t0.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(h["x-caliban-cache"], "miss");
        let t0 = Instant::now();
        let (_, h, _) = call(&s.app, "/v1/chat/completions", ("authorization", "Bearer cal_limited"), body(i, "measure")).await;
        off.push(t0.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(h["x-caliban-cache"], "bypass");
    }
    let pct = |v: &mut Vec<f64>, p: f64| {
        v.sort_by(f64::total_cmp);
        v[((v.len() as f64 - 1.0) * p) as usize]
    };
    let (on50, on99, off50, off99) = (pct(&mut on, 0.5), pct(&mut on, 0.99), pct(&mut off, 0.5), pct(&mut off, 0.99));
    eprintln!("miss with T2 (embed over HTTP + Qdrant search): p50 {on50:.2} ms, p99 {on99:.2} ms");
    eprintln!("same request without T2:                       p50 {off50:.2} ms, p99 {off99:.2} ms");
    eprintln!("added on a miss: p50 {:.2} ms, p99 {:.2} ms", on50 - off50, on99 - off99);

    // And the hit path through Qdrant works end to end.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (_, h, _) = call(&s.app, "/v1/chat/completions", BEARER, body(3, "measure")).await;
    assert_eq!(h["x-caliban-cache-tier"], "semantic");
    let http = reqwest::Client::new();
    let v: Value = http.get(format!("{url}/collections")).send().await.unwrap().json().await.unwrap();
    for c in v["result"]["collections"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        if name.starts_with(&prefix) {
            http.delete(format!("{url}/collections/{name}")).send().await.unwrap();
        }
    }
}

// ─────────────── caliban/auto: Stage-1 kNN, quality floors, metering ───────────────

mod auto_routing {
    use super::*;
    use crate::route_embed;
    use caliban_cache::semantic::MemoryStore;
    use caliban_types::{CacheStatus, CacheTier};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    /// OpenAI-compatible `/v1/embeddings` returning `caliban_route::hash_embed` vectors after
    /// `delay_ms` (shared, so a test can slow the embedder down after warm-up). Every input text
    /// is recorded in `seen`.
    async fn mock_embedder(delay_ms: Arc<AtomicU64>, seen: Arc<Mutex<Vec<String>>>) -> String {
        let app = Router::new().route(
            "/v1/embeddings",
            post(move |Json(b): Json<Value>| {
                let delay = Duration::from_millis(delay_ms.load(Ordering::SeqCst));
                let seen = Arc::clone(&seen);
                async move {
                    tokio::time::sleep(delay).await;
                    let inputs: Vec<String> = match &b["input"] {
                        Value::String(s) => vec![s.clone()],
                        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect(),
                        _ => vec![],
                    };
                    seen.lock().unwrap().extend(inputs.iter().cloned());
                    let data: Vec<Value> =
                        inputs.iter().enumerate().map(|(i, t)| json!({"object": "embedding", "index": i, "embedding": caliban_route::hash_embed(t, 256)})).collect();
                    Json(json!({"object": "list", "data": data, "model": b["model"], "usage": {"prompt_tokens": 1, "total_tokens": 1}}))
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}/v1")
    }

    struct Env {
        app: Router,
        gw: Arc<Gateway>,
        usage: RecentUsage,
        delay: Arc<AtomicU64>,
        /// Texts the embedding server received.
        seen: Arc<Mutex<Vec<String>>>,
        /// T2 store (used when `routing` also turns `[cache.semantic]` on).
        store: Arc<MemoryStore>,
    }

    async fn setup(routing: &str) -> Env {
        let (base, _log) = mock_upstream().await;
        let delay = Arc::new(AtomicU64::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let emb = mock_embedder(delay.clone(), Arc::clone(&seen)).await;
        let toml = format!(
            r#"
[routing]
embedding_model = "emb/mock"
auto_price_in_per_mtok = 10.0
auto_price_out_per_mtok = 20.0
{routing}
[routing.floors]
translate = 0.5
[routing.quality."ext/mock"]
translate = 0.9
[routing.quality."local/mock"]
translate = 0.4

[[providers]]
id = "embedder"
kind = "openai_compatible"
base_url = "{emb}"
trust_tier = "t0_sovereign"

[[models]]
id = "emb/mock"
provider = "embedder"
upstream_model = "hash-256"
kind = "embedding"
trust_tier = "t0_sovereign"

[[models]]
id = "ext/mock"
provider = "mockext"
upstream_model = "mock-external"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0

[[models]]
id = "local/mock"
provider = "mocklocal"
upstream_model = "mock-local"
trust_tier = "t0_sovereign"
price_in_per_mtok = 0.0
price_out_per_mtok = 0.0

[[tenants]]
id = "acme"
name = "Acme"
semantic_cache = "on"
api_key_hashes = ["{acme}"]
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  [[tenants.providers]]
  id = "mocklocal"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t0_sovereign"
  [[tenants.routes]]
  intent = "default"
  models = ["local/mock", "ext/mock"]
  [[tenants.routes]]
  intent = "translate"
  models = ["local/mock", "ext/mock"]
"#,
            acme = hash("cal_acme"),
        );
        let usage = RecentUsage::default();
        let store = Arc::new(MemoryStore::default());
        let gw = Arc::new(
            Gateway::new(ConfigHandle::new(Snapshot::new(Config::from_toml_str(&toml).unwrap(), "test")), Arc::new(usage.clone())).with_semantic_store(store.clone()),
        );
        gw.warm_router().await;
        assert!(gw.router.knn_ready(), "kNN index built from the mock embedder");
        Env { app: app(Arc::clone(&gw)), gw, usage, delay, seen, store }
    }

    const TRANSLATE: &str = "please translate this paragraph into french for me";

    fn auto(text: &str, stream: bool) -> Value {
        json!({"model": "caliban/auto", "stream": stream, "messages": [{"role": "user", "content": text}]})
    }

    #[tokio::test]
    async fn auto_reports_intent_and_meters_routed_cost_next_to_flat_price() {
        let env = setup("").await;
        let (status, h, _) = call(&env.app, "/v1/chat/completions", BEARER, auto(TRANSLATE, false)).await;
        assert_eq!(status, StatusCode::OK);
        let intent = h["x-caliban-intent"].to_str().unwrap();
        assert!(intent.starts_with("translate;confidence=") && intent.ends_with(";stage=knn"), "{intent}");
        // local/mock (0.4) is below the translate floor (0.5): the cheapest qualifying model.
        assert_eq!(h["x-caliban-routed-model"], "ext/mock");

        let ev = env.usage.snapshot(Some("acme"), 1).pop().unwrap();
        assert_eq!((ev.intent.as_str(), ev.requested_model.as_deref(), ev.route_stage.as_deref()), ("translate", Some("caliban/auto"), Some("knn")));
        // Mock usage: 12 prompt + 7 completion tokens.
        let routed = (12.0 * 1.0 + 7.0 * 2.0) / 1e6;
        let flat = (12.0 * 10.0 + 7.0 * 20.0) / 1e6;
        assert!((ev.routed_model_cost_usd.unwrap() - routed).abs() < 1e-12);
        assert!((ev.flat_price_usd.unwrap() - flat).abs() < 1e-12);
        assert!((ev.margin_usd().unwrap() - (flat - routed)).abs() < 1e-12);
        assert_eq!(ev.cost_usd, ev.routed_model_cost_usd);
        let json = serde_json::to_value(&ev).unwrap();
        assert!(json.get("flat_price_usd").is_some() && json.get("routed_model_cost_usd").is_some());

        // Streams carry the header too, and settle the same fields.
        let (status, h, _) = call(&env.app, "/v1/chat/completions", BEARER, auto(TRANSLATE, true)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(h["x-caliban-intent"].to_str().unwrap().starts_with("translate;"));
        let ev = env.usage.snapshot(Some("acme"), 1).pop().unwrap();
        assert!(ev.flat_price_usd.is_some() && ev.routed_model_cost_usd.is_some());
        // Anthropic dialect too.
        let (status, h, _) = call(&env.app, "/v1/messages", ANTH, json!({"model": "caliban/auto", "max_tokens": 64, "messages": [{"role": "user", "content": TRANSLATE}]})).await;
        assert_eq!(status, StatusCode::OK);
        assert!(h.contains_key("x-caliban-intent"));
    }

    #[tokio::test]
    async fn embedder_timeout_falls_back_to_the_rules_router() {
        let env = setup("budget_ms = 20").await;
        env.delay.store(300, Ordering::SeqCst);
        let started = Instant::now();
        let (status, h, _) = call(&env.app, "/v1/chat/completions", BEARER, auto("summarize this email thread for me", false)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(started.elapsed() < Duration::from_millis(300), "request waited for the slow embedder: {:?}", started.elapsed());
        let intent = h["x-caliban-intent"].to_str().unwrap();
        assert!(intent.starts_with("summarize;") && intent.ends_with(";stage=keyword;knn=timeout"), "{intent}");
        let ev = env.usage.snapshot(Some("acme"), 1).pop().unwrap();
        assert_eq!(ev.route_stage.as_deref(), Some("keyword"));
        assert!(ev.flat_price_usd.is_some());
    }

    #[tokio::test]
    async fn pinned_models_are_not_metered_against_the_flat_price() {
        let env = setup("").await;
        let (status, h, _) = call(&env.app, "/v1/chat/completions", BEARER, json!({"model": "ext/mock", "messages": [{"role": "user", "content": TRANSLATE}]})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["x-caliban-intent"], "pinned;confidence=1.000;stage=rules");
        let ev = env.usage.snapshot(Some("acme"), 1).pop().unwrap();
        assert_eq!((ev.requested_model.as_deref(), ev.route_stage.as_deref()), (Some("ext/mock"), Some("rules")));
        assert!(ev.routed_model_cost_usd.is_none() && ev.flat_price_usd.is_none() && ev.cost_usd.is_some());
        let json = serde_json::to_value(&ev).unwrap();
        assert!(json.get("flat_price_usd").is_none(), "absent, not null, for older consumers");
    }

    /// `[cache.semantic]` on, with the routing embedding model (the `[routing]` slot of `setup`
    /// is followed by other tables, so a whole table fits there).
    const WITH_T2: &str = "[cache.semantic]\nenabled = true\nstore = \"memory\"\nembedding_model = \"emb/mock\"\nlookup_budget_ms = 2000\n";

    /// Routing (Stage-1 kNN, shared provider) and T2 (tenant route to the same model and endpoint)
    /// embed the same prompt in one request: the embedder is called once for it.
    #[tokio::test]
    async fn routing_and_semantic_cache_embed_a_prompt_once() {
        let env = setup(WITH_T2).await;
        let prompt = "please translate the quarterly roadmap memo into german";
        let body = json!({"model": "caliban/auto", "temperature": 0.2, "messages": [{"role": "user", "content": prompt}]});
        let (status, h, _) = call(&env.app, "/v1/chat/completions", BEARER, body).await;
        assert_eq!(status, StatusCode::OK);
        assert!(h["x-caliban-intent"].to_str().unwrap().contains(";stage=knn"), "kNN embedded the prompt");
        assert_eq!(h["x-caliban-cache"], "miss", "T2 applied and looked up");
        for _ in 0..200 {
            if !env.store.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(env.store.len(), 1, "T2 stored the answer under the prompt vector");
        let times = env.seen.lock().unwrap().iter().filter(|t| t.as_str() == prompt).count();
        assert_eq!(times, 1, "one upstream embedding for routing and T2 together");
    }

    /// Both cache tiers meter a `caliban/auto` hit the same way: no tokens, zero routed cost and
    /// zero flat price (whether a hit should charge the flat price is an open pricing question),
    /// and the answer's tokens as `tokens_saved`.
    #[tokio::test]
    async fn exact_and_semantic_hits_meter_auto_the_same_way() {
        let env = setup(WITH_T2).await;
        let ask = |temperature: f64| json!({"model": "caliban/auto", "temperature": temperature, "messages": [{"role": "user", "content": TRANSLATE}]});
        for (temperature, tier) in [(0.0, CacheTier::Exact), (0.2, CacheTier::Semantic)] {
            let (_, h, _) = call(&env.app, "/v1/chat/completions", BEARER, ask(temperature)).await;
            assert_eq!(h["x-caliban-cache"], "miss");
            let miss = env.usage.snapshot(Some("acme"), 1).pop().unwrap();
            assert!(miss.flat_price_usd.unwrap() > 0.0);
            for _ in 0..200 {
                let (_, h, _) = call(&env.app, "/v1/chat/completions", BEARER, ask(temperature)).await;
                if h["x-caliban-cache"] == "hit" {
                    assert_eq!(h["x-caliban-cache-tier"], tier.as_str());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let hit = env.usage.snapshot(Some("acme"), 1).pop().unwrap();
            assert_eq!((hit.cache, hit.cache_tier), (CacheStatus::Hit, Some(tier)), "{tier:?}");
            assert_eq!(hit.requested_model.as_deref(), Some("caliban/auto"));
            assert_eq!((hit.prompt_tokens, hit.completion_tokens), (0, 0), "{tier:?}");
            assert_eq!(hit.tokens_saved, miss.prompt_tokens + miss.completion_tokens, "{tier:?}: saved tokens recorded");
            assert_eq!((hit.cost_usd, hit.routed_model_cost_usd, hit.flat_price_usd), (Some(0.0), Some(0.0), Some(0.0)), "{tier:?}");
            assert_eq!(hit.margin_usd(), Some(0.0));
        }
    }

    /// Added routing latency through the real adapter (HTTP to a local mock embedder) versus the
    /// keyword rules alone. `cargo test --release -p caliban-gateway knn_latency -- --nocapture`.
    #[tokio::test]
    async fn knn_latency_over_http_report() {
        let env = setup("").await;
        let snap = env.gw.config.load();
        let tenant = snap.tenant(&"acme".into()).unwrap().clone();
        let prompts = [TRANSLATE, "write a python function to parse dates", "top customers by revenue last quarter", "hello there"];
        let n = 200;
        let measure = |knn: bool| {
            let (gw, snap, tenant) = (Arc::clone(&env.gw), Arc::clone(&snap), tenant.clone());
            async move {
                let mut t = Vec::with_capacity(n);
                for i in 0..n {
                    let req = caliban_ir::ChatRequest::from_openai_json(auto(prompts[i % prompts.len()], false).to_string().as_bytes()).unwrap();
                    let started = Instant::now();
                    let d = if knn {
                        route_embed::route(&gw, &snap, &tenant, &req).await.unwrap()
                    } else {
                        gw.router.route(&snap, &tenant, &req, caliban_route::Constraints::default()).unwrap()
                    };
                    t.push(started.elapsed());
                    assert_eq!(d.stage == "knn", knn);
                }
                t.sort();
                (t[n / 2], t[n * 99 / 100])
            }
        };
        let (k50, k99) = measure(true).await;
        let (r50, r99) = measure(false).await;
        println!("routing over HTTP mock embedder: knn p50 {k50:?} p99 {k99:?}; rules only p50 {r50:?} p99 {r99:?}");
        assert!(k99 < Duration::from_millis(25), "p99 {k99:?}");
    }
}
