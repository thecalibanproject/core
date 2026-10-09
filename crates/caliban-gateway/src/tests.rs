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

// ─────────────── caliban/auto: Stage-1 kNN, quality floors, metering ───────────────

mod auto_routing {
    use super::*;
    use crate::route_embed;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    /// OpenAI-compatible `/v1/embeddings` returning `caliban_route::hash_embed` vectors after
    /// `delay_ms` (shared, so a test can slow the embedder down after warm-up).
    async fn mock_embedder(delay_ms: Arc<AtomicU64>) -> String {
        let app = Router::new().route(
            "/v1/embeddings",
            post(move |Json(b): Json<Value>| {
                let delay = Duration::from_millis(delay_ms.load(Ordering::SeqCst));
                async move {
                    tokio::time::sleep(delay).await;
                    let inputs: Vec<String> = match &b["input"] {
                        Value::String(s) => vec![s.clone()],
                        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect(),
                        _ => vec![],
                    };
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
    }

    async fn setup(routing: &str) -> Env {
        let (base, _log) = mock_upstream().await;
        let delay = Arc::new(AtomicU64::new(0));
        let emb = mock_embedder(delay.clone()).await;
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
        let gw = Arc::new(Gateway::new(ConfigHandle::new(Snapshot::new(Config::from_toml_str(&toml).unwrap(), "test")), Arc::new(usage.clone())));
        gw.warm_router().await;
        assert!(gw.router.knn_ready(), "kNN index built from the mock embedder");
        Env { app: app(Arc::clone(&gw)), gw, usage, delay }
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
