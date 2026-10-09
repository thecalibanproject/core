//! Metering accuracy, end to end through the gateway app against an in-process mock upstream:
//! stream usage is always requested upstream and hidden from clients that did not ask for it,
//! disconnected and usage-less streams are metered from an estimate (`usage_source`), and cost
//! applies prompt-cache prices.

use crate::{Gateway, app};
use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use caliban_config::{Config, ConfigHandle, Snapshot};
use caliban_meter::{JsonlSink, RecentUsage, Tee, UsageEvent, UsageSink, UsageSource};
use futures::StreamExt;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

type Seen = Arc<Mutex<Vec<Value>>>;

fn sse_body(frames: Vec<String>, delay: Duration) -> Response {
    let s = futures::stream::iter(frames).then(move |f| async move {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        Ok::<_, std::io::Error>(axum::body::Bytes::from(f))
    });
    Response::builder().header("content-type", "text/event-stream").body(Body::from_stream(s)).unwrap()
}

/// OpenAI-compatible upstream. `usage-final`: a short stream; `slow`: 40 chunks 15 ms apart;
/// `no-stream-options`: rejects requests that carry `stream_options` (and sends no usage).
/// Usage follows OpenAI: with `include_usage`, every chunk has `"usage": null` and a final
/// usage-only chunk carries the numbers.
fn openai(b: &Value) -> Response {
    let model = b["model"].as_str().unwrap_or_default().to_owned();
    let include = b.pointer("/stream_options/include_usage").and_then(Value::as_bool) == Some(true);
    if model == "no-stream-options" && b.get("stream_options").is_some() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": {"message": "unknown field stream_options"}})))
            .into_response();
    }
    let n = if model == "slow" { 40 } else { 3 };
    let delay = if model == "slow" { Duration::from_millis(15) } else { Duration::ZERO };
    let chunk = |delta: Value, finish: Value| {
        let mut c = json!({"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]});
        if include {
            c["usage"] = Value::Null;
        }
        format!("data: {c}\n\n")
    };
    let mut frames: Vec<String> = (0..n).map(|_| chunk(json!({"content": "abcd"}), Value::Null)).collect();
    frames.push(chunk(json!({}), json!("stop")));
    if include && model != "no-stream-options" {
        let u = json!({"id": "c1", "object": "chat.completion.chunk", "model": model, "choices": [],
            "usage": {"prompt_tokens": 20, "completion_tokens": n, "total_tokens": 20 + n, "prompt_tokens_details": {"cached_tokens": 8}}});
        frames.push(format!("data: {u}\n\n"));
    }
    frames.push("data: [DONE]\n\n".into());
    sse_body(frames, delay)
}

/// Anthropic upstream. Streams: 40 deltas 15 ms apart; `cache`: a JSON reply with prompt-cache
/// reads and writes of both TTLs.
fn anthropic(b: &Value) -> Response {
    let model = b["model"].clone();
    if b["stream"] == true {
        let ev = |e: Value| caliban_ir::anthropic::sse_event(&e);
        let mut frames = vec![ev(
            json!({"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": model, "content": [],
            "usage": {"input_tokens": 30, "cache_read_input_tokens": 10, "output_tokens": 1}}}),
        )];
        frames.push(ev(
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ));
        for _ in 0..40 {
            frames.push(ev(
                json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "abcd"}}),
            ));
        }
        frames.push(ev(json!({"type": "content_block_stop", "index": 0})));
        frames.push(ev(
            json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 40}}),
        ));
        frames.push(ev(json!({"type": "message_stop"})));
        return sse_body(frames, Duration::from_millis(15));
    }
    Json(json!({"id": "msg_1", "type": "message", "role": "assistant", "model": model, "content": [{"type": "text", "text": "ok"}],
        "stop_reason": "end_turn", "stop_sequence": null,
        "usage": {"input_tokens": 10, "cache_read_input_tokens": 100, "cache_creation_input_tokens": 50,
                  "cache_creation": {"ephemeral_5m_input_tokens": 20, "ephemeral_1h_input_tokens": 30}, "output_tokens": 5}}))
    .into_response()
}

async fn mock() -> (String, Seen) {
    let seen = Seen::default();
    let (s1, s2) = (seen.clone(), seen.clone());
    let app = Router::new()
        .route(
            "/v1/chat/completions",
            post(move |Json(b): Json<Value>| async move {
                s1.lock().unwrap().push(b.clone());
                openai(&b)
            }),
        )
        .route(
            "/v1/messages",
            post(move |Json(b): Json<Value>| async move {
                s2.lock().unwrap().push(b.clone());
                anthropic(&b)
            }),
        );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (format!("http://{addr}/v1"), seen)
}

struct Env {
    app: Router,
    usage: RecentUsage,
    seen: Seen,
    wal: Arc<JsonlSink>,
    wal_path: std::path::PathBuf,
}

async fn setup() -> Env {
    let (base, seen) = mock().await;
    let dir = std::env::temp_dir().join(format!("caliban-metering-{}", uuid::Uuid::now_v7().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = dir.join("anthropic-key");
    std::fs::write(&key_file, "sk-ant-test").unwrap();
    let toml = format!(
        r#"
[[models]]
id = "oa/final"
provider = "oa"
upstream_model = "usage-final"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0
price_cache_read_per_mtok = 0.5

[[models]]
id = "oa/slow"
provider = "oa"
upstream_model = "slow"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0

[[models]]
id = "oa/noso"
provider = "oa"
upstream_model = "no-stream-options"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0
[models.capabilities]
rejects_stream_options = true

[[models]]
id = "an/slow"
provider = "an"
upstream_model = "slow"
trust_tier = "t2_contracted"
price_in_per_mtok = 3.0
price_out_per_mtok = 15.0

[[models]]
id = "an/cache"
provider = "an"
upstream_model = "cache"
trust_tier = "t2_contracted"
price_in_per_mtok = 3.0
price_out_per_mtok = 15.0
price_cache_read_per_mtok = 0.3
price_cache_write_per_mtok = 3.75
price_cache_write_1h_per_mtok = 6.0

[[tenants]]
id = "acme"
name = "Acme"
api_key_hashes = ["{hash}"]
  [[tenants.providers]]
  id = "oa"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  [[tenants.providers]]
  id = "an"
  kind = "anthropic"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  api_key = {{ file = "{key}" }}
"#,
        hash = caliban_types::hash_api_key("cal_meter"),
        key = key_file.display(),
    );
    let cfg = Config::from_toml_str(&toml).unwrap();
    let usage = RecentUsage::default();
    let wal_path = dir.join("usage.jsonl");
    let wal = Arc::new(JsonlSink::new(&wal_path));
    let sink: Arc<dyn UsageSink> = Arc::new(Tee(vec![Arc::new(usage.clone()), Arc::clone(&wal) as Arc<dyn UsageSink>]));
    let gw = Gateway::new(ConfigHandle::new(Snapshot::new(cfg, "test")), sink);
    Env { app: app(Arc::new(gw)), usage, seen, wal, wal_path }
}

fn request(path: &str, body: &Value) -> Request<Body> {
    Request::post(path)
        .header("authorization", "Bearer cal_meter")
        .header("content-type", "application/json")
        .header("anthropic-version", "2023-06-01")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn call(env: &Env, path: &str, body: Value) -> (StatusCode, String) {
    let resp = env.app.clone().oneshot(request(path, &body)).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Reads `frames` body frames of a streaming response, then drops it (the client goes away).
async fn call_and_disconnect(env: &Env, path: &str, body: Value, frames: usize) -> String {
    let resp = env.app.clone().oneshot(request(path, &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut s = resp.into_body().into_data_stream();
    let mut got = String::new();
    for _ in 0..frames {
        let b = s.next().await.expect("a frame").unwrap();
        got.push_str(&String::from_utf8_lossy(&b));
    }
    got
}

/// The `n`-th most recent usage event (1 = the last), waiting for streams to settle.
async fn event(env: &Env, count: usize) -> UsageEvent {
    for _ in 0..300 {
        let all = env.usage.snapshot(None, usize::MAX);
        if all.len() >= count {
            return all[0].clone();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {count} usage events");
}

fn chat(model: &str, extra: Value) -> Value {
    let mut b =
        json!({"model": model, "stream": true, "messages": [{"role": "user", "content": "count me in please"}]});
    if let (Some(o), Some(e)) = (b.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    b
}

#[tokio::test]
async fn stream_usage_is_requested_upstream_and_shown_only_when_asked() {
    let env = setup().await;
    for (i, (extra, wants)) in [
        (json!({}), false),
        (json!({"stream_options": {"include_usage": false}}), false),
        (json!({"stream_options": {"include_usage": true}}), true),
    ]
    .into_iter()
    .enumerate()
    {
        let (status, out) = call(&env, "/v1/chat/completions", chat("oa/final", extra.clone())).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let sent = env.seen.lock().unwrap().last().cloned().unwrap();
        assert_eq!(sent["stream_options"]["include_usage"], true, "case {i}: usage always requested upstream");

        let chunks: Vec<Value> =
            out.lines().filter_map(|l| l.strip_prefix("data: ")).filter_map(|d| serde_json::from_str(d).ok()).collect();
        assert!(out.ends_with("data: [DONE]\n\n"), "case {i}: {out}");
        if wants {
            assert!(
                chunks.iter().any(|c| c["usage"]["prompt_tokens"] == 20),
                "case {i}: the client asked for usage: {out}"
            );
        } else {
            assert!(
                chunks.iter().all(|c| c.get("usage").is_none()),
                "case {i}: no usage field at all, not even null: {out}"
            );
            assert!(
                chunks.iter().all(|c| !c["choices"].as_array().unwrap().is_empty()),
                "case {i}: the usage-only chunk is dropped"
            );
        }
        assert_eq!(
            chunks.iter().filter_map(|c| c.pointer("/choices/0/delta/content")).count(),
            3,
            "case {i}: content intact"
        );

        let e = event(&env, i + 1).await;
        assert_eq!(
            (e.prompt_tokens, e.completion_tokens, e.cached_prompt_tokens),
            (20, 3, 8),
            "case {i}: metered from the provider's usage"
        );
        assert_eq!(e.usage_source, Some(UsageSource::Provider));
        // 12 uncached at 1.0, 8 cached at 0.5, 3 out at 2.0.
        assert!((e.cost_usd.unwrap() - (12.0 + 8.0 * 0.5 + 3.0 * 2.0) / 1e6).abs() < 1e-12);
    }
}

#[tokio::test]
async fn a_client_disconnect_is_metered_as_an_estimate() {
    let env = setup().await;
    // OpenAI-shaped stream: a few chunks, then the client goes away.
    let got = call_and_disconnect(&env, "/v1/chat/completions", chat("oa/slow", json!({})), 3).await;
    assert!(got.contains("abcd"));
    let e = event(&env, 1).await;
    assert_eq!(e.usage_source, Some(UsageSource::Estimated));
    assert!(e.prompt_tokens > 0, "the prompt estimate, not 0");
    assert!(
        e.completion_tokens >= 1 && e.completion_tokens < 40,
        "estimated from what was streamed: {}",
        e.completion_tokens
    );
    assert!(e.cost_usd.unwrap() > 0.0);

    // Native Anthropic stream: `message_start` gave the exact prompt (30 + 10 cached), output is
    // estimated from the deltas streamed before the disconnect.
    let body =
        json!({"model": "an/slow", "max_tokens": 64, "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let got = call_and_disconnect(&env, "/v1/messages", body, 4).await;
    assert!(got.contains("message_start"));
    let e = event(&env, 2).await;
    assert_eq!(e.model, "an/slow");
    assert_eq!(e.usage_source, Some(UsageSource::Estimated));
    assert_eq!((e.prompt_tokens, e.cached_prompt_tokens), (40, 10), "prompt from the provider's message_start");
    assert!(e.completion_tokens >= 1 && e.completion_tokens < 40, "{}", e.completion_tokens);
}

#[tokio::test]
async fn complete_streams_are_metered_from_the_provider() {
    let env = setup().await;
    let body =
        json!({"model": "an/slow", "max_tokens": 64, "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let (status, _) = call(&env, "/v1/messages", body).await;
    assert_eq!(status, StatusCode::OK);
    let e = event(&env, 1).await;
    assert_eq!((e.prompt_tokens, e.completion_tokens, e.usage_source), (40, 40, Some(UsageSource::Provider)));
}

#[tokio::test]
async fn servers_that_reject_stream_options_are_estimated_and_flagged() {
    let env = setup().await;
    let (status, out) =
        call(&env, "/v1/chat/completions", chat("oa/noso", json!({"stream_options": {"include_usage": true}}))).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let sent = env.seen.lock().unwrap().last().cloned().unwrap();
    assert!(sent.get("stream_options").is_none(), "not sent to a server that rejects it");
    let e = event(&env, 1).await;
    assert_eq!(e.usage_source, Some(UsageSource::Estimated));
    assert!(e.prompt_tokens > 0);
    assert_eq!(e.completion_tokens, 3, "3 x 4 bytes streamed");
}

#[tokio::test]
async fn cost_applies_prompt_cache_prices_and_the_wal_records_it() {
    let env = setup().await;
    let body = json!({"model": "an/cache", "max_tokens": 64, "messages": [{"role": "user", "content": "hi"}]});
    let resp = env.app.clone().oneshot(request("/v1/messages", &body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let header: f64 = resp.headers()["x-caliban-cost-usd"].to_str().unwrap().parse().unwrap();
    let e = event(&env, 1).await;
    assert_eq!(
        (e.prompt_tokens, e.cached_prompt_tokens, e.cache_write_tokens, e.cache_write_1h_tokens),
        (160, 100, 50, 30)
    );
    // 10 uncached at 3.0, 100 reads at 0.3, 20 five-minute writes at 3.75, 30 one-hour writes at 6.0, 5 out at 15.
    let want = (10.0 * 3.0 + 100.0 * 0.3 + 20.0 * 3.75 + 30.0 * 6.0 + 5.0 * 15.0) / 1e6;
    assert!((e.cost_usd.unwrap() - want).abs() < 1e-12, "{:?} vs {want}", e.cost_usd);
    assert!((header - want).abs() < 1e-8, "the cost header uses the same function");

    env.wal.flush().await;
    let wal = caliban_meter::read_wal(&env.wal_path).unwrap();
    assert_eq!(wal.last().unwrap(), &e, "the WAL line round-trips to the same event");

    let resp = env.app.clone().oneshot(Request::get("/healthz").body(Body::empty()).unwrap()).await.unwrap();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let health: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(health["usage_wal"]["written"], 1);
    assert_eq!(health["usage_wal"]["dropped"], 0);
}
