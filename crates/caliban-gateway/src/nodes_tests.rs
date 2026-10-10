//! The executor's model calls through the pipeline, and the run API's guards. The end-to-end node
//! tests (workers, crash and replay, split mode, usage shipping, the reference node) are in
//! `apps/caliban/src/nodes_tests.rs`.

use crate::nodes::{GatewayModels, LocalRuns, NodeRuns};
use crate::{Gateway, app};
use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use caliban_config::{Config, ConfigHandle, Snapshot};
use caliban_meter::RecentUsage;
use caliban_nodes::executor::{CallCtx, ExecutorOptions, ModelClient, ModelError, NoTools, idempotency_key};
use caliban_nodes::journal::memory::MemoryJournal;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

const KEY: &str = "cal_nodes_gateway_test_key_000000";
const OTHER: &str = "cal_nodes_gateway_other_key_00000";

/// An upstream that echoes the last user message and logs every body it receives.
async fn upstream() -> (String, Arc<Mutex<Vec<Value>>>) {
    let log: Arc<Mutex<Vec<Value>>> = Arc::default();
    let l = Arc::clone(&log);
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(b): Json<Value>| async move {
            l.lock().unwrap().push(b.clone());
            let text = b["messages"].as_array().and_then(|m| m.last()).map(|m| m["content"].clone()).unwrap_or_default();
            Json(json!({"id": "x", "object": "chat.completion", "model": b["model"],
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": format!("echo: {}", text.as_str().unwrap_or_default())}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 11, "completion_tokens": 4, "total_tokens": 15}}))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/v1"), log)
}

fn config(upstream: &str) -> Config {
    Config::from_toml_str(&format!(
        r#"
[[models]]
id = "ext/m"
provider = "ext"
upstream_model = "m"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0

[[tenants]]
id = "acme"
name = "Acme"
pii_mode = "mask"
api_key_hashes = ["{a}", "{b}"]
  [[tenants.providers]]
  id = "ext"
  kind = "openai_compatible"
  base_url = "{upstream}"
  trust_tier = "t2_contracted"
  [[tenants.routes]]
  intent = "default"
  models = ["ext/m"]
"#,
        a = caliban_types::hash_api_key(KEY),
        b = caliban_types::hash_api_key(OTHER),
    ))
    .unwrap()
}

fn ctx(step: &str, key: &str) -> CallCtx {
    CallCtx {
        tenant: "acme".into(),
        invoker_key_hash: Some(caliban_types::hash_api_key(key)),
        run_id: "run_1".into(),
        step_id: step.into(),
        idempotency_key: idempotency_key("run_1", step),
    }
}

fn body(text: &str) -> Value {
    json!({"model": "ext/m", "messages": [{"role": "user", "content": text}], "temperature": 0, "max_tokens": 32})
}

#[tokio::test]
async fn node_model_calls_go_through_the_pipeline_once_per_step() {
    let (url, log) = upstream().await;
    let ring = RecentUsage::default();
    let gw = Arc::new(Gateway::new(ConfigHandle::new(Snapshot::new(config(&url), "t")), Arc::new(ring.clone())));
    let models = GatewayModels::new(&gw);

    // PII is masked before the external model sees it; the reply is metered for the tenant.
    let r = models.chat(&ctx("ask#0", KEY), body("Mail jane.doe@acme.com about the invoice")).await.unwrap();
    assert_eq!((r.tokens, r.replayed), (15, false));
    assert!(r.usd > 0.0, "priced by the pipeline: {}", r.usd);
    let sent = log.lock().unwrap()[0].to_string();
    assert!(!sent.contains("jane.doe@acme.com"), "{sent}");
    let events = ring.snapshot(Some("acme"), 10);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].model, "ext/m");

    // The same step again (a replay after a worker died): the stored response, nothing paid.
    let again = models.chat(&ctx("ask#0", KEY), body("Mail jane.doe@acme.com about the invoice")).await.unwrap();
    assert!(again.replayed);
    assert_eq!(again.message, r.message);
    assert_eq!(log.lock().unwrap().len(), 1, "the upstream saw the step once");
    assert_eq!(ring.snapshot(Some("acme"), 10).len(), 1, "metered once");
    // Another step is another call.
    models.chat(&ctx("ask#1", KEY), body("next")).await.unwrap();
    assert_eq!(log.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn node_model_calls_stop_when_the_invoking_key_is_revoked() {
    let (url, _) = upstream().await;
    let cfg = config(&url);
    let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "t"));
    let gw = Arc::new(Gateway::new(handle.clone(), Arc::new(RecentUsage::default())));
    let models = GatewayModels::new(&gw);
    models.chat(&ctx("a#0", OTHER), body("hi")).await.unwrap();
    let mut revoked = cfg;
    revoked.tenants[0].api_key_hashes.retain(|h| *h != caliban_types::hash_api_key(OTHER));
    handle.store(Snapshot::new(revoked, "t2"));
    let e = models.chat(&ctx("a#1", OTHER), body("hi")).await.unwrap_err();
    assert!(matches!(e, ModelError::Rejected(ref m) if m.starts_with("401")), "{e:?}");
    // A caller set in-process cannot claim another tenant.
    let mut c = ctx("a#2", KEY);
    c.tenant = "globex".into();
    assert!(matches!(models.chat(&c, body("hi")).await.unwrap_err(), ModelError::Rejected(_)));
}

async fn send(app: &Router, method: &str, uri: &str, key: &str, body: Option<Value>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test]
async fn the_run_api_is_guarded() {
    let (url, _) = upstream().await;
    let mut cfg = config(&url);
    cfg.tenants[0].api_key_nodes.insert(caliban_types::hash_api_key(OTHER), vec!["other".into()]);
    let handle = ConfigHandle::new(Snapshot::new(cfg, "t"));
    let gw = Arc::new(Gateway::new(handle, Arc::new(RecentUsage::default())));
    let a = app(Arc::clone(&gw));
    let run = json!({"input": "x"});
    // Not enabled yet: 503.
    let (s, e) = send(&a, "POST", "/v1/nodes/triage/runs", KEY, Some(run.clone())).await;
    assert_eq!((s, e["error"]["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("nodes_not_enabled")));
    let keyring = Arc::new(caliban_config::Keyring::new([7; 32], []));
    let ex = crate::nodes::local_executor(
        &gw,
        Arc::new(MemoryJournal::new()),
        Arc::new(NoTools),
        keyring,
        "w1".into(),
        ExecutorOptions::default(),
    );
    gw.set_nodes(NodeRuns::Local(LocalRuns { executor: ex, sync_wait: std::time::Duration::from_secs(5) }));
    assert_eq!(
        send(&a, "POST", "/v1/nodes/triage/runs", "cal_wrong", Some(run.clone())).await.0,
        StatusCode::UNAUTHORIZED
    );
    // The allowlist: OTHER may run only "other".
    let (s, e) = send(&a, "POST", "/v1/nodes/triage/runs", OTHER, Some(run.clone())).await;
    assert_eq!((s, e["error"]["code"].as_str()), (StatusCode::FORBIDDEN, Some("node_not_allowed")));
    // Nothing is published: 404.
    let (s, e) = send(&a, "POST", "/v1/nodes/triage/runs", KEY, Some(run)).await;
    assert_eq!((s, e["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("node_not_found")), "{e}");
    assert_eq!(send(&a, "GET", "/v1/runs/run_nope", KEY, None).await.0, StatusCode::NOT_FOUND);
    let (s, _) = send(&a, "POST", "/v1/nodes/triage/runs", KEY, Some(json!({"inputs": 1}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "unknown fields are refused");
}

#[tokio::test]
async fn rate_limited_node_calls_ask_for_a_durable_sleep() {
    let (url, _) = upstream().await;
    let mut cfg = config(&url);
    cfg.limits.requests_per_minute = Some(1);
    let gw = Arc::new(Gateway::new(ConfigHandle::new(Snapshot::new(cfg, "t")), Arc::new(RecentUsage::default())));
    let models = GatewayModels::new(&gw);
    models.chat(&ctx("a#0", KEY), body("one")).await.unwrap();
    match models.chat(&ctx("b#0", KEY), body("two")).await.unwrap_err() {
        ModelError::Throttled { retry_after, message } => {
            assert!(retry_after >= std::time::Duration::from_secs(1), "{retry_after:?}");
            assert!(message.starts_with("429"), "{message}");
        }
        other => panic!("expected a rate limit, got {other:?}"),
    }
}
