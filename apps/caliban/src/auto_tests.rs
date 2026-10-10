//! `caliban/auto` picks a node (P3 M6): a request that Stage-1 kNN classifies into an intent the
//! tenant maps to a node runs the node; otherwise a model answers and the response says why. The
//! request is classified once on either path (the embedder sees it once).

use crate::nodes_tests::{ADMIN, KEY, LONG, Worker, env_toml, idem, journal, send, until, worker};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::post;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

const CHEST: &str = "my chest hurts since tuesday";
const INVOICE: &str = "question about my last invoice";
/// The same as the exemplars to the embedder (case and punctuation aside), but other texts: the
/// embedder's cache does not answer them, so each classification reaches the embedding server.
const CHEST_ASK: &str = "My chest hurts since Tuesday!";
const INVOICE_ASK: &str = "Question about my last invoice?";

/// An embedding server (deterministic hash embeddings) that records every text it embeds.
async fn embedder() -> (String, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let s = Arc::clone(&seen);
    let app = Router::new().route(
        "/v1/embeddings",
        post(move |axum::Json(b): axum::Json<Value>| {
            let s = Arc::clone(&s);
            async move {
                let inputs: Vec<String> = match &b["input"] {
                    Value::String(x) => vec![x.clone()],
                    Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect(),
                    _ => vec![],
                };
                s.lock().unwrap().extend(inputs.iter().cloned());
                let data: Vec<Value> = inputs
                    .iter()
                    .enumerate()
                    .map(|(i, t)| json!({"object": "embedding", "index": i, "embedding": caliban_route::hash_embed(t, 256)}))
                    .collect();
                axum::Json(json!({"object": "list", "data": data, "model": b["model"], "usage": {"prompt_tokens": 1, "total_tokens": 1}}))
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, seen)
}

/// Routing config: kNN over the tenant's own exemplars, accepting only near-exact matches (any
/// other prompt is out of scope, so the keyword rules decide it), and `triage` handed to a node.
fn routing(emb: &str) -> String {
    format!(
        r#"
[routing]
embedding_model = "emb/mock"
default_exemplars = false
budget_ms = 5000
oos_threshold = 0.95
abstain_threshold = 0.0
margin_threshold = 0.0
[routing.tenants.acme.exemplars]
triage = ["{CHEST}", "I have had a fever and a cough for days", "my knee is swollen after a fall"]
billing = ["{INVOICE}", "how do I pay my bill", "I was charged twice this month"]
[routing.tenants.acme.routes]
triage = "node/flow"

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
"#
    )
}

/// The node `triage` goes to: asks one question, then answers. Its own model calls name a model
/// (no classification of their own).
fn flow(usd: Option<f64>) -> Value {
    let mut budgets = json!({"steps": 10, "tokens": 10000, "wall_clock_s": 60});
    if let Some(u) = usd {
        budgets["usd"] = json!(u);
    }
    json!({
        "kind": "workflow", "model_policy": {"candidates": ["oa/m"]}, "budgets": budgets,
        "prompt": {"input_schema": {"type": "object", "required": ["case"], "properties": {"case": {"type": "string"}}}},
        "graph": {"vertices": [
            {"id": "classify", "type": "router", "config": {"prompt": "Case: {{input.case}}",
                "routes": {"clinical": "health", "billing": "money"}, "default": "billing"}},
            {"id": "clarify", "type": "human", "config": {"question": "Since when ({{input.route}})?"}},
            {"id": "answer", "type": "llm", "config": {"prompt": "Case {{input.case}}, since {{input.answer}}"}}
        ], "edges": [{"from": "classify", "to": "clarify"}, {"from": "clarify", "to": "answer"}]}
    })
}

fn auto(text: &str, stream: bool) -> Value {
    json!({"model": "caliban/auto", "stream": stream, "messages": [{"role": "user", "content": text}]})
}

async fn chat(app: &Router, key: &str, body: Value, extra: &[(&str, &str)]) -> (StatusCode, HeaderMap, String) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json");
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let (s, h) = (resp.status(), resp.headers().clone());
    let b = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    (s, h, String::from_utf8_lossy(&b).into_owned())
}

struct Auto {
    e: crate::nodes_tests::Env,
    w: Worker,
    seen: Arc<Mutex<Vec<String>>>,
    /// Usage events seen so far.
    events: usize,
}

impl Auto {
    async fn new(usd: Option<f64>) -> Self {
        let (emb, seen) = embedder().await;
        let e = env_toml(Duration::ZERO, None, &routing(&emb)).await;
        e.publish("flow", flow(usd)).await;
        let j = journal().await;
        let w = worker(&e, &j, &idem(), None, "worker-a", LONG);
        w.gw.warm_router().await;
        assert!(w.gw.router.knn_ready(), "the kNN index is built");
        Self { e, w, seen, events: 0 }
    }

    /// How often the embedder saw `text`.
    fn embedded(&self, text: &str) -> usize {
        self.seen.lock().unwrap().iter().filter(|t| t.as_str() == text).count()
    }

    /// A caliban/auto request answered by a model: its fallback reason, checked against the usage
    /// event, and the prompt classified once.
    async fn fallback(&mut self, key: &str, text: &str, stream: bool) -> String {
        let before = self.embedded(text);
        let (s, h, body) = chat(&self.w.app, key, auto(text, stream), &[]).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        assert_eq!(h["x-caliban-route"], "model:oa/m", "{body}");
        assert_eq!(self.embedded(text), before + 1, "classified once");
        let reason = h["x-caliban-route-fallback"].to_str().unwrap().to_owned();
        // The newest usage event is this request's model call.
        let before_events = self.events;
        let mut ev = None;
        until("the usage event", async || {
            let all = self.w.usage.snapshot(Some("acme"), 1000);
            ev = (all.len() > before_events).then(|| all[0].clone());
            ev.is_some()
        })
        .await;
        let ev = ev.unwrap();
        assert_eq!((ev.route.as_deref(), ev.route_fallback.as_deref()), (Some("model:oa/m"), Some(reason.as_str())));
        self.events = self.w.usage.snapshot(Some("acme"), 1000).len();
        reason
    }
}

#[tokio::test]
async fn auto_hands_a_classified_request_to_the_node_and_classifies_once() {
    let a = Auto::new(None).await;
    // JSON: the node's question, the run id, the path taken.
    let (s, h, body) = chat(&a.w.app, KEY, auto(CHEST_ASK, false), &[]).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(h["x-caliban-route"], "node/flow@v1");
    assert!(h["x-caliban-intent"].to_str().unwrap().starts_with("triage;"), "{:?}", h["x-caliban-intent"]);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["choices"][0]["finish_reason"], "input_required");
    assert_eq!(v["choices"][0]["message"]["content"], "Since when (clinical)?");
    assert_eq!(a.embedded(CHEST_ASK), 1, "the request was classified once");
    let run = v["caliban"]["run_id"].as_str().unwrap().to_owned();
    // Continued with caliban/auto and the run id: no new classification.
    let (s, h, body) = chat(&a.w.app, KEY, auto("two days", false), &[("caliban-run-id", &run)]).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["choices"][0]["message"]["content"], "You said: Case My chest hurts since Tuesday!, since two days");
    assert_eq!(h["x-caliban-route"], "node/flow@v1");
    assert_eq!(a.embedded("two days"), 0, "continuing a run classifies nothing");
    // The run says what started it; its model calls' usage events say which path ran.
    let (_, r) = send(&a.w.app, "GET", &format!("/v1/runs/{run}"), KEY, None, &[]).await;
    assert_eq!(r["origin"], "auto:triage");
    let evs = a.w.usage.snapshot(Some("acme"), 10);
    assert_eq!(evs.len(), 2, "the classifier and the answer");
    for e in &evs {
        assert_eq!(
            (e.route.as_deref(), e.run_id.as_deref(), e.route_fallback.as_deref()),
            (Some("node/flow@v1"), Some(run.as_str()), None)
        );
    }
    // Streamed: the node's answer in chunks, the path in the headers.
    let again = "My chest hurts since Tuesday...";
    let (s, h, body) = chat(&a.w.app, KEY, auto(again, true), &[]).await;
    assert_eq!((s, h["content-type"].to_str().unwrap()), (StatusCode::OK, "text/event-stream"));
    assert_eq!(h["x-caliban-route"], "node/flow@v1");
    assert!(body.contains("\"finish_reason\":\"input_required\""), "{body}");
    assert_eq!(a.embedded(again), 1);
}

#[tokio::test]
async fn auto_falls_back_to_a_model_and_says_why() {
    let mut a = Auto::new(Some(1.0)).await;
    // kNN abstains (out of scope): the keyword rules decided, no node.
    assert_eq!(a.fallback(KEY, "zebra quartz violin", false).await, "low_confidence");
    // A confident intent that maps to no node.
    assert_eq!(a.fallback(KEY, INVOICE_ASK, false).await, "no_node_for_intent");
    // A key that may not run the node.
    let (s, k) =
        send(&a.e.cp_app, "POST", "/api/v1/tenants/acme/api-keys", ADMIN, Some(json!({"nodes": ["other"]})), &[]).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(
        a.fallback(k["key"].as_str().unwrap(), "My chest hurts since Tuesday!!", false).await,
        "node_not_allowed"
    );
    // The tenant setting overrides the config file: triage now goes to a node that is not published.
    let patch = |r: Value| json!({"node_routes": r});
    let (s, t) =
        send(&a.e.cp_app, "PATCH", "/api/v1/tenants/acme", ADMIN, Some(patch(json!({"triage": "node/ghost"}))), &[])
            .await;
    assert_eq!(s, StatusCode::OK, "{t}");
    assert_eq!(a.fallback(KEY, "MY CHEST HURTS SINCE TUESDAY", false).await, "node_unavailable");
    send(&a.e.cp_app, "PATCH", "/api/v1/tenants/acme", ADMIN, Some(patch(Value::Null)), &[]).await;
    // The tenant's spend caps leave less than a run may spend ($1): the model answers, streamed.
    let caps = json!({"node_spend_caps": {"daily_usd": 0.5}});
    assert_eq!(send(&a.e.cp_app, "PATCH", "/api/v1/tenants/acme", ADMIN, Some(caps), &[]).await.0, StatusCode::OK);
    assert_eq!(a.fallback(KEY, "my chest hurts, since tuesday", true).await, "node_over_budget");
    let (_, runs) = send(&a.w.app, "GET", "/v1/runs", KEY, None, &[]).await;
    assert_eq!(runs["data"], json!([]), "no run was created on any fallback");
    // With room again, the node runs.
    send(&a.e.cp_app, "PATCH", "/api/v1/tenants/acme", ADMIN, Some(json!({"node_spend_caps": null})), &[]).await;
    let (_, h, _) = chat(&a.w.app, KEY, auto(CHEST_ASK, false), &[]).await;
    assert_eq!(h["x-caliban-route"], "node/flow@v1");
    // Requests that are not caliban/auto never show a route.
    let pinned = json!({"model": "oa/m", "messages": [{"role": "user", "content": CHEST}]});
    let (_, h, _) = chat(&a.w.app, KEY, pinned, &[]).await;
    assert!(h.get("x-caliban-route").is_none());
}

#[tokio::test]
async fn auto_on_a_router_runs_the_node_on_a_worker() {
    let a = Auto::new(Some(1.0)).await;
    let (router, r, server) = crate::exposure_tests::split(&a.e, &a.w).await;
    router.warm_router().await;
    let (s, h, body) = chat(&r, KEY, auto("My chest hurts since Tuesday?", false), &[]).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(h["x-caliban-route"], "node/flow@v1");
    let v: Value = serde_json::from_str(&body).unwrap();
    let run = v["caliban"]["run_id"].as_str().unwrap().to_owned();
    assert_eq!(
        a.w.ex.view("acme", &run).await.unwrap().unwrap().origin.as_deref(),
        Some("auto:triage"),
        "the worker ran it"
    );
    // The worker refuses the run (spend caps); the router answers with a model, saying why.
    let caps = json!({"node_spend_caps": {"daily_usd": 0.5}});
    assert_eq!(send(&a.e.cp_app, "PATCH", "/api/v1/tenants/acme", ADMIN, Some(caps), &[]).await.0, StatusCode::OK);
    let (s, h, body) = chat(&r, KEY, auto("my chest hurts since tuesday?!", false), &[]).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(
        (h["x-caliban-route"].to_str().unwrap(), h["x-caliban-route-fallback"].to_str().unwrap()),
        ("model:oa/m", "node_over_budget")
    );
    server.abort();
}
