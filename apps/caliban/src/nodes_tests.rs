//! Node runs end to end (P3 M2): a control plane publishes node versions, workers (real gateways
//! in front of the mock model server) execute them through the request pipeline, and the journal
//! is Postgres when `CALIBAN_TEST_DATABASE_URL` is set (in memory otherwise).
//!
//! - the reference triage node (`config/nodes/triage.node.json`), human step across a worker
//!   restart, PII masked on every model call, `Idempotency-Key` on run creation;
//! - a worker dies in the middle of a model call: another worker resumes the run, completed steps
//!   are not run again and the model server sees each call once;
//! - two workers and many runs: each run executes exactly once;
//! - split mode: a router without any database forwards runs to a worker over HTTP;
//! - node model calls reach the control plane's usage totals through usage shipping.

use crate::split::HttpUsageTransport;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use caliban_bench::mock::{Mock, MockConfig, Responder};
use caliban_config::{Config, ConfigHandle, Keyring, Snapshot};
use caliban_cp::ControlPlane;
use caliban_cp::store::Store;
use caliban_cp::tools::ToolsSetup;
use caliban_gateway::Gateway;
use caliban_gateway::nodes::{Forwarder, LocalRuns, NodeRuns, WORKER_TOKEN_HEADER, local_executor, worker_app};
use caliban_gateway::tools::SnapshotTools;
use caliban_mcp::client::McpClient;
use caliban_mcp::egress::EgressPolicy;
use caliban_mcp::testing::{TestMcpServer, TestTool};
use caliban_mcp::token::ToolTokenSigner;
use caliban_meter::idempotency::{IdempotencyStore, MemoryIdempotency};
use caliban_meter::{RecentUsage, ShipOptions, Tee, UsageShipper, UsageSink};
use caliban_nodes::executor::{Executor, ExecutorOptions};
use caliban_nodes::journal::memory::MemoryJournal;
use caliban_nodes::journal::postgres::PgJournal;
use caliban_nodes::journal::{Journal, RunStatus};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tower::ServiceExt;

pub(crate) const ADMIN: &str = "admin-secret";
pub(crate) const ROUTER_TOKEN: &str = "router-secret";
pub(crate) const WORKER_TOKEN: &str = "worker-secret";
pub(crate) const KEY: &str = "cal_nodes_e2e_test_key_00000000000";
pub(crate) const EMAIL: &str = "jane.roe@example.com";
pub(crate) const LONG: Duration = Duration::from_secs(30);
pub(crate) const SHORT: Duration = Duration::from_secs(1);

pub(crate) fn ring() -> Keyring {
    Keyring::new([7; 32], [])
}

/// The test config with `extra` TOML in front (top-level tables such as `[routing]`).
pub(crate) fn config_with(upstream: &str, extra: &str) -> Config {
    Config::from_toml_str(&format!(
        r#"
{extra}
[[models]]
id = "oa/m"
provider = "oa"
upstream_model = "mock-oa"
trust_tier = "t2_contracted"
price_in_per_mtok = 0.5
price_out_per_mtok = 1.5

[[tenants]]
id = "acme"
name = "Acme"
pii_mode = "mask"
api_key_hashes = ["{hash}"]
  [[tenants.providers]]
  id = "oa"
  kind = "openai_compatible"
  base_url = "{upstream}"
  trust_tier = "t2_contracted"
  [[tenants.routes]]
  intent = "default"
  models = ["oa/m"]
"#,
        hash = caliban_types::hash_api_key(KEY),
    ))
    .unwrap()
}

/// The catalogue tool of the reference node: its manifest, as an MCP server publishes it.
fn catalogue_manifest() -> caliban_mcp::ToolManifest {
    caliban_mcp::ToolManifest {
        name: "search_services".into(),
        description: "Searches the service catalogue for services that match a category and a case description.".into(),
        input_schema: json!({"type": "object", "required": ["category", "case"],
                             "properties": {"category": {"type": "string"}, "case": {"type": "string"}}}),
    }
}

fn catalogue_ref() -> String {
    format!("mcp://catalogue/search_services#{}", catalogue_manifest().pin())
}

/// A real MCP server (rmcp, Streamable HTTP) serving the catalogue tool.
async fn catalogue_server() -> TestMcpServer {
    let tool = TestTool::new(catalogue_manifest(), |args: &Value| {
        let services = match args["category"].as_str() {
            Some("clinical") => json!(["cardiology-clinic", "gp-same-day"]),
            _ => json!(["front-desk"]),
        };
        Ok(json!({"services": services}))
    });
    TestMcpServer::start(vec![tool], &[]).await
}

/// The key that signs minted tool tokens (control plane and workers share it).
pub(crate) fn tool_signer() -> Arc<ToolTokenSigner> {
    Arc::new(ToolTokenSigner::new(&[3; 32], "caliban", vec![]))
}

pub(crate) fn mcp_client() -> Arc<McpClient> {
    // The test server listens on loopback.
    Arc::new(McpClient::system(EgressPolicy { allow_loopback: true }))
}

/// Scripted model answers for the nodes in these tests (anything else gets the echo).
pub(crate) fn responder() -> Responder {
    Responder::new(|body| {
        let system = body["messages"][0]["content"].as_str().unwrap_or_default();
        let user = caliban_bench::mock::last_user_text(body);
        if system.contains("Labels:") {
            return Some(json!({"role": "assistant", "content": "clinical"}));
        }
        if user.contains("Catalogue matches") {
            let service = if user.contains("cardiology-clinic") { "cardiology-clinic" } else { "front-desk" };
            let rec = json!({"category": "clinical", "urgency": "soon", "services": [service],
                             "rationale": "Chest pain for two days, no immediate danger reported."});
            return Some(json!({"role": "assistant", "content": rec.to_string()}));
        }
        None
    })
}

pub(crate) struct Env {
    pub(crate) mock: Mock,
    pub(crate) cp: Arc<ControlPlane>,
    pub(crate) cp_app: Router,
    pub(crate) handle: ConfigHandle,
}

pub(crate) async fn env(latency: Duration) -> Env {
    env_with(latency, None).await
}

/// An environment whose control plane reads `journal` (the console's run endpoints).
pub(crate) async fn env_with(latency: Duration, journal: Option<Arc<dyn Journal>>) -> Env {
    env_toml(latency, journal, "").await
}

/// An environment whose config file starts with `extra`.
pub(crate) async fn env_toml(latency: Duration, journal: Option<Arc<dyn Journal>>, extra: &str) -> Env {
    let cfg = MockConfig { latency, responder: Some(responder()), ..MockConfig::default() };
    let mock = Mock::start("127.0.0.1:0", cfg).await.unwrap();
    let cfg = config_with(&mock.base_url(), extra);
    let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
    let cp = Arc::new(
        ControlPlane::new(Store::new(cfg, handle.clone(), RecentUsage::default()), ADMIN.into(), "standalone")
            .with_keyring(Some(Arc::new(ring())))
            .with_snapshots(None, Some(ROUTER_TOKEN.into()))
            .with_tools(ToolsSetup { client: mcp_client(), signer: Some(tool_signer()) })
            .with_journal(journal),
    );
    let cp_app = caliban_cp::app(Arc::clone(&cp), None);
    Env { mock, cp, cp_app, handle }
}

pub(crate) async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    bearer: &str,
    body: Option<Value>,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json");
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

impl Env {
    /// Creates, publishes and promotes a version of `name`.
    pub(crate) async fn publish(&self, name: &str, spec: Value) {
        let uri = format!("/api/v1/tenants/acme/nodes/{name}/versions");
        let (s, v) = send(&self.cp_app, "POST", &uri, ADMIN, Some(json!({"spec": spec})), &[]).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        let uri = format!("/api/v1/tenants/acme/nodes/{name}/versions/{}/publish", v["version"]);
        let (s, p) = send(&self.cp_app, "POST", &uri, ADMIN, None, &[]).await;
        assert_eq!(s, StatusCode::OK, "{p}");
    }
}

/// Short leases only where a test waits for one to expire; a long lease elsewhere, so a slow
/// machine never loses one by accident.
pub(crate) fn options(lease: Duration) -> ExecutorOptions {
    ExecutorOptions {
        lease_ttl: lease,
        heartbeat: Duration::from_millis(100),
        poll: Duration::from_millis(20),
        model_retry_for: Duration::from_secs(20),
        ..ExecutorOptions::default()
    }
}

pub(crate) struct Worker {
    pub(crate) gw: Arc<Gateway>,
    pub(crate) ex: Arc<Executor>,
    pub(crate) app: Router,
    pub(crate) usage: RecentUsage,
}

/// A worker: a gateway on the shared snapshot that executes runs from `journal`.
pub(crate) fn worker(
    e: &Env,
    journal: &Arc<dyn Journal>,
    idem: &Arc<dyn IdempotencyStore>,
    sink: Option<Arc<dyn UsageSink>>,
    id: &str,
    lease: Duration,
) -> Worker {
    let usage = RecentUsage::default();
    let mut sinks: Vec<Arc<dyn UsageSink>> = vec![Arc::new(usage.clone())];
    sinks.extend(sink);
    let gw = Arc::new(Gateway::new(e.handle.clone(), Arc::new(Tee(sinks))).with_idempotency(Arc::clone(idem)));
    let tools = Arc::new(SnapshotTools::new(e.handle.clone(), Arc::new(ring()), mcp_client(), Some(tool_signer())));
    let ex = local_executor(&gw, Arc::clone(journal), tools, Arc::new(ring()), id.into(), options(lease));
    gw.set_nodes(NodeRuns::Local(LocalRuns { executor: Arc::clone(&ex), sync_wait: Duration::from_secs(10) }));
    let app = caliban_gateway::app(Arc::clone(&gw));
    Worker { gw, ex, app, usage }
}

pub(crate) async fn journal() -> Arc<dyn Journal> {
    match std::env::var("CALIBAN_TEST_DATABASE_URL").ok() {
        Some(url) => Arc::new(PgJournal::isolated(&url).await.expect("CALIBAN_TEST_DATABASE_URL must be reachable")),
        None => {
            eprintln!("CALIBAN_TEST_DATABASE_URL not set; the node e2e tests use the memory journal");
            Arc::new(MemoryJournal::new())
        }
    }
}

pub(crate) fn idem() -> Arc<dyn IdempotencyStore> {
    Arc::new(MemoryIdempotency::default())
}

pub(crate) async fn until(what: &str, mut f: impl AsyncFnMut() -> bool) {
    for _ in 0..1500 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

pub(crate) async fn run_status(app: &Router, id: &str) -> Value {
    let (s, v) = send(app, "GET", &format!("/v1/runs/{id}"), KEY, None, &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

#[tokio::test]
async fn the_reference_triage_node_runs_end_to_end() {
    let e = env(Duration::ZERO).await;
    let spec: Value = serde_json::from_str(include_str!("../../../config/nodes/triage.node.json")).unwrap();
    assert_eq!(spec["tools"][0]["ref"], catalogue_ref(), "the reference node pins the catalogue manifest");
    // The catalogue is a real MCP server: registered, discovered, approved, then pinned.
    let mcp = catalogue_server().await;
    let jwks = tool_signer().jwks();
    let audience = format!("http://127.0.0.1:{}", mcp.port);
    let aud = audience.clone();
    mcp.require_auth(move |h| {
        let t = h.and_then(|h| h.strip_prefix("Bearer ")).ok_or("no bearer token")?;
        caliban_mcp::token::verify(t, &jwks, "caliban", &aud, chrono::Utc::now().timestamp(), 5)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    let servers = "/api/v1/tenants/acme/tool-servers";
    let (s, r) = send(&e.cp_app, "POST", servers, ADMIN, Some(json!({"name": "catalogue", "url": mcp.url})), &[]).await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    let (s, d) = send(&e.cp_app, "POST", &format!("{servers}/catalogue/discover"), ADMIN, None, &[]).await;
    assert_eq!((s, d["tools"][0]["findings"].clone()), (StatusCode::OK, json!([])), "{d}");
    let approve = json!({"pin": catalogue_manifest().pin()});
    let uri = format!("{servers}/catalogue/tools/search_services/approve");
    let (s, a) = send(&e.cp_app, "POST", &uri, ADMIN, Some(approve), &[]).await;
    assert_eq!((s, a["ref"].as_str()), (StatusCode::OK, Some(catalogue_ref().as_str())), "{a}");
    e.publish("triage", spec).await;
    let j = journal().await;
    let store = idem();
    let a = worker(&e, &j, &store, None, "worker-a", LONG);

    // A sync run: classified, then it waits for the clarifying answer.
    let case = json!({"input": {"case": format!("Chest pain since Tuesday; reach me at {EMAIL}")}});
    let key = [("idempotency-key", "case-42")];
    let (s, v) = send(&a.app, "POST", "/v1/nodes/triage/runs", KEY, Some(case.clone()), &key).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["status"], "input_required", "{v}");
    assert_eq!(v["awaiting"]["step"], "clarify#0");
    assert!(v["awaiting"]["question"].as_str().unwrap().contains("clinical case"));
    let id = v["id"].as_str().unwrap().to_owned();
    // The same Idempotency-Key returns the same run and calls nothing.
    let calls = e.mock.len();
    let (s, again) = send(&a.app, "POST", "/v1/nodes/triage/runs", KEY, Some(case), &key).await;
    assert_eq!((s, again["id"].as_str()), (StatusCode::ACCEPTED, Some(id.as_str())));
    assert_eq!(e.mock.len(), calls);

    // The version is retired while the run waits: new runs are refused, this one drains.
    let (s, r) = send(&e.cp_app, "POST", "/api/v1/tenants/acme/nodes/triage/versions/1/retire", ADMIN, None, &[]).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let fresh = json!({"input": {"case": "Another case"}, "async": true});
    let (s, _) = send(&a.app, "POST", "/v1/nodes/triage/runs", KEY, Some(fresh), &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "a retired version takes no new runs");

    // The worker restarts (a new process on the same journal); the answer goes to the new one.
    drop(a);
    let b = worker(&e, &j, &store, None, "worker-b", LONG);
    let answer = json!({"answer": "Two days, nobody in danger."});
    let (s, v) = send(&b.app, "POST", &format!("/v1/runs/{id}/input"), KEY, Some(answer), &[]).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let mut done = None;
    until("the run to finish", async || {
        done = b.ex.wait("acme", &id, Instant::now() + Duration::from_millis(200)).await.unwrap();
        done.as_ref().is_some_and(|d| d.status.is_terminal())
    })
    .await;
    assert_eq!(done.unwrap().status, RunStatus::Succeeded);
    let v = run_status(&b.app, &id).await;
    assert_eq!(v["output"]["services"], json!(["cardiology-clinic"]), "{v}");
    assert_eq!(v["output"]["urgency"], "soon");
    let steps: Vec<&str> = v["steps"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(steps, ["classify#0", "clarify#0", "catalogue#0", "recommend#0"]);
    assert_eq!(e.mock.len(), 2, "two model calls: classify and recommend");
    // PII never reached the model server, nor the (untrusted) tool server.
    for entry in e.mock.log() {
        assert!(!entry.body.to_string().contains(EMAIL), "{}", entry.body);
    }
    let calls = mcp.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].args["category"], "clinical");
    assert!(!calls[0].args.to_string().contains(EMAIL), "{:?}", calls[0].args);
    // Every request to the tool server carried a token minted for this call; never the API key.
    let auths = mcp.authorizations();
    assert!(!auths.is_empty());
    for a in &auths {
        let a = a.as_deref().unwrap();
        assert!(!a.contains(KEY), "the client's key never reaches a tool server");
        let claims = caliban_mcp::token::verify(
            a.strip_prefix("Bearer ").unwrap(),
            &tool_signer().jwks(),
            "caliban",
            &audience,
            chrono::Utc::now().timestamp(),
            60,
        )
        .unwrap();
        if claims.run_id != "discovery" {
            assert_eq!((claims.sub.as_str(), claims.run_id.as_str()), ("tenant:acme/node:triage@v1", id.as_str()));
            assert_eq!(claims.scope, "tool:search_services");
        }
    }
    assert!(mcp.rejected().is_empty());
    // The second call was made (and metered) by worker b.
    assert_eq!(b.usage.snapshot(Some("acme"), 10).len(), 1);
}

#[tokio::test]
async fn a_dead_worker_is_replaced_without_paying_twice() {
    // The model server answers after 300 ms, so worker a is surely still waiting when it dies.
    let e = env(Duration::from_millis(300)).await;
    let chain = json!({
        "kind": "workflow", "model_policy": {}, "budgets": {"steps": 10, "tokens": 10000, "wall_clock_s": 60},
        "graph": {"vertices": [{"id": "a", "type": "llm", "config": {"prompt": "first {{input}}"}},
                               {"id": "b", "type": "llm", "config": {"prompt": "second {{input}}"}},
                               {"id": "c", "type": "llm", "config": {"prompt": "third {{input}}"}}],
                  "edges": [{"from": "a", "to": "b"}, {"from": "b", "to": "c"}]}
    });
    e.publish("chain", chain).await;
    let j = journal().await;
    // Workers share the Idempotency-Key store (Valkey in a real deployment).
    let store = idem();
    let a = worker(&e, &j, &store, None, "worker-a", SHORT);
    let body = json!({"input": "x", "async": true});
    let (s, v) = send(&a.app, "POST", "/v1/nodes/chain/runs", KEY, Some(body), &[]).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let task = {
        let (ex, id) = (Arc::clone(&a.ex), id.clone());
        tokio::spawn(async move { ex.run_now(&id).await })
    };
    // Worker a dies while the model server is answering the second step.
    until("the second model call", async || e.mock.len() == 2).await;
    task.abort();
    let _ = task.await;
    let b = worker(&e, &j, &store, None, "worker-b", SHORT);
    let stop = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(Arc::clone(&b.ex).run_loop(Arc::clone(&stop)));
    let mut done = None;
    until("the run to finish on worker b", async || {
        done = b.ex.wait("acme", &id, Instant::now() + Duration::from_millis(200)).await.unwrap();
        done.as_ref().is_some_and(|d| d.status.is_terminal())
    })
    .await;
    stop.notify_waiters();
    let done = done.unwrap();
    assert_eq!((done.status, done.claims), (RunStatus::Succeeded, 2), "{done:?}");
    // Three steps, three model calls: a was not run again, b's in-flight call was answered from
    // its stored response, c ran on worker b.
    let prompts: Vec<String> = e.mock.log().iter().map(caliban_bench::mock::Entry::last_user_text).collect();
    assert_eq!(prompts.len(), 3, "{prompts:?}");
    assert!(prompts[0].starts_with("first") && prompts[1].starts_with("second") && prompts[2].starts_with("third"));
    // Metered once per call: the replayed answer is not billed again.
    until("worker a to meter its in-flight call", async || a.usage.snapshot(None, 10).len() == 2).await;
    assert_eq!(b.usage.snapshot(None, 10).len(), 1);
    let v = run_status(&b.app, &id).await;
    assert_eq!(v["steps"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn two_workers_run_each_run_exactly_once() {
    let e = env(Duration::from_millis(5)).await;
    let one = json!({"kind": "workflow", "model_policy": {}, "budgets": {"steps": 3, "tokens": 10000, "wall_clock_s": 60},
                     "graph": {"vertices": [{"id": "answer", "type": "llm", "config": {"prompt": "run {{input}}"}}], "edges": []}});
    e.publish("one", one).await;
    let j = journal().await;
    let store = idem();
    let (a, b) = (worker(&e, &j, &store, None, "worker-a", LONG), worker(&e, &j, &store, None, "worker-b", LONG));
    let mut ids = Vec::new();
    for i in 0..30 {
        let body = json!({"input": format!("n{i:02}"), "async": true});
        let (s, v) = send(&a.app, "POST", "/v1/nodes/one/runs", KEY, Some(body), &[]).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{v}");
        ids.push(v["id"].as_str().unwrap().to_owned());
    }
    let stop = Arc::new(tokio::sync::Notify::new());
    for w in [&a, &b] {
        tokio::spawn(Arc::clone(&w.ex).run_loop(Arc::clone(&stop)));
    }
    for id in &ids {
        until("every run to finish", async || {
            j.get_run("acme", id).await.unwrap().is_some_and(|r| r.status.is_terminal())
        })
        .await;
    }
    stop.notify_waiters();
    for id in &ids {
        let r = j.get_run("acme", id).await.unwrap().unwrap();
        assert_eq!((r.status, r.claims), (RunStatus::Succeeded, 1), "{r:?}");
    }
    let mut prompts: Vec<String> = e.mock.log().iter().map(caliban_bench::mock::Entry::last_user_text).collect();
    prompts.sort();
    let want: Vec<String> = (0..30).map(|i| format!("run n{i:02}")).collect();
    assert_eq!(prompts, want, "each run called the model exactly once");
    let (na, nb) = (a.usage.snapshot(None, 100).len(), b.usage.snapshot(None, 100).len());
    assert_eq!(na + nb, 30, "{na} + {nb}");
}

#[tokio::test]
async fn a_router_without_a_database_forwards_runs_to_a_worker() {
    let e = env(Duration::ZERO).await;
    let one = json!({"kind": "workflow", "model_policy": {}, "budgets": {"steps": 3, "tokens": 10000, "wall_clock_s": 60},
                     "graph": {"vertices": [{"id": "answer", "type": "llm", "config": {"prompt": "hello {{input}}"}}], "edges": []}});
    e.publish("one", one).await;
    let memory: Arc<dyn Journal> = Arc::new(MemoryJournal::new());
    let w = worker(&e, &memory, &idem(), None, "worker-1", LONG);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = worker_app(Arc::clone(&w.gw), WORKER_TOKEN.into());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // The router: the same snapshot, no journal and no database settings, only worker URLs. The
    // first URL has nothing listening: the router moves on to the next worker.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let router = Arc::new(Gateway::new(e.handle.clone(), Arc::new(RecentUsage::default())));
    let workers = vec![format!("http://{dead}"), url.clone()];
    router.set_nodes(NodeRuns::Forward(Forwarder::new(workers, WORKER_TOKEN.into(), Duration::from_secs(30)).unwrap()));
    let r = caliban_gateway::app(Arc::clone(&router));
    let (s, v) = send(&r, "POST", "/v1/nodes/one/runs", KEY, Some(json!({"input": "world"})), &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!((v["status"].as_str(), v["output"].as_str()), (Some("succeeded"), Some("You said: hello world")));
    let id = v["id"].as_str().unwrap();
    let (s, g) = send(&r, "GET", &format!("/v1/runs/{id}"), KEY, None, &[]).await;
    assert_eq!((s, &g["output"]), (StatusCode::OK, &v["output"]));
    // The router authenticates before forwarding; the worker refuses requests without its token.
    assert_eq!(send(&r, "GET", &format!("/v1/runs/{id}"), "cal_wrong", None, &[]).await.0, StatusCode::UNAUTHORIZED);
    let direct = reqwest::Client::new();
    let resp = direct.get(format!("{url}/v1/runs/{id}")).bearer_auth(KEY).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let resp = direct
        .get(format!("{url}/v1/runs/{id}"))
        .bearer_auth(KEY)
        .header(WORKER_TOKEN_HEADER, WORKER_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    server.abort();
}

#[tokio::test]
async fn node_model_calls_reach_the_control_plane_usage_totals() {
    let e = env(Duration::ZERO).await;
    let two = json!({"kind": "workflow", "model_policy": {}, "budgets": {"steps": 5, "tokens": 10000, "wall_clock_s": 60},
                     "graph": {"vertices": [{"id": "a", "type": "llm"}, {"id": "b", "type": "llm"}], "edges": [{"from": "a", "to": "b"}]}});
    e.publish("two", two).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp_url = format!("http://{}", listener.local_addr().unwrap());
    let cp_app = e.cp_app.clone();
    let server = tokio::spawn(async move { axum::serve(listener, cp_app).await.unwrap() });
    let transport = Arc::new(HttpUsageTransport::new(&cp_url, ROUTER_TOKEN.into(), "worker-1".into()).unwrap());
    let opts = ShipOptions { batch_max: 10, interval: Duration::from_millis(20), ..ShipOptions::default() };
    let shipper = Arc::new(UsageShipper::start(transport, opts).unwrap());
    let memory: Arc<dyn Journal> = Arc::new(MemoryJournal::new());
    let w = worker(&e, &memory, &idem(), Some(Arc::clone(&shipper) as Arc<dyn UsageSink>), "worker-1", LONG);
    let (s, v) = send(&w.app, "POST", "/v1/nodes/two/runs", KEY, Some(json!({"input": "usage"})), &[]).await;
    assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("succeeded")), "{v}");
    // Wait for the worker's acknowledgement count, then read the totals.
    until("both events acknowledged", async || shipper.stats().delivered.load(Ordering::Relaxed) == 2).await;
    let (s, u) = send(&e.cp_app, "GET", "/api/v1/usage?tenant_id=acme", ADMIN, None, &[]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(u["totals"]["requests"], 2, "{u}");
    let local = w.usage.snapshot(Some("acme"), 10);
    let mut ids: Vec<&str> =
        u["events"].as_array().unwrap().iter().map(|e| e["request_id"].as_str().unwrap()).collect();
    let mut want: Vec<&str> = local.iter().map(|e| e.request_id.as_str()).collect();
    ids.sort_unstable();
    want.sort_unstable();
    assert_eq!(ids, want);
    assert!(e.cp.store.state().has_tenant("acme"));
    // Tagged with the node, its version and the run: the run's cost is its usage.
    let run_id = v["id"].as_str().unwrap();
    for ev in u["events"].as_array().unwrap() {
        assert_eq!(
            (&ev["node"], &ev["node_version"], &ev["run_id"]),
            (&json!("two"), &json!(1), &json!(run_id)),
            "{ev}"
        );
    }
    let (_, by_run) = send(&e.cp_app, "GET", &format!("/api/v1/usage?run_id={run_id}"), ADMIN, None, &[]).await;
    let charged = by_run["totals"]["charged_usd"].as_f64().unwrap();
    assert!(charged > 0.0, "{by_run}");
    let cost = v["cost_usd"].as_f64().unwrap();
    assert!((cost - charged).abs() < 1e-9, "run cost {cost} vs usage {charged}");
    let (_, by_node) = send(&e.cp_app, "GET", "/api/v1/usage?node=two", ADMIN, None, &[]).await;
    assert_eq!(by_node["by_node"], json!([{"node": "two", "node_version": 1, "totals": by_run["totals"]}]));
    shipper.shutdown(Duration::from_secs(2)).await;
    server.abort();
}

/// Workers never migrate: they refuse a database whose schema is behind or ahead of their build,
/// and leave it untouched.
#[tokio::test]
async fn workers_refuse_a_schema_mismatch_and_never_migrate() {
    use caliban_cp::store::postgres::MIGRATIONS;
    use sqlx::{AssertSqlSafe, Row};
    let Ok(url) = std::env::var("CALIBAN_TEST_DATABASE_URL") else {
        eprintln!("CALIBAN_TEST_DATABASE_URL not set; skipping the worker schema test");
        return;
    };
    let schema = format!("w_{}", uuid::Uuid::now_v7().simple());
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE SCHEMA {schema}"))).execute(&admin).await.unwrap();
    let scoped = format!("{url}{}options=-c%20search_path%3D{schema}", if url.contains('?') { "&" } else { "?" });
    let pool = sqlx::PgPool::connect(&scoped).await.unwrap();
    let count = async |pool: &sqlx::PgPool| -> i64 {
        sqlx::query("SELECT count(*) FROM caliban_schema_migrations").fetch_one(pool).await.unwrap().get(0)
    };

    // An empty database: refused, nothing created.
    let e = crate::nodes::worker_journal(&scoped).await.err().unwrap();
    assert!(format!("{e:#}").contains("no Caliban schema"), "{e:#}");
    let tables: i64 = sqlx::query("SELECT count(*) FROM pg_tables WHERE schemaname = $1")
        .bind(&schema)
        .fetch_one(&admin)
        .await
        .unwrap()
        .get(0);
    assert_eq!(tables, 0, "the worker created nothing");

    // Behind: the control plane of the previous release applied up to the second-to-last migration.
    sqlx::raw_sql(
        "CREATE TABLE caliban_schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL,
                                                 applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
    )
    .execute(&pool)
    .await
    .unwrap();
    let record = async |pool: &sqlx::PgPool, version: i64, name: &str, sql: &str| {
        sqlx::query("INSERT INTO caliban_schema_migrations (version, name, checksum) VALUES ($1, $2, $3)")
            .bind(version)
            .bind(name)
            .bind(hex_sha256(sql))
            .execute(pool)
            .await
            .unwrap();
    };
    for &(version, name, sql) in &MIGRATIONS[..MIGRATIONS.len() - 1] {
        sqlx::raw_sql(AssertSqlSafe(sql)).execute(&pool).await.unwrap();
        record(&pool, version, name, sql).await;
    }
    let e = crate::nodes::worker_journal(&scoped).await.err().unwrap();
    assert!(format!("{e:#}").contains("behind this build"), "{e:#}");
    assert_eq!(count(&pool).await, MIGRATIONS.len() as i64 - 1, "the worker did not migrate");

    // Current: accepted.
    let &(version, name, sql) = MIGRATIONS.last().unwrap();
    sqlx::raw_sql(AssertSqlSafe(sql)).execute(&pool).await.unwrap();
    record(&pool, version, name, sql).await;
    crate::nodes::worker_journal(&scoped).await.unwrap();

    // Ahead: a newer control plane applied a migration this worker does not know.
    record(&pool, version + 1, "from_the_future", "SELECT 1").await;
    let e = crate::nodes::worker_journal(&scoped).await.err().unwrap();
    assert!(format!("{e:#}").contains("ahead of this build"), "{e:#}");
}

fn hex_sha256(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

#[test]
fn lease_owners_are_unique_per_process_under_a_stable_name() {
    let (a, b) = (crate::nodes::lease_owner("worker-0"), crate::nodes::lease_owner("worker-0"));
    assert!(a.starts_with("worker-0-") && b.starts_with("worker-0-"));
    assert_ne!(a, b, "two processes with the same CALIBAN_WORKER_ID never share a lease");
}

/// Personal data across tools: an untrusted tool server gets the tenant's surrogates (here, the
/// masked form: the tenant's PII mode is `mask`), a server the tenant marks as trusted gets the
/// value; results come back anonymized.
#[tokio::test]
async fn pii_reaches_only_trusted_tool_servers() {
    let e = env(Duration::ZERO).await;
    let echo = |name: &str| {
        let m = caliban_mcp::ToolManifest {
            name: name.into(),
            description: "Records a contact.".into(),
            input_schema: json!({"type": "object", "properties": {"email": {"type": "string"}}}),
        };
        let tool = TestTool::new(m.clone(), |args: &Value| {
            Ok(json!({"stored": args["email"], "owner": "mary.major@example.org"}))
        });
        (m, tool)
    };
    let (m, tool) = echo("record");
    let (crm, notes) =
        (TestMcpServer::start(vec![tool.clone()], &[]).await, TestMcpServer::start(vec![tool], &[]).await);
    let servers = "/api/v1/tenants/acme/tool-servers";
    for (name, srv, trusted) in [("crm", &crm, true), ("notes", &notes, false)] {
        let body = json!({"name": name, "url": srv.url, "auth": {"method": "none"}, "trusted": trusted});
        assert_eq!(send(&e.cp_app, "POST", servers, ADMIN, Some(body), &[]).await.0, StatusCode::CREATED);
        send(&e.cp_app, "POST", &format!("{servers}/{name}/discover"), ADMIN, None, &[]).await;
        let uri = format!("{servers}/{name}/tools/record/approve");
        assert_eq!(send(&e.cp_app, "POST", &uri, ADMIN, Some(json!({"pin": m.pin()})), &[]).await.0, StatusCode::OK);
    }
    let r = |s: &str| format!("mcp://{s}/record#{}", m.pin());
    let spec = |s: &str| {
        json!({
            "kind": "workflow", "model_policy": {}, "budgets": {"steps": 5, "tokens": 10000, "wall_clock_s": 60},
            "tools": [{"ref": r(s), "effect": "read"}],
            "graph": {"vertices": [{"id": "save", "type": "tool", "config": {"tool": r(s), "args": {"email": "{{input.email}}"}}}],
                      "edges": []}
        })
    };
    e.publish("to-crm", spec("crm")).await;
    e.publish("to-notes", spec("notes")).await;
    let j: Arc<dyn Journal> = Arc::new(MemoryJournal::new());
    let w = worker(&e, &j, &idem(), None, "worker-1", LONG);
    let mut outputs = vec![];
    for node in ["to-crm", "to-notes"] {
        let uri = format!("/v1/nodes/{node}/runs");
        let (s, v) = send(&w.app, "POST", &uri, KEY, Some(json!({"input": {"email": EMAIL}})), &[]).await;
        assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("succeeded")), "{v}");
        outputs.push(v);
    }
    assert_eq!(crm.calls()[0].args["email"], EMAIL, "the trusted server gets the value");
    assert_eq!(notes.calls()[0].args["email"], "[EMAIL]", "the untrusted one never does");
    // Results are anonymized as they enter the run.
    for v in outputs {
        assert!(!v["output"].to_string().contains("mary.major@example.org"), "{v}");
        assert_eq!(v["output"]["owner"], "[EMAIL]", "{v}");
    }
}
