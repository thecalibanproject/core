//! Executor behaviour against scripted models and tools, on the memory journal and (when
//! `CALIBAN_TEST_DATABASE_URL` is set) the Postgres journal. The end-to-end tests through the
//! gateway pipeline live in `caliban-gateway` (`nodes_tests.rs`).

use super::*;
use crate::journal::memory::MemoryJournal;
use crate::seal::TestSealer;
use serde_json::json;
use std::sync::atomic::AtomicUsize;

type Script = dyn Fn(&Value) -> Value + Send + Sync;

/// A model that answers with `script(body)` (an assistant message) and logs every call.
struct FakeModel {
    script: Box<Script>,
    calls: Mutex<Vec<(String, String)>>,
    /// Calls for this step block until `release` is notified.
    hold: Mutex<Option<String>>,
    held: Notify,
    release: Notify,
    /// Calls for this step are rate limited this many times first.
    throttle: Mutex<Option<(String, u32)>>,
}

impl FakeModel {
    fn new(script: impl Fn(&Value) -> Value + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            script: Box::new(script),
            calls: Mutex::default(),
            hold: Mutex::new(None),
            held: Notify::new(),
            release: Notify::new(),
            throttle: Mutex::new(None),
        })
    }

    fn calls_for(&self, step: &str) -> usize {
        self.calls.lock().iter().filter(|(s, _)| s == step).count()
    }

    fn steps(&self) -> Vec<String> {
        self.calls.lock().iter().map(|(s, _)| s.clone()).collect()
    }
}

#[async_trait::async_trait]
impl ModelClient for FakeModel {
    async fn chat(&self, ctx: &CallCtx, body: Value) -> Result<ModelReply, ModelError> {
        self.calls.lock().push((ctx.step_id.clone(), ctx.idempotency_key.clone()));
        if let Some((step, left)) = self.throttle.lock().as_mut()
            && *step == ctx.step_id
            && *left > 0
        {
            *left -= 1;
            return Err(ModelError::Throttled { retry_after: Duration::from_millis(30), message: "429".into() });
        }
        let hold = self.hold.lock().as_deref() == Some(ctx.step_id.as_str());
        if hold {
            *self.hold.lock() = None;
            self.held.notify_one();
            self.release.notified().await;
        }
        let message = (self.script)(&body);
        Ok(ModelReply { message, tokens: 10, usd: 0.001, replayed: false })
    }
}

fn text(s: &str) -> Value {
    json!({"role": "assistant", "content": s})
}

fn last_user(body: &Value) -> String {
    body["messages"]
        .as_array()
        .and_then(|m| m.iter().rev().find(|m| m["role"] == "user"))
        .and_then(|m| m["content"].as_str())
        .unwrap_or_default()
        .to_owned()
}

fn system(body: &Value) -> String {
    body["messages"][0]["content"].as_str().unwrap_or_default().to_owned()
}

#[derive(Default)]
struct Nodes(Mutex<HashMap<(String, u32), Arc<NodeSpec>>>, Mutex<TenantPolicy>);

impl Nodes {
    fn add(&self, name: &str, version: u32, spec: Value) {
        let spec: NodeSpec = serde_json::from_value(spec).unwrap();
        spec.validate().unwrap();
        self.0.lock().insert((name.to_owned(), version), Arc::new(spec));
    }

    /// The version leaves the data plane (retired).
    fn retire(&self, name: &str, version: u32) {
        self.0.lock().remove(&(name.to_owned(), version));
    }
}

impl NodeSource for Nodes {
    fn resolve(&self, _tenant: &str, name: &str, version: Option<u32>) -> Result<ResolvedNode, String> {
        let nodes = self.0.lock();
        let (key, spec) = match version {
            Some(v) => nodes.get_key_value(&(name.to_owned(), v)),
            None => nodes.iter().filter(|((n, _), _)| n == name).max_by_key(|((_, v), _)| *v),
        }
        .ok_or_else(|| format!("node {name} is not published"))?;
        let hash = crate::hash::content_hash(&serde_json::to_value(spec.as_ref()).unwrap());
        Ok(ResolvedNode { name: key.0.clone(), version: key.1, hash, spec: Arc::clone(spec) })
    }

    fn tenant_policy(&self, _tenant: &str) -> TenantPolicy {
        self.1.lock().clone()
    }
}

struct Harness {
    journal: Arc<dyn Journal>,
    nodes: Arc<Nodes>,
    sealer: Arc<TestSealer>,
    tools: Arc<StaticTools>,
}

impl Harness {
    fn new(journal: Arc<dyn Journal>) -> Self {
        Self { journal, nodes: Arc::default(), sealer: Arc::default(), tools: Arc::new(StaticTools::new()) }
    }

    fn with_tools(mut self, tools: StaticTools) -> Self {
        self.tools = Arc::new(tools);
        self
    }

    fn executor(&self, model: &Arc<FakeModel>, worker: &str) -> Arc<Executor> {
        self.executor_with(model, worker, |_| {})
    }

    fn executor_with(
        &self,
        model: &Arc<FakeModel>,
        worker: &str,
        tune: impl FnOnce(&mut ExecutorOptions),
    ) -> Arc<Executor> {
        let mut opts = ExecutorOptions {
            // Long enough that a slow machine never loses a lease by accident; the takeover
            // test waits for it once.
            lease_ttl: Duration::from_secs(1),
            heartbeat: Duration::from_millis(100),
            poll: Duration::from_millis(20),
            model_retry_for: Duration::from_secs(5),
            ..ExecutorOptions::default()
        };
        tune(&mut opts);
        Arc::new(Executor::new(
            Arc::clone(&self.journal),
            Arc::clone(model) as Arc<dyn ModelClient>,
            Arc::clone(&self.tools) as Arc<dyn ToolRegistry>,
            Arc::clone(&self.nodes) as Arc<dyn NodeSource>,
            Arc::clone(&self.sealer) as Arc<dyn Sealer>,
            worker,
            opts,
        ))
    }
}

fn start(node: &str, input: Value) -> StartRun {
    StartRun {
        tenant: "acme".into(),
        node: node.into(),
        version: None,
        input,
        invoker: "api_key:test".into(),
        invoker_key_hash: None,
        idempotency: None,
        budget: None,
    }
}

/// Creates a run and runs it on `ex` until it ends or suspends.
async fn run(ex: &Arc<Executor>, node: &str, input: Value) -> RunView {
    let (r, _) = ex.create(start(node, input)).await.unwrap();
    assert!(ex.run_now(&r.id).await.unwrap());
    ex.view("acme", &r.id).await.unwrap().unwrap()
}

async fn journals() -> Vec<Arc<dyn Journal>> {
    crate::journal::tests::journals().await
}

fn budgets(steps: u32, tokens: u64) -> Value {
    json!({"steps": steps, "tokens": tokens, "wall_clock_s": 60})
}

fn triage_spec() -> Value {
    json!({
        "kind": "workflow",
        "prompt": {"system": "You triage support cases."},
        "model_policy": {},
        "budgets": budgets(20, 10_000),
        "graph": {
            "vertices": [
                {"id": "classify", "type": "router", "config": {"routes": {"billing": "money", "clinical": "health"}}},
                {"id": "ask", "type": "human", "config": {"question": "What is the patient's age? ({{input.route}})"}},
                {"id": "recommend", "type": "llm", "config": {
                    "prompt": "Case: {{input.case}}; age {{input.answer}}; category {{outputs.classify.route}}",
                    "output_schema": {"type": "object", "required": ["service"], "properties": {"service": {"type": "string"}}}
                }}
            ],
            "edges": [{"from": "classify", "to": "ask", "when": "clinical"}, {"from": "ask", "to": "recommend"}]
        }
    })
}

fn triage_model() -> Arc<FakeModel> {
    FakeModel::new(|body| {
        if system(body).contains("Labels:") {
            text("clinical")
        } else {
            let u = last_user(body);
            text(&format!("{{\"service\": \"gp ({u})\"}}"))
        }
    })
}

#[tokio::test]
async fn a_workflow_runs_waits_for_a_human_and_resumes() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add("triage", 1, triage_spec());
        let model = triage_model();
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "triage", json!({"case": "chest pain"})).await;
        assert_eq!(v.status, RunStatus::InputRequired, "{v:?}");
        let a = v.awaiting.clone().unwrap();
        assert_eq!((a.step.as_str(), a.question.as_deref()), ("ask#0", Some("What is the patient's age? (clinical)")));
        assert_eq!(v.steps.len(), 1, "the router step is checkpointed");
        // A worker restart (a new executor) changes nothing until the answer comes.
        let ex2 = h.executor(&model, "w2");
        assert!(!ex2.run_now(&v.id).await.unwrap(), "not runnable while it waits");
        assert_eq!(ex2.deliver_input("acme", &v.id, None, &json!(41)).await.unwrap(), Delivered::Accepted);
        assert_eq!(ex2.deliver_input("acme", &v.id, None, &json!(42)).await.unwrap(), Delivered::NotAwaiting);
        assert!(ex2.run_now(&v.id).await.unwrap());
        let v = ex2.view("acme", &v.id).await.unwrap().unwrap();
        assert_eq!(v.status, RunStatus::Succeeded, "{v:?}");
        assert_eq!(v.output, Some(json!({"service": "gp (Case: chest pain; age 41; category clinical)"})));
        assert_eq!(v.steps.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), ["classify#0", "ask#0", "recommend#0"]);
        assert_eq!(model.calls_for("classify#0"), 1, "the replay did not classify again");
        assert_eq!((v.budget.steps_used, v.budget.tokens_used), (3, 20), "{:?}", v.budget);
        assert_eq!(v.claims, 2);
    }
}

#[tokio::test]
async fn a_dead_worker_is_replaced_and_completed_steps_are_not_rerun() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add(
            "chain",
            1,
            json!({
                "kind": "workflow", "model_policy": {}, "budgets": budgets(10, 10_000),
                "graph": {"vertices": [{"id": "a", "type": "llm"}, {"id": "b", "type": "llm"}, {"id": "c", "type": "llm"}],
                          "edges": [{"from": "a", "to": "b"}, {"from": "b", "to": "c"}]}
            }),
        );
        let model = FakeModel::new(|body| text(&format!("<{}>", last_user(body))));
        *model.hold.lock() = Some("b#0".into());
        let w1 = h.executor(&model, "w1");
        let (r, _) = w1.create(start("chain", json!("x"))).await.unwrap();
        let task = {
            let (w1, id) = (Arc::clone(&w1), r.id.clone());
            tokio::spawn(async move { w1.run_now(&id).await })
        };
        // Worker 1 dies in the middle of step b.
        model.held.notified().await;
        task.abort();
        let _ = task.await;
        // Worker 2 takes the run over once worker 1's lease has expired.
        let w2 = h.executor(&model, "w2");
        let stop = Arc::new(Notify::new());
        tokio::spawn(Arc::clone(&w2).run_loop(Arc::clone(&stop)));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut done = None;
        while Instant::now() < deadline {
            done = w2.wait("acme", &r.id, deadline).await.unwrap();
            if done.as_ref().is_some_and(|d| d.status.is_terminal()) {
                break;
            }
        }
        stop.notify_waiters();
        let done = done.unwrap();
        assert_eq!(done.status, RunStatus::Succeeded, "{done:?}");
        let v = w2.view("acme", &r.id).await.unwrap().unwrap();
        assert_eq!(v.output, Some(json!("<<<x>>>")));
        assert_eq!(model.calls_for("a#0"), 1, "step a completed before the crash: never called again");
        assert_eq!(model.calls_for("c#0"), 1);
        // Step b was in flight: it is called again with the same idempotency key, so the gateway
        // answers the second call from the first one's stored response (see the gateway tests).
        let keys: Vec<String> = model.calls.lock().iter().filter(|(s, _)| s == "b#0").map(|(_, k)| k.clone()).collect();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], keys[1]);
        assert_eq!(v.claims, 2);
    }
}

#[tokio::test]
async fn budget_exhaustion_ends_with_partial_results() {
    for j in journals().await {
        let h = Harness::new(j);
        let spec = |steps: u32, tokens: u64| {
            json!({
                "kind": "workflow", "model_policy": {}, "budgets": budgets(steps, tokens),
                "graph": {"vertices": [{"id": "a", "type": "llm"}, {"id": "b", "type": "llm"}, {"id": "c", "type": "llm"}],
                          "edges": [{"from": "a", "to": "b"}, {"from": "b", "to": "c"}]}
            })
        };
        h.nodes.add("steps", 1, spec(2, 10_000));
        h.nodes.add("tokens", 1, spec(10, 15));
        let model = FakeModel::new(|body| text(&format!("<{}>", last_user(body))));
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "steps", json!("x")).await;
        assert_eq!(v.status, RunStatus::BudgetExhausted);
        assert!(v.partial && v.stop_reason.as_deref() == Some("step budget exhausted"), "{v:?}");
        assert_eq!(v.output, Some(json!("<<x>>")), "the partial result is the last completed value");
        assert_eq!(v.steps.len(), 2);
        // Tokens: each call costs 10; the second one overruns 15 and the run stops after it.
        let v = run(&ex, "tokens", json!("x")).await;
        assert_eq!(v.status, RunStatus::BudgetExhausted);
        assert!(v.stop_reason.as_deref().unwrap().starts_with("token budget exhausted"), "{v:?}");
        assert_eq!((v.steps.len(), v.budget.tokens_used), (2, 15));
        assert_eq!(v.output, Some(json!("<<x>>")));
    }
}

#[tokio::test]
async fn a_bounded_loop_stops_at_max_iterations() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add(
            "refine",
            1,
            json!({
                "kind": "workflow", "model_policy": {}, "budgets": budgets(50, 100_000),
                "graph": {
                    "vertices": [{"id": "draft", "type": "llm", "config": {"prompt": "improve: {{input}}"}},
                                 {"id": "check", "type": "verify", "config": {"check": "llm", "criteria": "perfect"}, "max_iterations": 3}],
                    "edges": [{"from": "draft", "to": "check"}, {"from": "check", "to": "draft", "when": "fail"}]
                }
            }),
        );
        let model =
            FakeModel::new(
                |body| if system(body).contains("criteria") { text("FAIL: not yet") } else { text("draft") },
            );
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "refine", json!("x")).await;
        assert_eq!(v.status, RunStatus::Succeeded, "{v:?}");
        let ids: Vec<&str> = v.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["draft#0", "check#0", "draft#1", "check#1", "draft#2", "check#2"]);
        assert!(v.stop_reason.unwrap().contains("max_iterations (3)"));
        assert_eq!(v.output.unwrap()["feedback"], "not yet");
    }
}

/// Waits at a barrier of `n`: if the branches ran one after the other it would time out.
struct Barrier {
    barrier: tokio::sync::Barrier,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

#[async_trait::async_trait]
impl Tool for Barrier {
    fn info(&self) -> ToolInfo {
        ToolInfo {
            name: "score".into(),
            description: "Scores an item.".into(),
            input_schema: json!({"type": "object"}),
        }
    }

    async fn call(&self, _ctx: &ToolCtx, args: Value) -> Result<Value, ToolError> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), self.barrier.wait())
            .await
            .map_err(|_| ToolError::Failed("branches did not run concurrently".into()))?;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        Ok(json!({"item": args, "score": 1}))
    }
}

const PIN: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

#[tokio::test]
async fn map_fans_out_concurrently_and_reduce_joins() {
    for j in journals().await {
        let tool = Arc::new(Barrier {
            barrier: tokio::sync::Barrier::new(4),
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        });
        let reference = format!("mcp://scoring/score#{PIN}");
        let h = Harness::new(j).with_tools(StaticTools::new().with(reference.clone(), tool.clone()));
        h.nodes.add(
            "fan",
            1,
            json!({
                "kind": "workflow", "model_policy": {}, "budgets": {"steps": 20, "tokens": 1000, "wall_clock_s": 60, "fanout": 4},
                "tools": [{"ref": reference, "effect": "read"}],
                "graph": {
                    "vertices": [{"id": "each", "type": "map", "config": {"over": "/items", "body": {"type": "tool", "config": {"tool": reference}}}},
                                 {"id": "join", "type": "reduce", "config": {"mode": "concat"}}],
                    "edges": [{"from": "each", "to": "join"}]
                }
            }),
        );
        let model = FakeModel::new(|_| text("unused"));
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "fan", json!({"items": ["a", "b", "c", "d"]})).await;
        assert_eq!(v.status, RunStatus::Succeeded, "{v:?}");
        assert_eq!(tool.peak.load(Ordering::SeqCst), 4, "all four branches were in flight at once");
        let out = v.output.unwrap();
        assert_eq!(out.as_array().unwrap().len(), 4);
        assert_eq!(out[2], json!({"item": "c", "score": 1}), "results keep the input order");
        let mut ids: Vec<&str> = v.steps.iter().map(|s| s.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["each#0/0", "each#0/1", "each#0/2", "each#0/3"]);
    }
}

#[tokio::test]
async fn agents_loop_over_tools_until_a_final_answer() {
    for j in journals().await {
        let reference = format!("mcp://catalogue/search#{PIN}");
        let catalogue = Arc::new(FnTool {
            info: ToolInfo {
                name: "search".into(),
                description: "Searches the service catalogue.".into(),
                input_schema: json!({"type": "object", "properties": {"q": {"type": "string"}}}),
            },
            f: |_ctx: &ToolCtx, args: Value| {
                Ok(json!({"services": [format!("{}-clinic", args["q"].as_str().unwrap_or("?"))]}))
            },
        });
        let h = Harness::new(j).with_tools(StaticTools::new().with(reference.clone(), catalogue));
        h.nodes.add("helper", 1, json!({"kind": "agent", "model_policy": {}, "budgets": budgets(3, 1000)}));
        h.nodes.add(
            "agent",
            1,
            json!({
                "kind": "agent", "prompt": {"system": "Find a service."}, "model_policy": {},
                "tools": [{"ref": reference, "effect": "read"}, {"ref": "node://helper@v1", "effect": "read"}],
                "budgets": budgets(10, 10_000)
            }),
        );
        let model = FakeModel::new(|body| {
            let msgs = body["messages"].as_array().unwrap();
            let results: Vec<&str> =
                msgs.iter().filter(|m| m["role"] == "tool").filter_map(|m| m["content"].as_str()).collect();
            if body.get("tools").is_none() {
                return text("helper says hi");
            }
            if results.is_empty() {
                json!({"role": "assistant", "content": null, "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "search", "arguments": "{\"q\":\"cardio\"}"}},
                    {"id": "c2", "type": "function", "function": {"name": "helper_v1", "arguments": "{}"}},
                    {"id": "c3", "type": "function", "function": {"name": "nope", "arguments": "{}"}}
                ]})
            } else {
                text(&format!("done: {}", results.join(" | ")))
            }
        });
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "agent", json!("cardiology for a 41 year old")).await;
        assert_eq!(v.status, RunStatus::Succeeded, "{v:?}");
        let out = v.output.unwrap();
        let out = out.as_str().unwrap();
        assert!(
            out.contains("cardio-clinic") && out.contains("helper says hi") && out.contains("no tool named 'nope'"),
            "{out}"
        );
        let ids: Vec<&str> = v.steps.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["agent#0", "agent#0.0", "agent#0.1>agent#0", "agent#0.1", "agent#1"]);
    }
}

#[tokio::test]
async fn an_agent_stops_at_its_turn_limit() {
    for j in journals().await {
        let reference = format!("mcp://catalogue/search#{PIN}");
        let echo = Arc::new(FnTool {
            info: ToolInfo { name: "search".into(), description: "d".into(), input_schema: json!({"type": "object"}) },
            f: |_ctx: &ToolCtx, _args: Value| Ok(json!("again")),
        });
        let h = Harness::new(j).with_tools(StaticTools::new().with(reference.clone(), echo));
        h.nodes.add(
            "loopy",
            1,
            json!({"kind": "agent", "model_policy": {}, "tools": [{"ref": reference, "effect": "read"}],
                   "agent": {"max_turns": 2}, "budgets": budgets(50, 10_000)}),
        );
        let model = FakeModel::new(
            |_| json!({"role": "assistant", "content": "thinking", "tool_calls": [{"id": "c", "type": "function", "function": {"name": "search", "arguments": "{}"}}]}),
        );
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "loopy", json!("x")).await;
        assert_eq!(v.status, RunStatus::BudgetExhausted);
        assert!(v.stop_reason.unwrap().contains("turn limit (2)"));
        assert_eq!(v.output, Some(json!("thinking")));
        assert_eq!(model.steps(), ["agent#0", "agent#1"]);
    }
}

#[tokio::test]
async fn unknown_and_unavailable_tools_fail_clearly() {
    for j in journals().await {
        let h = Harness::new(j);
        let reference = format!("mcp://erp/lookup#{PIN}");
        h.nodes.add(
            "uses-mcp",
            1,
            json!({"kind": "workflow", "model_policy": {}, "budgets": budgets(5, 1000), "tools": [{"ref": reference, "effect": "read"}],
                   "graph": {"vertices": [{"id": "t", "type": "tool", "config": {"tool": reference}}], "edges": []}}),
        );
        let model = FakeModel::new(|_| text("unused"));
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "uses-mcp", json!({})).await;
        assert_eq!(v.status, RunStatus::Failed);
        let e = v.error.unwrap();
        assert!(e.contains("not available") && e.contains("M4"), "{e}");
        assert_eq!(v.steps[0].status, StepStatus::Failed, "the failed step is recorded");
    }
}

#[tokio::test]
async fn outputs_are_validated_and_corrected_once() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add(
            "structured",
            1,
            json!({"kind": "workflow", "model_policy": {}, "budgets": budgets(5, 1000),
                   "graph": {"vertices": [{"id": "x", "type": "llm", "config": {"output_schema": {"type": "object", "required": ["n"], "properties": {"n": {"type": "integer"}}}}}], "edges": []}}),
        );
        // First answer is prose; the corrective retry returns JSON.
        let model = FakeModel::new(|body| {
            if body["messages"].as_array().unwrap().len() > 2 {
                text("```json\n{\"n\": 7}\n```")
            } else {
                text("seven")
            }
        });
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "structured", json!("count")).await;
        assert_eq!((v.status, v.output.clone()), (RunStatus::Succeeded, Some(json!({"n": 7}))), "{v:?}");
        assert_eq!(model.steps(), ["x#0", "x#0~r1"]);
        // Never valid: the run fails with the schema violation.
        let model = FakeModel::new(|_| text("{\"n\": \"seven\"}"));
        let v = run(&h.executor(&model, "w2"), "structured", json!("count")).await;
        assert_eq!(v.status, RunStatus::Failed);
        assert!(v.error.unwrap().contains("/n: expected \"integer\""));
    }
}

#[tokio::test]
async fn run_data_is_sealed_at_rest() {
    let mem = Arc::new(MemoryJournal::new());
    let h = Harness::new(Arc::clone(&mem) as Arc<dyn Journal>);
    h.nodes.add("triage", 1, triage_spec());
    let model = triage_model();
    let ex = h.executor(&model, "w1");
    let v = run(&ex, "triage", json!({"case": "patient Jane Roe, chest pain"})).await;
    ex.deliver_input("acme", &v.id, None, &json!("forty-one")).await.unwrap();
    ex.run_now(&v.id).await.unwrap();
    let r = mem.get_run("acme", &v.id).await.unwrap().unwrap();
    assert_eq!(r.status, RunStatus::Succeeded);
    let steps = mem.steps(&v.id).await.unwrap();
    let ev = mem.event(&v.id, "ask#0").await.unwrap().unwrap();
    let mut stored = vec![r.input.clone(), r.output.clone().unwrap(), ev.payload.unwrap()];
    stored.extend(steps.iter().filter_map(|s| s.result.clone()));
    assert_eq!(stored.len(), 6);
    for s in &stored {
        // Markers with characters base64 never contains, so a ciphertext cannot match by chance.
        assert!(
            !s.contains("Jane Roe")
                && !s.contains("chest pain")
                && !s.contains("forty-one")
                && !s.contains("\"service\""),
            "{s}"
        );
        assert!(h.sealer.open("acme", &v.id, s).is_ok());
        assert!(h.sealer.open("acme", "run_other", s).is_err(), "bound to its run");
    }
}

#[tokio::test]
async fn subnodes_run_inside_the_run_under_a_child_budget() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add(
            "child",
            1,
            json!({"kind": "workflow", "model_policy": {}, "budgets": budgets(1, 1000),
                   "graph": {"vertices": [{"id": "a", "type": "llm"}, {"id": "b", "type": "llm"}], "edges": [{"from": "a", "to": "b"}]}}),
        );
        h.nodes.add(
            "parent",
            1,
            json!({"kind": "workflow", "model_policy": {}, "budgets": budgets(10, 1000),
                   "graph": {"vertices": [{"id": "call", "type": "subnode", "config": {"node": "node://child@v1"}}], "edges": []}}),
        );
        let model = FakeModel::new(|body| text(&format!("<{}>", last_user(body))));
        let v = run(&h.executor(&model, "w1"), "parent", json!("x")).await;
        assert_eq!(v.status, RunStatus::BudgetExhausted, "the child's own budget (1 step) stops it: {v:?}");
        assert_eq!(v.steps.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), ["call#0>a#0"]);
        assert_eq!(v.output, Some(json!("<x>")));
    }
}

#[tokio::test]
async fn run_creation_is_idempotent_and_inputs_are_validated() {
    let h = Harness::new(Arc::new(MemoryJournal::new()));
    h.nodes.add(
        "strict",
        1,
        json!({"kind": "agent", "model_policy": {}, "budgets": budgets(3, 100),
               "prompt": {"system": "x", "input_schema": {"type": "object", "required": ["case"]}}}),
    );
    let ex = h.executor(&FakeModel::new(|_| text("ok")), "w1");
    let mut req = start("strict", json!({"case": "c"}));
    req.idempotency = Some(("key-1".into(), "fp-1".into()));
    let (a, new) = ex.create(req.clone()).await.unwrap();
    assert!(new);
    let (b, new) = ex.create(req.clone()).await.unwrap();
    assert!(!new);
    assert_eq!(a.id, b.id);
    req.idempotency = Some(("key-1".into(), "fp-2".into()));
    assert_eq!(ex.create(req).await.unwrap_err(), ExecError::KeyReused);
    let e = ex.create(start("strict", json!({"other": 1}))).await.unwrap_err();
    assert!(matches!(e, ExecError::Invalid(ref m) if m.contains("case")), "{e}");
    assert!(matches!(ex.create(start("ghost", json!({}))).await.unwrap_err(), ExecError::NotFound(_)));
}

#[tokio::test]
async fn rate_limited_steps_sleep_durably_then_resume() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add(
            "chain",
            1,
            json!({"kind": "workflow", "model_policy": {}, "budgets": budgets(10, 10_000),
                   "graph": {"vertices": [{"id": "a", "type": "llm"}, {"id": "b", "type": "llm"}], "edges": [{"from": "a", "to": "b"}]}}),
        );
        let model = FakeModel::new(|body| text(&format!("<{}>", last_user(body))));
        *model.throttle.lock() = Some(("b#0".into(), 2));
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "chain", json!("x")).await;
        // The worker is not held: the run sleeps in the journal until the limit resets.
        assert_eq!(v.status, RunStatus::Sleeping, "{v:?}");
        assert_eq!(v.steps.len(), 1);
        let stop = Arc::new(Notify::new());
        tokio::spawn(Arc::clone(&ex).run_loop(Arc::clone(&stop)));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut done = None;
        while Instant::now() < deadline {
            done = ex.wait("acme", &v.id, Instant::now() + Duration::from_millis(100)).await.unwrap();
            if done.as_ref().is_some_and(|d| d.status.is_terminal()) {
                break;
            }
        }
        stop.notify_waiters();
        let done = done.unwrap();
        assert_eq!(done.status, RunStatus::Succeeded, "{done:?}");
        assert_eq!(model.calls_for("a#0"), 1, "a is not re-run after the sleeps");
        assert_eq!(model.calls_for("b#0"), 3, "two rate-limited calls, then the answer");
        assert!(h.journal.event(&v.id, "b#0:throttled:1").await.unwrap().is_some());
        assert!(h.journal.event(&v.id, "b#0:throttled:2").await.unwrap().is_none());
    }
}

#[tokio::test]
async fn run_data_is_sealed_at_rest_in_postgres() {
    let Some(pg) = crate::journal::tests::pg_journal().await else {
        eprintln!("CALIBAN_TEST_DATABASE_URL not set; skipping");
        return;
    };
    let pool = pg.pool().clone();
    let h = Harness::new(Arc::new(pg));
    h.nodes.add("triage", 1, triage_spec());
    let model = triage_model();
    let ex = h.executor(&model, "w1");
    let v = run(&ex, "triage", json!({"case": "patient Jane Roe, chest pain"})).await;
    ex.deliver_input("acme", &v.id, None, &json!("forty-one")).await.unwrap();
    ex.run_now(&v.id).await.unwrap();
    assert_eq!(ex.view("acme", &v.id).await.unwrap().unwrap().status, RunStatus::Succeeded);
    let stored: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT input FROM node_run UNION ALL SELECT output FROM node_run UNION ALL SELECT prompt FROM node_run
         UNION ALL SELECT result FROM node_step UNION ALL SELECT payload FROM node_event WHERE kind = 'input'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let stored: Vec<String> = stored.into_iter().flatten().collect();
    assert_eq!(stored.len(), 6, "input, output, three step results, the answer");
    for s in &stored {
        // Markers with characters base64 never contains, so a ciphertext cannot match by chance.
        assert!(
            !s.contains("Jane Roe")
                && !s.contains("chest pain")
                && !s.contains("forty-one")
                && !s.contains("\"service\""),
            "{s}"
        );
        assert!(h.sealer.open("acme", &v.id, s).is_ok());
    }
}

#[tokio::test]
async fn retiring_a_version_drains_its_runs() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add(
            "inner",
            1,
            json!({"kind": "workflow", "model_policy": {}, "budgets": budgets(5, 10_000),
                   "graph": {"vertices": [{"id": "say", "type": "llm", "config": {"prompt": "inner {{input}}"}}], "edges": []}}),
        );
        h.nodes.add(
            "outer",
            1,
            json!({"kind": "workflow", "model_policy": {}, "budgets": budgets(10, 10_000),
                   "graph": {"vertices": [{"id": "ask", "type": "human", "config": {"question": "Go?"}},
                                          {"id": "call", "type": "subnode", "config": {"node": "node://inner@v1", "input": "{{input.answer}}"}}],
                             "edges": [{"from": "ask", "to": "call"}]}}),
        );
        let model = FakeModel::new(|body| text(&format!("<{}>", last_user(body))));
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "outer", json!({"case": 1})).await;
        assert_eq!(v.status, RunStatus::InputRequired, "{v:?}");
        // Both versions are retired while the run waits: new runs are refused...
        h.nodes.retire("outer", 1);
        h.nodes.retire("inner", 1);
        assert!(matches!(ex.create(start("outer", json!({}))).await, Err(ExecError::NotFound(_))));
        // ...but the run in flight finishes on the versions it started on, the subnode included.
        let ex2 = h.executor(&model, "w2");
        assert_eq!(ex2.deliver_input("acme", &v.id, None, &json!("yes")).await.unwrap(), Delivered::Accepted);
        assert!(ex2.run_now(&v.id).await.unwrap());
        let v = ex2.view("acme", &v.id).await.unwrap().unwrap();
        assert_eq!((v.status, v.output.clone()), (RunStatus::Succeeded, Some(json!("<inner yes>"))), "{v:?}");
    }
}

/// Each model call of `FakeModel` costs $0.001.
fn chain(n: usize, budgets: Value) -> Value {
    let vertices: Vec<Value> = (0..n).map(|i| json!({"id": format!("s{i}"), "type": "llm"})).collect();
    let edges: Vec<Value> = (1..n).map(|i| json!({"from": format!("s{}", i - 1), "to": format!("s{i}")})).collect();
    json!({"kind": "workflow", "model_policy": {}, "budgets": budgets, "graph": {"vertices": vertices, "edges": edges}})
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

#[tokio::test]
async fn usd_caps_stop_runs_gracefully_and_run_budgets_only_lower_them() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add("spend", 1, chain(5, json!({"steps": 20, "tokens": 100_000, "wall_clock_s": 60, "usd": 0.0025})));
        let model = FakeModel::new(|body| text(&format!("<{}>", last_user(body))));
        let ex = h.executor(&model, "w1");
        let v = run(&ex, "spend", json!("x")).await;
        assert_eq!(v.status, RunStatus::BudgetExhausted, "{v:?}");
        assert!(v.stop_reason.as_deref().unwrap().starts_with("USD budget exhausted"), "{v:?}");
        assert_eq!(v.steps.len(), 3, "the third call overruns $0.0025 and the run stops after it");
        assert!(close(v.cost_usd, 0.003) && close(v.budget.usd, 0.003), "{v:?}");
        assert_eq!(v.budget.usd_limit, Some(0.0025));
        assert_eq!(v.output, Some(json!("<<<x>>>")), "partial result");

        // The run asks for less: honoured. It cannot ask for more than the version allows.
        let mut req = start("spend", json!("x"));
        req.budget = Some(RunBudget { usd: Some(0.0015), ..RunBudget::default() });
        let (r, _) = ex.create(req).await.unwrap();
        ex.run_now(&r.id).await.unwrap();
        let v = ex.view("acme", &r.id).await.unwrap().unwrap();
        assert_eq!((v.status, v.steps.len(), v.budget.usd_limit), (RunStatus::BudgetExhausted, 2, Some(0.0015)));
        let mut req = start("spend", json!("x"));
        req.budget = Some(RunBudget { usd: Some(5.0), steps: Some(2), ..RunBudget::default() });
        let (r, _) = ex.create(req).await.unwrap();
        assert_eq!((r.budget.usd_limit, r.budget.steps_limit), (Some(0.0025), 2));
        let mut bad = start("spend", json!("x"));
        bad.budget = Some(RunBudget { usd: Some(-1.0), ..RunBudget::default() });
        assert!(matches!(ex.create(bad).await, Err(ExecError::Invalid(_))));
    }
}

#[tokio::test]
async fn a_subnode_gets_at_most_what_its_parent_has_left() {
    for j in journals().await {
        let h = Harness::new(j);
        // The child would allow $1; the parent has $0.0025 left when it calls it.
        h.nodes.add("child", 1, chain(5, json!({"steps": 20, "tokens": 100_000, "wall_clock_s": 60, "usd": 1.0})));
        h.nodes.add(
            "parent",
            1,
            json!({"kind": "workflow", "model_policy": {}, "budgets": {"steps": 20, "tokens": 100_000, "wall_clock_s": 60, "usd": 0.0035},
                   "graph": {"vertices": [{"id": "first", "type": "llm"},
                                          {"id": "call", "type": "subnode", "config": {"node": "node://child@v1"}}],
                             "edges": [{"from": "first", "to": "call"}]}}),
        );
        let model = FakeModel::new(|body| text(&format!("<{}>", last_user(body))));
        let v = run(&h.executor(&model, "w1"), "parent", json!("x")).await;
        assert_eq!(v.status, RunStatus::BudgetExhausted, "{v:?}");
        assert_eq!(
            v.steps.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            ["first#0", "call#0>s0#0", "call#0>s1#0", "call#0>s2#0"]
        );
        assert!(close(v.cost_usd, 0.004), "{v:?}");
        assert_eq!((v.budget.depth_used, v.budget.depth_limit), (1, 3));
    }
}

#[tokio::test]
async fn a_resumed_run_keeps_what_it_spent() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add(
            "pause",
            1,
            json!({"kind": "workflow", "model_policy": {}, "budgets": {"steps": 20, "tokens": 100_000, "wall_clock_s": 60, "usd": 0.0025},
                   "graph": {"vertices": [{"id": "a", "type": "llm"}, {"id": "b", "type": "llm"},
                                          {"id": "ask", "type": "human", "config": {"question": "go on?"}},
                                          {"id": "c", "type": "llm"}, {"id": "d", "type": "llm"}],
                             "edges": [{"from": "a", "to": "b"}, {"from": "b", "to": "ask"}, {"from": "ask", "to": "c"}, {"from": "c", "to": "d"}]}}),
        );
        let model = FakeModel::new(|body| text(&format!("<{}>", last_user(body))));
        let v = run(&h.executor(&model, "w1"), "pause", json!("x")).await;
        assert_eq!(v.status, RunStatus::InputRequired);
        assert!(close(v.budget.usd, 0.002), "the spend is persisted while the run waits: {v:?}");
        // Another worker resumes it: it starts from $0.002 spent, not from zero, so c overruns.
        let w2 = h.executor(&model, "w2");
        w2.deliver_input("acme", &v.id, None, &json!("yes")).await.unwrap();
        w2.run_now(&v.id).await.unwrap();
        let v = w2.view("acme", &v.id).await.unwrap().unwrap();
        assert_eq!(v.status, RunStatus::BudgetExhausted, "{v:?}");
        assert_eq!(v.steps.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(), ["a#0", "b#0", "ask#0", "c#0"]);
        assert!(close(v.cost_usd, 0.003), "{v:?}");
        assert_eq!((model.calls_for("a#0"), model.calls_for("d#0")), (1, 0));
    }
}

#[tokio::test]
async fn the_tenant_daily_cap_holds_across_workers() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add("spend", 1, chain(10, json!({"steps": 20, "tokens": 100_000, "wall_clock_s": 60})));
        h.nodes.1.lock().spend = caliban_config::NodeSpendCaps { daily_usd: Some(0.0025), monthly_usd: Some(1.0) };
        let model = FakeModel::new(|body| text(&format!("<{}>", last_user(body))));
        // Worker 1 spends until the cap: three calls, the fourth is refused before it is made.
        let w1 = h.executor(&model, "w1");
        let v = run(&w1, "spend", json!("x")).await;
        assert_eq!((v.status, v.steps.len()), (RunStatus::BudgetExhausted, 3), "{v:?}");
        assert!(v.stop_reason.as_deref().unwrap().contains("daily node spend cap"), "{v:?}");
        let spent = h.journal.tenant_spend("acme").await.unwrap();
        assert!(close(spent.today_usd, 0.003) && close(spent.month_usd, 0.003), "{spent:?}");
        // Worker 2 (another process, the same journal) refuses at once: nothing is called.
        let w2 = h.executor(&model, "w2");
        let calls = model.calls.lock().len();
        let v = run(&w2, "spend", json!("y")).await;
        assert_eq!((v.status, v.steps.len()), (RunStatus::BudgetExhausted, 0), "{v:?}");
        assert_eq!(model.calls.lock().len(), calls);
        // Another tenant is not affected; the monthly cap works the same way.
        assert!(close(h.journal.tenant_spend("globex").await.unwrap().today_usd, 0.0));
        h.nodes.1.lock().spend = caliban_config::NodeSpendCaps { daily_usd: None, monthly_usd: Some(0.003) };
        let v = run(&w2, "spend", json!("z")).await;
        assert!(v.stop_reason.as_deref().unwrap().contains("monthly node spend cap"), "{v:?}");
    }
}

#[tokio::test]
async fn the_loop_guard_stops_a_loop_that_makes_no_progress() {
    for j in journals().await {
        let h = Harness::new(j);
        h.nodes.add(
            "stuck",
            1,
            json!({
                "kind": "workflow", "model_policy": {}, "budgets": budgets(50, 100_000), "guards": {"max_repeats": 2},
                "graph": {
                    "vertices": [{"id": "draft", "type": "llm", "config": {"prompt": "improve"}},
                                 {"id": "check", "type": "verify", "config": {"check": "llm"}, "max_iterations": 10}],
                    "edges": [{"from": "draft", "to": "check"}, {"from": "check", "to": "draft", "when": "fail"}]
                }
            }),
        );
        // The model answers the same thing every time: the loop never progresses.
        let model =
            FakeModel::new(|body| if system(body).contains("criteria") { text("FAIL: no") } else { text("same") });
        let v = run(&h.executor(&model, "w1"), "stuck", json!("x")).await;
        assert_eq!(v.status, RunStatus::BudgetExhausted, "{v:?}");
        assert!(v.stop_reason.as_deref().unwrap().starts_with("loop guard: vertex 'draft'"), "{v:?}");
        assert!(v.steps.len() < 10, "stopped long before max_iterations: {}", v.steps.len());
        let spec: NodeSpec =
            serde_json::from_value(json!({"kind": "agent", "model_policy": {}, "budgets": budgets(1, 1),
            "guards": {"max_repeats": 0}}))
            .unwrap();
        assert!(spec.validate().is_err(), "max_repeats must be at least 1");
    }
}

/// A tool that fails transiently while `failing` is set.
struct Flaky {
    calls: AtomicUsize,
    failing: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl Tool for Flaky {
    fn info(&self) -> ToolInfo {
        ToolInfo {
            name: "flaky".into(),
            description: "Sometimes down.".into(),
            input_schema: json!({"type": "object"}),
        }
    }
    async fn call(&self, _ctx: &ToolCtx, _args: Value) -> Result<Value, ToolError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.failing.load(Ordering::SeqCst) {
            Err(ToolError::Transient("503 from the server".into()))
        } else {
            Ok(json!({"ok": true}))
        }
    }
}

#[tokio::test]
async fn tool_retries_are_capped_and_the_breaker_opens_and_recovers() {
    let reference = format!("mcp://ops/flaky#{PIN}");
    let tool = Arc::new(Flaky { calls: AtomicUsize::new(0), failing: std::sync::atomic::AtomicBool::new(true) });
    let h = Harness::new(Arc::new(MemoryJournal::new()))
        .with_tools(StaticTools::new().with(reference.clone(), tool.clone() as Arc<dyn Tool>));
    h.nodes.add(
        "ops",
        1,
        json!({"kind": "workflow", "model_policy": {}, "budgets": budgets(5, 100), "guards": {"tool_retries": 1},
               "tools": [{"ref": reference, "effect": "read"}],
               "graph": {"vertices": [{"id": "t", "type": "tool", "config": {"tool": reference}}], "edges": []}}),
    );
    let model = FakeModel::new(|_| text("unused"));
    let ex = h.executor_with(&model, "w1", |o| {
        o.breaker_failures = 2;
        o.breaker_cooldown = Duration::from_millis(50);
    });
    // Each failing run tries the tool twice (one retry).
    let v = run(&ex, "ops", json!({})).await;
    assert_eq!(v.status, RunStatus::Failed);
    assert!(v.error.as_deref().unwrap().contains("after 2 attempts"), "{v:?}");
    assert_eq!(tool.calls.load(Ordering::SeqCst), 2);
    assert_eq!(ex.breaker_state("acme", &reference), breaker::State::Closed);
    run(&ex, "ops", json!({})).await;
    assert_eq!(ex.breaker_state("acme", &reference), breaker::State::Open, "two failed calls in a row");
    // Open: refused without reaching the tool.
    let v = run(&ex, "ops", json!({})).await;
    assert!(v.error.as_deref().unwrap().contains("circuit open"), "{v:?}");
    assert_eq!(tool.calls.load(Ordering::SeqCst), 4);
    assert_eq!(ex.breaker_state("globex", &reference), breaker::State::Closed, "per tenant");
    // The server recovers; after the cool-down one trial call closes the breaker.
    tool.failing.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(10);
    while ex.breaker_state("acme", &reference) != breaker::State::HalfOpen {
        assert!(Instant::now() < deadline, "the breaker never half-opened");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let v = run(&ex, "ops", json!({})).await;
    assert_eq!(v.status, RunStatus::Succeeded, "{v:?}");
    assert_eq!(ex.breaker_state("acme", &reference), breaker::State::Closed);
}
