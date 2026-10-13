//! Golden-set evals end to end (P3 exit criteria): a control plane holds the golden set and the
//! node's promotion bar, a worker (a real gateway in front of the mock model server) runs every
//! case `k` times through its executor and the request pipeline, the judge's calls go through the
//! same pipeline, the metrics come back to the admin API, and the version is promoted only once
//! its eval meets the bar. The journal is Postgres when `CALIBAN_TEST_DATABASE_URL` is set.

use crate::nodes_tests::{ADMIN, Env, KEY, config_with, env_from, idem, journal, responder, send, worker};
use axum::http::StatusCode;
use caliban_bench::mock::Responder;
use caliban_nodes::eval::runner::{EvalOptions, EvalRunner};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

const N: &str = "/api/v1/tenants/acme/nodes";

fn opts() -> EvalOptions {
    EvalOptions {
        lease_ttl: Duration::from_secs(30),
        heartbeat: Duration::from_millis(200),
        poll: Duration::from_millis(20),
        max_concurrent_evals: 2,
        snapshot_wait: Duration::from_secs(10),
    }
}

/// The reference responder, plus a judge that likes what it reads.
fn judged() -> Responder {
    let base = responder();
    Responder::new(move |body| {
        let system = body["messages"][0]["content"].as_str().unwrap_or_default();
        if system.starts_with("You grade") {
            return Some(json!({"role": "assistant", "content": "{\"score\": 0.9, \"reason\": \"sensible\"}"}));
        }
        (base.0)(body)
    })
}

fn triage() -> Value {
    json!({
        "kind": "workflow",
        "description": "Classifies a case and recommends a service.",
        "prompt": {"system": "You triage support cases.",
                   "input_schema": {"type": "object", "required": ["case"], "properties": {"case": {"type": "string"}}}},
        "model_policy": {},
        "budgets": {"steps": 10, "tokens": 20000, "wall_clock_s": 60},
        "graph": {
            "vertices": [
                {"id": "classify", "type": "router", "config": {"routes": {"clinical": "health", "billing": "money"}}},
                {"id": "recommend", "type": "llm", "config": {
                    "prompt": "Catalogue matches: cardiology-clinic. Case: {{input.case}}",
                    "output_schema": {"type": "object", "required": ["category", "services"]}}}
            ],
            "edges": [{"from": "classify", "to": "recommend"}]
        }
    })
}

async fn env() -> (Env, Arc<dyn caliban_nodes::journal::Journal>) {
    let j = journal().await;
    let e = env_from(Duration::ZERO, Some(Arc::clone(&j)), judged(), |url| config_with(url, "")).await;
    (e, j)
}

#[tokio::test]
async fn a_golden_eval_reports_pass_k_and_cost_per_success_and_gates_promotion() {
    let (e, j) = env().await;
    let app = &e.cp_app;
    let (s, v) = send(app, "POST", &format!("{N}/triage/versions"), ADMIN, Some(json!({"spec": triage()})), &[]).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    // The node's bar: every case passes all three runs.
    let bar = json!({"golden": {"min_pass_k": 1.0, "min_k": 3}});
    let (s, v) = send(app, "PUT", &format!("{N}/triage/eval-policy"), ADMIN, Some(bar), &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let cases = json!([
        {"id": "chest", "input": {"case": "Chest pain since Tuesday"},
         "checks": [{"type": "json_schema", "schema": {"type": "object", "required": ["urgency"]}},
                    {"type": "contains", "value": ["clinical", "cardiology-clinic"]},
                    {"type": "llm_judge", "rubric": "Does the recommendation fit the case?"}]},
        {"id": "dizzy", "input": {"case": "Dizzy after a new prescription"},
         "checks": [{"type": "regex", "pattern": "\"category\":\\s*\"clinical\""}]}
    ]);
    let golden = format!("{N}/triage/versions/1/golden-set");
    let (s, v) = send(app, "PUT", &golden, ADMIN, Some(json!({"cases": cases})), &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // A bar is set: publishing with promotion waits for an eval.
    let (s, v) = send(app, "POST", &format!("{N}/triage/versions/1/publish"), ADMIN, None, &[]).await;
    assert_eq!(
        (s, v["error"]["problems"][0]["kind"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("eval_gate")),
        "{v}"
    );
    let (s, v) =
        send(app, "POST", &format!("{N}/triage/versions/1/publish"), ADMIN, Some(json!({"promote": false})), &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // No key named: the tenant's eval key (P3 decision 9), created on first use and managed by
    // the control plane.
    let start = json!({"suite": "golden", "k": 3, "concurrency": 3});
    let (s, ev) = send(app, "POST", &format!("{N}/triage/versions/1/evals"), ADMIN, Some(start), &[]).await;
    assert_eq!((s, ev["status"].as_str()), (StatusCode::ACCEPTED, Some("pending")), "{ev}");
    let id = ev["id"].as_str().unwrap().to_owned();
    let (_, ek) = send(app, "GET", "/api/v1/tenants/acme/eval-key", ADMIN, None, &[]).await;
    assert_eq!(
        (ek["key"]["purpose"].as_str(), ev["api_key_id"].clone()),
        (Some("eval"), ek["key"]["id"].clone()),
        "{ek}"
    );

    // A worker runs it through its executor and gateway.
    let w = worker(&e, &j, &idem(), None, "worker-a", Duration::from_secs(30));
    assert!(EvalRunner::new(Arc::clone(&w.ex), opts()).run_once().await);
    let (s, d) = send(app, "GET", &format!("/api/v1/tenants/acme/evals/{id}"), ADMIN, None, &[]).await;
    assert_eq!((s, d["status"].as_str()), (StatusCode::OK, Some("succeeded")), "{d}");
    let sum = &d["summary"];
    assert_eq!(
        (sum["trials"].as_u64(), sum["passed_trials"].as_u64(), sum["pass_hat_k"].as_f64()),
        (Some(6), Some(6), Some(1.0)),
        "{sum}"
    );
    assert_eq!(sum["judge"]["default_model"], "caliban/auto");
    assert!(sum["latency_ms"]["p95"].is_u64(), "{sum}");
    // Cost per success is what the trials' runs cost, over the successes.
    let trials = d["trials"].as_array().unwrap();
    let mut run_cost = 0.0;
    for t in trials {
        let (_, r) =
            send(app, "GET", &format!("/api/v1/tenants/acme/runs/{}", t["run_id"].as_str().unwrap()), ADMIN, None, &[])
                .await;
        assert_eq!(
            (r["status"].as_str(), r["origin"].as_str()),
            (Some("succeeded"), Some(format!("eval:{id}:{}", t["case"].as_str().unwrap()).as_str())),
            "{r}"
        );
        run_cost += r["cost_usd"].as_f64().unwrap();
        assert!(t["detail"]["output"].is_object(), "content with runs.data: {t}");
    }
    assert!(run_cost > 0.0);
    assert!((sum["cost_per_success_usd"].as_f64().unwrap() - run_cost / 6.0).abs() < 1e-9, "{sum}");
    // Every model call went through the pipeline and was metered, tagged with the node; the
    // judge's calls carry the eval as their run.
    let events: Vec<Value> =
        w.usage.snapshot(Some("acme"), 1000).iter().map(|u| serde_json::to_value(u).unwrap()).collect();
    let run_ids: Vec<&str> = trials.iter().map(|t| t["run_id"].as_str().unwrap()).collect();
    let node_calls = events.iter().filter(|ev| ev["run_id"].as_str().is_some_and(|r| run_ids.contains(&r))).count();
    assert_eq!(node_calls, 12, "a router and an llm call per trial");
    let judge_calls: Vec<&Value> = events.iter().filter(|ev| ev["run_id"] == id.as_str()).collect();
    assert_eq!(judge_calls.len(), 3, "one judge call per trial of the judged case");
    assert!(judge_calls.iter().all(|ev| ev["node"] == "triage" && ev["node_version"] == 1));
    assert!(sum["judge_cost_usd"].as_f64().unwrap() > 0.0);

    // The bar is met: promotion goes through, with the eval as evidence.
    let (s, v) = send(app, "POST", &format!("{N}/triage/promote"), ADMIN, Some(json!({"version": 1})), &[]).await;
    assert_eq!((s, v["live"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
    // The worker's outbox (the end of the eval) reaches the hash chain, as its shipper sends it.
    let shipped = j.claim_audit("worker-a", Duration::from_secs(60), 100).await.unwrap();
    let ids: Vec<String> = shipped.iter().map(|x| x.id.clone()).collect();
    e.cp.store.ingest_audit(shipped).await.unwrap();
    j.ack_audit(&ids).await.unwrap();
    let (_, a) = send(app, "GET", "/api/v1/audit?limit=200", ADMIN, None, &[]).await;
    assert_eq!(a["chain_verified"], true);
    let entries = a["entries"].as_array().unwrap();
    let promote = entries.iter().find(|x| x["action"] == "node.promote").unwrap();
    assert_eq!(promote["detail"]["evals"]["golden"]["eval"], id.as_str());
    for action in ["node.eval_policy.update", "node.golden_set.update", "node.eval.start", "node.eval.finish"] {
        assert!(entries.iter().any(|x| x["action"] == action), "{action} is audited");
    }
}

/// A trial whose case cannot pass lowers pass^k, and the gate refuses the version.
#[tokio::test]
async fn a_failing_case_keeps_the_version_off_the_live_pointer() {
    let (e, j) = env().await;
    let app = &e.cp_app;
    send(app, "POST", &format!("{N}/triage/versions"), ADMIN, Some(json!({"spec": triage()})), &[]).await;
    send(app, "PUT", &format!("{N}/triage/eval-policy"), ADMIN, Some(json!({"golden": {"min_pass_k": 0.9}})), &[])
        .await;
    let cases = json!([{"id": "ok", "input": {"case": "Chest pain"}, "checks": [{"type": "contains", "value": "clinical"}]},
                       {"id": "billing", "input": {"case": "Refund my invoice"}, "checks": [{"type": "contains", "value": "billing"}]}]);
    send(app, "PUT", &format!("{N}/triage/versions/1/golden-set"), ADMIN, Some(json!({"cases": cases})), &[]).await;
    send(app, "POST", &format!("{N}/triage/versions/1/publish"), ADMIN, Some(json!({"promote": false})), &[]).await;
    let start = json!({"suite": "golden", "api_key_id": "key_cfg_acme_0", "k": 2});
    send(app, "POST", &format!("{N}/triage/versions/1/evals"), ADMIN, Some(start), &[]).await;
    let w = worker(&e, &j, &idem(), None, "worker-a", Duration::from_secs(30));
    assert!(EvalRunner::new(Arc::clone(&w.ex), opts()).run_once().await);
    let (_, list) = send(app, "GET", "/api/v1/tenants/acme/evals?node=triage", ADMIN, None, &[]).await;
    let sum = &list["data"][0]["summary"];
    assert_eq!((sum["pass_hat_k"].as_f64(), sum["pass_at_1"].as_f64()), (Some(0.5), Some(0.5)), "{sum}");
    let (s, v) = send(app, "POST", &format!("{N}/triage/promote"), ADMIN, Some(json!({"version": 1})), &[]).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("pass^2 = 0.500"), "{v}");
    let (_, gate) = send(app, "GET", &format!("{N}/triage/versions/1/gate"), ADMIN, None, &[]).await;
    assert_eq!(gate["allowed"], false, "{gate}");
}

// ───────────────────────── golden trials and write tools ─────────────────────────

/// A bank's refund desk: a real MCP server (rmcp) with a read tool and a write tool, approved,
/// and an agent node that refunds the transaction and looks it up, then reports what the refund
/// tool said. Returns the server and the version's spec.
pub(crate) struct Bank {
    pub server: caliban_mcp::testing::TestMcpServer,
    pub lookup: String,
    pub refund: String,
}

pub(crate) fn bank_model() -> Responder {
    let base = judged();
    Responder::new(move |body| {
        let system = body["messages"][0]["content"].as_str().unwrap_or_default();
        if !system.starts_with("You process refunds") {
            return (base.0)(body);
        }
        let msgs = body["messages"].as_array().cloned().unwrap_or_default();
        Some(match msgs.iter().find(|m| m["role"] == "tool") {
            Some(m) => {
                json!({"role": "assistant", "content": format!("Done: {}", m["content"].as_str().unwrap_or_default())})
            }
            // The refund first: its arguments carry no tool output, so it needs no approval.
            None => json!({"role": "assistant", "content": null, "tool_calls": [
                {"id": "c0", "type": "function", "function": {"name": "refund", "arguments": "{\"tx\": \"TX-30015\", \"amount\": 20}"}},
                {"id": "c1", "type": "function", "function": {"name": "lookup", "arguments": "{\"tx\": \"TX-30015\"}"}}]}),
        })
    })
}

pub(crate) async fn bank(e: &Env) -> Bank {
    use caliban_mcp::testing::{TestMcpServer, TestTool};
    let m = |name: &str, d: &str| caliban_mcp::ToolManifest {
        name: name.into(),
        description: d.into(),
        input_schema: json!({"type": "object"}),
    };
    let (lookup, refund) = (m("lookup", "Looks a transaction up."), m("refund", "Refunds a transaction."));
    let server = TestMcpServer::start(
        vec![
            TestTool::new(lookup.clone(), |_| Ok(json!({"tx": "TX-30015", "amount": 20}))),
            TestTool::new(refund.clone(), |_| Ok(json!({"status": "REAL REFUND ISSUED"}))),
        ],
        &[],
    )
    .await;
    let servers = "/api/v1/tenants/acme/tool-servers";
    let (s, v) = send(&e.cp_app, "POST", servers, ADMIN, Some(json!({"name": "bank", "url": server.url})), &[]).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let (s, v) = send(&e.cp_app, "POST", &format!("{servers}/bank/discover"), ADMIN, None, &[]).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for t in [&lookup, &refund] {
        let uri = format!("{servers}/bank/tools/{}/approve", t.name);
        let (s, v) = send(&e.cp_app, "POST", &uri, ADMIN, Some(json!({"pin": t.pin()})), &[]).await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    let bank = Bank {
        server,
        lookup: format!("mcp://bank/lookup#{}", lookup.pin()),
        refund: format!("mcp://bank/refund#{}", refund.pin()),
    };
    let spec = json!({"kind": "agent", "prompt": {"system": "You process refunds."}, "model_policy": {},
        "budgets": {"steps": 10, "tokens": 20000, "wall_clock_s": 60},
        "tools": [{"ref": bank.lookup, "effect": "read"}, {"ref": bank.refund, "effect": "write"}]});
    // A version with a write tool is published without promotion: it waits for its evals.
    e.publish_with("refunds", spec, false).await;
    bank
}

pub(crate) fn refunds_to_the_server(b: &Bank) -> usize {
    b.server.calls().iter().filter(|c| c.tool == "refund").count()
}

/// Fintech demo, 2026-10-13: a golden trial issued a real refund (TX-30015) on the bank's server.
/// A golden trial's writes now go to the eval sandbox: the real server receives no refund, the
/// case's scripted result answers instead, the read still reaches the real server, and the
/// `tool_call` check asserts the intended write.
#[tokio::test]
async fn a_golden_eval_never_reaches_a_real_write_tool() {
    let j = journal().await;
    let e = env_from(Duration::ZERO, Some(Arc::clone(&j)), bank_model(), |url| config_with(url, "")).await;
    let b = bank(&e).await;
    let cases = json!([
        {"id": "refund", "input": "Refund TX-30015",
         "tool_results": {"refund": {"status": "refunded", "refund_id": "R-1"}},
         "checks": [{"type": "contains", "value": "R-1"},
                    {"type": "tool_call", "tool": "refund", "args": {"tx": "TX-30015"}}]},
        {"id": "no-refund", "input": "Refund TX-30015",
         "checks": [{"type": "tool_call", "tool": "refund", "must_not_call": true}]}
    ]);
    let (s, v) = send(
        &e.cp_app,
        "PUT",
        &format!("{N}/refunds/versions/1/golden-set"),
        ADMIN,
        Some(json!({"cases": cases})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, ev) = send(
        &e.cp_app,
        "POST",
        &format!("{N}/refunds/versions/1/evals"),
        ADMIN,
        Some(json!({"suite": "golden", "k": 2})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{ev}");
    let w = worker(&e, &j, &idem(), None, "worker-a", Duration::from_secs(30));
    assert!(EvalRunner::new(Arc::clone(&w.ex), opts()).run_once().await);
    let (_, d) =
        send(&e.cp_app, "GET", &format!("/api/v1/tenants/acme/evals/{}", ev["id"].as_str().unwrap()), ADMIN, None, &[])
            .await;
    assert_eq!(d["status"], "succeeded", "{d}");
    assert_eq!(refunds_to_the_server(&b), 0, "a golden trial reached the real refund tool");
    assert_eq!(b.server.calls().iter().filter(|c| c.tool == "lookup").count(), 4, "reads still reach the server");
    let trials = d["trials"].as_array().unwrap();
    for t in trials {
        let want = if t["case"] == "refund" { "passed" } else { "failed" };
        assert_eq!(t["status"], want, "{t}");
        assert_eq!(t["verdict"]["sandboxed_calls"], 1, "{t}");
        let call =
            t["detail"]["tool_calls"].as_array().unwrap().iter().find(|c| c["name"] == "refund").cloned().unwrap();
        assert_eq!((call["sandboxed"].as_bool(), call["args"]["tx"].as_str()), (Some(true), Some("TX-30015")), "{t}");
    }
    assert_eq!(d["summary"]["pass_hat_k"].as_f64(), Some(0.5), "{d}");
}

// ───────────────────────── cases from runs ─────────────────────────

/// Production feedback (research note 04 §7): a reviewer turns finished runs into golden cases.
/// A good run of the refund desk becomes a case whose judge compares with its output and whose
/// `tool_call` check asserts the refund it made; evaluating that case never refunds for real. A
/// run waiting for a human cannot be captured until it ends; then its answers are scripted. A
/// bad run needs a note, and its MAST label lands on the run.
#[tokio::test]
async fn finished_runs_become_golden_cases() {
    let j = journal().await;
    let e = env_from(Duration::ZERO, Some(Arc::clone(&j)), bank_model(), |url| config_with(url, "")).await;
    let b = bank(&e).await;
    let app = &e.cp_app;
    let w = worker(&e, &j, &idem(), None, "worker-a", Duration::from_secs(30));
    let capture = |run: &str| format!("/api/v1/tenants/acme/runs/{run}/golden-case");

    // A production run refunds for real.
    let (s, run) = send(
        &w.app,
        "POST",
        "/v1/nodes/refunds/runs",
        KEY,
        Some(json!({"input": "Refund TX-30015", "version": 1})),
        &[],
    )
    .await;
    assert_eq!((s.is_success(), run["status"].as_str()), (true, Some("succeeded")), "{run}");
    let refund_run = run["id"].as_str().unwrap().to_owned();
    assert_eq!(refunds_to_the_server(&b), 1, "a production run writes for real");

    // Refused: no such run, a bad verdict without a note, a label on a good run, an unknown label.
    let good = json!({"verdict": "good"});
    let (s, v) = send(app, "POST", &capture("run_nope"), ADMIN, Some(good.clone()), &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    for body in [
        json!({"verdict": "bad"}),
        json!({"verdict": "bad", "note": "  "}),
        json!({"verdict": "good", "mast_label": "step_repetition"}),
        json!({"verdict": "bad", "note": "x", "mast_label": "FM-1.3"}),
    ] {
        let (s, v) = send(app, "POST", &capture(&refund_run), ADMIN, Some(body.clone()), &[]).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{body}: {v}");
    }
    let (s, v) =
        send(app, "POST", &capture(&refund_run), ADMIN, Some(json!({"verdict": "good", "version": 9})), &[]).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");

    // Good: the output is the judge's reference, the refund is asserted.
    let (s, c) = send(app, "POST", &capture(&refund_run), ADMIN, Some(good.clone()), &[]).await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    assert_eq!((c["object"].as_str(), c["case_id"].as_str()), (Some("node.golden_case"), Some(refund_run.as_str())));
    assert_eq!(c["checks"], json!(["llm_judge", "tool_call"]), "{c}");
    assert_eq!(c["case"]["checks"][1], json!({"type": "tool_call", "tool": "mcp://bank/refund"}));
    assert!(c["case"]["checks"][0]["reference"].as_str().unwrap().contains("REAL REFUND ISSUED"), "{c}");
    let (s, v) = send(app, "POST", &capture(&refund_run), ADMIN, Some(good.clone()), &[]).await;
    assert_eq!(s, StatusCode::CONFLICT, "captured once per set: {v}");

    // Its eval: the case passes, the refund goes to the sandbox, never to the bank.
    let (s, ev) = send(
        app,
        "POST",
        &format!("{N}/refunds/versions/1/evals"),
        ADMIN,
        Some(json!({"suite": "golden", "k": 2})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{ev}");
    assert!(EvalRunner::new(Arc::clone(&w.ex), opts()).run_once().await);
    let (_, d) =
        send(app, "GET", &format!("/api/v1/tenants/acme/evals/{}", ev["id"].as_str().unwrap()), ADMIN, None, &[]).await;
    assert_eq!((d["status"].as_str(), d["summary"]["pass_hat_k"].as_f64()), (Some("succeeded"), Some(1.0)), "{d}");
    assert_eq!(refunds_to_the_server(&b), 1, "the eval of the captured case refunded nothing");

    // A run that waits for a human is in progress; once answered, its answer is scripted.
    e.publish(
        "ask",
        json!({"kind": "workflow", "prompt": {"system": "You ask."}, "model_policy": {},
               "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 60},
               "graph": {"vertices": [{"id": "clarify", "type": "human", "config": {"question": "Which transaction?"}}], "edges": []}}),
    )
    .await;
    let (_, run) = send(&w.app, "POST", "/v1/nodes/ask/runs", KEY, Some(json!({"input": "refund"})), &[]).await;
    assert_eq!(run["status"], "input_required", "{run}");
    let ask_run = run["id"].as_str().unwrap().to_owned();
    let (s, v) = send(app, "POST", &capture(&ask_run), ADMIN, Some(good.clone()), &[]).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, v) = send(
        app,
        "POST",
        &format!("/api/v1/tenants/acme/runs/{ask_run}/input"),
        ADMIN,
        Some(json!({"answer": "TX-30015"})),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    w.ex.spawn_run(ask_run.clone());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let done = w.ex.wait("acme", &ask_run, deadline).await.unwrap().unwrap();
    assert!(done.status.is_terminal(), "{done:?}");

    // Bad, with a note and a MAST label: the rubric is the note; the label is on the run.
    let bad =
        json!({"verdict": "bad", "note": "Ask for the amount too.", "mast_label": "fail_to_ask_for_clarification"});
    let (s, c) = send(app, "POST", &capture(&ask_run), ADMIN, Some(bad), &[]).await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    assert_eq!(c["case"]["answers"], json!({"clarify#0": "TX-30015"}), "{c}");
    assert!(c["case"]["checks"][0]["rubric"].as_str().unwrap().contains("Ask for the amount too."));
    assert_eq!(c["case"]["tags"], json!(["captured", "bad", "mast:fail_to_ask_for_clarification"]));
    let (_, r) = send(app, "GET", &format!("/api/v1/tenants/acme/runs/{ask_run}"), ADMIN, None, &[]).await;
    assert_eq!(r["mast_label"], "fail_to_ask_for_clarification", "{r}");
    // Audited without the note.
    let (_, a) = send(app, "GET", "/api/v1/audit?limit=200", ADMIN, None, &[]).await;
    let captures: Vec<&Value> =
        a["entries"].as_array().unwrap().iter().filter(|x| x["action"] == "node.golden_set.capture").collect();
    assert_eq!(captures.len(), 2, "{a}");
    assert!(captures.iter().all(|x| !x.to_string().contains("amount too")));
}
