//! Golden-set evals end to end (P3 exit criteria): a control plane holds the golden set and the
//! node's promotion bar, a worker (a real gateway in front of the mock model server) runs every
//! case `k` times through its executor and the request pipeline, the judge's calls go through the
//! same pipeline, the metrics come back to the admin API, and the version is promoted only once
//! its eval meets the bar. The journal is Postgres when `CALIBAN_TEST_DATABASE_URL` is set.

use crate::nodes_tests::{ADMIN, Env, config_with, env_from, idem, journal, responder, send, worker};
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
            (Some("succeeded"), Some(format!("eval:{id}").as_str())),
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
