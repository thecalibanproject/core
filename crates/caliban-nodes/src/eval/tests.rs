use super::*;
use crate::journal::evals::{EvalRecord, EvalStatus, Suite};
use chrono::Utc;

fn spec(v: Value) -> NodeSpec {
    serde_json::from_value(v).unwrap()
}

fn agent(tools: Value) -> NodeSpec {
    spec(json!({"kind": "agent", "model_policy": {}, "tools": tools,
                "prompt": {"input_schema": {"type": "object", "required": ["case"], "properties": {"case": {"type": "string"}}}},
                "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30}}))
}

fn case(v: Value) -> GoldenCase {
    serde_json::from_value(v).unwrap()
}

#[test]
fn golden_sets_are_validated_against_the_version() {
    let s = agent(json!([]));
    let ok = case(json!({"id": "a", "input": {"case": "chest pain"}, "expected": "clinical"}));
    assert_eq!(validate_cases(std::slice::from_ref(&ok), &s), Ok(()));
    let bad = vec![
        ok.clone(),
        ok.clone(),
        case(json!({"id": "b c", "input": {"case": "x"}, "checks": [{"type": "regex", "pattern": "("}]})),
        case(json!({"id": "d", "input": {"nope": 1}})),
        case(
            json!({"id": "e", "input": {"case": "x"}, "checks": [{"type": "json_schema", "schema": {"$ref": "#/x"}}]}),
        ),
        case(
            json!({"id": "f", "input": {"case": "x"}, "checks": [{"type": "llm_judge", "rubric": " ", "threshold": 2}]}),
        ),
    ];
    let problems = validate_cases(&bad, &s).unwrap_err();
    let joined = problems.join("\n");
    for want in ["duplicate case id 'a'", "id 'b c'", "regex:", "input:", "needs `expected`", "json_schema:", "rubric"]
    {
        assert!(joined.contains(want), "{want} in {joined}");
    }
    assert!(validate_cases(&[], &s).is_err());
    // Unknown fields and check types are refused when parsing.
    assert!(serde_json::from_value::<GoldenCase>(json!({"id": "a", "input": 1, "extra": 1})).is_err());
    assert!(serde_json::from_value::<Check>(json!({"type": "fuzzy", "value": "x"})).is_err());
    assert!(serde_json::from_value::<Check>(json!({"type": "exact", "value": "x", "nope": 1})).is_err());
}

#[test]
fn checks_score_text_and_json_outputs() {
    let run = |c: Value, out: Value| check_output(&serde_json::from_value(c).unwrap(), &out).unwrap().passed;
    assert!(run(json!({"type": "exact", "value": "clinical"}), json!(" clinical\n")));
    assert!(!run(json!({"type": "exact", "value": "Clinical"}), json!("clinical")));
    assert!(run(json!({"type": "exact", "value": "Clinical", "case_sensitive": false}), json!("clinical")));
    assert!(run(json!({"type": "exact", "value": {"a": 1}}), json!("```json\n{\"a\": 1}\n```")));
    assert!(run(
        json!({"type": "contains", "value": ["cardio", "clinic"]}),
        json!({"services": ["cardiology-clinic"]})
    ));
    assert!(!run(json!({"type": "contains", "value": "dental"}), json!("cardiology")));
    assert!(run(json!({"type": "regex", "pattern": "^URGENT", "flags": ["IGNORECASE"]}), json!("urgent: yes")));
    let schema = json!({"type": "json_schema", "schema": {"type": "object", "required": ["category"]}});
    assert!(run(schema.clone(), json!("{\"category\": \"x\"}")) && !run(schema, json!("not json")));
    assert!(check_output(&Check::LlmJudge { rubric: "r".into(), model: None, threshold: 0.5 }, &json!(1)).is_none());
}

#[test]
fn the_judge_answers_a_score_and_its_request_holds_the_rubric() {
    let body = judge_request("local/judge", "Is it polite?", &json!({"case": "x"}), Some(&json!("ref")), &json!("hi"));
    assert_eq!((body["model"].as_str(), body["temperature"].as_i64()), (Some("local/judge"), Some(0)));
    let user = body["messages"][1]["content"].as_str().unwrap();
    assert!(
        user.contains("Is it polite?")
            && user.contains("Reference answer:\nref")
            && user.contains("Output to grade:\nhi")
    );
    let reply = |c: &str| json!({"role": "assistant", "content": c});
    assert_eq!(judge_verdict(&reply("{\"score\": 0.8, \"reason\": \"ok\"}")).unwrap(), (0.8, "ok".into()));
    assert_eq!(judge_verdict(&reply("Sure: {\"score\": \"1\"}")).unwrap().0, 1.0);
    assert_eq!(judge_verdict(&reply("{\"score\": 7}")).unwrap().0, 1.0, "clamped");
    assert!(judge_verdict(&reply("great")).is_err() && judge_verdict(&reply("{\"reason\": 1}")).is_err());
}

#[test]
fn scripted_answers_match_steps_or_vertices() {
    let c = case(json!({"id": "a", "input": 1, "expected": 1,
        "answers": {"clarify": "two days", "write@approve": {"approve": true}, "ask#1": "second"}}));
    assert_eq!(c.answer_for("clarify#0"), Some(&json!("two days")));
    assert_eq!(c.answer_for("ask#1"), Some(&json!("second")));
    assert_eq!(c.answer_for("ask#0"), None);
    assert_eq!(c.answer_for("write#0@approve"), Some(&json!({"approve": true})));
    assert_eq!(c.answer_for("call#0>clarify#2"), Some(&json!("two days")), "nested steps match their vertex");
    assert_eq!(c.answer_for("agent#1.0@approve"), None);
}

fn eval(suite: Suite, k: u32, summary: Value) -> EvalRecord {
    EvalRecord {
        id: format!("eval_{}", suite.as_str()),
        tenant_id: "acme".into(),
        node: "triage".into(),
        version: 2,
        spec_hash: "sha256:aa".into(),
        suite,
        k,
        concurrency: 1,
        created_by: "u".into(),
        api_key_id: None,
        invoker_key_hash: "h".into(),
        plan: "p".into(),
        case_count: 2,
        status: EvalStatus::Succeeded,
        lease_owner: None,
        lease_expires_at: None,
        claims: 1,
        summary: Some(summary),
        error: None,
        cancel_requested_at: None,
        cancelled_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        started_at: None,
        finished_at: None,
    }
}

#[test]
fn the_gate_needs_the_bar_and_an_injection_eval_for_write_tools() {
    let read_only = agent(json!([]));
    let writer = agent(json!([{"ref": format!("mcp://erp/send#sha256:{}", "0".repeat(64)), "effect": "write"}]));
    let none = EvalPolicy::default();
    assert_eq!(gate(&none, &read_only, "sha256:aa", None, None), Ok(Value::Null), "no bar, no write tools");
    let problems = gate(&none, &writer, "sha256:aa", None, None).unwrap_err();
    assert!(problems[0].contains("needs a finished injection eval"), "{problems:?}");
    let inj = |rate: f64| eval(Suite::Injection, 1, json!({"pass_rate": rate, "blocked": 9, "trials": 10}));
    assert!(gate(&none, &writer, "sha256:aa", None, Some(&inj(0.9))).unwrap_err()[0].contains("the bar is 1.000"));
    let ev = gate(&none, &writer, "sha256:aa", None, Some(&inj(1.0))).unwrap();
    assert_eq!(ev["injection"]["eval"], "eval_injection");
    let lowered = EvalPolicy {
        injection: Some(InjectionBar { min_pass_rate: 0.9, read_only: Default::default() }),
        ..EvalPolicy::default()
    };
    assert!(gate(&lowered, &writer, "sha256:aa", None, Some(&inj(0.9))).is_ok());
    assert!(gate(&lowered, &writer, "sha256:bb", None, Some(&inj(1.0))).is_err(), "another version's eval");

    // A read-only version (e2e gap 8): what it reads can steer its answer, so it needs an injection
    // eval too, unless the node's policy makes that optional; a finished one is checked anyway.
    let reader = agent(json!([{"ref": format!("mcp://crm/lookup#sha256:{}", "1".repeat(64)), "effect": "read"}]));
    let p = gate(&none, &reader, "sha256:aa", None, None).unwrap_err();
    assert!(p[0].contains("read tools"), "{p:?}");
    assert!(gate(&none, &reader, "sha256:aa", None, Some(&inj(1.0))).is_ok());
    assert!(gate(&none, &reader, "sha256:aa", None, Some(&inj(0.9))).is_err());
    let optional = EvalPolicy {
        injection: Some(InjectionBar { min_pass_rate: 1.0, read_only: crate::eval::ReadOnlyGate::Optional }),
        ..EvalPolicy::default()
    };
    assert!(gate(&optional, &reader, "sha256:aa", None, None).is_ok(), "exempted by the node's policy");
    assert!(gate(&optional, &reader, "sha256:aa", None, Some(&inj(0.5))).is_err(), "a finished eval still counts");
    assert!(gate(&optional, &writer, "sha256:aa", None, None).is_err(), "never for write tools");
    let subnode_only = agent(json!([{"ref": "node://kb@v1", "effect": "read"}]));
    assert_eq!(gate(&none, &subnode_only, "sha256:aa", None, None), Ok(Value::Null), "a subnode passes its own gate");

    let bar = EvalPolicy {
        golden: Some(GoldenBar {
            min_pass_k: 0.8,
            min_k: 3,
            max_cost_per_success_usd: Some(0.01),
            max_p95_latency_ms: Some(2000),
        }),
        injection: None,
    };
    let g = |k: u32, pass: f64, cost: f64, p95: u64| {
        eval(Suite::Golden, k, json!({"pass_hat_k": pass, "cost_per_success_usd": cost, "latency_ms": {"p95": p95}}))
    };
    assert!(gate(&bar, &read_only, "sha256:aa", None, None).unwrap_err()[0].contains("golden-set eval"));
    assert!(gate(&bar, &read_only, "sha256:aa", Some(&g(3, 0.9, 0.005, 1000)), None).is_ok());
    let p = gate(&bar, &read_only, "sha256:aa", Some(&g(1, 0.5, 0.05, 3000)), None).unwrap_err();
    assert_eq!(p.len(), 4, "{p:?}");
    let mut failed = g(3, 1.0, 0.0, 1);
    failed.status = EvalStatus::Failed;
    assert!(gate(&bar, &read_only, "sha256:aa", Some(&failed), None).is_err(), "only finished evals count");
    assert!(bar.validate().is_ok());
    let bad =
        EvalPolicy { golden: Some(GoldenBar { min_pass_k: 1.5, ..bar.golden.clone().unwrap() }), injection: None };
    assert!(bad.validate().is_err());
    assert!(serde_json::from_value::<EvalPolicy>(json!({"golden": {"min_pass_k": 1, "extra": 1}})).is_err());
}
