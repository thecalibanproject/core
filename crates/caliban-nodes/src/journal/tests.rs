//! Journal parity: one behaviour suite, run against the memory journal and (when
//! `CALIBAN_TEST_DATABASE_URL` is set) the Postgres journal, each test in its own schema.

use super::memory::MemoryJournal;
use super::postgres::PgJournal;
use super::*;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) async fn pg_journal() -> Option<PgJournal> {
    let url = std::env::var("CALIBAN_TEST_DATABASE_URL").ok()?;
    Some(PgJournal::isolated(&url).await.expect("CALIBAN_TEST_DATABASE_URL must be reachable"))
}

/// Both journals (Postgres only when configured).
pub(crate) async fn journals() -> Vec<Arc<dyn Journal>> {
    let mut v: Vec<Arc<dyn Journal>> = vec![Arc::new(MemoryJournal::new())];
    match pg_journal().await {
        Some(pg) => v.push(Arc::new(pg)),
        None => eprintln!("CALIBAN_TEST_DATABASE_URL not set; journal tests run on the memory journal only"),
    }
    v
}

pub(crate) fn new_run(id: &str, tenant: &str, key: Option<(&str, &str)>) -> NewRun {
    NewRun {
        id: id.into(),
        tenant_id: tenant.into(),
        node: "triage".into(),
        version: 1,
        spec_hash: "sha256:00".into(),
        invoker: "api_key:test".into(),
        invoker_key_hash: Some("ab".repeat(32)),
        input: "sealed-input".into(),
        budget: BudgetState::new(10, 1000, 60),
        idempotency: key.map(|(k, f)| (k.to_owned(), f.to_owned())),
        specs: Some("sealed-specs".into()),
        origin: None,
    }
}

fn step(run: &str, id: &str) -> StepRecord {
    let now = Utc::now();
    StepRecord {
        run_id: run.into(),
        tenant_id: "acme".into(),
        step_id: id.into(),
        attempt: 1,
        vertex: "classify".into(),
        kind: "router".into(),
        input_hash: "h".into(),
        status: StepStatus::Completed,
        result: Some(format!("result of {id}")),
        tokens: 12,
        prompt_tokens: 9,
        completion_tokens: 3,
        usd: 0.001,
        labels: vec!["pii".into()],
        started_at: now,
        finished_at: now,
    }
}

const TTL: Duration = Duration::from_secs(30);

async fn until(what: &str, mut f: impl AsyncFnMut() -> bool) {
    for _ in 0..500 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn idempotency_keys_return_the_first_run() {
    for j in journals().await {
        let n = j.name();
        let Created::New(a) = j.create_run(new_run("run_a", "acme", Some(("k1", "fp1")))).await.unwrap() else {
            panic!("{n}")
        };
        assert_eq!((a.status, a.claims, a.output.is_none()), (RunStatus::Pending, 0, true), "{n}");
        assert_eq!(a.specs.as_deref(), Some("sealed-specs"), "{n}: the pinned versions are stored");
        assert_eq!(
            j.create_run(new_run("run_b", "acme", Some(("k1", "fp1")))).await.unwrap(),
            Created::Existing(a.clone()),
            "{n}"
        );
        assert_eq!(j.create_run(new_run("run_c", "acme", Some(("k1", "fp2")))).await.unwrap(), Created::KeyReused);
        // Keys are per tenant; runs without a key never collide.
        assert!(matches!(
            j.create_run(new_run("run_d", "globex", Some(("k1", "fp1")))).await.unwrap(),
            Created::New(_)
        ));
        assert!(matches!(j.create_run(new_run("run_e", "acme", None)).await.unwrap(), Created::New(_)));
        assert!(j.get_run("acme", "run_b").await.unwrap().is_none(), "{n}: the duplicate created nothing");
        assert!(j.get_run("globex", "run_a").await.unwrap().is_none(), "{n}: runs are tenant-scoped");
        assert_eq!(j.get_run("acme", "run_a").await.unwrap().unwrap().id, "run_a");
    }
}

#[tokio::test]
async fn leases_fence_every_write() {
    for j in journals().await {
        let n = j.name();
        j.create_run(new_run("run_1", "acme", None)).await.unwrap();
        let r = j.claim_next("w1", TTL).await.unwrap().expect(n);
        assert_eq!(
            (r.id.as_str(), r.status, r.claims, r.lease_owner.as_deref()),
            ("run_1", RunStatus::Running, 1, Some("w1"))
        );
        assert!(r.started_at.is_some() && r.lease_expires_at.is_some());
        assert!(j.claim_next("w2", TTL).await.unwrap().is_none(), "{n}: nothing else to claim");
        assert!(j.claim("run_1", "w2", TTL).await.unwrap().is_none(), "{n}: held by w1");
        assert!(j.heartbeat("run_1", "w1", TTL).await.unwrap());
        assert!(!j.heartbeat("run_1", "w2", TTL).await.unwrap());

        let b = BudgetState { steps_used: 1, tokens_used: 12, ..BudgetState::new(10, 1000, 60) };
        assert_eq!(j.put_step("w2", step("run_1", "classify#0"), &b).await.unwrap(), StepWrite::LeaseLost, "{n}");
        assert_eq!(j.put_step("w1", step("run_1", "classify#0"), &b).await.unwrap(), StepWrite::Written, "{n}");
        let mut again = step("run_1", "classify#0");
        again.result = Some("another result".into());
        let StepWrite::Existing(first) = j.put_step("w1", again, &b).await.unwrap() else { panic!("{n}") };
        assert_eq!(first.result.as_deref(), Some("result of classify#0"), "{n}: first write wins");
        j.put_step("w1", step("run_1", "ask#0"), &b).await.unwrap();
        let steps = j.steps("run_1").await.unwrap();
        assert_eq!(steps.iter().map(|s| s.step_id.as_str()).collect::<Vec<_>>(), ["classify#0", "ask#0"], "{n}");
        assert_eq!((steps[0].tokens, steps[0].status), (12, StepStatus::Completed));
        assert_eq!(j.get_run("acme", "run_1").await.unwrap().unwrap().budget, b, "{n}: budget persisted");

        let f = Finish {
            status: RunStatus::Succeeded,
            output: Some("sealed-output".into()),
            error: None,
            stop_reason: None,
            budget: b,
        };
        assert!(!j.finish("run_1", "w2", f.clone()).await.unwrap(), "{n}");
        assert!(j.finish("run_1", "w1", f).await.unwrap(), "{n}");
        let done = j.get_run("acme", "run_1").await.unwrap().unwrap();
        assert_eq!(
            (done.status, done.output.as_deref(), done.lease_owner),
            (RunStatus::Succeeded, Some("sealed-output"), None)
        );
        assert!(done.finished_at.is_some());
        assert!(j.claim_next("w1", TTL).await.unwrap().is_none(), "{n}: finished runs are never claimed");
        assert!(j.suspend("run_1", "w1", sleep_until(Utc::now(), b)).await.is_ok_and(|ok| !ok));
    }
}

fn sleep_until(at: DateTime<Utc>, budget: BudgetState) -> Suspend {
    Suspend { status: RunStatus::Sleeping, awaiting: None, prompt: None, wake_at: Some(at), budget }
}

#[tokio::test]
async fn an_expired_lease_is_taken_over() {
    for j in journals().await {
        let n = j.name();
        j.create_run(new_run("run_1", "acme", None)).await.unwrap();
        j.claim_next("w1", Duration::ZERO).await.unwrap().expect(n);
        // w1 stopped heartbeating (it died): its lease expires and w2 takes the run over.
        let mut taken = None;
        until("the lease to expire", async || {
            taken = j.claim_next("w2", TTL).await.unwrap();
            taken.is_some()
        })
        .await;
        let r = taken.unwrap();
        assert_eq!((r.lease_owner.as_deref(), r.claims), (Some("w2"), 2), "{n}");
        // The old owner is fenced off everything.
        let b = BudgetState::default();
        assert!(!j.heartbeat("run_1", "w1", TTL).await.unwrap(), "{n}");
        assert_eq!(j.put_step("w1", step("run_1", "s#0"), &b).await.unwrap(), StepWrite::LeaseLost, "{n}");
        assert!(!j.release("run_1", "w1").await.unwrap());
        assert!(j.release("run_1", "w2").await.unwrap(), "{n}");
        let r = j.get_run("acme", "run_1").await.unwrap().unwrap();
        assert_eq!((r.status, r.lease_owner), (RunStatus::Pending, None), "{n}");
        assert!(j.claim_next("w3", TTL).await.unwrap().is_some(), "{n}: a released run is claimable at once");
    }
}

#[tokio::test]
async fn human_input_and_timers_wake_runs() {
    for j in journals().await {
        let n = j.name();
        j.create_run(new_run("run_1", "acme", None)).await.unwrap();
        j.claim_next("w1", TTL).await.unwrap().unwrap();
        let b = BudgetState::new(10, 1000, 60);
        let ask = Suspend {
            status: RunStatus::InputRequired,
            awaiting: Some("ask#0".into()),
            prompt: Some("sealed-question".into()),
            wake_at: None,
            budget: b,
        };
        assert!(j.suspend("run_1", "w1", ask).await.unwrap());
        let r = j.get_run("acme", "run_1").await.unwrap().unwrap();
        assert_eq!(
            (r.status, r.awaiting.as_deref(), r.prompt.as_deref()),
            (RunStatus::InputRequired, Some("ask#0"), Some("sealed-question"))
        );
        assert!(j.claim_next("w1", TTL).await.unwrap().is_none(), "{n}: waiting for a human");

        assert_eq!(
            j.deliver_input("acme", "run_1", "other#0", "x".into(), None, None).await.unwrap(),
            Delivered::NotAwaiting
        );
        assert_eq!(
            j.deliver_input("globex", "run_1", "ask#0", "x".into(), None, None).await.unwrap(),
            Delivered::NotFound
        );
        assert_eq!(
            j.deliver_input("acme", "nope", "ask#0", "x".into(), None, None).await.unwrap(),
            Delivered::NotFound
        );
        assert_eq!(
            j.deliver_input("acme", "run_1", "ask#0", "sealed-answer".into(), None, None).await.unwrap(),
            Delivered::Accepted
        );
        assert_eq!(
            j.deliver_input("acme", "run_1", "ask#0", "again".into(), None, None).await.unwrap(),
            Delivered::NotAwaiting
        );
        let ev = j.event("run_1", "ask#0").await.unwrap().expect(n);
        assert_eq!((ev.kind, ev.payload.as_deref()), (EventKind::Input, Some("sealed-answer")), "{n}");
        let r = j.claim_next("w2", TTL).await.unwrap().expect(n);
        assert_eq!((r.id.as_str(), r.awaiting, r.prompt), ("run_1", None, None), "{n}");

        // A durable sleep: not runnable before wake_at, runnable after. Past times are seconds in
        // the past: the database clock (Postgres `now()`) may lag this host's by a little.
        let later = Utc::now() + chrono::Duration::hours(1);
        assert!(j.suspend("run_1", "w2", sleep_until(later, b)).await.unwrap());
        assert!(j.claim_next("w1", TTL).await.unwrap().is_none(), "{n}: asleep");
        j.create_run(new_run("run_2", "acme", None)).await.unwrap();
        j.claim("run_2", "w1", TTL).await.unwrap().unwrap();
        let soon = Utc::now() - chrono::Duration::seconds(5);
        assert!(j.suspend("run_2", "w1", sleep_until(soon, b)).await.unwrap());
        assert_eq!(j.claim_next("w1", TTL).await.unwrap().map(|r| r.id), Some("run_2".into()), "{n}");

        // A human step with a deadline: woken by the timer without an answer.
        let timeout = Suspend {
            status: RunStatus::InputRequired,
            awaiting: Some("ask#0".into()),
            prompt: None,
            wake_at: Some(Utc::now() - chrono::Duration::seconds(5)),
            budget: b,
        };
        assert!(j.suspend("run_2", "w1", timeout).await.unwrap());
        assert_eq!(j.claim_next("w3", TTL).await.unwrap().map(|r| r.id), Some("run_2".into()), "{n}");

        // Events are written once.
        assert!(j.put_event("acme", "run_2", "ask#0:deadline", EventKind::Timer, Some("t1".into())).await.unwrap());
        assert!(!j.put_event("acme", "run_2", "ask#0:deadline", EventKind::Timer, Some("t2".into())).await.unwrap());
        assert_eq!(j.event("run_2", "ask#0:deadline").await.unwrap().unwrap().payload.as_deref(), Some("t1"), "{n}");
        assert!(j.put_event("globex", "run_2", "x", EventKind::Timer, None).await.is_err(), "{n}: tenant-scoped");
    }
}

#[tokio::test]
async fn concurrent_claimers_take_each_run_exactly_once() {
    for j in journals().await {
        let n = j.name();
        for i in 0..40 {
            j.create_run(new_run(&format!("run_{i:02}"), "acme", None)).await.unwrap();
        }
        let claimed: Arc<parking_lot::Mutex<HashMap<String, String>>> = Arc::default();
        let mut tasks = Vec::new();
        for w in 0..4 {
            let (j, claimed) = (Arc::clone(&j), Arc::clone(&claimed));
            tasks.push(tokio::spawn(async move {
                let worker = format!("w{w}");
                while let Some(r) = j.claim_next(&worker, TTL).await.unwrap() {
                    let prev = claimed.lock().insert(r.id.clone(), worker.clone());
                    assert!(prev.is_none(), "{} claimed twice ({prev:?} and {worker})", r.id);
                    let done = Finish {
                        status: RunStatus::Succeeded,
                        output: None,
                        error: None,
                        stop_reason: None,
                        budget: BudgetState::default(),
                    };
                    assert!(j.finish(&r.id, &worker, done).await.unwrap());
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(claimed.lock().len(), 40, "{n}");
        for i in 0..40 {
            let r = j.get_run("acme", &format!("run_{i:02}")).await.unwrap().unwrap();
            assert_eq!((r.status, r.claims), (RunStatus::Succeeded, 1), "{n}");
        }
    }
}

#[tokio::test]
async fn retention_purges_finished_runs_with_their_steps_and_events() {
    for j in journals().await {
        let n = j.name();
        let done =
            |budget| Finish { status: RunStatus::Succeeded, output: None, error: None, stop_reason: None, budget };
        let b = BudgetState::new(10, 1000, 60);
        for i in 0..6 {
            let id = format!("run_{i}");
            j.create_run(new_run(&id, "acme", None)).await.unwrap();
            j.claim(&id, "w1", TTL).await.unwrap().unwrap();
            j.put_step("w1", step(&id, "classify#0"), &b).await.unwrap();
            j.put_event("acme", &id, "timer", EventKind::Timer, None).await.unwrap();
            assert!(j.finish(&id, "w1", done(b)).await.unwrap());
        }
        // Not finished: never purged.
        j.create_run(new_run("run_live", "acme", None)).await.unwrap();
        j.create_run(new_run("run_busy", "acme", None)).await.unwrap();
        j.claim("run_busy", "w1", TTL).await.unwrap().unwrap();
        let spent = j.tenant_spend("acme").await.unwrap();
        assert!(spent.today_usd > 0.0, "{n}");

        assert_eq!(j.purge_finished(Duration::from_secs(3600), 100).await.unwrap(), 0, "{n}: too recent");
        // Two workers purge at once, in small batches: every finished run goes exactly once.
        let (a, b2) = (Arc::clone(&j), Arc::clone(&j));
        let purge = |j: Arc<dyn Journal>| async move {
            let mut total = 0;
            loop {
                let k = j.purge_finished(Duration::ZERO, 2).await.unwrap();
                total += k;
                if k == 0 {
                    return total;
                }
            }
        };
        let (x, y) = tokio::join!(purge(a), purge(b2));
        assert_eq!(x + y, 6, "{n}: {x} + {y}");
        for i in 0..6 {
            let id = format!("run_{i}");
            assert!(j.get_run("acme", &id).await.unwrap().is_none(), "{n}");
            assert!(j.steps(&id).await.unwrap().is_empty(), "{n}: steps go with the run");
            assert!(j.event(&id, "timer").await.unwrap().is_none(), "{n}: events go with the run");
        }
        assert!(
            j.get_run("acme", "run_live").await.unwrap().is_some()
                && j.get_run("acme", "run_busy").await.unwrap().is_some()
        );
        assert_eq!(j.tenant_spend("acme").await.unwrap(), spent, "{n}: the spend totals are not purged");
    }
}

fn kinds(evs: &[RunEvent]) -> Vec<&str> {
    evs.iter().map(|e| e.kind.as_str()).collect()
}

#[tokio::test]
async fn run_events_are_numbered_in_order_and_resume_after_any_number() {
    for j in journals().await {
        let n = j.name();
        let Created::New(r) = j.create_run(new_run("run_1", "acme", None)).await.unwrap() else { panic!("{n}") };
        assert_eq!(r.last_event, 1, "{n}: run.created");
        j.claim("run_1", "w1", TTL).await.unwrap().unwrap();
        let start =
            serde_json::json!({"step": "classify#0", "vertex": "classify", "kind": "router", "labels": ["pii"]});
        assert_eq!(j.start_step("run_1", "w2", start.clone()).await.unwrap(), StepStart::LeaseLost, "{n}");
        assert_eq!(j.start_step("run_1", "w1", start).await.unwrap(), StepStart::Started, "{n}");
        let b = BudgetState { usd: 0.001, ..BudgetState::new(10, 1000, 60) };
        j.put_step("w1", step("run_1", "classify#0"), &b).await.unwrap();
        // A duplicate checkpoint writes no second event.
        j.put_step("w1", step("run_1", "classify#0"), &b).await.unwrap();
        let ask = Suspend {
            status: RunStatus::InputRequired,
            awaiting: Some("ask#0".into()),
            prompt: Some("sealed-question".into()),
            wake_at: None,
            budget: b,
        };
        assert!(j.suspend("run_1", "w1", ask).await.unwrap());
        j.deliver_input("acme", "run_1", "ask#0", "sealed".into(), Some("api_key:abc"), None).await.unwrap();
        j.claim("run_1", "w2", TTL).await.unwrap().unwrap();
        let f = Finish { status: RunStatus::Succeeded, output: None, error: None, stop_reason: None, budget: b };
        assert!(j.finish("run_1", "w2", f).await.unwrap());

        let all = j.events("acme", "run_1", 0, 100).await.unwrap();
        assert_eq!(
            kinds(&all),
            [
                event::RUN_CREATED,
                event::STEP_STARTED,
                event::STEP_FINISHED,
                event::RUN_INPUT_REQUIRED,
                event::RUN_INPUT_RECEIVED,
                event::RUN_FINISHED
            ],
            "{n}"
        );
        assert_eq!(all.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2, 3, 4, 5, 6], "{n}");
        let fin = &all[2].data;
        assert_eq!(
            (&fin["step"], &fin["tokens"], &fin["prompt_tokens"], &fin["labels"], &fin["cost_usd"]),
            (
                &serde_json::json!("classify#0"),
                &serde_json::json!(12),
                &serde_json::json!(9),
                &serde_json::json!(["pii"]),
                &serde_json::json!(0.001)
            ),
            "{n}"
        );
        assert_eq!(all[3].data["sealed_question"], "sealed-question", "{n}: opened by the reader only");
        assert_eq!(all[4].data["by"], "api_key:abc", "{n}");
        assert_eq!(all[5].data["status"], "succeeded", "{n}");
        // Resume after any event; other tenants see nothing.
        assert_eq!(
            kinds(&j.events("acme", "run_1", 4, 100).await.unwrap()),
            [event::RUN_INPUT_RECEIVED, event::RUN_FINISHED]
        );
        assert_eq!(j.events("acme", "run_1", 1, 2).await.unwrap().len(), 2, "{n}: limit");
        assert!(j.events("globex", "run_1", 0, 100).await.unwrap().is_empty(), "{n}");
        assert_eq!(j.get_run("acme", "run_1").await.unwrap().unwrap().last_event, 6, "{n}");
        // Steps keep their usage split and labels.
        let s = &j.steps("run_1").await.unwrap()[0];
        assert_eq!((s.prompt_tokens, s.completion_tokens, s.labels.clone()), (9, 3, vec!["pii".to_owned()]), "{n}");
    }
}

#[tokio::test]
async fn cancel_ends_waiting_runs_and_stops_running_ones_at_the_next_step() {
    for j in journals().await {
        let n = j.name();
        let b = BudgetState::new(10, 1000, 60);
        let audit = |id: &str| AuditEvent {
            id: format!("{id}/cancel"),
            tenant_id: "acme".into(),
            actor: "api_key:abc".into(),
            action: "node.run.cancel".into(),
            target: Some(id.into()),
            detail: serde_json::json!({}),
            at: Utc::now(),
        };
        // Pending: cancelled at once, never claimed.
        j.create_run(new_run("run_p", "acme", None)).await.unwrap();
        assert_eq!(j.cancel("globex", "run_p", "x", None).await.unwrap(), Cancelled::NotFound, "{n}");
        assert_eq!(j.cancel("acme", "run_p", "api_key:abc", Some(audit("run_p"))).await.unwrap(), Cancelled::Ended);
        let r = j.get_run("acme", "run_p").await.unwrap().unwrap();
        assert_eq!((r.status, r.cancelled_by.as_deref()), (RunStatus::Cancelled, Some("api_key:abc")), "{n}");
        assert!(r.finished_at.is_some() && r.stop_reason.as_deref() == Some("cancelled by api_key:abc"), "{n}");
        assert!(j.claim_next("w1", TTL).await.unwrap().is_none(), "{n}");
        assert_eq!(
            j.cancel("acme", "run_p", "api_key:abc", Some(audit("run_p"))).await.unwrap(),
            Cancelled::AlreadyEnded(RunStatus::Cancelled),
            "{n}"
        );
        assert_eq!(j.events("acme", "run_p", 1, 10).await.unwrap()[0].data["status"], "cancelled", "{n}");

        // Waiting for a human: cancelled at once, the answer is refused.
        j.create_run(new_run("run_h", "acme", None)).await.unwrap();
        j.claim("run_h", "w1", TTL).await.unwrap().unwrap();
        let ask = Suspend {
            status: RunStatus::InputRequired,
            awaiting: Some("ask#0".into()),
            prompt: None,
            wake_at: None,
            budget: b,
        };
        assert!(j.suspend("run_h", "w1", ask).await.unwrap());
        assert_eq!(j.cancel("acme", "run_h", "user:jo", None).await.unwrap(), Cancelled::Ended, "{n}");
        assert_eq!(
            j.deliver_input("acme", "run_h", "ask#0", "x".into(), None, None).await.unwrap(),
            Delivered::NotAwaiting,
            "{n}"
        );

        // Running: asked to stop; the worker sees it at its next step, and cannot suspend.
        j.create_run(new_run("run_r", "acme", None)).await.unwrap();
        j.claim("run_r", "w1", TTL).await.unwrap().unwrap();
        assert!(!j.cancel_requested("run_r").await.unwrap());
        assert_eq!(j.cancel("acme", "run_r", "api_key:abc", Some(audit("run_r"))).await.unwrap(), Cancelled::Requested);
        assert_eq!(j.cancel("acme", "run_r", "api_key:abc", None).await.unwrap(), Cancelled::Requested, "{n}");
        assert!(j.cancel_requested("run_r").await.unwrap(), "{n}");
        let r = j.get_run("acme", "run_r").await.unwrap().unwrap();
        assert_eq!((r.status, r.cancel_requested_at.is_some()), (RunStatus::Running, true), "{n}");
        // The step in flight is still checkpointed (it was paid for).
        assert_eq!(j.put_step("w1", step("run_r", "a#0"), &b).await.unwrap(), StepWrite::Written, "{n}");
        assert_eq!(
            j.start_step("run_r", "w1", serde_json::json!({"step": "b#0"})).await.unwrap(),
            StepStart::Cancelled,
            "{n}"
        );
        assert!(!j.suspend("run_r", "w1", sleep_until(Utc::now(), b)).await.unwrap(), "{n}");
        let f = Finish {
            status: RunStatus::Cancelled,
            output: None,
            error: None,
            stop_reason: Some("cancelled by api_key:abc".into()),
            budget: b,
        };
        assert!(j.finish("run_r", "w1", f).await.unwrap(), "{n}");
        let evs = j.events("acme", "run_r", 0, 100).await.unwrap();
        assert_eq!(
            kinds(&evs),
            [event::RUN_CREATED, event::RUN_CANCEL_REQUESTED, event::STEP_FINISHED, event::RUN_FINISHED],
            "{n}"
        );
        // Finished cancelled runs are purged like any finished run.
        assert_eq!(j.purge_finished(Duration::ZERO, 100).await.unwrap(), 3, "{n}");

        // The audit outbox: once per id, each entry held by one worker at a time, gone once
        // acknowledged.
        let first = j.claim_audit("w1", TTL, 1).await.unwrap();
        assert_eq!(first.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), ["run_p/cancel"], "{n}");
        let second = j.claim_audit("w2", TTL, 10).await.unwrap();
        assert_eq!(
            second.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["run_r/cancel"],
            "{n}: the repeated cancel was not recorded twice, and w1's entry is not taken"
        );
        assert_eq!((second[0].action.as_str(), second[0].actor.as_str()), ("node.run.cancel", "api_key:abc"));
        j.ack_audit(&["run_p/cancel".to_owned(), "run_r/cancel".to_owned()]).await.unwrap();
        assert!(j.claim_audit("w3", TTL, 10).await.unwrap().is_empty(), "{n}");
        // A worker that dies before the acknowledgement: another one ships the entry after the hold.
        j.create_run(new_run("run_x", "acme", None)).await.unwrap();
        j.cancel("acme", "run_x", "api_key:abc", Some(audit("run_x"))).await.unwrap();
        assert_eq!(j.claim_audit("w1", Duration::ZERO, 10).await.unwrap().len(), 1, "{n}");
        let mut again = Vec::new();
        until("w1's hold to expire", async || {
            again = j.claim_audit("w2", TTL, 10).await.unwrap();
            !again.is_empty()
        })
        .await;
        assert_eq!(again[0].id, "run_x/cancel", "{n}");
    }
}

#[tokio::test]
async fn runs_are_listed_newest_first_with_filters_and_a_cursor() {
    for j in journals().await {
        let n = j.name();
        for i in 0..7 {
            let mut r = new_run(&format!("run_{i}"), "acme", None);
            r.node = if i % 2 == 0 { "triage".into() } else { "summary".into() };
            j.create_run(r).await.unwrap();
        }
        j.create_run(new_run("run_other", "globex", None)).await.unwrap();
        j.cancel("acme", "run_6", "x", None).await.unwrap();
        let q = |f: &dyn Fn(&mut RunQuery)| {
            let mut q = RunQuery { tenant: "acme".into(), limit: 100, ..RunQuery::default() };
            f(&mut q);
            q
        };
        let ids = |v: Vec<RunRecord>| v.into_iter().map(|r| r.id).collect::<Vec<_>>();
        let all = ids(j.list_runs(&q(&|_| {})).await.unwrap());
        assert_eq!(
            all,
            ["run_6", "run_5", "run_4", "run_3", "run_2", "run_1", "run_0"],
            "{n}: newest first, one tenant"
        );
        assert_eq!(
            ids(j.list_runs(&q(&|q| q.node = Some("summary".into()))).await.unwrap()),
            ["run_5", "run_3", "run_1"],
            "{n}"
        );
        assert_eq!(
            ids(j.list_runs(&q(&|q| q.nodes = Some(vec!["summary".into(), "nope".into()]))).await.unwrap()).len(),
            3,
            "{n}: an allowlist"
        );
        assert!(j.list_runs(&q(&|q| q.nodes = Some(vec![]))).await.unwrap().is_empty(), "{n}: an empty allowlist");
        assert_eq!(ids(j.list_runs(&q(&|q| q.statuses = vec![RunStatus::Cancelled])).await.unwrap()), ["run_6"], "{n}");
        // Pages of three: the cursor is the last (created_at, id) of the previous page.
        let mut pages = Vec::new();
        let mut before = None;
        loop {
            let page = j
                .list_runs(&q(&|q| {
                    q.limit = 3;
                    q.before.clone_from(&before);
                }))
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            before = page.last().map(|r| (r.created_at, r.id.clone()));
            pages.push(ids(page));
        }
        assert_eq!(pages.concat(), all, "{n}");
        assert_eq!(pages.len(), 3, "{n}");
        // A creation range.
        let r3 = j.get_run("acme", "run_3").await.unwrap().unwrap();
        let r5 = j.get_run("acme", "run_5").await.unwrap().unwrap();
        assert_eq!(
            ids(j
                .list_runs(&q(&|q| {
                    q.created_after = Some(r3.created_at);
                    q.created_before = Some(r5.created_at);
                }))
                .await
                .unwrap()),
            ["run_4", "run_3"],
            "{n}"
        );
    }
}
