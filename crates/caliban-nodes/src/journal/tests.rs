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
        input_labels: vec!["caller".into()],
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

pub(crate) async fn until_pub(what: &str, f: impl AsyncFnMut() -> bool) {
    until(what, f).await;
}

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
        assert_eq!(a.input_labels, ["caller"], "{n}: the input's labels are stored");
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
        let got = j.get_run("acme", "run_a").await.unwrap().unwrap();
        assert_eq!((got.id.as_str(), got.input_labels.clone()), ("run_a", vec!["caller".to_owned()]), "{n}");
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

// ───────────────────────────── evals ─────────────────────────────

use super::evals::*;

fn audit_event(id: &str, action: &str) -> AuditEvent {
    AuditEvent {
        id: id.into(),
        tenant_id: "acme".into(),
        actor: "user:jo".into(),
        action: action.into(),
        target: Some("triage".into()),
        detail: serde_json::json!({"node": "triage"}),
        at: Utc::now(),
    }
}

pub(crate) fn new_eval(id: &str, tenant: &str, suite: Suite) -> NewEval {
    NewEval {
        id: id.into(),
        tenant_id: tenant.into(),
        node: "triage".into(),
        version: 2,
        spec_hash: "sha256:01".into(),
        suite,
        k: 3,
        concurrency: 2,
        created_by: "user:jo".into(),
        api_key_id: Some("key_1".into()),
        invoker_key_hash: "ab".repeat(32),
        plan: "sealed-plan".into(),
        case_count: 2,
    }
}

fn trial(eval: &str, case: &str, n: u32, status: TrialStatus) -> TrialRecord {
    TrialRecord {
        eval_id: eval.into(),
        tenant_id: "acme".into(),
        case_id: case.into(),
        trial: n,
        run_id: Some(format!("run_{case}_{n}")),
        status,
        cost_usd: 0.25,
        latency_ms: 120,
        tokens: 40,
        verdict: serde_json::json!({"checks": [{"type": "exact", "passed": status == TrialStatus::Passed}]}),
        detail: Some("sealed-detail".into()),
        created_at: Utc::now(),
        finished_at: None,
    }
}

#[tokio::test]
async fn golden_sets_and_promotion_bars_are_stored_per_version_with_their_audit() {
    for j in journals().await {
        let n = j.name();
        let g = |v: u32, cases: &str, count: u32| GoldenSetRecord {
            tenant_id: "acme".into(),
            node: "triage".into(),
            version: v,
            cases: cases.into(),
            case_count: count,
            hash: format!("sha256:{cases}"),
            updated_at: Utc::now(),
            updated_by: "user:jo".into(),
        };
        j.put_golden_set(g(2, "sealed-a", 2), Some(audit_event("g1", "node.golden_set.update"))).await.unwrap();
        j.put_golden_set(g(1, "sealed-b", 1), None).await.unwrap();
        // Replaced in place.
        j.put_golden_set(g(2, "sealed-c", 3), Some(audit_event("g2", "node.golden_set.update"))).await.unwrap();
        let got = j.golden_set("acme", "triage", 2).await.unwrap().expect(n);
        assert_eq!((got.cases.as_str(), got.case_count, got.updated_by.as_str()), ("sealed-c", 3, "user:jo"), "{n}");
        assert!(j.golden_set("globex", "triage", 2).await.unwrap().is_none(), "{n}: tenant-scoped");
        let all: Vec<u32> = j.golden_sets("acme", "triage").await.unwrap().iter().map(|g| g.version).collect();
        assert_eq!(all, [1, 2], "{n}");
        assert!(
            j.delete_golden_set("acme", "triage", 1, Some(audit_event("g3", "node.golden_set.delete"))).await.unwrap()
        );
        assert!(!j.delete_golden_set("acme", "triage", 1, Some(audit_event("g4", "x"))).await.unwrap(), "{n}");

        assert!(j.eval_policy("acme", "triage").await.unwrap().is_none());
        let p = |bar: f64| EvalPolicyRecord {
            tenant_id: "acme".into(),
            node: "triage".into(),
            policy: serde_json::json!({"golden": {"min_pass_k": bar}}),
            updated_at: Utc::now(),
            updated_by: "user:jo".into(),
        };
        j.put_eval_policy(p(0.8), Some(audit_event("p1", "node.eval_policy.update"))).await.unwrap();
        j.put_eval_policy(p(0.9), None).await.unwrap();
        let got = j.eval_policy("acme", "triage").await.unwrap().expect(n);
        assert_eq!(got.policy["golden"]["min_pass_k"], 0.9, "{n}");

        // Every write recorded its audit event in the outbox (a no-op delete recorded nothing).
        let mut ids: Vec<String> =
            j.claim_audit("cp", TTL, 100).await.unwrap().into_iter().map(|a| a.id).collect::<Vec<_>>();
        ids.sort();
        assert_eq!(ids, ["g1", "g2", "g3", "p1"], "{n}");
    }
}

#[tokio::test]
async fn evals_are_claimed_once_fenced_by_their_lease_and_finished_with_metrics() {
    for j in journals().await {
        let n = j.name();
        let e = j.create_eval(new_eval("eval_1", "acme", Suite::Golden), Some(audit_event("e1", "node.eval.start")));
        let e = e.await.unwrap();
        assert_eq!((e.status, e.claims, e.k, e.suite), (EvalStatus::Pending, 0, 3, Suite::Golden), "{n}");
        assert!(j.get_eval("globex", "eval_1").await.unwrap().is_none(), "{n}: tenant-scoped");

        let c = j.claim_eval("w1", TTL).await.unwrap().expect(n);
        assert_eq!((c.status, c.lease_owner.as_deref(), c.claims), (EvalStatus::Running, Some("w1"), 1), "{n}");
        assert!(j.claim_eval("w2", TTL).await.unwrap().is_none(), "{n}: held");
        assert!(j.heartbeat_eval("eval_1", "w1", TTL).await.unwrap());
        assert!(!j.heartbeat_eval("eval_1", "w2", TTL).await.unwrap());

        // Trials: written while running, final once.
        let running =
            TrialRecord { status: TrialStatus::Running, detail: None, ..trial("eval_1", "a", 0, TrialStatus::Running) };
        assert_eq!(j.put_trial("w1", running).await.unwrap(), TrialWrite::Written, "{n}");
        assert_eq!(
            j.put_trial("w2", trial("eval_1", "a", 0, TrialStatus::Passed)).await.unwrap(),
            TrialWrite::LeaseLost
        );
        assert_eq!(j.put_trial("w1", trial("eval_1", "a", 0, TrialStatus::Passed)).await.unwrap(), TrialWrite::Written);
        match j.put_trial("w1", trial("eval_1", "a", 0, TrialStatus::Failed)).await.unwrap() {
            TrialWrite::Existing(t) => assert_eq!(t.status, TrialStatus::Passed, "{n}: the first final write wins"),
            other => panic!("{n}: {other:?}"),
        }
        j.put_trial("w1", trial("eval_1", "b", 1, TrialStatus::Failed)).await.unwrap();
        j.put_trial("w1", trial("eval_1", "b", 0, TrialStatus::Error)).await.unwrap();
        let ts = j.trials("eval_1").await.unwrap();
        let keys: Vec<(&str, u32, TrialStatus)> = ts.iter().map(|t| (t.case_id.as_str(), t.trial, t.status)).collect();
        assert_eq!(
            keys,
            [("a", 0, TrialStatus::Passed), ("b", 0, TrialStatus::Error), ("b", 1, TrialStatus::Failed)],
            "{n}"
        );
        assert!(ts.iter().all(|t| t.finished_at.is_some()), "{n}");
        assert_eq!((ts[0].run_id.as_deref(), ts[0].latency_ms, ts[0].cost_usd), (Some("run_a_0"), 120, 0.25), "{n}");
        assert_eq!(ts[0].verdict["checks"][0]["passed"], true, "{n}");

        // w1 stops heartbeating: w2 takes it over and w1 is fenced off.
        j.create_eval(new_eval("eval_2", "acme", Suite::Injection), None).await.unwrap();
        let c2 = j.claim_eval("w3", Duration::ZERO).await.unwrap().expect(n);
        assert_eq!(c2.id, "eval_2", "{n}");
        let mut taken = None;
        until("the eval lease to expire", async || {
            taken = j.claim_eval("w4", TTL).await.unwrap();
            taken.is_some()
        })
        .await;
        assert_eq!(taken.map(|e| (e.id, e.claims)), Some(("eval_2".to_owned(), 2)), "{n}");
        let done =
            |s: EvalStatus| EvalFinish { status: s, summary: Some(serde_json::json!({"pass_rate": 1.0})), error: None };
        assert!(!j.finish_eval("eval_2", "w3", done(EvalStatus::Succeeded), None).await.unwrap(), "{n}: fenced");
        assert!(j.finish_eval("eval_2", "w4", done(EvalStatus::Succeeded), None).await.unwrap(), "{n}");
        assert!(j.finish_eval("eval_1", "w1", done(EvalStatus::Running), None).await.is_err(), "{n}");
        let f = j.finish_eval("eval_1", "w1", done(EvalStatus::Succeeded), Some(audit_event("e2", "node.eval.finish")));
        assert!(f.await.unwrap(), "{n}");
        let e = j.get_eval("acme", "eval_1").await.unwrap().unwrap();
        assert_eq!(
            (e.status, e.lease_owner, e.summary.unwrap()["pass_rate"].as_f64()),
            (EvalStatus::Succeeded, None, Some(1.0))
        );
        assert!(e.finished_at.is_some() && e.started_at.is_some(), "{n}");
        assert_eq!(
            j.put_trial("w1", trial("eval_1", "c", 0, TrialStatus::Passed)).await.unwrap(),
            TrialWrite::LeaseLost
        );

        // Listing: newest first, filtered.
        j.create_eval(new_eval("eval_3", "acme", Suite::Golden), None).await.unwrap();
        let q = |suite: Option<Suite>, statuses: Vec<EvalStatus>| EvalQuery {
            tenant: "acme".into(),
            node: Some("triage".into()),
            version: Some(2),
            suite,
            statuses,
            before: None,
            limit: 10,
        };
        let ids = |v: Vec<EvalRecord>| v.into_iter().map(|e| e.id).collect::<Vec<_>>();
        assert_eq!(ids(j.list_evals(&q(None, vec![])).await.unwrap()), ["eval_3", "eval_2", "eval_1"], "{n}");
        assert_eq!(ids(j.list_evals(&q(Some(Suite::Golden), vec![EvalStatus::Succeeded])).await.unwrap()), ["eval_1"]);
        let mut page = q(None, vec![]);
        page.limit = 1;
        let first = j.list_evals(&page).await.unwrap();
        page.before = Some((first[0].created_at, first[0].id.clone()));
        assert_eq!(ids(j.list_evals(&page).await.unwrap()), ["eval_2"], "{n}");
        let mut other = q(None, vec![]);
        other.tenant = "globex".into();
        assert!(j.list_evals(&other).await.unwrap().is_empty(), "{n}");

        // Retention: the summary stays; the sealed content of finished evals goes.
        assert_eq!(j.purge_eval_content(Duration::from_secs(3600), 100).await.unwrap(), 0, "{n}: too recent");
        let cleared = j.purge_eval_content(Duration::ZERO, 100).await.unwrap();
        assert_eq!(cleared, 5, "{n}: three trials, two finished evals");
        let ts = j.trials("eval_1").await.unwrap();
        assert!(ts.iter().all(|t| t.detail.is_none()) && ts[0].verdict["checks"][0]["passed"] == true, "{n}");
        let e = j.get_eval("acme", "eval_1").await.unwrap().unwrap();
        assert_eq!((e.plan.as_str(), e.summary.unwrap()["pass_rate"].as_f64()), ("", Some(1.0)), "{n}");
        let pending = j.get_eval("acme", "eval_3").await.unwrap().unwrap();
        assert_eq!(pending.plan, "sealed-plan", "{n}: an eval not finished keeps its plan");
        assert_eq!(j.purge_eval_content(Duration::ZERO, 100).await.unwrap(), 0, "{n}: done");
    }
}

#[tokio::test]
async fn cancelling_an_eval_ends_a_pending_one_and_asks_a_running_one_to_stop() {
    for j in journals().await {
        let n = j.name();
        j.create_eval(new_eval("eval_p", "acme", Suite::Golden), None).await.unwrap();
        let c = j.cancel_eval("acme", "eval_p", "user:jo", Some(audit_event("eval_p/cancel", "node.eval.cancel")));
        assert_eq!(c.await.unwrap(), EvalCancel::Ended, "{n}");
        let e = j.get_eval("acme", "eval_p").await.unwrap().unwrap();
        assert_eq!((e.status, e.cancelled_by.as_deref()), (EvalStatus::Cancelled, Some("user:jo")), "{n}");
        assert!(j.claim_eval("w1", TTL).await.unwrap().is_none(), "{n}: nothing to claim");
        assert_eq!(
            j.cancel_eval("acme", "eval_p", "x", None).await.unwrap(),
            EvalCancel::AlreadyEnded(EvalStatus::Cancelled)
        );
        assert_eq!(j.cancel_eval("globex", "eval_p", "x", None).await.unwrap(), EvalCancel::NotFound, "{n}");

        j.create_eval(new_eval("eval_r", "acme", Suite::Injection), None).await.unwrap();
        j.claim_eval("w1", TTL).await.unwrap().expect(n);
        assert_eq!(j.cancel_eval("acme", "eval_r", "user:jo", None).await.unwrap(), EvalCancel::Requested, "{n}");
        assert_eq!(j.cancel_eval("acme", "eval_r", "user:jo", None).await.unwrap(), EvalCancel::Requested, "{n}");
        let e = j.get_eval("acme", "eval_r").await.unwrap().unwrap();
        assert!(e.cancel_requested_at.is_some() && e.status == EvalStatus::Running, "{n}");
        let f = EvalFinish { status: EvalStatus::Cancelled, summary: None, error: None };
        assert!(j.finish_eval("eval_r", "w1", f, None).await.unwrap(), "{n}");
        let ids: Vec<String> = j.claim_audit("cp", TTL, 10).await.unwrap().into_iter().map(|a| a.id).collect();
        assert_eq!(ids, ["eval_p/cancel"], "{n}");
    }
}

#[tokio::test]
async fn sandbox_observations_are_events_written_once() {
    for j in journals().await {
        let n = j.name();
        j.create_run(new_run("run_1", "acme", None)).await.unwrap();
        assert!(
            j.put_event("acme", "run_1", "sandbox:agent#1.0", EventKind::Observation, Some("a".into())).await.unwrap()
        );
        assert!(
            !j.put_event("acme", "run_1", "sandbox:agent#1.0", EventKind::Observation, Some("b".into())).await.unwrap()
        );
        let ev = j.event("run_1", "sandbox:agent#1.0").await.unwrap().expect(n);
        assert_eq!((ev.kind, ev.payload.as_deref()), (EventKind::Observation, Some("a")), "{n}");
    }
}
