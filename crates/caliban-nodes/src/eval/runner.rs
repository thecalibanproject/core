//! The eval runner: a worker (or a standalone process) claims eval runs from the journal and runs
//! them through its executor.
//!
//! - **Claims.** Like runs: one worker at a time holds an eval under a lease it renews; a worker
//!   that dies loses it to another, which carries on where it stopped.
//! - **Trials are ordinary node runs.** Each (case, trial) starts a run of the published version
//!   with the executor's normal `create` (input checked against the input schema, budgets, the
//!   eval's API key as the invoker), `Idempotency-Key: eval:<eval>:<case>:<trial>` (so a takeover
//!   finds the runs already created) and origin `eval:<eval>` (golden sets) or
//!   `injection:<eval>:<case>` (the injection suite, whose runs get sandboxed tools). Any worker
//!   may execute them; every model call goes through the gateway pipeline and is metered.
//! - **Human steps.** A golden case answers questions and approvals from its scripted `answers`
//!   (a question without one cancels the run and fails the trial; an approval without one is
//!   denied). The injection suite approves a tainted write only when its shown arguments carry
//!   none of the attack's markers, and answers questions neutrally. Answers are journaled and
//!   audited as `eval:<id>`.
//! - **Scoring** happens once the run ended: the golden case's checks (the LLM judge through the
//!   gateway, with the eval's API key, metered under the node with the eval id as run id), or the
//!   injection verdict. A trial is written once it is final; the eval ends with its metrics.

use super::injection::{self, Surface};
use super::{Check, GoldenCase, Plan, check_output, judge_request, judge_verdict, metrics};
use crate::NodeSpec;
use crate::executor::{CallCtx, ExecError, Executor, StartRun, idempotency_key, infrastructure_failure};
use crate::journal::evals::{EvalFinish, EvalRecord, EvalStatus, TrialRecord, TrialStatus, TrialWrite};
use crate::journal::{AuditEvent, Journal, RunRecord, RunStatus};
use chrono::Utc;
use futures::StreamExt;
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

#[derive(Debug, Clone)]
pub struct EvalOptions {
    /// Lease on a claimed eval, renewed every `heartbeat`.
    pub lease_ttl: Duration,
    pub heartbeat: Duration,
    /// How often an idle runner looks for evals, and how often a running one checks for a
    /// cancellation.
    pub poll: Duration,
    /// Evals this process runs at once.
    pub max_concurrent_evals: usize,
    /// How long an eval waits for its version to reach this process's snapshot (it was just
    /// published) before it fails.
    pub snapshot_wait: Duration,
}

impl Default for EvalOptions {
    fn default() -> Self {
        Self {
            lease_ttl: Duration::from_secs(30),
            heartbeat: Duration::from_secs(10),
            poll: Duration::from_millis(500),
            max_concurrent_evals: 4,
            snapshot_wait: Duration::from_secs(120),
        }
    }
}

/// The version of the judge's prompt (recorded with every golden eval, so scores are compared
/// under the same judge).
pub const JUDGE_PROMPT_VERSION: u32 = 1;

pub struct EvalRunner {
    ex: Arc<Executor>,
    opts: EvalOptions,
    /// Wakes the claim loop.
    wake: Notify,
}

/// Why a trial stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Abort {
    LeaseLost,
    Cancelled,
}

/// What a running eval's trials share.
struct Watch {
    lost: AtomicBool,
    cancel: AtomicBool,
    changed: Notify,
    /// Runs in flight (cancelled with the eval).
    inflight: Mutex<HashSet<String>>,
}

impl Watch {
    fn check(&self) -> Result<(), Abort> {
        if self.lost.load(Ordering::SeqCst) {
            return Err(Abort::LeaseLost);
        }
        if self.cancel.load(Ordering::SeqCst) {
            return Err(Abort::Cancelled);
        }
        Ok(())
    }
}

/// One trial to run.
enum Job {
    Golden(Arc<GoldenCase>, u32),
    /// The case, the trial, the run input and the pointers the caller marks untrusted.
    Injection(&'static injection::Case, u32, Value, Vec<String>),
    Manifest(&'static injection::Case),
}

struct Ctx<'a> {
    e: &'a EvalRecord,
    plan: &'a Plan,
    watch: &'a Watch,
}

impl EvalRunner {
    pub fn new(ex: Arc<Executor>, opts: EvalOptions) -> Arc<Self> {
        Arc::new(Self { ex, opts, wake: Notify::new() })
    }

    fn journal(&self) -> &Arc<dyn Journal> {
        self.ex.journal()
    }

    fn worker(&self) -> &str {
        self.ex.worker_id()
    }

    /// Wakes the claim loop (an eval was created by this process).
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Claims evals and runs them until `stop` is notified.
    pub async fn run_loop(self: Arc<Self>, stop: Arc<Notify>) {
        let slots = Arc::new(tokio::sync::Semaphore::new(self.opts.max_concurrent_evals.max(1)));
        loop {
            let Ok(permit) = Arc::clone(&slots).acquire_owned().await else { return };
            match self.journal().claim_eval(self.worker(), self.opts.lease_ttl).await {
                Ok(Some(e)) => {
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        me.execute(e).await;
                        drop(permit);
                    });
                    continue;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "claiming an eval failed"),
            }
            drop(permit);
            tokio::select! {
                () = stop.notified() => return,
                () = self.wake.notified() => {}
                () = tokio::time::sleep(self.opts.poll) => {}
            }
        }
    }

    /// Claims one eval and runs it to its end; `false` when there was none (tests).
    pub async fn run_once(self: &Arc<Self>) -> bool {
        match self.journal().claim_eval(self.worker(), self.opts.lease_ttl).await {
            Ok(Some(e)) => {
                self.execute(e).await;
                true
            }
            _ => false,
        }
    }

    async fn execute(self: &Arc<Self>, e: EvalRecord) {
        let watch = Arc::new(Watch {
            lost: AtomicBool::new(false),
            cancel: AtomicBool::new(e.cancel_requested_at.is_some()),
            changed: Notify::new(),
            inflight: Mutex::default(),
        });
        let _keeper = {
            let (me, w, id, tenant) = (Arc::clone(self), Arc::clone(&watch), e.id.clone(), e.tenant_id.clone());
            AbortOnDrop(tokio::spawn(async move {
                let mut beat = Instant::now();
                loop {
                    tokio::time::sleep(me.opts.poll.min(me.opts.heartbeat)).await;
                    if beat.elapsed() >= me.opts.heartbeat {
                        beat = Instant::now();
                        match me.journal().heartbeat_eval(&id, me.worker(), me.opts.lease_ttl).await {
                            Ok(true) => {}
                            Ok(false) => {
                                w.lost.store(true, Ordering::SeqCst);
                                w.changed.notify_waiters();
                                return;
                            }
                            Err(err) => tracing::warn!(eval = %id, error = %err, "eval lease heartbeat failed"),
                        }
                    }
                    if let Ok(Some(rec)) = me.journal().get_eval(&tenant, &id).await
                        && rec.cancel_requested_at.is_some()
                    {
                        w.cancel.store(true, Ordering::SeqCst);
                        w.changed.notify_waiters();
                    }
                }
            }))
        };
        let finish = match self.drive(&e, &watch).await {
            Err(Abort::LeaseLost) => {
                tracing::warn!(eval = %e.id, "lost the lease of an eval; another worker owns it now");
                return;
            }
            Err(Abort::Cancelled) => {
                let runs: Vec<String> = watch.inflight.lock().iter().cloned().collect();
                for run in runs {
                    let _ = self.ex.cancel(&e.tenant_id, &run, &by(&e)).await;
                }
                EvalFinish { status: EvalStatus::Cancelled, summary: self.summary(&e).await.ok(), error: None }
            }
            Ok(f) => f,
        };
        let audit = AuditEvent {
            id: format!("{}/finish", e.id),
            tenant_id: e.tenant_id.clone(),
            actor: by(&e),
            action: "node.eval.finish".into(),
            target: Some(e.id.clone()),
            detail: json!({
                "node": e.node, "version": e.version, "suite": e.suite, "status": finish.status,
                "pass_hat_k": finish.summary.as_ref().map(|s| &s["pass_hat_k"]),
                "pass_rate": finish.summary.as_ref().map(|s| &s["pass_rate"]),
                "error": finish.error,
            }),
            at: Utc::now(),
        };
        match self.journal().finish_eval(&e.id, self.worker(), finish, Some(audit)).await {
            Ok(true) => {}
            Ok(false) => tracing::warn!(eval = %e.id, "the eval's lease was lost before its end was recorded"),
            Err(err) => tracing::error!(eval = %e.id, error = %err, "recording the end of an eval failed"),
        }
    }

    fn fail(msg: impl Into<String>) -> EvalFinish {
        EvalFinish { status: EvalStatus::Failed, summary: None, error: Some(msg.into()) }
    }

    /// Runs every trial not recorded yet, then computes the metrics.
    async fn drive(&self, e: &EvalRecord, watch: &Watch) -> Result<EvalFinish, Abort> {
        let sealer = self.ex.sealer();
        let plan: Plan = match sealer.open(&e.tenant_id, &e.id, &e.plan).map(|t| serde_json::from_str(&t)) {
            Ok(Ok(p)) => p,
            Ok(Err(err)) => return Ok(Self::fail(format!("the eval's plan cannot be read: {err}"))),
            Err(err) => return Ok(Self::fail(format!("the eval's plan cannot be opened: {err}"))),
        };
        // The version was just published: wait for it to reach this process's snapshot.
        let deadline = Instant::now() + self.opts.snapshot_wait;
        let node = loop {
            watch.check()?;
            let known = self.ex.nodes().knows_key(&e.tenant_id, &e.invoker_key_hash);
            match self.ex.nodes().resolve(&e.tenant_id, &e.node, Some(e.version)) {
                Ok(n) if known => break n,
                Ok(_) if Instant::now() >= deadline => {
                    return Ok(Self::fail("the eval's API key has not reached this worker (revoked?)"));
                }
                Err(err) if Instant::now() >= deadline => return Ok(Self::fail(err)),
                _ => tokio::time::sleep(self.opts.poll).await,
            }
        };
        if node.hash != e.spec_hash {
            return Ok(Self::fail(format!("{}@v{} has another hash than the one evaluated", e.node, e.version)));
        }
        let done: HashSet<(String, u32)> = self
            .journal()
            .trials(&e.id)
            .await
            .map_err(|_| Abort::LeaseLost)?
            .into_iter()
            .filter(|t| t.status.is_final())
            .map(|t| (t.case_id, t.trial))
            .collect();
        let mut jobs = Vec::new();
        let mut not_applicable = Vec::new();
        match &plan {
            Plan::Golden { cases, .. } => {
                for c in cases {
                    let c = Arc::new(c.clone());
                    jobs.extend((0..e.k).map(|n| Job::Golden(Arc::clone(&c), n)));
                }
            }
            Plan::Injection { input, manifests, .. } => {
                let children = self.children(&e.tenant_id, &node.spec);
                let child_refs: Vec<&NodeSpec> = children.iter().map(Arc::as_ref).collect();
                let tools = Arc::clone(self.ex.tools());
                let info = |r: &str| tools.resolve(&e.tenant_id, r).ok().map(|t| (t.info(), t.reaches_network()));
                let surface = Surface::of(&node.spec, &child_refs, &info);
                for c in injection::cases() {
                    match injection::applicable(c, &surface, input, manifests) {
                        Err(why) => not_applicable.push((c.id, why)),
                        Ok(()) if c.goal == injection::Goal::ManifestFindings => jobs.push(Job::Manifest(c)),
                        Ok(()) => {
                            let (input, marks) = match c.goal {
                                _ if c.carrier.in_input() => injection::caller_input(c, &surface, input)
                                    .unwrap_or_else(|| (input.clone(), vec![])),
                                _ if c.needs_pii() => {
                                    (injection::with_pii(input).unwrap_or_else(|| input.clone()), vec![])
                                }
                                _ => (input.clone(), vec![]),
                            };
                            jobs.extend((0..e.k).map(|n| Job::Injection(c, n, input.clone(), marks.clone())));
                        }
                    }
                }
            }
        }
        jobs.retain(|j| {
            let key = match j {
                Job::Golden(c, n) => (c.id.clone(), *n),
                Job::Injection(c, n, ..) => (c.id.to_owned(), *n),
                Job::Manifest(c) => (c.id.to_owned(), 0),
            };
            !done.contains(&key)
        });
        let cx = Ctx { e, plan: &plan, watch };
        let results: Vec<Result<(), Abort>> = futures::stream::iter(jobs)
            .map(|j| self.trial(&cx, j))
            .buffer_unordered(e.concurrency.clamp(1, super::MAX_CONCURRENCY) as usize)
            .collect()
            .await;
        if let Some(abort) = results.iter().find_map(|r| r.err()) {
            return Err(abort);
        }
        // A cancellation that came in while the last trials ended still wins.
        if self
            .journal()
            .get_eval(&e.tenant_id, &e.id)
            .await
            .ok()
            .flatten()
            .is_some_and(|x| x.cancel_requested_at.is_some())
        {
            return Err(Abort::Cancelled);
        }
        let mut summary = self.summary(e).await.map_err(|_| Abort::LeaseLost)?;
        match &plan {
            Plan::Golden { golden_hash, judge_model, .. } => {
                summary["golden_hash"] = json!(golden_hash);
                summary["judge"] = json!({
                    "default_model": judge_model.as_deref().unwrap_or("caliban/auto"),
                    "prompt_version": JUDGE_PROMPT_VERSION,
                    "prompt_sha256": crate::hash::content_hash(&json!(super::JUDGE_SYSTEM)),
                    "temperature": 0,
                });
            }
            Plan::Injection { .. } => {
                let trials = self.journal().trials(&e.id).await.map_err(|_| Abort::LeaseLost)?;
                summary = metrics::injection_summary(injection::SUITE_VERSION, &trials, &not_applicable);
            }
        }
        Ok(EvalFinish { status: EvalStatus::Succeeded, summary: Some(summary), error: None })
    }

    /// The specs of every subnode a version can reach (published versions, from the snapshot).
    fn children(&self, tenant: &str, root: &NodeSpec) -> Vec<Arc<NodeSpec>> {
        let mut out: Vec<(String, u32, Arc<NodeSpec>)> = Vec::new();
        let mut queue = root.node_refs();
        while let Some((name, v)) = queue.pop() {
            if out.iter().any(|(n, x, _)| *n == name && *x == v) {
                continue;
            }
            if let Ok(n) = self.ex.nodes().resolve(tenant, &name, Some(v)) {
                queue.extend(n.spec.node_refs());
                out.push((name, v, n.spec));
            }
        }
        out.into_iter().map(|(_, _, s)| s).collect()
    }

    async fn summary(&self, e: &EvalRecord) -> Result<Value, String> {
        let trials = self.journal().trials(&e.id).await.map_err(|err| err.to_string())?;
        Ok(match e.suite {
            crate::journal::evals::Suite::Golden => {
                let judge: f64 = trials.iter().filter_map(|t| t.verdict["judge_usd"].as_f64()).sum();
                metrics::golden_summary(e.k, e.case_count as usize, &trials, judge)
            }
            crate::journal::evals::Suite::Injection => {
                metrics::injection_summary(injection::SUITE_VERSION, &trials, &[])
            }
        })
    }

    async fn put(&self, t: TrialRecord) -> Result<(), Abort> {
        match self.journal().put_trial(self.worker(), t).await {
            Ok(TrialWrite::LeaseLost) => Err(Abort::LeaseLost),
            Ok(_) => Ok(()),
            Err(err) => {
                tracing::warn!(error = %err, "recording a trial failed");
                Err(Abort::LeaseLost)
            }
        }
    }

    fn trial_record(e: &EvalRecord, case: &str, n: u32, run: Option<&RunRecord>, status: TrialStatus) -> TrialRecord {
        TrialRecord {
            eval_id: e.id.clone(),
            tenant_id: e.tenant_id.clone(),
            case_id: case.to_owned(),
            trial: n,
            run_id: run.map(|r| r.id.clone()),
            status,
            cost_usd: run.map_or(0.0, |r| r.budget.usd),
            latency_ms: run.map_or(0, |r| r.budget.wall_clock_ms_used),
            tokens: run.map_or(0, |r| r.budget.tokens_used),
            verdict: json!({}),
            detail: None,
            created_at: Utc::now(),
            finished_at: None,
        }
    }

    fn seal(&self, e: &EvalRecord, v: &Value) -> Option<String> {
        self.ex.sealer().seal(&e.tenant_id, &e.id, &v.to_string()).ok()
    }

    async fn trial(&self, cx: &Ctx<'_>, job: Job) -> Result<(), Abort> {
        cx.watch.check()?;
        let e = cx.e;
        let injected_case = match &job {
            Job::Injection(c, ..) => Some(*c),
            _ => None,
        };
        let (case_id, n, input, origin, untrusted) = match &job {
            Job::Manifest(c) => {
                let Plan::Injection { manifests, .. } = cx.plan else { return Ok(()) };
                let v = injection::manifest_verdict(c, manifests);
                let mut t = Self::trial_record(
                    e,
                    c.id,
                    0,
                    None,
                    if v.succeeded { TrialStatus::Failed } else { TrialStatus::Passed },
                );
                t.verdict = serde_json::to_value(&v).unwrap_or_default();
                return self.put(t).await;
            }
            Job::Golden(c, n) => (c.id.clone(), *n, c.input.clone(), format!("eval:{}", e.id), vec![]),
            Job::Injection(c, n, input, marks) => {
                (c.id.to_owned(), *n, input.clone(), injection::origin(&e.id, c.id), marks.clone())
            }
        };
        let start = StartRun {
            tenant: e.tenant_id.clone(),
            node: e.node.clone(),
            version: Some(e.version),
            input,
            chat: None,
            invoker: by(e),
            invoker_key_hash: Some(e.invoker_key_hash.clone()),
            idempotency: Some((format!("eval:{}:{case_id}:{n}", e.id), "eval".into())),
            budget: None,
            origin: Some(origin),
            check_spend: false,
            untrusted,
        };
        let run = match self.ex.create(start).await {
            Ok((run, _)) => run,
            Err(err) => {
                let mut t = Self::trial_record(e, &case_id, n, None, TrialStatus::Error);
                t.verdict = match (injected_case, &err) {
                    (Some(c), _) => json!({
                        "category": c.category,
                        "outcome": metrics::OUTCOME_ERROR,
                        "error_kind": "run_not_created",
                        "error": "the run could not be created",
                    }),
                    (None, _) => json!({"error": "the run could not be created"}),
                };
                t.detail = self.seal(e, &json!({"error": exec_message(&err)}));
                return self.put(t).await;
            }
        };
        self.put(Self::trial_record(e, &case_id, n, Some(&run), TrialStatus::Running)).await?;
        cx.watch.inflight.lock().insert(run.id.clone());
        if run.status == RunStatus::Pending {
            self.ex.spawn_run(run.id.clone());
        }
        // Kept in flight when the eval stops (cancelled), so its run is cancelled with it.
        let ended = self.follow(cx, &run.id, &job).await?;
        cx.watch.inflight.lock().remove(&run.id);
        let t = match &job {
            Job::Golden(c, _) => self.score_golden(cx, c, n, &ended).await,
            Job::Injection(c, ..) => self.score_injection(cx, c, n, &ended).await,
            Job::Manifest(_) => return Ok(()),
        };
        self.put(t).await
    }

    /// Waits until the run ends, answering its human steps on the way.
    async fn follow(&self, cx: &Ctx<'_>, run_id: &str, job: &Job) -> Result<RunRecord, Abort> {
        let e = cx.e;
        loop {
            cx.watch.check()?;
            let changed = cx.watch.changed.notified();
            let deadline = Instant::now() + Duration::from_secs(5);
            let r = tokio::select! {
                r = self.ex.wait(&e.tenant_id, run_id, deadline) => r,
                () = changed => continue,
            };
            let Ok(Some(r)) = r else { continue };
            if r.status.is_terminal() {
                return Ok(r);
            }
            if r.status != RunStatus::InputRequired {
                continue;
            }
            let step = r.awaiting.clone().unwrap_or_default();
            let question = r
                .prompt
                .as_deref()
                .and_then(|q| self.ex.sealer().open(&e.tenant_id, run_id, q).ok())
                .unwrap_or_default();
            let approval = step.ends_with("@approve");
            let answer: Option<Value> = match job {
                Job::Golden(c, _) => match c.answer_for(&step) {
                    Some(a) => Some(a.clone()),
                    None if approval => Some(json!({"approve": false})),
                    None => None,
                },
                Job::Injection(c, ..) if approval => Some(json!({"approve": c.approves(&question)})),
                Job::Injection(..) => Some(json!("No further details.")),
                Job::Manifest(_) => None,
            };
            match answer {
                Some(a) => {
                    if let Ok(crate::journal::Delivered::Accepted) =
                        self.ex.deliver_input(&e.tenant_id, run_id, Some(&step), &a, Some(&by(e))).await
                    {
                        self.ex.spawn_run(run_id.to_owned());
                    }
                }
                None => {
                    // A question the case does not answer: the trial cannot go on.
                    let _ = self.ex.cancel(&e.tenant_id, run_id, &by(e)).await;
                }
            }
        }
    }

    fn output(&self, r: &RunRecord) -> Value {
        r.output
            .as_deref()
            .and_then(|o| self.ex.sealer().open(&r.tenant_id, &r.id, o).ok())
            .map_or(Value::Null, |t| serde_json::from_str(&t).unwrap_or(Value::String(t)))
    }

    async fn score_golden(&self, cx: &Ctx<'_>, c: &GoldenCase, n: u32, r: &RunRecord) -> TrialRecord {
        let e = cx.e;
        let output = self.output(r);
        let judge_model = match cx.plan {
            Plan::Golden { judge_model, .. } => judge_model.clone(),
            Plan::Injection { .. } => None,
        };
        let mut results = Vec::new();
        let mut judge_usd = 0.0;
        let mut judge_error = None;
        if r.status == RunStatus::Succeeded {
            for (i, check) in c.all_checks().iter().enumerate() {
                if let Some(res) = check_output(check, &output) {
                    results.push(res);
                    continue;
                }
                let Check::LlmJudge { rubric, model, threshold } = check else { continue };
                let model = model.clone().or_else(|| judge_model.clone()).unwrap_or_else(|| "caliban/auto".into());
                let step_id = format!("judge:{}:{n}:{i}", c.id);
                let ctx = CallCtx {
                    tenant: e.tenant_id.clone(),
                    invoker_key_hash: Some(e.invoker_key_hash.clone()),
                    run_id: e.id.clone(),
                    node: e.node.clone(),
                    node_version: e.version,
                    idempotency_key: idempotency_key(&e.id, &step_id),
                    step_id,
                    origin: Some(format!("eval:{}", e.id)),
                };
                let body = judge_request(&model, rubric, &c.input, c.expected.as_ref(), &output);
                let mut res = super::CheckResult { kind: "llm_judge", passed: false, reason: None, score: None };
                // Retried like the node's own model calls (a 429 waits for its reset).
                let stop = || cx.watch.check().is_err();
                match self.ex.chat_retrying(&ctx, body, stop).await {
                    Ok(reply) => {
                        judge_usd += reply.usd;
                        match judge_verdict(&reply.message) {
                            Ok((score, reason)) => {
                                res.passed = score >= *threshold;
                                res.score = Some(score);
                                res.reason = Some(reason);
                            }
                            Err(err) => res.reason = Some(err),
                        }
                    }
                    Err(err) => {
                        res.reason = Some(err.to_string());
                        judge_error = Some(err.to_string());
                    }
                }
                results.push(res);
            }
        }
        let infra = infrastructure_failure(r.status, r.error.as_deref(), r.stop_reason.as_deref());
        let status = if judge_error.is_some() || infra.is_some() {
            TrialStatus::Error
        } else if r.status == RunStatus::Succeeded && results.iter().all(|x| x.passed) {
            TrialStatus::Passed
        } else {
            TrialStatus::Failed
        };
        let mut t = Self::trial_record(e, &c.id, n, Some(r), status);
        t.verdict = json!({
            "run_status": r.status,
            "checks": results.iter().map(|x| json!({"type": x.kind, "passed": x.passed, "score": x.score})).collect::<Vec<_>>(),
            "judge_usd": judge_usd,
        });
        if let Some(kind) = infra {
            t.verdict["error_kind"] = json!(kind);
        }
        t.detail =
            self.seal(e, &json!({"output": output, "checks": results, "error": r.error, "stop_reason": r.stop_reason}));
        t
    }

    async fn score_injection(&self, cx: &Ctx<'_>, c: &'static injection::Case, n: u32, r: &RunRecord) -> TrialRecord {
        let e = cx.e;
        let steps = self.journal().steps(&r.id).await.unwrap_or_default();
        let obs = match injection::observations(self.journal(), self.ex.sealer().as_ref(), r, &steps).await {
            Ok(o) => o,
            Err(err) => {
                let mut t = Self::trial_record(e, c.id, n, Some(r), TrialStatus::Error);
                t.verdict =
                    json!({"category": c.category, "outcome": metrics::OUTCOME_ERROR, "error_kind": "unscored"});
                t.detail = self.seal(e, &json!({"error": err}));
                return t;
            }
        };
        // Utility under attack: the run still did its job (the golden case's checks, when the
        // input came from one; else it succeeded). A defense that blocks attacks by breaking the
        // node shows here (arXiv 2610.04504).
        let output = self.output(r);
        let v = if c.goal == injection::Goal::AnswerCanary {
            let check = match self.journal().event(&r.id, crate::executor::answer::EVENT).await {
                Ok(Some(ev)) => ev
                    .payload
                    .as_deref()
                    .and_then(|p| self.ex.sealer().open(&r.tenant_id, &r.id, p).ok())
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok()),
                _ => None,
            };
            injection::answer_verdict(c, &output, check.as_ref(), obs.len())
        } else {
            injection::verdict(c, &steps, &obs)
        };
        let checks: &[Check] = match cx.plan {
            Plan::Injection { checks, .. } => checks,
            Plan::Golden { .. } => &[],
        };
        let utility = r.status == RunStatus::Succeeded
            && checks.iter().filter_map(|ch| check_output(ch, &output)).all(|x| x.passed);
        // A run that failed on a quota, the provider or a timeout says nothing about the defenses:
        // an error, unless the attack already had its effect (a tool received it) before the failure.
        // An answer never reached anyone from such a run, whatever its partial output holds.
        let infra = infrastructure_failure(r.status, r.error.as_deref(), r.stop_reason.as_deref());
        let effect_first = v.succeeded && c.goal != injection::Goal::AnswerCanary;
        let status = match infra {
            Some(_) if !effect_first => TrialStatus::Error,
            _ if v.succeeded => TrialStatus::Failed,
            _ => TrialStatus::Passed,
        };
        let mut t = Self::trial_record(e, c.id, n, Some(r), status);
        let mut verdict = serde_json::to_value(&v).unwrap_or_default();
        if status == TrialStatus::Error {
            verdict["succeeded"] = json!(false);
            verdict["outcome"] = json!(metrics::OUTCOME_ERROR);
            verdict["error_kind"] = json!(infra);
        }
        verdict["utility"] = json!(utility);
        verdict["run_status"] = json!(r.status);
        t.verdict = verdict;
        let calls: Vec<Value> = obs
            .iter()
            .map(|o| json!({"tool": o.tool, "write": o.write, "trusted": o.trusted, "args": o.args}))
            .collect();
        t.detail = self.seal(e, &json!({"tool_calls": calls, "error": r.error, "stop_reason": r.stop_reason}));
        t
    }
}

/// Who an eval's runs and answers are by.
fn by(e: &EvalRecord) -> String {
    format!("eval:{}", e.id)
}

fn exec_message(e: &ExecError) -> String {
    e.to_string()
}

/// Aborts the task when dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
