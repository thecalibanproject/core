//! In-memory journal: standalone mode without a database, and tests. Same behaviour as
//! [`super::postgres::PgJournal`] (the parity suite runs against both); everything is lost when
//! the process stops.

use super::evals::*;
use super::*;
use parking_lot::Mutex;
use std::collections::HashMap;

#[derive(Default)]
struct Tables {
    /// In creation order.
    runs: Vec<RunRecord>,
    steps: HashMap<String, Vec<StepRecord>>,
    events: HashMap<(String, String), EventRecord>,
    /// (tenant, UTC day) to USD.
    spend: HashMap<(String, chrono::NaiveDate), f64>,
    /// Run id to its events, in order.
    run_events: HashMap<String, Vec<RunEvent>>,
    /// The audit outbox, in creation order, with who holds each entry and until when.
    audit: Vec<(AuditEvent, Option<Hold>)>,
    /// (tenant, node, version) to its golden set.
    golden: HashMap<(String, String, u32), GoldenSetRecord>,
    /// (tenant, node) to its promotion bar.
    policies: HashMap<(String, String), EvalPolicyRecord>,
    /// In creation order.
    evals: Vec<EvalRecord>,
    /// Eval id to its trials.
    trials: HashMap<String, Vec<TrialRecord>>,
}

/// Who holds an outbox entry, and until when.
type Hold = (String, DateTime<Utc>);

impl Tables {
    /// Appends an event to a run (numbered after its last one).
    fn push_event(&mut self, run_id: &str, kind: &str, data: serde_json::Value) {
        let Some(r) = self.runs.iter_mut().find(|r| r.id == run_id) else { return };
        r.last_event += 1;
        let ev = RunEvent {
            run_id: run_id.to_owned(),
            seq: r.last_event,
            kind: kind.to_owned(),
            data,
            created_at: Utc::now(),
        };
        self.run_events.entry(run_id.to_owned()).or_default().push(ev);
    }

    fn push_audit(&mut self, a: Option<AuditEvent>) {
        if let Some(a) = a
            && !self.audit.iter().any(|(x, _)| x.id == a.id)
        {
            self.audit.push((a, None));
        }
    }
}

#[derive(Default)]
pub struct MemoryJournal {
    t: Mutex<Tables>,
}

impl MemoryJournal {
    pub fn new() -> Self {
        Self::default()
    }

    fn claim_audit_where(
        &self,
        worker: &str,
        ttl: Duration,
        limit: usize,
        keep: impl Fn(&AuditEvent) -> bool,
    ) -> JResult<Vec<AuditEvent>> {
        let now = Utc::now();
        let mut t = self.t.lock();
        let mut out = Vec::new();
        for (a, held) in &mut t.audit {
            if out.len() >= limit {
                break;
            }
            if keep(a) && held.as_ref().is_none_or(|(_, until)| *until < now) {
                *held = Some((worker.to_owned(), now + lease(ttl)));
                out.push(a.clone());
            }
        }
        Ok(out)
    }

    /// Ends the lease of a run as if its worker had died long ago (tests).
    pub fn expire_lease(&self, run_id: &str) {
        if let Some(r) = self.t.lock().runs.iter_mut().find(|r| r.id == run_id) {
            r.lease_expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        }
    }
}

/// The claim rule, shared with the Postgres query.
pub(crate) fn runnable(r: &RunRecord, now: DateTime<Utc>) -> bool {
    match r.status {
        RunStatus::Pending => r.wake_at.is_none_or(|w| w <= now),
        RunStatus::Sleeping | RunStatus::InputRequired => r.wake_at.is_some_and(|w| w <= now),
        RunStatus::Running => r.lease_expires_at.is_none_or(|e| e < now),
        _ => false,
    }
}

fn take(r: &mut RunRecord, worker: &str, ttl: Duration, now: DateTime<Utc>) -> RunRecord {
    r.status = RunStatus::Running;
    r.lease_owner = Some(worker.to_owned());
    r.lease_expires_at = Some(now + lease(ttl));
    r.claims += 1;
    r.started_at.get_or_insert(now);
    r.wake_at = None;
    r.awaiting = None;
    r.prompt = None;
    r.updated_at = now;
    r.clone()
}

fn holds(r: &RunRecord, worker: &str) -> bool {
    r.status == RunStatus::Running && r.lease_owner.as_deref() == Some(worker)
}

#[async_trait::async_trait]
impl Journal for MemoryJournal {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn create_run(&self, run: NewRun) -> JResult<Created> {
        let mut t = self.t.lock();
        if let Some((key, fp)) = &run.idempotency
            && let Some(existing) =
                t.runs.iter().find(|r| r.tenant_id == run.tenant_id && r.idempotency_key.as_ref() == Some(key))
        {
            return Ok(if existing.idempotency_fingerprint.as_ref() == Some(fp) {
                Created::Existing(existing.clone())
            } else {
                Created::KeyReused
            });
        }
        if t.runs.iter().any(|r| r.id == run.id) {
            return Err(JournalError(format!("run {} already exists", run.id)));
        }
        let now = Utc::now();
        let (idempotency_key, idempotency_fingerprint) =
            run.idempotency.map_or((None, None), |(k, f)| (Some(k), Some(f)));
        let rec = RunRecord {
            id: run.id,
            tenant_id: run.tenant_id,
            node: run.node,
            version: run.version,
            spec_hash: run.spec_hash,
            invoker: run.invoker,
            invoker_key_hash: run.invoker_key_hash,
            input: run.input,
            specs: run.specs,
            output: None,
            status: RunStatus::Pending,
            wake_at: None,
            awaiting: None,
            prompt: None,
            budget: run.budget,
            lease_owner: None,
            lease_expires_at: None,
            claims: 0,
            error: None,
            stop_reason: None,
            idempotency_key,
            idempotency_fingerprint,
            created_at: now,
            updated_at: now,
            started_at: None,
            finished_at: None,
            cancel_requested_at: None,
            cancelled_by: None,
            origin: run.origin,
            input_labels: run.input_labels,
            last_event: 0,
        };
        let data = serde_json::json!({"node": rec.node, "version": rec.version});
        t.runs.push(rec.clone());
        t.push_event(&rec.id, event::RUN_CREATED, data);
        let rec = t.runs.last().cloned().unwrap_or(rec);
        Ok(Created::New(rec))
    }

    async fn get_run(&self, tenant: &str, id: &str) -> JResult<Option<RunRecord>> {
        Ok(self.t.lock().runs.iter().find(|r| r.id == id && r.tenant_id == tenant).cloned())
    }

    async fn steps(&self, run_id: &str) -> JResult<Vec<StepRecord>> {
        Ok(self.t.lock().steps.get(run_id).cloned().unwrap_or_default())
    }

    async fn claim_next(&self, worker: &str, ttl: Duration) -> JResult<Option<RunRecord>> {
        let now = Utc::now();
        let mut t = self.t.lock();
        Ok(t.runs.iter_mut().find(|r| runnable(r, now)).map(|r| take(r, worker, ttl, now)))
    }

    async fn claim(&self, run_id: &str, worker: &str, ttl: Duration) -> JResult<Option<RunRecord>> {
        let now = Utc::now();
        let mut t = self.t.lock();
        Ok(t.runs.iter_mut().find(|r| r.id == run_id && runnable(r, now)).map(|r| take(r, worker, ttl, now)))
    }

    async fn heartbeat(&self, run_id: &str, worker: &str, ttl: Duration) -> JResult<bool> {
        let now = Utc::now();
        let mut t = self.t.lock();
        Ok(match t.runs.iter_mut().find(|r| r.id == run_id && holds(r, worker)) {
            Some(r) => {
                r.lease_expires_at = Some(now + lease(ttl));
                true
            }
            None => false,
        })
    }

    async fn release(&self, run_id: &str, worker: &str) -> JResult<bool> {
        let mut t = self.t.lock();
        Ok(match t.runs.iter_mut().find(|r| r.id == run_id && holds(r, worker)) {
            Some(r) => {
                r.status = RunStatus::Pending;
                r.lease_owner = None;
                r.lease_expires_at = None;
                r.updated_at = Utc::now();
                true
            }
            None => false,
        })
    }

    async fn put_step(&self, worker: &str, step: StepRecord, budget: &BudgetState) -> JResult<StepWrite> {
        let mut t = self.t.lock();
        let Some(run) = t.runs.iter_mut().find(|r| r.id == step.run_id && holds(r, worker)) else {
            return Ok(StepWrite::LeaseLost);
        };
        run.budget = *budget;
        run.updated_at = Utc::now();
        if let Some(existing) =
            t.steps.get(&step.run_id).and_then(|steps| steps.iter().find(|s| s.step_id == step.step_id))
        {
            return Ok(StepWrite::Existing(Box::new(existing.clone())));
        }
        if step.usd > 0.0 {
            *t.spend.entry((step.tenant_id.clone(), Utc::now().date_naive())).or_default() += step.usd;
        }
        let data = step_event(&step, budget.usd);
        t.push_event(&step.run_id, event::STEP_FINISHED, data);
        t.steps.entry(step.run_id.clone()).or_default().push(step);
        Ok(StepWrite::Written)
    }

    async fn suspend(&self, run_id: &str, worker: &str, s: Suspend) -> JResult<bool> {
        if !matches!(s.status, RunStatus::Sleeping | RunStatus::InputRequired) {
            return Err(JournalError(format!("cannot suspend a run as {}", s.status.as_str())));
        }
        let mut t = self.t.lock();
        let (kind, data) = suspend_event(&s);
        let ok = match t.runs.iter_mut().find(|r| r.id == run_id && holds(r, worker) && r.cancel_requested_at.is_none())
        {
            Some(r) => {
                r.status = s.status;
                r.awaiting = s.awaiting;
                r.prompt = s.prompt;
                r.wake_at = s.wake_at;
                r.budget = s.budget;
                r.lease_owner = None;
                r.lease_expires_at = None;
                r.updated_at = Utc::now();
                true
            }
            None => false,
        };
        if ok {
            t.push_event(run_id, kind, data);
        }
        Ok(ok)
    }

    async fn finish(&self, run_id: &str, worker: &str, f: Finish) -> JResult<bool> {
        if !f.status.is_terminal() {
            return Err(JournalError(format!("cannot finish a run as {}", f.status.as_str())));
        }
        let mut t = self.t.lock();
        let data = finish_event(f.status, f.error.as_deref(), f.stop_reason.as_deref(), f.budget.usd);
        let ok = match t.runs.iter_mut().find(|r| r.id == run_id && holds(r, worker)) {
            Some(r) => {
                let now = Utc::now();
                r.status = f.status;
                r.output = f.output;
                r.error = f.error;
                r.stop_reason = f.stop_reason;
                r.budget = f.budget;
                r.lease_owner = None;
                r.lease_expires_at = None;
                r.wake_at = None;
                r.updated_at = now;
                r.finished_at = Some(now);
                true
            }
            None => false,
        };
        if ok {
            t.push_event(run_id, event::RUN_FINISHED, data);
        }
        Ok(ok)
    }

    async fn purge_finished(&self, older_than: Duration, batch: usize) -> JResult<u64> {
        let cutoff = Utc::now() - lease(older_than);
        let mut t = self.t.lock();
        let gone: Vec<String> = t
            .runs
            .iter()
            .filter(|r| r.status.is_terminal() && r.finished_at.is_some_and(|f| f < cutoff))
            .take(batch)
            .map(|r| r.id.clone())
            .collect();
        t.runs.retain(|r| !gone.contains(&r.id));
        for id in &gone {
            t.steps.remove(id);
            t.run_events.remove(id);
        }
        t.events.retain(|(run, _), _| !gone.contains(run));
        Ok(gone.len() as u64)
    }

    async fn tenant_spend(&self, tenant: &str) -> JResult<TenantSpend> {
        use chrono::Datelike;
        let today = Utc::now().date_naive();
        let t = self.t.lock();
        let mut out = TenantSpend::default();
        for ((tn, day), usd) in &t.spend {
            if tn == tenant && day.year() == today.year() && day.month() == today.month() {
                out.month_usd += usd;
                if *day == today {
                    out.today_usd += usd;
                }
            }
        }
        Ok(out)
    }

    async fn event(&self, run_id: &str, name: &str) -> JResult<Option<EventRecord>> {
        Ok(self.t.lock().events.get(&(run_id.to_owned(), name.to_owned())).cloned())
    }

    async fn put_event(
        &self,
        tenant: &str,
        run_id: &str,
        name: &str,
        kind: EventKind,
        payload: Option<String>,
    ) -> JResult<bool> {
        let mut t = self.t.lock();
        if !t.runs.iter().any(|r| r.id == run_id && r.tenant_id == tenant) {
            return Err(JournalError(format!("run {run_id} not found")));
        }
        let key = (run_id.to_owned(), name.to_owned());
        if t.events.contains_key(&key) {
            return Ok(false);
        }
        let ev = EventRecord { run_id: run_id.into(), name: name.into(), kind, payload, created_at: Utc::now() };
        t.events.insert(key, ev);
        Ok(true)
    }

    async fn deliver_input(
        &self,
        tenant: &str,
        run_id: &str,
        step: &str,
        payload: String,
        by: Option<&str>,
        audit: Option<AuditEvent>,
    ) -> JResult<Delivered> {
        let mut t = self.t.lock();
        let Some(r) = t.runs.iter_mut().find(|r| r.id == run_id && r.tenant_id == tenant) else {
            return Ok(Delivered::NotFound);
        };
        if r.status != RunStatus::InputRequired || r.awaiting.as_deref() != Some(step) {
            return Ok(Delivered::NotAwaiting);
        }
        let now = Utc::now();
        r.status = RunStatus::Pending;
        r.wake_at = None;
        r.awaiting = None;
        r.prompt = None;
        r.updated_at = now;
        let key = (run_id.to_owned(), step.to_owned());
        t.events.entry(key).or_insert(EventRecord {
            run_id: run_id.into(),
            name: step.into(),
            kind: EventKind::Input,
            payload: Some(payload),
            created_at: now,
        });
        t.push_event(run_id, event::RUN_INPUT_RECEIVED, serde_json::json!({"step": step, "by": by}));
        t.push_audit(audit);
        Ok(Delivered::Accepted)
    }

    async fn start_step(&self, run_id: &str, worker: &str, data: serde_json::Value) -> JResult<StepStart> {
        let mut t = self.t.lock();
        let Some(r) = t.runs.iter().find(|r| r.id == run_id && holds(r, worker)) else {
            return Ok(StepStart::LeaseLost);
        };
        if r.cancel_requested_at.is_some() {
            return Ok(StepStart::Cancelled);
        }
        t.push_event(run_id, event::STEP_STARTED, data);
        Ok(StepStart::Started)
    }

    async fn cancel_requested(&self, run_id: &str) -> JResult<bool> {
        Ok(self.t.lock().runs.iter().any(|r| r.id == run_id && r.cancel_requested_at.is_some()))
    }

    async fn cancel(&self, tenant: &str, run_id: &str, by: &str, audit: Option<AuditEvent>) -> JResult<Cancelled> {
        let mut t = self.t.lock();
        let now = Utc::now();
        let Some(r) = t.runs.iter_mut().find(|r| r.id == run_id && r.tenant_id == tenant) else {
            return Ok(Cancelled::NotFound);
        };
        let out = match r.status {
            s if s.is_terminal() => return Ok(Cancelled::AlreadyEnded(s)),
            RunStatus::Running if r.cancel_requested_at.is_some() => return Ok(Cancelled::Requested),
            RunStatus::Running => {
                r.cancel_requested_at = Some(now);
                r.cancelled_by = Some(by.to_owned());
                r.updated_at = now;
                (Cancelled::Requested, event::RUN_CANCEL_REQUESTED, serde_json::json!({"by": by}))
            }
            _ => {
                let reason = format!("cancelled by {by}");
                r.status = RunStatus::Cancelled;
                r.cancel_requested_at = Some(now);
                r.cancelled_by = Some(by.to_owned());
                r.stop_reason = Some(reason.clone());
                r.wake_at = None;
                r.awaiting = None;
                r.prompt = None;
                r.updated_at = now;
                r.finished_at = Some(now);
                let data = finish_event(RunStatus::Cancelled, None, Some(&reason), r.budget.usd);
                (Cancelled::Ended, event::RUN_FINISHED, data)
            }
        };
        t.push_event(run_id, out.1, out.2);
        t.push_audit(audit);
        Ok(out.0)
    }

    async fn events(&self, tenant: &str, run_id: &str, after: u64, limit: usize) -> JResult<Vec<RunEvent>> {
        let t = self.t.lock();
        if !t.runs.iter().any(|r| r.id == run_id && r.tenant_id == tenant) {
            return Ok(Vec::new());
        }
        Ok(t.run_events
            .get(run_id)
            .map(|v| v.iter().filter(|e| e.seq > after).take(limit).cloned().collect())
            .unwrap_or_default())
    }

    async fn list_runs(&self, q: &RunQuery) -> JResult<Vec<RunRecord>> {
        let t = self.t.lock();
        let mut v: Vec<RunRecord> = t.runs.iter().filter(|r| q.matches(r)).cloned().collect();
        v.sort_by(|a, b| (b.created_at, &b.id).cmp(&(a.created_at, &a.id)));
        v.truncate(q.limit);
        Ok(v)
    }

    async fn claim_audit(&self, worker: &str, ttl: Duration, limit: usize) -> JResult<Vec<AuditEvent>> {
        self.claim_audit_where(worker, ttl, limit, |_| true)
    }

    async fn claim_audit_of(
        &self,
        worker: &str,
        ttl: Duration,
        limit: usize,
        actions: &[&str],
    ) -> JResult<Vec<AuditEvent>> {
        self.claim_audit_where(worker, ttl, limit, |a| actions.contains(&a.action.as_str()))
    }

    async fn ack_audit(&self, ids: &[String]) -> JResult<()> {
        self.t.lock().audit.retain(|(a, _)| !ids.contains(&a.id));
        Ok(())
    }
}

fn holds_eval(e: &EvalRecord, worker: &str) -> bool {
    e.status == EvalStatus::Running && e.lease_owner.as_deref() == Some(worker)
}

#[async_trait::async_trait]
impl EvalStore for MemoryJournal {
    async fn put_golden_set(&self, g: GoldenSetRecord, audit: Option<AuditEvent>) -> JResult<()> {
        let mut t = self.t.lock();
        let key = (g.tenant_id.clone(), g.node.clone(), g.version);
        t.golden.insert(key, GoldenSetRecord { updated_at: Utc::now(), ..g });
        t.push_audit(audit);
        Ok(())
    }

    async fn golden_set(&self, tenant: &str, node: &str, version: u32) -> JResult<Option<GoldenSetRecord>> {
        Ok(self.t.lock().golden.get(&(tenant.to_owned(), node.to_owned(), version)).cloned())
    }

    async fn golden_sets(&self, tenant: &str, node: &str) -> JResult<Vec<GoldenSetRecord>> {
        let t = self.t.lock();
        let mut v: Vec<GoldenSetRecord> =
            t.golden.values().filter(|g| g.tenant_id == tenant && g.node == node).cloned().collect();
        v.sort_by_key(|g| g.version);
        Ok(v)
    }

    async fn delete_golden_set(
        &self,
        tenant: &str,
        node: &str,
        version: u32,
        audit: Option<AuditEvent>,
    ) -> JResult<bool> {
        let mut t = self.t.lock();
        let gone = t.golden.remove(&(tenant.to_owned(), node.to_owned(), version)).is_some();
        if gone {
            t.push_audit(audit);
        }
        Ok(gone)
    }

    async fn put_eval_policy(&self, p: EvalPolicyRecord, audit: Option<AuditEvent>) -> JResult<()> {
        let mut t = self.t.lock();
        t.policies.insert((p.tenant_id.clone(), p.node.clone()), EvalPolicyRecord { updated_at: Utc::now(), ..p });
        t.push_audit(audit);
        Ok(())
    }

    async fn eval_policy(&self, tenant: &str, node: &str) -> JResult<Option<EvalPolicyRecord>> {
        Ok(self.t.lock().policies.get(&(tenant.to_owned(), node.to_owned())).cloned())
    }

    async fn create_eval(&self, e: NewEval, audit: Option<AuditEvent>) -> JResult<EvalRecord> {
        let mut t = self.t.lock();
        if t.evals.iter().any(|x| x.id == e.id) {
            return Err(JournalError(format!("eval {} already exists", e.id)));
        }
        let now = Utc::now();
        let rec = EvalRecord {
            id: e.id,
            tenant_id: e.tenant_id,
            node: e.node,
            version: e.version,
            spec_hash: e.spec_hash,
            suite: e.suite,
            k: e.k,
            concurrency: e.concurrency,
            created_by: e.created_by,
            api_key_id: e.api_key_id,
            invoker_key_hash: e.invoker_key_hash,
            plan: e.plan,
            case_count: e.case_count,
            status: EvalStatus::Pending,
            lease_owner: None,
            lease_expires_at: None,
            claims: 0,
            summary: None,
            error: None,
            cancel_requested_at: None,
            cancelled_by: None,
            created_at: now,
            updated_at: now,
            started_at: None,
            finished_at: None,
        };
        t.evals.push(rec.clone());
        t.push_audit(audit);
        Ok(rec)
    }

    async fn get_eval(&self, tenant: &str, id: &str) -> JResult<Option<EvalRecord>> {
        Ok(self.t.lock().evals.iter().find(|e| e.id == id && e.tenant_id == tenant).cloned())
    }

    async fn list_evals(&self, q: &EvalQuery) -> JResult<Vec<EvalRecord>> {
        let t = self.t.lock();
        let mut v: Vec<EvalRecord> = t.evals.iter().filter(|e| q.matches(e)).cloned().collect();
        v.sort_by(|a, b| (b.created_at, &b.id).cmp(&(a.created_at, &a.id)));
        v.truncate(q.limit);
        Ok(v)
    }

    async fn claim_eval(&self, worker: &str, ttl: Duration) -> JResult<Option<EvalRecord>> {
        let now = Utc::now();
        let mut t = self.t.lock();
        Ok(t.evals.iter_mut().find(|e| claimable(e, now)).map(|e| {
            e.status = EvalStatus::Running;
            e.lease_owner = Some(worker.to_owned());
            e.lease_expires_at = Some(lease_until(now, ttl));
            e.claims += 1;
            e.started_at.get_or_insert(now);
            e.updated_at = now;
            e.clone()
        }))
    }

    async fn heartbeat_eval(&self, id: &str, worker: &str, ttl: Duration) -> JResult<bool> {
        let now = Utc::now();
        let mut t = self.t.lock();
        Ok(match t.evals.iter_mut().find(|e| e.id == id && holds_eval(e, worker)) {
            Some(e) => {
                e.lease_expires_at = Some(lease_until(now, ttl));
                true
            }
            None => false,
        })
    }

    async fn cancel_eval(&self, tenant: &str, id: &str, by: &str, audit: Option<AuditEvent>) -> JResult<EvalCancel> {
        let mut t = self.t.lock();
        let now = Utc::now();
        let Some(e) = t.evals.iter_mut().find(|e| e.id == id && e.tenant_id == tenant) else {
            return Ok(EvalCancel::NotFound);
        };
        let out = match e.status {
            s if s.is_terminal() => return Ok(EvalCancel::AlreadyEnded(s)),
            EvalStatus::Running if e.cancel_requested_at.is_some() => return Ok(EvalCancel::Requested),
            EvalStatus::Running => {
                e.cancel_requested_at = Some(now);
                e.cancelled_by = Some(by.to_owned());
                e.updated_at = now;
                EvalCancel::Requested
            }
            _ => {
                e.status = EvalStatus::Cancelled;
                e.cancel_requested_at = Some(now);
                e.cancelled_by = Some(by.to_owned());
                e.updated_at = now;
                e.finished_at = Some(now);
                EvalCancel::Ended
            }
        };
        t.push_audit(audit);
        Ok(out)
    }

    async fn finish_eval(&self, id: &str, worker: &str, f: EvalFinish, audit: Option<AuditEvent>) -> JResult<bool> {
        bad_finish(&f)?;
        let mut t = self.t.lock();
        let ok = match t.evals.iter_mut().find(|e| e.id == id && holds_eval(e, worker)) {
            Some(e) => {
                let now = Utc::now();
                e.status = f.status;
                e.summary = f.summary;
                e.error = f.error;
                e.lease_owner = None;
                e.lease_expires_at = None;
                e.updated_at = now;
                e.finished_at = Some(now);
                true
            }
            None => false,
        };
        if ok {
            t.push_audit(audit);
        }
        Ok(ok)
    }

    async fn put_trial(&self, worker: &str, tr: TrialRecord) -> JResult<TrialWrite> {
        let mut t = self.t.lock();
        if !t.evals.iter().any(|e| e.id == tr.eval_id && holds_eval(e, worker)) {
            return Ok(TrialWrite::LeaseLost);
        }
        let list = t.trials.entry(tr.eval_id.clone()).or_default();
        match list.iter_mut().find(|x| x.case_id == tr.case_id && x.trial == tr.trial) {
            Some(x) if x.status.is_final() => Ok(TrialWrite::Existing(Box::new(x.clone()))),
            Some(x) => {
                let created_at = x.created_at;
                *x = TrialRecord { created_at, finished_at: tr.status.is_final().then(Utc::now), ..tr };
                Ok(TrialWrite::Written)
            }
            None => {
                let now = Utc::now();
                list.push(TrialRecord { created_at: now, finished_at: tr.status.is_final().then_some(now), ..tr });
                Ok(TrialWrite::Written)
            }
        }
    }

    async fn trials(&self, eval_id: &str) -> JResult<Vec<TrialRecord>> {
        let mut v = self.t.lock().trials.get(eval_id).cloned().unwrap_or_default();
        v.sort_by(|a, b| (&a.case_id, a.trial).cmp(&(&b.case_id, b.trial)));
        Ok(v)
    }

    async fn purge_eval_content(&self, older_than: Duration, batch: usize) -> JResult<u64> {
        let cutoff = Utc::now() - lease(older_than);
        let mut t = self.t.lock();
        let mut n = 0u64;
        for tr in t.trials.values_mut().flatten() {
            if n as usize >= batch {
                break;
            }
            if tr.detail.is_some() && tr.finished_at.is_some_and(|f| f < cutoff) {
                tr.detail = None;
                n += 1;
            }
        }
        let mut m = 0usize;
        for e in t.evals.iter_mut() {
            if m >= batch {
                break;
            }
            if e.status.is_terminal() && !e.plan.is_empty() && e.finished_at.is_some_and(|f| f < cutoff) {
                e.plan.clear();
                m += 1;
            }
        }
        Ok(n + m as u64)
    }
}
