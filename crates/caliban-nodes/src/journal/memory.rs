//! In-memory journal: standalone mode without a database, and tests. Same behaviour as
//! [`super::postgres::PgJournal`] (the parity suite runs against both); everything is lost when
//! the process stops.

use super::*;
use parking_lot::Mutex;
use std::collections::HashMap;

#[derive(Default)]
struct Tables {
    /// In creation order.
    runs: Vec<RunRecord>,
    steps: HashMap<String, Vec<StepRecord>>,
    events: HashMap<(String, String), EventRecord>,
}

#[derive(Default)]
pub struct MemoryJournal {
    t: Mutex<Tables>,
}

impl MemoryJournal {
    pub fn new() -> Self {
        Self::default()
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
        };
        t.runs.push(rec.clone());
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
        let steps = t.steps.entry(step.run_id.clone()).or_default();
        if let Some(existing) = steps.iter().find(|s| s.step_id == step.step_id) {
            return Ok(StepWrite::Existing(Box::new(existing.clone())));
        }
        steps.push(step);
        Ok(StepWrite::Written)
    }

    async fn suspend(&self, run_id: &str, worker: &str, s: Suspend) -> JResult<bool> {
        if !matches!(s.status, RunStatus::Sleeping | RunStatus::InputRequired) {
            return Err(JournalError(format!("cannot suspend a run as {}", s.status.as_str())));
        }
        let mut t = self.t.lock();
        Ok(match t.runs.iter_mut().find(|r| r.id == run_id && holds(r, worker)) {
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
        })
    }

    async fn finish(&self, run_id: &str, worker: &str, f: Finish) -> JResult<bool> {
        if !f.status.is_terminal() {
            return Err(JournalError(format!("cannot finish a run as {}", f.status.as_str())));
        }
        let mut t = self.t.lock();
        Ok(match t.runs.iter_mut().find(|r| r.id == run_id && holds(r, worker)) {
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
        })
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

    async fn deliver_input(&self, tenant: &str, run_id: &str, step: &str, payload: String) -> JResult<Delivered> {
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
        Ok(Delivered::Accepted)
    }
}
