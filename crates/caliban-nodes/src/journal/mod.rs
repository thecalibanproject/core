//! The durable run journal (decided: a minimal Postgres journal following the Absurd model).
//!
//! One schema (`migrations/0013_node_journal.sql`): `node_run` (one row per run, with its status,
//! budget and lease), `node_step` (one row per checkpointed step), `node_event` (awaited events:
//! human answers and timers). Two implementations with the same behaviour, checked by one parity
//! suite (`tests.rs`): [`memory::MemoryJournal`] (standalone without a database, tests) and
//! [`postgres::PgJournal`].
//!
//! How workers use it:
//! - **Claim.** A worker claims a runnable run ([`Journal::claim_next`], `FOR UPDATE SKIP LOCKED`
//!   on Postgres, so two workers never claim the same run) and holds it under a lease it renews
//!   ([`Journal::heartbeat`]). Runnable: `pending`; `sleeping` or `input_required` whose `wake_at`
//!   has passed; `running` whose lease expired (its worker died: another one takes over).
//! - **Checkpoint.** Every completed step is written once ([`Journal::put_step`]); a write is
//!   fenced by the lease, so a worker that lost its run cannot record anything for it. Replay
//!   reads these rows and never runs a recorded step again.
//! - **Suspend.** A run waiting for a human or a timer releases its lease ([`Journal::suspend`]);
//!   [`Journal::deliver_input`] records the answer and makes it runnable again.
//!
//! Payloads are opaque strings here: the executor seals them with the tenant's data key before
//! they reach the journal ([`crate::seal`]).

pub mod memory;
pub mod postgres;
#[cfg(test)]
pub(crate) mod tests;

use crate::budget::BudgetState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Waiting for a worker.
    Pending,
    /// Claimed by a worker (`lease_owner`).
    Running,
    /// Durable sleep until `wake_at`.
    Sleeping,
    /// Waiting for a human answer (`awaiting`); also woken at `wake_at` when the step has a timeout.
    InputRequired,
    Succeeded,
    Failed,
    /// Ended gracefully on a budget overrun, with partial results and a reason.
    BudgetExhausted,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Sleeping => "sleeping",
            Self::InputRequired => "input_required",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::BudgetExhausted => "budget_exhausted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "sleeping" => Self::Sleeping,
            "input_required" => Self::InputRequired,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "budget_exhausted" => Self::BudgetExhausted,
            _ => return None,
        })
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::BudgetExhausted)
    }
}

/// A run to create.
#[derive(Debug, Clone, PartialEq)]
pub struct NewRun {
    pub id: String,
    pub tenant_id: String,
    pub node: String,
    pub version: u32,
    pub spec_hash: String,
    pub invoker: String,
    pub invoker_key_hash: Option<String>,
    /// Sealed.
    pub input: String,
    pub budget: BudgetState,
    /// `Idempotency-Key` of the creating request and the request's fingerprint.
    pub idempotency: Option<(String, String)>,
    /// Sealed: the specs of the run's version and of every version it can reach (`node://`), so a
    /// run finishes on what it started on even if a version is retired meanwhile.
    pub specs: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunRecord {
    pub id: String,
    pub tenant_id: String,
    pub node: String,
    pub version: u32,
    pub spec_hash: String,
    pub invoker: String,
    pub invoker_key_hash: Option<String>,
    /// Sealed.
    pub input: String,
    /// Sealed: the node versions the run started on (see [`NewRun::specs`]).
    pub specs: Option<String>,
    /// Sealed.
    pub output: Option<String>,
    pub status: RunStatus,
    pub wake_at: Option<DateTime<Utc>>,
    pub awaiting: Option<String>,
    /// Sealed question of the human step the run waits for.
    pub prompt: Option<String>,
    pub budget: BudgetState,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    /// How many times a worker claimed the run.
    pub claims: u32,
    pub error: Option<String>,
    pub stop_reason: Option<String>,
    pub idempotency_key: Option<String>,
    pub idempotency_fingerprint: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StepRecord {
    pub run_id: String,
    pub tenant_id: String,
    /// Deterministic: the same step of a replayed run has the same id.
    pub step_id: String,
    pub attempt: u32,
    pub vertex: String,
    pub kind: String,
    /// Hash of the step's input, checked on replay (a mismatch means the run diverged).
    pub input_hash: String,
    pub status: StepStatus,
    /// Sealed.
    pub result: Option<String>,
    pub tokens: u64,
    pub usd: f64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Input,
    Timer,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Timer => "timer",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EventRecord {
    pub run_id: String,
    pub name: String,
    pub kind: EventKind,
    /// Sealed (input), or an RFC 3339 deadline (timer).
    pub payload: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Result of [`Journal::create_run`].
#[derive(Debug, Clone, PartialEq)]
pub enum Created {
    New(RunRecord),
    /// Same tenant and `Idempotency-Key`, same request: the run created the first time.
    Existing(RunRecord),
    /// Same tenant and `Idempotency-Key`, different request.
    KeyReused,
}

/// Result of [`Journal::put_step`].
#[derive(Debug, Clone, PartialEq)]
pub enum StepWrite {
    Written,
    /// The step was recorded before (by this run's earlier attempt); this is the recorded one.
    Existing(Box<StepRecord>),
    /// The worker no longer holds the run's lease: it must stop.
    LeaseLost,
}

/// How a run gives up its lease while it waits.
#[derive(Debug, Clone, PartialEq)]
pub struct Suspend {
    /// `Sleeping` or `InputRequired`.
    pub status: RunStatus,
    pub awaiting: Option<String>,
    /// Sealed question.
    pub prompt: Option<String>,
    pub wake_at: Option<DateTime<Utc>>,
    pub budget: BudgetState,
}

/// How a run ends.
#[derive(Debug, Clone, PartialEq)]
pub struct Finish {
    /// `Succeeded`, `Failed` or `BudgetExhausted`.
    pub status: RunStatus,
    /// Sealed.
    pub output: Option<String>,
    pub error: Option<String>,
    pub stop_reason: Option<String>,
    pub budget: BudgetState,
}

/// Result of [`Journal::deliver_input`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    /// Recorded; the run is runnable again.
    Accepted,
    /// The run is not waiting for input (or not for this step).
    NotAwaiting,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("journal: {0}")]
pub struct JournalError(pub String);

pub type JResult<T> = Result<T, JournalError>;

#[async_trait::async_trait]
pub trait Journal: Send + Sync {
    fn name(&self) -> &'static str;

    /// Creates a run in `pending`, or returns the run an earlier request with the same
    /// `Idempotency-Key` created.
    async fn create_run(&self, run: NewRun) -> JResult<Created>;
    /// The run, if it belongs to `tenant`.
    async fn get_run(&self, tenant: &str, id: &str) -> JResult<Option<RunRecord>>;
    /// The run's checkpointed steps, in the order they were written.
    async fn steps(&self, run_id: &str) -> JResult<Vec<StepRecord>>;

    /// Claims the oldest runnable run for `worker`, under a lease of `ttl`.
    async fn claim_next(&self, worker: &str, ttl: Duration) -> JResult<Option<RunRecord>>;
    /// Claims this run if it is runnable.
    async fn claim(&self, run_id: &str, worker: &str, ttl: Duration) -> JResult<Option<RunRecord>>;
    /// Renews the lease. `false`: the worker no longer holds the run.
    async fn heartbeat(&self, run_id: &str, worker: &str, ttl: Duration) -> JResult<bool>;
    /// Gives the run back (`pending`) without finishing it, e.g. on shutdown.
    async fn release(&self, run_id: &str, worker: &str) -> JResult<bool>;

    /// Checkpoints a step (first write wins) and the run's budget, fenced by the lease.
    async fn put_step(&self, worker: &str, step: StepRecord, budget: &BudgetState) -> JResult<StepWrite>;
    async fn suspend(&self, run_id: &str, worker: &str, s: Suspend) -> JResult<bool>;
    async fn finish(&self, run_id: &str, worker: &str, f: Finish) -> JResult<bool>;

    async fn event(&self, run_id: &str, name: &str) -> JResult<Option<EventRecord>>;
    /// Records an event once (first write wins). Returns whether this call wrote it.
    async fn put_event(
        &self,
        tenant: &str,
        run_id: &str,
        name: &str,
        kind: EventKind,
        payload: Option<String>,
    ) -> JResult<bool>;
    /// Records the answer to the human step `step` of a run waiting for it, and makes the run
    /// runnable again.
    async fn deliver_input(&self, tenant: &str, run_id: &str, step: &str, payload: String) -> JResult<Delivered>;
}

fn lease(ttl: Duration) -> chrono::Duration {
    chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(30))
}
