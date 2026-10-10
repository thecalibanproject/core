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
//! - **Events.** Every change a client can watch is also an event row (`node_run_event`, numbered
//!   per run in commit order: the run row's `event_seq` is incremented under the row lock): the run
//!   created, a step started and finished, the run waiting for input or a timer, an answer, a
//!   cancellation, the end. Run event streams (`GET /v1/runs/{id}/events`) read them, so a client
//!   can resume on any worker with `Last-Event-ID`. Event data holds no sealed content except the
//!   sealed question of `run.input_required` (opened by the reader, for callers that may see it).
//! - **Cancel.** [`Journal::cancel`] ends a run that waits (pending, sleeping, input required) at
//!   once, and asks a running one to stop: its worker sees the request at its next step boundary
//!   ([`Journal::start_step`]).
//! - **Audit outbox.** Human answers and cancellations write an [`AuditEvent`] in the same
//!   transaction; every worker ships them to the control plane's hash-chained audit log
//!   ([`Journal::claim_audit`], [`Journal::ack_audit`]), which deduplicates by the event's id.
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
    /// Stopped by a cancellation (at once while it waited, else at its next step boundary).
    Cancelled,
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
            Self::Cancelled => "cancelled",
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
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::BudgetExhausted | Self::Cancelled)
    }

    pub const ALL: [RunStatus; 8] = [
        Self::Pending,
        Self::Running,
        Self::Sleeping,
        Self::InputRequired,
        Self::Succeeded,
        Self::Failed,
        Self::BudgetExhausted,
        Self::Cancelled,
    ];
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
    /// What started the run when it was not a direct run request (e.g. `auto:<intent>` when
    /// `caliban/auto` handed a chat request to the node). Its model calls' usage events say so.
    pub origin: Option<String>,
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
    /// A cancellation was asked for (a running run stops at its next step boundary).
    pub cancel_requested_at: Option<DateTime<Utc>>,
    /// Who cancelled the run.
    pub cancelled_by: Option<String>,
    /// See [`NewRun::origin`].
    pub origin: Option<String>,
    /// The number of the run's last event (0: none yet).
    pub last_event: u64,
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
    /// Prompt and completion tokens of a model step (their sum is `tokens`); 0 for other steps.
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub usd: f64,
    /// Taint labels of the step's output (what it consumed, plus a tool's own label).
    pub labels: Vec<String>,
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

/// What a tenant's node runs spent on model calls (USD), in the current UTC day and month.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct TenantSpend {
    pub today_usd: f64,
    pub month_usd: f64,
}

/// Kinds of run events (`node_run_event.kind`).
pub mod event {
    pub const RUN_CREATED: &str = "run.created";
    pub const STEP_STARTED: &str = "step.started";
    pub const STEP_FINISHED: &str = "step.finished";
    pub const RUN_INPUT_REQUIRED: &str = "run.input_required";
    pub const RUN_SLEEPING: &str = "run.sleeping";
    pub const RUN_INPUT_RECEIVED: &str = "run.input_received";
    pub const RUN_CANCEL_REQUESTED: &str = "run.cancel_requested";
    pub const RUN_FINISHED: &str = "run.finished";
}

/// One event of a run, numbered from 1 in the order the journal committed them.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunEvent {
    pub run_id: String,
    pub seq: u64,
    pub kind: String,
    pub data: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// The event data of a checkpointed step (also what `step.started` carries, without results).
pub fn step_event(s: &StepRecord, cost_usd: f64) -> serde_json::Value {
    serde_json::json!({
        "step": s.step_id,
        "vertex": s.vertex,
        "kind": s.kind,
        "status": s.status,
        "tokens": s.tokens,
        "prompt_tokens": s.prompt_tokens,
        "completion_tokens": s.completion_tokens,
        "usd": s.usd,
        "cost_usd": cost_usd,
        "labels": s.labels,
        "duration_ms": (s.finished_at - s.started_at).num_milliseconds(),
    })
}

fn suspend_event(s: &Suspend) -> (&'static str, serde_json::Value) {
    match s.status {
        RunStatus::InputRequired => (
            event::RUN_INPUT_REQUIRED,
            serde_json::json!({"step": s.awaiting, "sealed_question": s.prompt, "wake_at": s.wake_at, "cost_usd": s.budget.usd}),
        ),
        _ => (event::RUN_SLEEPING, serde_json::json!({"wake_at": s.wake_at, "cost_usd": s.budget.usd})),
    }
}

fn finish_event(status: RunStatus, error: Option<&str>, stop_reason: Option<&str>, usd: f64) -> serde_json::Value {
    serde_json::json!({"status": status, "error": error, "stop_reason": stop_reason, "cost_usd": usd})
}

/// Result of [`Journal::start_step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStart {
    Started,
    /// The run was cancelled: stop here.
    Cancelled,
    LeaseLost,
}

/// Result of [`Journal::cancel`].
#[derive(Debug, Clone, PartialEq)]
pub enum Cancelled {
    /// The run was waiting (pending, sleeping, input required): it is `cancelled` now.
    Ended,
    /// The run is executing: its worker stops at the next step boundary (also when asked before).
    Requested,
    /// The run had already ended, with this status.
    AlreadyEnded(RunStatus),
    NotFound,
}

/// An entry for the control plane's audit log, written by the data plane in the transaction of
/// what it records (the outbox) and shipped at least once. `id` is stable (the same decision always
/// has the same id), so the control plane records it once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub tenant_id: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    /// Never secrets or run content.
    pub detail: serde_json::Value,
    pub at: DateTime<Utc>,
}

/// What [`Journal::list_runs`] returns, newest first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunQuery {
    pub tenant: String,
    /// Only these nodes (an API key's allowlist); `None`: all.
    pub nodes: Option<Vec<String>>,
    pub node: Option<String>,
    pub statuses: Vec<RunStatus>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
    /// Runs strictly older than this `(created_at, id)` (the cursor of the previous page).
    pub before: Option<(DateTime<Utc>, String)>,
    pub limit: usize,
}

impl RunQuery {
    pub fn matches(&self, r: &RunRecord) -> bool {
        r.tenant_id == self.tenant
            && self.nodes.as_ref().is_none_or(|n| n.contains(&r.node))
            && self.node.as_ref().is_none_or(|n| *n == r.node)
            && (self.statuses.is_empty() || self.statuses.contains(&r.status))
            && self.created_after.is_none_or(|t| r.created_at >= t)
            && self.created_before.is_none_or(|t| r.created_at < t)
            && self.before.as_ref().is_none_or(|(t, id)| (r.created_at, r.id.as_str()) < (*t, id.as_str()))
    }
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

    /// Checkpoints a step (first write wins) and the run's budget, fenced by the lease. A step
    /// written for the first time adds its cost to its tenant's spend of the day.
    async fn put_step(&self, worker: &str, step: StepRecord, budget: &BudgetState) -> JResult<StepWrite>;
    /// Suspends the run (event `run.input_required` or `run.sleeping`). `false` when the worker
    /// lost the lease, or a cancellation was asked for (the caller then finishes it as cancelled).
    async fn suspend(&self, run_id: &str, worker: &str, s: Suspend) -> JResult<bool>;
    /// Ends the run (event `run.finished`).
    async fn finish(&self, run_id: &str, worker: &str, f: Finish) -> JResult<bool>;
    /// Before a new step runs: records `step.started` (data: step, vertex, kind, labels), fenced
    /// by the lease, unless the run was cancelled.
    async fn start_step(&self, run_id: &str, worker: &str, data: serde_json::Value) -> JResult<StepStart>;
    /// Whether a cancellation was asked for (cheap; checked before a model call is retried).
    async fn cancel_requested(&self, run_id: &str) -> JResult<bool>;
    /// Cancels a run of `tenant` (see [`Cancelled`]); `audit` is recorded with it.
    async fn cancel(&self, tenant: &str, run_id: &str, by: &str, audit: Option<AuditEvent>) -> JResult<Cancelled>;
    /// The run's events after `after`, in order, at most `limit`.
    async fn events(&self, tenant: &str, run_id: &str, after: u64, limit: usize) -> JResult<Vec<RunEvent>>;
    /// Runs matching the query, newest first (`created_at`, then `id`, descending).
    async fn list_runs(&self, q: &RunQuery) -> JResult<Vec<RunRecord>>;
    /// Takes up to `limit` audit events not yet shipped and not taken by another worker in the
    /// last `ttl`.
    async fn claim_audit(&self, worker: &str, ttl: Duration, limit: usize) -> JResult<Vec<AuditEvent>>;
    /// The control plane stored these: they leave the outbox.
    async fn ack_audit(&self, ids: &[String]) -> JResult<()>;

    /// Retention: deletes runs that finished more than `older_than` ago, with their steps and
    /// events, at most `batch` per call (call again while it returns `batch`). Safe on several
    /// workers at once. Returns how many runs were deleted.
    async fn purge_finished(&self, older_than: Duration, batch: usize) -> JResult<u64>;

    /// The tenant's node spend today and this month (UTC), across every worker.
    async fn tenant_spend(&self, tenant: &str) -> JResult<TenantSpend>;

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
    /// Records the answer to the human step `step` of a run waiting for it (event
    /// `run.input_received` with `by`), and makes the run runnable again. `audit` is recorded in
    /// the same transaction.
    async fn deliver_input(
        &self,
        tenant: &str,
        run_id: &str,
        step: &str,
        payload: String,
        by: Option<&str>,
        audit: Option<AuditEvent>,
    ) -> JResult<Delivered>;
}

fn lease(ttl: Duration) -> chrono::Duration {
    chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(30))
}
