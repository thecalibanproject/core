//! Evals in the journal (`migrations/0024_node_evals.sql`): golden sets, promotion bars, eval runs
//! and their trials. Same two implementations as the run journal (memory and Postgres), checked
//! by the same parity suite.
//!
//! - **Golden sets and promotion bars** are written by the control plane (admin API), each write
//!   with its audit event in the outbox, in the same transaction.
//! - **Eval runs** are created by the control plane (`pending`, with a sealed plan) and executed by
//!   workers: a worker claims one ([`EvalStore::claim_eval`], `FOR UPDATE SKIP LOCKED` on
//!   Postgres) under a lease it renews, like a run. Every write a worker makes for an eval (trials,
//!   the end) is fenced by that lease, so a worker that lost an eval records nothing; the worker
//!   that takes it over finds the trials already recorded and the node runs already created
//!   (their `Idempotency-Key` is derived from the eval, the case and the trial).
//! - **Trials** are written once they are final (first final write wins).
//!
//! Sealed values (golden-set cases, eval plans, trial details) are opaque strings here, like run
//! content: the caller seals them with the tenant's data key.

use super::{AuditEvent, JResult, JournalError, lease};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// What an eval measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Suite {
    /// The version's golden set, `k` runs per case: pass^k, cost per success, p95 latency.
    Golden,
    /// The built-in prompt-injection suite, against sandboxed tools: how many attacks were blocked.
    Injection,
}

impl Suite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Golden => "golden",
            Self::Injection => "injection",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "golden" => Some(Self::Golden),
            "injection" => Some(Self::Injection),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalStatus {
    Pending,
    Running,
    /// Every trial was run and scored (whatever the scores): `summary` holds the metrics.
    Succeeded,
    /// The eval could not be completed (`error` says why).
    Failed,
    Cancelled,
}

impl EvalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "pending" => Self::Pending,
            "running" => Self::Running,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

/// The golden set of one node version.
#[derive(Debug, Clone, PartialEq)]
pub struct GoldenSetRecord {
    pub tenant_id: String,
    pub node: String,
    pub version: u32,
    /// Sealed (the cases, as JSON), with [`golden_context`] as the sealer's context.
    pub cases: String,
    pub case_count: u32,
    /// `sha256:<hex>` of the cases' canonical JSON: which golden set an eval ran.
    pub hash: String,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
}

/// The sealing context of a golden set (the sealer's "run id"): a set cannot be moved to another
/// version or node.
pub fn golden_context(node: &str, version: u32) -> String {
    format!("golden/{node}@v{version}")
}

/// The promotion bar of a node.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalPolicyRecord {
    pub tenant_id: String,
    pub node: String,
    /// [`crate::eval::EvalPolicy`] as JSON.
    pub policy: serde_json::Value,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
}

/// An eval run to create.
#[derive(Debug, Clone, PartialEq)]
pub struct NewEval {
    pub id: String,
    pub tenant_id: String,
    pub node: String,
    pub version: u32,
    pub spec_hash: String,
    pub suite: Suite,
    /// Runs per case.
    pub k: u32,
    /// Trials in flight at once.
    pub concurrency: u32,
    /// Who started it (the audit actor).
    pub created_by: String,
    pub api_key_id: Option<String>,
    /// The API key its node runs and judge calls are made as.
    pub invoker_key_hash: String,
    /// Sealed ([`crate::eval::Plan`] as JSON), with the eval id as the sealer's context.
    pub plan: String,
    pub case_count: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvalRecord {
    pub id: String,
    pub tenant_id: String,
    pub node: String,
    pub version: u32,
    pub spec_hash: String,
    pub suite: Suite,
    pub k: u32,
    pub concurrency: u32,
    pub created_by: String,
    pub api_key_id: Option<String>,
    pub invoker_key_hash: String,
    pub plan: String,
    pub case_count: u32,
    pub status: EvalStatus,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub claims: u32,
    /// The metrics of a finished eval (never content).
    pub summary: Option<serde_json::Value>,
    pub error: Option<String>,
    pub cancel_requested_at: Option<DateTime<Utc>>,
    pub cancelled_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// How an eval ends.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalFinish {
    /// `Succeeded`, `Failed` or `Cancelled`.
    pub status: EvalStatus,
    pub summary: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialStatus {
    /// Its node run was created and has not been scored yet.
    Running,
    Passed,
    Failed,
    /// The trial could not be scored (its run could not be created, a judge call failed): it
    /// counts as not passed.
    Error,
}

impl TrialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "running" => Self::Running,
            "passed" => Self::Passed,
            "failed" => Self::Failed,
            "error" => Self::Error,
            _ => return None,
        })
    }

    pub fn is_final(self) -> bool {
        self != Self::Running
    }
}

/// One case run once.
#[derive(Debug, Clone, PartialEq)]
pub struct TrialRecord {
    pub eval_id: String,
    pub tenant_id: String,
    pub case_id: String,
    /// 0 to k - 1.
    pub trial: u32,
    pub run_id: Option<String>,
    pub status: TrialStatus,
    /// What the node run spent (USD, priced like the metering).
    pub cost_usd: f64,
    /// The run's execution time (its wall clock: not time spent queued or waiting for a human).
    pub latency_ms: u64,
    pub tokens: u64,
    /// Metadata of the verdict: which checks passed, the attack outcome, the defenses that held.
    /// Never content.
    pub verdict: serde_json::Value,
    /// Sealed, with the eval id as the sealer's context: what the scorers said (reasons, the
    /// judge's answer, the output when it failed a check).
    pub detail: Option<String>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// Result of [`EvalStore::put_trial`].
#[derive(Debug, Clone, PartialEq)]
pub enum TrialWrite {
    Written,
    /// The trial is final already: this is the recorded one.
    Existing(Box<TrialRecord>),
    /// The worker no longer holds the eval's lease: it must stop.
    LeaseLost,
}

/// Result of [`EvalStore::cancel_eval`].
#[derive(Debug, Clone, PartialEq)]
pub enum EvalCancel {
    /// It was pending: it is `cancelled` now.
    Ended,
    /// It is running: its worker stops (and cancels its node runs) at its next check.
    Requested,
    AlreadyEnded(EvalStatus),
    NotFound,
}

/// What [`EvalStore::list_evals`] returns, newest first.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EvalQuery {
    pub tenant: String,
    pub node: Option<String>,
    pub version: Option<u32>,
    pub suite: Option<Suite>,
    pub statuses: Vec<EvalStatus>,
    /// Evals strictly older than this `(created_at, id)`.
    pub before: Option<(DateTime<Utc>, String)>,
    pub limit: usize,
}

impl EvalQuery {
    pub fn matches(&self, e: &EvalRecord) -> bool {
        e.tenant_id == self.tenant
            && self.node.as_ref().is_none_or(|n| *n == e.node)
            && self.version.is_none_or(|v| v == e.version)
            && self.suite.is_none_or(|s| s == e.suite)
            && (self.statuses.is_empty() || self.statuses.contains(&e.status))
            && self.before.as_ref().is_none_or(|(t, id)| (e.created_at, e.id.as_str()) < (*t, id.as_str()))
    }
}

/// The claim rule of evals (shared with the Postgres query): pending, or running with an expired
/// lease (its worker died).
pub(crate) fn claimable(e: &EvalRecord, now: DateTime<Utc>) -> bool {
    match e.status {
        EvalStatus::Pending => true,
        EvalStatus::Running => e.lease_expires_at.is_none_or(|x| x < now),
        _ => false,
    }
}

pub(crate) fn lease_until(now: DateTime<Utc>, ttl: Duration) -> DateTime<Utc> {
    now + lease(ttl)
}

pub(crate) fn bad_finish(f: &EvalFinish) -> JResult<()> {
    if f.status.is_terminal() {
        Ok(())
    } else {
        Err(JournalError(format!("cannot finish an eval as {}", f.status.as_str())))
    }
}

/// Golden sets, promotion bars, eval runs and trials. Every [`super::Journal`] implements it.
#[async_trait::async_trait]
pub trait EvalStore: Send + Sync {
    /// Creates or replaces the golden set of a version; `audit` is recorded with it.
    async fn put_golden_set(&self, g: GoldenSetRecord, audit: Option<AuditEvent>) -> JResult<()>;
    async fn golden_set(&self, tenant: &str, node: &str, version: u32) -> JResult<Option<GoldenSetRecord>>;
    /// The golden sets of a node's versions, by version.
    async fn golden_sets(&self, tenant: &str, node: &str) -> JResult<Vec<GoldenSetRecord>>;
    /// Whether there was one to delete.
    async fn delete_golden_set(
        &self,
        tenant: &str,
        node: &str,
        version: u32,
        audit: Option<AuditEvent>,
    ) -> JResult<bool>;

    async fn put_eval_policy(&self, p: EvalPolicyRecord, audit: Option<AuditEvent>) -> JResult<()>;
    async fn eval_policy(&self, tenant: &str, node: &str) -> JResult<Option<EvalPolicyRecord>>;

    /// Creates an eval in `pending`; `audit` is recorded with it.
    async fn create_eval(&self, e: NewEval, audit: Option<AuditEvent>) -> JResult<EvalRecord>;
    async fn get_eval(&self, tenant: &str, id: &str) -> JResult<Option<EvalRecord>>;
    /// Newest first (`created_at`, then `id`, descending).
    async fn list_evals(&self, q: &EvalQuery) -> JResult<Vec<EvalRecord>>;
    /// Claims the oldest claimable eval for `worker`, under a lease of `ttl`.
    async fn claim_eval(&self, worker: &str, ttl: Duration) -> JResult<Option<EvalRecord>>;
    /// Renews the lease. `false`: the worker no longer holds the eval.
    async fn heartbeat_eval(&self, id: &str, worker: &str, ttl: Duration) -> JResult<bool>;
    /// Cancels an eval of `tenant` (see [`EvalCancel`]); `audit` is recorded with it.
    async fn cancel_eval(&self, tenant: &str, id: &str, by: &str, audit: Option<AuditEvent>) -> JResult<EvalCancel>;
    /// Ends the eval, fenced by the lease; `audit` is recorded with it.
    async fn finish_eval(&self, id: &str, worker: &str, f: EvalFinish, audit: Option<AuditEvent>) -> JResult<bool>;

    /// Records a trial, fenced by the eval's lease: inserted, or updated while it is not final.
    async fn put_trial(&self, worker: &str, t: TrialRecord) -> JResult<TrialWrite>;
    /// The eval's trials, by case then trial.
    async fn trials(&self, eval_id: &str) -> JResult<Vec<TrialRecord>>;
}
