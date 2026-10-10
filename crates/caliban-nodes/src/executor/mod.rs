//! The node executor (tokio): runs workflow graphs and bounded agent loops, checkpointing every
//! step in the [`Journal`], and replays recorded steps instead of running them again.
//!
//! **Replay.** A worker that claims a run (new, woken, or taken over after another worker died)
//! loads its recorded steps and runs the node from the start. Execution is deterministic given the
//! recorded results: each step has a deterministic id (`classify#0`, `fanout#0/3`, `agent#2.0`), and
//! a step found in the journal returns its recorded result (and re-charges its recorded tokens)
//! without calling anything. Only steps not yet recorded run. A recorded step whose input hash no
//! longer matches stops the run (the journal and the node diverged).
//!
//! **Side effects.** Model calls carry an `Idempotency-Key` derived from (run id, step id), so a
//! step that ran but was not checkpointed before its worker died gets the stored response when it
//! is replayed instead of paying twice ([`ModelClient`]). Tool calls get the same key
//! ([`ToolCtx::idempotency_key`]).
//!
//! **Steps** are vertex executions that call something (a model, a tool, a human). Pure transforms
//! (`reduce` concat or merge, `verify` against a schema) are recomputed on replay and not
//! journaled. Each step costs one step of the budget plus its tokens; the run's wall clock counts
//! execution time only (not time spent waiting for a human or a timer).

mod agent;
pub mod breaker;
mod graph;
pub mod taint;
pub mod template;
pub mod tools;

pub use tools::{DataGuard, FnTool, NoGuard, NoTools, StaticTools, Tool, ToolCtx, ToolError, ToolInfo, ToolRegistry};

use crate::budget::{BudgetError, BudgetState, Ledger};
use crate::journal::{
    AuditEvent, Cancelled, Created, Delivered, EventKind, Finish, Journal, NewRun, RunEvent, RunQuery, RunRecord,
    RunStatus, StepRecord, StepStart, StepStatus, StepWrite, Suspend,
};
use crate::seal::Sealer;
use crate::{NodeKind, NodeSpec};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

tokio::task_local! {
    /// Taint labels of what the step being built consumes (set around each vertex, tool call and
    /// agent turn), so a checkpoint records its output's labels.
    static CONSUMED: taint::Taint;
}

/// The labels in scope (see [`CONSUMED`]).
fn consumed() -> taint::Taint {
    CONSUMED.try_with(Clone::clone).unwrap_or_default()
}

/// Runs `f` with `t` as the labels of what it consumes.
pub(crate) async fn consuming<F: std::future::Future>(t: taint::Taint, f: F) -> F::Output {
    CONSUMED.scope(t, f).await
}

// ───────────────────────────── what the executor needs ─────────────────────────────

/// Who and what a model call is for.
#[derive(Debug, Clone)]
pub struct CallCtx {
    pub tenant: String,
    /// The invoking API key's hash: the call is authorized, rate-limited and metered as that key.
    pub invoker_key_hash: Option<String>,
    pub run_id: String,
    /// The run's node and version (a subnode's calls are the run's: they carry the root node).
    pub node: String,
    pub node_version: u32,
    pub step_id: String,
    /// Derived from (run id, step id): the same for every attempt of the step.
    pub idempotency_key: String,
    /// What started the run (`auto:<intent>`), if not a run request.
    pub origin: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ModelReply {
    /// The assistant message (OpenAI Chat Completions shape: `content`, `tool_calls`).
    pub message: Value,
    /// Prompt and completion tokens.
    pub tokens: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub usd: f64,
    /// The response was a stored one (an `Idempotency-Key` replay): nothing was paid again.
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ModelError {
    /// Refused for good (authentication, policy, invalid request, quota): the run fails.
    #[error("model call refused: {0}")]
    Rejected(String),
    /// A transient failure (upstream down, the same step still in flight elsewhere): retried.
    #[error("model call failed: {0}")]
    Unavailable(String),
    /// Rate limited (a tenant quota): the run sleeps durably until `retry_after` instead of
    /// holding a worker, then calls again.
    #[error("model call rate limited: {message}")]
    Throttled { retry_after: Duration, message: String },
}

/// Durable sleeps of one step while it is rate limited, after which the run fails.
pub const MAX_THROTTLED_SLEEPS: u32 = 5;

/// Makes the model calls of node runs. The data plane implements it with its own request pipeline
/// (PII, cache, routing, quotas, metering, tracing), so a node never reaches a provider directly.
#[async_trait::async_trait]
pub trait ModelClient: Send + Sync {
    /// `body` is an OpenAI Chat Completions request (non-streaming).
    async fn chat(&self, ctx: &CallCtx, body: Value) -> Result<ModelReply, ModelError>;
}

/// A node version resolved for execution.
#[derive(Debug, Clone)]
pub struct ResolvedNode {
    pub name: String,
    pub version: u32,
    pub hash: String,
    pub spec: Arc<NodeSpec>,
}

/// Where published node versions come from (the data plane: the signed snapshot).
pub trait NodeSource: Send + Sync {
    /// `version: None` is the promoted (live) version.
    fn resolve(&self, tenant: &str, name: &str, version: Option<u32>) -> Result<ResolvedNode, String>;

    /// The tenant's settings that apply to every run (the data plane: the snapshot).
    fn tenant_policy(&self, _tenant: &str) -> TenantPolicy {
        TenantPolicy::default()
    }
}

/// Tenant settings the executor enforces on every run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TenantPolicy {
    /// Daily and monthly node spend caps, checked against the journal before every model call.
    pub spend: caliban_config::NodeSpendCaps,
}

/// An extra check before every model call (after the budget and tenant spend checks). The default
/// allows everything. `Err` ends the run gracefully with that reason.
#[async_trait::async_trait]
pub trait RunGuard: Send + Sync {
    async fn before_model_call(&self, _ctx: &CallCtx, _budget: &BudgetState) -> Result<(), String> {
        Ok(())
    }
}

/// The default guard.
pub struct AllowAll;
impl RunGuard for AllowAll {}

#[derive(Debug, Clone)]
pub struct ExecutorOptions {
    /// Lease on a claimed run; renewed every `heartbeat`.
    pub lease_ttl: Duration,
    pub heartbeat: Duration,
    /// How often an idle worker looks for runnable runs (it is also woken when this process
    /// creates a run or delivers an answer).
    pub poll: Duration,
    /// Runs this worker executes at once.
    pub max_concurrent_runs: usize,
    /// How long a model call is retried while it fails transiently (e.g. the same step is still
    /// in flight on a worker that died: its idempotency key is busy until that call ends).
    pub model_retry_for: Duration,
    /// Consecutive failed calls of one tool (per tenant) that open its circuit breaker.
    pub breaker_failures: u32,
    /// How long an open breaker refuses calls before it lets one trial call through (half-open).
    pub breaker_cooldown: Duration,
}

impl Default for ExecutorOptions {
    fn default() -> Self {
        Self {
            lease_ttl: Duration::from_secs(30),
            heartbeat: Duration::from_secs(10),
            poll: Duration::from_millis(500),
            max_concurrent_runs: 64,
            model_retry_for: Duration::from_secs(60),
            breaker_failures: 5,
            breaker_cooldown: Duration::from_secs(30),
        }
    }
}

// ───────────────────────────── API types ─────────────────────────────

/// A request to start a run.
#[derive(Debug, Clone)]
pub struct StartRun {
    pub tenant: String,
    pub node: String,
    /// `None`: the promoted version.
    pub version: Option<u32>,
    pub input: Value,
    /// Chat messages instead of `input`: mapped to the node's input by [`crate::chat`].
    pub chat: Option<Vec<Value>>,
    pub invoker: String,
    pub invoker_key_hash: Option<String>,
    /// Client `Idempotency-Key` and the request fingerprint.
    pub idempotency: Option<(String, String)>,
    /// Run-level limits: each one lowers the version's budget for this run (never raises it).
    pub budget: Option<RunBudget>,
    /// What started the run, when not a run request (`auto:<intent>`).
    pub origin: Option<String>,
    /// Refuse the run ([`ExecError::OverBudget`]) instead of creating one that would stop at its
    /// first model call: the tenant's node spend caps are reached, or what is left of them is less
    /// than the version's `budgets.usd` (`caliban/auto` falls back to a model call then).
    pub check_spend: bool,
}

/// Run-level budget (`"budget"` on `POST /v1/nodes/{name}/runs`).
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunBudget {
    pub steps: Option<u32>,
    pub tokens: Option<u64>,
    pub usd: Option<f64>,
    pub wall_clock_s: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ExecError {
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error("this Idempotency-Key was used for a different run request")]
    KeyReused,
    #[error("{0}")]
    Conflict(String),
    /// The tenant's node spend caps leave no room for the run (only with [`StartRun::check_spend`]).
    #[error("{0}")]
    OverBudget(String),
    #[error("{0}")]
    Internal(String),
}

impl From<crate::journal::JournalError> for ExecError {
    fn from(e: crate::journal::JournalError) -> Self {
        ExecError::Internal(e.to_string())
    }
}

/// What `GET /v1/runs/{id}` shows.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RunView {
    pub id: String,
    pub object: &'static str,
    pub node: String,
    pub version: u32,
    pub hash: String,
    pub status: RunStatus,
    pub output: Option<Value>,
    /// The run ended on a budget overrun: `output` holds the partial result.
    pub partial: bool,
    pub error: Option<String>,
    pub stop_reason: Option<String>,
    pub awaiting: Option<Awaiting>,
    pub budget: BudgetState,
    /// What the run spent on model calls so far (USD, priced like the metering).
    pub cost_usd: f64,
    /// The run's model calls so far (prompt and completion tokens).
    pub usage: RunUsage,
    pub steps: Vec<StepView>,
    pub claims: u32,
    /// What started the run when it was not a run request (`auto:<intent>`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// A cancellation was asked for and the run has not stopped yet.
    pub cancel_requested: bool,
    /// The number of the run's last event (`GET /v1/runs/{id}/events?after=` resumes there).
    pub last_event: u64,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// Token usage of a run's model calls.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct RunUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

impl RunUsage {
    pub fn of(steps: &[StepRecord]) -> Self {
        let (p, c) = steps.iter().fold((0, 0), |(p, c), s| (p + s.prompt_tokens, c + s.completion_tokens));
        Self { prompt_tokens: p, completion_tokens: c, total_tokens: p + c }
    }
}

/// A run in a listing (`GET /v1/runs`): no steps and no content.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RunSummary {
    pub id: String,
    pub object: &'static str,
    pub node: String,
    pub version: u32,
    pub status: RunStatus,
    pub awaiting_step: Option<String>,
    pub cost_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    pub invoker: String,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

impl RunSummary {
    pub fn of(r: &RunRecord) -> Self {
        Self {
            id: r.id.clone(),
            object: "node.run",
            node: r.node.clone(),
            version: r.version,
            status: r.status,
            awaiting_step: r.awaiting.clone(),
            cost_usd: r.budget.usd,
            origin: r.origin.clone(),
            invoker: r.invoker.clone(),
            created_at: r.created_at,
            finished_at: r.finished_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Awaiting {
    pub step: String,
    pub question: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StepView {
    pub id: String,
    pub vertex: String,
    pub kind: String,
    pub status: StepStatus,
    pub tokens: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub usd: f64,
    /// Taint labels of the step's output.
    pub labels: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub duration_ms: i64,
}

impl StepView {
    pub fn of(s: &StepRecord) -> Self {
        Self {
            id: s.step_id.clone(),
            vertex: s.vertex.clone(),
            kind: s.kind.clone(),
            status: s.status,
            tokens: s.tokens,
            prompt_tokens: s.prompt_tokens,
            completion_tokens: s.completion_tokens,
            usd: s.usd,
            labels: s.labels.clone(),
            started_at: s.started_at,
            duration_ms: (s.finished_at - s.started_at).num_milliseconds(),
        }
    }
}

// ───────────────────────────── the executor ─────────────────────────────

pub struct Executor {
    journal: Arc<dyn Journal>,
    models: Arc<dyn ModelClient>,
    tools: Arc<dyn ToolRegistry>,
    nodes: Arc<dyn NodeSource>,
    sealer: Arc<dyn Sealer>,
    guard: Arc<dyn RunGuard>,
    data: Arc<dyn DataGuard>,
    worker: String,
    opts: ExecutorOptions,
    /// Wakes the claim loop (a run was created or answered here).
    wake: Notify,
    /// Run id → notified whenever this process stops executing that run (suspended, finished).
    watchers: Mutex<HashMap<String, Arc<Notify>>>,
    /// Runs this process is executing.
    active: Mutex<std::collections::HashSet<String>>,
    /// Circuit breakers per (tenant, tool), in this process.
    breakers: Mutex<HashMap<(String, String), breaker::Breaker>>,
    /// Notified whenever this process writes a run event (event streams wake up at once; events
    /// written by other workers are seen at the next poll).
    events: Notify,
}

impl Executor {
    pub fn new(
        journal: Arc<dyn Journal>,
        models: Arc<dyn ModelClient>,
        tools: Arc<dyn ToolRegistry>,
        nodes: Arc<dyn NodeSource>,
        sealer: Arc<dyn Sealer>,
        worker: impl Into<String>,
        opts: ExecutorOptions,
    ) -> Self {
        Self {
            journal,
            models,
            tools,
            nodes,
            sealer,
            guard: Arc::new(AllowAll),
            data: Arc::new(NoGuard),
            worker: worker.into(),
            opts,
            wake: Notify::new(),
            watchers: Mutex::default(),
            active: Mutex::default(),
            breakers: Mutex::default(),
            events: Notify::new(),
        }
    }

    /// The sealer of run data (event streams open questions with it).
    pub fn sealer(&self) -> &Arc<dyn Sealer> {
        &self.sealer
    }

    /// How often an idle worker polls (event streams poll as often for other workers' events).
    pub fn poll_interval(&self) -> Duration {
        self.opts.poll
    }

    /// Resolves when this process writes a run event (or at once if one was written since the
    /// returned future was created and polled).
    pub fn event_written(&self) -> tokio::sync::futures::Notified<'_> {
        self.events.notified()
    }

    fn changed(&self) {
        self.events.notify_waiters();
    }

    /// The state of a tool's circuit breaker for a tenant (`Closed` when it never failed).
    pub fn breaker_state(&self, tenant: &str, tool: &str) -> breaker::State {
        self.breakers
            .lock()
            .get(&(tenant.to_owned(), breaker::tool_key(tool)))
            .map_or(breaker::State::Closed, |b| b.state(Instant::now(), self.opts.breaker_cooldown))
    }

    #[must_use]
    pub fn with_guard(mut self, guard: Arc<dyn RunGuard>) -> Self {
        self.guard = guard;
        self
    }

    /// PII handling across tools (see [`DataGuard`]).
    #[must_use]
    pub fn with_data_guard(mut self, data: Arc<dyn DataGuard>) -> Self {
        self.data = data;
        self
    }

    pub fn worker_id(&self) -> &str {
        &self.worker
    }

    pub fn journal(&self) -> &Arc<dyn Journal> {
        &self.journal
    }

    pub fn nodes(&self) -> &Arc<dyn NodeSource> {
        &self.nodes
    }

    /// Creates a run (`pending`) after validating its input. Returns the run and whether it is new
    /// (`false`: an earlier request with the same `Idempotency-Key` created it).
    pub async fn create(&self, req: StartRun) -> Result<(RunRecord, bool), ExecError> {
        let node = self.nodes.resolve(&req.tenant, &req.node, req.version).map_err(ExecError::NotFound)?;
        let mut req = req;
        if let Some(messages) = req.chat.take() {
            req.input = crate::chat::input_from_messages(&node.spec, &messages).map_err(ExecError::Invalid)?;
        }
        if let Some(s) = node.spec.input_schema() {
            crate::schema::validate(s, &req.input).map_err(|e| ExecError::Invalid(format!("input: {e}")))?;
        }
        let id = format!("run_{}", uuid::Uuid::now_v7().simple());
        let input = self.sealer.seal(&req.tenant, &id, &req.input.to_string()).map_err(ExecError::Internal)?;
        // The run keeps the versions it starts on: retiring one later drains it instead of
        // failing the runs in flight.
        let specs = pin_specs(&self.nodes, &req.tenant, &node);
        let specs = self.sealer.seal(&req.tenant, &id, &specs.to_string()).map_err(ExecError::Internal)?;
        let budget = run_budget(&node.spec, req.budget.as_ref()).map_err(ExecError::Invalid)?;
        if req.check_spend {
            self.check_spend(&req.tenant, &node, budget.usd_limit).await?;
        }
        let run = NewRun {
            id,
            tenant_id: req.tenant,
            node: node.name,
            version: node.version,
            spec_hash: node.hash,
            invoker: req.invoker,
            invoker_key_hash: req.invoker_key_hash,
            input,
            budget,
            idempotency: req.idempotency,
            specs: Some(specs),
            origin: req.origin,
        };
        let out = match self.journal.create_run(run).await? {
            Created::New(r) => (r, true),
            Created::Existing(r) => (r, false),
            Created::KeyReused => return Err(ExecError::KeyReused),
        };
        self.wake.notify_one();
        self.changed();
        Ok(out)
    }

    /// Whether the tenant's node spend caps leave room for a run of `node` (see
    /// [`StartRun::check_spend`]).
    async fn check_spend(&self, tenant: &str, node: &ResolvedNode, usd_limit: Option<f64>) -> Result<(), ExecError> {
        let caps = self.nodes.tenant_policy(tenant).spend;
        if caps.daily_usd.is_none() && caps.monthly_usd.is_none() {
            return Ok(());
        }
        let spent = self.journal.tenant_spend(tenant).await?;
        let need = usd_limit.unwrap_or(0.0);
        for (what, cap, used) in
            [("daily", caps.daily_usd, spent.today_usd), ("monthly", caps.monthly_usd, spent.month_usd)]
        {
            if let Some(cap) = cap
                && (used >= cap || cap - used < need)
            {
                return Err(ExecError::OverBudget(format!(
                    "node {}: the tenant's {what} node spend cap leaves ${:.6} (of ${cap:.6}); a run may spend ${need:.6}",
                    node.name,
                    (cap - used).max(0.0)
                )));
            }
        }
        Ok(())
    }

    /// Claims this run if it is runnable and executes it until it ends or suspends. Returns
    /// whether this worker ran it.
    pub async fn run_now(self: &Arc<Self>, run_id: &str) -> Result<bool, ExecError> {
        match self.journal.claim(run_id, &self.worker, self.opts.lease_ttl).await? {
            Some(run) => {
                self.execute_claimed(run).await;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Starts a run in the background on this worker (the sync path of `POST /v1/nodes/{name}/runs`:
    /// the run keeps going if the client goes away).
    pub fn spawn_run(self: &Arc<Self>, run_id: String) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = me.run_now(&run_id).await {
                tracing::warn!(run = %run_id, error = %e, "could not start run");
            }
        });
    }

    /// The claim loop: executes runnable runs (new, answered, woken, or abandoned by a dead worker)
    /// until `stop` is notified.
    pub async fn run_loop(self: Arc<Self>, stop: Arc<Notify>) {
        let slots = Arc::new(tokio::sync::Semaphore::new(self.opts.max_concurrent_runs.max(1)));
        loop {
            let Ok(permit) = Arc::clone(&slots).acquire_owned().await else { return };
            match self.journal.claim_next(&self.worker, self.opts.lease_ttl).await {
                Ok(Some(run)) => {
                    let me = Arc::clone(&self);
                    tokio::spawn(async move {
                        me.execute_claimed(run).await;
                        drop(permit);
                    });
                    continue;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "claiming a node run failed"),
            }
            drop(permit);
            tokio::select! {
                () = stop.notified() => return,
                () = self.wake.notified() => {}
                () = tokio::time::sleep(self.opts.poll) => {}
            }
        }
    }

    /// The run as the API shows it.
    pub async fn view(&self, tenant: &str, run_id: &str) -> Result<Option<RunView>, ExecError> {
        let Some(r) = self.journal.get_run(tenant, run_id).await? else { return Ok(None) };
        let steps = self.journal.steps(run_id).await?;
        let open = |s: &Option<String>| -> Result<Option<String>, ExecError> {
            s.as_ref().map(|s| self.sealer.open(tenant, run_id, s)).transpose().map_err(ExecError::Internal)
        };
        let output = open(&r.output)?.map(|o| serde_json::from_str(&o).unwrap_or(Value::String(o)));
        let question = open(&r.prompt)?;
        let usage = RunUsage::of(&steps);
        Ok(Some(RunView {
            id: r.id.clone(),
            object: "node.run",
            node: r.node.clone(),
            version: r.version,
            hash: r.spec_hash.clone(),
            status: r.status,
            output,
            partial: r.status == RunStatus::BudgetExhausted,
            error: r.error.clone(),
            stop_reason: r.stop_reason.clone(),
            awaiting: r.awaiting.clone().map(|step| Awaiting { step, question }),
            budget: r.budget,
            cost_usd: r.budget.usd,
            usage,
            steps: steps.iter().map(StepView::of).collect(),
            claims: r.claims,
            origin: r.origin.clone(),
            cancel_requested: r.cancel_requested_at.is_some() && !r.status.is_terminal(),
            last_event: r.last_event,
            created_at: r.created_at,
            started_at: r.started_at,
            finished_at: r.finished_at,
        }))
    }

    /// Records the answer to the human step the run waits for (`step`, or the one it waits for
    /// when `None`) and wakes the run. `by` is who answered (journaled with the answer; approvals
    /// of tainted writes record it).
    pub async fn deliver_input(
        &self,
        tenant: &str,
        run_id: &str,
        step: Option<&str>,
        answer: &Value,
        by: Option<&str>,
    ) -> Result<Delivered, ExecError> {
        let d = deliver(&self.journal, self.sealer.as_ref(), tenant, run_id, step, answer, by).await?;
        if d == Delivered::Accepted {
            self.wake.notify_one();
            self.changed();
        }
        Ok(d)
    }

    /// Cancels a run (see [`Journal::cancel`]), audited as `node.run.cancel` with `by`.
    pub async fn cancel(&self, tenant: &str, run_id: &str, by: &str) -> Result<Cancelled, ExecError> {
        let out = cancel(&self.journal, tenant, run_id, by).await?;
        if matches!(out, Cancelled::Ended | Cancelled::Requested) {
            self.changed();
            self.notify_watchers(run_id);
        }
        Ok(out)
    }

    /// The run's events after `after` (at most `limit`).
    pub async fn events(
        &self,
        tenant: &str,
        run_id: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<RunEvent>, ExecError> {
        Ok(self.journal.events(tenant, run_id, after, limit).await?)
    }

    /// Runs of a tenant, newest first.
    pub async fn list(&self, q: &RunQuery) -> Result<Vec<RunRecord>, ExecError> {
        Ok(self.journal.list_runs(q).await?)
    }

    /// Waits until the run ends or waits for a human, at most until `deadline`, and returns it.
    pub async fn wait(&self, tenant: &str, run_id: &str, deadline: Instant) -> Result<Option<RunRecord>, ExecError> {
        let notify = Arc::clone(self.watchers.lock().entry(run_id.to_owned()).or_default());
        loop {
            let notified = notify.notified();
            let r = self.journal.get_run(tenant, run_id).await?;
            let settled = r.as_ref().is_none_or(|r| r.status.is_terminal() || r.status == RunStatus::InputRequired);
            let now = Instant::now();
            if settled || now >= deadline {
                if !self.active.lock().contains(run_id) {
                    self.watchers.lock().remove(run_id);
                }
                return Ok(r);
            }
            // Another worker may be running it: poll as well.
            let wait = self.opts.poll.min(deadline - now);
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    fn notify_watchers(&self, run_id: &str) {
        if let Some(n) = self.watchers.lock().get(run_id) {
            n.notify_waiters();
        }
    }

    /// Executes a run this worker has claimed, until it ends, suspends, or the lease is lost.
    async fn execute_claimed(self: &Arc<Self>, run: RunRecord) {
        let run_id = run.id.clone();
        self.active.lock().insert(run_id.clone());
        let lost = Arc::new(AtomicBool::new(false));
        let lost_signal = Arc::new(Notify::new());
        // Aborted when this future ends or is dropped (a cancelled execution must not keep the
        // lease alive).
        let _heartbeat = {
            let (me, lost, signal, id) =
                (Arc::clone(self), Arc::clone(&lost), Arc::clone(&lost_signal), run_id.clone());
            AbortOnDrop(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(me.opts.heartbeat).await;
                    match me.journal.heartbeat(&id, &me.worker, me.opts.lease_ttl).await {
                        Ok(true) => {}
                        Ok(false) => {
                            lost.store(true, Ordering::SeqCst);
                            signal.notify_one();
                            return;
                        }
                        Err(e) => tracing::warn!(run = %id, error = %e, "lease heartbeat failed"),
                    }
                }
            }))
        };
        let work = self.drive(run);
        tokio::select! {
            () = work => {}
            () = lost_signal.notified() => {
                tracing::warn!(run = %run_id, worker = %self.worker, "lost the lease of a run; another worker owns it now");
            }
        }
        drop(_heartbeat);
        self.active.lock().remove(&run_id);
        self.notify_watchers(&run_id);
    }

    /// Replays and continues the run, then records how it stopped.
    async fn drive(self: &Arc<Self>, run: RunRecord) {
        let (id, tenant, budget) = (run.id.clone(), run.tenant_id.clone(), run.budget);
        let cx = match RunCx::load(Arc::clone(self), run).await {
            Ok(cx) => cx,
            Err(Stop::LeaseLost) => return,
            Err(stop) => {
                // The run cannot even start (its version is gone, its data cannot be opened...).
                self.end(&id, &tenant, stop, None, budget).await;
                return;
            }
        };
        // The run input is labelled `pii` when it holds personal data.
        let mut input_taint = taint::Taint::new();
        if self.data.has_pii(&cx.run.tenant_id, &cx.input).await {
            input_taint.insert(taint::PII.to_owned());
        }
        let result = match cx.root.spec.kind {
            NodeKind::Workflow => {
                graph::run_graph(&cx, &cx.root, cx.input.clone(), input_taint, "", &cx.ledger, 0).await
            }
            NodeKind::Agent => {
                agent::run_agent_at(&cx, &cx.root, cx.input.clone(), input_taint, "", &cx.ledger, 0).await
            }
        }
        .map(|(v, _)| v);
        let result = result.and_then(|out| match cx.root.spec.output_schema() {
            Some(s) => {
                let v = match &out {
                    Value::String(t) => template::extract_json(t).unwrap_or(out.clone()),
                    other => other.clone(),
                };
                crate::schema::validate(s, &v)
                    .map(|()| v)
                    .map_err(|e| Stop::Fail(format!("the run's output does not match prompt.output_schema: {e}")))
            }
            None => Ok(out),
        });
        let budget = cx.budget_state();
        let partial = cx.last.lock().clone();
        let note = cx.note.lock().clone();
        match result {
            Ok(out) => self.end(&id, &cx.run.tenant_id, Stop::Done(out, note), None, budget).await,
            Err(stop) => self.end(&id, &cx.run.tenant_id, stop, partial, budget).await,
        }
    }

    async fn end(&self, run_id: &str, tenant: &str, stop: Stop, partial: Option<Value>, budget: BudgetState) {
        let seal = |v: &Value| self.sealer.seal(tenant, run_id, &v.to_string()).ok();
        let res = match stop {
            Stop::LeaseLost => return,
            Stop::Done(out, note) => {
                let f =
                    Finish { status: RunStatus::Succeeded, output: seal(&out), error: None, stop_reason: note, budget };
                self.journal.finish(run_id, &self.worker, f).await
            }
            Stop::Budget(reason) => {
                let f = Finish {
                    status: RunStatus::BudgetExhausted,
                    output: partial.as_ref().and_then(seal),
                    error: None,
                    stop_reason: Some(reason),
                    budget,
                };
                self.journal.finish(run_id, &self.worker, f).await
            }
            Stop::Fail(e) => {
                let f = Finish {
                    status: RunStatus::Failed,
                    output: partial.as_ref().and_then(seal),
                    error: Some(e),
                    stop_reason: None,
                    budget,
                };
                self.journal.finish(run_id, &self.worker, f).await
            }
            Stop::Cancelled(by) => {
                let f = Finish {
                    status: RunStatus::Cancelled,
                    output: partial.as_ref().and_then(seal),
                    error: None,
                    stop_reason: Some(format!("cancelled by {by}")),
                    budget,
                };
                self.journal.finish(run_id, &self.worker, f).await
            }
            Stop::Suspend(s) => {
                let s = Suspend {
                    status: s.status,
                    awaiting: s.awaiting,
                    prompt: s.question.and_then(|q| self.sealer.seal(tenant, run_id, &q).ok()),
                    wake_at: s.wake_at,
                    budget,
                };
                match self.journal.suspend(run_id, &self.worker, s).await {
                    // Not suspended: the lease was lost, or a cancellation came in meanwhile.
                    Ok(false) => match self.journal.get_run(tenant, run_id).await {
                        Ok(Some(r))
                            if r.cancel_requested_at.is_some()
                                && r.lease_owner.as_deref() == Some(self.worker.as_str()) =>
                        {
                            let by = r.cancelled_by.unwrap_or_else(|| "unknown".into());
                            let f = Finish {
                                status: RunStatus::Cancelled,
                                output: partial.as_ref().and_then(seal),
                                error: None,
                                stop_reason: Some(format!("cancelled by {by}")),
                                budget,
                            };
                            self.journal.finish(run_id, &self.worker, f).await
                        }
                        other => other.map(|_| false),
                    },
                    other => other,
                }
            }
        };
        self.changed();
        match res {
            Ok(true) => {}
            Ok(false) => tracing::warn!(run = %run_id, "the run's lease was lost before its state was recorded"),
            Err(e) => {
                tracing::error!(run = %run_id, error = %e, "recording the run's state failed; it will be resumed")
            }
        }
    }
}

// ───────────────────────────── a run in progress ─────────────────────────────

/// Why execution stopped before the node returned.
#[derive(Debug, Clone)]
pub(crate) enum Stop {
    /// Finished (only built by `drive`), with an optional note (e.g. a loop that hit its cap).
    Done(Value, Option<String>),
    Suspend(Suspension),
    /// Budget overrun: the run ends gracefully with partial results.
    Budget(String),
    Fail(String),
    /// Another worker owns the run now; record nothing.
    LeaseLost,
    /// A cancellation was asked for (by whom): the run ends as `cancelled`, with partial results.
    Cancelled(String),
}

#[derive(Debug, Clone)]
pub(crate) struct Suspension {
    pub status: RunStatus,
    pub awaiting: Option<String>,
    pub question: Option<String>,
    pub wake_at: Option<DateTime<Utc>>,
}

/// What a step produced.
#[derive(Debug, Clone)]
pub(crate) struct StepOut {
    pub output: Value,
    /// Branch label (`router`: the route; `verify`: pass or fail).
    pub label: Option<String>,
    pub tokens: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub usd: f64,
    /// Taint labels of the output, journaled with tool steps so a replay sees the same labels
    /// (model steps leave it empty: their labels come from their inputs).
    pub taint: taint::Taint,
}

impl StepOut {
    pub fn value(output: Value) -> Self {
        Self {
            output,
            label: None,
            tokens: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            usd: 0.0,
            taint: taint::Taint::new(),
        }
    }

    /// The output of a model call.
    pub fn model(output: Value, r: &ModelReply) -> Self {
        Self {
            tokens: r.tokens,
            prompt_tokens: r.prompt_tokens,
            completion_tokens: r.completion_tokens,
            usd: r.usd,
            ..Self::value(output)
        }
    }
}

pub(crate) struct RunCx {
    pub ex: Arc<Executor>,
    pub run: RunRecord,
    pub root: ResolvedNode,
    /// The versions the run started on (`node_run.specs`), by (name, version).
    pinned: HashMap<(String, u32), ResolvedNode>,
    pub input: Value,
    pub ledger: Ledger,
    recorded: HashMap<String, StepRecord>,
    usd: Mutex<f64>,
    /// Deepest nesting level and widest `map` the run reached (reported in its budget).
    depth_used: std::sync::atomic::AtomicU32,
    fanout_used: std::sync::atomic::AtomicU32,
    /// Loop guard: executions per (vertex, input hash, map branch).
    repeats: Mutex<HashMap<String, u32>>,
    pub guards: crate::Guards,
    elapsed_base_ms: u64,
    t0: Instant,
    /// Last completed value (partial result on a budget stop).
    pub last: Mutex<Option<Value>>,
    /// Shown as `stop_reason` of a run that succeeded (e.g. a loop stopped at its cap).
    pub note: Mutex<Option<String>>,
}

impl RunCx {
    async fn load(ex: Arc<Executor>, run: RunRecord) -> Result<Self, Stop> {
        if run.cancel_requested_at.is_some() {
            return Err(Stop::Cancelled(run.cancelled_by.clone().unwrap_or_else(|| "unknown".into())));
        }
        let pinned = match &run.specs {
            Some(sealed) => {
                let text = ex
                    .sealer
                    .open(&run.tenant_id, &run.id, sealed)
                    .map_err(|e| Stop::Fail(format!("the run's node versions cannot be opened: {e}")))?;
                open_pinned(&text).map_err(Stop::Fail)?
            }
            None => HashMap::new(),
        };
        let root = match pinned.get(&(run.node.clone(), run.version)) {
            Some(n) => n.clone(),
            None => ex
                .nodes
                .resolve(&run.tenant_id, &run.node, Some(run.version))
                .map_err(|e| Stop::Fail(format!("node {}@v{} cannot run: {e}", run.node, run.version)))?,
        };
        if root.hash != run.spec_hash {
            return Err(Stop::Fail(format!(
                "node {}@v{} changed under the run (hash {} instead of {})",
                run.node, run.version, root.hash, run.spec_hash
            )));
        }
        let input = ex
            .sealer
            .open(&run.tenant_id, &run.id, &run.input)
            .map_err(|e| Stop::Fail(format!("the run's input cannot be opened: {e}")))?;
        let input: Value = serde_json::from_str(&input).unwrap_or(Value::String(input));
        let recorded = ex
            .journal
            .steps(&run.id)
            .await
            .map_err(|e| Stop::Fail(e.to_string()))?
            .into_iter()
            .map(|s| (s.step_id.clone(), s))
            .collect();
        let b = run.budget;
        let ledger = Ledger::root(b.ledger_limits());
        let guards = root.spec.guards();
        Ok(Self {
            elapsed_base_ms: b.wall_clock_ms_used,
            depth_used: std::sync::atomic::AtomicU32::new(0),
            fanout_used: std::sync::atomic::AtomicU32::new(0),
            repeats: Mutex::default(),
            guards,
            ex,
            root,
            pinned,
            input,
            ledger,
            recorded,
            usd: Mutex::new(0.0),
            t0: Instant::now(),
            last: Mutex::new(None),
            note: Mutex::new(None),
            run,
        })
    }

    pub fn tenant(&self) -> &str {
        &self.run.tenant_id
    }

    /// A version this run calls: the one it started on, else (runs created before versions were
    /// pinned) the published one.
    pub fn node(&self, name: &str, version: u32) -> Result<ResolvedNode, String> {
        match self.pinned.get(&(name.to_owned(), version)) {
            Some(n) => Ok(n.clone()),
            None => self.ex.nodes.resolve(self.tenant(), name, Some(version)),
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_base_ms + u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub fn budget_state(&self) -> BudgetState {
        let (limit, left) = (self.ledger.limit(), self.ledger.remaining());
        BudgetState {
            steps_limit: limit.steps,
            steps_used: limit.steps - left.steps,
            tokens_limit: limit.tokens,
            tokens_used: limit.tokens - left.tokens,
            wall_clock_ms_limit: self.run.budget.wall_clock_ms_limit,
            wall_clock_ms_used: self.elapsed_ms(),
            usd: *self.usd.lock(),
            usd_limit: self.run.budget.usd_limit,
            depth_limit: limit.depth,
            depth_used: self.depth_used.load(Ordering::Relaxed),
            fanout_limit: limit.fanout,
            fanout_used: self.fanout_used.load(Ordering::Relaxed),
        }
    }

    /// Records the nesting level and map width the run reached.
    pub fn note_depth(&self, level: u32) {
        self.depth_used.fetch_max(level, Ordering::Relaxed);
    }

    pub fn note_fanout(&self, width: u32) {
        self.fanout_used.fetch_max(width, Ordering::Relaxed);
    }

    /// The loop guard: the same vertex with the same input (in the same `map` branch) at most
    /// `guards.max_repeats` times.
    fn count_repeat(&self, step_id: &str, vertex: &str, input_hash: &str) -> Result<(), Stop> {
        let key = format!("{}\0{vertex}\0{input_hash}", loop_key(step_id));
        let mut r = self.repeats.lock();
        let n = r.entry(key).or_default();
        *n += 1;
        if *n > self.guards.max_repeats {
            return Err(Stop::Budget(format!(
                "loop guard: vertex '{vertex}' received the same input {} times (guards.max_repeats = {})",
                *n, self.guards.max_repeats
            )));
        }
        Ok(())
    }

    pub fn set_last(&self, v: &Value) {
        *self.last.lock() = Some(v.clone());
    }

    pub fn call_ctx(&self, step_id: &str) -> CallCtx {
        CallCtx {
            tenant: self.run.tenant_id.clone(),
            invoker_key_hash: self.run.invoker_key_hash.clone(),
            run_id: self.run.id.clone(),
            node: self.run.node.clone(),
            node_version: self.run.version,
            step_id: step_id.to_owned(),
            idempotency_key: idempotency_key(&self.run.id, step_id),
            origin: self.run.origin.clone(),
        }
    }

    fn budget_stop(e: BudgetError) -> Stop {
        Stop::Budget(e.to_string())
    }

    /// Whether this step is in the journal (replay).
    pub fn is_recorded(&self, step_id: &str) -> bool {
        self.recorded.contains_key(step_id)
    }

    /// Before running (or waiting for) a new step: budget and wall clock.
    pub fn admit_step(&self, ledger: &Ledger) -> Result<(), Stop> {
        ledger.ensure_time(self.elapsed_ms()).map_err(Self::budget_stop)?;
        ledger.ensure_step().map_err(Self::budget_stop)
    }

    /// One journaled step: the recorded result if there is one, else `f` (then checkpointed).
    pub async fn step<F>(
        &self,
        ledger: &Ledger,
        step_id: &str,
        vertex: &str,
        kind: &str,
        input: &Value,
        f: F,
    ) -> Result<StepOut, Stop>
    where
        F: std::future::Future<Output = Result<StepOut, Stop>>,
    {
        let input_hash = hash_value(input);
        self.count_repeat(step_id, vertex, &input_hash)?;
        if let Some(rec) = self.recorded.get(step_id) {
            if rec.input_hash != input_hash {
                return Err(Stop::Fail(format!(
                    "step {step_id} was recorded with another input: the run diverged from its journal"
                )));
            }
            let out = self.open_step(rec)?;
            *self.usd.lock() += rec.usd;
            if rec.status == StepStatus::Failed {
                // The same error as when it failed, so a replay sees exactly what the run saw.
                return Err(Stop::Fail(out.output.as_str().unwrap_or("unknown error").to_owned()));
            }
            if let Err(e) = ledger.charge_spent(rec.tokens, rec.usd) {
                self.set_last(&out.output);
                return Err(Self::budget_stop(e));
            }
            return Ok(out);
        }
        self.admit_step(ledger)?;
        let labels: Vec<String> = consumed().into_iter().collect();
        let data = json!({"step": step_id, "vertex": vertex, "kind": kind, "labels": labels});
        match self.ex.journal.start_step(&self.run.id, &self.ex.worker, data).await {
            Ok(StepStart::Started) => self.ex.changed(),
            Ok(StepStart::Cancelled) => return Err(self.cancelled().await),
            Ok(StepStart::LeaseLost) => return Err(Stop::LeaseLost),
            Err(e) => return Err(Stop::Fail(format!("recording the start of step {step_id}: {e}"))),
        }
        let started = Utc::now();
        let result = f.await;
        let (status, out) = match result {
            Ok(out) => (StepStatus::Completed, out),
            Err(Stop::Fail(e)) => {
                // Recorded so the run's steps show what failed; the run fails with it.
                let out = StepOut::value(Value::String(e.clone()));
                self.checkpoint(ledger, step_id, vertex, kind, &input_hash, StepStatus::Failed, &out, started).await?;
                return Err(Stop::Fail(e));
            }
            Err(other) => return Err(other),
        };
        *self.usd.lock() += out.usd;
        let charged = ledger.charge_spent(out.tokens, out.usd);
        let out = self.checkpoint(ledger, step_id, vertex, kind, &input_hash, status, &out, started).await?;
        if let Err(e) = charged {
            // The step completed: its result is part of the partial result.
            self.set_last(&out.output);
            return Err(Self::budget_stop(e));
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    async fn checkpoint(
        &self,
        ledger: &Ledger,
        step_id: &str,
        vertex: &str,
        kind: &str,
        input_hash: &str,
        status: StepStatus,
        out: &StepOut,
        started: DateTime<Utc>,
    ) -> Result<StepOut, Stop> {
        let _ = ledger;
        let mut labels = consumed();
        labels.extend(out.taint.iter().cloned());
        let mut body = json!({"output": out.output, "label": out.label});
        if !out.taint.is_empty() {
            body["taint"] = json!(out.taint);
        }
        let body = body.to_string();
        let result = self
            .ex
            .sealer
            .seal(self.tenant(), &self.run.id, &body)
            .map_err(|e| Stop::Fail(format!("sealing step {step_id}: {e}")))?;
        let rec = StepRecord {
            run_id: self.run.id.clone(),
            tenant_id: self.run.tenant_id.clone(),
            step_id: step_id.to_owned(),
            attempt: self.run.claims,
            vertex: vertex.to_owned(),
            kind: kind.to_owned(),
            input_hash: input_hash.to_owned(),
            status,
            result: Some(result),
            tokens: out.tokens,
            prompt_tokens: out.prompt_tokens,
            completion_tokens: out.completion_tokens,
            usd: out.usd,
            labels: labels.into_iter().collect(),
            started_at: started,
            finished_at: Utc::now(),
        };
        let written = self.ex.journal.put_step(&self.ex.worker, rec, &self.budget_state()).await;
        self.ex.changed();
        match written {
            Ok(StepWrite::Written) => Ok(out.clone()),
            // Recorded concurrently by this run's earlier attempt: that result stands.
            Ok(StepWrite::Existing(rec)) => self.open_step(&rec),
            Ok(StepWrite::LeaseLost) => Err(Stop::LeaseLost),
            Err(e) => Err(Stop::Fail(format!("checkpointing step {step_id}: {e}"))),
        }
    }

    fn open_step(&self, rec: &StepRecord) -> Result<StepOut, Stop> {
        let body = rec
            .result
            .as_deref()
            .map(|s| self.ex.sealer.open(self.tenant(), &self.run.id, s))
            .transpose()
            .map_err(|e| Stop::Fail(format!("step {} cannot be opened: {e}", rec.step_id)))?
            .unwrap_or_else(|| "{}".into());
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        Ok(StepOut {
            output: v.get("output").cloned().unwrap_or(Value::Null),
            label: v.get("label").and_then(Value::as_str).map(str::to_owned),
            tokens: rec.tokens,
            prompt_tokens: rec.prompt_tokens,
            completion_tokens: rec.completion_tokens,
            usd: rec.usd,
            taint: v.get("taint").and_then(|t| serde_json::from_value(t.clone()).ok()).unwrap_or_default(),
        })
    }

    /// A model call through the gateway, retried while it fails transiently.
    pub async fn model(&self, step_id: &str, body: Value) -> Result<ModelReply, Stop> {
        let ctx = self.call_ctx(step_id);
        self.check_tenant_spend().await?;
        self.ex.guard.before_model_call(&ctx, &self.budget_state()).await.map_err(Stop::Budget)?;
        let deadline = Instant::now() + self.ex.opts.model_retry_for;
        let mut wait = Duration::from_millis(50);
        loop {
            match self.ex.models.chat(&ctx, body.clone()).await {
                Ok(r) => return Ok(r),
                Err(ModelError::Rejected(e)) => {
                    return Err(Stop::Fail(format!("step {step_id}: model call refused: {e}")));
                }
                Err(ModelError::Unavailable(e)) => {
                    // A cancelled run does not retry its model call.
                    if self.ex.journal.cancel_requested(&self.run.id).await.unwrap_or(false) {
                        return Err(self.cancelled().await);
                    }
                    if Instant::now() + wait > deadline {
                        return Err(Stop::Fail(format!("step {step_id}: model call failed: {e}")));
                    }
                    tracing::debug!(step = step_id, error = %e, "model call failed transiently; retrying");
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(Duration::from_secs(2));
                }
                Err(ModelError::Throttled { retry_after, message }) => {
                    return Err(self.throttled(step_id, retry_after, &message).await);
                }
            }
        }
    }

    /// The stop of a run whose cancellation was asked for.
    async fn cancelled(&self) -> Stop {
        let by = match self.ex.journal.get_run(self.tenant(), &self.run.id).await {
            Ok(Some(r)) => r.cancelled_by,
            _ => None,
        };
        Stop::Cancelled(by.unwrap_or_else(|| "unknown".into()))
    }

    /// The tenant's daily and monthly node spend caps, against the journal (shared by every worker).
    async fn check_tenant_spend(&self) -> Result<(), Stop> {
        let caps = self.ex.nodes.tenant_policy(self.tenant()).spend;
        if caps.daily_usd.is_none() && caps.monthly_usd.is_none() {
            return Ok(());
        }
        let spent = self.ex.journal.tenant_spend(self.tenant()).await.map_err(|e| Stop::Fail(e.to_string()))?;
        for (what, cap, used) in
            [("daily", caps.daily_usd, spent.today_usd), ("monthly", caps.monthly_usd, spent.month_usd)]
        {
            if let Some(cap) = cap
                && used >= cap
            {
                return Err(Stop::Budget(format!(
                    "the tenant's {what} node spend cap is reached (${used:.6} spent of ${cap:.6}, UTC)"
                )));
            }
        }
        Ok(())
    }

    /// A rate-limited step: a durable sleep (timer `<step>:throttled:<n>`) until the limit resets,
    /// at most [`MAX_THROTTLED_SLEEPS`] times.
    async fn throttled(&self, step_id: &str, retry_after: Duration, message: &str) -> Stop {
        let mut n = 0;
        loop {
            match self.ex.journal.event(&self.run.id, &format!("{step_id}:throttled:{n}")).await {
                Ok(Some(_)) => n += 1,
                Ok(None) => break,
                Err(e) => return Stop::Fail(e.to_string()),
            }
        }
        if n >= MAX_THROTTLED_SLEEPS {
            return Stop::Fail(format!("step {step_id}: still rate limited after {n} waits: {message}"));
        }
        let pause = retry_after.clamp(Duration::from_millis(10), Duration::from_secs(300));
        match self.deadline(&format!("{step_id}:throttled:{n}"), pause).await {
            Ok(wake_at) => Stop::Suspend(Suspension {
                status: RunStatus::Sleeping,
                awaiting: None,
                question: None,
                wake_at: Some(wake_at),
            }),
            Err(stop) => stop,
        }
    }

    /// The tokens a model call may use: what the budget has left (at least 1).
    pub fn max_tokens(&self, ledger: &Ledger, wanted: u64) -> u64 {
        wanted.min(ledger.remaining().tokens).max(1)
    }

    /// Records a timer once and returns its deadline.
    pub async fn deadline(&self, name: &str, after: Duration) -> Result<DateTime<Utc>, Stop> {
        let j = &self.ex.journal;
        let proposed = Utc::now() + chrono::Duration::from_std(after).unwrap_or(chrono::Duration::zero());
        j.put_event(self.tenant(), &self.run.id, name, EventKind::Timer, Some(proposed.to_rfc3339()))
            .await
            .map_err(|e| Stop::Fail(e.to_string()))?;
        let ev = j.event(&self.run.id, name).await.map_err(|e| Stop::Fail(e.to_string()))?;
        Ok(ev
            .and_then(|e| e.payload)
            .and_then(|p| DateTime::parse_from_rfc3339(&p).ok())
            .map_or(proposed, |d| d.with_timezone(&Utc)))
    }

    /// The answer delivered for a human step, if any.
    pub async fn answer(&self, step_id: &str) -> Result<Option<Value>, Stop> {
        Ok(self.answer_by(step_id).await?.map(|(a, _)| a))
    }

    /// The answer delivered for a human step and who delivered it (`api_key:<prefix>`).
    pub async fn answer_by(&self, step_id: &str) -> Result<Option<(Value, Option<String>)>, Stop> {
        let ev = self.ex.journal.event(&self.run.id, step_id).await.map_err(|e| Stop::Fail(e.to_string()))?;
        let Some(sealed) = ev.and_then(|e| e.payload) else { return Ok(None) };
        let text = self
            .ex
            .sealer
            .open(self.tenant(), &self.run.id, &sealed)
            .map_err(|e| Stop::Fail(format!("the answer to {step_id} cannot be opened: {e}")))?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        // Answers are stored as {"$answer": ..., "$by": ...}; older ones as the bare answer.
        Ok(Some(match v {
            Value::Object(mut m) if m.contains_key("$answer") => {
                let by = m.get("$by").and_then(Value::as_str).map(str::to_owned);
                (m.remove("$answer").unwrap_or(Value::Null), by)
            }
            other => (other, None),
        }))
    }
}

/// A step id without its iteration counters (`#n` and `.n`), keeping `map` branch indices (`/n`)
/// and subnode nesting (`>`): `draft#2` and `draft#0` are the same place in the graph,
/// `each#0/1` and `each#0/2` are not.
fn loop_key(step_id: &str) -> String {
    let mut out = String::with_capacity(step_id.len());
    let mut skipping = false;
    for c in step_id.chars() {
        if skipping && c.is_ascii_digit() {
            continue;
        }
        skipping = c == '#' || c == '.';
        out.push(c);
    }
    out
}

/// The run's limits: the version's budgets, each lowered by the run request's `budget` when it
/// asks for less.
fn run_budget(spec: &NodeSpec, req: Option<&RunBudget>) -> Result<BudgetState, String> {
    let b = &spec.budgets;
    let r = req.copied().unwrap_or_default();
    if r.steps == Some(0) || r.tokens == Some(0) || r.wall_clock_s == Some(0) {
        return Err("budget: steps, tokens and wall_clock_s must be positive".into());
    }
    if r.usd.is_some_and(|u| !u.is_finite() || u <= 0.0) {
        return Err("budget: usd must be a positive number".into());
    }
    let min = |a: Option<u64>, b: u64| a.map_or(b, |a| a.min(b));
    let mut st = BudgetState::new(
        r.steps.map_or(b.steps, |s| s.min(b.steps)),
        min(r.tokens, b.tokens),
        min(r.wall_clock_s, b.wall_clock_s),
    );
    st.usd_limit = match (r.usd, b.usd) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    st.depth_limit = b.depth;
    st.fanout_limit = b.fanout;
    Ok(st)
}

/// The run's version and every version it can reach through `node://` references, as JSON:
/// `{"name@vN": {"hash": ..., "spec": ...}}`. A reference that cannot be resolved now is left out
/// (it fails when the run reaches it, as it would have without pinning).
fn pin_specs(nodes: &Arc<dyn NodeSource>, tenant: &str, root: &ResolvedNode) -> Value {
    let mut all: Vec<ResolvedNode> = vec![root.clone()];
    let mut i = 0;
    while i < all.len() {
        for (name, version) in all[i].spec.node_refs() {
            if !all.iter().any(|n| n.name == name && n.version == version)
                && let Ok(n) = nodes.resolve(tenant, &name, Some(version))
            {
                all.push(n);
            }
        }
        i += 1;
    }
    let mut out = serde_json::Map::new();
    for n in all {
        out.insert(format!("{}@v{}", n.name, n.version), json!({"hash": n.hash, "spec": n.spec.as_ref()}));
    }
    Value::Object(out)
}

/// Parses what [`pin_specs`] stored.
fn open_pinned(text: &str) -> Result<HashMap<(String, u32), ResolvedNode>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("the run's node versions: {e}"))?;
    let mut out = HashMap::new();
    for (key, entry) in v.as_object().into_iter().flatten() {
        let Some((name, version)) = key.split_once("@v").and_then(|(n, v)| Some((n, v.parse::<u32>().ok()?))) else {
            return Err(format!("the run's node versions: bad key '{key}'"));
        };
        let spec: NodeSpec = serde_json::from_value(entry.get("spec").cloned().unwrap_or(Value::Null))
            .map_err(|e| format!("the run's node version {key}: {e}"))?;
        let hash = entry.get("hash").and_then(Value::as_str).unwrap_or_default().to_owned();
        out.insert(
            (name.to_owned(), version),
            ResolvedNode { name: name.to_owned(), version, hash, spec: Arc::new(spec) },
        );
    }
    Ok(out)
}

/// Records the answer to the human step a run waits for (`step`, or the one it waits for), sealed
/// with `by`, and the audit event of the decision: `node.write.approve` or `node.write.deny` for a
/// tainted write's approval step (`...@approve`), else `node.run.answer`. The event id is stable per
/// (run, step), so the audit log records the decision once. Used by the data plane and the control
/// plane (an answer from the console).
pub async fn deliver(
    journal: &Arc<dyn Journal>,
    sealer: &dyn Sealer,
    tenant: &str,
    run_id: &str,
    step: Option<&str>,
    answer: &Value,
    by: Option<&str>,
) -> Result<Delivered, ExecError> {
    let Some(r) = journal.get_run(tenant, run_id).await? else { return Ok(Delivered::NotFound) };
    let Some(step) = step.map(str::to_owned).or(r.awaiting.clone()) else { return Ok(Delivered::NotAwaiting) };
    let body = json!({"$answer": answer, "$by": by});
    let sealed = sealer.seal(tenant, run_id, &body.to_string()).map_err(ExecError::Internal)?;
    let approval = step.ends_with("@approve");
    let action = match (approval, taint::approved(answer)) {
        (true, true) => "node.write.approve",
        (true, false) => "node.write.deny",
        (false, _) => "node.run.answer",
    };
    let audit = AuditEvent {
        id: format!("{run_id}/{step}/answer"),
        tenant_id: tenant.to_owned(),
        actor: by.unwrap_or("unknown").to_owned(),
        action: action.into(),
        target: Some(run_id.to_owned()),
        detail: json!({"node": r.node, "version": r.version, "step": step}),
        at: Utc::now(),
    };
    Ok(journal.deliver_input(tenant, run_id, &step, sealed, by, Some(audit)).await?)
}

/// Cancels a run, audited as `node.run.cancel` (event id `<run>/cancel`: recorded once however
/// often it is asked).
pub async fn cancel(journal: &Arc<dyn Journal>, tenant: &str, run_id: &str, by: &str) -> Result<Cancelled, ExecError> {
    let Some(r) = journal.get_run(tenant, run_id).await? else { return Ok(Cancelled::NotFound) };
    let audit = AuditEvent {
        id: format!("{run_id}/cancel"),
        tenant_id: tenant.to_owned(),
        actor: by.to_owned(),
        action: "node.run.cancel".into(),
        target: Some(run_id.to_owned()),
        detail: json!({"node": r.node, "version": r.version, "status": r.status}),
        at: Utc::now(),
    };
    Ok(journal.cancel(tenant, run_id, by, Some(audit)).await?)
}

/// An event as clients see it: `run.input_required` carries its question opened when the caller
/// may see run content (`content`), else none; nothing else is sealed.
pub fn render_event(sealer: &dyn Sealer, tenant: &str, ev: &RunEvent, content: bool) -> Value {
    let mut data = ev.data.clone();
    if let Some(o) = data.as_object_mut()
        && let Some(sealed) = o.remove("sealed_question")
    {
        let q = sealed
            .as_str()
            .filter(|_| content)
            .and_then(|s| sealer.open(tenant, &ev.run_id, s).ok())
            .map_or(Value::Null, Value::String);
        o.insert("question".into(), q);
    }
    json!({"id": ev.seq, "type": ev.kind, "run_id": ev.run_id, "at": ev.created_at, "data": data})
}

/// Aborts the task when dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// `Idempotency-Key` of a step's side effects: a hash of (run id, step id).
pub fn idempotency_key(run_id: &str, step_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(run_id.as_bytes());
    h.update([0]);
    h.update(step_id.as_bytes());
    format!("caliban-node-{}", &hex::encode(h.finalize())[..40])
}

fn hash_value(v: &Value) -> String {
    hex::encode(Sha256::digest(crate::hash::canonical_json(v).as_bytes()))[..32].to_owned()
}

#[cfg(test)]
mod tests;
