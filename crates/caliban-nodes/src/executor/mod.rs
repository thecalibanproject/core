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
mod graph;
pub mod template;
pub mod tools;

pub use tools::{FnTool, NoTools, StaticTools, Tool, ToolCtx, ToolError, ToolInfo, ToolRegistry};

use crate::budget::{Budget, BudgetError, BudgetState, Ledger};
use crate::journal::{
    Created, Delivered, EventKind, Finish, Journal, NewRun, RunRecord, RunStatus, StepRecord, StepStatus, StepWrite,
    Suspend,
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

// ───────────────────────────── what the executor needs ─────────────────────────────

/// Who and what a model call is for.
#[derive(Debug, Clone)]
pub struct CallCtx {
    pub tenant: String,
    /// The invoking API key's hash: the call is authorized, rate-limited and metered as that key.
    pub invoker_key_hash: Option<String>,
    pub run_id: String,
    pub step_id: String,
    /// Derived from (run id, step id): the same for every attempt of the step.
    pub idempotency_key: String,
}

#[derive(Debug, Clone)]
pub struct ModelReply {
    /// The assistant message (OpenAI Chat Completions shape: `content`, `tool_calls`).
    pub message: Value,
    /// Prompt and completion tokens.
    pub tokens: u64,
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
}

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
}

/// Hook for P3 M3 guards (USD caps, tenant spend caps, loop guards), called before every model
/// call. The default allows everything.
pub trait RunGuard: Send + Sync {
    fn before_model_call(&self, _ctx: &CallCtx, _budget: &BudgetState) -> Result<(), String> {
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
}

impl Default for ExecutorOptions {
    fn default() -> Self {
        Self {
            lease_ttl: Duration::from_secs(30),
            heartbeat: Duration::from_secs(10),
            poll: Duration::from_millis(500),
            max_concurrent_runs: 64,
            model_retry_for: Duration::from_secs(60),
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
    pub invoker: String,
    pub invoker_key_hash: Option<String>,
    /// Client `Idempotency-Key` and the request fingerprint.
    pub idempotency: Option<(String, String)>,
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
    pub steps: Vec<StepView>,
    pub claims: u32,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
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
    pub usd: f64,
    pub duration_ms: i64,
}

// ───────────────────────────── the executor ─────────────────────────────

pub struct Executor {
    journal: Arc<dyn Journal>,
    models: Arc<dyn ModelClient>,
    tools: Arc<dyn ToolRegistry>,
    nodes: Arc<dyn NodeSource>,
    sealer: Arc<dyn Sealer>,
    guard: Arc<dyn RunGuard>,
    worker: String,
    opts: ExecutorOptions,
    /// Wakes the claim loop (a run was created or answered here).
    wake: Notify,
    /// Run id → notified whenever this process stops executing that run (suspended, finished).
    watchers: Mutex<HashMap<String, Arc<Notify>>>,
    /// Runs this process is executing.
    active: Mutex<std::collections::HashSet<String>>,
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
            worker: worker.into(),
            opts,
            wake: Notify::new(),
            watchers: Mutex::default(),
            active: Mutex::default(),
        }
    }

    #[must_use]
    pub fn with_guard(mut self, guard: Arc<dyn RunGuard>) -> Self {
        self.guard = guard;
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
        if let Some(s) = node.spec.input_schema() {
            crate::schema::validate(s, &req.input).map_err(|e| ExecError::Invalid(format!("input: {e}")))?;
        }
        let id = format!("run_{}", uuid::Uuid::now_v7().simple());
        let input = self.sealer.seal(&req.tenant, &id, &req.input.to_string()).map_err(ExecError::Internal)?;
        let b = &node.spec.budgets;
        let run = NewRun {
            id,
            tenant_id: req.tenant,
            node: node.name,
            version: node.version,
            spec_hash: node.hash,
            invoker: req.invoker,
            invoker_key_hash: req.invoker_key_hash,
            input,
            budget: BudgetState::new(b.steps, b.tokens, b.wall_clock_s),
            idempotency: req.idempotency,
        };
        let out = match self.journal.create_run(run).await? {
            Created::New(r) => (r, true),
            Created::Existing(r) => (r, false),
            Created::KeyReused => return Err(ExecError::KeyReused),
        };
        self.wake.notify_one();
        Ok(out)
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
            steps: steps
                .iter()
                .map(|s| StepView {
                    id: s.step_id.clone(),
                    vertex: s.vertex.clone(),
                    kind: s.kind.clone(),
                    status: s.status,
                    tokens: s.tokens,
                    usd: s.usd,
                    duration_ms: (s.finished_at - s.started_at).num_milliseconds(),
                })
                .collect(),
            claims: r.claims,
            created_at: r.created_at,
            started_at: r.started_at,
            finished_at: r.finished_at,
        }))
    }

    /// Records the answer to the human step the run waits for (`step`, or the one it waits for
    /// when `None`) and wakes the run.
    pub async fn deliver_input(
        &self,
        tenant: &str,
        run_id: &str,
        step: Option<&str>,
        answer: &Value,
    ) -> Result<Delivered, ExecError> {
        let Some(r) = self.journal.get_run(tenant, run_id).await? else { return Ok(Delivered::NotFound) };
        let Some(step) = step.map(str::to_owned).or(r.awaiting) else { return Ok(Delivered::NotAwaiting) };
        let sealed = self.sealer.seal(tenant, run_id, &answer.to_string()).map_err(ExecError::Internal)?;
        let d = self.journal.deliver_input(tenant, run_id, &step, sealed).await?;
        if d == Delivered::Accepted {
            self.wake.notify_one();
        }
        Ok(d)
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
        let result = match cx.root.spec.kind {
            NodeKind::Workflow => graph::run_graph(&cx, &cx.root, cx.input.clone(), "", &cx.ledger, 0).await,
            NodeKind::Agent => agent::run_agent_at(&cx, &cx.root, cx.input.clone(), "", &cx.ledger, 0).await,
        };
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
            Stop::Suspend(s) => {
                let s = Suspend {
                    status: s.status,
                    awaiting: s.awaiting,
                    prompt: s.question.and_then(|q| self.sealer.seal(tenant, run_id, &q).ok()),
                    wake_at: s.wake_at,
                    budget,
                };
                self.journal.suspend(run_id, &self.worker, s).await
            }
        };
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
    pub usd: f64,
}

impl StepOut {
    pub fn value(output: Value) -> Self {
        Self { output, label: None, tokens: 0, usd: 0.0 }
    }
}

pub(crate) struct RunCx {
    pub ex: Arc<Executor>,
    pub run: RunRecord,
    pub root: ResolvedNode,
    pub input: Value,
    pub ledger: Ledger,
    recorded: HashMap<String, StepRecord>,
    usd: Mutex<f64>,
    elapsed_base_ms: u64,
    t0: Instant,
    /// Last completed value (partial result on a budget stop).
    pub last: Mutex<Option<Value>>,
    /// Shown as `stop_reason` of a run that succeeded (e.g. a loop stopped at its cap).
    pub note: Mutex<Option<String>>,
}

impl RunCx {
    async fn load(ex: Arc<Executor>, run: RunRecord) -> Result<Self, Stop> {
        let root = ex
            .nodes
            .resolve(&run.tenant_id, &run.node, Some(run.version))
            .map_err(|e| Stop::Fail(format!("node {}@v{} cannot run: {e}", run.node, run.version)))?;
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
        let ledger = Ledger::root(Budget { steps: b.steps_limit, tokens: b.tokens_limit });
        Ok(Self {
            elapsed_base_ms: b.wall_clock_ms_used,
            ex,
            root,
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

    fn elapsed_ms(&self) -> u64 {
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
        }
    }

    pub fn set_last(&self, v: &Value) {
        *self.last.lock() = Some(v.clone());
    }

    pub fn call_ctx(&self, step_id: &str) -> CallCtx {
        CallCtx {
            tenant: self.run.tenant_id.clone(),
            invoker_key_hash: self.run.invoker_key_hash.clone(),
            run_id: self.run.id.clone(),
            step_id: step_id.to_owned(),
            idempotency_key: idempotency_key(&self.run.id, step_id),
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
        let (used, limit) = (self.elapsed_ms(), self.run.budget.wall_clock_ms_limit);
        if limit > 0 && used >= limit {
            return Err(Self::budget_stop(BudgetError::WallClock { used_ms: used, limit_ms: limit }));
        }
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
            if let Err(e) = ledger.charge_spent(rec.tokens) {
                self.set_last(&out.output);
                return Err(Self::budget_stop(e));
            }
            return Ok(out);
        }
        self.admit_step(ledger)?;
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
        let charged = ledger.charge_spent(out.tokens);
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
        let body = json!({"output": out.output, "label": out.label}).to_string();
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
            usd: out.usd,
            started_at: started,
            finished_at: Utc::now(),
        };
        match self.ex.journal.put_step(&self.ex.worker, rec, &self.budget_state()).await {
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
            usd: rec.usd,
        })
    }

    /// A model call through the gateway, retried while it fails transiently.
    pub async fn model(&self, step_id: &str, body: Value) -> Result<ModelReply, Stop> {
        let ctx = self.call_ctx(step_id);
        self.ex.guard.before_model_call(&ctx, &self.budget_state()).map_err(Stop::Budget)?;
        let deadline = Instant::now() + self.ex.opts.model_retry_for;
        let mut wait = Duration::from_millis(50);
        loop {
            match self.ex.models.chat(&ctx, body.clone()).await {
                Ok(r) => return Ok(r),
                Err(ModelError::Rejected(e)) => {
                    return Err(Stop::Fail(format!("step {step_id}: model call refused: {e}")));
                }
                Err(ModelError::Unavailable(e)) => {
                    if Instant::now() + wait > deadline {
                        return Err(Stop::Fail(format!("step {step_id}: model call failed: {e}")));
                    }
                    tracing::debug!(step = step_id, error = %e, "model call failed transiently; retrying");
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(Duration::from_secs(2));
                }
            }
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
        let ev = self.ex.journal.event(&self.run.id, step_id).await.map_err(|e| Stop::Fail(e.to_string()))?;
        let Some(sealed) = ev.and_then(|e| e.payload) else { return Ok(None) };
        let text = self
            .ex
            .sealer
            .open(self.tenant(), &self.run.id, &sealed)
            .map_err(|e| Stop::Fail(format!("the answer to {step_id} cannot be opened: {e}")))?;
        Ok(Some(serde_json::from_str(&text).unwrap_or(Value::String(text))))
    }
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
