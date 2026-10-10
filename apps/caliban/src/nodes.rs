//! Node runs in each mode (P3 M2; decision 1 of the P3 plan):
//! - **standalone**: the run API executes runs in this process, with the Postgres journal when
//!   `CALIBAN_DATABASE_URL` is set (else in memory);
//! - **router** (split mode): no database; run requests are forwarded to workers
//!   (`CALIBAN_WORKER_URLS`, authenticated with `CALIBAN_WORKER_TOKEN`);
//! - **worker**: a gateway with the Postgres journal and the control plane's snapshot (like a
//!   router), serving the run API to routers only. Its model calls go through its own pipeline
//!   in-process, and it ships usage to the control plane like a router.

use anyhow::{Context, Result};
use caliban_gateway::Gateway;
use caliban_gateway::nodes::{Forwarder, LocalRuns, NodeRuns};
use caliban_nodes::executor::{ExecutorOptions, NoTools};
use caliban_nodes::journal::Journal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Node-run settings shared by every mode.
#[derive(clap::Args)]
pub struct NodeArgs {
    /// Router: worker base URLs to forward node runs to, comma separated (e.g.
    /// `http://worker-1:8082,http://worker-2:8082`). Unset: routers answer the run API with 503.
    #[arg(long, env = "CALIBAN_WORKER_URLS", value_delimiter = ',', global = true)]
    worker_urls: Vec<String>,
    /// Shared secret between routers and workers (sent as `x-caliban-worker-token`).
    #[arg(long, env = "CALIBAN_WORKER_TOKEN", global = true, hide_env_values = true)]
    worker_token: Option<String>,
    /// Longest a sync run request waits before answering 202 with the run so far.
    #[arg(long, env = "CALIBAN_NODE_SYNC_WAIT_SECS", default_value_t = 60, global = true)]
    node_sync_wait_secs: u64,
    /// How often an idle worker looks for runnable runs (milliseconds).
    #[arg(long, env = "CALIBAN_NODE_POLL_MS", default_value_t = 500, global = true)]
    node_poll_ms: u64,
    /// Lease a worker holds on a run it executes (renewed every third of it). A worker that dies
    /// loses its runs to another worker this long after its last renewal.
    #[arg(long, env = "CALIBAN_NODE_LEASE_SECS", default_value_t = 30, global = true)]
    node_lease_secs: u64,
    /// Runs one process executes at once.
    #[arg(long, env = "CALIBAN_NODE_MAX_RUNS", default_value_t = 64, global = true)]
    node_max_runs: usize,
    /// Consecutive failed calls of a tool (per tenant) that open its circuit breaker.
    #[arg(long, env = "CALIBAN_NODE_BREAKER_FAILURES", default_value_t = 5, global = true)]
    node_breaker_failures: u32,
    /// Days finished node runs (with their steps and events) are kept in the journal; 0 keeps them
    /// forever. Every worker purges, in small batches, hourly.
    #[arg(long, env = "CALIBAN_NODE_RUN_RETENTION_DAYS", default_value_t = 30, global = true)]
    node_run_retention_days: u64,
    /// Seconds an open circuit breaker refuses calls before it lets one trial call through.
    #[arg(long, env = "CALIBAN_NODE_BREAKER_COOLDOWN_SECS", default_value_t = 30, global = true)]
    node_breaker_cooldown_secs: u64,
}

#[derive(clap::Args)]
pub struct WorkerArgs {
    /// Control-plane base URL (snapshots, usage), e.g. http://cp:8081. Requires
    /// CALIBAN_ROUTER_TOKEN and CALIBAN_SNAPSHOT_PUBLIC_KEY, like a split-mode router.
    #[arg(long, env = "CALIBAN_CONTROL_PLANE_URL")]
    pub control_plane_url: String,
    /// Seconds between snapshot polls.
    #[arg(long, env = "CALIBAN_SNAPSHOT_POLL_SECS", default_value_t = 10)]
    pub poll_interval_secs: u64,
    /// Listen address (routers reach workers here).
    #[arg(long, env = "CALIBAN_WORKER_ADDR", default_value = "0.0.0.0:8082")]
    pub listen: String,
    /// Persist the last good signed snapshot here.
    #[arg(long, env = "CALIBAN_SNAPSHOT_CACHE")]
    pub snapshot_cache: Option<PathBuf>,
}

impl NodeArgs {
    pub fn options(&self) -> ExecutorOptions {
        let lease = Duration::from_secs(self.node_lease_secs.max(3));
        ExecutorOptions {
            lease_ttl: lease,
            heartbeat: lease / 3,
            poll: Duration::from_millis(self.node_poll_ms.max(10)),
            max_concurrent_runs: self.node_max_runs.max(1),
            breaker_failures: self.node_breaker_failures.max(1),
            breaker_cooldown: Duration::from_secs(self.node_breaker_cooldown_secs),
            ..ExecutorOptions::default()
        }
    }

    fn sync_wait(&self) -> Duration {
        Duration::from_secs(self.node_sync_wait_secs.max(1))
    }

    pub fn worker_token(&self) -> Result<String> {
        self.worker_token
            .clone()
            .filter(|t| !t.trim().is_empty())
            .context("CALIBAN_WORKER_TOKEN is required (routers send it to workers)")
    }

    /// Router: forwards node runs to `CALIBAN_WORKER_URLS` when set.
    pub fn forward_to_workers(&self, gw: &Gateway) -> Result<()> {
        if self.worker_urls.is_empty() {
            tracing::info!("node runs: no CALIBAN_WORKER_URLS, the run API answers 503 on this router");
            return Ok(());
        }
        let f =
            Forwarder::new(self.worker_urls.clone(), self.worker_token()?, self.sync_wait() + Duration::from_secs(30))
                .map_err(anyhow::Error::msg)
                .context("CALIBAN_WORKER_URLS")?;
        tracing::info!(workers = ?self.worker_urls, "node runs are forwarded to workers");
        gw.set_nodes(NodeRuns::Forward(f));
        Ok(())
    }

    /// Standalone and worker: executes runs here, and starts the claim loop. Returns the handle
    /// that stops it.
    pub fn run_locally(
        &self,
        gw: &Arc<Gateway>,
        journal: Arc<dyn Journal>,
        keyring: Arc<caliban_config::Keyring>,
        worker_id: String,
    ) -> Result<Arc<Notify>> {
        let opts = self.options();
        tracing::info!(
            worker_id,
            journal = journal.name(),
            lease_secs = opts.lease_ttl.as_secs(),
            max_runs = opts.max_concurrent_runs,
            "node runs execute in this process"
        );
        // TODO(P3 M4): the tenant tool registry with the MCP client; until then mcp:// tools are
        // refused at run time with a clear error.
        let executor = caliban_gateway::nodes::local_executor(gw, journal, Arc::new(NoTools), keyring, worker_id, opts);
        let stop = Arc::new(Notify::new());
        tokio::spawn(Arc::clone(&executor).run_loop(Arc::clone(&stop)));
        if self.node_run_retention_days > 0 {
            let keep = Duration::from_secs(self.node_run_retention_days.saturating_mul(86_400));
            tokio::spawn(purge_runs(Arc::clone(executor.journal()), keep, Arc::clone(&stop)));
        }
        gw.set_nodes(NodeRuns::Local(LocalRuns { executor, sync_wait: self.sync_wait() }));
        Ok(stop)
    }
}

/// Retention of finished runs: hourly, in batches (several workers may purge at once).
async fn purge_runs(journal: Arc<dyn Journal>, keep: Duration, stop: Arc<Notify>) {
    const BATCH: usize = 500;
    loop {
        let mut total = 0;
        loop {
            match journal.purge_finished(keep, BATCH).await {
                Ok(n) => {
                    total += n;
                    if (n as usize) < BATCH {
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "purging finished node runs failed; retrying next hour");
                    break;
                }
            }
        }
        if total > 0 {
            tracing::info!(runs = total, days = keep.as_secs() / 86_400, "purged finished node runs past retention");
        }
        tokio::select! {
            () = stop.notified() => return,
            () = tokio::time::sleep(Duration::from_secs(3600)) => {}
        }
    }
}

/// This worker's stable name: `CALIBAN_WORKER_ID` as is when set (deploy sets the pod name), else
/// the host's id (like a router's). Snapshot check-ins and usage shipping use it, so a restarted
/// worker keeps its check-in row.
pub fn worker_name() -> String {
    std::env::var("CALIBAN_WORKER_ID").ok().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()).map_or_else(
        crate::split::router_id,
        |v| {
            v.chars()
                .take(120)
                .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-') { c } else { '-' })
                .collect()
        },
    )
}

/// The lease owner of this process's runs: the worker's name plus a per-process instance suffix,
/// so two processes started with the same name can never both hold a lease (and a restarted
/// worker never mistakes its predecessor's leases for its own).
pub fn lease_owner(name: &str) -> String {
    format!("{name}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

/// The Postgres journal of a worker. Workers never migrate (the control plane owns migrations, and
/// a worker needs no DDL rights): the schema must be exactly the one this build expects, else the
/// worker refuses to start with what to do.
pub async fn worker_journal(url: &str) -> Result<Arc<dyn Journal>> {
    let pg = caliban_cp::store::postgres::PgBackend::connect(url)
        .await
        .context("connecting to Postgres (CALIBAN_DATABASE_URL)")?;
    pg.check_schema().await.map_err(|e| anyhow::anyhow!("{e}")).context("checking the database schema")?;
    let j = caliban_nodes::journal::postgres::PgJournal::from_pool(pg.pool().clone());
    Ok(Arc::new(j))
}

/// The Postgres journal of a standalone process (its control plane migrated the database).
pub async fn postgres_journal(url: &str) -> Result<Arc<dyn Journal>> {
    let j = caliban_nodes::journal::postgres::PgJournal::connect(url)
        .await
        .context("opening the node journal (CALIBAN_DATABASE_URL)")?;
    Ok(Arc::new(j))
}

/// Exactly-once model calls across workers need a shared `Idempotency-Key` store: with the
/// in-memory one, a step replayed on another worker after a crash may pay its model call twice.
pub fn warn_if_local_idempotency(gw: &Gateway) {
    if gw.idempotency.kind() == "memory" {
        tracing::warn!(
            "IDEMPOTENCY STORE IS IN MEMORY: model calls are exactly-once only within this worker. With more than \
             one worker, set [limits] store = \"valkey\" (CALIBAN_VALKEY_URL) on the control plane, or a run taken \
             over after a crash may pay an in-flight model call twice"
        );
    }
}
