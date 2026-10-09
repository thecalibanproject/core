//! Runs PII protection off the async runtime when the engine has a heavy detector (the L1 NER
//! model).
//!
//! Model inference costs milliseconds of CPU per request. Run inline, it would hold a tokio worker
//! for that long (and, with every session busy, block it on a session mutex), so unrelated
//! requests on the same worker would wait behind it. Instead:
//!
//! - **Workers**: a fixed set of dedicated OS threads (`caliban-pii-N`), one per NER session, so
//!   a worker always finds a free session and never waits on a mutex. They are not tokio's
//!   blocking pool, so inference cannot starve other `spawn_blocking` users (file I/O, DNS).
//! - **Bounded queue**: admission takes one of `workers + queue` permits (a semaphore), so at most
//!   `queue` requests wait for a worker. The caller awaits a oneshot; tokio workers never block.
//!   A job whose caller has gone (client disconnected) is dropped without running the model.
//! - **Overflow** (every permit taken): wait up to `queue_wait` for a permit, then apply
//!   [`Overflow`]. The default, [`Overflow::Reject`], answers 503 with `retry-after`: the request
//!   fails closed and nothing is sent upstream. [`Overflow::Degrade`] is an explicit opt-in that
//!   screens the request with the regex tier only (names, organisations and places then reach
//!   the provider unprotected); every degraded request is logged and marked on its span.
//!
//! Configured from the environment by the binary (`CALIBAN_PII_NER_QUEUE`,
//! `CALIBAN_PII_NER_QUEUE_WAIT_MS`, `CALIBAN_PII_NER_OVERFLOW`; see the README).

use crate::{ApiError, Gateway};
use caliban_ir::ChatRequest;
use caliban_pii::{PiiError, Protected};
use caliban_types::{CalibanError, PiiMode};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError, oneshot};

/// What to do with a request when the PII queue is full (after `queue_wait`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Overflow {
    /// Fail closed: 503 with `retry-after`, nothing is sent upstream (default).
    #[default]
    Reject,
    /// Screen with the cheap detectors only (regex patterns, dictionaries) and skip the model.
    /// Less is detected, so less-screened text goes upstream. Opt-in only.
    Degrade,
}

impl std::str::FromStr for Overflow {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "reject" => Ok(Overflow::Reject),
            "degrade" => Ok(Overflow::Degrade),
            other => Err(format!("unknown PII overflow policy {other:?} (expected `reject` or `degrade`)")),
        }
    }
}

/// Sizing and overflow policy of the PII worker pool.
#[derive(Debug, Clone)]
pub struct PiiPoolOptions {
    /// Worker threads. Use the NER session count: more workers than sessions only wait on
    /// session mutexes.
    pub workers: usize,
    /// Requests that may wait for a worker beyond the ones running (default 128).
    pub queue: usize,
    /// How long a request waits for a queue slot when the queue is full before [`Overflow`]
    /// applies (default 0: immediately).
    pub queue_wait: Duration,
    pub overflow: Overflow,
}

/// Default queue length: enough for a burst of 128 concurrent PII requests per router before
/// anything is rejected. At about 2.5 ms per request per worker, a full queue is drained in well
/// under a second.
pub const DEFAULT_QUEUE: usize = 128;

impl PiiPoolOptions {
    pub fn new(workers: usize) -> Self {
        Self { workers: workers.max(1), queue: DEFAULT_QUEUE, queue_wait: Duration::ZERO, overflow: Overflow::Reject }
    }

    /// Applies `CALIBAN_PII_NER_QUEUE`, `CALIBAN_PII_NER_QUEUE_WAIT_MS` and
    /// `CALIBAN_PII_NER_OVERFLOW` from `get` (the process environment in the binary). A value that
    /// does not parse is an error: a typo must not silently change a privacy setting.
    pub fn with_env(mut self, get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        if let Some(v) = get("CALIBAN_PII_NER_QUEUE") {
            self.queue = v.trim().parse().map_err(|_| format!("CALIBAN_PII_NER_QUEUE: not a number: {v:?}"))?;
        }
        if let Some(v) = get("CALIBAN_PII_NER_QUEUE_WAIT_MS") {
            let ms: u64 =
                v.trim().parse().map_err(|_| format!("CALIBAN_PII_NER_QUEUE_WAIT_MS: not a number: {v:?}"))?;
            self.queue_wait = Duration::from_millis(ms);
        }
        if let Some(v) = get("CALIBAN_PII_NER_OVERFLOW") {
            self.overflow = v.parse().map_err(|e| format!("CALIBAN_PII_NER_OVERFLOW: {e}"))?;
        }
        Ok(self)
    }
}

/// Why a job did not run.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PoolError {
    /// Every worker busy and the queue full (after `queue_wait`).
    Full,
    /// The job panicked, or the pool is shut down.
    Failed,
}

type Job = Box<dyn FnOnce() + Send>;

/// Counters for logs and tests.
#[derive(Debug, Default)]
pub struct PiiPoolStats {
    pub completed: AtomicU64,
    pub rejected: AtomicU64,
    pub degraded: AtomicU64,
    /// Jobs dropped before running because their caller had gone.
    pub abandoned: AtomicU64,
}

pub struct PiiPool {
    tx: mpsc::Sender<Job>,
    permits: Arc<Semaphore>,
    opts: PiiPoolOptions,
    pub(crate) stats: Arc<PiiPoolStats>,
}

impl std::fmt::Debug for PiiPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PiiPool").field("opts", &self.opts).finish_non_exhaustive()
    }
}

impl PiiPool {
    /// Starts `opts.workers` threads. They exit when the pool is dropped.
    pub fn new(opts: PiiPoolOptions) -> Self {
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..opts.workers.max(1) {
            let rx = Arc::clone(&rx);
            std::thread::Builder::new()
                .name(format!("caliban-pii-{i}"))
                .spawn(move || {
                    loop {
                        // Hold the lock only to take a job, never while running one.
                        let job = rx.lock().unwrap_or_else(PoisonError::into_inner).recv();
                        match job {
                            Ok(job) => job(),
                            Err(_) => break, // pool dropped
                        }
                    }
                })
                .expect("spawning a PII worker thread");
        }
        let permits = Arc::new(Semaphore::new(opts.workers.max(1) + opts.queue));
        Self { tx, permits, opts, stats: Arc::default() }
    }

    pub fn options(&self) -> &PiiPoolOptions {
        &self.opts
    }

    /// Takes a queue slot: immediately, or after waiting up to `queue_wait`; [`PoolError::Full`]
    /// otherwise.
    pub(crate) async fn admit(&self) -> Result<OwnedSemaphorePermit, PoolError> {
        match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(p) => Ok(p),
            Err(TryAcquireError::Closed) => Err(PoolError::Failed),
            Err(TryAcquireError::NoPermits) if self.opts.queue_wait.is_zero() => Err(PoolError::Full),
            Err(TryAcquireError::NoPermits) => {
                match tokio::time::timeout(self.opts.queue_wait, Arc::clone(&self.permits).acquire_owned()).await {
                    Ok(Ok(p)) => Ok(p),
                    Ok(Err(_)) => Err(PoolError::Failed),
                    Err(_) => Err(PoolError::Full),
                }
            }
        }
    }

    /// Runs `f` on a worker with an admitted slot (released when `f` returns).
    pub(crate) async fn run_admitted<R: Send + 'static>(
        &self,
        permit: OwnedSemaphorePermit,
        f: impl FnOnce() -> R + Send + 'static,
    ) -> Result<R, PoolError> {
        let (rtx, rrx) = oneshot::channel();
        let stats = Arc::clone(&self.stats);
        let job: Job = Box::new(move || {
            let _permit = permit;
            if rtx.is_closed() {
                stats.abandoned.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // A panic fails this request (the caller sees `Failed`), not the worker.
            if let Ok(r) = std::panic::catch_unwind(AssertUnwindSafe(f)) {
                stats.completed.fetch_add(1, Ordering::Relaxed);
                let _ = rtx.send(r);
            }
        });
        self.tx.send(job).map_err(|_| PoolError::Failed)?;
        rrx.await.map_err(|_| PoolError::Failed)
    }

    /// [`Self::admit`] then [`Self::run_admitted`].
    #[cfg(test)]
    pub(crate) async fn run<R: Send + 'static>(&self, f: impl FnOnce() -> R + Send + 'static) -> Result<R, PoolError> {
        let permit = self.admit().await?;
        self.run_admitted(permit, f).await
    }
}

/// `retry-after` on a rejected request.
const RETRY_AFTER: Duration = Duration::from_secs(1);

impl Gateway {
    /// Protects a request (see [`PiiEngine::protect`]). Light engines and `PiiMode::Off` run
    /// inline; a heavy engine runs on the worker pool, with its overflow policy when the queue is
    /// full. A detector failure or a credential is a 403 and a pool failure a 500: both fail
    /// closed, nothing is sent upstream.
    pub(crate) async fn protect(
        &self,
        mut req: ChatRequest,
        mode: PiiMode,
        scope_key: &[u8],
    ) -> Result<(ChatRequest, Protected), ApiError> {
        let policy = |e: PiiError| ApiError::from(CalibanError::PolicyViolation(e.to_string()));
        let Some(pool) = self.pii_pool.as_ref().filter(|_| mode != PiiMode::Off) else {
            let p = self.pii.protect(&mut req, mode, scope_key).map_err(policy)?;
            return Ok((req, p));
        };
        let permit = match pool.admit().await {
            Ok(p) => p,
            Err(PoolError::Full) => return self.overflow(pool, req, mode, scope_key),
            Err(PoolError::Failed) => return Err(pool_failed()),
        };
        let engine = Arc::clone(&self.pii);
        let key = scope_key.to_vec();
        let job = move || {
            let mut req = req;
            engine.protect(&mut req, mode, &key).map(|p| (req, p))
        };
        match pool.run_admitted(permit, job).await {
            Ok(r) => r.map_err(policy),
            Err(_) => Err(pool_failed()),
        }
    }

    fn overflow(
        &self,
        pool: &PiiPool,
        mut req: ChatRequest,
        mode: PiiMode,
        scope_key: &[u8],
    ) -> Result<(ChatRequest, Protected), ApiError> {
        match pool.opts.overflow {
            Overflow::Reject => {
                let n = pool.stats.rejected.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    rejected_total = n,
                    queue = pool.opts.queue,
                    "PII model queue full: request rejected with 503 (CALIBAN_PII_NER_OVERFLOW=reject)"
                );
                Err(ApiError::overloaded(
                    "PII screening is at capacity; the request was not sent upstream. Retry later.",
                    "pii_ner_queue",
                    RETRY_AFTER,
                ))
            }
            Overflow::Degrade => {
                let n = pool.stats.degraded.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    degraded_total = n,
                    queue = pool.opts.queue,
                    "PII model queue full: screened with the regex tier only (CALIBAN_PII_NER_OVERFLOW=degrade)"
                );
                tracing::Span::current().record("caliban.pii.degraded", true);
                let p = self
                    .pii
                    .protect_light(&mut req, mode, scope_key)
                    .map_err(|e| ApiError::from(CalibanError::PolicyViolation(e.to_string())))?;
                Ok((req, p))
            }
        }
    }
}

fn pool_failed() -> ApiError {
    CalibanError::Internal("PII screening failed; the request was blocked".into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    #[tokio::test]
    async fn runs_jobs_on_dedicated_threads() {
        let pool = PiiPool::new(PiiPoolOptions::new(2));
        let name = pool.run(|| std::thread::current().name().map(str::to_owned)).await.unwrap();
        assert!(name.unwrap().starts_with("caliban-pii-"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_runtime_keeps_running_while_workers_are_busy() {
        // One runtime thread: if a job blocked it, the timer below could not fire on time.
        let pool = Arc::new(PiiPool::new(PiiPoolOptions::new(1)));
        let p = Arc::clone(&pool);
        let slow = tokio::spawn(async move { p.run(|| std::thread::sleep(Duration::from_millis(300))).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let t = Instant::now();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(t.elapsed() < Duration::from_millis(150), "runtime blocked for {:?}", t.elapsed());
        slow.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn full_queue_is_rejected_immediately_by_default() {
        let pool = Arc::new(PiiPool::new(PiiPoolOptions { queue: 1, ..PiiPoolOptions::new(1) }));
        let gate = Arc::new(std::sync::Barrier::new(2));
        let (p, g) = (Arc::clone(&pool), Arc::clone(&gate));
        let running = tokio::spawn(async move { p.run(move || g.wait()).await });
        let p = Arc::clone(&pool);
        let queued = tokio::spawn(async move { p.run(|| 7).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // One running, one queued: the third is over capacity.
        let t = Instant::now();
        assert_eq!(pool.run(|| 1).await, Err(PoolError::Full));
        assert!(t.elapsed() < Duration::from_millis(50));
        tokio::task::spawn_blocking(move || gate.wait()).await.unwrap();
        running.await.unwrap().unwrap();
        assert_eq!(queued.await.unwrap(), Ok(7));
        assert_eq!(pool.run(|| 2).await, Ok(2), "capacity is released after the jobs finish");
    }

    #[tokio::test]
    async fn waits_for_a_slot_up_to_the_deadline() {
        let opts = PiiPoolOptions { queue: 0, queue_wait: Duration::from_millis(500), ..PiiPoolOptions::new(1) };
        let pool = Arc::new(PiiPool::new(opts));
        let p = Arc::clone(&pool);
        let busy = tokio::spawn(async move { p.run(|| std::thread::sleep(Duration::from_millis(100))).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(pool.run(|| 3).await, Ok(3), "got a slot within the deadline");
        busy.await.unwrap().unwrap();

        let opts = PiiPoolOptions { queue: 0, queue_wait: Duration::from_millis(30), ..PiiPoolOptions::new(1) };
        let pool = Arc::new(PiiPool::new(opts));
        let p = Arc::clone(&pool);
        let busy = tokio::spawn(async move { p.run(|| std::thread::sleep(Duration::from_millis(300))).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let t = Instant::now();
        assert_eq!(pool.run(|| 4).await, Err(PoolError::Full));
        assert!(t.elapsed() >= Duration::from_millis(25));
        busy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn abandoned_jobs_do_not_run_and_panics_fail_only_their_request() {
        let pool = Arc::new(PiiPool::new(PiiPoolOptions::new(1)));
        let ran = Arc::new(AtomicUsize::new(0));
        let p = Arc::clone(&pool);
        let blocker = tokio::spawn(async move { p.run(|| std::thread::sleep(Duration::from_millis(100))).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (p, r) = (Arc::clone(&pool), Arc::clone(&ran));
        let gone = tokio::spawn(async move { p.run(move || r.fetch_add(1, Ordering::SeqCst)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        gone.abort(); // the client disconnects while queued
        blocker.await.unwrap().unwrap();
        assert_eq!(pool.run(|| ()).await, Ok(()));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(pool.stats.abandoned.load(Ordering::Relaxed), 1);

        assert_eq!(pool.run(|| -> u8 { panic!("boom") }).await, Err(PoolError::Failed));
        assert_eq!(pool.run(|| 5).await, Ok(5), "the worker survives a panicking job");
    }

    #[test]
    fn options_from_env_reject_typos() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned())
        };
        let o = PiiPoolOptions::new(4).with_env(env(&[])).unwrap();
        assert_eq!(
            (o.workers, o.queue, o.queue_wait, o.overflow),
            (4, DEFAULT_QUEUE, Duration::ZERO, Overflow::Reject)
        );
        let o = PiiPoolOptions::new(2)
            .with_env(env(&[
                ("CALIBAN_PII_NER_QUEUE", "16"),
                ("CALIBAN_PII_NER_QUEUE_WAIT_MS", "250"),
                ("CALIBAN_PII_NER_OVERFLOW", "Degrade"),
            ]))
            .unwrap();
        assert_eq!((o.queue, o.queue_wait, o.overflow), (16, Duration::from_millis(250), Overflow::Degrade));
        assert!(PiiPoolOptions::new(1).with_env(env(&[("CALIBAN_PII_NER_OVERFLOW", "degarde")])).is_err());
        assert!(PiiPoolOptions::new(1).with_env(env(&[("CALIBAN_PII_NER_QUEUE", "lots")])).is_err());
    }

    // ---- gateway integration: `Gateway::protect` with a heavy detector ----

    use axum::response::IntoResponse;
    use caliban_config::{Config, ConfigHandle, Snapshot};
    use caliban_meter::RecentUsage;
    use caliban_pii::{DetectError, Detector, EntityType, PiiEngine, Span};

    /// Stands in for the NER model: finds "Zed" as a person, after waiting on `gate` (if any).
    struct SlowModel {
        gate: Option<Arc<std::sync::Barrier>>,
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    impl Detector for SlowModel {
        fn detect(&self, text: &str) -> Vec<Span> {
            self.try_detect(text).unwrap_or_default()
        }
        fn try_detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(g) = &self.gate {
                g.wait();
            }
            if self.fail {
                return Err(DetectError { detector: "ner", message: "inference failed".into() });
            }
            Ok(text
                .match_indices("Zed")
                .map(|(i, m)| Span { start: i, end: i + m.len(), entity: EntityType::Person })
                .collect())
        }
        fn is_heavy(&self) -> bool {
            true
        }
    }

    fn gateway(model: SlowModel, opts: PiiPoolOptions) -> Arc<Gateway> {
        let cfg = Config::from_toml_str("").unwrap();
        let gw = Gateway::new(ConfigHandle::new(Snapshot::new(cfg, "test")), Arc::new(RecentUsage::default()));
        Arc::new(gw.with_pii(PiiEngine::default().with_detector(model), opts))
    }

    fn chat(text: &str) -> ChatRequest {
        ChatRequest::from_openai_json(
            serde_json::json!({"model": "m", "messages": [{"role": "user", "content": text}]}).to_string().as_bytes(),
        )
        .unwrap()
    }

    const TEXT: &str = "Zed wrote from zed@acme.com";

    /// Occupies the single worker (its detector waits on `gate`) and returns the pending call.
    async fn occupy(gw: &Arc<Gateway>) -> tokio::task::JoinHandle<Result<(ChatRequest, Protected), ApiError>> {
        let g = Arc::clone(gw);
        let h = tokio::spawn(async move { g.protect(chat(TEXT), PiiMode::Reversible, b"k").await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        h
    }

    #[tokio::test]
    async fn heavy_engine_runs_on_the_pool_and_protects() {
        let calls = Arc::new(AtomicUsize::new(0));
        let gw = gateway(SlowModel { gate: None, calls: Arc::clone(&calls), fail: false }, PiiPoolOptions::new(2));
        assert!(gw.pii_pool.is_some());
        let (req, p) = gw.protect(chat(TEXT), PiiMode::Reversible, b"k").await.unwrap();
        let sent = req.last_user_text().unwrap();
        assert!(!sent.contains("Zed") && !sent.contains("zed@acme.com"), "{sent}");
        assert_eq!(p.entities, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn full_queue_fails_closed_with_503_and_retry_after() {
        let gate = Arc::new(std::sync::Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let gw = gateway(
            SlowModel { gate: Some(Arc::clone(&gate)), calls: Arc::clone(&calls), fail: false },
            PiiPoolOptions { queue: 0, ..PiiPoolOptions::new(1) },
        );
        let busy = occupy(&gw).await;
        let err = gw.protect(chat(TEXT), PiiMode::Reversible, b"k").await.unwrap_err();
        assert!(matches!(err.error, CalibanError::Overloaded(_)));
        let resp = err.into_response();
        assert_eq!(resp.status(), 503);
        assert_eq!(resp.headers()["retry-after"], "1");
        assert!(resp.headers().get("x-caliban-ratelimit-scope").is_none());
        assert_eq!(gw.pii_pool.as_ref().unwrap().stats.rejected.load(Ordering::Relaxed), 1);
        // PII off never needs the model, so it is not affected by the full queue.
        let (req, p) = gw.protect(chat(TEXT), PiiMode::Off, b"k").await.unwrap();
        assert_eq!((req.last_user_text().unwrap(), p.entities), (TEXT.to_owned(), 0));
        tokio::task::spawn_blocking(move || gate.wait()).await.unwrap();
        busy.await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the rejected request never reached the model");
    }

    #[tokio::test]
    async fn degrade_policy_screens_with_the_regex_tier_only() {
        let gate = Arc::new(std::sync::Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let opts = PiiPoolOptions { queue: 0, overflow: Overflow::Degrade, ..PiiPoolOptions::new(1) };
        let gw = gateway(SlowModel { gate: Some(Arc::clone(&gate)), calls: Arc::clone(&calls), fail: false }, opts);
        let busy = occupy(&gw).await;
        let (req, p) = gw.protect(chat(TEXT), PiiMode::Reversible, b"k").await.unwrap();
        let sent = req.last_user_text().unwrap();
        assert!(!sent.contains("zed@acme.com"), "the regex tier still runs: {sent}");
        assert!(sent.starts_with("Zed "), "the model was skipped: {sent}");
        assert_eq!(p.entities, 1);
        assert_eq!(gw.pii_pool.as_ref().unwrap().stats.degraded.load(Ordering::Relaxed), 1);
        tokio::task::spawn_blocking(move || gate.wait()).await.unwrap();
        busy.await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn model_failure_on_the_pool_blocks_the_request() {
        let gw = gateway(SlowModel { gate: None, calls: Arc::default(), fail: true }, PiiPoolOptions::new(1));
        let err = gw.protect(chat(TEXT), PiiMode::Reversible, b"k").await.unwrap_err();
        assert!(matches!(err.error, CalibanError::PolicyViolation(_)), "{:?}", err.error);
    }

    #[tokio::test]
    async fn light_engine_has_no_pool() {
        let cfg = Config::from_toml_str("").unwrap();
        let gw = Gateway::new(ConfigHandle::new(Snapshot::new(cfg, "test")), Arc::new(RecentUsage::default()))
            .with_pii(PiiEngine::default(), PiiPoolOptions::new(4));
        assert!(gw.pii_pool.is_none());
        let (req, _) = gw.protect(chat(TEXT), PiiMode::Mask, b"k").await.unwrap();
        assert_eq!(req.last_user_text().unwrap(), "Zed wrote from [EMAIL]");
    }
}
