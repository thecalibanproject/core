//! Usage shipping: a split-mode router (or a standalone control plane with a Postgres store)
//! delivers its usage events to the control plane's store, at least once.
//!
//! The request path only enqueues the event on a bounded queue ([`ShipOptions::queue`]; when it is
//! full the event is dropped and counted, the request never waits). A background task sends the
//! queue in batches through a [`UsageTransport`]: when [`ShipOptions::batch_max`] events are
//! waiting, or [`ShipOptions::interval`] after the first event of a batch. A batch that cannot be
//! delivered goes to the backlog ([`Spool`]): a directory of JSONL segments, one per batch, or
//! memory when no directory is configured. The backlog is bounded by
//! [`ShipOptions::spool_max_events`]; events beyond it are dropped, counted and logged. While the
//! receiver is unreachable, new batches go straight to the backlog and delivery is retried with
//! exponential backoff (1 s to 30 s); once a send succeeds the backlog is drained oldest first.
//! A segment is deleted only after the receiver acknowledged it, so a crash in between sends it
//! again: the receiver deduplicates by `request_id`, and a retried batch is never counted twice.
//!
//! Graceful shutdown ([`UsageShipper::shutdown`]) sends what is queued; what cannot be sent stays
//! in the spool directory for the next start (with a memory backlog it is lost, and logged).

use crate::{UsageEvent, UsageSink};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// What the receiver did with a batch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Delivered {
    /// Events stored for the first time.
    pub accepted: u64,
    /// Events it already had (a retry).
    pub duplicates: u64,
    /// Events it refused as invalid (never retried).
    pub rejected: u64,
}

/// Why a batch was not delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShipError {
    /// Worth retrying: the receiver is down, slow, overloaded or not ready.
    Retry(String),
    /// Retrying the same batch cannot succeed (for example the receiver refuses it as malformed):
    /// the batch is dropped and counted.
    Fatal(String),
}

impl std::fmt::Display for ShipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry(m) | Self::Fatal(m) => f.write_str(m),
        }
    }
}

/// Delivers a batch to the control plane's store. `Ok` means the receiver has stored every event
/// of the batch (or already had it).
#[async_trait]
pub trait UsageTransport: Send + Sync {
    async fn send(&self, events: &[UsageEvent]) -> Result<Delivered, ShipError>;
}

#[derive(Debug, Clone)]
pub struct ShipOptions {
    /// Events per batch at most; a full batch is sent at once.
    pub batch_max: usize,
    /// How long the first event of a batch waits for more before the batch is sent.
    pub interval: Duration,
    /// Events the in-memory queue holds; beyond it `record` drops and counts.
    pub queue: usize,
    /// Directory of the on-disk backlog. `None`: the backlog is kept in memory (lost on restart).
    pub spool_dir: Option<PathBuf>,
    /// Events the backlog holds at most (disk or memory); beyond it new batches are dropped.
    pub spool_max_events: usize,
    /// First retry delay after a failed send; doubles up to `retry_max`.
    pub retry_min: Duration,
    pub retry_max: Duration,
}

impl Default for ShipOptions {
    fn default() -> Self {
        Self {
            batch_max: 500,
            interval: Duration::from_secs(1),
            queue: 10_000,
            spool_dir: None,
            spool_max_events: 100_000,
            retry_min: Duration::from_secs(1),
            retry_max: Duration::from_secs(30),
        }
    }
}

/// Counters, in `/healthz` under `usage_shipping` and on `/metrics`.
#[derive(Debug, Default)]
pub struct ShipStats {
    /// Events the receiver acknowledged as new.
    pub delivered: AtomicU64,
    /// Events the receiver already had (retries after a lost acknowledgement or a crash).
    pub duplicates: AtomicU64,
    /// Events the receiver refused as invalid.
    pub rejected: AtomicU64,
    /// Events lost: queue full, backlog full, a batch the receiver can never accept, or a
    /// memory backlog at shutdown.
    pub dropped: AtomicU64,
    /// Failed sends (each is retried).
    pub send_errors: AtomicU64,
    /// Events currently in the backlog.
    pub backlog: AtomicU64,
}

impl ShipStats {
    fn n(a: &AtomicU64) -> u64 {
        a.load(Ordering::Relaxed)
    }
}

enum Msg {
    Event(Box<UsageEvent>),
    /// Send (or spool) everything queued before this message and try the backlog once.
    Flush(oneshot::Sender<()>),
    /// Like `Flush`, then stop.
    Stop(oneshot::Sender<()>),
}

/// The shipping sink. Create it inside a Tokio runtime (it spawns its sender task).
pub struct UsageShipper {
    tx: mpsc::Sender<Msg>,
    stats: Arc<ShipStats>,
    last_error: Arc<parking_lot::Mutex<Option<String>>>,
    opts: ShipOptions,
}

impl UsageShipper {
    /// Starts the sender task. A spool directory that cannot be created or read is an error
    /// (refuse to start rather than silently lose the backlog).
    pub fn start(transport: Arc<dyn UsageTransport>, opts: ShipOptions) -> std::io::Result<Self> {
        let spool = match &opts.spool_dir {
            Some(dir) => Spool::open_dir(dir)?,
            None => Spool::memory(),
        };
        let stats = Arc::new(ShipStats::default());
        stats.backlog.store(spool.len() as u64, Ordering::Relaxed);
        if !spool.is_empty() {
            tracing::info!(events = spool.len(), "usage shipping: backlog from an earlier run will be delivered");
        }
        let last_error = Arc::new(parking_lot::Mutex::new(None));
        let (tx, rx) = mpsc::channel(opts.queue.max(1));
        let sender = Sender {
            transport,
            spool,
            stats: Arc::clone(&stats),
            last_error: Arc::clone(&last_error),
            opts: opts.clone(),
            retry_at: None,
            backoff: opts.retry_min,
        };
        tokio::spawn(sender.run(rx));
        Ok(Self { tx, stats, last_error, opts })
    }

    pub fn stats(&self) -> &ShipStats {
        &self.stats
    }

    /// Events waiting in the queue.
    pub fn queue_depth(&self) -> usize {
        self.tx.max_capacity() - self.tx.capacity()
    }

    /// Returns once every event recorded before this call was delivered or put in the backlog
    /// (one send attempt, no waiting for the backoff).
    pub async fn flush(&self) {
        let (ack, done) = oneshot::channel();
        if self.tx.send(Msg::Flush(ack)).await.is_ok() {
            let _ = done.await;
        }
    }

    /// Graceful shutdown: flushes while late events (streams that finish after the server stopped
    /// accepting) still arrive, for up to `grace`, then stops the sender. Undelivered events stay
    /// in the spool directory for the next start.
    pub async fn shutdown(&self, grace: Duration) {
        let deadline = Instant::now() + grace;
        loop {
            let seen = self.recorded();
            self.flush().await;
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50).min(grace)).await;
            if self.queue_depth() == 0 && self.recorded() == seen {
                break;
            }
        }
        let (ack, done) = oneshot::channel();
        if self.tx.send(Msg::Stop(ack)).await.is_ok() {
            let _ = done.await;
        }
        let s = &self.stats;
        tracing::info!(
            delivered = ShipStats::n(&s.delivered),
            duplicates = ShipStats::n(&s.duplicates),
            backlog = ShipStats::n(&s.backlog),
            dropped = ShipStats::n(&s.dropped),
            "usage shipping stopped"
        );
    }

    /// Events accounted for so far (for the shutdown loop).
    fn recorded(&self) -> u64 {
        let s = &self.stats;
        ShipStats::n(&s.delivered)
            + ShipStats::n(&s.duplicates)
            + ShipStats::n(&s.rejected)
            + ShipStats::n(&s.dropped)
            + ShipStats::n(&s.backlog)
    }
}

/// Counts dropped events and warns on the first and then every 1,000th.
fn count_dropped(stats: &ShipStats, n: u64, why: &str) {
    if n == 0 {
        return;
    }
    let before = stats.dropped.fetch_add(n, Ordering::Relaxed);
    if before == 0 || (before + n) / 1000 > before / 1000 {
        tracing::warn!(dropped_total = before + n, now = n, why, "usage shipping dropped events (not billed)");
    }
}

#[async_trait]
impl UsageSink for UsageShipper {
    async fn record(&self, event: UsageEvent) {
        match self.tx.try_send(Msg::Event(Box::new(event))) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => count_dropped(&self.stats, 1, "queue full"),
            Err(mpsc::error::TrySendError::Closed(_)) => count_dropped(&self.stats, 1, "shipper stopped"),
        }
    }

    fn status(&self) -> Vec<(&'static str, serde_json::Value)> {
        let s = &self.stats;
        vec![(
            "usage_shipping",
            serde_json::json!({
                "delivered": ShipStats::n(&s.delivered),
                "duplicates": ShipStats::n(&s.duplicates),
                "rejected": ShipStats::n(&s.rejected),
                "dropped": ShipStats::n(&s.dropped),
                "send_errors": ShipStats::n(&s.send_errors),
                "backlog": ShipStats::n(&s.backlog),
                "backlog_max": self.opts.spool_max_events,
                "spool": self.opts.spool_dir.as_ref().map_or("memory".to_owned(), |d| d.display().to_string()),
                "queue_depth": self.queue_depth(),
                "queue_capacity": self.tx.max_capacity(),
                "last_error": *self.last_error.lock(),
            }),
        )]
    }

    fn metrics(&self, out: &mut String) {
        let s = &self.stats;
        #[allow(clippy::cast_precision_loss)]
        let n = |a: &AtomicU64| ShipStats::n(a) as f64;
        let m = crate::prometheus_sample;
        m(out, "caliban_usage_shipped_total", "counter", "Usage events the control plane stored.", n(&s.delivered));
        m(
            out,
            "caliban_usage_ship_duplicates_total",
            "counter",
            "Usage events sent again that the control plane already had.",
            n(&s.duplicates),
        );
        m(
            out,
            "caliban_usage_ship_rejected_total",
            "counter",
            "Usage events the control plane refused.",
            n(&s.rejected),
        );
        m(out, "caliban_usage_ship_dropped_total", "counter", "Usage events lost before delivery.", n(&s.dropped));
        m(out, "caliban_usage_ship_errors_total", "counter", "Failed usage deliveries (retried).", n(&s.send_errors));
        m(out, "caliban_usage_ship_backlog", "gauge", "Usage events waiting in the backlog.", n(&s.backlog));
    }
}

struct Sender {
    transport: Arc<dyn UsageTransport>,
    spool: Spool,
    stats: Arc<ShipStats>,
    last_error: Arc<parking_lot::Mutex<Option<String>>>,
    opts: ShipOptions,
    /// While set and in the future, batches go to the backlog without a send attempt.
    retry_at: Option<Instant>,
    backoff: Duration,
}

/// Backlog segments sent per wake-up, so new events are never starved by a long drain.
const DRAIN_PER_WAKE: usize = 8;

impl Sender {
    async fn run(mut self, mut rx: mpsc::Receiver<Msg>) {
        let mut buf: Vec<UsageEvent> = Vec::new();
        let mut first_at: Option<Instant> = None;
        loop {
            let now = Instant::now();
            let batch_due = first_at.map(|t| t + self.opts.interval);
            let drain_due = (!self.spool.is_empty()).then(|| self.retry_at.map_or(now, |t| t.max(now)));
            let wake = [batch_due, drain_due].into_iter().flatten().min();
            let msg = match wake {
                Some(at) => tokio::select! {
                    m = rx.recv() => Some(m),
                    () = tokio::time::sleep_until(at) => None,
                },
                None => Some(rx.recv().await),
            };
            match msg {
                Some(Some(Msg::Event(e))) => {
                    buf.push(*e);
                    first_at.get_or_insert_with(Instant::now);
                    if buf.len() >= self.opts.batch_max.max(1) {
                        self.ship(std::mem::take(&mut buf)).await;
                        first_at = None;
                    }
                }
                Some(Some(Msg::Flush(ack))) => {
                    self.flush_all(&mut buf, &mut rx).await;
                    first_at = None;
                    let _ = ack.send(());
                }
                Some(Some(Msg::Stop(ack))) => {
                    self.flush_all(&mut buf, &mut rx).await;
                    self.stop();
                    let _ = ack.send(());
                    return;
                }
                Some(None) => {
                    // Every sender is gone: deliver or spool what is left.
                    self.ship(std::mem::take(&mut buf)).await;
                    self.stop();
                    return;
                }
                None => {
                    if first_at.is_some_and(|t| t + self.opts.interval <= Instant::now()) {
                        self.ship(std::mem::take(&mut buf)).await;
                        first_at = None;
                    }
                    self.drain().await;
                }
            }
        }
    }

    /// Takes everything already queued, ships it, and tries the backlog once (ignoring backoff).
    async fn flush_all(&mut self, buf: &mut Vec<UsageEvent>, rx: &mut mpsc::Receiver<Msg>) {
        let mut pending = Vec::new();
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Event(e) => buf.push(*e),
                Msg::Flush(ack) | Msg::Stop(ack) => pending.push(ack),
            }
        }
        self.retry_at = None;
        for chunk in std::mem::take(buf).chunks(self.opts.batch_max.max(1)) {
            self.ship(chunk.to_vec()).await;
        }
        self.drain().await;
        for ack in pending {
            let _ = ack.send(());
        }
    }

    fn stop(&self) {
        if self.opts.spool_dir.is_none() && !self.spool.is_empty() {
            count_dropped(&self.stats, self.spool.len() as u64, "memory backlog at shutdown (no spool directory)");
        }
    }

    fn backing_off(&self) -> bool {
        self.retry_at.is_some_and(|t| Instant::now() < t)
    }

    /// Sends one batch, or puts it in the backlog.
    async fn ship(&mut self, batch: Vec<UsageEvent>) {
        if batch.is_empty() {
            return;
        }
        if self.backing_off() {
            self.backlog(batch);
            return;
        }
        match self.send(&batch).await {
            Ok(()) => {}
            Err(ShipError::Retry(_)) => self.backlog(batch),
            Err(ShipError::Fatal(_)) => count_dropped(&self.stats, batch.len() as u64, "refused by the control plane"),
        }
    }

    async fn send(&mut self, batch: &[UsageEvent]) -> Result<(), ShipError> {
        match self.transport.send(batch).await {
            Ok(d) => {
                self.stats.delivered.fetch_add(d.accepted, Ordering::Relaxed);
                self.stats.duplicates.fetch_add(d.duplicates, Ordering::Relaxed);
                self.stats.rejected.fetch_add(d.rejected, Ordering::Relaxed);
                if d.rejected > 0 {
                    tracing::warn!(rejected = d.rejected, "the control plane refused usage events as invalid");
                }
                if self.retry_at.take().is_some() {
                    tracing::info!(backlog = self.spool.len(), "usage shipping: control plane reachable again");
                }
                self.backoff = self.opts.retry_min;
                *self.last_error.lock() = None;
                Ok(())
            }
            Err(e) => {
                self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                if matches!(e, ShipError::Retry(_)) {
                    if self.retry_at.is_none() {
                        tracing::warn!(error = %e, "usage shipping failed; keeping events in the backlog and retrying");
                    } else {
                        tracing::debug!(error = %e, "usage shipping retry failed");
                    }
                    self.retry_at = Some(Instant::now() + self.backoff);
                    self.backoff = (self.backoff * 2).min(self.opts.retry_max);
                } else {
                    tracing::error!(error = %e, events = batch.len(), "the control plane refused a usage batch; dropping it");
                }
                *self.last_error.lock() = Some(e.to_string());
                Err(e)
            }
        }
    }

    fn backlog(&mut self, batch: Vec<UsageEvent>) {
        let room = self.opts.spool_max_events.saturating_sub(self.spool.len());
        let n = batch.len();
        let keep: Vec<UsageEvent> = batch.into_iter().take(room).collect();
        count_dropped(&self.stats, (n - keep.len()) as u64, "backlog full");
        if !keep.is_empty() {
            let k = keep.len();
            if let Err(e) = self.spool.push(keep) {
                tracing::error!(error = %e, "cannot write the usage spool");
                count_dropped(&self.stats, k as u64, "spool write failed");
            }
        }
        self.stats.backlog.store(self.spool.len() as u64, Ordering::Relaxed);
    }

    /// Sends backlog segments, oldest first, until one fails or `DRAIN_PER_WAKE` went out.
    async fn drain(&mut self) {
        for _ in 0..DRAIN_PER_WAKE {
            if self.backing_off() {
                return;
            }
            let Some((id, events)) = self.spool.oldest() else { return };
            match self.send(&events).await {
                Ok(()) => self.spool.remove(id),
                Err(ShipError::Retry(_)) => return,
                Err(ShipError::Fatal(_)) => {
                    count_dropped(&self.stats, events.len() as u64, "refused by the control plane");
                    self.spool.remove(id);
                }
            }
            self.stats.backlog.store(self.spool.len() as u64, Ordering::Relaxed);
        }
    }
}

/// The backlog: batches in arrival order, on disk (one JSONL segment per batch) or in memory.
pub struct Spool {
    dir: Option<PathBuf>,
    /// `(segment id, events)`: on disk the events are only counted, and read back when sent.
    segments: VecDeque<(u64, Segment)>,
    next_id: u64,
    len: usize,
}

enum Segment {
    Memory(Vec<UsageEvent>),
    Disk(usize),
}

impl Spool {
    pub fn memory() -> Self {
        Self { dir: None, segments: VecDeque::new(), next_id: 0, len: 0 }
    }

    /// Opens (creating it, mode 0700) a spool directory and counts the segments left by an
    /// earlier run. Unreadable lines are skipped with a warning when the segment is sent.
    pub fn open_dir(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut ids: Vec<u64> = std::fs::read_dir(dir)?
            .filter_map(|e| {
                let name = e.ok()?.file_name().into_string().ok()?;
                u64::from_str_radix(name.strip_prefix("usage-")?.strip_suffix(".jsonl")?, 16).ok()
            })
            .collect();
        ids.sort_unstable();
        let mut s = Self { dir: Some(dir.to_owned()), segments: VecDeque::new(), next_id: 0, len: 0 };
        for id in ids {
            let f = std::fs::File::open(s.path(id))?;
            let n = std::io::BufReader::new(f).lines().map_while(Result::ok).filter(|l| !l.trim().is_empty()).count();
            s.segments.push_back((id, Segment::Disk(n)));
            s.len += n;
            s.next_id = id + 1;
        }
        Ok(s)
    }

    fn path(&self, id: u64) -> PathBuf {
        self.dir.as_ref().map(|d| d.join(format!("usage-{id:016x}.jsonl"))).unwrap_or_default()
    }

    /// Events in the backlog.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends a batch (on disk: written to a temporary file, synced, then renamed).
    pub fn push(&mut self, events: Vec<UsageEvent>) -> std::io::Result<()> {
        let id = self.next_id;
        let n = events.len();
        let seg = match &self.dir {
            None => Segment::Memory(events),
            Some(_) => {
                let path = self.path(id);
                let tmp = path.with_extension("tmp");
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
                let mut f = std::io::BufWriter::new(opts.open(&tmp)?);
                for e in &events {
                    serde_json::to_writer(&mut f, e)?;
                    f.write_all(b"\n")?;
                }
                f.into_inner().map_err(std::io::IntoInnerError::into_error)?.sync_all()?;
                std::fs::rename(&tmp, &path)?;
                Segment::Disk(n)
            }
        };
        self.next_id += 1;
        self.segments.push_back((id, seg));
        self.len += n;
        Ok(())
    }

    /// The oldest batch, without removing it.
    pub fn oldest(&self) -> Option<(u64, Vec<UsageEvent>)> {
        let (id, seg) = self.segments.front()?;
        match seg {
            Segment::Memory(v) => Some((*id, v.clone())),
            Segment::Disk(_) => {
                let raw = match std::fs::read_to_string(self.path(*id)) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(error = %e, segment = id, "cannot read a usage spool segment");
                        return Some((*id, Vec::new()));
                    }
                };
                let mut bad = 0;
                let events = raw
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|l| serde_json::from_str(l).map_err(|_| bad += 1).ok())
                    .collect();
                if bad > 0 {
                    tracing::warn!(lines = bad, segment = id, "skipping unreadable lines of a usage spool segment");
                }
                Some((*id, events))
            }
        }
    }

    /// Removes a delivered batch (deletes its file).
    pub fn remove(&mut self, id: u64) {
        if let Some(pos) = self.segments.iter().position(|(i, _)| *i == id)
            && let Some((_, seg)) = self.segments.remove(pos)
        {
            self.len -= match seg {
                Segment::Memory(v) => v.len(),
                Segment::Disk(n) => n,
            };
            if self.dir.is_some()
                && let Err(e) = std::fs::remove_file(self.path(id))
            {
                tracing::warn!(error = %e, segment = id, "cannot delete a delivered usage spool segment");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn ev(id: &str) -> UsageEvent {
        serde_json::from_value(serde_json::json!({
            "request_id": id, "tenant_id": "acme", "model": "m", "intent": "chat", "prompt_tokens": 1,
            "completion_tokens": 2, "cached_prompt_tokens": 0, "tokens_saved": 0, "cache": "miss",
            "pii_entities": 0, "cost_usd": 0.0, "latency_ms": 1, "ts": "2026-10-10T12:00:00Z",
            "requested_model": "caliban/auto", "flat_price_usd": 0.001, "billed_usd": 0.001
        }))
        .unwrap()
    }

    /// A receiver that dedupes by `request_id`, and can be switched off.
    #[derive(Default)]
    struct Receiver {
        seen: parking_lot::Mutex<Vec<String>>,
        batches: AtomicU64,
        down: AtomicBool,
    }

    #[async_trait]
    impl UsageTransport for Receiver {
        async fn send(&self, events: &[UsageEvent]) -> Result<Delivered, ShipError> {
            if self.down.load(Ordering::SeqCst) {
                return Err(ShipError::Retry("connection refused".into()));
            }
            self.batches.fetch_add(1, Ordering::SeqCst);
            let mut seen = self.seen.lock();
            let mut d = Delivered::default();
            for e in events {
                if seen.contains(&e.request_id) {
                    d.duplicates += 1;
                } else {
                    seen.push(e.request_id.clone());
                    d.accepted += 1;
                }
            }
            Ok(d)
        }
    }

    fn dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("caliban-ship-{}-{name}", uuid::Uuid::now_v7().simple()))
    }

    fn fast(spool_dir: Option<PathBuf>) -> ShipOptions {
        ShipOptions {
            batch_max: 10,
            interval: Duration::from_millis(20),
            spool_dir,
            retry_min: Duration::from_millis(20),
            retry_max: Duration::from_millis(40),
            ..ShipOptions::default()
        }
    }

    async fn until(what: &str, f: impl Fn() -> bool) {
        for _ in 0..500 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test]
    async fn batches_by_size_and_by_interval() {
        let rx = Arc::new(Receiver::default());
        let s =
            UsageShipper::start(rx.clone(), ShipOptions { interval: Duration::from_secs(3600), ..fast(None) }).unwrap();
        for i in 0..25 {
            s.record(ev(&format!("r{i}"))).await;
        }
        // Two full batches go at once; the last 5 wait for the interval (an hour here).
        until("two batches", || rx.batches.load(Ordering::SeqCst) == 2).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(rx.seen.lock().len(), 20);
        s.flush().await;
        assert_eq!(rx.seen.lock().len(), 25);

        let rx = Arc::new(Receiver::default());
        let s = UsageShipper::start(rx.clone(), fast(None)).unwrap();
        s.record(ev("lonely")).await;
        until("the interval batch", || rx.seen.lock().len() == 1).await;
        assert_eq!(ShipStats::n(&s.stats().delivered), 1);
    }

    #[tokio::test]
    async fn an_outage_is_spooled_to_disk_and_delivered_after_a_restart() {
        let d = dir("outage");
        let rx = Arc::new(Receiver { down: AtomicBool::new(true), ..Receiver::default() });
        let s = UsageShipper::start(rx.clone(), fast(Some(d.clone()))).unwrap();
        for i in 0..35 {
            s.record(ev(&format!("r{i}"))).await;
        }
        s.shutdown(Duration::from_millis(100)).await;
        assert_eq!(ShipStats::n(&s.stats().backlog), 35);
        assert_eq!(ShipStats::n(&s.stats().dropped), 0);
        assert!(std::fs::read_dir(&d).unwrap().count() >= 4, "one segment per batch");

        // Restarted router, control plane back: the backlog goes out, oldest first, and the spool
        // is emptied.
        rx.down.store(false, Ordering::SeqCst);
        let s = UsageShipper::start(rx.clone(), fast(Some(d.clone()))).unwrap();
        assert_eq!(ShipStats::n(&s.stats().backlog), 35);
        until("the backlog", || rx.seen.lock().len() == 35).await;
        until("an empty backlog", || ShipStats::n(&s.stats().backlog) == 0).await;
        assert_eq!(rx.seen.lock()[0], "r0");
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn a_segment_sent_twice_is_counted_once() {
        // A crash between the acknowledgement and the deletion of the segment.
        let d = dir("crash");
        let rx = Arc::new(Receiver::default());
        let mut spool = Spool::open_dir(&d).unwrap();
        spool.push(vec![ev("a"), ev("b")]).unwrap();
        rx.send(&[ev("a"), ev("b")]).await.unwrap();
        drop(spool);
        let s = UsageShipper::start(rx.clone(), fast(Some(d.clone()))).unwrap();
        until("the retry", || ShipStats::n(&s.stats().duplicates) == 2).await;
        assert_eq!((rx.seen.lock().len(), ShipStats::n(&s.stats().delivered)), (2, 0));
        until("an empty backlog", || ShipStats::n(&s.stats().backlog) == 0).await;
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn bounded_backlog_and_queue_drop_and_count() {
        let rx = Arc::new(Receiver { down: AtomicBool::new(true), ..Receiver::default() });
        let s = UsageShipper::start(rx.clone(), ShipOptions { spool_max_events: 15, ..fast(None) }).unwrap();
        for i in 0..40 {
            s.record(ev(&format!("r{i}"))).await;
        }
        s.flush().await;
        assert_eq!((ShipStats::n(&s.stats().backlog), ShipStats::n(&s.stats().dropped)), (15, 25));
        let (_, st) = s.status().remove(0);
        assert_eq!(
            (st["backlog"].as_u64(), st["dropped"].as_u64(), st["spool"].as_str()),
            (Some(15), Some(25), Some("memory"))
        );
        let mut m = String::new();
        s.metrics(&mut m);
        assert!(m.contains("caliban_usage_ship_dropped_total 25\n") && m.contains("caliban_usage_ship_backlog 15\n"));
        // Back up: the backlog is delivered; a memory backlog left at shutdown would be dropped.
        rx.down.store(false, Ordering::SeqCst);
        until("the backlog", || rx.seen.lock().len() == 15).await;
        s.shutdown(Duration::from_millis(50)).await;
        assert_eq!(ShipStats::n(&s.stats().dropped), 25);
    }

    #[tokio::test]
    async fn a_refused_batch_is_dropped_not_retried_forever() {
        struct Refuses;
        #[async_trait]
        impl UsageTransport for Refuses {
            async fn send(&self, _: &[UsageEvent]) -> Result<Delivered, ShipError> {
                Err(ShipError::Fatal("400 malformed".into()))
            }
        }
        let s = UsageShipper::start(Arc::new(Refuses), fast(None)).unwrap();
        s.record(ev("x")).await;
        s.flush().await;
        assert_eq!((ShipStats::n(&s.stats().dropped), ShipStats::n(&s.stats().backlog)), (1, 0));
    }
}
