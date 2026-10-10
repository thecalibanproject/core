//! Usage write-ahead log: one JSON object per line (JSONL), appended in event order.
//!
//! The request path only enqueues the event on a bounded channel. A background writer task
//! serialises events into a buffer and appends it to a file handle it keeps open: it flushes
//! whenever the queue runs empty (so an idle gateway writes each event within microseconds of
//! the request), when the buffer reaches `max_batch_bytes` (so a busy one writes in batches), on
//! [`JsonlSink::flush`], and on [`JsonlSink::shutdown`]. File writes run on the blocking pool,
//! one per batch, never on an async worker.
//!
//! Durability: with [`FsyncPolicy::Off`] (the default, as before) data reaches the OS page cache
//! on every flush and survives a process crash, not a power loss; [`FsyncPolicy::Batch`] also
//! calls `fdatasync` after every flushed batch. Graceful shutdown always flushes and syncs.
//!
//! Backpressure: when the queue is full, `record` waits up to `enqueue_timeout` for room and then
//! drops the event, counting it (`dropped` in `/healthz`). A full queue means the disk is not
//! keeping up; the response path is never blocked for longer than that timeout.
//!
//! Log rotation: the writer checks about once per `flush_interval` whether the path still names
//! the open file (same device and inode on Unix) and reopens it if not, so `mv` plus a new file
//! works as it did when the file was opened per event.

use crate::{UsageEvent, UsageSink};
use async_trait::async_trait;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// When the WAL calls `fdatasync`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FsyncPolicy {
    /// Never on the write path (the OS writes back on its own); always on graceful shutdown.
    #[default]
    Off,
    /// After every flushed batch.
    Batch,
}

impl FsyncPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Batch => "batch",
        }
    }
}

impl std::str::FromStr for FsyncPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "never" | "none" => Ok(Self::Off),
            "batch" | "on" | "always" => Ok(Self::Batch),
            other => Err(format!("unknown usage WAL fsync policy {other:?} (off or batch)")),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WalOptions {
    /// Events the queue holds before `record` waits.
    pub queue: usize,
    /// Buffered bytes that force a write even while events keep arriving.
    pub max_batch_bytes: usize,
    /// Safety-net flush and rotation check period.
    pub flush_interval: Duration,
    /// How long `record` waits for room in a full queue before dropping the event.
    pub enqueue_timeout: Duration,
    pub fsync: FsyncPolicy,
}

impl Default for WalOptions {
    fn default() -> Self {
        Self {
            queue: 16_384,
            max_batch_bytes: 256 * 1024,
            flush_interval: Duration::from_secs(1),
            enqueue_timeout: Duration::from_millis(20),
            fsync: FsyncPolicy::Off,
        }
    }
}

/// Counters, exposed in `/healthz` under `usage_wal`.
#[derive(Debug, Default)]
pub struct WalStats {
    /// Events appended to the file.
    pub written: AtomicU64,
    /// Events lost: the queue stayed full for `enqueue_timeout`, or a batch could not be written.
    pub dropped: AtomicU64,
    /// Failed open, write or sync calls.
    pub write_errors: AtomicU64,
    /// `record` calls that found the queue full and had to wait.
    pub backpressure_waits: AtomicU64,
}

enum Msg {
    Event(Box<UsageEvent>),
    /// Write everything queued before this message, `fdatasync`, then reply.
    Flush(oneshot::Sender<()>),
}

/// The usage WAL sink. Create it inside a Tokio runtime (it spawns its writer task).
pub struct JsonlSink {
    tx: mpsc::Sender<Msg>,
    stats: Arc<WalStats>,
    opts: WalOptions,
}

impl JsonlSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_options(path, WalOptions::default())
    }

    pub fn with_options(path: impl Into<PathBuf>, opts: WalOptions) -> Self {
        let (tx, rx) = mpsc::channel(opts.queue.max(1));
        let stats = Arc::new(WalStats::default());
        let writer = Writer {
            path: path.into(),
            file: None,
            buf: Vec::with_capacity(opts.max_batch_bytes.min(1 << 20)),
            pending: 0,
            stats: Arc::clone(&stats),
            opts,
        };
        tokio::spawn(writer.run(rx));
        Self { tx, stats, opts }
    }

    pub fn stats(&self) -> &WalStats {
        &self.stats
    }

    /// Events waiting in the queue.
    pub fn queue_depth(&self) -> usize {
        self.tx.max_capacity() - self.tx.capacity()
    }

    /// Returns once every event recorded before this call is written and synced.
    pub async fn flush(&self) {
        let (ack, done) = oneshot::channel();
        if self.tx.send(Msg::Flush(ack)).await.is_ok() {
            let _ = done.await;
        }
    }

    /// Graceful shutdown: flushes, then keeps flushing while late events (streams that finish
    /// after the server stopped accepting) still arrive, for up to `grace`.
    pub async fn shutdown(&self, grace: Duration) {
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            let seen = self.stats.written.load(Ordering::Relaxed) + self.stats.dropped.load(Ordering::Relaxed);
            self.flush().await;
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50).min(grace)).await;
            let now = self.stats.written.load(Ordering::Relaxed) + self.stats.dropped.load(Ordering::Relaxed);
            if self.queue_depth() == 0 && now == seen {
                break;
            }
        }
        self.flush().await;
        tracing::info!(
            written = self.stats.written.load(Ordering::Relaxed),
            dropped = self.stats.dropped.load(Ordering::Relaxed),
            "usage WAL flushed"
        );
    }

    fn drop_event(&self, why: &'static str) {
        let n = self.stats.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if n == 1 || n.is_multiple_of(1000) {
            tracing::error!(dropped = n, why, "usage WAL dropped an event");
        }
    }
}

#[async_trait]
impl UsageSink for JsonlSink {
    async fn record(&self, event: UsageEvent) {
        match self.tx.try_send(Msg::Event(Box::new(event))) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(msg)) => {
                self.stats.backpressure_waits.fetch_add(1, Ordering::Relaxed);
                match tokio::time::timeout(self.opts.enqueue_timeout, self.tx.send(msg)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => self.drop_event("writer stopped"),
                    Err(_) => self.drop_event("queue full"),
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => self.drop_event("writer stopped"),
        }
    }

    fn status(&self) -> Vec<(&'static str, serde_json::Value)> {
        let s = &self.stats;
        vec![(
            "usage_wal",
            serde_json::json!({
                "written": s.written.load(Ordering::Relaxed),
                "dropped": s.dropped.load(Ordering::Relaxed),
                "write_errors": s.write_errors.load(Ordering::Relaxed),
                "backpressure_waits": s.backpressure_waits.load(Ordering::Relaxed),
                "queue_depth": self.queue_depth(),
                "queue_capacity": self.tx.max_capacity(),
                "fsync": self.opts.fsync.as_str(),
            }),
        )]
    }

    fn metrics(&self, out: &mut String) {
        let s = &self.stats;
        #[allow(clippy::cast_precision_loss)]
        let n = |a: &AtomicU64| a.load(Ordering::Relaxed) as f64;
        crate::prometheus_sample(
            out,
            "caliban_usage_wal_written_total",
            "counter",
            "Usage events appended to the WAL.",
            n(&s.written),
        );
        crate::prometheus_sample(
            out,
            "caliban_usage_wal_dropped_total",
            "counter",
            "Usage events the WAL lost.",
            n(&s.dropped),
        );
        crate::prometheus_sample(
            out,
            "caliban_usage_wal_write_errors_total",
            "counter",
            "Failed WAL open, write or sync calls.",
            n(&s.write_errors),
        );
    }
}

struct Writer {
    path: PathBuf,
    file: Option<File>,
    buf: Vec<u8>,
    /// Events in `buf`.
    pending: u64,
    stats: Arc<WalStats>,
    opts: WalOptions,
}

impl Writer {
    async fn run(mut self, mut rx: mpsc::Receiver<Msg>) {
        let mut tick = tokio::time::interval(self.opts.flush_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                msg = rx.recv() => match msg {
                    Some(Msg::Event(e)) => {
                        match serde_json::to_writer(&mut self.buf, &e) {
                            Ok(()) => {
                                self.buf.push(b'\n');
                                self.pending += 1;
                            }
                            Err(err) => {
                                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                                tracing::error!(error = %err, "usage WAL: event not serialisable");
                            }
                        }
                        if self.buf.len() >= self.opts.max_batch_bytes || rx.is_empty() {
                            self.flush(self.opts.fsync == FsyncPolicy::Batch).await;
                        }
                    }
                    Some(Msg::Flush(ack)) => {
                        self.flush(true).await;
                        let _ = ack.send(());
                    }
                    None => {
                        self.flush(true).await;
                        break;
                    }
                },
                _ = tick.tick() => {
                    if !self.buf.is_empty() {
                        self.flush(self.opts.fsync == FsyncPolicy::Batch).await;
                    }
                    self.check_rotation().await;
                }
            }
        }
    }

    /// Appends the buffer (one blocking write), optionally followed by `fdatasync`.
    async fn flush(&mut self, sync: bool) {
        if self.buf.is_empty() && !(sync && self.file.is_some()) {
            return;
        }
        let path = self.path.clone();
        let file = self.file.take();
        let buf = std::mem::take(&mut self.buf);
        let res = tokio::task::spawn_blocking(move || {
            let mut f = match file {
                Some(f) => f,
                None => match open(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!(error = %e, path = %path.display(), "usage WAL: open failed");
                        return (None, buf, 1, false);
                    }
                },
            };
            match f.write_all(&buf).and_then(|()| if sync { f.sync_data() } else { Ok(()) }) {
                Ok(()) => (Some(f), buf, 0, true),
                Err(e) => {
                    // Not retried (a partial write would duplicate lines); the next batch reopens.
                    tracing::error!(error = %e, path = %path.display(), "usage WAL: write failed");
                    (None, buf, 1, false)
                }
            }
        })
        .await;
        match res {
            Ok((file, mut buf, errors, ok)) => {
                self.file = file;
                self.stats.write_errors.fetch_add(errors, Ordering::Relaxed);
                let n = std::mem::take(&mut self.pending);
                if ok {
                    self.stats.written.fetch_add(n, Ordering::Relaxed);
                } else {
                    self.stats.dropped.fetch_add(n, Ordering::Relaxed);
                }
                buf.clear();
                self.buf = buf;
            }
            Err(e) => {
                // The blocking task panicked; the batch is lost.
                self.stats.write_errors.fetch_add(1, Ordering::Relaxed);
                self.stats.dropped.fetch_add(std::mem::take(&mut self.pending), Ordering::Relaxed);
                tracing::error!(error = %e, "usage WAL: writer task failed");
            }
        }
    }

    /// Reopens the file when the path no longer names the open file (rotated or removed).
    async fn check_rotation(&mut self) {
        let Some(f) = self.file.take() else { return };
        let path = self.path.clone();
        self.file = tokio::task::spawn_blocking(move || if same_file(&f, &path) { Some(f) } else { None })
            .await
            .unwrap_or(None);
    }
}

fn open(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(unix)]
fn same_file(f: &File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (f.metadata(), std::fs::metadata(path)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_file(_: &File, path: &Path) -> bool {
    path.exists()
}

/// Reads a usage WAL back (replay, billing export, tests). Lines that do not parse (a torn last
/// line after a crash) are skipped, the same way the bench harness reads the file.
pub fn read_wal(path: impl AsRef<Path>) -> std::io::Result<Vec<UsageEvent>> {
    let s = std::fs::read_to_string(path)?;
    Ok(s.lines().filter(|l| !l.trim().is_empty()).filter_map(|l| serde_json::from_str(l).ok()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UsageSource;
    use caliban_types::{CacheStatus, CacheTier};
    use serde_json::Value;

    fn event(i: u64) -> UsageEvent {
        UsageEvent {
            request_id: format!("req_{i}"),
            tenant_id: "acme".into(),
            model: "m".into(),
            intent: "chat".into(),
            prompt_tokens: 10 + i,
            completion_tokens: 5,
            cached_prompt_tokens: 2,
            cache_write_tokens: i % 3,
            cache_write_1h_tokens: 0,
            tokens_saved: 0,
            cache: CacheStatus::Miss,
            cache_tier: None,
            usage_source: Some(if i.is_multiple_of(2) { UsageSource::Provider } else { UsageSource::Estimated }),
            pii_entities: 0,
            cost_usd: Some(0.001),
            latency_ms: 3,
            ts: chrono::Utc::now(),
            requested_model: None,
            intent_confidence: None,
            route_stage: None,
            routed_model_cost_usd: None,
            flat_price_usd: None,
            billed_usd: None,
            saved_usd: None,
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("caliban-wal-{}-{name}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("usage.jsonl")
    }

    #[tokio::test]
    async fn events_are_appended_in_order_and_replayable() {
        let path = tmp("order");
        // An existing WAL (written by an older build: no usage_source, no cache writes) is
        // appended to, never truncated.
        let old = r#"{"request_id":"old_1","tenant_id":"acme","model":"m","intent":"chat","prompt_tokens":7,"completion_tokens":1,"cached_prompt_tokens":0,"tokens_saved":0,"cache":"hit","cache_tier":"exact","pii_entities":0,"cost_usd":null,"latency_ms":1,"ts":"2026-10-01T12:00:00Z"}"#;
        std::fs::write(&path, format!("{old}\n")).unwrap();
        let sink = JsonlSink::new(&path);
        let events: Vec<UsageEvent> = (0..500).map(event).collect();
        for e in &events {
            sink.record(e.clone()).await;
        }
        sink.shutdown(Duration::from_millis(200)).await;
        assert_eq!(sink.stats().written.load(Ordering::Relaxed), 500);
        assert_eq!(sink.stats().dropped.load(Ordering::Relaxed), 0);

        let back = read_wal(&path).unwrap();
        assert_eq!(back.len(), 501);
        assert_eq!(
            (back[0].request_id.as_str(), back[0].cache_tier, back[0].usage_source),
            ("old_1", Some(CacheTier::Exact), None)
        );
        assert_eq!((back[0].billed_usd, back[0].saved_usd), (None, None), "older lines have no billing fields");
        assert_eq!(&back[1..], &events[..], "same events, same order");

        // The format is unchanged: one JSON object per line, readable as plain JSON (the bench
        // harness and billing exports parse it line by line), new fields only when set.
        let raw = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<Value> = raw.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines.len(), 501);
        assert_eq!(lines[1], serde_json::to_value(&events[0]).unwrap());
        assert_eq!(lines[1]["usage_source"], "provider");
        assert!(lines[1].get("cache_write_tokens").is_none(), "zero cache writes are omitted");
        assert_eq!(lines[2]["usage_source"], "estimated");
        assert_eq!(lines[2]["cache_write_tokens"], 1);
    }

    #[tokio::test]
    async fn an_idle_writer_flushes_without_being_asked() {
        let path = tmp("idle");
        let sink = JsonlSink::new(&path);
        sink.record(event(1)).await;
        for _ in 0..100 {
            if read_wal(&path).map(|v| v.len()).unwrap_or(0) == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("event not written within 500 ms");
    }

    #[tokio::test]
    async fn lost_events_are_counted_and_record_never_blocks() {
        // The writer cannot open a path inside a missing directory: every batch fails, and with a
        // queue of 1 some events are also dropped after the enqueue timeout. Either way each one
        // is counted, and `record` returns quickly.
        let path = std::env::temp_dir()
            .join(format!("caliban-wal-missing-{}", uuid::Uuid::now_v7().simple()))
            .join("usage.jsonl");
        let opts = WalOptions { queue: 1, enqueue_timeout: Duration::from_millis(5), ..WalOptions::default() };
        let sink = JsonlSink::with_options(&path, opts);
        let started = std::time::Instant::now();
        for i in 0..200 {
            sink.record(event(i)).await;
        }
        assert!(started.elapsed() < Duration::from_secs(5), "record never blocks for long");
        sink.flush().await;
        let s = sink.stats();
        assert_eq!(s.written.load(Ordering::Relaxed), 0);
        assert_eq!(s.dropped.load(Ordering::Relaxed), 200, "every event is accounted for as dropped");
        assert!(s.write_errors.load(Ordering::Relaxed) > 0);
        let status = sink.status();
        let (key, st) = status.first().unwrap();
        assert_eq!(*key, "usage_wal");
        assert_eq!(st["dropped"], 200);
        assert_eq!(st["queue_capacity"], 1);
        let mut m = String::new();
        sink.metrics(&mut m);
        assert!(m.contains("caliban_usage_wal_dropped_total 200\n"), "{m}");
    }

    #[tokio::test]
    async fn a_rotated_file_is_reopened() {
        let path = tmp("rotate");
        let opts = WalOptions { flush_interval: Duration::from_millis(20), ..WalOptions::default() };
        let sink = JsonlSink::with_options(&path, opts);
        sink.record(event(1)).await;
        sink.flush().await;
        let rotated = path.with_extension("jsonl.1");
        std::fs::rename(&path, &rotated).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        sink.record(event(2)).await;
        sink.flush().await;
        assert_eq!(read_wal(&rotated).unwrap().len(), 1);
        assert_eq!(read_wal(&path).unwrap()[0].request_id, "req_2");
    }

    #[test]
    fn fsync_policy_parses() {
        assert_eq!("batch".parse::<FsyncPolicy>().unwrap(), FsyncPolicy::Batch);
        assert_eq!("".parse::<FsyncPolicy>().unwrap(), FsyncPolicy::Off);
        assert!("sometimes".parse::<FsyncPolicy>().is_err());
    }
}
