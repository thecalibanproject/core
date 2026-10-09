//! Closed-loop load generator: `concurrency` workers each send one request at a time, back to
//! back, until `requests` have completed. Latencies go into HDR histograms (nanoseconds, 3
//! significant digits).
//!
//! - Total latency: request sent until the whole body has been read.
//! - TTFB (streams): request sent until the first body chunk arrives (the first SSE frame;
//!   response headers alone do not count).

use bytes::Bytes;
use hdrhistogram::Histogram;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// One request shape, sent repeatedly.
#[derive(Debug, Clone)]
pub struct Target {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// Read the body as a stream and record TTFB.
    pub stream: bool,
    /// The body must contain this (e.g. `[DONE]` or `message_stop`), or the request counts as an error.
    pub expect: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Stats {
    pub total: Histogram<u64>,
    pub ttfb: Histogram<u64>,
    pub ok: u64,
    pub errors: u64,
    pub wall: Duration,
}

fn hist() -> Histogram<u64> {
    Histogram::new_with_bounds(1_000, 120_000_000_000, 3).expect("histogram bounds")
}

impl Stats {
    pub fn empty() -> Self {
        Self {
            total: hist(),
            ttfb: hist(),
            ok: 0,
            errors: 0,
            wall: Duration::ZERO,
        }
    }

    pub fn merge(&mut self, o: &Stats) {
        let _ = self.total.add(&o.total);
        let _ = self.ttfb.add(&o.ttfb);
        self.ok += o.ok;
        self.errors += o.errors;
        self.wall += o.wall;
    }

    pub fn throughput(&self) -> f64 {
        if self.wall.is_zero() {
            0.0
        } else {
            self.ok as f64 / self.wall.as_secs_f64()
        }
    }
}

async fn one(client: &reqwest::Client, t: &Target) -> Result<(Duration, Option<Duration>), String> {
    let start = Instant::now();
    let mut req = client.post(&t.url).body(t.body.clone());
    for (k, v) in &t.headers {
        req = req.header(k, v);
    }
    let mut resp = req.send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "{s}: {}",
            body.chars().take(300).collect::<String>()
        ));
    }
    let mut ttfb = None;
    let mut body = Vec::new();
    if t.stream {
        while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
            if ttfb.is_none() && !chunk.is_empty() {
                ttfb = Some(start.elapsed());
            }
            body.extend_from_slice(&chunk);
        }
    } else {
        body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
    }
    let total = start.elapsed();
    if let Some(exp) = &t.expect
        && !body.windows(exp.len()).any(|w| w == exp.as_bytes())
    {
        return Err(format!(
            "response lacks {exp:?}: {}",
            String::from_utf8_lossy(&body)
                .chars()
                .take(300)
                .collect::<String>()
        ));
    }
    Ok((total, ttfb))
}

/// Runs `requests` requests at `concurrency` and returns the merged stats. The first error
/// message is printed once.
pub async fn run(
    client: &reqwest::Client,
    target: &Target,
    concurrency: usize,
    requests: usize,
) -> Stats {
    let remaining = Arc::new(AtomicUsize::new(requests));
    let target = Arc::new(target.clone());
    let started = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..concurrency.max(1) {
        let (client, target, remaining) =
            (client.clone(), Arc::clone(&target), Arc::clone(&remaining));
        tasks.push(tokio::spawn(async move {
            let mut s = Stats::empty();
            let mut first_err: Option<String> = None;
            while take_one(&remaining) {
                match one(&client, &target).await {
                    Ok((total, ttfb)) => {
                        let _ = s.total.record(total.as_nanos() as u64);
                        if let Some(t) = ttfb {
                            let _ = s.ttfb.record(t.as_nanos() as u64);
                        }
                        s.ok += 1;
                    }
                    Err(e) => {
                        s.errors += 1;
                        first_err.get_or_insert(e);
                    }
                }
            }
            (s, first_err)
        }));
    }
    let mut all = Stats::empty();
    let mut reported = false;
    for t in tasks {
        if let Ok((s, err)) = t.await {
            all.merge(&s);
            if let Some(e) = err
                && !reported
            {
                eprintln!("  request error ({}): {e}", target.url);
                reported = true;
            }
        }
    }
    all.wall = started.elapsed();
    all
}

/// Milliseconds at a quantile (0..=1; 1.0 is the max).
pub fn ms(h: &Histogram<u64>, q: f64) -> f64 {
    if h.is_empty() {
        return f64::NAN;
    }
    let ns = if q >= 1.0 {
        h.max()
    } else {
        h.value_at_quantile(q)
    };
    ns as f64 / 1e6
}

/// Claims one request from the shared budget; false once it is exhausted.
fn take_one(remaining: &AtomicUsize) -> bool {
    let mut n = remaining.load(Ordering::Acquire);
    while n > 0 {
        match remaining.compare_exchange_weak(n, n - 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(cur) => n = cur,
        }
    }
    false
}
