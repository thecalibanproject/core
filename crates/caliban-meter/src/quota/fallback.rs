//! Shared store with a local safety net: Valkey when it answers, this router's in-memory limiter
//! when it does not.
//!
//! Failure policy (fail open on shared state, never unlimited):
//! - Every Valkey call is bounded by the store's timeout (default 30 ms). A refusal (`429`) from
//!   Valkey is final; only errors and timeouts fall back.
//! - On an error the call is served by the local [`InMemoryQuota`] with the same limits, and the
//!   circuit opens for [`RETRY_AFTER`]: calls go straight to the local limiter (no added
//!   latency) until one probe call tries Valkey again. A successful probe closes the circuit.
//! - Settlement goes to the store that made the reservation. A Valkey settlement that fails (or
//!   is skipped while the circuit is open) leaves the reservation charged: the minute bucket
//!   refills within a minute; day counters stay over-counted by the unsettled estimate.
//! - While degraded, each router enforces the full limits on its own, so the deployment-wide
//!   ceiling is up to N times the limit for N routers, and day budgets restart from zero locally.
//! - Logs one warning when it degrades and at most one every [`WARN_EVERY`] after that (with the
//!   number of calls served locally), and an info line on recovery. [`QuotaStore::status`]
//!   reports `degraded` with the last error for the health endpoint.

use super::valkey::ValkeyQuota;
use super::{Amount, InMemoryQuota, QuotaError, QuotaPolicy, QuotaStatus, QuotaStore, Reservation};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How long the circuit stays open before one call probes Valkey again.
pub const RETRY_AFTER: Duration = Duration::from_secs(2);
/// Minimum interval between "still degraded" warnings.
pub const WARN_EVERY: Duration = Duration::from_secs(30);

pub struct FallbackQuota {
    shared: ValkeyQuota,
    local: InMemoryQuota,
    breaker: Breaker,
}

impl FallbackQuota {
    pub fn new(shared: ValkeyQuota) -> Self {
        Self { shared, local: InMemoryQuota::new(), breaker: Breaker::new(RETRY_AFTER) }
    }

    /// Same, with a custom probe interval (tests).
    pub fn with_retry_after(shared: ValkeyQuota, retry_after: Duration) -> Self {
        Self { shared, local: InMemoryQuota::new(), breaker: Breaker::new(retry_after) }
    }

    /// The shared store.
    pub fn shared(&self) -> &ValkeyQuota {
        &self.shared
    }

    /// Pings Valkey once (bounded by `limit`) and records the outcome; for start-up.
    pub async fn probe(&self, limit: Duration) -> bool {
        match self.shared.ping_within(limit).await {
            Ok(()) => {
                self.breaker.success(self.shared.endpoint());
                true
            }
            Err(e) => {
                self.breaker.failure(self.shared.endpoint(), &e);
                false
            }
        }
    }

    /// The local fallback store (diagnostics and tests).
    pub fn local(&self) -> &InMemoryQuota {
        &self.local
    }

    /// Calls served by the local limiter since start.
    pub fn fallbacks(&self) -> u64 {
        self.breaker.fallbacks.load(Ordering::Relaxed)
    }

    fn fell_back(&self) {
        self.breaker.fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    /// Runs `shared` unless the circuit is open; returns `None` when the caller must go local.
    async fn try_shared<T>(&self, shared: impl Future<Output = Result<T, QuotaError>>) -> Option<Result<T, QuotaError>> {
        if !self.breaker.allow() {
            self.fell_back();
            return None;
        }
        match shared.await {
            Err(QuotaError::Backend(msg)) => {
                self.breaker.failure(self.shared.endpoint(), &QuotaError::Backend(msg));
                self.fell_back();
                None
            }
            other => {
                self.breaker.success(self.shared.endpoint());
                Some(other)
            }
        }
    }
}

#[async_trait]
impl QuotaStore for FallbackQuota {
    async fn check_rate(&self, tenant: &str, key: Option<&str>, policy: &QuotaPolicy) -> Result<(), QuotaError> {
        // Nothing to check: do not touch Valkey, and do not count it as a probe.
        if policy.requests_per_minute.is_none() && (policy.key_requests_per_minute.is_none() || key.is_none()) {
            return Ok(());
        }
        match self.try_shared(self.shared.check_rate(tenant, key, policy)).await {
            Some(r) => r,
            None => self.local.check_rate(tenant, key, policy).await,
        }
    }

    async fn reserve(&self, tenant: &str, policy: &QuotaPolicy, amount: Amount) -> Result<Reservation, QuotaError> {
        if !policy.has_budgets() {
            return self.local.reserve(tenant, policy, amount).await;
        }
        match self.try_shared(self.shared.reserve(tenant, policy, amount)).await {
            Some(r) => r,
            None => self.local.reserve(tenant, policy, amount).await.map(|r| Reservation { local: true, ..r }),
        }
    }

    async fn settle(&self, r: &Reservation, actual: Amount) {
        if !r.tracked {
            return;
        }
        if r.local {
            return self.local.settle(r, actual).await;
        }
        let lost = match self.try_shared(self.shared.try_settle(r, actual)).await {
            Some(res) => res.err(),
            None => Some(QuotaError::Backend("circuit open".into())),
        };
        if let Some(e) = lost {
            self.breaker.settlements_lost.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(error = %e, tenant = %r.tenant, "valkey settlement lost; the reservation stays charged");
        }
    }

    fn status(&self) -> QuotaStatus {
        let degraded = self.breaker.degraded.load(Ordering::Relaxed);
        QuotaStatus {
            store: "valkey",
            state: if degraded { "degraded" } else { "ok" },
            endpoint: Some(self.shared.endpoint().to_owned()),
            detail: degraded.then(|| {
                let err = self.breaker.last_error.lock().clone().unwrap_or_default();
                format!("valkey unreachable, limiting locally on this router: {err}")
            }),
            local_fallbacks: self.fallbacks(),
            settlements_lost: self.breaker.settlements_lost.load(Ordering::Relaxed),
        }
    }
}

/// Circuit breaker with a single half-open probe and rate-limited logging.
struct Breaker {
    retry_after: Duration,
    epoch: Instant,
    degraded: AtomicBool,
    /// Milliseconds since `epoch` before which calls skip Valkey.
    open_until_ms: AtomicU64,
    fallbacks: AtomicU64,
    settlements_lost: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// Last warning, and the fallback count at that time.
    last_warn: Mutex<Option<(Instant, u64)>>,
}

impl Breaker {
    fn new(retry_after: Duration) -> Self {
        Self {
            retry_after,
            epoch: Instant::now(),
            degraded: AtomicBool::new(false),
            open_until_ms: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
            settlements_lost: AtomicU64::new(0),
            last_error: Mutex::new(None),
            last_warn: Mutex::new(None),
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn retry_ms(&self) -> u64 {
        u64::try_from(self.retry_after.as_millis()).unwrap_or(u64::MAX)
    }

    /// Closed: always. Open: one caller (the probe) per `retry_after`. The probe pushes the
    /// window forward before it runs, so a probe that is cancelled midway cannot wedge the
    /// breaker: the next one simply happens a window later.
    fn allow(&self) -> bool {
        if !self.degraded.load(Ordering::Acquire) {
            return true;
        }
        let now = self.now_ms();
        let until = self.open_until_ms.load(Ordering::Acquire);
        now >= until
            && self
                .open_until_ms
                .compare_exchange(until, now.saturating_add(self.retry_ms()), Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    fn success(&self, endpoint: &str) {
        if self.degraded.swap(false, Ordering::AcqRel) {
            let served = self.fallbacks.load(Ordering::Relaxed);
            tracing::info!(valkey = endpoint, local_fallbacks = served, "valkey quota store reachable again; shared limits restored");
            *self.last_warn.lock() = None;
        }
    }

    fn failure(&self, endpoint: &str, e: &QuotaError) {
        let retry_ms = self.retry_ms();
        self.open_until_ms.store(self.now_ms().saturating_add(retry_ms), Ordering::Release);
        let first = !self.degraded.swap(true, Ordering::AcqRel);
        *self.last_error.lock() = Some(e.to_string());

        let served = self.fallbacks.load(Ordering::Relaxed);
        let mut last = self.last_warn.lock();
        let due = first || last.is_none_or(|(at, _)| at.elapsed() >= WARN_EVERY);
        if due {
            let since = last.map_or(0, |(_, n)| served.saturating_sub(n));
            *last = Some((Instant::now(), served));
            drop(last);
            tracing::warn!(
                valkey = endpoint,
                error = %e,
                local_calls_since_last_warning = since,
                retry_ms,
                "valkey quota store unavailable; limiting locally on this router (shared limits not enforced across routers)"
            );
        }
    }
}
