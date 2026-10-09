//! Rate limits and token budgets (request lifecycle stage 3; settlement is stage 13).
//!
//! - **Request rate**: GCRA per tenant and, optionally, per API key.
//! - **Token budgets**: tokens per minute (a token bucket that refills continuously), tokens per
//!   UTC day, and USD per UTC day.
//!
//! Budgets work by *reservation*: before the upstream call the gateway reserves an estimate
//! (prompt-token estimate + `max_tokens`, and the matching cost), and after the call it settles
//! the reservation against the usage the upstream reported. Over-estimates are refunded;
//! under-estimates leave the minute bucket in debt so the next request waits.
//!
//! Stores ([`QuotaStore`]):
//! - [`InMemoryQuota`]: exact for one router process (`[limits] store = "memory"`, the default).
//! - [`ValkeyQuota`]: shared by every router of a deployment; each check is one atomic Lua script
//!   on the server, so routers cannot double-spend (see [`valkey`]).
//! - [`FallbackQuota`]: what `store = "valkey"` runs: Valkey, with this router's in-memory
//!   limiter as the fallback while Valkey is unreachable (see [`fallback`] for the policy).

pub mod fallback;
pub mod valkey;

pub use fallback::FallbackQuota;
pub use valkey::{ValkeyOptions, ValkeyQuota};

use async_trait::async_trait;
use governor::clock::{Clock, DefaultClock};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Effective limits for one tenant. `None` = unlimited.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QuotaPolicy {
    pub requests_per_minute: Option<u32>,
    /// Applied to each API key separately (on top of the tenant-wide rate).
    pub key_requests_per_minute: Option<u32>,
    pub tokens_per_minute: Option<u64>,
    pub tokens_per_day: Option<u64>,
    pub usd_per_day: Option<f64>,
}

impl QuotaPolicy {
    pub fn has_budgets(&self) -> bool {
        self.tokens_per_minute.is_some() || self.tokens_per_day.is_some() || self.usd_per_day.is_some()
    }
}

/// Which limit was hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    Requests,
    KeyRequests,
    TokensPerMinute,
    TokensPerDay,
    UsdPerDay,
}

impl LimitScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requests => "requests_per_minute",
            Self::KeyRequests => "key_requests_per_minute",
            Self::TokensPerMinute => "tokens_per_minute",
            Self::TokensPerDay => "tokens_per_day",
            Self::UsdPerDay => "usd_per_day",
        }
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum QuotaError {
    #[error("{} limit exceeded; retry after {}s", .scope.as_str(), retry_secs(*.retry_after))]
    Exceeded { scope: LimitScope, retry_after: Duration },
    /// The shared store is unreachable. Callers decide whether to fail open or closed.
    #[error("quota backend unavailable: {0}")]
    Backend(String),
}

/// Whole seconds for a `Retry-After` header (at least 1).
pub fn retry_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0).max(u64::from(d.is_zero()))
}

/// Tokens and money, reserved or actually used.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Amount {
    pub tokens: u64,
    pub usd: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Reservation {
    pub tenant: String,
    pub amount: Amount,
    /// UTC day (days since the epoch) the reservation was counted in.
    pub day: i64,
    /// False when the tenant had no budgets at reservation time (settling is then a no-op).
    pub tracked: bool,
    /// Made in this router's local fallback store rather than the shared one; settled there too.
    pub local: bool,
}

/// What a store reports on the health endpoint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct QuotaStatus {
    /// `memory` or `valkey`.
    pub store: &'static str,
    /// `ok`, or `degraded` while a shared store is unreachable and limits are local.
    pub state: &'static str,
    /// Shared store address, password redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Quota calls served by the local fallback since start.
    pub local_fallbacks: u64,
    /// Shared-store settlements that failed (those reservations stay charged).
    pub settlements_lost: u64,
}

impl Default for QuotaStatus {
    fn default() -> Self {
        Self { store: "memory", state: "ok", endpoint: None, detail: None, local_fallbacks: 0, settlements_lost: 0 }
    }
}

#[async_trait]
pub trait QuotaStore: Send + Sync {
    /// GCRA request-rate check for the tenant and (optionally) the API key.
    async fn check_rate(&self, tenant: &str, key: Option<&str>, policy: &QuotaPolicy) -> Result<(), QuotaError>;

    /// Reserves `amount` against the tenant's token/USD budgets.
    async fn reserve(&self, tenant: &str, policy: &QuotaPolicy, amount: Amount) -> Result<Reservation, QuotaError>;

    /// Replaces the reserved amount with what was actually used.
    async fn settle(&self, reservation: &Reservation, actual: Amount);

    /// Health detail (store kind, degraded or not).
    fn status(&self) -> QuotaStatus {
        QuotaStatus::default()
    }
}

// ─────────────────────────────── in-memory store ───────────────────────────────

/// Single-process store. Limiter state is created lazily per tenant/key and recreated when the
/// configured rate changes (hot reload).
#[derive(Default)]
pub struct InMemoryQuota {
    rates: Mutex<HashMap<String, (u32, Arc<DefaultDirectRateLimiter>)>>,
    budgets: Mutex<HashMap<String, Budget>>,
}

#[derive(Debug)]
struct Budget {
    minute: Option<Bucket>,
    day: i64,
    day_tokens: u64,
    day_usd: f64,
}

/// Token bucket of `capacity` tokens refilling at `capacity / 60` per second. The level may go
/// negative when actual usage exceeds the reservation.
#[derive(Debug)]
struct Bucket {
    capacity: f64,
    level: f64,
    last: Instant,
}

impl Bucket {
    fn new(capacity: u64, now: Instant) -> Self {
        #[allow(clippy::cast_precision_loss)]
        let capacity = capacity as f64;
        Self { capacity, level: capacity, last: now }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.level = (self.level + dt * self.rate()).min(self.capacity);
        self.last = now;
    }

    fn rate(&self) -> f64 {
        self.capacity / 60.0
    }
}

pub(crate) fn utc_day_and_secs_left() -> (i64, u64) {
    let now = chrono::Utc::now().timestamp();
    (now.div_euclid(86_400), u64::try_from(86_400 - now.rem_euclid(86_400)).unwrap_or(1))
}

impl InMemoryQuota {
    pub fn new() -> Self {
        Self::default()
    }

    fn limiter(&self, key: String, rpm: u32) -> Arc<DefaultDirectRateLimiter> {
        let mut rates = self.rates.lock();
        match rates.get(&key) {
            Some((r, l)) if *r == rpm => Arc::clone(l),
            _ => {
                let per_min = NonZeroU32::new(rpm.max(1)).unwrap_or(NonZeroU32::MIN);
                let l = Arc::new(RateLimiter::direct(Quota::per_minute(per_min)));
                rates.insert(key, (rpm, Arc::clone(&l)));
                l
            }
        }
    }

    fn check_one(&self, key: String, rpm: u32, scope: LimitScope) -> Result<(), QuotaError> {
        let limiter = self.limiter(key, rpm);
        limiter.check().map_err(|not_until| QuotaError::Exceeded {
            scope,
            retry_after: not_until.wait_time_from(DefaultClock::default().now()),
        })
    }

    /// `reserve` with an explicit clock, for tests.
    fn reserve_at(&self, tenant: &str, policy: &QuotaPolicy, amount: Amount, now: Instant, day: i64, secs_left: u64) -> Result<Reservation, QuotaError> {
        if !policy.has_budgets() {
            return Ok(Reservation { tenant: tenant.to_owned(), amount, day, tracked: false, local: false });
        }
        let mut budgets = self.budgets.lock();
        let b = budgets
            .entry(tenant.to_owned())
            .or_insert_with(|| Budget { minute: None, day, day_tokens: 0, day_usd: 0.0 });
        if b.day != day {
            b.day = day;
            b.day_tokens = 0;
            b.day_usd = 0.0;
        }
        let until_midnight = Duration::from_secs(secs_left.max(1));

        if let Some(limit) = policy.tokens_per_day
            && b.day_tokens.saturating_add(amount.tokens) > limit
        {
            return Err(QuotaError::Exceeded { scope: LimitScope::TokensPerDay, retry_after: until_midnight });
        }
        if let Some(limit) = policy.usd_per_day
            && (b.day_usd >= limit || b.day_usd + amount.usd > limit)
        {
            return Err(QuotaError::Exceeded { scope: LimitScope::UsdPerDay, retry_after: until_midnight });
        }
        match (policy.tokens_per_minute, &mut b.minute) {
            (None, m) => *m = None,
            (Some(tpm), m) => {
                #[allow(clippy::cast_precision_loss)]
                let cap = tpm as f64;
                let bucket = match m {
                    Some(bk) if (bk.capacity - cap).abs() < f64::EPSILON => bk,
                    _ => m.insert(Bucket::new(tpm, now)),
                };
                bucket.refill(now);
                #[allow(clippy::cast_precision_loss)]
                let need = amount.tokens as f64;
                // A request bigger than the whole bucket is admitted once the bucket is full, so
                // it is not starved forever; the bucket then goes into debt.
                let full = bucket.level >= bucket.capacity;
                if bucket.level < need && !full {
                    let wait = (need.min(bucket.capacity) - bucket.level) / bucket.rate();
                    return Err(QuotaError::Exceeded { scope: LimitScope::TokensPerMinute, retry_after: Duration::from_secs_f64(wait.max(0.001)) });
                }
                bucket.level -= need;
            }
        }
        b.day_tokens = b.day_tokens.saturating_add(amount.tokens);
        b.day_usd += amount.usd;
        Ok(Reservation { tenant: tenant.to_owned(), amount, day, tracked: true, local: false })
    }

    fn settle_at(&self, r: &Reservation, actual: Amount, now: Instant) {
        if !r.tracked {
            return;
        }
        let mut budgets = self.budgets.lock();
        let Some(b) = budgets.get_mut(&r.tenant) else { return };
        if let Some(bucket) = &mut b.minute {
            bucket.refill(now);
            #[allow(clippy::cast_precision_loss)]
            let delta = r.amount.tokens as f64 - actual.tokens as f64;
            bucket.level = (bucket.level + delta).min(bucket.capacity);
        }
        if b.day == r.day {
            b.day_tokens = b.day_tokens.saturating_sub(r.amount.tokens).saturating_add(actual.tokens);
            b.day_usd = (b.day_usd - r.amount.usd).max(0.0) + actual.usd;
        } else {
            // The day rolled over while the request ran: charge what it used to the new day.
            b.day_tokens = b.day_tokens.saturating_add(actual.tokens);
            b.day_usd += actual.usd;
        }
    }

    /// Current per-day usage (tokens, USD) for a tenant; for diagnostics and tests.
    pub fn day_usage(&self, tenant: &str) -> (u64, f64) {
        self.budgets.lock().get(tenant).map_or((0, 0.0), |b| (b.day_tokens, b.day_usd))
    }
}

#[async_trait]
impl QuotaStore for InMemoryQuota {
    async fn check_rate(&self, tenant: &str, key: Option<&str>, policy: &QuotaPolicy) -> Result<(), QuotaError> {
        if let Some(rpm) = policy.requests_per_minute {
            self.check_one(format!("t:{tenant}"), rpm, LimitScope::Requests)?;
        }
        if let (Some(rpm), Some(k)) = (policy.key_requests_per_minute, key) {
            self.check_one(format!("k:{k}"), rpm, LimitScope::KeyRequests)?;
        }
        Ok(())
    }

    async fn reserve(&self, tenant: &str, policy: &QuotaPolicy, amount: Amount) -> Result<Reservation, QuotaError> {
        let (day, left) = utc_day_and_secs_left();
        self.reserve_at(tenant, policy, amount, Instant::now(), day, left)
    }

    async fn settle(&self, reservation: &Reservation, actual: Amount) {
        self.settle_at(reservation, actual, Instant::now());
    }
}

// ─────────────────────────────── settlement guard ───────────────────────────────

/// Owns a reservation until it is settled. If dropped unsettled (client disconnected, handler
/// cancelled) it settles in the background with the drop charge: zero by default, or the full
/// reservation while an upstream call is in flight (the provider bills it anyway).
pub struct Settlement {
    store: Option<Arc<dyn QuotaStore>>,
    reservation: Option<Reservation>,
    charge_on_drop: bool,
}

impl Settlement {
    pub fn new(store: Arc<dyn QuotaStore>, reservation: Reservation) -> Self {
        Self { store: Some(store), reservation: Some(reservation), charge_on_drop: false }
    }

    /// Nothing reserved (no budgets, or the store failed open).
    pub fn none() -> Self {
        Self { store: None, reservation: None, charge_on_drop: false }
    }

    pub fn reserved(&self) -> Amount {
        self.reservation.as_ref().map(|r| r.amount).unwrap_or_default()
    }

    /// Mark whether an upstream call is in flight (decides what a drop charges).
    pub fn set_in_flight(&mut self, in_flight: bool) {
        self.charge_on_drop = in_flight;
    }

    pub async fn settle(mut self, actual: Amount) {
        if let (Some(store), Some(r)) = (self.store.take(), self.reservation.take()) {
            store.settle(&r, actual).await;
        }
    }
}

impl Drop for Settlement {
    fn drop(&mut self) {
        let (Some(store), Some(r)) = (self.store.take(), self.reservation.take()) else { return };
        let actual = if self.charge_on_drop { r.amount } else { Amount::default() };
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(async move { store.settle(&r, actual).await });
        }
    }
}

#[cfg(test)]
mod store_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> QuotaPolicy {
        QuotaPolicy::default()
    }

    #[tokio::test]
    async fn gcra_allows_burst_then_limits_with_retry_after() {
        let q = InMemoryQuota::new();
        let p = QuotaPolicy { requests_per_minute: Some(2), ..policy() };
        q.check_rate("t", None, &p).await.unwrap();
        q.check_rate("t", None, &p).await.unwrap();
        let Err(QuotaError::Exceeded { scope, retry_after }) = q.check_rate("t", None, &p).await else { panic!("expected 429") };
        assert_eq!(scope, LimitScope::Requests);
        assert!(retry_after > Duration::from_secs(20) && retry_after <= Duration::from_secs(30), "{retry_after:?}");
        assert_eq!(retry_secs(retry_after), retry_after.as_secs() + 1);
        // Other tenants are unaffected.
        q.check_rate("other", None, &p).await.unwrap();
    }

    #[tokio::test]
    async fn per_key_rate_is_separate_from_tenant_rate() {
        let q = InMemoryQuota::new();
        let p = QuotaPolicy { key_requests_per_minute: Some(1), ..policy() };
        q.check_rate("t", Some("k1"), &p).await.unwrap();
        q.check_rate("t", Some("k2"), &p).await.unwrap();
        let err = q.check_rate("t", Some("k1"), &p).await.unwrap_err();
        assert!(matches!(err, QuotaError::Exceeded { scope: LimitScope::KeyRequests, .. }));
    }

    #[tokio::test]
    async fn rate_change_takes_effect() {
        let q = InMemoryQuota::new();
        let one = QuotaPolicy { requests_per_minute: Some(1), ..policy() };
        q.check_rate("t", None, &one).await.unwrap();
        assert!(q.check_rate("t", None, &one).await.is_err());
        let more = QuotaPolicy { requests_per_minute: Some(100), ..policy() };
        q.check_rate("t", None, &more).await.unwrap();
    }

    #[test]
    fn minute_bucket_reserves_refunds_and_refills() {
        let q = InMemoryQuota::new();
        let p = QuotaPolicy { tokens_per_minute: Some(600), ..policy() };
        let t0 = Instant::now();
        let r = q.reserve_at("t", &p, Amount { tokens: 500, usd: 0.0 }, t0, 1, 100).unwrap();
        // 100 left: a 200-token request must wait (100 missing at 10 tokens/s = 10 s).
        let Err(QuotaError::Exceeded { scope, retry_after }) = q.reserve_at("t", &p, Amount { tokens: 200, usd: 0.0 }, t0, 1, 100) else { panic!() };
        assert_eq!(scope, LimitScope::TokensPerMinute);
        assert!((retry_after.as_secs_f64() - 10.0).abs() < 0.01, "{retry_after:?}");
        // Actual usage was only 50: 450 refunded, so the 200-token request now fits.
        q.settle_at(&r, Amount { tokens: 50, usd: 0.0 }, t0);
        q.reserve_at("t", &p, Amount { tokens: 200, usd: 0.0 }, t0, 1, 100).unwrap();
        // Refill: after 60 s the bucket is full again.
        q.reserve_at("t", &p, Amount { tokens: 600, usd: 0.0 }, t0 + Duration::from_secs(60), 1, 100).unwrap();
    }

    #[test]
    fn underestimate_puts_bucket_in_debt() {
        let q = InMemoryQuota::new();
        let p = QuotaPolicy { tokens_per_minute: Some(60), ..policy() };
        let t0 = Instant::now();
        let r = q.reserve_at("t", &p, Amount { tokens: 10, usd: 0.0 }, t0, 1, 100).unwrap();
        q.settle_at(&r, Amount { tokens: 110, usd: 0.0 }, t0);
        // Level is 60 - 110 = -50; one token needs 51 s of refill at 1 token/s.
        let Err(QuotaError::Exceeded { retry_after, .. }) = q.reserve_at("t", &p, Amount { tokens: 1, usd: 0.0 }, t0, 1, 100) else { panic!() };
        assert!((retry_after.as_secs_f64() - 51.0).abs() < 0.01, "{retry_after:?}");
    }

    #[test]
    fn oversized_request_admitted_only_when_bucket_full() {
        let q = InMemoryQuota::new();
        let p = QuotaPolicy { tokens_per_minute: Some(100), ..policy() };
        let t0 = Instant::now();
        q.reserve_at("t", &p, Amount { tokens: 1000, usd: 0.0 }, t0, 1, 100).unwrap();
        assert!(q.reserve_at("t", &p, Amount { tokens: 1000, usd: 0.0 }, t0, 1, 100).is_err());
    }

    #[test]
    fn daily_tokens_and_usd_with_settlement_and_rollover() {
        let q = InMemoryQuota::new();
        let p = QuotaPolicy { tokens_per_day: Some(1000), usd_per_day: Some(1.0), ..policy() };
        let t0 = Instant::now();
        let r = q.reserve_at("t", &p, Amount { tokens: 800, usd: 0.5 }, t0, 7, 3600).unwrap();
        let Err(QuotaError::Exceeded { scope, retry_after }) = q.reserve_at("t", &p, Amount { tokens: 300, usd: 0.0 }, t0, 7, 3600) else { panic!() };
        assert_eq!((scope, retry_after), (LimitScope::TokensPerDay, Duration::from_secs(3600)));
        q.settle_at(&r, Amount { tokens: 100, usd: 0.9 }, t0);
        assert_eq!(q.day_usage("t").0, 100);
        // Tokens fit now, but the USD budget (0.9 spent + 0.2) does not.
        let err = q.reserve_at("t", &p, Amount { tokens: 300, usd: 0.2 }, t0, 7, 3600).unwrap_err();
        assert!(matches!(err, QuotaError::Exceeded { scope: LimitScope::UsdPerDay, .. }));
        // Next UTC day: counters reset.
        q.reserve_at("t", &p, Amount { tokens: 900, usd: 0.2 }, t0, 8, 3600).unwrap();
        // A request reserved yesterday and settled today is charged to today.
        q.settle_at(&r, Amount { tokens: 50, usd: 0.0 }, t0);
        assert_eq!(q.day_usage("t").0, 950);
    }

    #[test]
    fn untracked_without_budgets() {
        let q = InMemoryQuota::new();
        let r = q.reserve_at("t", &policy(), Amount { tokens: 10, usd: 0.0 }, Instant::now(), 1, 1).unwrap();
        assert!(!r.tracked);
        q.settle_at(&r, Amount { tokens: 99, usd: 0.0 }, Instant::now());
        assert_eq!(q.day_usage("t"), (0, 0.0));
    }

    #[tokio::test]
    async fn dropped_settlement_refunds_or_charges() {
        let q = Arc::new(InMemoryQuota::new());
        let p = QuotaPolicy { tokens_per_day: Some(1000), ..policy() };
        let store: Arc<dyn QuotaStore> = q.clone();
        let r = store.reserve("t", &p, Amount { tokens: 400, usd: 0.0 }).await.unwrap();
        drop(Settlement::new(Arc::clone(&store), r));
        tokio::task::yield_now().await;
        assert_eq!(q.day_usage("t").0, 0, "not in flight: refunded");

        let r = store.reserve("t", &p, Amount { tokens: 400, usd: 0.0 }).await.unwrap();
        let mut s = Settlement::new(Arc::clone(&store), r);
        s.set_in_flight(true);
        drop(s);
        tokio::task::yield_now().await;
        assert_eq!(q.day_usage("t").0, 400, "in flight: provider bills it, keep the charge");

        let r = store.reserve("t", &p, Amount { tokens: 400, usd: 0.0 }).await.unwrap();
        Settlement::new(Arc::clone(&store), r).settle(Amount { tokens: 10, usd: 0.0 }).await;
        assert_eq!(q.day_usage("t").0, 410);
    }
}
