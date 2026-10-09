//! Idempotency records on Valkey, and the fallback to this router's memory store.

use super::{
    Begin, IdempotencyError, IdempotencyStore, LEASE_TTL, Lease, MemoryIdempotency, REPLAY_TTL, Record, StoredResponse,
};
use crate::quota::valkey::{Lua, ValkeyOptions, ValkeyQuota};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Bound for storing a result (off the request's critical path; bodies can be megabytes).
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
/// How long the fallback goes local after a Valkey error before trying Valkey again.
pub const RETRY_AFTER: Duration = Duration::from_secs(2);
const WARN_EVERY: Duration = Duration::from_secs(30);

/// Shared records on Valkey (same connection settings as the quota store).
pub struct ValkeyIdempotency {
    conn: ValkeyQuota,
    prefix: String,
    begin: Lua,
    complete: Lua,
    release: Lua,
}

impl ValkeyIdempotency {
    /// Builds the store without connecting (see [`ValkeyQuota::new`]). Must run inside a Tokio
    /// runtime.
    pub fn new(opts: &ValkeyOptions) -> Result<Self, IdempotencyError> {
        let conn = ValkeyQuota::new(opts).map_err(|e| IdempotencyError(e.to_string()))?;
        Ok(Self {
            conn,
            prefix: opts.key_prefix.clone(),
            begin: Lua::new(include_str!("begin.lua")),
            complete: Lua::new(include_str!("complete.lua")),
            release: Lua::new(include_str!("release.lua")),
        })
    }

    pub fn endpoint(&self) -> &str {
        self.conn.endpoint()
    }

    fn key(&self, id: &str) -> String {
        format!("{}:idem:{{{id}}}", self.prefix)
    }

    fn json(r: &Record) -> String {
        serde_json::to_string(r).unwrap_or_default()
    }

    pub async fn try_begin(&self, tenant: &str, key: &str, fingerprint: &str) -> Result<Begin, IdempotencyError> {
        let lease = super::new_lease(tenant, key, fingerprint);
        let args = [Self::json(&lease.pending()), ms(LEASE_TTL)];
        let existing: Option<String> = self
            .conn
            .eval_within(self.conn.timeout(), &self.begin, &[self.key(&lease.id)], &args)
            .await
            .map_err(|e| IdempotencyError(e.to_string()))?;
        Ok(match existing {
            None => Begin::Started(lease),
            Some(raw) => match serde_json::from_str::<Record>(&raw) {
                Ok(r) => super::judge(&r, fingerprint),
                // A record this version cannot read: never run the request twice on a guess.
                Err(_) => Begin::InProgress,
            },
        })
    }

    pub async fn try_complete(&self, lease: &Lease, response: Option<StoredResponse>) -> Result<(), IdempotencyError> {
        let args = [Self::json(&lease.pending()), Self::json(&super::done(lease, response)), ms(REPLAY_TTL)];
        self.conn
            .eval_within::<i64>(WRITE_TIMEOUT, &self.complete, &[self.key(&lease.id)], &args)
            .await
            .map(|_| ())
            .map_err(|e| IdempotencyError(e.to_string()))
    }

    pub async fn try_release(&self, lease: &Lease) -> Result<(), IdempotencyError> {
        let args = [Self::json(&lease.pending())];
        self.conn
            .eval_within::<i64>(WRITE_TIMEOUT, &self.release, &[self.key(&lease.id)], &args)
            .await
            .map(|_| ())
            .map_err(|e| IdempotencyError(e.to_string()))
    }
}

fn ms(d: Duration) -> String {
    d.as_millis().to_string()
}

#[async_trait]
impl IdempotencyStore for ValkeyIdempotency {
    async fn begin(&self, tenant: &str, key: &str, fingerprint: &str) -> Result<Begin, IdempotencyError> {
        self.try_begin(tenant, key, fingerprint).await
    }

    async fn complete(&self, lease: &Lease, response: Option<StoredResponse>) {
        if let Err(e) = self.try_complete(lease, response).await {
            tracing::warn!(error = %e, "idempotency result not stored; a retry with this key will be refused until the lease expires");
        }
    }

    async fn release(&self, lease: &Lease) {
        if let Err(e) = self.try_release(lease).await {
            tracing::debug!(error = %e, "idempotency key not released; it frees itself when the lease expires");
        }
    }

    fn kind(&self) -> &'static str {
        "valkey"
    }
}

/// Valkey while it answers, this router's [`MemoryIdempotency`] while it does not (a claim made
/// locally is completed and released locally).
pub struct FallbackIdempotency {
    shared: ValkeyIdempotency,
    local: MemoryIdempotency,
    degraded: AtomicBool,
    open_until: Mutex<Option<Instant>>,
    last_warn: Mutex<Option<Instant>>,
    retry_after: Duration,
}

impl FallbackIdempotency {
    pub fn new(shared: ValkeyIdempotency) -> Self {
        Self::with_retry_after(shared, RETRY_AFTER)
    }

    pub fn with_retry_after(shared: ValkeyIdempotency, retry_after: Duration) -> Self {
        Self {
            shared,
            local: MemoryIdempotency::default(),
            degraded: AtomicBool::new(false),
            open_until: Mutex::new(None),
            last_warn: Mutex::new(None),
            retry_after,
        }
    }

    pub fn local(&self) -> &MemoryIdempotency {
        &self.local
    }

    /// Whether to try Valkey now (closed circuit, or the open window has passed).
    fn allow(&self) -> bool {
        let mut until = self.open_until.lock();
        match *until {
            Some(t) if Instant::now() < t => false,
            Some(_) => {
                // One probe per window.
                *until = Some(Instant::now() + self.retry_after);
                true
            }
            None => true,
        }
    }

    fn failed(&self, e: &IdempotencyError) {
        *self.open_until.lock() = Some(Instant::now() + self.retry_after);
        let first = !self.degraded.swap(true, Ordering::AcqRel);
        let mut last = self.last_warn.lock();
        if first || last.is_none_or(|t| t.elapsed() >= WARN_EVERY) {
            *last = Some(Instant::now());
            tracing::warn!(valkey = self.shared.endpoint(), error = %e,
                "valkey idempotency store unavailable; keys are deduplicated on this router only");
        }
    }

    fn succeeded(&self) {
        if self.degraded.swap(false, Ordering::AcqRel) {
            *self.open_until.lock() = None;
            tracing::info!(valkey = self.shared.endpoint(), "valkey idempotency store reachable again");
        }
    }
}

#[async_trait]
impl IdempotencyStore for FallbackIdempotency {
    async fn begin(&self, tenant: &str, key: &str, fingerprint: &str) -> Result<Begin, IdempotencyError> {
        if self.allow() {
            match self.shared.try_begin(tenant, key, fingerprint).await {
                Ok(b) => {
                    self.succeeded();
                    return Ok(b);
                }
                Err(e) => self.failed(&e),
            }
        }
        Ok(match self.local.begin_sync(tenant, key, fingerprint) {
            Begin::Started(l) => Begin::Started(Lease { local: true, ..l }),
            other => other,
        })
    }

    async fn complete(&self, lease: &Lease, response: Option<StoredResponse>) {
        if lease.local {
            return self.local.complete(lease, response).await;
        }
        self.shared.complete(lease, response).await;
    }

    async fn release(&self, lease: &Lease) {
        if lease.local {
            return self.local.release(lease).await;
        }
        self.shared.release(lease).await;
    }

    fn kind(&self) -> &'static str {
        "valkey"
    }
}
