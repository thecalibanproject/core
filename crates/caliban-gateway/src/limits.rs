//! Glue between the config's `[limits]` and the quota store (request lifecycle stage 3).
//!
//! Store failures fail **open** on shared state: with `store = "valkey"` the store itself falls
//! back to this router's in-memory limiter (see `caliban_meter::quota::fallback`), and any other
//! backend error lets the request through with a warning. Quotas protect budgets; they must not
//! take the gateway down.

use crate::{ApiError, Gateway};
use caliban_config::{Limits, LimitsConfig, QuotaStoreKind};
use caliban_meter::quota::valkey::{DEFAULT_PREFIX, DEFAULT_TIMEOUT};
use caliban_meter::quota::{Amount, FallbackQuota, InMemoryQuota, QuotaError, QuotaPolicy, QuotaStore, Settlement, ValkeyOptions, ValkeyQuota};
use std::sync::Arc;
use std::time::Duration;

/// Builds the store `[limits] store` selects. `valkey` needs `CALIBAN_VALKEY_URL`
/// (`redis://` or `rediss://`; the password in the URL or in `CALIBAN_VALKEY_PASSWORD`). The
/// connection is opened in the background, so a router starts (limiting locally) while Valkey is
/// down. Must run inside a Tokio runtime. Read once at start-up.
pub fn quota_store(l: &LimitsConfig) -> Result<Arc<dyn QuotaStore>, String> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    match l.store {
        QuotaStoreKind::Memory => {
            if env("CALIBAN_VALKEY_URL").is_some() {
                tracing::info!("CALIBAN_VALKEY_URL is set but [limits] store = \"memory\": quotas are enforced per router process");
            }
            Ok(Arc::new(InMemoryQuota::new()))
        }
        QuotaStoreKind::Valkey => {
            let url = env("CALIBAN_VALKEY_URL").ok_or("[limits] store = \"valkey\" needs CALIBAN_VALKEY_URL (redis:// or rediss://)")?;
            let opts = ValkeyOptions {
                url,
                password: env("CALIBAN_VALKEY_PASSWORD"),
                key_prefix: l.valkey_key_prefix.clone().unwrap_or_else(|| DEFAULT_PREFIX.to_owned()),
                timeout: l.valkey_timeout_ms.map_or(DEFAULT_TIMEOUT, Duration::from_millis),
            };
            let store = Arc::new(FallbackQuota::new(ValkeyQuota::new(&opts).map_err(|e| e.to_string())?));
            let probe = Arc::clone(&store);
            tokio::spawn(async move {
                if probe.probe(Duration::from_secs(3)).await {
                    let v = probe.shared();
                    tracing::info!(valkey = v.endpoint(), prefix = v.key_prefix(), timeout_ms = v.timeout().as_millis() as u64, "quota store: valkey (shared by all routers)");
                }
            });
            Ok(store)
        }
    }
}

/// Reserved for output when a request sets no `max_tokens`.
pub const DEFAULT_OUTPUT_RESERVE: u64 = 1024;

pub fn policy(l: &Limits) -> QuotaPolicy {
    QuotaPolicy {
        requests_per_minute: l.requests_per_minute,
        key_requests_per_minute: l.key_requests_per_minute,
        tokens_per_minute: l.tokens_per_minute,
        tokens_per_day: l.tokens_per_day,
        usd_per_day: l.usd_per_day,
    }
}

fn to_api(e: QuotaError) -> Option<ApiError> {
    match e {
        QuotaError::Exceeded { scope, retry_after } => Some(ApiError::rate_limited(scope.as_str(), retry_after)),
        QuotaError::Backend(msg) => {
            tracing::warn!(error = %msg, "quota store unavailable; failing open");
            None
        }
    }
}

/// GCRA request-rate check (tenant, then API key).
pub async fn check_rate(gw: &Gateway, tenant: &str, key_hash: Option<&str>, p: &QuotaPolicy) -> Result<(), ApiError> {
    if p.requests_per_minute.is_none() && p.key_requests_per_minute.is_none() {
        return Ok(());
    }
    match gw.quota.check_rate(tenant, key_hash, p).await {
        Ok(()) => Ok(()),
        Err(e) => to_api(e).map_or(Ok(()), Err),
    }
}

/// Reserves `amount` against the tenant's token/USD budgets.
pub async fn reserve(gw: &Gateway, tenant: &str, p: &QuotaPolicy, amount: Amount) -> Result<Settlement, ApiError> {
    if !p.has_budgets() {
        return Ok(Settlement::none());
    }
    match gw.quota.reserve(tenant, p, amount).await {
        Ok(r) => Ok(Settlement::new(Arc::clone(&gw.quota), r)),
        Err(e) => to_api(e).map_or(Ok(Settlement::none()), Err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_follows_config() {
        let mem = quota_store(&LimitsConfig::default()).unwrap();
        assert_eq!(mem.status().store, "memory");
        // `valkey` without a URL refuses to start (only checkable when the variable is unset).
        if std::env::var_os("CALIBAN_VALKEY_URL").is_none() {
            let err = quota_store(&LimitsConfig { store: QuotaStoreKind::Valkey, ..LimitsConfig::default() }).err().unwrap();
            assert!(err.contains("CALIBAN_VALKEY_URL"), "{err}");
        }
    }
}
