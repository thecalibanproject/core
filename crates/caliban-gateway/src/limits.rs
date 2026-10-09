//! Glue between the config's `[limits]` and the quota store (request lifecycle stage 3).
//!
//! Store failures (e.g. an unreachable shared store) fail **open** with a warning: quotas protect
//! budgets, they must not take the gateway down.

use crate::{ApiError, Gateway};
use caliban_config::Limits;
use caliban_meter::quota::{Amount, QuotaError, QuotaPolicy, Settlement};
use std::sync::Arc;

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
