//! Usage events on the control plane: ingestion from split-mode routers (deduplicated by
//! `request_id`), and the events and totals behind `GET /api/v1/usage`.
//!
//! - **Postgres store**: `usage_event` is the record. Events are inserted with
//!   `ON CONFLICT (request_id) DO NOTHING`, so a retried batch or a router restarted before it saw
//!   the acknowledgement never counts twice, whichever control-plane replica receives it. Reports
//!   are read back from the table (totals aggregated in SQL), so every replica sees every router.
//!   A standalone process ships its own events there too.
//! - **Memory store**: events go to the process's ring ([`RecentUsage`], the last 10,000), as the
//!   standalone data plane's own events always did; ingested events are deduplicated against the
//!   last [`MEMORY_DEDUP`] request ids. For development and demos only.
//!
//! Billing fields (`billed_usd`, `saved_usd`, `flat_price_usd`, `routed_model_cost_usd`) are
//! computed by the data plane that served the request, with the prices and cache-hit fraction of
//! the snapshot it served it under, and stored as received: the same code computes them in
//! standalone and split mode, and an event delivered late (after an outage) keeps the price that
//! applied when the request was served.

use caliban_meter::{RecentUsage, UsageEvent, UsageSink, UsageSource};
use caliban_types::{CacheStatus, CacheTier};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};

/// Request ids the memory store remembers for deduplication.
pub const MEMORY_DEDUP: usize = 200_000;

/// What an ingest did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Ingested {
    /// Events stored for the first time.
    pub accepted: u64,
    /// Events already stored (a retry); ignored.
    pub duplicates: u64,
    /// Invalid events (empty or oversized ids); ignored, never worth retrying.
    pub rejected: u64,
}

/// An event the store can keep: ids present and of sane length.
pub fn valid_event(e: &UsageEvent) -> bool {
    (1..=200).contains(&e.request_id.len()) && (1..=200).contains(&e.tenant_id.len()) && e.model.len() <= 400
}

/// Sum of USD amounts, starting from +0.0: `Iterator::sum::<f64>()` returns -0.0 for an empty
/// iterator, which the API would serialize as `-0.0` (and the console show as "-$0.00").
pub fn usd_total(amounts: impl Iterator<Item = f64>) -> f64 {
    amounts.fold(0.0, |acc, x| acc + x)
}

/// Totals of `GET /api/v1/usage`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UsageTotals {
    pub requests: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cached_prompt_tokens: u64,
    pub cache_write_tokens: u64,
    /// Requests whose tokens are a gateway estimate (disconnects, streams without usage).
    pub estimated_requests: u64,
    pub cache_hits: u64,
    /// What cache hits of both tiers saved customers (see `UsageEvent::saved_usd`).
    pub saved_usd: f64,
    pub semantic_cache_hits: u64,
    pub tokens_saved: u64,
    pub cost_usd: f64,
    // caliban/auto: the full flat price and what was billed (discounted on cache hits) vs the
    // routed models' real cost, over events with both prices.
    pub auto_requests: u64,
    pub auto_cache_hits: u64,
    pub flat_price_usd: f64,
    pub billed_usd: f64,
    pub auto_saved_usd: f64,
    pub routed_model_cost_usd: f64,
    pub margin_usd: f64,
}

impl UsageTotals {
    pub fn from_events(all: &[UsageEvent]) -> Self {
        let count = |f: &dyn Fn(&UsageEvent) -> bool| all.iter().filter(|e| f(e)).count() as u64;
        let auto = |e: &UsageEvent| e.requested_model.as_deref() == Some("caliban/auto");
        let priced = || all.iter().filter(|e| e.margin_usd().is_some());
        Self {
            requests: all.len() as u64,
            prompt_tokens: all.iter().map(|e| e.prompt_tokens).sum(),
            completion_tokens: all.iter().map(|e| e.completion_tokens).sum(),
            cached_prompt_tokens: all.iter().map(|e| e.cached_prompt_tokens).sum(),
            cache_write_tokens: all.iter().map(|e| e.cache_write_tokens).sum(),
            estimated_requests: count(&|e| e.usage_source == Some(UsageSource::Estimated)),
            cache_hits: count(&|e| e.cache == CacheStatus::Hit),
            saved_usd: usd_total(all.iter().filter_map(|e| e.saved_usd)),
            semantic_cache_hits: count(&|e| e.cache_tier == Some(CacheTier::Semantic)),
            tokens_saved: all.iter().map(|e| e.tokens_saved + e.cached_prompt_tokens).sum(),
            cost_usd: usd_total(all.iter().filter_map(|e| e.cost_usd)),
            auto_requests: count(&auto),
            auto_cache_hits: count(&|e| auto(e) && e.cache == CacheStatus::Hit),
            flat_price_usd: usd_total(priced().filter_map(|e| e.flat_price_usd)),
            billed_usd: usd_total(priced().filter_map(UsageEvent::auto_billed_usd)),
            auto_saved_usd: usd_total(priced().filter_map(|e| e.saved_usd)),
            routed_model_cost_usd: usd_total(priced().filter_map(|e| e.routed_model_cost_usd)),
            margin_usd: usd_total(priced().filter_map(UsageEvent::margin_usd)),
        }
    }
}

/// Newest events (up to the requested limit) and the totals over all matching events.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct UsageReport {
    pub events: Vec<UsageEvent>,
    pub totals: UsageTotals,
}

/// The memory store's usage: the process ring plus a bounded set of ingested request ids.
pub(crate) struct MemoryUsage {
    seen: parking_lot::Mutex<(HashSet<String>, VecDeque<String>)>,
}

impl MemoryUsage {
    pub(crate) fn new() -> Self {
        Self { seen: parking_lot::Mutex::default() }
    }

    pub(crate) async fn ingest(&self, ring: &RecentUsage, events: Vec<UsageEvent>) -> Ingested {
        let mut out = Ingested::default();
        let mut fresh = Vec::new();
        {
            let mut guard = self.seen.lock();
            let (set, order) = &mut *guard;
            for e in events {
                if set.contains(&e.request_id) {
                    out.duplicates += 1;
                    continue;
                }
                set.insert(e.request_id.clone());
                order.push_back(e.request_id.clone());
                if order.len() > MEMORY_DEDUP
                    && let Some(old) = order.pop_front()
                {
                    set.remove(&old);
                }
                out.accepted += 1;
                fresh.push(e);
            }
        }
        for e in fresh {
            ring.record(e).await;
        }
        out
    }

    pub(crate) fn report(ring: &RecentUsage, tenants: Option<&[String]>, limit: usize) -> UsageReport {
        let mut all = ring.snapshot(None, usize::MAX);
        if let Some(t) = tenants {
            all.retain(|e| t.contains(&e.tenant_id));
        }
        let totals = UsageTotals::from_events(&all);
        all.truncate(limit);
        UsageReport { events: all, totals }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_totals_are_positive_zero() {
        assert!(std::iter::empty::<f64>().sum::<f64>().is_sign_negative(), "the pitfall usd_total avoids");
        let t = serde_json::to_value(UsageTotals::from_events(&[])).unwrap();
        for k in [
            "cost_usd",
            "saved_usd",
            "flat_price_usd",
            "billed_usd",
            "auto_saved_usd",
            "routed_model_cost_usd",
            "margin_usd",
        ] {
            assert_eq!(serde_json::to_string(&t[k]).unwrap(), "0.0", "{k}");
        }
    }
}
