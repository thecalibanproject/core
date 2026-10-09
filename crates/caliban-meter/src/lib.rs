//! Usage metering. Every request emits exactly one `UsageEvent` (also on cache hits and errors
//! after the upstream was called). Events are append-only; billing and the savings dashboard are
//! computed from them.
//!
//! Quotas (rate limits, token reservation before the call and settlement after) live in
//! [`quota`]. TODO: NATS/Kafka sink.

pub mod quota;
mod wal;

pub use wal::{FsyncPolicy, JsonlSink, WalOptions, WalStats, read_wal};

use async_trait::async_trait;
use caliban_types::{CacheStatus, CacheTier};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;

/// Where an event's token counts come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    /// The provider's own usage report (exact; what the provider bills).
    Provider,
    /// Estimated by the gateway (about 4 bytes per token), because no complete usage report
    /// arrived: the client disconnected mid-stream, the upstream stream ended or failed without
    /// usage, or the model rejects `stream_options`. After a disconnect the provider may bill
    /// more than the estimate (it can keep generating until it notices the cancellation).
    Estimated,
}

impl UsageSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Estimated => "estimated",
        }
    }
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Matches the OpenAPI `UsageEvent` schema. Fields added after the first release are optional
/// (omitted when unset or zero) and default when absent, so old and new WAL lines both parse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageEvent {
    pub request_id: String,
    pub tenant_id: String,
    pub model: String,
    pub intent: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cached_prompt_tokens: u64,
    /// Prompt tokens written to the provider's prompt cache (Anthropic
    /// `cache_creation_input_tokens`); part of `prompt_tokens`, priced at the cache-write price.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_write_tokens: u64,
    /// The part of `cache_write_tokens` written with Anthropic's 1-hour TTL.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_write_1h_tokens: u64,
    /// Tokens not sent upstream thanks to Caliban (cache hits; later compression/routing).
    pub tokens_saved: u64,
    pub cache: CacheStatus,
    /// On hits: `exact` (T1) or `semantic` (T2). `cache` stays `hit` for both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_tier: Option<CacheTier>,
    /// `provider` (the provider's usage report) or `estimated` (see [`UsageSource`]). Unset on
    /// gateway cache hits, where nothing was consumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_source: Option<UsageSource>,
    pub pii_entities: usize,
    pub cost_usd: Option<f64>,
    pub latency_ms: u64,
    pub ts: DateTime<Utc>,
    /// The model the client asked for: `caliban/auto` or a pinned catalogue id (chat only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_model: Option<String>,
    /// Confidence of the intent decision, 0..=1 (chat only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_confidence: Option<f32>,
    /// Stage that decided the intent: `rules` (pinned), `knn` or `keyword` (chat only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_stage: Option<String>,
    /// `caliban/auto` only: real cost of the routed model for this request (its prices times the
    /// reported usage; the same number as `cost_usd`), recorded next to `flat_price_usd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routed_model_cost_usd: Option<f64>,
    /// `caliban/auto` only: the flat auto price for this request's tokens
    /// (`[routing] auto_price_in_per_mtok` / `auto_price_out_per_mtok`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flat_price_usd: Option<f64>,
}

impl UsageEvent {
    /// `flat_price_usd - routed_model_cost_usd`, when both are known.
    pub fn margin_usd(&self) -> Option<f64> {
        Some(self.flat_price_usd? - self.routed_model_cost_usd?)
    }
}

/// Prices of one model, USD per million tokens.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Prices {
    pub input: Option<f64>,
    pub output: Option<f64>,
    /// Prompt-cache reads. `None`: the input price.
    pub cache_read: Option<f64>,
    /// Prompt-cache writes (default 5-minute TTL). `None`: the input price.
    pub cache_write: Option<f64>,
    /// Prompt-cache writes with the 1-hour TTL. `None`: the cache-write price.
    pub cache_write_1h: Option<f64>,
}

impl Prices {
    /// Input and output prices only (cache tokens are priced as input).
    pub fn flat(input: Option<f64>, output: Option<f64>) -> Self {
        Self { input, output, ..Self::default() }
    }
}

/// Token counts to price. `prompt` includes the cache reads and writes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tokens {
    pub prompt: u64,
    pub completion: u64,
    pub cache_read: u64,
    /// All cache writes (both TTLs).
    pub cache_write: u64,
    /// The part of `cache_write` with the 1-hour TTL.
    pub cache_write_1h: u64,
}

/// The one cost function: uncached input + cache reads x read price + cache writes x write
/// price (1-hour writes at their own price) + output. `None` unless both the input and the
/// output price are set. Cache prices default to the input price, so a model without cache
/// prices costs what it did before cache pricing existed.
pub fn cost(t: Tokens, p: Prices) -> Option<f64> {
    let (pi, po) = (p.input?, p.output?);
    let read = p.cache_read.unwrap_or(pi);
    let write = p.cache_write.unwrap_or(pi);
    let write_1h = p.cache_write_1h.unwrap_or(write);
    let cache_read = t.cache_read.min(t.prompt);
    let cache_write = t.cache_write.min(t.prompt - cache_read);
    let write_1h_n = t.cache_write_1h.min(cache_write);
    let uncached = t.prompt - cache_read - cache_write;
    #[allow(clippy::cast_precision_loss)]
    let usd = uncached as f64 * pi
        + cache_read as f64 * read
        + (cache_write - write_1h_n) as f64 * write
        + write_1h_n as f64 * write_1h
        + t.completion as f64 * po;
    Some(usd / 1_000_000.0)
}

/// Cost with every prompt token at the input price (estimates and reservations).
pub fn cost_usd(prompt: u64, completion: u64, price_in_per_mtok: Option<f64>, price_out_per_mtok: Option<f64>) -> Option<f64> {
    cost(Tokens { prompt, completion, ..Tokens::default() }, Prices::flat(price_in_per_mtok, price_out_per_mtok))
}

#[async_trait]
pub trait UsageSink: Send + Sync {
    async fn record(&self, event: UsageEvent);

    /// Health counters for `/healthz` (the WAL reports its queue, drops and errors).
    fn status(&self) -> Option<serde_json::Value> {
        None
    }
}

/// Bounded in-memory ring buffer, read by the control plane's `/api/v1/usage`.
#[derive(Clone, Default)]
pub struct RecentUsage {
    inner: Arc<Mutex<VecDeque<UsageEvent>>>,
}

const RING: usize = 10_000;

impl RecentUsage {
    pub fn snapshot(&self, tenant: Option<&str>, limit: usize) -> Vec<UsageEvent> {
        self.inner
            .lock()
            .iter()
            .rev()
            .filter(|e| tenant.is_none_or(|t| e.tenant_id == t))
            .take(limit)
            .cloned()
            .collect()
    }
}

#[async_trait]
impl UsageSink for RecentUsage {
    async fn record(&self, event: UsageEvent) {
        let mut q = self.inner.lock();
        if q.len() == RING {
            q.pop_front();
        }
        q.push_back(event);
    }
}

/// Fan-out to several sinks.
pub struct Tee(pub Vec<Arc<dyn UsageSink>>);

#[async_trait]
impl UsageSink for Tee {
    async fn record(&self, event: UsageEvent) {
        for s in &self.0 {
            s.record(event.clone()).await;
        }
    }

    fn status(&self) -> Option<serde_json::Value> {
        self.0.iter().find_map(|s| s.status())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_needs_both_prices() {
        assert_eq!(cost_usd(1_000_000, 0, Some(2.0), Some(8.0)), Some(2.0));
        assert_eq!(cost_usd(10, 10, None, Some(1.0)), None);
    }

    fn close(a: Option<f64>, b: f64) -> bool {
        a.is_some_and(|a| (a - b).abs() < 1e-12)
    }

    #[test]
    fn cache_reads_and_writes_are_priced_separately() {
        // 1000 prompt tokens: 600 read from cache, 300 written (100 of them 1-hour), 100 uncached.
        let t = Tokens { prompt: 1000, completion: 50, cache_read: 600, cache_write: 300, cache_write_1h: 100 };
        let p = Prices { input: Some(3.0), output: Some(15.0), cache_read: Some(0.3), cache_write: Some(3.75), cache_write_1h: Some(6.0) };
        let want = (100.0 * 3.0 + 600.0 * 0.3 + 200.0 * 3.75 + 100.0 * 6.0 + 50.0 * 15.0) / 1e6;
        assert!(close(cost(t, p), want), "{:?} vs {want}", cost(t, p));
        // 1-hour writes default to the 5-minute write price.
        let p5 = Prices { cache_write_1h: None, ..p };
        assert!(close(cost(t, p5), (100.0 * 3.0 + 600.0 * 0.3 + 300.0 * 3.75 + 50.0 * 15.0) / 1e6));
    }

    #[test]
    fn unset_cache_prices_default_to_the_input_price() {
        let t = Tokens { prompt: 1000, completion: 10, cache_read: 900, cache_write: 50, cache_write_1h: 0 };
        assert_eq!(cost(t, Prices::flat(Some(2.0), Some(8.0))), cost_usd(1000, 10, Some(2.0), Some(8.0)));
        assert_eq!(cost(t, Prices { input: None, ..Prices::flat(None, Some(1.0)) }), None);
    }

    #[test]
    fn inconsistent_counts_never_underflow() {
        // More cache tokens than prompt tokens (a confused upstream): clamped, never negative.
        let t = Tokens { prompt: 10, completion: 0, cache_read: 8, cache_write: 8, cache_write_1h: 20 };
        let c = cost(t, Prices { input: Some(1.0), output: Some(1.0), cache_read: Some(0.1), cache_write: Some(2.0), cache_write_1h: Some(4.0) });
        assert!(close(c, (8.0 * 0.1 + 2.0 * 4.0) / 1e6), "{c:?}");
    }
}
