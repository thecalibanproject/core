//! Usage metering. Every request emits exactly one `UsageEvent` (also on cache hits and errors
//! after the upstream was called). Events are append-only; billing and the savings dashboard are
//! computed from them.
//!
//! Quotas (rate limits, token reservation before the call and settlement after) live in
//! [`quota`]. TODO: NATS/Kafka sink.

pub mod quota;

use async_trait::async_trait;
use caliban_types::CacheStatus;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// Matches the OpenAPI `UsageEvent` schema.
#[derive(Debug, Clone, Serialize)]
pub struct UsageEvent {
    pub request_id: String,
    pub tenant_id: String,
    pub model: String,
    pub intent: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cached_prompt_tokens: u64,
    /// Tokens not sent upstream thanks to Caliban (cache hits; later compression/routing).
    pub tokens_saved: u64,
    pub cache: CacheStatus,
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

pub fn cost_usd(prompt: u64, completion: u64, price_in_per_mtok: Option<f64>, price_out_per_mtok: Option<f64>) -> Option<f64> {
    let (pi, po) = (price_in_per_mtok?, price_out_per_mtok?);
    #[allow(clippy::cast_precision_loss)]
    Some((prompt as f64 * pi + completion as f64 * po) / 1_000_000.0)
}

#[async_trait]
pub trait UsageSink: Send + Sync {
    async fn record(&self, event: UsageEvent);
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

/// Append-only JSONL write-ahead log; shipped to billing/ClickHouse asynchronously.
pub struct JsonlSink {
    path: PathBuf,
}

impl JsonlSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl UsageSink for JsonlSink {
    async fn record(&self, event: UsageEvent) {
        let Ok(mut line) = serde_json::to_vec(&event) else { return };
        line.push(b'\n');
        let res = async {
            let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(&self.path).await?;
            f.write_all(&line).await
        }
        .await;
        if let Err(e) = res {
            tracing::error!(error = %e, path = %self.path.display(), "usage WAL write failed");
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_needs_both_prices() {
        assert_eq!(cost_usd(1_000_000, 0, Some(2.0), Some(8.0)), Some(2.0));
        assert_eq!(cost_usd(10, 10, None, Some(1.0)), None);
    }
}
