//! Per-stage timings of a request: the W3C `Server-Timing` response header and the usage event's
//! `timings` object.
//!
//! Metrics, in pipeline order (a stage that did not run is left out; durations in milliseconds):
//!
//! | Metric | Stage |
//! |---|---|
//! | `auth` | authentication and the rate-limit check |
//! | `route` | classification and model choice, `desc` = the stage that decided (`pinned`, `rules`, `knn`, `keyword`) |
//! | `embed` | the routing embedder call (Stage-1 kNN), part of `route` |
//! | `pii` | PII screening |
//! | `cache` | cache lookups, `desc` = `hit` or `miss` |
//! | `upstream` | upstream model, time to its response headers (first byte) |
//! | `upstream_total` | upstream model, the whole call (non-streaming responses; streams report it in the usage event) |
//! | `node` | a node run that answered, `desc` = the run id (its steps: `GET /v1/runs/{id}`) |
//! | `total` | request start to the response headers |
//!
//! `[telemetry] server_timing = false` removes the header; the usage event keeps the durations
//! (never the deciding stage, which is content-class like the intent).

use axum::http::HeaderValue;
use caliban_meter::UsageTimings;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

/// Response header name.
pub(crate) const HEADER: &str = "server-timing";

/// What one request spent per stage.
#[derive(Debug, Clone, Default)]
pub(crate) struct Timings {
    /// Send the `Server-Timing` header (`[telemetry] server_timing`).
    pub enabled: bool,
    pub auth: Option<Duration>,
    pub route: Option<Duration>,
    /// The classifier stage that decided (`pinned`, `rules`, `knn`, `keyword`).
    pub route_stage: Option<&'static str>,
    pub embed: Option<Duration>,
    pub pii: Option<Duration>,
    pub cache: Option<Duration>,
    pub cache_hit: Option<bool>,
    /// Time to the upstream response headers.
    pub upstream: Option<Duration>,
    /// When the answering upstream call started (completes `upstream_total` at the end of a stream).
    pub upstream_started: Option<Instant>,
    pub upstream_total: Option<Duration>,
    pub node: Option<Duration>,
    pub run_id: Option<String>,
}

fn ms(d: Duration) -> f64 {
    // Microsecond precision.
    (d.as_secs_f64() * 1_000_000.0).round() / 1000.0
}

impl Timings {
    pub(crate) fn new(enabled: bool) -> Self {
        Self { enabled, ..Self::default() }
    }

    pub(crate) fn add_pii(&mut self, d: Duration) {
        self.pii = Some(self.pii.unwrap_or_default() + d);
    }

    /// One cache lookup (T1, then T2 after a T1 miss).
    pub(crate) fn add_cache(&mut self, d: Duration, hit: bool) {
        self.cache = Some(self.cache.unwrap_or_default() + d);
        self.cache_hit = Some(hit);
    }

    /// The upstream call that answers: started at `started`, headers at `headers_at`.
    pub(crate) fn upstream_call(&mut self, started: Instant, headers_at: Option<Instant>) {
        let first = headers_at.unwrap_or_else(Instant::now);
        self.upstream = Some(first.saturating_duration_since(started));
        self.upstream_started = Some(started);
        self.upstream_total = None;
    }

    /// The upstream call returned its whole body now (non-streaming).
    pub(crate) fn upstream_done(&mut self) {
        self.upstream_total = self.upstream_started.map(|s| s.elapsed());
    }

    /// The `Server-Timing` value, `total` measured from `started`. `None` when disabled.
    pub(crate) fn header(&self, started: Instant) -> Option<HeaderValue> {
        if !self.enabled {
            return None;
        }
        let mut s = String::new();
        let mut metric = |name: &str, d: Option<Duration>, desc: Option<&str>| {
            if d.is_none() && desc.is_none() {
                return;
            }
            if !s.is_empty() {
                s.push_str(", ");
            }
            s.push_str(name);
            if let Some(d) = d {
                let _ = write!(s, ";dur={:.3}", ms(d));
            }
            if let Some(desc) = desc {
                let _ = write!(s, ";desc=\"{}\"", desc.replace(['"', '\\'], ""));
            }
        };
        metric("auth", self.auth, None);
        metric("route", self.route, self.route.and(self.route_stage));
        metric("embed", self.embed, None);
        metric("pii", self.pii, None);
        metric("cache", self.cache, self.cache.and(self.cache_hit.map(|h| if h { "hit" } else { "miss" })));
        metric("upstream", self.upstream, None);
        metric("upstream_total", self.upstream_total, None);
        metric("node", self.node, self.run_id.as_deref());
        metric("total", Some(started.elapsed()), None);
        HeaderValue::from_str(&s).ok()
    }

    /// The usage event's `timings`: a stream's upstream call ends now.
    pub(crate) fn usage(&self, started: Instant) -> UsageTimings {
        let upstream_total = self.upstream_total.or_else(|| self.upstream_started.map(|s| s.elapsed()));
        UsageTimings {
            auth_ms: self.auth.map(ms),
            route_ms: self.route.map(ms),
            embed_ms: self.embed.map(ms),
            pii_ms: self.pii.map(ms),
            cache_ms: self.cache.map(ms),
            upstream_ms: self.upstream.map(ms),
            upstream_total_ms: upstream_total.map(ms),
            total_ms: Some(ms(started.elapsed())),
        }
    }
}

/// The routing stage for `route;desc=`: `pinned` for a named model, else the deciding stage.
pub(crate) fn route_stage(policy: &str, stage: &'static str) -> &'static str {
    if policy == "pinned" { "pinned" } else { stage }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lists_stages_in_order_and_skips_missing_ones() {
        let mut t = Timings::new(true);
        t.auth = Some(Duration::from_micros(120));
        t.route = Some(Duration::from_micros(3400));
        t.route_stage = Some("knn");
        t.add_cache(Duration::from_micros(50), false);
        let started = Instant::now();
        t.upstream_call(started, Some(started + Duration::from_millis(5)));
        let h = t.header(Instant::now()).expect("enabled");
        let h = h.to_str().unwrap();
        assert!(h.starts_with("auth;dur=0.120, route;dur=3.400;desc=\"knn\", cache;dur=0.050;desc=\"miss\", upstream;dur=5.000, total;dur="), "{h}");
        assert!(!h.contains("pii") && !h.contains("embed") && !h.contains("upstream_total"), "{h}");
        assert!(Timings::new(false).header(Instant::now()).is_none());
    }

    #[test]
    fn usage_fills_the_upstream_total_of_a_stream() {
        let mut t = Timings::new(false);
        t.upstream_call(Instant::now(), None);
        let u = t.usage(Instant::now());
        assert!(u.upstream_total_ms.is_some() && u.upstream_ms.is_some() && u.total_ms.is_some());
        assert!(u.auth_ms.is_none());
    }
}
