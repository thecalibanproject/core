//! Escalation admission budgets per API key (research note 02; GateDrain, arXiv 2609.33992,
//! preprint): `[routing.escalation]`.
//!
//! A `caliban/auto` request whose chosen model is in the expensive tier is an escalation. Each API
//! key may make `per_key_per_minute` of them (a burst of that many, refilled evenly; counted in the
//! quota store, so shared across routers with `[limits] store = "valkey"`). Over the budget, the
//! request is not queued and not refused: it takes the cheaper models of its route, else the
//! cheaper models of the tenant's default route (`x-caliban-escalation: denied`). A bounded
//! perturbation that lowers routing confidence can push traffic into a shared strong tier without
//! raising the request rate; the budget caps what one key can drain, whatever the classifier says.
//!
//! Counters (no tenant data) are on `/metrics`: `caliban_escalations_total{outcome}`.

use caliban_config::{Snapshot, TenantConfig};
use caliban_meter::quota::{QuotaError, QuotaPolicy, QuotaStore};
use caliban_route::{DEFAULT_INTENT, RouteDecision};
use caliban_types::ModelId;
use std::sync::atomic::{AtomicU64, Ordering};

/// What happened to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// Not an escalation (pinned model, not the expensive tier, budgets off).
    None,
    Admitted,
    /// Over budget: the decision now holds the cheaper candidates.
    Denied,
}

impl Admission {
    pub(crate) fn header(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Admitted => Some("admitted"),
            Self::Denied => Some("denied"),
        }
    }
}

/// Process-wide counters for `/metrics`.
#[derive(Debug, Default)]
pub struct EscalationStats {
    admitted: AtomicU64,
    denied: AtomicU64,
}

impl EscalationStats {
    pub fn admitted(&self) -> u64 {
        self.admitted.load(Ordering::Relaxed)
    }

    pub fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }

    pub(crate) fn metrics(&self, out: &mut String) {
        out.push_str(
            "# HELP caliban_escalations_total caliban/auto requests routed to the expensive tier: admitted, or denied by the per-key escalation budget (served by cheaper models).\n\
             # TYPE caliban_escalations_total counter\n",
        );
        out.push_str(&format!("caliban_escalations_total{{outcome=\"admitted\"}} {}\n", self.admitted()));
        out.push_str(&format!("caliban_escalations_total{{outcome=\"denied\"}} {}\n", self.denied()));
    }
}

/// The quota-store key of an API key's escalation budget (never collides with request limits).
fn budget_key(key_hash: &str) -> String {
    format!("escalation:{key_hash}")
}

/// Applies the escalation budget of `key_hash` to `d` (see the module docs).
pub(crate) async fn admit(
    quota: &dyn QuotaStore,
    stats: &EscalationStats,
    snap: &Snapshot,
    tenant: &TenantConfig,
    key_hash: &str,
    d: &mut RouteDecision,
) -> Admission {
    let cfg = &snap.config.routing.escalation;
    if !d.auto || cfg.is_off() {
        return Admission::None;
    }
    let expensive = |id: &ModelId| snap.model(id).is_some_and(|m| cfg.is_expensive(m));
    if !d.candidates.first().is_some_and(expensive) {
        return Admission::None;
    }
    let Some(per_minute) = cfg.per_key_per_minute else {
        stats.admitted.fetch_add(1, Ordering::Relaxed);
        return Admission::Admitted;
    };
    let policy = QuotaPolicy { key_requests_per_minute: Some(per_minute), ..QuotaPolicy::default() };
    match quota.check_rate(tenant.id.as_str(), Some(&budget_key(key_hash)), &policy).await {
        Ok(()) => {
            stats.admitted.fetch_add(1, Ordering::Relaxed);
            Admission::Admitted
        }
        Err(QuotaError::Backend(e)) => {
            // The shared store is down (the fallback store already counts locally when it can):
            // fail open, like other limits, rather than degrade every answer.
            tracing::warn!(error = %e, "escalation budget unavailable; admitting");
            stats.admitted.fetch_add(1, Ordering::Relaxed);
            Admission::Admitted
        }
        Err(QuotaError::Exceeded { .. }) => {
            let cheaper: Vec<ModelId> = d.candidates.iter().filter(|m| !expensive(m)).cloned().collect();
            let fallback = || {
                tenant
                    .routes
                    .iter()
                    .find(|r| r.intent == DEFAULT_INTENT)
                    .map(|r| r.models.iter().filter(|m| !expensive(m)).cloned().collect::<Vec<_>>())
                    .unwrap_or_default()
            };
            let next = if cheaper.is_empty() { fallback() } else { cheaper };
            if next.is_empty() {
                // Nothing cheaper is configured: the budget cannot steer this request.
                tracing::warn!(tenant = %tenant.id, "escalation budget exceeded, but the route and the default route have only expensive models; admitting");
                stats.admitted.fetch_add(1, Ordering::Relaxed);
                return Admission::Admitted;
            }
            d.candidates = next;
            d.policy = "escalation_budget";
            stats.denied.fetch_add(1, Ordering::Relaxed);
            Admission::Denied
        }
    }
}
