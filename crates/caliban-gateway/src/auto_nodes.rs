//! `caliban/auto` picks a node (P3 M6): a tenant maps intents to nodes (`[routing.tenants.<id>.routes]`
//! in the config file, overridden by the tenant's `node_routes` setting on the control plane). When a
//! `caliban/auto` request classifies into such an intent, the node runs instead of a model call,
//! through the same path as `model: "node/<name>"` (`crate::node_chat`), with the classification the
//! request already got (it is not classified again). Otherwise the request goes on to a model, and
//! the response says why (`x-caliban-route-fallback`):
//!
//! | Reason | When |
//! |---|---|
//! | `low_confidence` | Stage-1 kNN did not decide the intent (it abstained: confidence or margin under the thresholds, out of scope; timed out; off), so the keyword rules did |
//! | `no_node_for_intent` | The intent maps to no node |
//! | `node_not_allowed` | The API key may not run the node (its allowlist) |
//! | `node_unavailable` | The node has no published (live, or pinned) version, or no worker answers |
//! | `nodes_not_enabled` | This data plane runs no nodes (no `CALIBAN_KEK`, or a router without workers) |
//! | `node_over_budget` | The tenant's node spend caps leave no room for a run (the version's `budgets.usd`) |
//! | `node_input_invalid` | The conversation does not fit the node's input schema |
//!
//! A node's own model calls never hand off to a node (no recursion), and a run that started is
//! never replaced by a model call: its failure is the answer.

use crate::Gateway;
use crate::node_chat::Target;
use crate::runs::RunError;
use caliban_config::{Snapshot, TenantConfig};
use caliban_route::RouteDecision;

/// What `caliban/auto` does with a classified request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Choice {
    /// The tenant maps no intent to a node: the usual model path, nothing to report.
    NoRoutes,
    Node(Target),
    Fallback(&'static str),
}

pub(crate) fn choose(
    gw: &Gateway,
    snap: &Snapshot,
    tenant: &TenantConfig,
    key_hash: &str,
    d: &RouteDecision,
) -> Choice {
    let routes = snap.node_routes_for(tenant);
    if routes.is_empty() {
        return Choice::NoRoutes;
    }
    // Only an intent Stage-1 kNN accepted (confidence and margin over the abstain thresholds).
    if d.stage != "knn" || d.knn_fallback.is_some() {
        return Choice::Fallback("low_confidence");
    }
    let Some(r) = routes.get(&d.intent) else { return Choice::Fallback("no_node_for_intent") };
    if !tenant.key_may_run(key_hash, &r.name) {
        return Choice::Fallback("node_not_allowed");
    }
    if tenant.node(&r.name, r.version).is_none() {
        return Choice::Fallback("node_unavailable");
    }
    if gw.nodes().is_none() {
        return Choice::Fallback("nodes_not_enabled");
    }
    Choice::Node(Target { name: r.name.clone(), version: r.version })
}

/// The fallback reason of a run that could not start.
pub(crate) fn reason(e: &RunError) -> &'static str {
    match e.code.as_deref() {
        Some("node_over_budget") => "node_over_budget",
        Some("invalid_input") => "node_input_invalid",
        Some("node_not_allowed") => "node_not_allowed",
        _ => "node_unavailable",
    }
}
