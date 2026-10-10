//! Publish-time validation: what a node version must satisfy, against its tenant, before it can be
//! published (and again before it is promoted).
//!
//! On top of the static checks ([`NodeSpec::validate`]):
//! - every `node://name@vN` it calls (tools and subnode vertices) is a **published** version of
//!   the same tenant, and node-to-node references form no cycle;
//! - every datasource scope exists for the tenant ([`PublishContext::scope_exists`]);
//! - its budgets fit inside the tenant's node caps ([`NodeCaps`]);
//! - every `mcp://` tool stays pinned (static check) and passes [`PublishContext::check_tool`].
//!   TODO(P3 M4): resolve `mcp://` references against the tenant's approved tool registry (pinned
//!   manifests, re-approval on change) in that hook; until then any pinned reference passes and the
//!   executor refuses to call it.

use crate::{NodeSpec, ToolTarget};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Upper bounds a tenant puts on every node version it publishes. Tenant settings
/// (`PATCH /api/v1/tenants/{id}` with `node_caps`); [`NodeCaps::DEFAULT`] when unset.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeCaps {
    pub steps: u32,
    pub tokens: u64,
    pub wall_clock_s: u64,
    pub depth: u32,
    pub fanout: u32,
    /// Most a version may let one run spend (USD). When set, every version must declare a
    /// `budgets.usd` within it. `None`: no cap (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd: Option<f64>,
}

impl NodeCaps {
    pub const DEFAULT: NodeCaps =
        NodeCaps { steps: 200, tokens: 2_000_000, wall_clock_s: 3600, depth: 5, fanout: 32, usd: None };

    pub fn validate(&self) -> Result<(), String> {
        if self.steps == 0 || self.tokens == 0 || self.wall_clock_s == 0 || self.depth == 0 || self.fanout == 0 {
            return Err("node_caps: every cap must be positive".into());
        }
        if self.usd.is_some_and(|u| !u.is_finite() || u <= 0.0) {
            return Err("node_caps: usd must be a positive number".into());
        }
        Ok(())
    }

    /// The budgets of `spec` that exceed a cap.
    pub fn violations(&self, spec: &NodeSpec) -> Vec<String> {
        let b = &spec.budgets;
        let mut out = Vec::new();
        let mut over = |what: &str, got: u64, cap: u64| {
            if got > cap {
                out.push(format!("budgets.{what} = {got} exceeds the tenant's node cap of {cap}"));
            }
        };
        over("steps", b.steps.into(), self.steps.into());
        over("tokens", b.tokens, self.tokens);
        over("wall_clock_s", b.wall_clock_s, self.wall_clock_s);
        over("depth", b.depth.into(), self.depth.into());
        over("fanout", b.fanout.into(), self.fanout.into());
        match (self.usd, b.usd) {
            (Some(cap), None) => {
                out.push(format!("budgets.usd is required: the tenant caps what one run may spend at ${cap}"))
            }
            (Some(cap), Some(got)) if got > cap => {
                out.push(format!("budgets.usd = {got} exceeds the tenant's node cap of {cap}"));
            }
            _ => {}
        }
        out
    }
}

impl Default for NodeCaps {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The state of another version of the tenant's nodes, as publish-time validation sees it.
#[derive(Debug, Clone, PartialEq)]
pub enum RefState {
    Missing,
    Draft,
    Retired,
    Published(Box<NodeSpec>),
}

/// What publish-time validation needs to know about the tenant.
pub trait PublishContext {
    /// `Ok` when `scope` (`<datasource>.<object>:<access>`) names something the tenant has.
    fn scope_exists(&self, scope: &str) -> Result<(), String>;
    /// Another version of the tenant's nodes.
    fn version(&self, name: &str, version: u32) -> RefState;
    fn caps(&self) -> NodeCaps;
    /// Hook for the approved tool registry (P3 M4). `mcp://` references reach it pinned.
    fn check_tool(&self, _target: &ToolTarget) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("cannot publish {name}@v{version}: {}", problems.join("; "))]
pub struct PublishError {
    pub name: String,
    pub version: u32,
    pub problems: Vec<String>,
}

/// Every reason `spec` (version `version` of node `name`) cannot be published; `Ok` when none.
pub fn validate_for_publish(
    name: &str,
    version: u32,
    spec: &NodeSpec,
    ctx: &dyn PublishContext,
) -> Result<(), PublishError> {
    let mut problems = Vec::new();
    if let Err(e) = spec.validate() {
        problems.push(e.to_string());
    }
    for t in &spec.tools {
        if let Ok(target) = ToolTarget::parse(&t.reference)
            && let Err(e) = ctx.check_tool(&target)
        {
            problems.push(format!("tool '{}': {e}", t.reference));
        }
    }
    for scope in spec.datasource_scopes() {
        if let Err(e) = ctx.scope_exists(&scope) {
            problems.push(format!("datasource scope '{scope}': {e}"));
        }
    }
    problems.extend(ctx.caps().violations(spec));
    let refs = spec.node_refs();
    for (n, v) in &refs {
        if n == name && *v == version {
            problems.push(format!("node://{n}@v{v} refers to this version itself"));
            continue;
        }
        match ctx.version(n, *v) {
            RefState::Published(_) => {}
            RefState::Missing => problems.push(format!("node://{n}@v{v} does not exist in this tenant")),
            RefState::Draft => problems.push(format!("node://{n}@v{v} is a draft; publish it first")),
            RefState::Retired => problems.push(format!("node://{n}@v{v} is retired")),
        }
    }
    if let Some(cycle) = find_cycle(name, version, &refs, ctx) {
        problems.push(format!("node references form a cycle: {cycle}"));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        problems.dedup();
        Err(PublishError { name: name.to_owned(), version, problems })
    }
}

/// A path back to (`name`, `version`) through published versions, if there is one.
fn find_cycle(name: &str, version: u32, refs: &[(String, u32)], ctx: &dyn PublishContext) -> Option<String> {
    fn walk(
        at: &(String, u32),
        target: &(String, u32),
        ctx: &dyn PublishContext,
        path: &mut Vec<(String, u32)>,
        seen: &mut HashSet<(String, u32)>,
    ) -> bool {
        if at == target {
            return true;
        }
        if !seen.insert(at.clone()) {
            return false;
        }
        let RefState::Published(spec) = ctx.version(&at.0, at.1) else { return false };
        for next in spec.node_refs() {
            path.push(next.clone());
            if walk(&next, target, ctx, path, seen) {
                return true;
            }
            path.pop();
        }
        false
    }
    let target = (name.to_owned(), version);
    let mut seen = HashSet::new();
    for r in refs {
        let mut path = vec![target.clone(), r.clone()];
        if walk(r, &target, ctx, &mut path, &mut seen) {
            return Some(path.iter().map(|(n, v)| format!("{n}@v{v}")).collect::<Vec<_>>().join(" -> "));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    struct Ctx {
        versions: HashMap<(String, u32), RefState>,
        scopes: Vec<&'static str>,
        caps: NodeCaps,
    }

    impl PublishContext for Ctx {
        fn scope_exists(&self, scope: &str) -> Result<(), String> {
            if self.scopes.contains(&scope) { Ok(()) } else { Err("no such datasource object".into()) }
        }
        fn version(&self, name: &str, version: u32) -> RefState {
            self.versions.get(&(name.to_owned(), version)).cloned().unwrap_or(RefState::Missing)
        }
        fn caps(&self) -> NodeCaps {
            self.caps
        }
    }

    fn spec(tools: &[&str], scopes: &[&str], steps: u32) -> NodeSpec {
        serde_json::from_value(json!({
            "kind": "agent", "prompt": {"system": "x"}, "model_policy": {},
            "tools": tools.iter().map(|t| json!({"ref": t, "effect": "read"})).collect::<Vec<_>>(),
            "datasources": {"scopes": scopes},
            "budgets": {"steps": steps, "tokens": 1000, "wall_clock_s": 30}
        }))
        .unwrap()
    }

    fn ctx() -> Ctx {
        let mut versions = HashMap::new();
        versions.insert(("risk".to_owned(), 1), RefState::Published(Box::new(spec(&[], &[], 3))));
        versions.insert(("risk".to_owned(), 2), RefState::Draft);
        versions.insert(("old".to_owned(), 1), RefState::Retired);
        Ctx { versions, scopes: vec!["erp.invoices:read"], caps: NodeCaps::DEFAULT }
    }

    #[test]
    fn a_clean_version_publishes() {
        let s = spec(&["node://risk@v1"], &["erp.invoices:read"], 10);
        assert_eq!(validate_for_publish("triage", 1, &s, &ctx()), Ok(()));
    }

    #[test]
    fn every_problem_is_reported() {
        let s = spec(&["node://risk@v2", "node://old@v1", "node://ghost@v1"], &["erp.orders:read"], 500);
        let e = validate_for_publish("triage", 1, &s, &ctx()).unwrap_err();
        let all = e.problems.join("\n");
        for want in ["is a draft", "is retired", "does not exist", "erp.orders:read", "budgets.steps = 500 exceeds"] {
            assert!(all.contains(want), "missing '{want}' in {all}");
        }
    }

    #[test]
    fn cycles_through_published_versions_are_refused() {
        // b@v1 calls a@v3; a@v3 (being published) calls b@v1.
        let mut c = ctx();
        c.versions.insert(("b".to_owned(), 1), RefState::Published(Box::new(spec(&["node://a@v3"], &[], 3))));
        let s = spec(&["node://b@v1"], &[], 3);
        let e = validate_for_publish("a", 3, &s, &c).unwrap_err();
        assert!(e.problems.iter().any(|p| p.contains("cycle: a@v3 -> b@v1 -> a@v3")), "{e}");
        let me = spec(&["node://a@v3"], &[], 3);
        assert!(validate_for_publish("a", 3, &me, &c).unwrap_err().to_string().contains("itself"));
    }

    #[test]
    fn caps_are_checked() {
        let caps = NodeCaps { steps: 5, tokens: 10, wall_clock_s: 1, depth: 1, fanout: 1, usd: None };
        let v = caps.violations(&spec(&[], &[], 5));
        assert_eq!(v.len(), 4, "{v:?}"); // tokens, wall clock, depth (3 > 1), fanout (8 > 1)
        assert!(NodeCaps { steps: 0, ..caps }.validate().is_err());
        let usd = NodeCaps { usd: Some(0.5), ..NodeCaps::DEFAULT };
        assert!(usd.violations(&spec(&[], &[], 5))[0].contains("budgets.usd is required"));
        let mut s = spec(&[], &[], 5);
        s.budgets.usd = Some(0.75);
        assert!(usd.violations(&s)[0].contains("budgets.usd = 0.75 exceeds"));
        s.budgets.usd = Some(0.25);
        assert!(usd.violations(&s).is_empty());
    }
}
