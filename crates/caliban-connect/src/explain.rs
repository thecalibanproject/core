//! Native-lane dry run: summarize `explain` (`queryPlanner` verbosity, which does not execute)
//! and decide whether the pipeline may run on the source or belongs on the CDC replica
//! (research 08, "Validation steps" 4 and 6).
//!
//! Handles the classic shape (`stages[0].$cursor.queryPlanner.winningPlan`), the SBE shape
//! (`queryPlanner.winningPlan.queryPlan`, `explainVersion: "2"`) and sharded replies
//! (`shards.<name>.…`): every `winningPlan` subtree is walked; `rejectedPlans` are ignored.

use serde::{Deserialize, Serialize};
use serde_json::Value as J;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ExplainSummary {
    pub explain_version: Option<String>,
    /// Query-plan stages of the winning plan(s), in walk order (`COLLSCAN`, `IXSCAN`, `GROUP`, …).
    pub plan_stages: Vec<String>,
    /// Aggregation stages left outside the query layer (`$lookup`, `$sort`, …), classic explain.
    pub pipeline_stages: Vec<String>,
    pub collscan: bool,
    pub index_names: Vec<String>,
    /// `$lookup` join strategies reported by SBE (`IndexedLoopJoin`, `NestedLoopJoin`, `HashJoin`).
    pub lookup_strategies: Vec<String>,
    /// An in-memory `SORT` stage (no index provides the order).
    pub blocking_sort: bool,
}

fn walk_plan(v: &J, s: &mut ExplainSummary) {
    match v {
        J::Object(o) => {
            if let Some(stage) = o.get("stage").and_then(J::as_str) {
                s.plan_stages.push(stage.to_owned());
                match stage {
                    "COLLSCAN" => s.collscan = true,
                    "SORT" => s.blocking_sort = true,
                    _ => {}
                }
            }
            if let Some(ix) = o.get("indexName").and_then(J::as_str) {
                s.index_names.push(ix.to_owned());
            }
            if let Some(strategy) = o.get("strategy").and_then(J::as_str) {
                s.lookup_strategies.push(strategy.to_owned());
            }
            for (k, child) in o {
                if k != "rejectedPlans" {
                    walk_plan(child, s);
                }
            }
        }
        J::Array(a) => a.iter().for_each(|c| walk_plan(c, s)),
        _ => {}
    }
}

fn walk(v: &J, s: &mut ExplainSummary) {
    match v {
        J::Object(o) => {
            for (k, child) in o {
                match k.as_str() {
                    "winningPlan" => walk_plan(child, s),
                    "rejectedPlans" => {}
                    "stages" => {
                        for st in child.as_array().into_iter().flatten() {
                            if let Some(name) = st.as_object().and_then(|o| o.keys().next())
                                && name != "$cursor"
                            {
                                s.pipeline_stages.push(name.clone());
                                if name == "$sort" {
                                    s.blocking_sort = true;
                                }
                            }
                            walk(st, s);
                        }
                    }
                    _ => walk(child, s),
                }
            }
        }
        J::Array(a) => a.iter().for_each(|c| walk(c, s)),
        _ => {}
    }
}

pub fn summarize(explain: &J) -> ExplainSummary {
    let mut s = ExplainSummary {
        explain_version: explain.get("explainVersion").and_then(J::as_str).map(str::to_owned),
        ..Default::default()
    };
    walk(explain, &mut s);
    let dedup = |v: &mut Vec<String>| {
        let mut seen = BTreeSet::new();
        v.retain(|x| seen.insert(x.clone()));
    };
    dedup(&mut s.index_names);
    dedup(&mut s.lookup_strategies);
    s
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatePolicy {
    /// A COLLSCAN is tolerated only on collections at most this large (estimated documents).
    pub max_collscan_docs: u64,
    /// Reject `$lookup` executed as a nested-loop or hash join (unindexed foreign field).
    pub reject_unindexed_lookup: bool,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self { max_collscan_docs: 100_000, reject_unindexed_lookup: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GateReport {
    pub summary: ExplainSummary,
    pub estimated_docs: Option<u64>,
    /// `true`: may run natively. `false`: route to the replica (reasons say why).
    pub native_ok: bool,
    pub reasons: Vec<String>,
}

pub fn gate(summary: ExplainSummary, estimated_docs: Option<u64>, policy: &GatePolicy) -> GateReport {
    let mut reasons = Vec::new();
    if summary.collscan {
        match estimated_docs {
            Some(n) if n <= policy.max_collscan_docs => {}
            Some(n) => reasons.push(format!("COLLSCAN over ~{n} documents (limit {})", policy.max_collscan_docs)),
            None => reasons.push("COLLSCAN over a collection of unknown size".to_owned()),
        }
    }
    if policy.reject_unindexed_lookup {
        for s in &summary.lookup_strategies {
            if s == "NestedLoopJoin" || s == "HashJoin" {
                reasons.push(format!("$lookup runs as {s} (foreign field not indexed)"));
            }
        }
    }
    GateReport { native_ok: reasons.is_empty(), reasons, summary, estimated_docs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sbe_collscan() -> J {
        json!({
          "explainVersion": "2",
          "queryPlanner": {
            "namespace": "shop.orders",
            "winningPlan": { "queryPlan": {
              "stage": "GROUP", "planNodeId": 5,
              "inputStage": { "stage": "UNWIND", "inputStage": {
                "stage": "EQ_LOOKUP", "foreignCollection": "shop.customers", "strategy": "IndexedLoopJoin", "indexName": "_id_",
                "inputStage": { "stage": "COLLSCAN", "filter": { "status": { "$in": ["paid"] } }, "direction": "forward" } } } },
              "slotBasedPlan": { "stages": "[5] group ..." } },
            "rejectedPlans": [ { "queryPlan": { "stage": "IXSCAN", "indexName": "never_used" } } ]
          },
          "stages": [ { "$cursor": { "queryPlanner": {} } }, { "$sort": { "sortKey": { "gross_revenue": -1 } } } ],
          "ok": 1.0
        })
    }

    #[test]
    fn parses_sbe_plan_and_ignores_rejected() {
        let s = summarize(&sbe_collscan());
        assert_eq!(s.explain_version.as_deref(), Some("2"));
        assert_eq!(s.plan_stages, vec!["GROUP", "UNWIND", "EQ_LOOKUP", "COLLSCAN"]);
        assert!(s.collscan);
        assert_eq!(s.index_names, vec!["_id_"]);
        assert_eq!(s.lookup_strategies, vec!["IndexedLoopJoin"]);
        assert_eq!(s.pipeline_stages, vec!["$sort"]);
        assert!(!s.plan_stages.contains(&"IXSCAN".to_string()));
    }

    #[test]
    fn parses_classic_cursor_shape() {
        let v = json!({
          "stages": [
            { "$cursor": { "queryPlanner": { "winningPlan": {
                "stage": "FETCH", "inputStage": { "stage": "IXSCAN", "indexName": "createdAt_1", "keyPattern": { "createdAt": 1 } } } } } },
            { "$lookup": { "from": "customers", "as": "__customer" } },
            { "$group": { "_id": "$x" } }
          ] });
        let s = summarize(&v);
        assert!(!s.collscan);
        assert_eq!(s.plan_stages, vec!["FETCH", "IXSCAN"]);
        assert_eq!(s.index_names, vec!["createdAt_1"]);
        assert_eq!(s.pipeline_stages, vec!["$lookup", "$group"]);
    }

    #[test]
    fn gate_rejects_large_collscan_and_unindexed_lookup() {
        let s = summarize(&sbe_collscan());
        let p = GatePolicy::default();
        assert!(gate(s.clone(), Some(5_000), &p).native_ok);
        let r = gate(s.clone(), Some(5_000_000), &p);
        assert!(!r.native_ok && r.reasons[0].contains("COLLSCAN"));
        assert!(!gate(s, None, &p).native_ok);

        let mut nl = sbe_collscan();
        nl["queryPlanner"]["winningPlan"]["queryPlan"]["inputStage"]["inputStage"]["strategy"] =
            json!("NestedLoopJoin");
        let r = gate(summarize(&nl), Some(10), &p);
        assert!(!r.native_ok && r.reasons[0].contains("NestedLoopJoin"), "{r:?}");
    }
}
