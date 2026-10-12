//! Ontology review and versions on the control plane (research notes 03 and 08).
//!
//! **Tenant scope.** Element ids are the tenant's own (two tenants may both have `Service`): every
//! lookup is by tenant and id. `POST /api/v1/tenants/{t}/ontology/review` takes a batch of
//! decisions; the older `POST /api/v1/ontology/elements/{id}/review` needs `tenant_id` in its body.
//!
//! **Versions.** A review batch is one ontology version (none when it changes nothing). Each
//! element records the version its definition (spec or status) last changed in (`changed_in`). A
//! CQIR query names the version it was written for, and keeps compiling on later versions as long
//! as nothing it touches changed after it (`caliban_ontology::compile::plan`): approving new
//! elements, or changing ones the query does not use, is compatible.
//!
//! **Breaking changes are flagged at review time.** A decision that withdraws an approved element
//! (reject, deprecate, mark stale) breaks the published node versions whose fixed CQIR queries
//! touch it. The review is refused (`409`, with the element and the node versions) unless it says
//! `acknowledge_breaking: true`; those versions then fail on that query until a version written on
//! the new ontology is published. **Publishing** checks every fixed CQIR query of the spec: its
//! version must be the tenant's, not newer than the current one, and still compatible.

use crate::store::{NodeRecord, NodeState, State};
use caliban_ontology::compile::{CompileError, plan};
use caliban_ontology::cqir::Query;
use caliban_ontology::{Model, Ontology, Status};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

/// Every fixed CQIR query of a spec: objects with `ontology_version` and `metrics`, with where
/// they are (a JSON pointer).
pub(crate) fn fixed_queries(spec: &Value) -> Vec<(String, Value)> {
    fn walk(v: &Value, path: &str, out: &mut Vec<(String, Value)>) {
        match v {
            Value::Object(m) => {
                if m.contains_key("ontology_version") && m.contains_key("metrics") {
                    out.push((path.to_owned(), v.clone()));
                    return;
                }
                for (k, x) in m {
                    walk(x, &format!("{path}/{}", k.replace('~', "~0").replace('/', "~1")), out);
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    walk(x, &format!("{path}/{i}"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(spec, "", &mut out);
    out
}

/// The element ids a query touches, as far as `model` (the full ontology, every status) knows
/// them: its metrics, attributes and their entities (embedded parents included), the metrics'
/// attributes and grains.
fn touched(model: &Model, q: &Value) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    let strs = |v: Option<&Value>, key: &str| -> Vec<String> {
        v.and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|x| x.get(key).and_then(Value::as_str).map(str::to_owned))
            .collect()
    };
    ids.extend(strs(q.get("metrics"), "id"));
    ids.extend(strs(q.get("dimensions"), "id"));
    ids.extend(strs(q.get("filters"), "attr"));
    ids.extend(strs(q.get("order_by"), "metric"));
    ids.extend(strs(q.get("order_by"), "dimension"));
    let metrics: Vec<String> = ids.iter().filter(|i| model.metrics.contains_key(*i)).cloned().collect();
    for m in metrics {
        let def = &model.metrics[&m];
        ids.insert(def.grain.clone());
        let mut attrs = Vec::new();
        metric_attrs(&def.expr, &mut attrs);
        ids.extend(attrs);
        ids.extend(def.filters.iter().map(|f| f.attr.clone()));
    }
    let attrs: Vec<String> = ids.iter().filter_map(|i| model.attributes.get(i).map(|a| a.entity.clone())).collect();
    ids.extend(attrs);
    // Embedded entities live in their parents' documents.
    let mut stack: Vec<String> = ids.iter().filter(|i| model.entities.contains_key(*i)).cloned().collect();
    while let Some(e) = stack.pop() {
        if let Some(caliban_ontology::model::EntityBinding::Embedded { parent, .. }) =
            model.entities.get(&e).map(|d| &d.binding)
            && ids.insert(parent.clone())
        {
            stack.push(parent.clone());
        }
    }
    ids
}

fn metric_attrs(e: &caliban_ontology::model::MetricExpr, out: &mut Vec<String>) {
    use caliban_ontology::model::MetricExpr::{Add, Attr, Mul, Rows, Sub};
    match e {
        Attr { id } => out.push(id.clone()),
        Mul { left, right } | Add { left, right } | Sub { left, right } => {
            metric_attrs(left, out);
            metric_attrs(right, out);
        }
        Rows => {}
    }
}

/// Every element of `o` as if approved: what the ids of a query may name, whatever their status.
fn full_model(o: &Ontology) -> Model {
    let mut all = o.clone();
    for e in &mut all.elements {
        e.status = Status::Approved;
    }
    Model::from_ontology(&all)
}

/// A published node version that review decisions would break.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct Breaking {
    pub element: String,
    pub change: String,
    /// `name@vN` of the published versions whose fixed queries touch it.
    pub nodes: Vec<String>,
}

/// What `decisions` on the tenant's ontology would break: approved elements they withdraw that
/// published node versions' fixed CQIR queries touch.
pub(crate) fn breaking(st: &State, tenant: &str, decisions: &[(String, Status)]) -> Vec<Breaking> {
    let Some(o) = st.ontologies.get(tenant) else { return vec![] };
    let model = full_model(o);
    let published: Vec<&NodeRecord> =
        st.nodes.iter().filter(|n| n.tenant_id == tenant && n.is_live() && n.state == NodeState::Published).collect();
    let mut out = Vec::new();
    for (id, to) in decisions {
        let Some(e) = o.elements.iter().find(|e| &e.id == id) else { continue };
        if e.status != Status::Approved || *to == Status::Approved {
            continue;
        }
        let nodes: Vec<String> = published
            .iter()
            .filter(|n| fixed_queries(&n.spec).iter().any(|(_, q)| touched(&model, q).contains(id)))
            .map(|n| format!("{}@v{}", n.name, n.version))
            .collect();
        if !nodes.is_empty() {
            out.push(Breaking { element: id.clone(), change: format!("approved -> {}", status_str(*to)), nodes });
        }
    }
    out
}

fn status_str(s: Status) -> &'static str {
    match s {
        Status::Proposed => "proposed",
        Status::Approved => "approved",
        Status::Rejected => "rejected",
        Status::Stale => "stale",
        Status::Deprecated => "deprecated",
    }
}

/// Publish-time check of a spec's fixed CQIR queries against the tenant's current ontology: the
/// version they name must be the tenant's and not newer than the current one, and nothing they
/// touch may have changed since (or be withdrawn). Values filled by templates are not checked
/// here (they are known only when the node runs).
pub(crate) fn publish_problems(st: &State, tenant: &str, spec: &Value) -> Vec<caliban_nodes::publish::Problem> {
    use caliban_nodes::publish::Problem;
    let queries = fixed_queries(spec);
    if queries.is_empty() {
        return vec![];
    }
    let empty = Ontology { tenant_id: tenant.to_owned(), version: 0, elements: vec![] };
    let o = st.ontologies.get(tenant).unwrap_or(&empty);
    let model = Model::from_ontology(o);
    let mut out = Vec::new();
    for (path, q) in queries {
        let problem = |m: String| Problem::new("ontology_version", m, Some(path.clone()));
        let query: Query = match serde_json::from_value(q.clone()) {
            Ok(q) => q,
            Err(e) => {
                out.push(problem(format!("not a CQIR query: {e}")));
                continue;
            }
        };
        match plan(&model, &query, &[]) {
            Ok(_) => {}
            Err(e @ (CompileError::VersionMismatch { .. } | CompileError::Changed { .. })) => {
                out.push(problem(e.to_string()));
            }
            Err(e @ (CompileError::Unknown(..) | CompileError::NoPath { .. })) => {
                out.push(problem(format!("{e} in ontology {}", model.version)));
            }
            // Type checks of literal values: templates fill them when the node runs.
            Err(_) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::NodeState;
    use caliban_ontology::Element;
    use serde_json::json;

    fn el(id: &str, kind: &str, spec: Value, changed_in: u64) -> Element {
        serde_json::from_value(json!({"id": id, "name": id, "status": "approved", "provenance": "human",
            "kind": kind, "spec": spec, "changed_in": changed_in}))
        .unwrap()
    }

    fn ontology(version: u64, region_changed_in: u64) -> Ontology {
        Ontology {
            tenant_id: "acme".into(),
            version,
            elements: vec![
                el(
                    "Service",
                    "entity",
                    json!({"binding": {"type": "root", "datasource": "ds", "collection": "services"}, "keys": ["_id"]}),
                    1,
                ),
                el(
                    "Service.specialty",
                    "attribute",
                    json!({"entity": "Service", "path": "specialty", "column": "specialty", "data_type": "string"}),
                    1,
                ),
                el(
                    "Service.city",
                    "attribute",
                    json!({"entity": "Service", "path": "city", "column": "city", "data_type": "string"}),
                    region_changed_in,
                ),
                el(
                    "services",
                    "metric",
                    json!({"grain": "Service", "aggregation": "count", "expr": {"op": "rows"}}),
                    1,
                ),
                el(
                    "Facility",
                    "entity",
                    json!({"binding": {"type": "root", "datasource": "ds", "collection": "facilities"}, "keys": ["_id"]}),
                    2,
                ),
            ],
        }
    }

    /// A node version whose tool vertex holds a fixed CQIR query on `version`, with a templated
    /// filter value.
    fn node(version: &str, state: NodeState) -> NodeRecord {
        let spec = json!({"kind": "workflow", "graph": {"vertices": [{"id": "services", "type": "tool", "config": {
            "tool": "builtin://datasource_query",
            "args": {"query": {"ir_version": "1", "ontology_version": version, "metrics": [{"id": "services"}],
                     "dimensions": [{"id": "Service.specialty"}],
                     "filters": [{"attr": "Service.city", "op": "eq", "value": {"type": "string", "v": "{{outputs.assess.city}}"}}]}}
        }}]}});
        NodeRecord {
            id: "node_1".into(),
            tenant_id: "acme".into(),
            name: "triage".into(),
            version: 3,
            hash: caliban_nodes::hash::content_hash(&spec),
            spec,
            state,
            created_at: chrono::Utc::now(),
            created_by: None,
            published_at: None,
            retired_at: None,
            sealed_spec: None,
            deleted_at: None,
        }
    }

    fn state(o: Ontology, n: NodeRecord) -> State {
        let mut st = State::default();
        st.ontologies.insert("acme".into(), o);
        st.nodes.push(n);
        st
    }

    #[test]
    fn publishing_checks_the_version_fixed_queries_name() {
        // Written on 2; 3 approved Facility (not touched): compatible.
        let st = state(ontology(3, 1), node("acme@2", NodeState::Draft));
        assert!(publish_problems(&st, "acme", &st.nodes[0].spec).is_empty());
        // Service.city, which the filter uses, changed in 3: breaking, and the path says where.
        let st = state(ontology(3, 3), node("acme@2", NodeState::Draft));
        let p = publish_problems(&st, "acme", &st.nodes[0].spec);
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].message.contains("'Service.city' changed in version 3"), "{}", p[0].message);
        assert_eq!(p[0].path.as_deref(), Some("/graph/vertices/0/config/args/query"));
        // A version that does not exist yet, or another tenant's.
        for v in ["acme@4", "globex@3"] {
            let st = state(ontology(3, 1), node(v, NodeState::Draft));
            assert_eq!(publish_problems(&st, "acme", &st.nodes[0].spec).len(), 1, "{v}");
        }
    }

    #[test]
    fn withdrawing_an_element_a_published_node_queries_is_breaking() {
        let st = state(ontology(3, 1), node("acme@3", NodeState::Published));
        // Approving or withdrawing what no fixed query touches: nothing to flag.
        assert!(breaking(&st, "acme", &[("Facility".into(), Status::Rejected)]).is_empty());
        // The grain entity of a metric it uses, an attribute of a filter: flagged with the node.
        let b =
            breaking(&st, "acme", &[("Service".into(), Status::Deprecated), ("Service.city".into(), Status::Rejected)]);
        assert_eq!(b.len(), 2);
        assert_eq!((b[0].element.as_str(), b[0].nodes.clone()), ("Service", vec!["triage@v3".to_owned()]));
        assert_eq!(b[1].change, "approved -> rejected");
        // Drafts and retired versions are not published: nothing breaks.
        let st = state(ontology(3, 1), node("acme@3", NodeState::Draft));
        assert!(breaking(&st, "acme", &[("Service".into(), Status::Rejected)]).is_empty());
    }
}
