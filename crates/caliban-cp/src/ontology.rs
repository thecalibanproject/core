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
//! version must be the tenant's, not newer than the current one, and still compatible, and its
//! static parts must compile. Templates in filter values (`{"type": "string_list", "v":
//! "{{outputs.assess.cities}}"}`) stand for a value of the declared type until the node runs.
//!
//! **Proposals** (`POST /api/v1/tenants/{t}/ontology/proposals`, [`proposals`]): an element whose
//! spec, name and description are unchanged is skipped whatever status it is sent with, so posting
//! the tenant's model again is a no-op and never overwrites a review decision. A changed element
//! goes back to `proposed`; over an approved element that is a withdrawal, flagged like a review.

use crate::store::{NodeRecord, NodeState, State};
use caliban_ontology::compile::{CompileError, plan};
use caliban_ontology::cqir::Query;
use caliban_ontology::{Element, Model, Ontology, Status};
use serde::Serialize;
use serde_json::{Value, json};
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

/// Proposed elements against the tenant's ontology: the ones to write (as `proposed`), how many
/// were skipped as unchanged (whatever status they were sent with), and what writing them breaks.
pub(crate) fn proposals(st: &State, tenant: &str, elements: Vec<Element>) -> (Vec<Element>, usize, Vec<Breaking>) {
    let current = st.ontologies.get(tenant);
    let n = elements.len();
    let write: Vec<Element> = elements
        .into_iter()
        .filter(|e| current.and_then(|o| o.elements.iter().find(|x| x.id == e.id)).is_none_or(|x| !x.same_proposal(e)))
        .map(|e| Element { status: Status::Proposed, changed_in: None, ..e })
        .collect();
    let withdrawn: Vec<(String, Status)> = write.iter().map(|e| (e.id.clone(), Status::Proposed)).collect();
    let breaking = breaking(st, tenant, &withdrawn);
    let skipped = n - write.len();
    (write, skipped, breaking)
}

/// A published node version that review decisions would break.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct Breaking {
    pub element: String,
    pub change: String,
    /// `name@vN` of the published versions whose fixed queries touch it.
    pub nodes: Vec<String>,
    /// The same versions, structured.
    pub versions: Vec<NodeVersion>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct NodeVersion {
    pub node: String,
    pub version: u32,
}

/// The error of the routes that can withdraw approved elements: a refusal because published node
/// versions query them (`409`) carries `code: "ontology_breaking_change"` and the `breaking` list
/// next to the message, so a client does not have to parse the message.
pub(crate) enum OntologyError {
    Api(crate::ApiError),
    Breaking(String, Vec<Breaking>),
}

impl From<crate::ApiError> for OntologyError {
    fn from(e: crate::ApiError) -> Self {
        Self::Api(e)
    }
}

impl From<crate::StoreError> for OntologyError {
    fn from(e: crate::StoreError) -> Self {
        Self::Api(e.into())
    }
}

impl axum::response::IntoResponse for OntologyError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Api(e) => e.into_response(),
            Self::Breaking(message, breaking) => {
                let body = serde_json::json!({"error": {"message": message, "type": "conflict",
                                                        "code": BREAKING_CODE, "breaking": breaking}});
                (axum::http::StatusCode::CONFLICT, axum::Json(body)).into_response()
            }
        }
    }
}

/// `error.code` of a refused withdrawal.
pub(crate) const BREAKING_CODE: &str = "ontology_breaking_change";

/// A refusal: `what` and the elements with the node versions they break.
pub(crate) fn refuse(what: &str, breaking: Vec<Breaking>) -> OntologyError {
    let list = breaking.iter().map(|b| format!("{} ({}): {}", b.element, b.change, b.nodes.join(", ")));
    let message = format!(
        "{what}; publish versions written on the new ontology, or send acknowledge_breaking: true: {}",
        list.collect::<Vec<_>>().join("; ")
    );
    OntologyError::Breaking(message, breaking)
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
        let versions: Vec<NodeVersion> = published
            .iter()
            .filter(|n| fixed_queries(&n.spec).iter().any(|(_, q)| touched(&model, q).contains(id)))
            .map(|n| NodeVersion { node: n.name.clone(), version: n.version })
            .collect();
        if !versions.is_empty() {
            let nodes = versions.iter().map(|v| format!("{}@v{}", v.node, v.version)).collect();
            let change = format!("approved -> {}", status_str(*to));
            out.push(Breaking { element: id.clone(), change, nodes, versions });
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

/// Is `s` exactly one `{{ expr }}` placeholder? Then the executor replaces it by the value itself,
/// of any JSON type (`render_value` in `caliban_nodes::executor::template`).
fn whole_template(s: &str) -> bool {
    s.trim()
        .strip_prefix("{{")
        .and_then(|x| x.strip_suffix("}}"))
        .is_some_and(|inner| !inner.contains("{{") && !inner.contains("}}"))
}

/// A value of the CQIR literal type `ty` (`v` of a filter value) standing for a template, and one
/// for an element of it when it is a list or a range.
fn placeholder(ty: &str) -> Option<(Value, Value)> {
    const TS: &str = "1970-01-01T00:00:00Z";
    Some(match ty {
        "string" => (json!("x"), json!("x")),
        "number" => (json!(0), json!(0)),
        "bool" => (json!(false), json!(false)),
        "timestamp" => (json!(TS), json!(TS)),
        "string_list" => (json!(["x"]), json!("x")),
        "number_list" => (json!([0]), json!(0)),
        "timestamp_range" => (json!([TS, TS]), json!(TS)),
        "number_range" => (json!([0, 0]), json!(0)),
        _ => return None,
    })
}

/// `q` with the templates of its template slots replaced by placeholders of the declared type, as
/// the executor fills them before deserializing the query, and the attributes of the filters whose
/// literal is still unknown (a whole-value template, or text around a placeholder): their literal
/// checks wait for the run. A placeholder has the declared type, so a literal check that fails on
/// it is a static mistake (a type that does not fit the operator or the attribute).
///
/// The template slots are filter values: the whole `value` (`"value": "{{outputs.x.value}}"`), its
/// `v`, or an element of a list or range `v`. Anything else (ids, operators, `ontology_version`,
/// `limit`) is static: a template there is checked as written, so it is refused.
fn fill_templates(q: &Value) -> (Value, BTreeSet<String>) {
    let mut q = q.clone();
    let mut templated = BTreeSet::new();
    let has_template = |v: &Value| v.to_string().contains("{{");
    let Some(filters) = q.get_mut("filters").and_then(Value::as_array_mut) else { return (q, templated) };
    for f in filters.iter_mut().filter_map(Value::as_object_mut) {
        let attr = f.get("attr").and_then(Value::as_str).map(str::to_owned);
        let Some(value) = f.get_mut("value") else { continue };
        if !has_template(value) {
            continue;
        }
        if value.as_str().is_some_and(whole_template) {
            // The whole typed value comes from the run: its type is not known here.
            *value = Value::Null;
            templated.extend(attr);
            continue;
        }
        if let Some(obj) = value.as_object_mut()
            && let Some((whole, element)) = obj.get("type").and_then(Value::as_str).and_then(placeholder)
            && let Some(v) = obj.get_mut("v")
        {
            match v {
                Value::String(s) if whole_template(s) => *v = whole,
                Value::Array(a) => {
                    for x in a.iter_mut().filter(|x| x.as_str().is_some_and(whole_template)) {
                        *x = element.clone();
                    }
                }
                // Text around a placeholder renders to a string: deserialized as it is.
                _ => {}
            }
        }
        if has_template(value) {
            templated.extend(attr);
        }
    }
    (q, templated)
}

/// Publish-time check of a spec's fixed CQIR queries against the tenant's current ontology: the
/// version they name must be the tenant's and not newer than the current one, nothing they touch
/// may have changed since (or be withdrawn), and the static parts (ids, operators, structure) must
/// compile. Templates are accepted in template slots (filter values, see [`fill_templates`]): they
/// are replaced by placeholders of the declared type, and the literal checks of those filters wait
/// for the run, where the executor renders the templates and compiles the query again.
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
        let (filled, templated) = fill_templates(&q);
        let query: Query = match serde_json::from_value(filled) {
            Ok(q) => q,
            Err(e) => {
                out.push(problem(format!("not a CQIR query: {e}")));
                continue;
            }
        };
        match plan(&model, &query, &[]) {
            Ok(_) => {}
            Err(e @ (CompileError::Unknown(..) | CompileError::NoPath { .. })) => {
                out.push(problem(format!("{e} in ontology {}", model.version)));
            }
            // Literals a template leaves unknown are checked when the node runs; policies apply
            // as they are then.
            Err(CompileError::BadValue(a)) if templated.contains(&a) => {}
            Err(CompileError::Denied(_)) => {}
            Err(e) => out.push(problem(e.to_string())),
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

    /// The ontology of [`ontology`] with a number and a timestamp attribute, and a spec whose
    /// one fixed query (on version 3) has `filters`.
    fn with_filters(filters: Value) -> (State, Value) {
        let mut o = ontology(3, 1);
        for (id, ty) in [("Service.price", "number"), ("Service.updated", "timestamp")] {
            let spec = json!({"entity": "Service", "path": id, "column": id, "data_type": ty});
            o.elements.push(el(id, "attribute", spec, 1));
        }
        let mut st = State::default();
        st.ontologies.insert("acme".into(), o);
        let spec = json!({"kind": "workflow", "graph": {"vertices": [{"id": "q", "type": "tool", "config": {
            "tool": "builtin://datasource_query",
            "args": {"query": {"ir_version": "1", "ontology_version": "acme@3", "metrics": [{"id": "services"}],
                     "dimensions": [{"id": "Service.specialty"}], "filters": filters}}}}]}});
        (st, spec)
    }

    /// e2e follow-up: the triage node's `{"type": "string_list", "v": "{{outputs.assess.cities}}"}`
    /// was refused at publish ("not a CQIR query: invalid type: string, expected a sequence"),
    /// although the executor fills it with a list before it deserializes the query.
    #[test]
    fn templates_in_filter_values_publish() {
        let (st, spec) = with_filters(json!([
            {"attr": "Service.specialty", "op": "in",
             "value": {"type": "string_list", "v": ["{{outputs.assess.specialty}}", "emergency_medicine"]}},
            {"attr": "Service.city", "op": "in", "value": {"type": "string_list", "v": "{{outputs.assess.cities}}"}},
            {"attr": "Service.city", "op": "eq", "value": {"type": "string", "v": "{{ outputs.assess.city }}"}},
            {"attr": "Service.city", "op": "ne", "value": {"type": "string", "v": "near {{input.city}}"}},
            {"attr": "Service.price", "op": "lte", "value": {"type": "number", "v": "{{input.budget}}"}},
            {"attr": "Service.price", "op": "in", "value": {"type": "number_list", "v": [1, "{{input.price}}"]}},
            {"attr": "Service.price", "op": "between", "value": {"type": "number_range", "v": "{{input.range}}"}},
            {"attr": "Service.updated", "op": "gte", "value": {"type": "timestamp", "v": "{{input.since}}"}},
            {"attr": "Service.updated", "op": "lt", "value": {"type": "timestamp", "v": "{{input.day}}T00:00:00Z"}},
            {"attr": "Service.updated", "op": "between",
             "value": {"type": "timestamp_range", "v": ["{{input.from}}", "2026-01-01T00:00:00Z"]}},
            {"attr": "Service.specialty", "op": "eq", "value": "{{outputs.assess.filter}}"}
        ]));
        let p = publish_problems(&st, "acme", &spec);
        assert!(p.is_empty(), "{p:?}");
        // The query itself is left as written.
        assert_eq!(fixed_queries(&spec)[0].1["filters"][1]["value"]["v"], "{{outputs.assess.cities}}");
    }

    /// A template in a filter value does not excuse what is static: ids, operators, the literal
    /// type, the structure, and templates outside filter values.
    #[test]
    fn a_template_does_not_excuse_static_mistakes() {
        let cities = json!({"type": "string_list", "v": "{{outputs.assess.cities}}"});
        let refused = |filters: Value, want: &str| {
            let (st, spec) = with_filters(filters);
            let p = publish_problems(&st, "acme", &spec);
            assert_eq!(p.len(), 1, "{want}: {p:?}");
            assert!(p[0].message.contains(want), "{want}: {}", p[0].message);
            assert_eq!(p[0].path.as_deref(), Some("/graph/vertices/0/config/args/query"));
        };
        refused(json!([{"attr": "Service.town", "op": "in", "value": cities}]), "unknown attribute 'Service.town'");
        refused(json!([{"attr": "{{input.attr}}", "op": "in", "value": cities}]), "unknown attribute '{{input.attr}}'");
        refused(
            json!([{"attr": "Service.city", "op": "contains", "value": cities}]),
            "not a CQIR query: unknown variant",
        );
        refused(json!([{"attr": "Service.city", "op": "{{input.op}}", "value": cities}]), "not a CQIR query");
        refused(json!([{"attr": "Service.city", "op": "in", "value": cities, "extra": 1}]), "not a CQIR query");
        refused(
            json!([{"attr": "Service.city", "op": "in", "value": {"type": "text_list", "v": "{{input.x}}"}}]),
            "not a CQIR query",
        );
        refused(json!([{"attr": "Service.city", "op": "gt", "value": cities}]), "operator Gt is not valid");
        refused(
            json!([{"attr": "Service.city", "op": "eq", "value": cities}]),
            "value for Service.city does not match",
        );
        refused(
            json!([{"attr": "Service.price", "op": "eq", "value": {"type": "string", "v": "{{input.p}}"}}]),
            "value for Service.price does not match",
        );
        // A number slot cannot take text around a placeholder (it renders to a string).
        refused(
            json!([{"attr": "Service.price", "op": "eq", "value": {"type": "number", "v": "{{input.p}}0"}}]),
            "not a CQIR query",
        );
        // Outside filter values, a template is checked as written.
        let (st, mut spec) = with_filters(json!([{"attr": "Service.city", "op": "in", "value": cities}]));
        let path = "/graph/vertices/0/config/args/query";
        spec.pointer_mut(path).unwrap()["dimensions"] = json!([{"id": "{{input.dimension}}"}]);
        let p = publish_problems(&st, "acme", &spec);
        assert!(p.len() == 1 && p[0].message.contains("unknown"), "{p:?}");
        spec.pointer_mut(path).unwrap()["dimensions"] = json!([]);
        spec.pointer_mut(path).unwrap()["limit"] = json!("{{input.limit}}");
        let p = publish_problems(&st, "acme", &spec);
        assert!(p.len() == 1 && p[0].message.contains("not a CQIR query"), "{p:?}");
        // And the version check still applies.
        spec.pointer_mut(path).unwrap()["limit"] = json!(10);
        spec.pointer_mut(path).unwrap()["ontology_version"] = json!("acme@4");
        assert_eq!(publish_problems(&st, "acme", &spec).len(), 1);
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

    /// e2e follow-up: re-posting an approved element unchanged was written back as `proposed`
    /// (or refused with 409 when a published node queries it).
    #[test]
    fn an_unchanged_proposal_is_skipped_and_keeps_the_review_decision() {
        let st = state(ontology(3, 1), node("acme@3", NodeState::Published));
        let current = |id: &str| st.ontologies["acme"].elements.iter().find(|e| e.id == id).unwrap().clone();
        // The whole model as exported, sent as proposed or with any other status: nothing to do.
        let mut again: Vec<Element> = st.ontologies["acme"].elements.clone();
        for (i, e) in again.iter_mut().enumerate() {
            e.status = [Status::Proposed, Status::Rejected, Status::Approved][i % 3];
            e.confidence = Some(0.1);
            e.changed_in = None;
        }
        let (write, skipped, b) = proposals(&st, "acme", again);
        assert_eq!((write.len(), skipped, b.len()), (0, 5, 0));
        // A changed spec goes back to proposed and is flagged when a published node queries it.
        let mut city = current("Service.city");
        city.spec = el(
            "Service.city",
            "attribute",
            json!({"entity": "Service", "path": "town", "column": "town", "data_type": "string"}),
            1,
        )
        .spec;
        let mut facility = current("Facility");
        facility.description = Some("A clinic".into());
        let (write, skipped, b) = proposals(
            &st,
            "acme",
            vec![city, facility, el("New", "glossary_term", json!({"phrase": "new", "maps_to": "x"}), 0)],
        );
        assert_eq!(skipped, 0);
        assert!(write.iter().all(|e| e.status == Status::Proposed && e.changed_in.is_none()));
        assert_eq!(write.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), ["Service.city", "Facility", "New"]);
        assert_eq!(b.len(), 1, "only Service.city is queried by a published node: {b:?}");
        assert_eq!((b[0].element.as_str(), b[0].change.as_str()), ("Service.city", "approved -> proposed"));
    }

    /// A refused withdrawal: `409`, a stable code and the breaking list, structured.
    #[tokio::test]
    async fn a_refused_withdrawal_names_the_elements_and_versions_in_the_body() {
        use axum::response::IntoResponse;
        let st = state(ontology(3, 1), node("acme@3", NodeState::Published));
        let b = breaking(&st, "acme", &[("Service".into(), Status::Rejected)]);
        let resp = refuse("these decisions withdraw approved elements", b).into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::CONFLICT);
        let body: Value =
            serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap()).unwrap();
        let e = &body["error"];
        assert_eq!((e["type"].as_str(), e["code"].as_str()), (Some("conflict"), Some(BREAKING_CODE)));
        assert_eq!(
            e["breaking"],
            json!([{"element": "Service", "change": "approved -> rejected", "nodes": ["triage@v3"],
                    "versions": [{"node": "triage", "version": 3}]}])
        );
        assert!(e["message"].as_str().unwrap().contains("Service (approved -> rejected): triage@v3"), "{e}");
    }
}
