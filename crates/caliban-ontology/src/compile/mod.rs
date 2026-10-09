//! Deterministic CQIR compiler: validate → inject policy → plan the query shape → lower.

pub mod mongo;
pub mod planner;
pub mod sql;

use crate::cqir::{Filter, Op, Query, Value};
use crate::model::{DataType, EntityBinding, Model, RelationDef};
use std::collections::BTreeSet;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CompileError {
    #[error("unknown {0} '{1}'")]
    Unknown(&'static str, String),
    #[error("query was built for ontology {got}, current is {want}")]
    VersionMismatch { got: String, want: String },
    #[error("operator {op:?} is not valid for {attr} ({ty:?})")]
    OpType { op: Op, attr: String, ty: DataType },
    #[error("value for {0} does not match the operator/type")]
    BadValue(String),
    #[error("metrics must share one grain root; got {0:?}")]
    MixedGrain(Vec<String>),
    #[error("no approved path from {from} to {to}; only embedded children and verified N:1 references can be joined")]
    NoPath { from: String, to: String },
    #[error("fan-out: dimension {dim} is finer than metric grain {grain}; pre-aggregate or change the question")]
    FanOut { dim: String, grain: String },
    #[error("nothing to compute: add a metric")]
    Empty,
    #[error("attribute {0} is denied by policy")]
    Denied(String),
}

/// How each entity participates in a compiled query.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Role {
    Root,
    /// Embedded array of the root, at `array_path`.
    Child {
        array_path: String,
    },
    /// Joined through a verified N:1 reference from the root (or from a child).
    Reference {
        via: RelationDef,
    },
}

/// Validated, policy-injected query with every id resolved.
#[derive(Debug, Clone)]
pub struct Plan {
    pub(crate) root: String,
    pub(crate) grain: String,
    pub(crate) entities: Vec<(String, Role)>,
    pub(crate) query: Query,
    /// Metric-definition filters + policy filters + user filters.
    pub(crate) filters: Vec<Filter>,
}

/// Validates the query against the model and injects metric and policy filters.
/// `policy_filters` are row predicates already resolved for the calling principal.
pub fn plan(model: &Model, q: &Query, policy_filters: &[Filter]) -> Result<Plan, CompileError> {
    if q.ontology_version != model.version {
        return Err(CompileError::VersionMismatch { got: q.ontology_version.clone(), want: model.version.clone() });
    }
    if q.metrics.is_empty() {
        return Err(CompileError::Empty);
    }
    let denied: BTreeSet<&str> =
        model.policies.iter().flat_map(|p| p.denied_attributes.iter().map(String::as_str)).collect();

    let mut grains = BTreeSet::new();
    let mut filters: Vec<Filter> = Vec::new();
    for m in &q.metrics {
        let def = model.metrics.get(&m.id).ok_or_else(|| CompileError::Unknown("metric", m.id.clone()))?;
        grains.insert(def.grain.clone());
        filters.extend(def.filters.iter().cloned());
    }
    if grains.len() != 1 {
        return Err(CompileError::MixedGrain(grains.into_iter().collect()));
    }
    let grain = grains.into_iter().next().unwrap_or_default();
    let root = model.root_of(&grain).ok_or_else(|| CompileError::Unknown("entity", grain.clone()))?.to_owned();

    filters.extend(policy_filters.iter().cloned());
    filters.extend(q.filters.iter().cloned());

    let mut attrs: Vec<&str> = q.dimensions.iter().map(|d| d.id.as_str()).collect();
    attrs.extend(filters.iter().map(|f| f.attr.as_str()));
    for m in &q.metrics {
        collect_metric_attrs(&model.metrics[&m.id].expr, &mut attrs);
    }

    let mut entities: Vec<(String, Role)> = vec![(root.clone(), Role::Root)];
    for a in &attrs {
        if denied.contains(a) {
            return Err(CompileError::Denied((*a).to_owned()));
        }
        let def = model.attributes.get(*a).ok_or_else(|| CompileError::Unknown("attribute", (*a).to_owned()))?;
        if !entities.iter().any(|(e, _)| e == &def.entity) {
            let role = role_for(model, &root, &def.entity)?;
            entities.push((def.entity.clone(), role));
        }
    }

    for f in &filters {
        check_filter(model, f)?;
    }
    // Fan-out: a dimension on an embedded child while the grain is the root would multiply rows.
    for d in &q.dimensions {
        let ent = &model.attributes[&d.id].entity;
        let is_child = matches!(entities.iter().find(|(e, _)| e == ent), Some((_, Role::Child { .. })));
        if is_child && *ent != grain {
            return Err(CompileError::FanOut { dim: d.id.clone(), grain: grain.clone() });
        }
    }
    Ok(Plan { root, grain, entities, query: q.clone(), filters })
}

fn role_for(model: &Model, root: &str, entity: &str) -> Result<Role, CompileError> {
    let def = model.entities.get(entity).ok_or_else(|| CompileError::Unknown("entity", entity.to_owned()))?;
    if let EntityBinding::Embedded { parent, array_path, .. } = &def.binding
        && parent == root
    {
        return Ok(Role::Child { array_path: array_path.clone() });
    }
    if let Some(r) = model.reference(root, entity) {
        return Ok(Role::Reference { via: r.clone() });
    }
    Err(CompileError::NoPath { from: root.to_owned(), to: entity.to_owned() })
}

fn collect_metric_attrs<'a>(e: &'a crate::model::MetricExpr, out: &mut Vec<&'a str>) {
    use crate::model::MetricExpr::{Add, Attr, Mul, Rows, Sub};
    match e {
        Attr { id } => out.push(id),
        Mul { left, right } | Add { left, right } | Sub { left, right } => {
            collect_metric_attrs(left, out);
            collect_metric_attrs(right, out);
        }
        Rows => {}
    }
}

fn check_filter(model: &Model, f: &Filter) -> Result<(), CompileError> {
    let def = model.attributes.get(&f.attr).ok_or_else(|| CompileError::Unknown("attribute", f.attr.clone()))?;
    let ty = def.data_type;
    let op_ok = match f.op {
        Op::Gt | Op::Gte | Op::Lt | Op::Lte | Op::Between => matches!(ty, DataType::Number | DataType::Timestamp),
        _ => true,
    };
    if !op_ok {
        return Err(CompileError::OpType { op: f.op, attr: f.attr.clone(), ty });
    }
    #[allow(clippy::match_like_matches_macro)]
    let value_ok = match (f.op, &f.value, ty) {
        (Op::IsNull | Op::IsMissing | Op::IsEmpty, None, _) => true,
        (Op::Eq | Op::Ne, Some(Value::String(_)), DataType::String)
        | (Op::Eq | Op::Ne | Op::Gt | Op::Gte | Op::Lt | Op::Lte, Some(Value::Number(_)), DataType::Number)
        | (Op::Eq | Op::Ne | Op::Gt | Op::Gte | Op::Lt | Op::Lte, Some(Value::Timestamp(_)), DataType::Timestamp)
        | (Op::Eq | Op::Ne, Some(Value::Bool(_)), DataType::Bool)
        | (Op::In, Some(Value::StringList(_)), DataType::String)
        | (Op::In, Some(Value::NumberList(_)), DataType::Number)
        | (Op::Between, Some(Value::TimestampRange(_)), DataType::Timestamp)
        | (Op::Between, Some(Value::NumberRange(_)), DataType::Number) => true,
        _ => false,
    };
    if !value_ok {
        return Err(CompileError::BadValue(f.attr.clone()));
    }
    if let Some(Value::Timestamp(t)) = &f.value {
        check_ts(&f.attr, t)?;
    }
    if let Some(Value::TimestampRange([a, b])) = &f.value {
        check_ts(&f.attr, a)?;
        check_ts(&f.attr, b)?;
    }
    Ok(())
}

/// Requires `YYYY-MM-DDTHH:MM:SS[.fff]Z` (UTC). Full parsing happens in the executor.
fn check_ts(attr: &str, t: &str) -> Result<(), CompileError> {
    let b = t.as_bytes();
    let shape = b.len() >= 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && t.ends_with('Z')
        && t.chars().all(|c| c.is_ascii_digit() || "-:T.Z".contains(c));
    if shape { Ok(()) } else { Err(CompileError::BadValue(attr.to_owned())) }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! The worked example from docs/research/08-ontology-deep-dive-nosql.md.

    use crate::cqir::{ElementMatch, Filter, Op, Query, Value};
    use crate::model::*;
    use std::collections::HashMap;

    fn attr(entity: &str, path: &str, column: &str, ty: DataType) -> AttributeDef {
        AttributeDef {
            entity: entity.into(),
            path: path.into(),
            column: column.into(),
            data_type: ty,
            pii_class: None,
            unit: None,
        }
    }

    pub fn model() -> Model {
        let mut entities = HashMap::new();
        entities.insert(
            "Order".into(),
            EntityDef {
                binding: EntityBinding::Root {
                    datasource: "dw".into(),
                    collection: "orders".into(),
                    table: None,
                    discriminator: None,
                },
                keys: vec!["_id".into()],
            },
        );
        entities.insert(
            "OrderLine".into(),
            EntityDef {
                binding: EntityBinding::Embedded { parent: "Order".into(), array_path: "lines".into(), table: None },
                keys: vec![],
            },
        );
        entities.insert(
            "Customer".into(),
            EntityDef {
                binding: EntityBinding::Root {
                    datasource: "dw".into(),
                    collection: "customers".into(),
                    table: None,
                    discriminator: None,
                },
                keys: vec!["_id".into()],
            },
        );
        let mut attributes = HashMap::new();
        for (id, a) in [
            ("Order.status", attr("Order", "status", "status", DataType::String)),
            ("Order.created_at", attr("Order", "createdAt", "created_at", DataType::Timestamp)),
            ("Order.sales_org", attr("Order", "salesOrg", "sales_org", DataType::String)),
            ("OrderLine.category", attr("OrderLine", "category", "category", DataType::String)),
            ("OrderLine.sku", attr("OrderLine", "sku", "sku", DataType::String)),
            ("OrderLine.qty", attr("OrderLine", "qty", "qty", DataType::Number)),
            ("OrderLine.unit_price", attr("OrderLine", "unitPrice", "unit_price", DataType::Number)),
            ("Customer.region", attr("Customer", "region", "region", DataType::String)),
        ] {
            attributes.insert(id.to_string(), a);
        }
        let relations = vec![RelationDef {
            from: "Order".into(),
            to: "Customer".into(),
            cardinality: Cardinality::ManyToOne,
            local_path: "customerId".into(),
            local_column: "customer_id".into(),
            foreign_path: "_id".into(),
            foreign_column: "_id".into(),
            verified: true,
            foreign_indexed: true,
        }];
        let mut metrics = HashMap::new();
        metrics.insert(
            "metric.gross_revenue".into(),
            MetricDef {
                grain: "OrderLine".into(),
                aggregation: Aggregation::Sum,
                expr: MetricExpr::Mul {
                    left: Box::new(MetricExpr::Attr { id: "OrderLine.qty".into() }),
                    right: Box::new(MetricExpr::Attr { id: "OrderLine.unit_price".into() }),
                },
                filters: vec![Filter {
                    attr: "Order.status".into(),
                    op: Op::In,
                    value: Some(Value::StringList(vec!["paid".into(), "shipped".into()])),
                    half_open: true,
                    element: ElementMatch::Same,
                }],
            },
        );
        metrics.insert(
            "metric.order_count".into(),
            MetricDef {
                grain: "Order".into(),
                aggregation: Aggregation::Count,
                expr: MetricExpr::Rows,
                filters: vec![],
            },
        );
        Model { version: "acme@42".into(), entities, attributes, relations, metrics, policies: vec![] }
    }

    pub fn query() -> Query {
        serde_json::from_str(
            r#"{
              "ir_version": "1",
              "ontology_version": "acme@42",
              "metrics":    [{ "id": "metric.gross_revenue" }],
              "dimensions": [{ "id": "OrderLine.category" }],
              "filters": [
                { "attr": "Customer.region",  "op": "eq", "value": { "type": "string", "v": "EU" } },
                { "attr": "Order.created_at", "op": "between", "half_open": true,
                  "value": { "type": "timestamp_range", "v": ["2026-07-01T00:00:00Z", "2026-10-01T00:00:00Z"] } }
              ],
              "order_by": [{ "metric": "metric.gross_revenue", "dir": "desc" }],
              "limit": 5,
              "freshness": "PT15M"
            }"#,
        )
        .unwrap()
    }

    pub fn eu_policy() -> Vec<Filter> {
        vec![Filter {
            attr: "Order.sales_org".into(),
            op: Op::In,
            value: Some(Value::StringList(vec!["EU-1".into(), "EU-2".into()])),
            half_open: true,
            element: ElementMatch::Same,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::cqir::IdRef;

    #[test]
    fn rejects_stale_ontology_version() {
        let mut q = query();
        q.ontology_version = "acme@41".into();
        assert!(matches!(plan(&model(), &q, &[]), Err(CompileError::VersionMismatch { .. })));
    }

    #[test]
    fn rejects_type_mismatch() {
        let mut q = query();
        q.filters[0].op = Op::Gt;
        assert!(matches!(plan(&model(), &q, &[]), Err(CompileError::OpType { .. })));
    }

    #[test]
    fn rejects_fan_out() {
        let mut q = query();
        q.metrics = vec![IdRef { id: "metric.order_count".into() }];
        assert!(matches!(plan(&model(), &q, &[]), Err(CompileError::FanOut { .. })));
    }

    #[test]
    fn unknown_ids_are_rejected_not_guessed() {
        let mut q = query();
        q.dimensions[0].id = "OrderLine.colour".into();
        assert_eq!(plan(&model(), &q, &[]).unwrap_err(), CompileError::Unknown("attribute", "OrderLine.colour".into()));
    }

    #[test]
    fn denied_attribute_is_blocked() {
        let mut m = model();
        m.policies.push(crate::model::PolicyDef {
            entity: "Customer".into(),
            row_filter: None,
            denied_attributes: vec!["Customer.region".into()],
        });
        assert_eq!(plan(&m, &query(), &[]).unwrap_err(), CompileError::Denied("Customer.region".into()));
    }
}
