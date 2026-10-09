//! Native lane: CQIR → MongoDB aggregation pipeline, plus a defensive lint.
//!
//! Field paths come only from ontology bindings and literals are typed scalars, so there is no
//! path for operator injection. The pipeline runs on a tagged read-only secondary with
//! `maxTimeMS`, `allowDiskUse: false`, and an audit comment; a `queryPlanner` explain gates it.

use super::{CompileError, Plan, Role};
use crate::cqir::{Dir, ElementMatch, Filter, Op, Value};
use crate::model::{Aggregation, EntityBinding, MetricExpr, Model};
use serde_json::{Map, Value as J, json};

#[derive(Debug, Clone, PartialEq)]
pub struct MongoQuery {
    pub datasource: String,
    pub collection: String,
    pub pipeline: Vec<J>,
    /// Driver options: maxTimeMS, allowDiskUse, comment, readPreference.
    pub options: J,
}

pub struct NativeOptions<'a> {
    pub max_time_ms: u64,
    pub audit_id: &'a str,
    /// Replica-set tag for the analytics secondary.
    pub read_tag: Option<(&'a str, &'a str)>,
}

impl Default for NativeOptions<'_> {
    fn default() -> Self {
        Self { max_time_ms: 15_000, audit_id: "unset", read_tag: Some(("workload", "analytics")) }
    }
}

fn alias(entity: &str) -> String {
    format!("__{}", entity.to_ascii_lowercase())
}

/// Full document path of an attribute in the pipeline at the point where it is used.
fn path(model: &Model, plan: &Plan, attr: &str) -> String {
    let def = &model.attributes[attr];
    match plan.entities.iter().find(|(e, _)| e == &def.entity).map(|(_, r)| r) {
        Some(Role::Child { array_path }) => format!("{array_path}.{}", def.path),
        Some(Role::Reference { .. }) => format!("{}.{}", alias(&def.entity), def.path),
        _ => def.path.clone(),
    }
}

fn lit(v: &Value) -> J {
    match v {
        Value::String(s) => J::String(s.clone()),
        Value::Number(n) => json!(n),
        Value::Bool(b) => J::Bool(*b),
        Value::Timestamp(t) => json!({ "$date": t }),
        Value::StringList(l) => json!(l),
        Value::NumberList(l) => json!(l),
        Value::TimestampRange(r) => json!(r.iter().map(|t| json!({ "$date": t })).collect::<Vec<_>>()),
        Value::NumberRange(r) => json!(r),
    }
}

/// Operator object for one filter, e.g. `{"$gte": …, "$lt": …}`.
fn cond(f: &Filter) -> J {
    let v = f.value.as_ref().map(lit).unwrap_or(J::Null);
    match f.op {
        Op::Eq => json!({ "$eq": v }),
        Op::Ne => json!({ "$ne": v }),
        Op::In => json!({ "$in": v }),
        Op::Gt => json!({ "$gt": v }),
        Op::Gte => json!({ "$gte": v }),
        Op::Lt => json!({ "$lt": v }),
        Op::Lte => json!({ "$lte": v }),
        Op::Between => {
            let hi = if f.half_open { "$lt" } else { "$lte" };
            json!({ "$gte": v[0].clone(), hi: v[1].clone() })
        }
        Op::IsNull => json!({ "$type": "null" }),
        Op::IsMissing => json!({ "$exists": false }),
        Op::IsEmpty => json!({ "$size": 0 }),
    }
}

/// Merges conditions into one `$match` document; repeated operators on a path go into `$and`.
fn match_doc(conds: &[(String, J)]) -> J {
    let mut doc = Map::new();
    let mut and: Vec<J> = Vec::new();
    for (p, c) in conds {
        match doc.get_mut(p).and_then(J::as_object_mut) {
            Some(existing) if c.as_object().is_some_and(|o| o.keys().all(|k| !existing.contains_key(k))) => {
                for (k, v) in c.as_object().into_iter().flatten() {
                    existing.insert(k.clone(), v.clone());
                }
            }
            Some(_) => and.push(json!({ p.clone(): c })),
            None => {
                doc.insert(p.clone(), c.clone());
            }
        }
    }
    if !and.is_empty() {
        doc.insert("$and".into(), J::Array(and));
    }
    J::Object(doc)
}

fn expr(model: &Model, plan: &Plan, e: &MetricExpr) -> J {
    match e {
        MetricExpr::Attr { id } => J::String(format!("${}", path(model, plan, id))),
        MetricExpr::Mul { left, right } => json!({ "$multiply": [expr(model, plan, left), expr(model, plan, right)] }),
        MetricExpr::Add { left, right } => json!({ "$add": [expr(model, plan, left), expr(model, plan, right)] }),
        MetricExpr::Sub { left, right } => json!({ "$subtract": [expr(model, plan, left), expr(model, plan, right)] }),
        MetricExpr::Rows => json!(1),
    }
}

pub(crate) fn out_name(id: &str) -> &str {
    id.rsplit('.').next().unwrap_or(id)
}

pub fn lower(model: &Model, plan: &Plan, opts: &NativeOptions<'_>) -> Result<MongoQuery, CompileError> {
    let (datasource, collection) = match &model.entities[&plan.root].binding {
        EntityBinding::Root { datasource, collection, .. } => (datasource.clone(), collection.clone()),
        EntityBinding::Embedded { .. } => return Err(CompileError::Unknown("root entity", plan.root.clone())),
    };
    let grain_is_child = plan.grain != plan.root;
    let role_of = |attr: &str| {
        let ent = &model.attributes[attr].entity;
        plan.entities.iter().find(|(e, _)| e == ent).map(|(e, r)| (e.clone(), r.clone()))
    };

    let mut pipeline = Vec::new();

    // 1. Root-level filters first so they can use indexes. Child filters at root grain use
    //    $elemMatch (same element) or dotted paths (any element).
    let mut root_conds: Vec<(String, J)> = Vec::new();
    let mut same_element: Map<String, J> = Map::new();
    let mut child_array = String::new();
    for f in &plan.filters {
        match role_of(&f.attr) {
            Some((_, Role::Root)) => root_conds.push((model.attributes[&f.attr].path.clone(), cond(f))),
            Some((_, Role::Child { array_path })) if !grain_is_child => {
                let rel = model.attributes[&f.attr].path.clone();
                if f.element == ElementMatch::Any {
                    root_conds.push((format!("{array_path}.{rel}"), cond(f)));
                } else {
                    child_array = array_path;
                    same_element.insert(rel, cond(f));
                }
            }
            _ => {}
        }
    }
    if !same_element.is_empty() {
        root_conds.push((child_array, json!({ "$elemMatch": same_element })));
    }
    // Subtype entities sharing a collection are selected by their discriminator.
    if let EntityBinding::Root { discriminator: Some(d), .. } = &model.entities[&plan.root].binding {
        root_conds.push((d.path.clone(), json!({ "$eq": d.value })));
    }
    if !root_conds.is_empty() {
        pipeline.push(json!({ "$match": match_doc(&root_conds) }));
    }

    // 2. Verified N:1 references: $lookup projecting only the fields needed, inner unwind, filter.
    for (entity, role) in &plan.entities {
        let Role::Reference { via } = role else { continue };
        if !via.foreign_indexed {
            return Err(CompileError::NoPath {
                from: plan.root.clone(),
                to: format!("{entity} (unindexed $lookup; use the replica lane)"),
            });
        }
        let EntityBinding::Root { collection: from, discriminator, .. } = &model.entities[entity].binding else {
            continue;
        };
        let a = alias(entity);
        let mut project = Map::new();
        project.insert(via.foreign_path.clone(), json!(1));
        let mut conds = Vec::new();
        if let Some(d) = discriminator {
            project.insert(d.path.clone(), json!(1));
            conds.push((format!("{a}.{}", d.path), json!({ "$eq": d.value })));
        }
        let mut needed: Vec<&str> = plan.query.dimensions.iter().map(|d| d.id.as_str()).collect();
        needed.extend(plan.filters.iter().map(|f| f.attr.as_str()));
        for attr in needed {
            let def = &model.attributes[attr];
            if &def.entity == entity {
                project.insert(def.path.clone(), json!(1));
            }
        }
        for f in plan.filters.iter().filter(|f| &model.attributes[&f.attr].entity == entity) {
            conds.push((format!("{a}.{}", model.attributes[&f.attr].path), cond(f)));
        }
        pipeline.push(json!({ "$lookup": {
            "from": from, "localField": via.local_path, "foreignField": via.foreign_path, "as": a,
            "pipeline": [ { "$project": project } ]
        }}));
        pipeline.push(json!({ "$unwind": format!("${a}") }));
        if !conds.is_empty() {
            pipeline.push(json!({ "$match": match_doc(&conds) }));
        }
    }

    // 3. Unwind the embedded array only when the metric grain is the child entity.
    if grain_is_child {
        let EntityBinding::Embedded { array_path, .. } = &model.entities[&plan.grain].binding else {
            return Err(CompileError::Unknown("embedded grain", plan.grain.clone()));
        };
        pipeline.push(json!({ "$unwind": format!("${array_path}") }));
        let conds: Vec<(String, J)> = plan
            .filters
            .iter()
            .filter(|f| model.attributes[&f.attr].entity == plan.grain)
            .map(|f| (path(model, plan, &f.attr), cond(f)))
            .collect();
        if !conds.is_empty() {
            pipeline.push(json!({ "$match": match_doc(&conds) }));
        }
    }

    // 4. Group by dimensions, compute metrics.
    let dims: Vec<(String, String)> = plan
        .query
        .dimensions
        .iter()
        .map(|d| (out_name(&d.id).to_owned(), format!("${}", path(model, plan, &d.id))))
        .collect();
    let group_id = match dims.as_slice() {
        [] => J::Null,
        [(_, p)] => J::String(p.clone()),
        many => J::Object(many.iter().map(|(n, p)| (n.clone(), J::String(p.clone()))).collect()),
    };
    let mut group = Map::new();
    group.insert("_id".into(), group_id);
    let mut project = Map::new();
    project.insert("_id".into(), json!(0));
    match dims.as_slice() {
        [] => {}
        [(n, _)] => {
            project.insert(n.clone(), json!("$_id"));
        }
        many => {
            for (n, _) in many {
                project.insert(n.clone(), J::String(format!("$_id.{n}")));
            }
        }
    }
    for m in &plan.query.metrics {
        let def = &model.metrics[&m.id];
        let name = out_name(&m.id).to_owned();
        let e = expr(model, plan, &def.expr);
        let acc = match def.aggregation {
            Aggregation::Sum => json!({ "$sum": e }),
            Aggregation::Avg => json!({ "$avg": e }),
            Aggregation::Min => json!({ "$min": e }),
            Aggregation::Max => json!({ "$max": e }),
            Aggregation::Count => json!({ "$sum": 1 }),
            Aggregation::CountDistinct => json!({ "$addToSet": e }),
        };
        group.insert(name.clone(), acc);
        let proj = if def.aggregation == Aggregation::CountDistinct {
            json!({ "$size": format!("${name}") })
        } else {
            json!(1)
        };
        project.insert(name, proj);
    }
    pipeline.push(json!({ "$group": group }));
    pipeline.push(json!({ "$project": project }));

    // 5. Order and limit on output names.
    if !plan.query.order_by.is_empty() {
        let mut sort = Map::new();
        for o in &plan.query.order_by {
            let key = o.metric.as_deref().or(o.dimension.as_deref()).map(out_name).unwrap_or("_id");
            sort.insert(key.to_owned(), json!(if o.dir == Dir::Desc { -1 } else { 1 }));
        }
        pipeline.push(json!({ "$sort": sort }));
    }
    if let Some(n) = plan.query.limit {
        pipeline.push(json!({ "$limit": n }));
    }

    let mut options = json!({
        "maxTimeMS": opts.max_time_ms,
        "allowDiskUse": false,
        "comment": format!("caliban:{}", opts.audit_id),
    });
    options["readPreference"] = match opts.read_tag {
        Some((k, v)) => json!({ "mode": "secondary", "tags": [{ k: v }] }),
        None => json!({ "mode": "secondaryPreferred" }),
    };
    let q = MongoQuery { datasource, collection, pipeline, options };
    lint(&q.pipeline).map_err(|e| CompileError::Unknown("lint", e.to_string()))?;
    Ok(q)
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum LintError {
    #[error("stage {0} is not allowed")]
    Stage(String),
    #[error("operator {0} is not allowed anywhere in a pipeline")]
    Operator(String),
    #[error("pipeline too long ({0} stages)")]
    TooLong(usize),
}

const ALLOWED_STAGES: &[&str] = &[
    "$match",
    "$project",
    "$set",
    "$addFields",
    "$unwind",
    "$group",
    "$sort",
    "$limit",
    "$skip",
    "$count",
    "$bucket",
    "$lookup",
    "$facet",
    "$setWindowFields",
];
const DENIED_ANYWHERE: &[&str] = &[
    "$where",
    "$function",
    "$accumulator",
    "$out",
    "$merge",
    "$unionWith",
    "$currentOp",
    "$listSessions",
    "$collStats",
    "$documents",
    "$graphLookup",
];

/// Defensive lint for any pipeline Caliban runs (compiled or from a verified query).
pub fn lint(pipeline: &[J]) -> Result<(), LintError> {
    if pipeline.len() > 50 {
        return Err(LintError::TooLong(pipeline.len()));
    }
    for stage in pipeline {
        let Some(obj) = stage.as_object() else { return Err(LintError::Stage("<non-object>".into())) };
        for k in obj.keys() {
            if !ALLOWED_STAGES.contains(&k.as_str()) {
                return Err(LintError::Stage(k.clone()));
            }
        }
        walk(stage)?;
    }
    Ok(())
}

fn walk(v: &J) -> Result<(), LintError> {
    match v {
        J::Object(o) => {
            for (k, child) in o {
                if DENIED_ANYWHERE.contains(&k.as_str()) {
                    return Err(LintError::Operator(k.clone()));
                }
                walk(child)?;
            }
        }
        J::Array(a) => {
            for child in a {
                walk(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::fixtures::*;
    use crate::compile::plan;

    #[test]
    fn compiles_the_reference_example() {
        let m = model();
        let p = plan(&m, &query(), &eu_policy()).unwrap();
        let q = lower(&m, &p, &NativeOptions { audit_id: "q_8f3a", ..Default::default() }).unwrap();
        assert_eq!(q.collection, "orders");
        let expected = json!([
            { "$match": {
                "status": { "$in": ["paid", "shipped"] },
                "salesOrg": { "$in": ["EU-1", "EU-2"] },
                "createdAt": { "$gte": { "$date": "2026-07-01T00:00:00Z" }, "$lt": { "$date": "2026-10-01T00:00:00Z" } } } },
            { "$lookup": { "from": "customers", "localField": "customerId", "foreignField": "_id", "as": "__customer",
                           "pipeline": [ { "$project": { "_id": 1, "region": 1 } } ] } },
            { "$unwind": "$__customer" },
            { "$match": { "__customer.region": { "$eq": "EU" } } },
            { "$unwind": "$lines" },
            { "$group": { "_id": "$lines.category",
                          "gross_revenue": { "$sum": { "$multiply": ["$lines.qty", "$lines.unitPrice"] } } } },
            { "$project": { "_id": 0, "category": "$_id", "gross_revenue": 1 } },
            { "$sort": { "gross_revenue": -1 } },
            { "$limit": 5 }
        ]);
        assert_eq!(J::Array(q.pipeline.clone()), expected, "{}", serde_json::to_string_pretty(&q.pipeline).unwrap());
        assert_eq!(q.options["allowDiskUse"], false);
        assert_eq!(q.options["comment"], "caliban:q_8f3a");
    }

    #[test]
    fn child_filter_at_root_grain_uses_elem_match() {
        let m = model();
        let mut q = query();
        q.metrics = vec![crate::cqir::IdRef { id: "metric.order_count".into() }];
        q.dimensions.clear();
        q.order_by.clear();
        q.filters = serde_json::from_str(
            r#"[{"attr":"OrderLine.sku","op":"eq","value":{"type":"string","v":"A"}},
                {"attr":"OrderLine.qty","op":"gt","value":{"type":"number","v":5}}]"#,
        )
        .unwrap();
        let p = plan(&m, &q, &[]).unwrap();
        let out = lower(&m, &p, &NativeOptions::default()).unwrap();
        assert_eq!(
            out.pipeline[0],
            json!({ "$match": { "lines": { "$elemMatch": { "sku": { "$eq": "A" }, "qty": { "$gt": 5.0 } } } } })
        );
        assert!(!out.pipeline.iter().any(|s| s.get("$unwind").is_some()), "no unwind at root grain");
    }

    #[test]
    fn subtype_root_and_joined_subtype_get_discriminator_filters() {
        use crate::model::{Discriminator, EntityBinding};
        let mut m = model();
        for (ent, path, value) in [("Order", "type", "sale"), ("Customer", "kind", "business")] {
            if let EntityBinding::Root { discriminator, .. } = &mut m.entities.get_mut(ent).unwrap().binding {
                *discriminator = Some(Discriminator { path: path.into(), column: path.into(), value: value.into() });
            }
        }
        let p = plan(&m, &query(), &[]).unwrap();
        let q = lower(&m, &p, &NativeOptions::default()).unwrap();
        assert_eq!(q.pipeline[0]["$match"]["type"], json!({ "$eq": "sale" }));
        assert_eq!(q.pipeline[1]["$lookup"]["pipeline"][0]["$project"]["kind"], json!(1));
        assert_eq!(q.pipeline[3]["$match"]["__customer.kind"], json!({ "$eq": "business" }));
        let sql = crate::compile::sql::lower(&m, &p).unwrap();
        assert!(sql.contains(r#"t0."type" = 'sale'"#) && sql.contains(r#"t2."kind" = 'business'"#), "{sql}");
    }

    #[test]
    fn lint_blocks_server_side_js_and_writes() {
        assert_eq!(lint(&[json!({"$match": {"$where": "sleep(10000)"}})]), Err(LintError::Operator("$where".into())));
        assert_eq!(lint(&[json!({"$out": "stolen"})]), Err(LintError::Stage("$out".into())));
        assert_eq!(
            lint(&[json!({"$group": {"_id": null, "x": {"$accumulator": {}}}})]),
            Err(LintError::Operator("$accumulator".into()))
        );
    }
}
