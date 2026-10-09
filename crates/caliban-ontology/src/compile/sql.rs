//! Accelerated lane: CQIR → SQL over the CDC replica's relational projection (DataFusion).
//!
//! Replica layout: each root collection is a table; each embedded array is a child table keyed by
//! `(_parent_id, _idx)`. Identifiers are always quoted; literals are typed and escaped.

use super::mongo::out_name;
use super::{CompileError, Plan, Role};
use crate::cqir::{Dir, ElementMatch, Filter, Op, Value};
use crate::model::{Aggregation, EntityBinding, MetricExpr, Model};

fn ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn string_lit(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn num(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 { format!("{n:.0}") } else { format!("{n}") }
}

fn ts(t: &str) -> String {
    format!("TIMESTAMP {}", string_lit(t))
}

fn lit(v: &Value) -> String {
    match v {
        Value::String(s) => string_lit(s),
        Value::Number(n) => num(*n),
        Value::Bool(b) => b.to_string().to_uppercase(),
        Value::Timestamp(t) => ts(t),
        Value::StringList(l) => l.iter().map(|s| string_lit(s)).collect::<Vec<_>>().join(", "),
        Value::NumberList(l) => l.iter().map(|n| num(*n)).collect::<Vec<_>>().join(", "),
        Value::TimestampRange(_) | Value::NumberRange(_) => String::new(),
    }
}

fn predicate(col: &str, f: &Filter) -> String {
    let v = f.value.as_ref();
    let l = || v.map(lit).unwrap_or_default();
    match f.op {
        Op::Eq => format!("{col} = {}", l()),
        Op::Ne => format!("{col} <> {}", l()),
        Op::In => format!("{col} IN ({})", l()),
        Op::Gt => format!("{col} > {}", l()),
        Op::Gte => format!("{col} >= {}", l()),
        Op::Lt => format!("{col} < {}", l()),
        Op::Lte => format!("{col} <= {}", l()),
        Op::Between => {
            let (lo, hi) = match v {
                Some(Value::TimestampRange([a, b])) => (ts(a), ts(b)),
                Some(Value::NumberRange([a, b])) => (num(*a), num(*b)),
                _ => (String::new(), String::new()),
            };
            let hi_op = if f.half_open { "<" } else { "<=" };
            format!("{col} >= {lo} AND {col} {hi_op} {hi}")
        }
        // The replica cannot distinguish missing from null; both read as NULL.
        Op::IsNull | Op::IsMissing => format!("{col} IS NULL"),
        Op::IsEmpty => format!("{col} IS NULL"),
    }
}

pub fn lower(model: &Model, plan: &Plan) -> Result<String, CompileError> {
    let grain_is_child = plan.grain != plan.root;
    let root_table = model.table_of(&plan.root).ok_or_else(|| CompileError::Unknown("entity", plan.root.clone()))?;

    // Aliases: root t0, then t1.. for joined entities. Children are joined only at child grain.
    let mut aliases: Vec<(String, String)> = vec![(plan.root.clone(), "t0".into())];
    let mut from = format!("FROM {} t0", ident(&root_table));
    for (entity, role) in plan.entities.iter().skip(1) {
        let a = format!("t{}", aliases.len());
        match role {
            Role::Child { .. } if grain_is_child && *entity == plan.grain => {
                let table = model.table_of(entity).unwrap_or_default();
                from.push_str(&format!("\nJOIN {} {a} ON {a}.\"_parent_id\" = t0.\"_id\"", ident(&table)));
                aliases.push((entity.clone(), a));
            }
            Role::Reference { via } => {
                let table = model.table_of(entity).unwrap_or_default();
                from.push_str(&format!(
                    "\nJOIN {} {a} ON {a}.{} = t0.{}",
                    ident(&table),
                    ident(&via.foreign_column),
                    ident(&via.local_column)
                ));
                aliases.push((entity.clone(), a));
            }
            _ => {}
        }
    }
    let col = |attr: &str| -> Option<String> {
        let def = &model.attributes[attr];
        aliases.iter().find(|(e, _)| e == &def.entity).map(|(_, a)| format!("{a}.{}", ident(&def.column)))
    };

    let mut where_: Vec<String> = Vec::new();
    // Subtype entities sharing a table are selected by their discriminator column.
    for (entity, a) in &aliases {
        if let Some(EntityBinding::Root { discriminator: Some(d), .. }) = model.entities.get(entity).map(|e| &e.binding)
        {
            where_.push(format!("{a}.{} = {}", ident(&d.column), string_lit(&d.value)));
        }
    }
    let mut same_element: Vec<String> = Vec::new();
    let mut child_table = String::new();
    for f in &plan.filters {
        match col(&f.attr) {
            Some(c) => where_.push(predicate(&c, f)),
            None => {
                // Child filter at root grain → EXISTS over the child table.
                let def = &model.attributes[&f.attr];
                child_table = model.table_of(&def.entity).unwrap_or_default();
                let p = predicate(&format!("c.{}", ident(&def.column)), f);
                if f.element == ElementMatch::Any {
                    where_.push(format!(
                        "EXISTS (SELECT 1 FROM {} c WHERE c.\"_parent_id\" = t0.\"_id\" AND {p})",
                        ident(&child_table)
                    ));
                } else {
                    same_element.push(p);
                }
            }
        }
    }
    if !same_element.is_empty() {
        where_.push(format!(
            "EXISTS (SELECT 1 FROM {} c WHERE c.\"_parent_id\" = t0.\"_id\" AND {})",
            ident(&child_table),
            same_element.join(" AND ")
        ));
    }

    let mut select = Vec::new();
    let mut group_by = Vec::new();
    for d in &plan.query.dimensions {
        let c = col(&d.id).ok_or_else(|| CompileError::FanOut { dim: d.id.clone(), grain: plan.grain.clone() })?;
        select.push(format!("{c} AS {}", ident(out_name(&d.id))));
        group_by.push(c);
    }
    for m in &plan.query.metrics {
        let def = &model.metrics[&m.id];
        let e = expr(&def.expr, &col)?;
        let agg = match def.aggregation {
            Aggregation::Sum => format!("SUM({e})"),
            Aggregation::Avg => format!("AVG({e})"),
            Aggregation::Min => format!("MIN({e})"),
            Aggregation::Max => format!("MAX({e})"),
            Aggregation::Count => "COUNT(*)".to_owned(),
            Aggregation::CountDistinct => format!("COUNT(DISTINCT {e})"),
        };
        select.push(format!("{agg} AS {}", ident(out_name(&m.id))));
    }

    let mut sql = format!("SELECT {}\n{from}", select.join(", "));
    if !where_.is_empty() {
        sql.push_str(&format!("\nWHERE {}", where_.join("\n  AND ")));
    }
    if !group_by.is_empty() {
        sql.push_str(&format!("\nGROUP BY {}", group_by.join(", ")));
    }
    if !plan.query.order_by.is_empty() {
        let parts: Vec<String> = plan
            .query
            .order_by
            .iter()
            .filter_map(|o| {
                let key = o.metric.as_deref().or(o.dimension.as_deref())?;
                Some(format!("{} {}", ident(out_name(key)), if o.dir == Dir::Desc { "DESC" } else { "ASC" }))
            })
            .collect();
        sql.push_str(&format!("\nORDER BY {}", parts.join(", ")));
    }
    if let Some(n) = plan.query.limit {
        sql.push_str(&format!("\nLIMIT {n}"));
    }
    Ok(sql)
}

fn expr(e: &MetricExpr, col: &dyn Fn(&str) -> Option<String>) -> Result<String, CompileError> {
    let bin = |l: &MetricExpr, r: &MetricExpr, op: &str| -> Result<String, CompileError> {
        Ok(format!("({} {op} {})", expr(l, col)?, expr(r, col)?))
    };
    match e {
        MetricExpr::Attr { id } => col(id).ok_or_else(|| CompileError::Unknown("attribute in scope", id.clone())),
        MetricExpr::Mul { left, right } => bin(left, right, "*"),
        MetricExpr::Add { left, right } => bin(left, right, "+"),
        MetricExpr::Sub { left, right } => bin(left, right, "-"),
        MetricExpr::Rows => Ok("1".into()),
    }
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
        let sql = lower(&m, &p).unwrap();
        let expected = r#"SELECT t1."category" AS "category", SUM((t1."qty" * t1."unit_price")) AS "gross_revenue"
FROM "orders" t0
JOIN "orders__lines" t1 ON t1."_parent_id" = t0."_id"
JOIN "customers" t2 ON t2."_id" = t0."customer_id"
WHERE t0."status" IN ('paid', 'shipped')
  AND t0."sales_org" IN ('EU-1', 'EU-2')
  AND t2."region" = 'EU'
  AND t0."created_at" >= TIMESTAMP '2026-07-01T00:00:00Z' AND t0."created_at" < TIMESTAMP '2026-10-01T00:00:00Z'
GROUP BY t1."category"
ORDER BY "gross_revenue" DESC
LIMIT 5"#;
        assert_eq!(sql, expected, "\n{sql}");
    }

    #[test]
    fn literals_are_escaped() {
        let m = model();
        let mut q = query();
        q.filters[0].value = Some(Value::String("EU' OR 1=1 --".into()));
        let sql = lower(&m, &plan(&m, &q, &[]).unwrap()).unwrap();
        assert!(sql.contains(r#"t2."region" = 'EU'' OR 1=1 --'"#), "{sql}");
    }
}
