//! BSON → typed cells → Arrow `RecordBatch`, and Arrow → JSON rows for answers and shadow
//! comparison.
//!
//! Coercions follow the ontology data type of the column:
//! - `Utf8`: strings as-is; ObjectId → 24-char hex; integral numbers → `"42"`; other numbers,
//!   booleans and dates → their canonical text. Keys (`_id`, `_parent_id`, reference columns) use
//!   the same rule on both sides of a join, so joins on ObjectIds work.
//! - `Float64`: int32/int64/double/decimal128; anything else → NULL.
//! - `TimestampUtc`: BSON dates (ms → µs) and BSON timestamps; anything else → NULL (dates stored
//!   as strings stay strings, as in the native lane where they never match a `$date`).
//! - `Bool`: booleans only.
//!
//! Missing and `null` both become NULL (the replica cannot tell them apart; the SQL compiler
//! documents this).

use crate::projection::{ColumnType, ID, TableKind, TableSpec};
use caliban_connect::infer::{bson_f64, get_path};
use caliban_connect::mongo::bson::{Bson, Document};
use datafusion::arrow::array::{
    Array, ArrayRef, BooleanArray, BooleanBuilder, Float64Array, Float64Builder, Int64Array, Int64Builder,
    StringBuilder, TimestampMicrosecondArray, TimestampMicrosecondBuilder,
};
use datafusion::arrow::datatypes::{DataType as ArrowType, TimeUnit};
use datafusion::arrow::error::ArrowError;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::arrow::util::display::{ArrayFormatter, FormatOptions};
use serde_json::{Map, Value as J};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Str(String),
    F64(f64),
    I64(i64),
    /// Microseconds since the Unix epoch, UTC.
    Ts(i64),
    Bool(bool),
}

pub type Row = Vec<Cell>;

/// Canonical text of a key value (`_id`, references): ObjectId → hex, integral numbers without
/// a fraction, strings as-is.
pub fn key_string(b: &Bson) -> Option<String> {
    Some(match b {
        Bson::ObjectId(o) => o.to_hex(),
        Bson::String(s) | Bson::Symbol(s) => s.clone(),
        Bson::Int32(i) => i.to_string(),
        Bson::Int64(i) => i.to_string(),
        Bson::Double(d) if d.fract() == 0.0 && d.abs() < 9.0e15 => (*d as i64).to_string(),
        Bson::Double(d) => d.to_string(),
        Bson::Decimal128(d) => d.to_string(),
        Bson::Boolean(v) => v.to_string(),
        Bson::DateTime(d) => d.try_to_rfc3339_string().unwrap_or_else(|_| d.timestamp_millis().to_string()),
        Bson::Null | Bson::Undefined => return None,
        other => caliban_connect::infer::bson_to_json(other).to_string(),
    })
}

pub fn cell(b: Option<&Bson>, ty: ColumnType) -> Cell {
    let Some(b) = b else { return Cell::Null };
    match ty {
        ColumnType::Utf8 => match b {
            Bson::Document(_) | Bson::Array(_) => Cell::Null,
            other => key_string(other).map(Cell::Str).unwrap_or(Cell::Null),
        },
        ColumnType::Float64 => bson_f64(b).map(Cell::F64).unwrap_or(Cell::Null),
        ColumnType::Int64 => match b {
            Bson::Int32(i) => Cell::I64(i64::from(*i)),
            Bson::Int64(i) => Cell::I64(*i),
            _ => Cell::Null,
        },
        ColumnType::TimestampUtc => match b {
            Bson::DateTime(d) => d.timestamp_millis().checked_mul(1000).map(Cell::Ts).unwrap_or(Cell::Null),
            Bson::Timestamp(t) => Cell::Ts(i64::from(t.time) * 1_000_000),
            _ => Cell::Null,
        },
        ColumnType::Bool => match b {
            Bson::Boolean(v) => Cell::Bool(*v),
            _ => Cell::Null,
        },
    }
}

/// Does a root document belong in this table (discriminator check)?
pub fn matches_table(spec: &TableSpec, doc: &Document) -> bool {
    match &spec.kind {
        TableKind::Root { discriminator: Some(d) } => {
            matches!(get_path(doc, &d.path), Some(Bson::String(v)) if *v == d.value)
        }
        _ => true,
    }
}

/// The row of a root table for one document.
pub fn root_row(spec: &TableSpec, doc: &Document) -> Row {
    spec.columns
        .iter()
        .map(|c| if c.name == ID { cell(doc.get(ID), ColumnType::Utf8) } else { cell(get_path(doc, &c.path), c.ty) })
        .collect()
}

/// Child rows of one parent document, with `$unwind` semantics: an array yields one row per
/// element; a non-array, non-null value is a one-element array; missing/null/empty yield none.
pub fn child_rows(spec: &TableSpec, parent_id: &str, doc: &Document) -> Vec<Row> {
    let TableKind::Child { array_path, .. } = &spec.kind else {
        return vec![];
    };
    let elements: Vec<&Bson> = match get_path(doc, array_path) {
        None | Some(Bson::Null) | Some(Bson::Undefined) => vec![],
        Some(Bson::Array(a)) => a.iter().collect(),
        Some(other) => vec![other],
    };
    elements
        .into_iter()
        .enumerate()
        .map(|(idx, el)| {
            let mut row = vec![Cell::Str(parent_id.to_owned()), Cell::I64(idx as i64)];
            for c in &spec.columns[2..] {
                let v = match el {
                    Bson::Document(d) => get_path(d, &c.path),
                    _ => None,
                };
                row.push(cell(v, c.ty));
            }
            row
        })
        .collect()
}

/// Builds a `RecordBatch` with the table's schema from rows in order.
pub fn to_batch<'a>(spec: &TableSpec, rows: impl Iterator<Item = &'a Row> + Clone) -> Result<RecordBatch, ArrowError> {
    let schema = spec.schema();
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(spec.columns.len());
    for (i, c) in spec.columns.iter().enumerate() {
        let col = rows.clone().map(|r| r.get(i).unwrap_or(&Cell::Null));
        let a: ArrayRef = match c.ty {
            ColumnType::Utf8 => {
                let mut b = StringBuilder::new();
                for v in col {
                    match v {
                        Cell::Str(s) => b.append_value(s),
                        _ => b.append_null(),
                    }
                }
                Arc::new(b.finish())
            }
            ColumnType::Float64 => {
                let mut b = Float64Builder::new();
                col.for_each(|v| b.append_option(if let Cell::F64(x) = v { Some(*x) } else { None }));
                Arc::new(b.finish())
            }
            ColumnType::Int64 => {
                let mut b = Int64Builder::new();
                col.for_each(|v| b.append_option(if let Cell::I64(x) = v { Some(*x) } else { None }));
                Arc::new(b.finish())
            }
            ColumnType::TimestampUtc => {
                let mut b = TimestampMicrosecondBuilder::new().with_timezone("UTC");
                col.for_each(|v| b.append_option(if let Cell::Ts(x) = v { Some(*x) } else { None }));
                Arc::new(b.finish())
            }
            ColumnType::Bool => {
                let mut b = BooleanBuilder::new();
                col.for_each(|v| b.append_option(if let Cell::Bool(x) = v { Some(*x) } else { None }));
                Arc::new(b.finish())
            }
        };
        arrays.push(a);
    }
    RecordBatch::try_new(schema, arrays)
}

/// Arrow → JSON rows (objects keyed by column name). Numbers stay numbers, timestamps become
/// RFC 3339 strings, other types use Arrow's display formatting.
pub fn batches_to_json(batches: &[RecordBatch]) -> Result<Vec<J>, ArrowError> {
    let mut out = Vec::new();
    for b in batches {
        let schema = b.schema();
        let fmt_opts = FormatOptions::default().with_null("null");
        let formatters: Vec<ArrayFormatter<'_>> =
            b.columns().iter().map(|c| ArrayFormatter::try_new(c.as_ref(), &fmt_opts)).collect::<Result<_, _>>()?;
        for row in 0..b.num_rows() {
            let mut obj = Map::new();
            for (i, col) in b.columns().iter().enumerate() {
                let name = schema.field(i).name().clone();
                let v = if col.is_null(row) {
                    J::Null
                } else {
                    match col.data_type() {
                        ArrowType::Float64 => {
                            let x = col.as_any().downcast_ref::<Float64Array>().map(|a| a.value(row));
                            x.and_then(serde_json::Number::from_f64).map(J::Number).unwrap_or(J::Null)
                        }
                        ArrowType::Int64 => {
                            col.as_any().downcast_ref::<Int64Array>().map(|a| J::from(a.value(row))).unwrap_or(J::Null)
                        }
                        ArrowType::Boolean => col
                            .as_any()
                            .downcast_ref::<BooleanArray>()
                            .map(|a| J::Bool(a.value(row)))
                            .unwrap_or(J::Null),
                        ArrowType::Timestamp(TimeUnit::Microsecond, _) => col
                            .as_any()
                            .downcast_ref::<TimestampMicrosecondArray>()
                            .and_then(|a| {
                                caliban_connect::mongo::bson::DateTime::from_millis(a.value(row) / 1000)
                                    .try_to_rfc3339_string()
                                    .ok()
                            })
                            .map(J::String)
                            .unwrap_or(J::Null),
                        ArrowType::Int8
                        | ArrowType::Int16
                        | ArrowType::Int32
                        | ArrowType::UInt8
                        | ArrowType::UInt16
                        | ArrowType::UInt32
                        | ArrowType::UInt64 => {
                            let s = formatters[i].value(row).to_string();
                            s.parse::<i64>().map(J::from).unwrap_or(J::String(s))
                        }
                        ArrowType::Float32 | ArrowType::Decimal128(..) | ArrowType::Decimal256(..) => {
                            let s = formatters[i].value(row).to_string();
                            s.parse::<f64>()
                                .ok()
                                .and_then(serde_json::Number::from_f64)
                                .map(J::Number)
                                .unwrap_or(J::String(s))
                        }
                        _ => J::String(formatters[i].value(row).to_string()),
                    }
                };
                obj.insert(name, v);
            }
            out.push(J::Object(obj));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::Projection;
    use crate::projection::tests::model;
    use caliban_connect::mongo::bson::{DateTime, Decimal128, doc, oid::ObjectId};
    use serde_json::json;

    #[test]
    fn coerces_bson_to_column_types() {
        let oid = ObjectId::parse_str("65a1f0c2e4b0a1b2c3d4e5f6").unwrap();
        assert_eq!(cell(Some(&Bson::ObjectId(oid)), ColumnType::Utf8), Cell::Str("65a1f0c2e4b0a1b2c3d4e5f6".into()));
        assert_eq!(cell(Some(&Bson::Int32(3)), ColumnType::Float64), Cell::F64(3.0));
        assert_eq!(cell(Some(&Bson::Int64(7)), ColumnType::Utf8), Cell::Str("7".into()));
        let dec: Decimal128 = "12.5".parse().unwrap();
        assert_eq!(cell(Some(&Bson::Decimal128(dec)), ColumnType::Float64), Cell::F64(12.5));
        assert_eq!(cell(Some(&Bson::String("x".into())), ColumnType::Float64), Cell::Null);
        assert_eq!(
            cell(Some(&Bson::DateTime(DateTime::from_millis(1_500))), ColumnType::TimestampUtc),
            Cell::Ts(1_500_000)
        );
        assert_eq!(cell(Some(&Bson::String("2026-01-01".into())), ColumnType::TimestampUtc), Cell::Null);
        assert_eq!(cell(Some(&Bson::Null), ColumnType::Utf8), Cell::Null);
        assert_eq!(cell(None, ColumnType::Bool), Cell::Null);
        assert_eq!(cell(Some(&Bson::Document(doc! {})), ColumnType::Utf8), Cell::Null);
    }

    #[test]
    fn order_document_to_arrow_and_back() {
        let p = Projection::from_model(&model(), None).unwrap();
        let cust = ObjectId::parse_str("65a1f0c2e4b0a1b2c3d4e5f6").unwrap();
        let d = doc! {
            "_id": 1, "status": "paid", "salesOrg": "EU-1", "customerId": cust,
            "createdAt": DateTime::parse_rfc3339_str("2026-07-02T10:00:00Z").unwrap(),
            "lines": [ { "category": "books", "qty": 2, "unitPrice": 9.5, "sku": "B1" }, { "category": "toys", "qty": 1_i64 }, "junk" ],
            "unbound": "never copied"
        };
        let orders = p.table("orders").unwrap();
        let row = root_row(orders, &d);
        let batch = to_batch(orders, [row].iter()).unwrap();
        assert_eq!(batch.num_rows(), 1);
        assert_eq!(batch.num_columns(), 5);
        assert_eq!(
            batches_to_json(&[batch]).unwrap(),
            vec![
                json!({ "_id": "1", "created_at": "2026-07-02T10:00:00Z", "sales_org": "EU-1", "status": "paid", "customer_id": "65a1f0c2e4b0a1b2c3d4e5f6" })
            ]
        );

        let lines = p.table("orders__lines").unwrap();
        let rows = child_rows(lines, "1", &d);
        assert_eq!(rows.len(), 3, "non-document elements still unwind");
        let batch = to_batch(lines, rows.iter()).unwrap();
        let j = batches_to_json(&[batch]).unwrap();
        assert_eq!(
            j[0],
            json!({ "_parent_id": "1", "_idx": 0, "category": "books", "qty": 2.0, "sku": "B1", "unit_price": 9.5 })
        );
        assert_eq!(j[1]["unit_price"], J::Null);
        assert_eq!(
            j[2],
            json!({ "_parent_id": "1", "_idx": 2, "category": null, "qty": null, "sku": null, "unit_price": null })
        );

        assert!(child_rows(lines, "2", &doc! { "_id": 2, "lines": [] }).is_empty());
        assert!(child_rows(lines, "3", &doc! { "_id": 3 }).is_empty());
        assert_eq!(child_rows(lines, "4", &doc! { "_id": 4, "lines": { "category": "x" } }).len(), 1);
    }
}
