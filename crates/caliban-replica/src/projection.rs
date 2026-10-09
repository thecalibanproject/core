//! Relational projection of an approved ontology over its MongoDB collections.
//!
//! - One table per **root** entity (`Model::table_of`, default = collection name) with `_id`
//!   (Utf8) plus one column per bound attribute and per reference column.
//! - One child table per **embedded** entity (`<parent_table>__<array_path>` by default) keyed by
//!   `(_parent_id, _idx)`, with the element's bound attributes.
//! - Root entities sharing a table (subtypes without their own table) are merged; a root table
//!   whose entities all carry the same discriminator keeps only matching documents.
//! - Only bound paths are replicated (research 08, "CDC acceleration policy"): unbound fields are
//!   never copied, which also limits PII.

use crate::ReplicaError;
use caliban_connect::mongo::bson::{Document, doc};
use caliban_ontology::model::{DataType, Discriminator, EntityBinding, Model};
use datafusion::arrow::datatypes::{DataType as ArrowType, Field, Schema, SchemaRef, TimeUnit};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const ID: &str = "_id";
pub const PARENT_ID: &str = "_parent_id";
pub const IDX: &str = "_idx";

/// Column type in the replica. `Number` is Float64 (MongoDB int/long/double/decimal all widen),
/// timestamps are microseconds in UTC; ObjectIds are stored as their hex string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Utf8,
    Float64,
    Int64,
    TimestampUtc,
    Bool,
}

impl From<DataType> for ColumnType {
    fn from(d: DataType) -> Self {
        match d {
            DataType::String => ColumnType::Utf8,
            DataType::Number => ColumnType::Float64,
            DataType::Timestamp => ColumnType::TimestampUtc,
            DataType::Bool => ColumnType::Bool,
        }
    }
}

impl ColumnType {
    pub fn arrow(self) -> ArrowType {
        match self {
            ColumnType::Utf8 => ArrowType::Utf8,
            ColumnType::Float64 => ArrowType::Float64,
            ColumnType::Int64 => ArrowType::Int64,
            ColumnType::TimestampUtc => ArrowType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            ColumnType::Bool => ArrowType::Boolean,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ColumnSpec {
    pub name: String,
    /// Dotted path relative to the document (root tables) or array element (child tables).
    /// Empty for the synthetic key columns.
    pub path: String,
    pub ty: ColumnType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TableKind {
    Root {
        discriminator: Option<Discriminator>,
    },
    /// Rows are the elements of `array_path` (from the document root) of the parent's documents.
    Child {
        parent_table: String,
        array_path: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct TableSpec {
    pub name: String,
    pub collection: String,
    pub entities: Vec<String>,
    pub kind: TableKind,
    pub columns: Vec<ColumnSpec>,
}

impl TableSpec {
    pub fn schema(&self) -> SchemaRef {
        Arc::new(Schema::new(
            self.columns
                .iter()
                .map(|c| Field::new(&c.name, c.ty.arrow(), !matches!(c.name.as_str(), ID | PARENT_ID | IDX)))
                .collect::<Vec<_>>(),
        ))
    }

    pub fn is_root(&self) -> bool {
        matches!(self.kind, TableKind::Root { .. })
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Projection {
    pub datasource: Option<String>,
    pub tables: Vec<TableSpec>,
    /// Entities that could not be projected, with the reason (e.g. arrays nested in arrays).
    pub skipped: Vec<(String, String)>,
}

fn push_col(cols: &mut Vec<ColumnSpec>, name: &str, path: &str, ty: ColumnType) -> Result<(), ReplicaError> {
    match cols.iter().find(|c| c.name == name) {
        Some(c) if c.path != path => {
            Err(ReplicaError::Projection(format!("column '{name}' is bound to both '{}' and '{path}'", c.path)))
        }
        Some(_) => Ok(()),
        None => {
            cols.push(ColumnSpec { name: name.to_owned(), path: path.to_owned(), ty });
            Ok(())
        }
    }
}

impl Projection {
    /// Builds the projection for the entities bound to `datasource` (all datasources if `None`).
    pub fn from_model(model: &Model, datasource: Option<&str>) -> Result<Self, ReplicaError> {
        let mut p = Projection { datasource: datasource.map(str::to_owned), ..Default::default() };
        // Deterministic order.
        let entities: BTreeMap<&String, _> = model.entities.iter().collect();

        // Root tables (grouped by table name).
        let mut roots: BTreeMap<String, TableSpec> = BTreeMap::new();
        let mut discs: BTreeMap<String, Vec<Option<Discriminator>>> = BTreeMap::new();
        for (id, def) in &entities {
            let EntityBinding::Root { datasource: ds, collection, discriminator, .. } = &def.binding else {
                continue;
            };
            if datasource.is_some_and(|want| want != ds) {
                continue;
            }
            let table = model.table_of(id).unwrap_or_else(|| collection.clone());
            let t = roots.entry(table.clone()).or_insert_with(|| TableSpec {
                name: table.clone(),
                collection: collection.clone(),
                entities: vec![],
                kind: TableKind::Root { discriminator: None },
                columns: vec![ColumnSpec { name: ID.into(), path: ID.into(), ty: ColumnType::Utf8 }],
            });
            if t.collection != *collection {
                return Err(ReplicaError::Projection(format!(
                    "table '{table}' is bound to collections '{}' and '{collection}'",
                    t.collection
                )));
            }
            t.entities.push((*id).clone());
            discs.entry(table).or_default().push(discriminator.clone());
        }
        for (table, ds) in discs {
            let first = ds[0].clone();
            if first.is_some()
                && ds.iter().all(|d| *d == first)
                && let Some(t) = roots.get_mut(&table)
            {
                t.kind = TableKind::Root { discriminator: first };
            }
        }

        // Child tables for embedded entities whose parent is a projected root entity.
        let mut children: BTreeMap<String, TableSpec> = BTreeMap::new();
        for (id, def) in &entities {
            let EntityBinding::Embedded { parent, array_path, .. } = &def.binding else {
                continue;
            };
            let Some(parent_def) = model.entities.get(parent) else {
                p.skipped.push(((*id).clone(), format!("unknown parent '{parent}'")));
                continue;
            };
            if !matches!(parent_def.binding, EntityBinding::Root { .. }) {
                p.skipped.push(((*id).clone(), "arrays nested in arrays are not replicated yet".into()));
                continue;
            }
            let parent_table = model.table_of(parent).unwrap_or_default();
            let Some(pt) = roots.get(&parent_table) else {
                continue;
            };
            let table = model.table_of(id).unwrap_or_default();
            children.insert(
                table.clone(),
                TableSpec {
                    name: table,
                    collection: pt.collection.clone(),
                    entities: vec![(*id).clone()],
                    kind: TableKind::Child { parent_table, array_path: array_path.clone() },
                    columns: vec![
                        ColumnSpec { name: PARENT_ID.into(), path: String::new(), ty: ColumnType::Utf8 },
                        ColumnSpec { name: IDX.into(), path: String::new(), ty: ColumnType::Int64 },
                    ],
                },
            );
        }

        let mut tables: Vec<TableSpec> = roots.into_values().chain(children.into_values()).collect();
        let table_of_entity: BTreeMap<String, usize> =
            tables.iter().enumerate().flat_map(|(i, t)| t.entities.iter().map(move |e| (e.clone(), i))).collect();

        // Attributes (sorted by id for a stable column order).
        let attrs: BTreeMap<&String, _> = model.attributes.iter().collect();
        for a in attrs.values() {
            let Some(&i) = table_of_entity.get(&a.entity) else {
                continue;
            };
            if matches!(a.column.as_str(), ID | PARENT_ID | IDX) && a.path != ID {
                return Err(ReplicaError::Projection(format!("attribute column '{}' is reserved", a.column)));
            }
            push_col(&mut tables[i].columns, &a.column, &a.path, a.data_type.into())?;
        }
        // Reference columns (local and foreign side). Keys are compared as strings unless an
        // attribute already typed the column.
        for r in &model.relations {
            for (entity, column, path) in
                [(&r.from, &r.local_column, &r.local_path), (&r.to, &r.foreign_column, &r.foreign_path)]
            {
                let Some(&i) = table_of_entity.get(entity) else {
                    continue;
                };
                if tables[i].columns.iter().any(|c| c.name == *column) {
                    continue;
                }
                push_col(&mut tables[i].columns, column, path, ColumnType::Utf8)?;
            }
        }
        // Discriminator columns.
        for t in &mut tables {
            if let TableKind::Root { discriminator: Some(d) } = t.kind.clone() {
                push_col(&mut t.columns, &d.column, &d.path, ColumnType::Utf8)?;
            }
        }
        p.tables = tables;
        Ok(p)
    }

    pub fn table(&self, name: &str) -> Option<&TableSpec> {
        self.tables.iter().find(|t| t.name == name)
    }

    pub fn collections(&self) -> BTreeSet<String> {
        self.tables.iter().map(|t| t.collection.clone()).collect()
    }

    /// Tables fed by one collection (roots first).
    pub fn tables_of(&self, collection: &str) -> impl Iterator<Item = &TableSpec> {
        self.tables.iter().filter(move |t| t.collection == collection)
    }

    /// Document paths (from the root) read for a collection: `_id`, root columns, discriminator
    /// paths, and `<array>.<element path>` for child columns.
    pub fn bound_paths(&self, collection: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::from([ID.to_owned()]);
        for t in self.tables_of(collection) {
            match &t.kind {
                TableKind::Root { discriminator } => {
                    out.extend(t.columns.iter().filter(|c| !c.path.is_empty()).map(|c| c.path.clone()));
                    if let Some(d) = discriminator {
                        out.insert(d.path.clone());
                    }
                }
                TableKind::Child { array_path, .. } => {
                    out.insert(array_path.clone());
                    out.extend(
                        t.columns.iter().filter(|c| !c.path.is_empty()).map(|c| format!("{array_path}.{}", c.path)),
                    );
                }
            }
        }
        // A path and its prefix cannot both be projected (`lines` and `lines.qty` collide); keep
        // the narrower paths so unbound element fields are not read.
        let all = out.clone();
        out.retain(|p| {
            !all.iter().any(|q| q != p && q.starts_with(p.as_str()) && q.as_bytes().get(p.len()) == Some(&b'.'))
        });
        out
    }

    /// `find` projection for the snapshot.
    pub fn find_projection(&self, collection: &str) -> Document {
        let mut d = doc! {};
        for p in self.bound_paths(collection) {
            d.insert(p, 1);
        }
        d
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use caliban_ontology::model::*;
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

    /// The orders/lines/customers model from caliban-ontology's compile fixtures.
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
        Model { version: "acme@42".into(), entities, attributes, relations, metrics: HashMap::new(), policies: vec![] }
    }

    #[test]
    fn projects_roots_children_and_reference_columns() {
        let p = Projection::from_model(&model(), Some("dw")).unwrap();
        let names: Vec<&str> = p.tables.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["customers", "orders", "orders__lines"]);
        let orders = p.table("orders").unwrap();
        let cols: Vec<(&str, ColumnType)> = orders.columns.iter().map(|c| (c.name.as_str(), c.ty)).collect();
        assert_eq!(
            cols,
            vec![
                ("_id", ColumnType::Utf8),
                ("created_at", ColumnType::TimestampUtc),
                ("sales_org", ColumnType::Utf8),
                ("status", ColumnType::Utf8),
                ("customer_id", ColumnType::Utf8),
            ]
        );
        let lines = p.table("orders__lines").unwrap();
        assert_eq!(lines.kind, TableKind::Child { parent_table: "orders".into(), array_path: "lines".into() });
        assert_eq!(lines.columns[0].name, "_parent_id");
        assert_eq!(lines.columns[1].name, "_idx");
        assert!(
            lines
                .columns
                .iter()
                .any(|c| c.name == "unit_price" && c.path == "unitPrice" && c.ty == ColumnType::Float64)
        );
        assert_eq!(
            p.bound_paths("orders").into_iter().collect::<Vec<_>>(),
            vec![
                "_id",
                "createdAt",
                "customerId",
                "lines.category",
                "lines.qty",
                "lines.sku",
                "lines.unitPrice",
                "salesOrg",
                "status"
            ]
        );
        assert_eq!(lines.schema().field(1).data_type(), &ArrowType::Int64);
        assert!(Projection::from_model(&model(), Some("other")).unwrap().tables.is_empty());
    }

    #[test]
    fn discriminated_subtype_tables_filter() {
        let mut m = model();
        m.entities.insert(
            "VipCustomer".into(),
            EntityDef {
                binding: EntityBinding::Root {
                    datasource: "dw".into(),
                    collection: "customers".into(),
                    table: Some("vip_customers".into()),
                    discriminator: Some(Discriminator {
                        path: "tier".into(),
                        column: "tier".into(),
                        value: "vip".into(),
                    }),
                },
                keys: vec!["_id".into()],
            },
        );
        let p = Projection::from_model(&m, None).unwrap();
        let vip = p.table("vip_customers").unwrap();
        assert!(matches!(&vip.kind, TableKind::Root { discriminator: Some(d) } if d.value == "vip"));
        assert!(vip.columns.iter().any(|c| c.name == "tier"));
        assert!(matches!(p.table("customers").unwrap().kind, TableKind::Root { discriminator: None }));
    }
}
