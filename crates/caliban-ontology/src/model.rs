//! Typed ontology definitions and the compiled, in-memory model used by the compiler.

use crate::cqir::Filter;
use crate::{Ontology, Status};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataType {
    String,
    Number,
    Timestamp,
    Bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntityBinding {
    /// Top-level documents/rows of a collection or table.
    Root {
        datasource: String,
        collection: String,
        /// Table name in the CDC replica (defaults to the collection name).
        table: Option<String>,
        /// Discriminator for subtypes sharing a collection, e.g. `{"path": "type", "value": "invoice"}`.
        discriminator: Option<Discriminator>,
    },
    /// Elements of an array embedded in the parent entity's documents (1:N, owned).
    Embedded {
        parent: String,
        array_path: String,
        /// Child table in the replica (defaults to `<parent_table>__<array_path>`), keyed by
        /// `(_parent_id, _idx)`.
        table: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Discriminator {
    pub path: String,
    pub column: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntityDef {
    pub binding: EntityBinding,
    #[serde(default)]
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttributeDef {
    pub entity: String,
    /// Dotted document path relative to the entity's document (or array element).
    pub path: String,
    /// Column in the replica / SQL sources.
    pub column: String,
    pub data_type: DataType,
    pub pii_class: Option<String>,
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Cardinality {
    OneToOne,
    OneToMany,
    ManyToOne,
    ManyToMany,
}

/// A reference relation (ObjectId or key pointing at another entity). Embedded relations are
/// implied by `EntityBinding::Embedded`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelationDef {
    pub from: String,
    pub to: String,
    pub cardinality: Cardinality,
    pub local_path: String,
    pub local_column: String,
    pub foreign_path: String,
    pub foreign_column: String,
    /// Set only after a value-overlap check; unverified references are never joined.
    pub verified: bool,
    /// Native lane may `$lookup` only if the foreign field is indexed.
    #[serde(default)]
    pub foreign_indexed: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Aggregation {
    Sum,
    Avg,
    Min,
    Max,
    Count,
    CountDistinct,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MetricExpr {
    Attr { id: String },
    Mul { left: Box<MetricExpr>, right: Box<MetricExpr> },
    Add { left: Box<MetricExpr>, right: Box<MetricExpr> },
    Sub { left: Box<MetricExpr>, right: Box<MetricExpr> },
    /// Row count at the metric's grain.
    Rows,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricDef {
    /// Entity whose rows the metric aggregates.
    pub grain: String,
    pub aggregation: Aggregation,
    pub expr: MetricExpr,
    /// Part of the metric's definition (e.g. only paid orders).
    #[serde(default)]
    pub filters: Vec<Filter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDef {
    pub entity: String,
    /// Row predicate template; `{principal.<attr>}` placeholders are resolved per request.
    pub row_filter: Option<Filter>,
    #[serde(default)]
    pub denied_attributes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "spec", rename_all = "snake_case")]
pub enum ElementSpec {
    Entity(EntityDef),
    Attribute(AttributeDef),
    Relation(RelationDef),
    Metric(MetricDef),
    GlossaryTerm { phrase: String, maps_to: String },
    Policy(PolicyDef),
    VerifiedQuery { question: String, query: crate::cqir::Query, approver: String },
}

/// Compiled view of the approved elements of one ontology version.
#[derive(Debug, Clone, Default)]
pub struct Model {
    pub version: String,
    pub entities: HashMap<String, EntityDef>,
    pub attributes: HashMap<String, AttributeDef>,
    pub relations: Vec<RelationDef>,
    pub metrics: HashMap<String, MetricDef>,
    pub policies: Vec<PolicyDef>,
}

impl Model {
    pub fn from_ontology(o: &Ontology) -> Self {
        let mut m = Model { version: format!("{}@{}", o.tenant_id, o.version), ..Default::default() };
        for e in o.elements.iter().filter(|e| e.status == Status::Approved) {
            match &e.spec {
                ElementSpec::Entity(d) => {
                    m.entities.insert(e.id.clone(), d.clone());
                }
                ElementSpec::Attribute(d) => {
                    m.attributes.insert(e.id.clone(), d.clone());
                }
                ElementSpec::Relation(d) => m.relations.push(d.clone()),
                ElementSpec::Metric(d) => {
                    m.metrics.insert(e.id.clone(), d.clone());
                }
                ElementSpec::Policy(d) => m.policies.push(d.clone()),
                ElementSpec::GlossaryTerm { .. } | ElementSpec::VerifiedQuery { .. } => {}
            }
        }
        m
    }

    /// Embedded entities resolve to the root entity whose collection holds their documents.
    pub fn root_of<'a>(&'a self, entity: &'a str) -> Option<&'a str> {
        let mut cur = entity;
        for _ in 0..16 {
            match &self.entities.get(cur)?.binding {
                EntityBinding::Root { .. } => return Some(cur),
                EntityBinding::Embedded { parent, .. } => cur = parent,
            }
        }
        None
    }

    pub fn table_of(&self, entity: &str) -> Option<String> {
        match &self.entities.get(entity)?.binding {
            EntityBinding::Root { collection, table, .. } => Some(table.clone().unwrap_or_else(|| collection.clone())),
            EntityBinding::Embedded { parent, array_path, table } => {
                Some(table.clone().unwrap_or_else(|| format!("{}__{}", self.table_of(parent).unwrap_or_default(), array_path)))
            }
        }
    }

    /// Verified N:1 (or 1:1) reference from `from` to `to`.
    pub fn reference(&self, from: &str, to: &str) -> Option<&RelationDef> {
        self.relations.iter().find(|r| {
            r.from == from && r.to == to && r.verified && matches!(r.cardinality, Cardinality::ManyToOne | Cardinality::OneToOne)
        })
    }
}
