//! Caliban Query IR (CQIR). Emitted by the LLM under schema-constrained decoding; references
//! ontology ids only. See docs/research/08-ontology-deep-dive-nosql.md "The typed query IR".

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub ir_version: String,
    pub ontology_version: String,
    #[serde(default)]
    pub metrics: Vec<IdRef>,
    #[serde(default)]
    pub dimensions: Vec<IdRef>,
    #[serde(default)]
    pub filters: Vec<Filter>,
    #[serde(default)]
    pub order_by: Vec<OrderBy>,
    pub limit: Option<u32>,
    /// ISO-8601 duration; the planner routes to the native lane when replica lag exceeds it.
    pub freshness: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdRef {
    pub id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Ne,
    In,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
    IsNull,
    IsMissing,
    IsEmpty,
}

/// Typed literal. Only scalars or arrays of scalars: no objects, so no operator injection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "v", rename_all = "snake_case")]
pub enum Value {
    String(String),
    Number(f64),
    Bool(bool),
    /// RFC 3339, normalized to UTC.
    Timestamp(String),
    StringList(Vec<String>),
    NumberList(Vec<f64>),
    TimestampRange([String; 2]),
    NumberRange([f64; 2]),
}

/// For filters on embedded-array entities when the query grain is the parent: does one array
/// element have to satisfy all conditions (`same`) or may different elements satisfy each (`any`)?
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ElementMatch {
    #[default]
    Same,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub attr: String,
    pub op: Op,
    pub value: Option<Value>,
    /// `between` is `[lo, hi)` when true (default), `[lo, hi]` otherwise.
    #[serde(default = "yes")]
    pub half_open: bool,
    #[serde(default)]
    pub element: ElementMatch,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Dir {
    Asc,
    Desc,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OrderBy {
    pub metric: Option<String>,
    pub dimension: Option<String>,
    pub dir: Dir,
}
