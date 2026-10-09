//! Caliban Semantic Model (CSM) and the query compiler.
//!
//! See docs/research/03-ontology-and-datasource-layer.md and 08-ontology-deep-dive-nosql.md.
//!
//! - [`model`]: typed ontology elements (entities with document-aware bindings, attributes,
//!   reference/embedded relations, metrics, policies) and the compiled in-memory [`model::Model`].
//! - [`cqir`]: the Caliban Query IR. The LLM emits CQIR that names ontology ids only; it never
//!   names a collection, path, or operator string.
//! - [`compile`]: deterministic lowering of CQIR to a MongoDB aggregation pipeline (native lane)
//!   or SQL over the CDC replica (accelerated lane), plus a pipeline lint.

pub mod compile;
pub mod cqir;
pub mod model;

use serde::{Deserialize, Serialize};

pub use model::{ElementSpec, Model};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Proposed,
    Approved,
    Rejected,
    Stale,
    Deprecated,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Introspect,
    Profile,
    QueryLog,
    Llm,
    Human,
}

/// A stored ontology element. JSON shape matches the OpenAPI `OntologyElement`
/// (`kind` + `spec` at the top level).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Element {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub synonyms: Vec<String>,
    pub status: Status,
    pub provenance: Provenance,
    pub confidence: Option<f32>,
    #[serde(flatten)]
    pub spec: ElementSpec,
}

impl Element {
    /// Relations, metrics and policies always need a human; low-risk metadata may auto-approve.
    pub fn requires_human_review(&self) -> bool {
        matches!(self.spec, ElementSpec::Relation(_) | ElementSpec::Metric(_) | ElementSpec::Policy(_))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Ontology {
    pub tenant_id: String,
    pub version: u64,
    pub elements: Vec<Element>,
}

impl Ontology {
    pub fn approved(&self) -> impl Iterator<Item = &Element> {
        self.elements.iter().filter(|e| e.status == Status::Approved)
    }
}
