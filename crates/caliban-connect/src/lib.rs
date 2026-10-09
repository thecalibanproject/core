//! Connectors (docs/research/03-ontology-and-datasource-layer.md §1, 08-ontology-deep-dive-nosql.md).
//!
//! One trait for every source. Connectors are read-only by construction and expose what the
//! ontology bootstrap needs (introspect, profile, query log) plus a change feed that bumps
//! datasource epochs for cache invalidation.
//!
//! Modules:
//! - [`infer`]: sampling-based schema inference over documents (path tree, BSON type histograms,
//!   presence/null fractions, array length percentiles, distinct estimates, top values,
//!   discriminator detection) and reference-candidate selection. Pure; no I/O.
//! - [`bootstrap`]: turns a [`SchemaSnapshot`] into `proposed` ontology elements (root, subtype and
//!   embedded entities, attributes, unverified reference relations), research 08 §"Schema
//!   inference & ontology bootstrap".
//! - [`privileges`]: classifies `connectionStatus {showPrivileges: true}` output; any write or
//!   admin action refuses the connection.
//! - [`explain`]: summarizes `explain` (`queryPlanner` verbosity) output and gates the native lane
//!   (COLLSCAN on large collections, unindexed `$lookup`).
//! - [`mongo`] (feature `mongodb`, default on): the MongoDB connector itself: connect, read-only
//!   verification, introspection, profiling, reference discovery, the native-lane executor and
//!   epochs. The `bson`/`mongodb` crates are re-exported from there so dependents (the CDC replica)
//!   use the exact same driver version.
//!
//! TODO: Postgres/MySQL via DataFusion table providers, REST/OpenAPI, Parquet/S3, MCP (untrusted tier).

pub mod bootstrap;
pub mod explain;
#[cfg(feature = "mongodb")]
pub mod infer;
pub mod privileges;

#[cfg(feature = "mongodb")]
pub mod mongo;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("connection: {0}")]
    Connection(String),
    #[error("query rejected: {0}")]
    Rejected(String),
    #[error("source error: {0}")]
    Source(String),
    /// The configured principal can write or administer the source; Caliban refuses to use it.
    #[error("not read-only: {0}")]
    NotReadOnly(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    pub filter_pushdown: bool,
    pub aggregate_pushdown: bool,
    pub join_pushdown: bool,
    pub change_feed: bool,
    pub per_user_impersonation: bool,
}

/// Array-specific statistics of a path whose values are (mostly) arrays.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ArrayStats {
    pub len_p50: u32,
    pub len_p99: u32,
    pub len_max: u32,
    /// Share of the observed arrays that are empty.
    pub empty_fraction: f32,
    /// BSON type histogram of the array elements.
    pub element_types: BTreeMap<String, u64>,
}

impl ArrayStats {
    /// Arrays whose elements are (≥80%) documents are child-entity candidates.
    pub fn of_documents(&self) -> bool {
        let total: u64 = self.element_types.values().sum();
        total > 0
            && self.element_types.get("object").copied().unwrap_or(0) as f64 >= 0.8 * total as f64
    }

    /// Most frequent element type.
    pub fn dominant_element_type(&self) -> Option<&str> {
        self.element_types
            .iter()
            .filter(|(t, _)| *t != "null")
            .max_by_key(|(_, n)| **n)
            .map(|(t, _)| t.as_str())
    }
}

/// A field observed in a source object. For documents, `path` is dotted and `types` can hold
/// several BSON types (polymorphic fields). Paths inside arrays of documents use the element's
/// field name after the array path (`lines.qty`), as in MongoDB dotted notation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldInfo {
    pub path: String,
    /// Observed BSON type names (`$type` aliases), most frequent first.
    pub types: Vec<String>,
    /// Fraction of sampled containers (documents, or array elements for paths under an array)
    /// where the field is present.
    pub presence: f32,
    pub is_array: bool,
    /// BSON type histogram (`$type` alias → count).
    #[serde(default)]
    pub type_counts: BTreeMap<String, u64>,
    /// Fraction of the containers where the field is present but `null`.
    #[serde(default)]
    pub null_fraction: f32,
    #[serde(default)]
    pub array: Option<ArrayStats>,
    /// Nearest enclosing array-of-documents path (`lines` for `lines.qty`), if any.
    #[serde(default)]
    pub parent_array: Option<String>,
    /// More than one non-null type family (e.g. string and number): needs a human decision.
    #[serde(default)]
    pub polymorphic: bool,
    /// Object whose keys look like data (dates, ids, locales): a map attribute, not columns.
    #[serde(default)]
    pub dynamic_keys: bool,
    #[serde(default)]
    pub distinct_estimate: Option<u64>,
    /// Most frequent values; only kept for low-cardinality scalar paths.
    #[serde(default)]
    pub top_values: Vec<(serde_json::Value, u64)>,
}

impl FieldInfo {
    /// Most frequent non-null type, if any.
    pub fn dominant_type(&self) -> Option<&str> {
        self.types
            .iter()
            .map(String::as_str)
            .find(|t| *t != "null" && *t != "undefined")
    }

    /// Share of the non-null occurrences that have the dominant type.
    pub fn dominant_share(&self) -> f32 {
        let non_null: u64 = self
            .type_counts
            .iter()
            .filter(|(t, _)| *t != "null" && *t != "undefined")
            .map(|(_, n)| n)
            .sum();
        match self.dominant_type() {
            Some(t) if non_null > 0 => {
                self.type_counts.get(t).copied().unwrap_or(0) as f32 / non_null as f32
            }
            _ => 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndexInfo {
    pub name: String,
    /// Key paths in index order.
    pub keys: Vec<String>,
    #[serde(default)]
    pub unique: bool,
}

/// A low-cardinality field whose values select subtypes sharing one collection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscriminatorInfo {
    pub path: String,
    /// Observed values with sample counts, most frequent first.
    pub values: Vec<(String, u64)>,
    /// Paths whose presence is (almost) fully determined by the discriminator value.
    pub predictive_paths: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectInfo {
    pub name: String,
    pub estimated_rows: Option<u64>,
    pub fields: Vec<FieldInfo>,
    pub indexes: Vec<IndexInfo>,
    /// `collection`, `view` or `timeseries` (MongoDB); `table` elsewhere.
    #[serde(default)]
    pub kind: String,
    /// Documents in the (deduplicated) sample.
    #[serde(default)]
    pub sampled: u64,
    #[serde(default)]
    pub discriminators: Vec<DiscriminatorInfo>,
    /// `$jsonSchema` validator, treated as declared (high-trust) schema.
    #[serde(default)]
    pub declared_schema: Option<serde_json::Value>,
    /// Too many polymorphic paths or top-level keys: keep out of the query lanes until curated.
    #[serde(default)]
    pub unstable: bool,
}

impl ObjectInfo {
    pub fn field(&self, path: &str) -> Option<&FieldInfo> {
        self.fields.iter().find(|f| f.path == path)
    }

    /// Is `path` the first key of some index (so `$lookup`/filters on it can use the index)?
    pub fn is_indexed(&self, path: &str) -> bool {
        path == "_id"
            || self
                .indexes
                .iter()
                .any(|i| i.keys.first().is_some_and(|k| k == path))
    }
}

/// A candidate reference: sampled values of `from_object.from_path` found in `to_object.to_path`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReferenceInfo {
    pub from_object: String,
    /// Full dotted path from the document root (`customerId`, `lines.productId`).
    pub from_path: String,
    pub to_object: String,
    pub to_path: String,
    /// BSON type of the referencing values (`objectId`, `string`, `int`, …).
    pub value_type: String,
    /// Distinct sampled values probed / found in the target.
    pub probed: u64,
    pub matched: u64,
    /// `matched / probed` (containment ratio).
    pub overlap: f32,
    /// The referencing field holds arrays of references (N:M).
    #[serde(default)]
    pub many_valued: bool,
    /// Distinct / non-null sampled values of the referencing field (≈1 means 1:1).
    #[serde(default)]
    pub local_distinct_ratio: f32,
    /// The field name points at the target (`customerId` → `customers`).
    #[serde(default)]
    pub name_match: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SchemaSnapshot {
    /// Datasource id the snapshot was taken from (used in proposed entity bindings).
    #[serde(default)]
    pub datasource: String,
    pub objects: Vec<ObjectInfo>,
    #[serde(default)]
    pub references: Vec<ReferenceInfo>,
}

impl SchemaSnapshot {
    pub fn object(&self, name: &str) -> Option<&ObjectInfo> {
        self.objects.iter().find(|o| o.name == name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Profile {
    pub object: String,
    pub path: String,
    pub distinct_estimate: Option<u64>,
    /// Fraction of containers where the field is missing or null.
    pub null_fraction: f32,
    pub top_values: Vec<(serde_json::Value, u64)>,
    /// Fraction of containers where the field is missing (included in `null_fraction`).
    #[serde(default)]
    pub missing_fraction: f32,
}

#[async_trait]
pub trait Connector: Send + Sync {
    fn capabilities(&self) -> Capabilities;
    async fn introspect(&self) -> Result<SchemaSnapshot, ConnectError>;
    async fn profile(&self, object: &str, sample: u32) -> Result<Vec<Profile>, ConnectError>;
    /// Current data version (oplog/resume token time, LSN, snapshot id, max(updated_at)).
    async fn epoch(&self) -> Result<u64, ConnectError>;
}
