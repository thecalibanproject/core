//! MongoDB connector (official `mongodb` driver, Apache-2.0).
//!
//! - [`MongoConnector::connect`] from `{uri, database, read_preference?, read_tag?}` (the shape
//!   the web console sends).
//! - [`MongoConnector::verify_read_only`]: `connectionStatus {showPrivileges: true}`; refuses any
//!   principal holding a write/admin action, reports whether change streams are available.
//! - Introspection: `listCollections`, `listIndexes`, `estimatedDocumentCount`, and a stratified
//!   sample per collection (`$sample` + newest-N + oldest-N by `_id`, never natural order), fed
//!   to [`crate::infer`]; references found by probing sampled values against target `_id`s with
//!   an indexed `$in` count.
//! - Native lane: [`MongoConnector::execute`] re-lints the compiled pipeline and runs it with
//!   `maxTimeMS`, `allowDiskUse: false`, an audit `comment`, the read preference, and a row cap;
//!   [`MongoConnector::explain_gate`] dry-runs it with `explain` (`queryPlanner`).
//! - [`MongoConnector::epoch`]: the cluster's `operationTime` packed as `(seconds << 32) | inc`.

pub use mongodb;
pub use mongodb::bson;

use crate::explain::{GatePolicy, GateReport};
use crate::infer::{self, InferOptions, RefCandidate, bson_to_json, doc_to_json, value_key};
use crate::privileges::{PrivilegeReport, classify_connection_status};
use crate::{Capabilities, ConnectError, Connector, IndexInfo, ObjectInfo, Profile, ReferenceInfo, SchemaSnapshot};
use async_trait::async_trait;
use bson::{Bson, Document, Timestamp, doc};
use caliban_ontology::compile::mongo::{MongoQuery, lint};
use futures::TryStreamExt;
use mongodb::options::{ClientOptions, ReadPreference, ReadPreferenceOptions, SelectionCriteria};
use mongodb::results::CollectionType;
use mongodb::{Client, Collection, Database};
use serde::{Deserialize, Serialize};
use serde_json::Value as J;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

/// A replica-set tag for routing analytics reads: `"workload:analytics"` or `{"workload": "analytics"}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ReadTag {
    Pair(String),
    Map(BTreeMap<String, String>),
}

impl ReadTag {
    fn tag_set(&self) -> Result<HashMap<String, String>, ConnectError> {
        match self {
            ReadTag::Map(m) => Ok(m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
            ReadTag::Pair(s) => {
                let (k, v) = s
                    .split_once([':', '='])
                    .ok_or_else(|| ConnectError::Connection(format!("read_tag '{s}' must look like 'key:value'")))?;
                Ok([(k.trim().to_owned(), v.trim().to_owned())].into_iter().collect())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoConfig {
    pub uri: String,
    pub database: String,
    /// `primary` | `primaryPreferred` | `secondary` | `secondaryPreferred` | `nearest`. When set,
    /// it overrides the read preference compiled into a query (the operator knows the topology).
    #[serde(default)]
    pub read_preference: Option<String>,
    #[serde(default)]
    pub read_tag: Option<ReadTag>,
    /// Datasource id; when set, queries compiled for another datasource are rejected.
    #[serde(default)]
    pub datasource_id: Option<String>,
    /// Upper bound for `maxTimeMS` on every operation (default 15 s).
    #[serde(default)]
    pub max_time_ms: Option<u64>,
}

impl MongoConfig {
    pub fn new(uri: impl Into<String>, database: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            database: database.into(),
            read_preference: None,
            read_tag: None,
            datasource_id: None,
            max_time_ms: None,
        }
    }
}

/// Sampling and discovery knobs for [`MongoConnector::introspect_with`].
#[derive(Debug, Clone)]
pub struct SampleConfig {
    /// `$sample` size (pseudo-random).
    pub sample_size: u32,
    /// Newest documents by `_id` (catches recent shape changes).
    pub newest: u32,
    /// Oldest documents by `_id`.
    pub oldest: u32,
    pub max_collections: usize,
    /// Distinct values per candidate probed against the target `_id`.
    pub reference_probe_values: usize,
    /// Targets probed per candidate (name matches first).
    pub max_reference_targets: usize,
    /// Keep reference evidence at or above this overlap in the snapshot (proposal uses 0.95).
    pub min_reported_overlap: f32,
    pub infer: InferOptions,
}

impl Default for SampleConfig {
    fn default() -> Self {
        Self {
            sample_size: 1_000,
            newest: 500,
            oldest: 200,
            max_collections: 200,
            reference_probe_values: 1_000,
            max_reference_targets: 20,
            min_reported_overlap: 0.5,
            infer: InferOptions::default(),
        }
    }
}

/// Topology facts read from `hello` at connect time.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Topology {
    pub replica_set: bool,
    pub set_name: Option<String>,
    pub sharded: bool,
    pub max_wire_version: Option<i32>,
}

impl Topology {
    /// Change streams need a replica set or a sharded cluster.
    pub fn change_streams(&self) -> bool {
        self.replica_set || self.sharded
    }
}

/// Native-lane result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NativeResult {
    /// Rows as plain JSON (ObjectId → hex, dates → RFC 3339).
    pub rows: Vec<J>,
    /// More rows than `row_cap` were available; `rows` holds the first `row_cap`.
    pub truncated: bool,
}

pub struct MongoConnector {
    client: Client,
    db: Database,
    cfg: MongoConfig,
    topology: Topology,
}

fn src(e: impl std::fmt::Display) -> ConnectError {
    ConnectError::Source(e.to_string())
}

/// Packs a BSON timestamp as `(seconds << 32) | increment`, ordered like cluster time.
pub fn ts_to_u64(t: Timestamp) -> u64 {
    (u64::from(t.time) << 32) | u64::from(t.increment)
}

pub fn u64_to_ts(v: u64) -> Timestamp {
    Timestamp { time: (v >> 32) as u32, increment: (v & 0xffff_ffff) as u32 }
}

/// Converts a compiled pipeline (JSON) to BSON. Only one Extended-JSON form is honoured:
/// `{"$date": "<RFC 3339>"}`, which the compiler emits for timestamp literals. Other wrappers
/// (`$oid`, `$code`, `$binary`, …) are rejected: compiled pipelines never contain them, so their
/// presence means the pipeline did not come from the compiler.
pub fn json_to_bson(v: &J) -> Result<Bson, ConnectError> {
    Ok(match v {
        J::Null => Bson::Null,
        J::Bool(b) => Bson::Boolean(*b),
        J::Number(n) => match n.as_i64() {
            Some(i) if i32::try_from(i).is_ok() => Bson::Int32(i as i32),
            Some(i) => Bson::Int64(i),
            None => Bson::Double(n.as_f64().ok_or_else(|| ConnectError::Rejected(format!("number {n}")))?),
        },
        J::String(s) => Bson::String(s.clone()),
        J::Array(a) => Bson::Array(a.iter().map(json_to_bson).collect::<Result<_, _>>()?),
        J::Object(o) => {
            if o.len() == 1
                && let Some(J::String(s)) = o.get("$date")
            {
                return bson::DateTime::parse_rfc3339_str(s)
                    .map(Bson::DateTime)
                    .map_err(|e| ConnectError::Rejected(format!("bad $date literal '{s}': {e}")));
            }
            const EXTJSON: &[&str] = &[
                "$oid",
                "$code",
                "$binary",
                "$uuid",
                "$symbol",
                "$regularExpression",
                "$numberInt",
                "$numberLong",
                "$numberDouble",
                "$numberDecimal",
                "$timestamp",
                "$minKey",
                "$maxKey",
                "$dbPointer",
                "$undefined",
                "$date",
            ];
            if let Some(k) = o.keys().find(|k| EXTJSON.contains(&k.as_str())) {
                return Err(ConnectError::Rejected(format!("extended-JSON wrapper {k} is not allowed in a pipeline")));
            }
            let mut d = Document::new();
            for (k, v) in o {
                d.insert(k.clone(), json_to_bson(v)?);
            }
            Bson::Document(d)
        }
    })
}

fn pipeline_to_bson(p: &[J]) -> Result<Vec<Document>, ConnectError> {
    p.iter()
        .map(|s| match json_to_bson(s)? {
            Bson::Document(d) => Ok(d),
            _ => Err(ConnectError::Rejected("pipeline stage is not a document".into())),
        })
        .collect()
}

/// Parses a read-preference mode (camelCase or snake_case) with optional tag sets.
pub fn read_preference(
    mode: &str,
    tags: Vec<HashMap<String, String>>,
    max_staleness: Option<Duration>,
) -> Result<ReadPreference, ConnectError> {
    let options = if tags.is_empty() && max_staleness.is_none() {
        None
    } else {
        Some(
            ReadPreferenceOptions::builder()
                .tag_sets((!tags.is_empty()).then_some(tags))
                .max_staleness(max_staleness)
                .build(),
        )
    };
    let m = mode.replace(['_', '-'], "").to_ascii_lowercase();
    Ok(match m.as_str() {
        "primary" if options.is_none() => ReadPreference::Primary,
        "primary" => {
            return Err(ConnectError::Connection("read preference 'primary' cannot have tags".into()));
        }
        "primarypreferred" => ReadPreference::PrimaryPreferred { options },
        "secondary" => ReadPreference::Secondary { options },
        "secondarypreferred" => ReadPreference::SecondaryPreferred { options },
        "nearest" => ReadPreference::Nearest { options },
        other => {
            return Err(ConnectError::Connection(format!("unknown read preference '{other}'")));
        }
    })
}

impl MongoConnector {
    pub async fn connect(cfg: MongoConfig) -> Result<Self, ConnectError> {
        let conn = |e: mongodb::error::Error| ConnectError::Connection(e.to_string());
        let mut opts = ClientOptions::parse(&cfg.uri).await.map_err(conn)?;
        if opts.app_name.is_none() {
            opts.app_name = Some("caliban".into());
        }
        if opts.server_selection_timeout.is_none() {
            opts.server_selection_timeout = Some(Duration::from_secs(10));
        }
        let client = Client::with_options(opts).map_err(conn)?;
        let db = client.database(&cfg.database);
        let hello = db.run_command(doc! { "hello": 1 }).await.map_err(conn)?;
        let topology = Topology {
            replica_set: hello.get_str("setName").is_ok(),
            set_name: hello.get_str("setName").ok().map(str::to_owned),
            sharded: hello.get_str("msg").ok() == Some("isdbgrid"),
            max_wire_version: hello.get_i32("maxWireVersion").ok(),
        };
        let mut me = Self { client, db, cfg, topology };
        // Validate the configured read preference early.
        me.configured_selection()?;
        me.cfg.max_time_ms = Some(me.cfg.max_time_ms.unwrap_or(15_000));
        Ok(me)
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    pub fn config(&self) -> &MongoConfig {
        &self.cfg
    }

    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    fn max_time(&self) -> Duration {
        Duration::from_millis(self.cfg.max_time_ms.unwrap_or(15_000))
    }

    fn configured_selection(&self) -> Result<Option<SelectionCriteria>, ConnectError> {
        let Some(mode) = &self.cfg.read_preference else {
            return Ok(None);
        };
        let tags = self.cfg.read_tag.as_ref().map(ReadTag::tag_set).transpose()?.into_iter().collect();
        Ok(Some(SelectionCriteria::ReadPreference(read_preference(mode, tags, None)?)))
    }

    /// Read preference for introspection, profiling, snapshots and change streams: the configured
    /// one, else `secondaryPreferred`.
    pub fn selection_criteria(&self) -> SelectionCriteria {
        self.configured_selection()
            .ok()
            .flatten()
            .unwrap_or(SelectionCriteria::ReadPreference(ReadPreference::SecondaryPreferred { options: None }))
    }

    /// Read preference for a compiled query: the configured one wins; otherwise the query's
    /// `options.readPreference` (`{mode, tags: [{k: v}], maxStalenessSeconds}`).
    fn query_selection(&self, opt: Option<&J>) -> Result<SelectionCriteria, ConnectError> {
        if let Some(s) = self.configured_selection()? {
            return Ok(s);
        }
        let Some(rp) = opt else {
            return Ok(self.selection_criteria());
        };
        let mode = rp.get("mode").and_then(J::as_str).unwrap_or("secondaryPreferred");
        let tags = rp
            .get("tags")
            .and_then(J::as_array)
            .into_iter()
            .flatten()
            .filter_map(J::as_object)
            .map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned()))).collect())
            .collect();
        let staleness = rp.get("maxStalenessSeconds").and_then(J::as_u64).map(Duration::from_secs);
        Ok(SelectionCriteria::ReadPreference(read_preference(mode, tags, staleness)?))
    }

    /// Classifies the connected principal's privileges without failing.
    pub async fn privilege_report(&self) -> Result<PrivilegeReport, ConnectError> {
        let reply = self.db.run_command(doc! { "connectionStatus": 1, "showPrivileges": true }).await.map_err(src)?;
        let mut r = classify_connection_status(&doc_to_json(&reply));
        r.replica_set = self.topology.change_streams();
        r.set_name = self.topology.set_name.clone();
        Ok(r)
    }

    /// Refuses (error) if the user holds any write/admin action or the connection is
    /// unauthenticated. The report says whether change streams (CDC) are available.
    pub async fn verify_read_only(&self) -> Result<PrivilegeReport, ConnectError> {
        let r = self.privilege_report().await?;
        if r.read_only { Ok(r) } else { Err(ConnectError::NotReadOnly(r.reason.clone().unwrap_or_default())) }
    }

    /// Stratified sample: `$sample` + newest-N + oldest-N by `_id`, de-duplicated by `_id`.
    pub async fn sample(&self, coll: &str, cfg: &SampleConfig) -> Result<Vec<Document>, ConnectError> {
        let c: Collection<Document> = self.db.collection(coll);
        let comment = Bson::String("caliban:introspect".into());
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut add = |docs: Vec<Document>, out: &mut Vec<Document>| {
            for d in docs {
                let key = d.get("_id").map(value_key).unwrap_or_else(|| format!("#{}", out.len()));
                if seen.insert(key) {
                    out.push(d);
                }
            }
        };
        if cfg.sample_size > 0 {
            let docs: Vec<Document> = c
                .aggregate([doc! { "$sample": { "size": i64::from(cfg.sample_size) } }])
                .max_time(self.max_time())
                .allow_disk_use(false)
                .comment(comment.clone())
                .selection_criteria(self.selection_criteria())
                .await
                .map_err(src)?
                .try_collect()
                .await
                .map_err(src)?;
            add(docs, &mut out);
        }
        for (n, dir) in [(cfg.newest, -1), (cfg.oldest, 1)] {
            if n == 0 {
                continue;
            }
            let docs: Vec<Document> = c
                .find(doc! {})
                .sort(doc! { "_id": dir })
                .limit(i64::from(n))
                .max_time(self.max_time())
                .comment(comment.clone())
                .selection_criteria(self.selection_criteria())
                .await
                .map_err(src)?
                .try_collect()
                .await
                .map_err(src)?;
            add(docs, &mut out);
        }
        Ok(out)
    }

    async fn indexes(&self, coll: &str) -> Result<Vec<IndexInfo>, ConnectError> {
        let c: Collection<Document> = self.db.collection(coll);
        let models: Vec<mongodb::IndexModel> = c.list_indexes().await.map_err(src)?.try_collect().await.map_err(src)?;
        Ok(models
            .into_iter()
            .map(|m| {
                let opts = m.options.unwrap_or_default();
                IndexInfo {
                    name: opts.name.clone().unwrap_or_default(),
                    keys: m.keys.keys().cloned().collect(),
                    unique: opts.unique.unwrap_or(false),
                }
            })
            .collect())
    }

    pub async fn introspect_with(&self, cfg: &SampleConfig) -> Result<SchemaSnapshot, ConnectError> {
        let mut specs: Vec<mongodb::results::CollectionSpecification> =
            self.db.list_collections().await.map_err(src)?.try_collect().await.map_err(src)?;
        specs.retain(|s| !s.name.starts_with("system."));
        specs.sort_by(|a, b| a.name.cmp(&b.name));
        specs.truncate(cfg.max_collections);

        let mut objects: Vec<ObjectInfo> = Vec::new();
        let mut candidates: Vec<(String, Vec<RefCandidate>)> = Vec::new();
        for spec in &specs {
            let kind = match spec.collection_type {
                CollectionType::View => "view",
                CollectionType::Timeseries => "timeseries",
                _ => "collection",
            };
            let c: Collection<Document> = self.db.collection(&spec.name);
            let est = if kind == "view" { None } else { c.estimated_document_count().await.ok() };
            let docs = self.sample(&spec.name, cfg).await?;
            let inf = infer::infer(&docs, est, &cfg.infer);
            candidates.push((spec.name.clone(), infer::reference_candidates(&inf, cfg.reference_probe_values)));
            let mut info = inf.into_object_info(&spec.name, kind);
            if kind != "view" {
                info.indexes = self.indexes(&spec.name).await?;
            }
            info.declared_schema =
                spec.options.validator.as_ref().and_then(|v| v.get_document("$jsonSchema").ok()).map(doc_to_json);
            objects.push(info);
        }

        let mut references = Vec::new();
        for (from, cands) in &candidates {
            for cand in cands {
                let mut targets: Vec<(&ObjectInfo, bool)> = objects
                    .iter()
                    .filter(|o| o.kind != "view")
                    .filter_map(|o| {
                        let id_type = o.field("_id")?.dominant_type()?;
                        let hex_vs_oid = cand.value_type == "string" && id_type == "objectId";
                        (infer::type_compatible(&cand.value_type, id_type) || hex_vs_oid)
                            .then(|| (o, infer::name_matches(&cand.path, &o.name)))
                    })
                    .collect();
                if !targets.iter().any(|(_, m)| *m) && cand.value_type != "objectId" {
                    continue; // key-like scalar names are only probed against name-matching targets
                }
                targets.sort_by_key(|(o, m)| (!*m, o.name.clone()));
                targets.truncate(cfg.max_reference_targets);
                for (target, name_match) in targets {
                    let (matched, probed) = self.probe(cand, &target.name).await?;
                    let overlap = if probed == 0 { 0.0 } else { matched as f32 / probed as f32 };
                    if overlap >= cfg.min_reported_overlap {
                        references.push(ReferenceInfo {
                            from_object: from.clone(),
                            from_path: cand.path.clone(),
                            to_object: target.name.clone(),
                            to_path: "_id".into(),
                            value_type: cand.value_type.clone(),
                            probed,
                            matched,
                            overlap,
                            many_valued: cand.many_valued,
                            local_distinct_ratio: cand.distinct_ratio,
                            name_match,
                        });
                    }
                }
            }
        }
        // Best target first per (object, path).
        references.sort_by(|a, b| {
            (a.from_object.as_str(), a.from_path.as_str())
                .cmp(&(b.from_object.as_str(), b.from_path.as_str()))
                .then(b.name_match.cmp(&a.name_match))
                .then(b.overlap.total_cmp(&a.overlap))
        });
        Ok(SchemaSnapshot { datasource: self.cfg.datasource_id.clone().unwrap_or_default(), objects, references })
    }

    /// Containment probe: how many of the candidate's distinct values exist as `_id` in `target`.
    async fn probe(&self, cand: &RefCandidate, target: &str) -> Result<(u64, u64), ConnectError> {
        let values: Vec<Bson> = cand
            .values
            .iter()
            .map(|v| match v {
                Bson::String(s) if s.len() == 24 => {
                    bson::oid::ObjectId::parse_str(s).map(Bson::ObjectId).unwrap_or_else(|_| v.clone())
                }
                other => other.clone(),
            })
            .collect();
        if values.is_empty() {
            return Ok((0, 0));
        }
        let probed = values.len() as u64;
        let c: Collection<Document> = self.db.collection(target);
        let matched = c
            .count_documents(doc! { "_id": { "$in": values } })
            .max_time(self.max_time())
            .comment(Bson::String("caliban:introspect".into()))
            .selection_criteria(self.selection_criteria())
            .await
            .map_err(src)?;
        Ok((matched.min(probed), probed))
    }

    /// Native-lane executor: lint again, enforce options, run, cap rows.
    pub async fn execute(&self, q: &MongoQuery, row_cap: usize) -> Result<NativeResult, ConnectError> {
        if let Some(ds) = &self.cfg.datasource_id
            && *ds != q.datasource
        {
            return Err(ConnectError::Rejected(format!(
                "query targets datasource '{}', connector is '{ds}'",
                q.datasource
            )));
        }
        lint(&q.pipeline).map_err(|e| ConnectError::Rejected(e.to_string()))?;
        let mut pipeline = pipeline_to_bson(&q.pipeline)?;
        pipeline.push(doc! { "$limit": (row_cap as i64).saturating_add(1) });
        let cap_ms = self.cfg.max_time_ms.unwrap_or(15_000);
        let max_ms = q.options.get("maxTimeMS").and_then(J::as_u64).unwrap_or(cap_ms).min(cap_ms);
        let comment = q.options.get("comment").and_then(J::as_str).unwrap_or("caliban:unset").to_owned();
        let selection = self.query_selection(q.options.get("readPreference"))?;
        let c: Collection<Document> = self.db.collection(&q.collection);
        let mut cursor = c
            .aggregate(pipeline)
            .allow_disk_use(false)
            .max_time(Duration::from_millis(max_ms))
            .comment(Bson::String(comment))
            .selection_criteria(selection)
            .await
            .map_err(src)?;
        let mut rows = Vec::new();
        let mut truncated = false;
        while let Some(d) = cursor.try_next().await.map_err(src)? {
            if rows.len() == row_cap {
                truncated = true;
                break;
            }
            rows.push(doc_to_json(&d));
        }
        Ok(NativeResult { rows, truncated })
    }

    /// Raw `explain` (`queryPlanner` verbosity; the pipeline is planned, not executed).
    pub async fn explain(&self, q: &MongoQuery) -> Result<J, ConnectError> {
        lint(&q.pipeline).map_err(|e| ConnectError::Rejected(e.to_string()))?;
        let pipeline: Vec<Bson> = pipeline_to_bson(&q.pipeline)?.into_iter().map(Bson::Document).collect();
        let comment = q.options.get("comment").and_then(J::as_str).unwrap_or("caliban:unset").to_owned();
        let cmd = doc! {
            "explain": { "aggregate": &q.collection, "pipeline": pipeline, "cursor": {}, "allowDiskUse": false },
            "verbosity": "queryPlanner",
            "comment": comment,
        };
        let selection = self.query_selection(q.options.get("readPreference"))?;
        let reply = self.db.run_command(cmd).selection_criteria(selection).await.map_err(src)?;
        Ok(doc_to_json(&reply))
    }

    /// Dry run: explain + gate (COLLSCAN over large collections, unindexed `$lookup`). The report
    /// carries the plan summary so the planner can route to the replica.
    pub async fn explain_gate(&self, q: &MongoQuery, policy: &GatePolicy) -> Result<GateReport, ConnectError> {
        let reply = self.explain(q).await?;
        let c: Collection<Document> = self.db.collection(&q.collection);
        let est = c.estimated_document_count().await.ok();
        Ok(crate::explain::gate(crate::explain::summarize(&reply), est, policy))
    }

    /// Cluster `operationTime` (or `$clusterTime`) as `(seconds << 32) | increment`.
    pub async fn cluster_time(&self) -> Result<Timestamp, ConnectError> {
        let reply = self.db.run_command(doc! { "ping": 1 }).await.map_err(src)?;
        if let Ok(t) = reply.get_timestamp("operationTime") {
            return Ok(t);
        }
        if let Ok(t) = reply.get_document("$clusterTime").and_then(|c| c.get_timestamp("clusterTime")) {
            return Ok(t);
        }
        let hello = self.db.run_command(doc! { "hello": 1 }).await.map_err(src)?;
        hello
            .get_document("lastWrite")
            .and_then(|w| w.get_document("opTime"))
            .and_then(|o| o.get_timestamp("ts"))
            .map_err(|_| {
                ConnectError::Source("no cluster time (standalone mongod?); change streams need a replica set".into())
            })
    }

    pub fn bson_to_json(b: &Bson) -> J {
        bson_to_json(b)
    }
}

#[async_trait]
impl Connector for MongoConnector {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            filter_pushdown: true,
            aggregate_pushdown: true,
            join_pushdown: true,
            change_feed: self.topology.change_streams(),
            per_user_impersonation: false,
        }
    }

    async fn introspect(&self) -> Result<SchemaSnapshot, ConnectError> {
        self.introspect_with(&SampleConfig::default()).await
    }

    async fn profile(&self, object: &str, sample: u32) -> Result<Vec<Profile>, ConnectError> {
        let cfg = SampleConfig { sample_size: sample.max(1), newest: 0, oldest: 0, ..Default::default() };
        let docs = self.sample(object, &cfg).await?;
        let c: Collection<Document> = self.db.collection(object);
        let est = c.estimated_document_count().await.ok();
        Ok(infer::infer(&docs, est, &cfg.infer).profiles(object))
    }

    async fn epoch(&self) -> Result<u64, ConnectError> {
        Ok(ts_to_u64(self.cluster_time().await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_to_bson_honours_only_date() {
        let b = json_to_bson(
            &json!({ "createdAt": { "$gte": { "$date": "2026-07-01T00:00:00Z" } }, "qty": { "$gt": 5.0 }, "n": 3 }),
        )
        .unwrap();
        let d = b.as_document().unwrap();
        let gte = d.get_document("createdAt").unwrap().get("$gte").unwrap();
        assert_eq!(gte, &Bson::DateTime(bson::DateTime::parse_rfc3339_str("2026-07-01T00:00:00Z").unwrap()));
        assert_eq!(d.get_document("qty").unwrap().get("$gt"), Some(&Bson::Double(5.0)));
        assert_eq!(d.get("n"), Some(&Bson::Int32(3)));
        assert!(json_to_bson(&json!({ "$code": "while(1){}" })).is_err());
        assert!(json_to_bson(&json!({ "x": { "$oid": "65a1f0c2e4b0a1b2c3d4e5f6" } })).is_err());
        assert!(json_to_bson(&json!({ "$date": "yesterday" })).is_err());
    }

    #[test]
    fn read_preferences_and_tags() {
        let rp =
            read_preference("secondary", vec![ReadTag::Pair("workload:analytics".into()).tag_set().unwrap()], None)
                .unwrap();
        match rp {
            ReadPreference::Secondary { options: Some(o) } => {
                assert_eq!(o.tag_sets.unwrap()[0].get("workload").map(String::as_str), Some("analytics"))
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            read_preference("secondary_preferred", vec![], None).unwrap(),
            ReadPreference::SecondaryPreferred { options: None }
        ));
        assert!(read_preference("primary", vec![HashMap::from([("a".into(), "b".into())])], None).is_err());
        assert!(read_preference("bogus", vec![], None).is_err());
        let cfg: MongoConfig = serde_json::from_value(json!({ "uri": "mongodb://h", "database": "d", "read_preference": "secondaryPreferred", "read_tag": { "workload": "analytics" } })).unwrap();
        assert_eq!(cfg.read_tag, Some(ReadTag::Map(BTreeMap::from([("workload".into(), "analytics".into())]))));
    }

    #[test]
    fn timestamp_packing_is_ordered() {
        let a = ts_to_u64(Timestamp { time: 10, increment: 5 });
        let b = ts_to_u64(Timestamp { time: 11, increment: 1 });
        assert!(a < b);
        assert_eq!(u64_to_ts(a), Timestamp { time: 10, increment: 5 });
    }
}
