//! CDC-fed analytical replica (the accelerated lane, research 08 "Recommendation: execution
//! architecture" and "CDC acceleration policy").
//!
//! ```text
//! approved Model ──▶ Projection (root tables + `<table>__<array>` child tables, bound paths only)
//! snapshot: operationTime T0, full scan of each collection (bound paths only)
//! change stream from T0 (db-level, filtered to the replicated collections, fullDocument:
//!   updateLookup, projected to bound paths) ─▶ upsert/delete in memory ─▶ flush ─▶ Parquet
//! query(sql) ─▶ DataFusion SessionContext over the Parquet files
//! watermark = last applied clusterTime (as `(seconds << 32) | increment`)
//! ```
//!
//! **v1 simplifications** (documented gaps, see README):
//! - Storage: the in-memory table state is authoritative; each flush rewrites the whole Parquet
//!   file of every dirty table (`<dir>/<table>.parquet`, temp file + atomic rename). Delta files +
//!   compaction (15 min / 128 MB) replace this when tables get large.
//! - Restart: a manifest (`manifest.json`: watermark, resume token, tables) is written on every
//!   flush, but a restarted replica re-snapshots instead of reloading Parquet and resuming.
//! - Snapshot: single full scan per collection sorted by `_id` (no parallel `_id` ranges); the
//!   change stream starts at the pre-scan operation time, so events during the scan are replayed
//!   idempotently (upserts carry the full current document).
//! - Embedded arrays nested in arrays and map attributes are not replicated.
//! - Idle watermark: when the stream is idle, the watermark advances to the cluster time encoded
//!   in the post-batch resume token (all earlier events are applied and flushed).

pub mod convert;
pub mod projection;

use caliban_connect::mongo::bson::{self, Bson, Document, Timestamp, doc};
use caliban_connect::mongo::mongodb::change_stream::event::{
    ChangeStreamEvent, OperationType, ResumeToken,
};
use caliban_connect::mongo::mongodb::options::FullDocumentType;
use caliban_connect::mongo::mongodb::{Collection, Database};
use caliban_connect::mongo::{MongoConnector, ts_to_u64};
use caliban_ontology::model::Model;
use convert::{Row, child_rows, key_string, matches_table, root_row, to_batch};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::TableReference;
use datafusion::execution::context::SQLOptions;
use datafusion::parquet::arrow::ArrowWriter;
use datafusion::parquet::basic::Compression;
use datafusion::parquet::file::properties::WriterProperties;
use datafusion::prelude::{ParquetReadOptions, SessionConfig, SessionContext};
use futures::TryStreamExt;
use parking_lot::Mutex;
use projection::{Projection, TableKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub use convert::batches_to_json;

#[derive(Debug, thiserror::Error)]
pub enum ReplicaError {
    #[error("projection: {0}")]
    Projection(String),
    #[error("source: {0}")]
    Source(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("query: {0}")]
    Query(String),
    #[error("replica is stale: {0}")]
    Stale(String),
}

fn source(e: impl std::fmt::Display) -> ReplicaError {
    ReplicaError::Source(e.to_string())
}

fn storage(e: impl std::fmt::Display) -> ReplicaError {
    ReplicaError::Storage(e.to_string())
}

#[derive(Debug, Clone)]
pub struct ReplicaConfig {
    /// Directory holding `<table>.parquet` files and `manifest.json`.
    pub dir: PathBuf,
    /// Flush dirty tables at least this often while events arrive.
    pub flush_interval: Duration,
    /// …or after this many applied events.
    pub max_batch_events: usize,
    /// Server-side wait per `getMore` on the change stream (bounds stop/flush latency).
    pub max_await: Duration,
}

impl ReplicaConfig {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            flush_interval: Duration::from_millis(500),
            max_batch_events: 1_000,
            max_await: Duration::from_millis(250),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ReplicaStatus {
    Empty,
    Snapshotting,
    /// Snapshot done; change stream not (yet) running.
    Snapshotted,
    Live,
    /// Oplog window lost, collection dropped/renamed, or stream error: route native, re-snapshot.
    Stale {
        reason: String,
    },
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SnapshotStats {
    pub documents: BTreeMap<String, u64>,
    pub rows: BTreeMap<String, u64>,
    pub start_time: u64,
}

/// One table's rows, keyed by root `_id` (root tables: one row) or by parent `_id` (child tables:
/// that parent's elements), so a parent update rewrites its child rows.
#[derive(Debug, Default)]
struct TableData {
    rows: BTreeMap<String, Vec<Row>>,
}

#[derive(Debug, Default)]
struct State {
    tables: BTreeMap<String, TableData>,
    dirty: BTreeSet<String>,
    /// Highest clusterTime applied (not necessarily flushed).
    last_applied: u64,
    resume_token: Option<ResumeToken>,
    events_applied: u64,
    pending_events: usize,
}

/// One immutable Parquet file generation of a table. A flush writes a new generation and retires
/// the previous one; a retired file is deleted when the last query holding it finishes, so
/// readers never observe a file being replaced underneath them.
#[derive(Debug)]
struct FileGen {
    path: PathBuf,
    retired: std::sync::atomic::AtomicBool,
}

impl Drop for FileGen {
    fn drop(&mut self) {
        if self.retired.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Keeps the file generations a query was planned against alive until it completes.
pub struct SnapshotGuard {
    _files: Vec<Arc<FileGen>>,
}

struct Inner {
    /// Current file generation per table.
    files: Mutex<std::collections::HashMap<String, Arc<FileGen>>>,
    generation: AtomicU64,
    projection: Projection,
    cfg: ReplicaConfig,
    state: Mutex<State>,
    /// Last clusterTime whose effects are persisted in Parquet.
    watermark: AtomicU64,
    status: Mutex<ReplicaStatus>,
}

/// The replica for one datasource. Cheap to clone (shared state).
#[derive(Clone)]
pub struct Replica {
    inner: Arc<Inner>,
}

/// Handle on the change-stream task.
pub struct CdcHandle {
    stop: Arc<AtomicBool>,
    join: tokio::task::JoinHandle<()>,
}

impl CdcHandle {
    /// Stops the stream after the current `getMore` and flushes.
    pub async fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.join.await;
    }

    pub fn is_finished(&self) -> bool {
        self.join.is_finished()
    }
}

/// Cluster time encoded in a change-stream resume token (`_data` hex KeyString: `0x82` tag,
/// then big-endian seconds and increment). `None` if the format is not recognized.
pub fn resume_token_time(token: &ResumeToken) -> Option<Timestamp> {
    let b = bson::to_bson(token).ok()?;
    let data = match &b {
        Bson::Document(d) => d.get_str("_data").ok()?.to_owned(),
        _ => return None,
    };
    if data.len() < 18 || !data.starts_with("82") {
        return None;
    }
    let time = u32::from_str_radix(data.get(2..10)?, 16).ok()?;
    let increment = u32::from_str_radix(data.get(10..18)?, 16).ok()?;
    Some(Timestamp { time, increment })
}

impl Replica {
    /// Creates an empty replica for the approved entities of `model` bound to `datasource`.
    pub fn new(
        model: &Model,
        datasource: Option<&str>,
        cfg: ReplicaConfig,
    ) -> Result<Self, ReplicaError> {
        let projection = Projection::from_model(model, datasource)?;
        if projection.tables.is_empty() {
            return Err(ReplicaError::Projection(
                "no approved root entities to replicate".into(),
            ));
        }
        std::fs::create_dir_all(&cfg.dir).map_err(storage)?;
        let mut state = State::default();
        for t in &projection.tables {
            state.tables.insert(t.name.clone(), TableData::default());
        }
        Ok(Self {
            inner: Arc::new(Inner {
                files: Mutex::new(std::collections::HashMap::new()),
                generation: AtomicU64::new(0),
                projection,
                cfg,
                state: Mutex::new(state),
                watermark: AtomicU64::new(0),
                status: Mutex::new(ReplicaStatus::Empty),
            }),
        })
    }

    pub fn projection(&self) -> &Projection {
        &self.inner.projection
    }

    /// Last clusterTime whose effects are visible to [`Replica::query`].
    pub fn watermark(&self) -> u64 {
        self.inner.watermark.load(Ordering::SeqCst)
    }

    /// Seconds the replica trails a source epoch (from `Connector::epoch`).
    pub fn lag_secs(&self, source_epoch: u64) -> u64 {
        (source_epoch >> 32).saturating_sub(self.watermark() >> 32)
    }

    pub fn status(&self) -> ReplicaStatus {
        self.inner.status.lock().clone()
    }

    pub fn events_applied(&self) -> u64 {
        self.inner.state.lock().events_applied
    }

    fn set_status(&self, s: ReplicaStatus) {
        *self.inner.status.lock() = s;
    }

    /// Path of the table's current Parquet generation (`<table>.<gen>.parquet`).
    pub fn table_path(&self, table: &str) -> PathBuf {
        self.inner
            .files
            .lock()
            .get(table)
            .map_or_else(|| self.inner.cfg.dir.join(format!("{table}.parquet")), |f| f.path.clone())
    }

    /// Initial snapshot: records the cluster time, scans every replicated collection (bound
    /// paths only), and flushes. The change stream later starts from that time.
    pub async fn snapshot(&self, conn: &MongoConnector) -> Result<SnapshotStats, ReplicaError> {
        self.set_status(ReplicaStatus::Snapshotting);
        let start = conn.cluster_time().await.map_err(source)?;
        let mut stats = SnapshotStats {
            start_time: ts_to_u64(start),
            ..Default::default()
        };
        {
            let mut st = self.inner.state.lock();
            for t in st.tables.values_mut() {
                t.rows.clear();
            }
        }
        for coll in self.inner.projection.collections() {
            let c: Collection<Document> = conn.database().collection(&coll);
            let mut cursor = c
                .find(doc! {})
                .projection(self.inner.projection.find_projection(&coll))
                .sort(doc! { "_id": 1 })
                .batch_size(1_000)
                .comment(Bson::String("caliban:replica-snapshot".into()))
                .selection_criteria(conn.selection_criteria())
                .await
                .map_err(source)?;
            let mut n = 0u64;
            while let Some(d) = cursor.try_next().await.map_err(source)? {
                self.inner
                    .state
                    .lock()
                    .upsert(&self.inner.projection, &coll, &d);
                n += 1;
            }
            stats.documents.insert(coll, n);
        }
        {
            let mut st = self.inner.state.lock();
            st.last_applied = st.last_applied.max(stats.start_time);
            st.resume_token = None;
            for (name, t) in &st.tables {
                stats
                    .rows
                    .insert(name.clone(), t.rows.values().map(|r| r.len() as u64).sum());
            }
            st.dirty = self
                .inner
                .projection
                .tables
                .iter()
                .map(|t| t.name.clone())
                .collect();
        }
        self.flush()?;
        self.set_status(ReplicaStatus::Snapshotted);
        Ok(stats)
    }

    /// Writes every dirty table to Parquet (whole-file rewrite, atomic rename), then advances the
    /// watermark to the last applied cluster time and writes the manifest.
    pub fn flush(&self) -> Result<(), ReplicaError> {
        let mut st = self.inner.state.lock();
        let dirty = std::mem::take(&mut st.dirty);
        for name in &dirty {
            let Some(spec) = self.inner.projection.table(name) else {
                continue;
            };
            let data = st
                .tables
                .get(name)
                .map(|t| t.rows.values().flatten().collect::<Vec<_>>())
                .unwrap_or_default();
            let batch = to_batch(spec, data.iter().copied()).map_err(storage)?;
            let generation = self.inner.generation.fetch_add(1, Ordering::SeqCst);
            let path = self.inner.cfg.dir.join(format!("{name}.{generation}.parquet"));
            write_parquet(&path, &batch)?;
            let new = Arc::new(FileGen { path, retired: std::sync::atomic::AtomicBool::new(false) });
            if let Some(old) = self.inner.files.lock().insert(name.clone(), new) {
                old.retired.store(true, Ordering::SeqCst);
            }
        }
        st.pending_events = 0;
        let applied = st.last_applied;
        let token = st.resume_token.clone();
        drop(st);
        self.inner.watermark.fetch_max(applied, Ordering::SeqCst);
        self.write_manifest(token.as_ref())
    }

    fn write_manifest(&self, token: Option<&ResumeToken>) -> Result<(), ReplicaError> {
        let manifest = serde_json::json!({
            "watermark": self.watermark(),
            "watermark_cluster_time": { "t": self.watermark() >> 32, "i": self.watermark() & 0xffff_ffff },
            "status": self.status(),
            "resume_token": token.and_then(|t| bson::to_bson(t).ok()).map(|b| b.into_relaxed_extjson()),
            "tables": self.inner.projection.tables.iter().map(|t| serde_json::json!({
                "name": t.name, "collection": t.collection, "file": self.table_path(&t.name).file_name().map(|f| f.to_string_lossy().into_owned()),
                "columns": t.columns.iter().map(|c| &c.name).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "storage": "v1: whole-table Parquet rewrite per flush, one immutable file generation per flush",
        });
        let path = self.inner.cfg.dir.join("manifest.json");
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&manifest).map_err(storage)?)
            .map_err(storage)?;
        std::fs::rename(&tmp, &path).map_err(storage)
    }

    /// Starts the change stream from the snapshot time (or the last resume token).
    pub async fn start_cdc(&self, conn: &MongoConnector) -> Result<CdcHandle, ReplicaError> {
        let colls: Vec<String> = self.inner.projection.collections().into_iter().collect();
        // Keep the event envelope (the driver needs `_id`, `operationType`, `ns`) and only the
        // bound paths of the full document.
        let mut project =
            doc! { "operationType": 1, "ns": 1, "documentKey": 1, "clusterTime": 1, "to": 1 };
        for c in &colls {
            for p in self.inner.projection.bound_paths(c) {
                project.insert(format!("fullDocument.{p}"), 1);
            }
        }
        let pipeline = vec![
            doc! { "$match": { "ns.coll": { "$in": &colls } } },
            doc! { "$project": project },
        ];
        let (token, start) = {
            let st = self.inner.state.lock();
            (st.resume_token.clone(), st.last_applied)
        };
        if start == 0 && token.is_none() {
            return Err(ReplicaError::Stale("snapshot first".into()));
        }
        let db: Database = conn.database().clone();
        let mut watch = db
            .watch()
            .pipeline(pipeline)
            .full_document(FullDocumentType::UpdateLookup)
            .max_await_time(self.inner.cfg.max_await)
            // No `comment`: driver 3.9 serializes it inside the `$changeStream` stage, which
            // MongoDB 8 rejects (IDLUnknownField).
            .selection_criteria(conn.selection_criteria());
        watch = match token {
            Some(t) => watch.resume_after(t),
            None => watch.start_at_operation_time(caliban_connect::mongo::u64_to_ts(start)),
        };
        let mut stream = watch.await.map_err(|e| {
            let msg = e.to_string();
            self.set_status(ReplicaStatus::Stale {
                reason: msg.clone(),
            });
            ReplicaError::Stale(msg)
        })?;
        self.set_status(ReplicaStatus::Live);

        let stop = Arc::new(AtomicBool::new(false));
        let me = self.clone();
        let stop2 = stop.clone();
        let join = tokio::spawn(async move {
            let mut last_flush = Instant::now();
            loop {
                if stop2.load(Ordering::SeqCst) {
                    let _ = me.flush();
                    break;
                }
                match stream.next_if_any().await {
                    Ok(Some(ev)) => {
                        let token = stream.resume_token();
                        if let Err(reason) = me.apply(ev, token) {
                            let _ = me.flush();
                            me.set_status(ReplicaStatus::Stale { reason });
                            break;
                        }
                    }
                    Ok(None) => {
                        // Idle: flush what is pending; then everything up to the post-batch
                        // resume token's cluster time is reflected in Parquet.
                        let pending = me.inner.state.lock().pending_events > 0;
                        if pending && me.flush().is_err() {
                            me.set_status(ReplicaStatus::Stale {
                                reason: "flush failed".into(),
                            });
                            break;
                        }
                        last_flush = Instant::now();
                        if let Some(t) = stream.resume_token()
                            && let Some(ts) = resume_token_time(&t)
                        {
                            let mut st = me.inner.state.lock();
                            st.last_applied = st.last_applied.max(ts_to_u64(ts));
                            st.resume_token = Some(t);
                            let applied = st.last_applied;
                            drop(st);
                            me.inner.watermark.fetch_max(applied, Ordering::SeqCst);
                        }
                    }
                    Err(e) => {
                        let _ = me.flush();
                        me.set_status(ReplicaStatus::Stale {
                            reason: format!("change stream: {e}"),
                        });
                        break;
                    }
                }
                let pending = me.inner.state.lock().pending_events;
                if pending >= me.inner.cfg.max_batch_events
                    || (pending > 0 && last_flush.elapsed() >= me.inner.cfg.flush_interval)
                {
                    if me.flush().is_err() {
                        me.set_status(ReplicaStatus::Stale {
                            reason: "flush failed".into(),
                        });
                        break;
                    }
                    last_flush = Instant::now();
                }
            }
        });
        Ok(CdcHandle { stop, join })
    }

    /// Applies one change event. `Err(reason)` means the replica must be re-snapshotted.
    fn apply(
        &self,
        ev: ChangeStreamEvent<Document>,
        token: Option<ResumeToken>,
    ) -> Result<(), String> {
        let coll = ev
            .ns
            .as_ref()
            .and_then(|n| n.coll.clone())
            .unwrap_or_default();
        let mut st = self.inner.state.lock();
        match ev.operation_type {
            OperationType::Insert | OperationType::Replace | OperationType::Update => {
                match ev.full_document {
                    Some(d) => st.upsert(&self.inner.projection, &coll, &d),
                    // updateLookup found nothing: the document was deleted after this update.
                    None => {
                        if let Some(id) = ev.document_key.as_ref().and_then(|k| k.get("_id")) {
                            st.delete(&self.inner.projection, &coll, id);
                        }
                    }
                }
            }
            OperationType::Delete => {
                if let Some(id) = ev.document_key.as_ref().and_then(|k| k.get("_id")) {
                    st.delete(&self.inner.projection, &coll, id);
                }
            }
            OperationType::Drop
            | OperationType::Rename
            | OperationType::DropDatabase
            | OperationType::Invalidate => {
                return Err(format!(
                    "{:?} on '{coll}': re-snapshot required",
                    ev.operation_type
                ));
            }
            _ => {}
        }
        if let Some(t) = ev.cluster_time {
            st.last_applied = st.last_applied.max(ts_to_u64(t));
        }
        if token.is_some() {
            st.resume_token = token;
        }
        st.events_applied += 1;
        st.pending_events += 1;
        Ok(())
    }

    /// Runs one read-only SQL `SELECT` over the replica's Parquet tables.
    pub async fn query(&self, sql: &str) -> Result<Vec<RecordBatch>, ReplicaError> {
        if let ReplicaStatus::Stale { reason } = self.status() {
            return Err(ReplicaError::Stale(reason));
        }
        let (ctx, _guard) = self.session().await?;
        let opts = SQLOptions::new()
            .with_allow_ddl(false)
            .with_allow_dml(false)
            .with_allow_statements(false);
        let df = ctx
            .sql_with_options(sql, opts)
            .await
            .map_err(|e| ReplicaError::Query(e.to_string()))?;
        df.collect()
            .await
            .map_err(|e| ReplicaError::Query(e.to_string()))
    }

    /// A fresh DataFusion session with every flushed table registered (files are replaced
    /// atomically on flush, so each query sees one consistent version per table).
    /// A DataFusion session over a consistent set of file generations. Keep the guard alive for as
    /// long as the session is used.
    pub async fn session(&self) -> Result<(SessionContext, SnapshotGuard), ReplicaError> {
        let ctx =
            SessionContext::new_with_config(SessionConfig::new().with_information_schema(false));
        let files: Vec<(String, Arc<FileGen>)> =
            self.inner.files.lock().iter().map(|(k, v)| (k.clone(), Arc::clone(v))).collect();
        for (name, f) in &files {
            ctx.register_parquet(
                TableReference::bare(name.as_str()),
                f.path.to_string_lossy().as_ref(),
                ParquetReadOptions::default(),
            )
            .await
            .map_err(|e| ReplicaError::Query(e.to_string()))?;
        }
        Ok((ctx, SnapshotGuard { _files: files.into_iter().map(|(_, f)| f).collect() }))
    }
}

impl State {
    fn upsert(&mut self, p: &Projection, coll: &str, d: &Document) {
        let Some(id) = d.get("_id").and_then(key_string) else {
            return;
        };
        for spec in p.tables_of(coll) {
            let Some(t) = self.tables.get_mut(&spec.name) else {
                continue;
            };
            match &spec.kind {
                TableKind::Root { .. } => {
                    if matches_table(spec, d) {
                        t.rows.insert(id.clone(), vec![root_row(spec, d)]);
                    } else {
                        t.rows.remove(&id);
                    }
                }
                TableKind::Child { .. } => {
                    // A parent update rewrites all its child rows.
                    let rows = child_rows(spec, &id, d);
                    if rows.is_empty() {
                        t.rows.remove(&id);
                    } else {
                        t.rows.insert(id.clone(), rows);
                    }
                }
            }
            self.dirty.insert(spec.name.clone());
        }
    }

    fn delete(&mut self, p: &Projection, coll: &str, id: &Bson) {
        let Some(id) = key_string(id) else { return };
        for spec in p.tables_of(coll) {
            if let Some(t) = self.tables.get_mut(&spec.name)
                && t.rows.remove(&id).is_some()
            {
                self.dirty.insert(spec.name.clone());
            }
        }
    }
}

fn write_parquet(path: &Path, batch: &RecordBatch) -> Result<(), ReplicaError> {
    let tmp = path.with_extension("parquet.tmp");
    let file = std::fs::File::create(&tmp).map_err(storage)?;
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .build();
    let mut w = ArrowWriter::try_new(file, batch.schema(), Some(props)).map_err(storage)?;
    if batch.num_rows() > 0 {
        w.write(batch).map_err(storage)?;
    }
    w.close().map_err(storage)?;
    std::fs::rename(&tmp, path).map_err(storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::tests::model;
    use caliban_connect::mongo::bson::{DateTime, oid::ObjectId};
    use serde_json::json;

    /// Loads documents into a replica without MongoDB and checks the SQL lane end to end,
    /// including the exact SQL `caliban_ontology::compile::sql::lower` emits for the reference
    /// question (quoted identifiers, `TIMESTAMP '…Z'` literals).
    #[tokio::test]
    async fn sql_lane_over_parquet() {
        let dir = tempfile::tempdir().unwrap();
        let r = Replica::new(&model(), Some("dw"), ReplicaConfig::new(dir.path())).unwrap();
        let eu = ObjectId::new();
        let us = ObjectId::new();
        let ts = |s: &str| DateTime::parse_rfc3339_str(s).unwrap();
        {
            let p = &r.inner.projection;
            let mut st = r.inner.state.lock();
            st.upsert(p, "customers", &doc! { "_id": eu, "region": "EU" });
            st.upsert(p, "customers", &doc! { "_id": us, "region": "US" });
            st.upsert(p, "orders", &doc! { "_id": 1, "status": "paid", "salesOrg": "EU-1", "customerId": eu, "createdAt": ts("2026-07-02T00:00:00Z"),
                "lines": [{ "category": "books", "qty": 2, "unitPrice": 10.0 }, { "category": "toys", "qty": 1, "unitPrice": 5.5 }] });
            st.upsert(p, "orders", &doc! { "_id": 2, "status": "shipped", "salesOrg": "EU-2", "customerId": eu, "createdAt": ts("2026-09-30T23:59:59Z"),
                "lines": [{ "category": "books", "qty": 1, "unitPrice": 7.0 }] });
            // Excluded: wrong region, out of range (half-open upper bound), wrong status.
            st.upsert(p, "orders", &doc! { "_id": 3, "status": "paid", "salesOrg": "EU-1", "customerId": us, "createdAt": ts("2026-07-03T00:00:00Z"),
                "lines": [{ "category": "books", "qty": 100, "unitPrice": 1.0 }] });
            st.upsert(p, "orders", &doc! { "_id": 4, "status": "paid", "salesOrg": "EU-1", "customerId": eu, "createdAt": ts("2026-10-01T00:00:00Z"),
                "lines": [{ "category": "books", "qty": 100, "unitPrice": 1.0 }] });
            st.upsert(p, "orders", &doc! { "_id": 5, "status": "pending", "salesOrg": "EU-1", "customerId": eu, "createdAt": ts("2026-07-03T00:00:00Z"),
                "lines": [{ "category": "books", "qty": 100, "unitPrice": 1.0 }] });
            st.last_applied = 42;
        }
        r.flush().unwrap();
        assert_eq!(r.watermark(), 42);
        assert!(r.table_path("orders__lines").exists() && dir.path().join("manifest.json").exists());
        // Retired generations are deleted once no query holds them: one file per table remains.
        let parquet = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| e.as_ref().unwrap().path().extension().is_some_and(|x| x == "parquet"))
            .count();
        assert_eq!(parquet, r.projection().tables.len());

        let sql = r#"SELECT t1."category" AS "category", SUM((t1."qty" * t1."unit_price")) AS "gross_revenue"
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
        let rows = batches_to_json(&r.query(sql).await.unwrap()).unwrap();
        assert_eq!(
            rows,
            vec![
                json!({ "category": "books", "gross_revenue": 27.0 }),
                json!({ "category": "toys", "gross_revenue": 5.5 })
            ]
        );

        // A parent update rewrites its child rows; a delete removes parent and children.
        {
            let p = &r.inner.projection;
            let mut st = r.inner.state.lock();
            st.upsert(p, "orders", &doc! { "_id": 1, "status": "paid", "salesOrg": "EU-1", "customerId": eu, "createdAt": ts("2026-07-02T00:00:00Z"),
                "lines": [{ "category": "toys", "qty": 2, "unitPrice": 1.0 }] });
            st.delete(p, "orders", &Bson::Int32(2));
            st.last_applied = 43;
        }
        r.flush().unwrap();
        let rows = batches_to_json(&r.query(sql).await.unwrap()).unwrap();
        assert_eq!(
            rows,
            vec![json!({ "category": "toys", "gross_revenue": 2.0 })]
        );
        let n = batches_to_json(
            &r.query(r#"SELECT COUNT(*) AS n FROM "orders__lines""#)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(n, vec![json!({ "n": 4 })]);
        assert_eq!(r.watermark(), 43);

        // Read-only: DDL/DML are refused.
        assert!(r.query(r#"DROP TABLE "orders""#).await.is_err());
        assert!(
            r.query(r#"INSERT INTO "orders" ("_id") VALUES ('x')"#)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn retired_generation_survives_while_a_query_holds_it() {
        let f = Arc::new(FileGen { path: std::env::temp_dir().join(format!("caliban-gen-{}.parquet", std::process::id())), retired: std::sync::atomic::AtomicBool::new(false) });
        std::fs::write(&f.path, b"x").unwrap();
        let reader = SnapshotGuard { _files: vec![Arc::clone(&f)] };
        let path = f.path.clone();
        f.retired.store(true, Ordering::SeqCst);
        drop(f);
        assert!(path.exists(), "still referenced by a running query");
        drop(reader);
        assert!(!path.exists(), "deleted after the last reader finished");
    }

    #[test]
    fn resume_token_cluster_time() {
        let token: ResumeToken = bson::from_bson(Bson::Document(
            doc! { "_data": "8266F1A2B3000000022B042C0100296E5A1004" },
        ))
        .unwrap();
        assert_eq!(
            resume_token_time(&token),
            Some(Timestamp {
                time: 0x66F1A2B3,
                increment: 2
            })
        );
        let bad: ResumeToken = bson::from_bson(Bson::Document(doc! { "_data": "zz" })).unwrap();
        assert_eq!(resume_token_time(&bad), None);
    }
}
