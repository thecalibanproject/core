//! The document registry: collections, document versions and their indexing state, in Postgres
//! next to the node journal ([`crate::pg::PgRagStore`], migration 0029) or in memory
//! ([`MemoryRagStore`], standalone without a database, and tests). Both behave the same (the
//! parity suite in `tests/store.rs`).
//!
//! The control plane writes (collections, ingest, delete, release), each with its audit event in
//! the same transaction (the `node_audit` outbox the control plane drains into its hash chain).
//! Workers claim pending documents (`FOR UPDATE SKIP LOCKED`, under a lease), record the outcome
//! of indexing, answer visibility checks for retrieval, and purge what was deleted. Document
//! content is sealed under the tenant's data key before it reaches the store; once a version no
//! longer needs it (superseded, deleted, failed), the sealed content is wiped.
//!
//! **Visibility is fail closed.** Only a version in `ready` is ever served: `pending` and
//! `indexing` versions are invisible until indexing completes and the ingest checks pass, a
//! `quarantined` one until an administrator releases it and it is indexed again. A new version
//! replaces the old one only when it becomes ready, in one transaction.

use caliban_nodes::journal::AuditEvent;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RagStoreError {
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Invalid(String),
    #[error("document store error: {0}")]
    Backend(String),
}

pub type SResult<T> = Result<T, RagStoreError>;

/// How far a document's source is trusted (note 06, "Corpus poisoning": provenance tiers).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Curated by the tenant: findings of the ingest checks are recorded; only hidden characters
    /// quarantine the document.
    Trusted,
    /// Anything else (the default): any instruction, exfiltration or hidden-character finding, or
    /// a near-duplicate of another document, quarantines it; and its checks must pass within the
    /// collection's vetting deadline.
    #[default]
    Untrusted,
}

impl Trust {
    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Trusted => "trusted",
            Trust::Untrusted => "untrusted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "trusted" => Some(Trust::Trusted),
            "untrusted" => Some(Trust::Untrusted),
            _ => None,
        }
    }
}

pub const DEFAULT_NAV_MIN_CHUNKS: u32 = 24;
pub const DEFAULT_VET_DEADLINE_SECS: u64 = 900;

fn d_chunk() -> u32 {
    crate::chunk::DEFAULT_MAX_TOKENS
}
fn d_nav() -> u32 {
    DEFAULT_NAV_MIN_CHUNKS
}
fn d_deadline() -> u64 {
    DEFAULT_VET_DEADLINE_SECS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionSettings {
    /// Largest chunk, in estimated tokens (64 to 2048).
    #[serde(default = "d_chunk")]
    pub chunk_tokens: u32,
    /// Trust of documents ingested without one.
    #[serde(default)]
    pub default_trust: Trust,
    /// Documents with at least this many chunks get a navigation tree ([`crate::navtree`]).
    #[serde(default = "d_nav")]
    pub nav_min_chunks: u32,
    /// An untrusted document whose checks have not passed this long after ingest fails (and stays
    /// invisible) instead of waiting for a backlog to clear.
    #[serde(default = "d_deadline")]
    pub vet_deadline_secs: u64,
}

impl Default for CollectionSettings {
    fn default() -> Self {
        Self {
            chunk_tokens: d_chunk(),
            default_trust: Trust::default(),
            nav_min_chunks: d_nav(),
            vet_deadline_secs: d_deadline(),
        }
    }
}

impl CollectionSettings {
    pub fn validate(&self) -> Result<(), String> {
        if !(crate::chunk::MIN_MAX_TOKENS..=crate::chunk::MAX_MAX_TOKENS).contains(&self.chunk_tokens) {
            return Err(format!(
                "chunk_tokens must be between {} and {}",
                crate::chunk::MIN_MAX_TOKENS,
                crate::chunk::MAX_MAX_TOKENS
            ));
        }
        if self.nav_min_chunks < 4 {
            return Err("nav_min_chunks must be at least 4".into());
        }
        if !(60..=7 * 86_400).contains(&self.vet_deadline_secs) {
            return Err("vet_deadline_secs must be between 60 and 604800".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CollectionRecord {
    pub id: String,
    pub tenant_id: String,
    /// What nodes name in their scopes (`rag.<name>:read`): `[a-z0-9_]`, 1 to 64 characters.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// A catalogue embedding model the tenant may use. Fixed for the collection's life: vectors of
    /// two models are not comparable.
    pub embedding_model: String,
    /// A catalogue rerank model; without one, results are ranked by fusion alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rerank_model: Option<String>,
    pub settings: CollectionSettings,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,
    /// When a worker dropped its vectors (deleted collections only).
    #[serde(skip)]
    pub purged_at: Option<DateTime<Utc>>,
}

impl CollectionRecord {
    pub fn is_live(&self) -> bool {
        self.deleted_at.is_none()
    }

    /// The Qdrant collection holding its vectors.
    pub fn index_name(&self, prefix: &str) -> String {
        format!("{prefix}_{}", self.id)
    }
}

/// Collection names: what node scopes and API key scopes name.
pub fn valid_collection_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
}

/// Document ids: 1 to 200 visible ASCII characters without `/`. They are stored in clear in the
/// registry (never in the vector index), so they should not carry personal data.
pub fn valid_doc_id(id: &str) -> bool {
    (1..=200).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_graphic() && b != b'/')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocStatus {
    /// Ingested, waiting for a worker. Invisible.
    Pending,
    /// A worker is indexing it. Invisible.
    Indexing,
    /// Indexed and its checks passed: the only state retrieval serves.
    Ready,
    /// A check flagged it: invisible until an administrator releases it.
    Quarantined,
    /// Indexing failed for good (or an untrusted document missed its vetting deadline). Invisible.
    Failed,
    /// A newer version became ready.
    Superseded,
    Deleted,
}

impl DocStatus {
    pub const ALL: [DocStatus; 7] = [
        DocStatus::Pending,
        DocStatus::Indexing,
        DocStatus::Ready,
        DocStatus::Quarantined,
        DocStatus::Failed,
        DocStatus::Superseded,
        DocStatus::Deleted,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            DocStatus::Pending => "pending",
            DocStatus::Indexing => "indexing",
            DocStatus::Ready => "ready",
            DocStatus::Quarantined => "quarantined",
            DocStatus::Failed => "failed",
            DocStatus::Superseded => "superseded",
            DocStatus::Deleted => "deleted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.as_str() == s)
    }

    /// Its vectors are no longer needed.
    pub fn is_purgeable(self) -> bool {
        matches!(self, DocStatus::Superseded | DocStatus::Deleted | DocStatus::Failed)
    }
}

/// What an ingest check found. No excerpt: document text stays sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocFinding {
    /// `instruction`, `exfiltration`, `hidden_unicode`, `url` (from the injection scan of tool
    /// manifests) or `near_duplicate` (a chunk almost identical to a chunk of another document).
    pub kind: String,
    /// The chunk (0-based) it was found in.
    pub chunk: u32,
    /// The headings above that chunk (document order), so a reviewer can find the place in the
    /// source. Pseudonymised like the indexed text, each at most 80 characters, hidden characters
    /// removed; never the text that triggered the finding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heading_path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DocumentRecord {
    pub tenant_id: String,
    pub collection_id: String,
    pub doc_id: String,
    pub version: u32,
    /// Keyed hash of the document id: how the vector index names the document.
    #[serde(skip)]
    pub doc_key: String,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub trust: Trust,
    /// Keyed hash of the content: ingesting the same content again is a no-op.
    #[serde(skip)]
    pub content_hash: String,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<DateTime<Utc>>,
    pub status: DocStatus,
    pub chunks: u32,
    pub tokens: u64,
    /// Personal-data entities the PII engine found (and pseudonymised before embedding).
    pub pii_entities: u64,
    pub findings: Vec<DocFinding>,
    pub findings_acknowledged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub attempts: u32,
    #[serde(skip)]
    pub retry_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub lease_owner: Option<String>,
    #[serde(skip)]
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub released_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub released_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub points_purged: bool,
}

impl DocumentRecord {
    pub fn key(&self) -> DocRef {
        DocRef {
            tenant_id: self.tenant_id.clone(),
            collection_id: self.collection_id.clone(),
            doc_id: self.doc_id.clone(),
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DocRef {
    pub tenant_id: String,
    pub collection_id: String,
    pub doc_id: String,
    pub version: u32,
}

/// A document to ingest (content already sealed).
#[derive(Debug, Clone)]
pub struct NewDocument {
    pub tenant_id: String,
    pub collection_id: String,
    pub doc_id: String,
    pub doc_key: String,
    pub content_type: String,
    pub source: Option<String>,
    pub trust: Trust,
    pub sealed_content: String,
    pub content_hash: String,
    pub bytes: u64,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
    pub created_by: String,
}

/// What indexing came to.
#[derive(Debug, Clone, PartialEq)]
pub enum IndexOutcome {
    /// Indexed, checks passed, its points are ready: the version becomes visible (or superseded,
    /// if a newer version became ready first).
    Ready { chunks: u32, tokens: u64, pii_entities: u64, findings: Vec<DocFinding> },
    /// Indexed but a check flagged it: invisible until released.
    Quarantined { chunks: u32, tokens: u64, pii_entities: u64, findings: Vec<DocFinding> },
    /// Failed for good.
    Failed { error: String },
    /// Failed for now (the embedder or the index is down): pending again after `after`.
    Retry { error: String, after: Duration },
}

/// A page of documents: the newest version of each document id, by id.
#[derive(Debug, Clone, Default)]
pub struct DocQuery {
    pub status: Option<DocStatus>,
    /// Ids after this one (the cursor).
    pub after: Option<String>,
    pub limit: usize,
}

/// One row of a listing: the newest version of a document, and the version being served.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DocumentSummary {
    #[serde(flatten)]
    pub latest: DocumentRecord,
    /// The version retrieval serves now (`None`: no version is ready).
    pub live_version: Option<u32>,
}

#[async_trait::async_trait]
pub trait RagStore: Send + Sync {
    fn name(&self) -> &'static str;

    // Collections (control plane).
    async fn create_collection(&self, c: CollectionRecord, audit: Option<AuditEvent>) -> SResult<CollectionRecord>;
    /// Live collections of a tenant, by name.
    async fn collections(&self, tenant: &str) -> SResult<Vec<CollectionRecord>>;
    async fn collection(&self, tenant: &str, name: &str) -> SResult<Option<CollectionRecord>>;
    /// Soft-deletes it and deletes its documents (content wiped); a worker drops its vectors.
    async fn delete_collection(
        &self,
        tenant: &str,
        name: &str,
        at: DateTime<Utc>,
        audit: Option<AuditEvent>,
    ) -> SResult<bool>;
    /// Every collection of a deleted tenant.
    async fn delete_tenant(&self, tenant: &str, at: DateTime<Utc>) -> SResult<u64>;

    // Documents (control plane).
    /// A new version (`version` = the highest so far + 1), pending. If the newest version that is
    /// not deleted or failed has the same content and settings, nothing is written and it is
    /// returned with `false`.
    async fn put_document(&self, d: NewDocument, audit: Option<AuditEvent>) -> SResult<(DocumentRecord, bool)>;
    async fn documents(&self, tenant: &str, collection_id: &str, q: &DocQuery) -> SResult<Vec<DocumentSummary>>;
    /// Documents per collection and status, counting each document's newest version (as the
    /// listing shows it; deleted documents are not counted): collection id to status to count.
    async fn document_counts(&self, tenant: &str) -> SResult<BTreeMap<String, BTreeMap<String, u64>>>;
    /// Every version of a document, newest first (deleted ones included).
    async fn document(&self, tenant: &str, collection_id: &str, doc_id: &str) -> SResult<Vec<DocumentRecord>>;
    /// Deletes every version (content wiped). `false`: no such document.
    async fn delete_document(
        &self,
        tenant: &str,
        collection_id: &str,
        doc_id: &str,
        at: DateTime<Utc>,
        audit: Option<AuditEvent>,
    ) -> SResult<bool>;
    /// A quarantined version goes back to `pending` with its findings acknowledged.
    async fn release(
        &self,
        d: &DocRef,
        by: &str,
        at: DateTime<Utc>,
        audit: Option<AuditEvent>,
    ) -> SResult<DocumentRecord>;

    // Workers.
    /// The oldest claimable document (pending and due, or indexing with an expired lease), with its
    /// sealed content.
    async fn claim(&self, worker: &str, lease: Duration) -> SResult<Option<(DocumentRecord, String)>>;
    async fn heartbeat(&self, d: &DocRef, worker: &str, lease: Duration) -> SResult<bool>;
    /// Records the outcome, only while `worker` holds the lease. `false`: it did not (the lease was
    /// lost, or the document was deleted meanwhile).
    async fn finish(&self, d: &DocRef, worker: &str, outcome: IndexOutcome) -> SResult<bool>;
    /// Which `(doc_key, version)` pairs are ready in a collection of the tenant.
    async fn visible(
        &self,
        tenant: &str,
        collection_id: &str,
        refs: &[(String, u32)],
    ) -> SResult<HashSet<(String, u32)>>;
    /// Versions whose vectors can go, in a live collection (deleted collections are dropped whole).
    async fn purge_queue(&self, limit: usize) -> SResult<Vec<DocumentRecord>>;
    async fn mark_purged(&self, d: &DocRef) -> SResult<()>;
    /// Deleted collections whose vectors are still there.
    async fn collections_to_drop(&self, limit: usize) -> SResult<Vec<CollectionRecord>>;
    async fn mark_dropped(&self, tenant: &str, id: &str, at: DateTime<Utc>) -> SResult<()>;

    // The audit outbox (the control plane drains it into its hash chain).
    async fn claim_audit(&self, owner: &str, hold: Duration, limit: usize) -> SResult<Vec<AuditEvent>>;
    async fn ack_audit(&self, ids: &[String]) -> SResult<()>;
}

// ───────────────────────────── memory ─────────────────────────────

#[derive(Default)]
struct Inner {
    collections: Vec<CollectionRecord>,
    docs: Vec<(DocumentRecord, Option<String>)>,
    audit: Vec<(AuditEvent, Option<std::time::Instant>)>,
}

/// In memory: lost on restart. For a standalone process without a database, and tests.
#[derive(Default)]
pub struct MemoryRagStore {
    inner: Mutex<Inner>,
}

impl MemoryRagStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn wipe(status: DocStatus) -> bool {
    status.is_purgeable()
}

#[async_trait::async_trait]
impl RagStore for MemoryRagStore {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn create_collection(&self, c: CollectionRecord, audit: Option<AuditEvent>) -> SResult<CollectionRecord> {
        let mut g = self.inner.lock();
        if g.collections.iter().any(|x| x.tenant_id == c.tenant_id && x.name == c.name && x.is_live()) {
            return Err(RagStoreError::Conflict(format!("a collection named '{}' exists", c.name)));
        }
        g.collections.push(c.clone());
        g.audit.extend(audit.map(|a| (a, None)));
        Ok(c)
    }

    async fn collections(&self, tenant: &str) -> SResult<Vec<CollectionRecord>> {
        let g = self.inner.lock();
        let mut v: Vec<_> = g.collections.iter().filter(|c| c.tenant_id == tenant && c.is_live()).cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(v)
    }

    async fn collection(&self, tenant: &str, name: &str) -> SResult<Option<CollectionRecord>> {
        Ok(self
            .inner
            .lock()
            .collections
            .iter()
            .find(|c| c.tenant_id == tenant && c.name == name && c.is_live())
            .cloned())
    }

    async fn delete_collection(
        &self,
        tenant: &str,
        name: &str,
        at: DateTime<Utc>,
        audit: Option<AuditEvent>,
    ) -> SResult<bool> {
        let mut g = self.inner.lock();
        let Some(c) = g.collections.iter_mut().find(|c| c.tenant_id == tenant && c.name == name && c.is_live()) else {
            return Ok(false);
        };
        c.deleted_at = Some(at);
        let id = c.id.clone();
        for (d, content) in g.docs.iter_mut().filter(|(d, _)| d.tenant_id == tenant && d.collection_id == id) {
            if d.status != DocStatus::Deleted {
                d.status = DocStatus::Deleted;
                d.lease_owner = None;
                d.lease_expires_at = None;
            }
            *content = None;
        }
        g.audit.extend(audit.map(|a| (a, None)));
        Ok(true)
    }

    async fn delete_tenant(&self, tenant: &str, at: DateTime<Utc>) -> SResult<u64> {
        let names: Vec<String> = self.collections(tenant).await?.into_iter().map(|c| c.name).collect();
        let mut n = 0;
        for name in names {
            if self.delete_collection(tenant, &name, at, None).await? {
                n += 1;
            }
        }
        Ok(n)
    }

    async fn put_document(&self, d: NewDocument, audit: Option<AuditEvent>) -> SResult<(DocumentRecord, bool)> {
        let mut g = self.inner.lock();
        if !g.collections.iter().any(|c| c.tenant_id == d.tenant_id && c.id == d.collection_id && c.is_live()) {
            return Err(RagStoreError::NotFound("collection".into()));
        }
        let versions = g
            .docs
            .iter()
            .filter(|(x, _)| x.tenant_id == d.tenant_id && x.collection_id == d.collection_id && x.doc_id == d.doc_id);
        let newest_live = versions
            .clone()
            .filter(|(x, _)| !matches!(x.status, DocStatus::Deleted | DocStatus::Failed))
            .max_by_key(|(x, _)| x.version);
        if let Some((x, _)) = newest_live
            && same_input(x, &d)
        {
            return Ok((x.clone(), false));
        }
        let version = versions.map(|(x, _)| x.version).max().unwrap_or(0) + 1;
        let rec = new_record(&d, version, Utc::now());
        g.docs.push((rec.clone(), Some(d.sealed_content)));
        g.audit.extend(audit.map(|a| (a, None)));
        Ok((rec, true))
    }

    async fn document_counts(&self, tenant: &str) -> SResult<BTreeMap<String, BTreeMap<String, u64>>> {
        let g = self.inner.lock();
        let mut newest: BTreeMap<(&str, &str), &DocumentRecord> = BTreeMap::new();
        for (d, _) in g.docs.iter().filter(|(d, _)| d.tenant_id == tenant) {
            let e = newest.entry((d.collection_id.as_str(), d.doc_id.as_str())).or_insert(d);
            if d.version > e.version {
                *e = d;
            }
        }
        let mut out: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for ((c, _), d) in newest.into_iter().filter(|(_, d)| d.status != DocStatus::Deleted) {
            *out.entry(c.to_owned()).or_default().entry(d.status.as_str().to_owned()).or_default() += 1;
        }
        Ok(out)
    }

    async fn documents(&self, tenant: &str, collection_id: &str, q: &DocQuery) -> SResult<Vec<DocumentSummary>> {
        let g = self.inner.lock();
        let mut ids: Vec<&String> = g
            .docs
            .iter()
            .filter(|(d, _)| d.tenant_id == tenant && d.collection_id == collection_id)
            .map(|(d, _)| &d.doc_id)
            .collect();
        ids.sort();
        ids.dedup();
        let mut out = Vec::new();
        for id in ids {
            if q.after.as_ref().is_some_and(|a| id <= a) {
                continue;
            }
            let versions: Vec<&DocumentRecord> = g
                .docs
                .iter()
                .map(|(d, _)| d)
                .filter(|d| d.tenant_id == tenant && d.collection_id == collection_id && &d.doc_id == id)
                .collect();
            let Some(latest) = versions.iter().max_by_key(|d| d.version) else { continue };
            if latest.status == DocStatus::Deleted || q.status.is_some_and(|s| s != latest.status) {
                continue;
            }
            let live_version = versions.iter().find(|d| d.status == DocStatus::Ready).map(|d| d.version);
            out.push(DocumentSummary { latest: (*latest).clone(), live_version });
            if out.len() >= q.limit {
                break;
            }
        }
        Ok(out)
    }

    async fn document(&self, tenant: &str, collection_id: &str, doc_id: &str) -> SResult<Vec<DocumentRecord>> {
        let g = self.inner.lock();
        let mut v: Vec<DocumentRecord> = g
            .docs
            .iter()
            .map(|(d, _)| d)
            .filter(|d| d.tenant_id == tenant && d.collection_id == collection_id && d.doc_id == doc_id)
            .cloned()
            .collect();
        v.sort_by_key(|d| std::cmp::Reverse(d.version));
        Ok(v)
    }

    async fn delete_document(
        &self,
        tenant: &str,
        collection_id: &str,
        doc_id: &str,
        _at: DateTime<Utc>,
        audit: Option<AuditEvent>,
    ) -> SResult<bool> {
        let mut g = self.inner.lock();
        let mut found = false;
        for (d, content) in g
            .docs
            .iter_mut()
            .filter(|(d, _)| d.tenant_id == tenant && d.collection_id == collection_id && d.doc_id == doc_id)
        {
            if d.status != DocStatus::Deleted {
                found = true;
                d.status = DocStatus::Deleted;
                d.lease_owner = None;
                d.lease_expires_at = None;
                d.points_purged = false;
            }
            *content = None;
        }
        if found {
            g.audit.extend(audit.map(|a| (a, None)));
        }
        Ok(found)
    }

    async fn release(
        &self,
        r: &DocRef,
        by: &str,
        at: DateTime<Utc>,
        audit: Option<AuditEvent>,
    ) -> SResult<DocumentRecord> {
        let mut g = self.inner.lock();
        let (d, _) = g
            .docs
            .iter_mut()
            .find(|(d, _)| d.key() == *r)
            .ok_or_else(|| RagStoreError::NotFound("document version".into()))?;
        if d.status != DocStatus::Quarantined {
            return Err(RagStoreError::Conflict(format!("the document is {}, not quarantined", d.status.as_str())));
        }
        d.status = DocStatus::Pending;
        d.findings_acknowledged = true;
        d.released_by = Some(by.to_owned());
        d.released_at = Some(at);
        d.retry_at = None;
        d.attempts = 0;
        let rec = d.clone();
        g.audit.extend(audit.map(|a| (a, None)));
        Ok(rec)
    }

    async fn claim(&self, worker: &str, lease: Duration) -> SResult<Option<(DocumentRecord, String)>> {
        let mut g = self.inner.lock();
        let now = Utc::now();
        let live: HashSet<String> = g.collections.iter().filter(|c| c.is_live()).map(|c| c.id.clone()).collect();
        let pick = g
            .docs
            .iter()
            .enumerate()
            .filter(|(_, (d, c))| {
                c.is_some()
                    && live.contains(&d.collection_id)
                    && ((d.status == DocStatus::Pending && d.retry_at.is_none_or(|r| r <= now))
                        || (d.status == DocStatus::Indexing && d.lease_expires_at.is_some_and(|l| l < now)))
            })
            .min_by_key(|(_, (d, _))| d.created_at)
            .map(|(i, _)| i);
        let Some(i) = pick else { return Ok(None) };
        let (d, content) = &mut g.docs[i];
        d.status = DocStatus::Indexing;
        d.lease_owner = Some(worker.to_owned());
        d.lease_expires_at = Some(now + lease);
        d.attempts += 1;
        Ok(Some((d.clone(), content.clone().unwrap_or_default())))
    }

    async fn heartbeat(&self, r: &DocRef, worker: &str, lease: Duration) -> SResult<bool> {
        let mut g = self.inner.lock();
        let now = Utc::now();
        Ok(match g.docs.iter_mut().find(|(d, _)| d.key() == *r) {
            Some((d, _)) if d.status == DocStatus::Indexing && d.lease_owner.as_deref() == Some(worker) => {
                d.lease_expires_at = Some(now + lease);
                true
            }
            _ => false,
        })
    }

    async fn finish(&self, r: &DocRef, worker: &str, outcome: IndexOutcome) -> SResult<bool> {
        let mut g = self.inner.lock();
        let now = Utc::now();
        let Some(i) = g.docs.iter().position(|(d, _)| d.key() == *r) else { return Ok(false) };
        {
            let d = &g.docs[i].0;
            if d.status != DocStatus::Indexing || d.lease_owner.as_deref() != Some(worker) {
                return Ok(false);
            }
        }
        let newer_ready = g.docs.iter().any(|(x, _)| {
            x.tenant_id == r.tenant_id
                && x.collection_id == r.collection_id
                && x.doc_id == r.doc_id
                && x.version > r.version
                && x.status == DocStatus::Ready
        });
        let ready = matches!(outcome, IndexOutcome::Ready { .. });
        {
            let (d, content) = &mut g.docs[i];
            d.lease_owner = None;
            d.lease_expires_at = None;
            match outcome {
                IndexOutcome::Ready { chunks, tokens, pii_entities, findings }
                | IndexOutcome::Quarantined { chunks, tokens, pii_entities, findings } => {
                    d.chunks = chunks;
                    d.tokens = tokens;
                    d.pii_entities = pii_entities;
                    d.findings = findings;
                    d.indexed_at = Some(now);
                    d.error = None;
                    d.status = if !ready {
                        DocStatus::Quarantined
                    } else if newer_ready {
                        DocStatus::Superseded
                    } else {
                        DocStatus::Ready
                    };
                }
                IndexOutcome::Failed { error } => {
                    d.status = DocStatus::Failed;
                    d.error = Some(error);
                }
                IndexOutcome::Retry { error, after } => {
                    d.status = DocStatus::Pending;
                    d.error = Some(error);
                    d.retry_at = Some(now + after);
                }
            }
            if wipe(d.status) {
                *content = None;
            }
        }
        if ready && !newer_ready {
            for (x, content) in g.docs.iter_mut() {
                if x.tenant_id == r.tenant_id
                    && x.collection_id == r.collection_id
                    && x.doc_id == r.doc_id
                    && x.version < r.version
                    && x.status == DocStatus::Ready
                {
                    x.status = DocStatus::Superseded;
                    *content = None;
                }
            }
        }
        Ok(true)
    }

    async fn visible(
        &self,
        tenant: &str,
        collection_id: &str,
        refs: &[(String, u32)],
    ) -> SResult<HashSet<(String, u32)>> {
        let g = self.inner.lock();
        Ok(g.docs
            .iter()
            .map(|(d, _)| d)
            .filter(|d| d.tenant_id == tenant && d.collection_id == collection_id && d.status == DocStatus::Ready)
            .map(|d| (d.doc_key.clone(), d.version))
            .filter(|k| refs.contains(k))
            .collect())
    }

    async fn purge_queue(&self, limit: usize) -> SResult<Vec<DocumentRecord>> {
        let g = self.inner.lock();
        let live: HashSet<&String> = g.collections.iter().filter(|c| c.is_live()).map(|c| &c.id).collect();
        Ok(g.docs
            .iter()
            .map(|(d, _)| d)
            .filter(|d| d.status.is_purgeable() && !d.points_purged && live.contains(&d.collection_id))
            .take(limit)
            .cloned()
            .collect())
    }

    async fn mark_purged(&self, r: &DocRef) -> SResult<()> {
        if let Some((d, _)) = self.inner.lock().docs.iter_mut().find(|(d, _)| d.key() == *r) {
            d.points_purged = true;
        }
        Ok(())
    }

    async fn collections_to_drop(&self, limit: usize) -> SResult<Vec<CollectionRecord>> {
        Ok(self
            .inner
            .lock()
            .collections
            .iter()
            .filter(|c| c.deleted_at.is_some() && c.purged_at.is_none())
            .take(limit)
            .cloned()
            .collect())
    }

    async fn mark_dropped(&self, tenant: &str, id: &str, at: DateTime<Utc>) -> SResult<()> {
        let mut g = self.inner.lock();
        if let Some(c) = g.collections.iter_mut().find(|c| c.tenant_id == tenant && c.id == id) {
            c.purged_at = Some(at);
        }
        for (d, _) in g.docs.iter_mut().filter(|(d, _)| d.tenant_id == tenant && d.collection_id == id) {
            d.points_purged = true;
        }
        Ok(())
    }

    async fn claim_audit(&self, _owner: &str, hold: Duration, limit: usize) -> SResult<Vec<AuditEvent>> {
        let mut g = self.inner.lock();
        let now = std::time::Instant::now();
        let mut out = Vec::new();
        for (e, until) in g.audit.iter_mut() {
            if out.len() >= limit {
                break;
            }
            if until.is_none_or(|u| u < now) {
                *until = Some(now + hold);
                out.push(e.clone());
            }
        }
        Ok(out)
    }

    async fn ack_audit(&self, ids: &[String]) -> SResult<()> {
        self.inner.lock().audit.retain(|(e, _)| !ids.contains(&e.id));
        Ok(())
    }
}

/// Re-ingesting the same content with the same settings is a no-op.
pub(crate) fn same_input(x: &DocumentRecord, d: &NewDocument) -> bool {
    x.content_hash == d.content_hash
        && x.content_type == d.content_type
        && x.source == d.source
        && x.trust == d.trust
        && x.valid_from == d.valid_from
        && x.valid_to == d.valid_to
}

pub(crate) fn new_record(d: &NewDocument, version: u32, now: DateTime<Utc>) -> DocumentRecord {
    DocumentRecord {
        tenant_id: d.tenant_id.clone(),
        collection_id: d.collection_id.clone(),
        doc_id: d.doc_id.clone(),
        version,
        doc_key: d.doc_key.clone(),
        content_type: d.content_type.clone(),
        source: d.source.clone(),
        trust: d.trust,
        content_hash: d.content_hash.clone(),
        bytes: d.bytes,
        valid_from: d.valid_from,
        valid_to: d.valid_to,
        status: DocStatus::Pending,
        chunks: 0,
        tokens: 0,
        pii_entities: 0,
        findings: Vec::new(),
        findings_acknowledged: false,
        error: None,
        attempts: 0,
        retry_at: None,
        lease_owner: None,
        lease_expires_at: None,
        created_at: now,
        created_by: d.created_by.clone(),
        indexed_at: None,
        released_by: None,
        released_at: None,
        points_purged: false,
    }
}
