//! Indexing one claimed document version (the worker side of ingest).
//!
//! 1. Open the sealed content with the tenant's data key; parse it with its structure.
//! 2. Chunk it (structure-aligned, heading paths, no overlap).
//! 3. **Poisoning checks** (note 06, "Corpus poisoning"): every chunk goes through the injection
//!    scan Caliban runs on tool manifests (instructions to the model, hidden characters,
//!    exfiltration); an untrusted document is also compared with the ready chunks of other
//!    documents, and a near-identical chunk (cosine >= [`NEAR_DUPLICATE`]) is a finding, since
//!    PoisonedRAG-style attacks plant near-copies of target passages (arXiv 2402.07867).
//!    Trusted sources: findings are recorded, and only hidden characters quarantine. Untrusted
//!    sources: any finding other than a URL quarantines. Provenance tiers remain the main control
//!    because per-document checks miss sets of individually benign documents that jointly
//!    redirect answers (LENS, arXiv 2609.35155, preprint); taint labels on retrieved text are what
//!    makes an injection harmless to writes.
//! 4. Personal data: the indexed text is pseudonymised with the tenant's PII engine before it is
//!    embedded or turned into sparse terms (note 05 §5: never embed raw PII). The original text is
//!    only stored sealed.
//! 5. Embed through the gateway's embedding path, as the tenant (no API key), in batches.
//! 6. Write the points `pending`, with a navigation tree for long documents, then flip them to
//!    `ready`. The registry is told last; until then nothing of the version is visible.

use crate::chunk::{ChunkDraft, chunk};
use crate::index::{Filter, Point, PointKind, PointPayload, PointState, SearchRequest, VectorIndex};
use crate::navtree;
use crate::parse::{ContentType, parse};
use crate::store::{CollectionRecord, DocFinding, DocumentRecord, IndexOutcome, RagStore, Trust};
use crate::{CallScope, DocumentEnvelope, RagError, RagServices, SealedChunk};
use std::sync::Arc;
use std::time::Duration;

/// Cosine similarity above which a chunk counts as a near-copy of another document's chunk.
pub const NEAR_DUPLICATE: f32 = 0.97;
/// Chunks of an untrusted document compared with the collection, at most.
pub const NEAR_DUPLICATE_CHECKS: usize = 64;
/// Texts per embedding call (TEI's default `max_client_batch_size` is 32).
pub const EMBED_BATCH: usize = 32;
/// Points per upsert.
pub const UPSERT_BATCH: usize = 128;
/// Largest document, in bytes of text.
pub const MAX_DOCUMENT_BYTES: usize = 5 * 1024 * 1024;
/// Chunks per document, at most.
pub const MAX_CHUNKS: usize = 20_000;

/// A document as the admin API receives it.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestRequest {
    pub doc_id: String,
    #[serde(default)]
    pub title: Option<String>,
    pub content: String,
    /// `text/markdown`, `text/html` or `text/plain` (default markdown).
    #[serde(default)]
    pub content_type: Option<String>,
    /// Where it came from (a URL, a system name). Stored in clear: no personal data.
    #[serde(default)]
    pub source: Option<String>,
    /// Default: the collection's `default_trust`.
    #[serde(default)]
    pub trust: Option<Trust>,
    #[serde(default)]
    pub valid_from: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub valid_to: Option<chrono::DateTime<chrono::Utc>>,
}

/// Checks a request and seals it for the registry under the tenant's data key.
pub fn prepare(
    dek: &caliban_config::Dek,
    c: &CollectionRecord,
    r: IngestRequest,
    by: &str,
) -> Result<crate::store::NewDocument, String> {
    if !crate::store::valid_doc_id(&r.doc_id) {
        return Err("doc_id must be 1 to 200 visible ASCII characters without '/'".into());
    }
    if r.content.trim().is_empty() {
        return Err("content is empty".into());
    }
    if r.content.len() > MAX_DOCUMENT_BYTES {
        return Err(format!("content is larger than {MAX_DOCUMENT_BYTES} bytes"));
    }
    if r.title.as_ref().is_some_and(|t| t.chars().count() > 500) {
        return Err("title is longer than 500 characters".into());
    }
    if r.source.as_ref().is_some_and(|s| s.len() > 2000) {
        return Err("source is longer than 2000 bytes".into());
    }
    if let (Some(f), Some(t)) = (r.valid_from, r.valid_to)
        && f >= t
    {
        return Err("valid_from must be before valid_to".into());
    }
    let kind = ContentType::parse(r.content_type.as_deref().unwrap_or("text/markdown"))?;
    let env = DocumentEnvelope { title: r.title.clone(), content: r.content };
    let json = serde_json::to_string(&env).map_err(|e| e.to_string())?;
    let hash = crate::content_key(dek, &format!("{}\0{}", env.title.as_deref().unwrap_or_default(), env.content));
    Ok(crate::store::NewDocument {
        tenant_id: c.tenant_id.clone(),
        collection_id: c.id.clone(),
        doc_key: crate::doc_key(dek, &c.id, &r.doc_id),
        sealed_content: dek.seal_with(&c.tenant_id, &crate::document_context(&c.id, &r.doc_id), &json),
        doc_id: r.doc_id,
        content_type: kind.as_str().to_owned(),
        source: r.source,
        trust: r.trust.unwrap_or(c.settings.default_trust),
        content_hash: hash,
        bytes: env.content.len() as u64,
        valid_from: r.valid_from,
        valid_to: r.valid_to,
        created_by: by.to_owned(),
    })
}

pub struct Indexer {
    pub store: Arc<dyn RagStore>,
    pub index: Arc<dyn VectorIndex>,
    pub services: Arc<dyn RagServices>,
    /// Qdrant collection prefix.
    pub prefix: String,
    /// Chunk without structure (fixed windows, no heading paths): the baseline the retrieval eval
    /// compares structure-aware chunking with. Never set in production.
    pub plain_chunks: bool,
}

/// Whether a finding quarantines a document from a source of this trust.
pub fn quarantines(trust: Trust, kind: &str) -> bool {
    match trust {
        Trust::Trusted => kind == "hidden_unicode",
        Trust::Untrusted => kind != "url",
    }
}

fn unix(t: Option<chrono::DateTime<chrono::Utc>>) -> Option<i64> {
    t.map(|t| t.timestamp())
}

/// A retryable failure, or a permanent one.
fn outcome_of(e: RagError, attempts: u32) -> IndexOutcome {
    match e {
        RagError::Unavailable(m) if attempts < MAX_ATTEMPTS => {
            let secs = 2u64.saturating_pow(attempts.min(8)).min(300);
            IndexOutcome::Retry { error: m, after: Duration::from_secs(secs) }
        }
        other => IndexOutcome::Failed { error: other.to_string() },
    }
}

/// Indexing attempts before a document fails for good.
pub const MAX_ATTEMPTS: u32 = 6;

impl Indexer {
    /// Indexes `doc` (claimed) and returns what to record. Never panics on bad content.
    pub async fn process(&self, doc: &DocumentRecord, sealed: &str, collection: &CollectionRecord) -> IndexOutcome {
        match self.run(doc, sealed, collection).await {
            Ok(o) => o,
            Err(e) => outcome_of(e, doc.attempts),
        }
    }

    async fn run(
        &self,
        doc: &DocumentRecord,
        sealed: &str,
        collection: &CollectionRecord,
    ) -> Result<IndexOutcome, RagError> {
        let tenant = doc.tenant_id.as_str();
        let dek = self.services.data_key(tenant)?;
        let plain = dek
            .open_with(tenant, &crate::document_context(&doc.collection_id, &doc.doc_id), sealed)
            .map_err(|e| RagError::Invalid(format!("the document cannot be opened: {e}")))?;
        let env: DocumentEnvelope =
            serde_json::from_str(&plain).map_err(|e| RagError::Invalid(format!("the document is malformed: {e}")))?;
        let kind = ContentType::parse(&doc.content_type).map_err(RagError::Invalid)?;
        let parsed = if self.plain_chunks {
            parse(ContentType::Text, &env.content.replace('\n', " "))
        } else {
            parse(kind, &env.content)
        };
        let title = if self.plain_chunks { None } else { env.title.clone().or_else(|| parsed.title.clone()) };
        let chunks = chunk(&parsed, collection.settings.chunk_tokens);
        if chunks.is_empty() {
            return Ok(IndexOutcome::Failed { error: "the document has no text".into() });
        }
        if chunks.len() > MAX_CHUNKS {
            return Ok(IndexOutcome::Failed { error: format!("the document has more than {MAX_CHUNKS} chunks") });
        }

        // Injection scan of the original text (what the model would read).
        let mut findings: Vec<DocFinding> = Vec::new();
        for c in &chunks {
            for f in caliban_mcp::scan::scan_document(&c.indexed_text(title.as_deref()), "chunk") {
                let f = DocFinding { kind: f.kind, chunk: c.index };
                if !findings.contains(&f) {
                    findings.push(f);
                }
            }
        }

        // What is indexed: heading path + text, personal data pseudonymised.
        let indexed: Vec<String> = chunks.iter().map(|c| c.indexed_text(title.as_deref())).collect();
        let (protected, pii_entities) = self.services.protect(tenant, indexed).await?;
        let scope = CallScope { tenant: tenant.to_owned(), ..CallScope::default() };
        let mut dense: Vec<Vec<f32>> = Vec::with_capacity(protected.len());
        for batch in protected.chunks(EMBED_BATCH) {
            let v = self.services.embed(&scope, &collection.embedding_model, batch).await?;
            if v.len() != batch.len() {
                return Err(RagError::Internal("the embedder returned a vector count that does not match".into()));
            }
            dense.extend(v);
        }
        let dim = dense.first().map_or(0, Vec::len);
        if dim == 0 || dense.iter().any(|v| v.len() != dim) {
            return Err(RagError::Internal("the embedder returned empty or mixed-dimension vectors".into()));
        }
        let name = collection.index_name(&self.prefix);
        self.index.ensure(&name, dim).await?;

        if doc.trust == Trust::Untrusted {
            for (c, v) in chunks.iter().zip(&dense).take(NEAR_DUPLICATE_CHECKS) {
                let req = SearchRequest {
                    dense: Some(v.clone()),
                    filter: Filter { exclude_doc_key: Some(doc.doc_key.clone()), ..Filter::default() },
                    limit: 1,
                    ..SearchRequest::default()
                };
                let hit = self.index.search(&name, &req).await?.dense.into_iter().next();
                if hit.is_some_and(|h| h.score >= NEAR_DUPLICATE) {
                    findings.push(DocFinding { kind: "near_duplicate".into(), chunk: c.index });
                }
            }
        }

        let hasher = crate::term_hasher(&dek);
        let points = self.points(doc, collection, &dek, &hasher, &chunks, &protected, &dense, title.as_deref())?;
        for batch in points.chunks(UPSERT_BATCH) {
            self.index.upsert(&name, batch).await?;
        }
        let tokens: u64 = chunks.iter().map(|c| u64::from(c.tokens)).sum();
        let n = u32::try_from(chunks.len()).unwrap_or(u32::MAX);
        let pii = u64::try_from(pii_entities).unwrap_or(u64::MAX);
        let blocking = !doc.findings_acknowledged && findings.iter().any(|f| quarantines(doc.trust, &f.kind));
        if blocking {
            return Ok(IndexOutcome::Quarantined { chunks: n, tokens, pii_entities: pii, findings });
        }
        self.index.set_state(&name, &doc.doc_key, doc.version, PointState::Ready).await?;
        Ok(IndexOutcome::Ready { chunks: n, tokens, pii_entities: pii, findings })
    }

    #[allow(clippy::too_many_arguments)]
    fn points(
        &self,
        doc: &DocumentRecord,
        collection: &CollectionRecord,
        dek: &caliban_config::Dek,
        hasher: &crate::sparse::TermHasher,
        chunks: &[ChunkDraft],
        protected: &[String],
        dense: &[Vec<f32>],
        title: Option<&str>,
    ) -> Result<Vec<Point>, RagError> {
        let tenant = doc.tenant_id.as_str();
        let tree = (chunks.len() >= collection.settings.nav_min_chunks as usize)
            .then(|| navtree::build(chunks.len(), navtree::FANOUT))
            .flatten();
        let base = |kind, node_key: String, index: u32, level: u32, parent: Option<String>, tokens: u32| PointPayload {
            tenant_id: tenant.to_owned(),
            collection_id: collection.id.clone(),
            doc_key: doc.doc_key.clone(),
            doc_version: doc.version,
            kind,
            state: PointState::Pending,
            chunk_index: index,
            level,
            node_key,
            parent,
            tokens,
            content_key: String::new(),
            valid_from: unix(doc.valid_from),
            valid_to: unix(doc.valid_to),
            sealed: String::new(),
        };
        let mut out = Vec::with_capacity(chunks.len());
        for (i, c) in chunks.iter().enumerate() {
            let node_key = navtree::leaf_key(c.index);
            let id = crate::point_id(&collection.id, &doc.doc_key, doc.version, &node_key);
            let sealed = SealedChunk {
                doc_id: doc.doc_id.clone(),
                title: title.map(str::to_owned),
                heading_path: c.heading_path.clone(),
                text: c.text.clone(),
                source: doc.source.clone(),
            };
            let json = serde_json::to_string(&sealed).map_err(|e| RagError::Internal(e.to_string()))?;
            let parent = tree.as_ref().map(|t| t.leaf_parent[i].clone());
            let mut payload = base(PointKind::Chunk, node_key, c.index, 0, parent, c.tokens);
            payload.content_key = crate::content_key(dek, &c.text);
            payload.sealed = dek.seal_with(tenant, &crate::chunk_context(&collection.id, &id), &json);
            out.push(Point { id, dense: dense[i].clone(), sparse: hasher.document(&protected[i]), payload });
        }
        if let Some(t) = &tree {
            for n in &t.nodes {
                let range = n.first as usize..=n.last as usize;
                let vectors: Vec<&Vec<f32>> = dense[range.clone()].iter().collect();
                let text = protected[range].join("\n\n");
                let id = crate::point_id(&collection.id, &doc.doc_key, doc.version, &n.key);
                let tokens: u32 = chunks[n.first as usize..=n.last as usize].iter().map(|c| c.tokens).sum();
                let payload = base(PointKind::Nav, n.key.clone(), n.first, n.level, n.parent.clone(), tokens);
                out.push(Point { id, dense: navtree::mean(&vectors), sparse: hasher.document(&text), payload });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_decides_what_quarantines() {
        assert!(quarantines(Trust::Untrusted, "instruction"));
        assert!(quarantines(Trust::Untrusted, "near_duplicate"));
        assert!(!quarantines(Trust::Untrusted, "url"));
        assert!(quarantines(Trust::Trusted, "hidden_unicode"));
        assert!(!quarantines(Trust::Trusted, "instruction"));
        match outcome_of(RagError::Unavailable("down".into()), 1) {
            IndexOutcome::Retry { after, .. } => assert_eq!(after, Duration::from_secs(2)),
            o => panic!("{o:?}"),
        }
        assert!(matches!(outcome_of(RagError::Unavailable("down".into()), MAX_ATTEMPTS), IndexOutcome::Failed { .. }));
        assert!(matches!(outcome_of(RagError::Invalid("bad".into()), 1), IndexOutcome::Failed { .. }));
    }
}
