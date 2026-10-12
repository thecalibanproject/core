//! Retrieval for Caliban (docs/research/06-rag-and-token-efficiency.md; docs/rag.md).
//!
//! **Ingest** ([`ingest`]): a document is parsed with its structure ([`parse`]), cut into
//! structure-aligned chunks with their heading paths ([`chunk`]), scanned for injections and
//! near-duplicates (poisoning controls), pseudonymised with the tenant's PII engine, embedded
//! through the gateway's embedding path (so on-prem embedders, quotas, metering and PII masking
//! apply), and written to the tenant's own vector collection with BM25 sparse vectors
//! ([`sparse`]) and, for long documents, a navigation tree ([`navtree`]). The chunk text is sealed
//! under the tenant's data key. Nothing is visible until the whole document is indexed and its
//! checks pass (fail closed, [`store`]).
//!
//! **Retrieve** ([`retrieve`]): hybrid dense + BM25 search fused with reciprocal rank fusion,
//! a registry check of every candidate, tree navigation for long documents when the query needs
//! several pieces of evidence, a rerank through the gateway's rerank path, a near-duplicate
//! penalty only when the candidate pool is redundant, and context assembly under a token budget
//! with citations (document id, heading path, chunk id).
//!
//! Workers run the indexing loop ([`runner`]); the data plane exposes retrieval to nodes as the
//! built-in tool `builtin://rag_search` (`caliban-gateway`), whose results carry the `retrieved`
//! taint label.

pub mod chunk;
pub mod eval;
pub mod index;
pub mod ingest;
pub mod navtree;
pub mod parse;
pub mod pg;
pub mod qdrant;
pub mod retrieve;
pub mod runner;
pub mod sparse;
pub mod store;

use caliban_config::Dek;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Default prefix of the Qdrant collections holding RAG vectors.
pub const DEFAULT_PREFIX: &str = "caliban_rag";

/// Purposes of the keys derived from a tenant's data key.
const DOC_KEY_PURPOSE: &str = "caliban rag document key v1";
const TERMS_PURPOSE: &str = "caliban rag sparse terms v1";
const CONTENT_PURPOSE: &str = "caliban rag content key v1";

/// What a chunk point carries sealed (everything readable about it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedChunk {
    pub doc_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub heading_path: Vec<String>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// A document as the control plane seals it into the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentEnvelope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub content: String,
}

/// Associated data for a sealed document in the registry.
pub fn document_context(collection_id: &str, doc_id: &str) -> String {
    format!("rag-document\0{collection_id}\0{doc_id}")
}

/// Associated data for a sealed chunk in the vector index: bound to its point.
pub fn chunk_context(collection_id: &str, point_id: &str) -> String {
    format!("rag-chunk\0{collection_id}\0{point_id}")
}

/// The keyed hash naming a document in the vector index.
pub fn doc_key(dek: &Dek, collection_id: &str, doc_id: &str) -> String {
    let k = dek.derive(DOC_KEY_PURPOSE);
    let h = blake3::keyed_hash(&k, format!("{collection_id}\0{doc_id}").as_bytes());
    hex::encode(&h.as_bytes()[..16])
}

/// A keyed hash of content (duplicate detection without plaintext hashes).
pub fn content_key(dek: &Dek, text: &str) -> String {
    let k = dek.derive(CONTENT_PURPOSE);
    hex::encode(&blake3::keyed_hash(&k, text.as_bytes()).as_bytes()[..16])
}

/// The tenant's keyed term ids for the sparse (BM25) leg.
pub fn term_hasher(dek: &Dek) -> sparse::TermHasher {
    sparse::TermHasher::new(dek.derive(TERMS_PURPOSE))
}

/// A deterministic point id (a UUID): re-indexing a version overwrites its points.
pub fn point_id(collection_id: &str, doc_key: &str, version: u32, node_key: &str) -> String {
    let h = blake3::hash(format!("caliban rag point v1\0{collection_id}\0{doc_key}\0{version}\0{node_key}").as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&h.as_bytes()[..16]);
    uuid::Builder::from_random_bytes(b).into_uuid().to_string()
}

/// Who a retrieval or ingest call is made for: metering, quotas and usage tags follow it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallScope {
    pub tenant: String,
    /// The API key the call is made as (a node run's invoking key). `None`: the tenant's own
    /// background work (indexing), limited by the tenant's limits only.
    pub key_hash: Option<String>,
    /// The node run that asked (its usage events are tagged with it).
    pub node: Option<NodeCall>,
    /// Makes embedding and rerank calls of a replayed step hit the stored response.
    pub idempotency_key: Option<String>,
    /// What the calls do (their usage events' `purpose`): indexing or a search.
    pub purpose: CallPurpose,
}

/// What retrieval's embedding and rerank calls are for, so their spend is separable from the
/// tenant's own embedding calls (usage `purpose`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CallPurpose {
    /// Embedding a collection's documents (the tenant's background work).
    #[default]
    Ingest,
    /// A node's retrieval query: its embedding and reranking.
    Search,
}

impl CallPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            CallPurpose::Ingest => "rag.ingest",
            CallPurpose::Search => "rag.search",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCall {
    pub node: String,
    pub version: u32,
    pub run_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RagError {
    /// Worth retrying (an upstream, the index or the store is down).
    #[error("{0}")]
    Unavailable(String),
    /// The request cannot work (a bad argument, a model that is not there).
    #[error("{0}")]
    Invalid(String),
    /// Outside what the caller may read.
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    Internal(String),
}

impl From<store::RagStoreError> for RagError {
    fn from(e: store::RagStoreError) -> Self {
        match e {
            store::RagStoreError::Backend(m) => RagError::Unavailable(m),
            other => RagError::Internal(other.to_string()),
        }
    }
}

impl From<index::IndexError> for RagError {
    fn from(e: index::IndexError) -> Self {
        match e {
            index::IndexError::Unavailable(m) => RagError::Unavailable(m),
            index::IndexError::Backend(m) => RagError::Internal(m),
        }
    }
}

/// What retrieval needs from the data plane. The gateway implements it with its own pipeline
/// (`caliban_gateway::rag`): the tenant's data key from the snapshot, its PII engine, and
/// `/v1/embeddings` and `/v1/rerank` called in-process, so quotas, metering, PII masking for
/// external providers and tracing apply as to any client call.
#[async_trait::async_trait]
pub trait RagServices: Send + Sync {
    /// The tenant's data key.
    fn data_key(&self, tenant: &str) -> Result<Arc<Dek>, RagError>;
    /// Texts as they may be indexed: personal data replaced by the tenant's tenant-scope
    /// surrogates (or masked, per the tenant's PII mode), so a query naming the same person
    /// matches. Returns the texts and the number of entities found.
    async fn protect(&self, tenant: &str, texts: Vec<String>) -> Result<(Vec<String>, usize), RagError>;
    /// One vector per text, in order.
    async fn embed(&self, scope: &CallScope, model: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, RagError>;
    /// One relevance score per document, in order.
    async fn rerank(&self, scope: &CallScope, model: &str, query: &str, docs: &[String]) -> Result<Vec<f32>, RagError>;
}

/// Reciprocal rank fusion of ranked lists of ids, `Σ 1 / (k + rank)` with ranks from 1 (Cormack,
/// Clarke and Buettcher 2009; k = 60). Ties broken by id, so the order is deterministic.
pub fn rrf(lists: &[Vec<String>], k: f32) -> Vec<(String, f32)> {
    let mut scores: HashMap<&str, f32> = HashMap::new();
    for list in lists {
        for (rank, id) in list.iter().enumerate() {
            #[allow(clippy::cast_precision_loss)]
            let s = 1.0 / (k + rank as f32 + 1.0);
            *scores.entry(id.as_str()).or_default() += s;
        }
    }
    let mut v: Vec<(String, f32)> = scores.into_iter().map(|(id, s)| (id.to_owned(), s)).collect();
    v.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

pub const RRF_K: f32 = 60.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrf_rewards_agreement() {
        let fused = rrf(&[vec!["a".into(), "b".into()], vec!["b".into(), "c".into()]], 60.0);
        assert_eq!(fused[0].0, "b");
        assert_eq!(fused.len(), 3);
    }

    #[test]
    fn keys_are_tenant_bound_and_stable() {
        let (a, b) = (Dek::generate(), Dek::generate());
        assert_eq!(doc_key(&a, "c1", "handbook"), doc_key(&a, "c1", "handbook"));
        assert_ne!(doc_key(&a, "c1", "handbook"), doc_key(&b, "c1", "handbook"));
        assert_ne!(doc_key(&a, "c1", "handbook"), doc_key(&a, "c2", "handbook"));
        let p = point_id("c1", "k", 1, "c0");
        assert_eq!(p, point_id("c1", "k", 1, "c0"));
        assert!(uuid::Uuid::parse_str(&p).is_ok());
        assert_ne!(p, point_id("c1", "k", 2, "c0"));
    }
}
