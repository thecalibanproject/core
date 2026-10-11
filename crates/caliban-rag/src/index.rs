//! The vector index: dense and sparse vectors per point, on Qdrant ([`crate::qdrant`]) or in
//! memory ([`MemoryIndex`], tests and single-process development).
//!
//! **One Qdrant collection per RAG collection.** A RAG collection belongs to one tenant, so each
//! tenant's vectors live in physically separate collections, not in a shared collection with a
//! tenant filter (note 05 §5.2; RAG membership inference makes shared indexes a leak). Every point
//! also carries its tenant and collection, and every search filters on readiness.
//!
//! **What a point holds.** Two vectors (dense, from the pseudonymised chunk; sparse, keyed term
//! ids), an opaque document key (a keyed hash of the document id), the document version, and the
//! chunk's text, title, heading path and document id **sealed under the tenant's data key**
//! (`sealed`). Nothing readable without the tenant's key is stored in Qdrant except the vectors.
//!
//! **Visibility.** Points are written `pending` and flipped to `ready` only after the whole
//! document is indexed and its checks passed. Searches only see `ready` points, and the retriever
//! then checks every candidate against the document registry (Postgres), so a crash between the
//! two writes, a quarantine or a delete is never visible (fail closed).

use crate::sparse::{SparseVec, idf};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexError {
    #[error("vector index unavailable: {0}")]
    Unavailable(String),
    #[error("vector index error: {0}")]
    Backend(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointKind {
    /// A chunk: what retrieval returns.
    Chunk,
    /// An inner node of a document's navigation tree ([`crate::navtree`]): searched, never returned.
    Nav,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointState {
    Pending,
    Ready,
}

impl PointState {
    pub fn as_str(self) -> &'static str {
        match self {
            PointState::Pending => "pending",
            PointState::Ready => "ready",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PointPayload {
    pub tenant_id: String,
    pub collection_id: String,
    /// Keyed hash of the document id ([`crate::doc_key`]).
    pub doc_key: String,
    pub doc_version: u32,
    pub kind: PointKind,
    pub state: PointState,
    /// Chunks: position in the document. Navigation nodes: their first chunk.
    pub chunk_index: u32,
    /// 0 for chunks; navigation nodes count up to the root.
    pub level: u32,
    /// The node's key inside its document's tree (`c<index>` for chunks, `n<level>.<i>` above).
    pub node_key: String,
    /// The parent navigation node, for documents that have a tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub tokens: u32,
    /// Keyed hash of the chunk text: exact duplicates are dropped at query time.
    #[serde(default)]
    pub content_key: String,
    /// Unix seconds; the document is not retrieved before / after.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<i64>,
    /// [`crate::SealedChunk`] sealed under the tenant DEK; empty for navigation nodes.
    #[serde(default)]
    pub sealed: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    /// A UUID (Qdrant point ids are UUIDs or integers).
    pub id: String,
    pub dense: Vec<f32>,
    pub sparse: SparseVec,
    pub payload: PointPayload,
}

/// What a search may return. Every search sees `ready` points only.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    /// Only these kinds (empty: chunks only).
    pub kinds: Vec<PointKind>,
    /// Only these documents (empty: any).
    pub doc_keys: Vec<String>,
    /// Only children of these navigation nodes (empty: any).
    pub parents: Vec<String>,
    /// Not this document (the near-duplicate check).
    pub exclude_doc_key: Option<String>,
    /// Unix seconds: leave out documents outside their validity window.
    pub now: Option<i64>,
    /// Search pending points instead of ready ones (indexing checks only).
    pub pending: bool,
    /// Only points without a parent (the root of a navigation tree).
    pub roots_only: bool,
}

impl Filter {
    pub fn matches(&self, p: &PointPayload) -> bool {
        let state = if self.pending { PointState::Pending } else { PointState::Ready };
        let kinds_ok = if self.kinds.is_empty() { p.kind == PointKind::Chunk } else { self.kinds.contains(&p.kind) };
        p.state == state
            && kinds_ok
            && (self.doc_keys.is_empty() || self.doc_keys.contains(&p.doc_key))
            && (self.parents.is_empty() || p.parent.as_ref().is_some_and(|x| self.parents.contains(x)))
            && (!self.roots_only || p.parent.is_none())
            && self.exclude_doc_key.as_ref().is_none_or(|k| *k != p.doc_key)
            && self.now.is_none_or(|now| p.valid_from.is_none_or(|f| f <= now) && p.valid_to.is_none_or(|t| t > now))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub id: String,
    pub score: f32,
    pub payload: PointPayload,
    /// The dense vector, when asked for.
    pub dense: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Default)]
pub struct SearchRequest {
    pub dense: Option<Vec<f32>>,
    pub sparse: Option<SparseVec>,
    pub filter: Filter,
    /// Per leg.
    pub limit: usize,
    pub with_vectors: bool,
}

/// One ranked list per leg that was asked for.
#[derive(Debug, Clone, Default)]
pub struct SearchResponse {
    pub dense: Vec<Hit>,
    pub sparse: Vec<Hit>,
}

#[async_trait]
pub trait VectorIndex: Send + Sync {
    fn name(&self) -> &'static str;
    /// Creates the collection (dense vectors of `dim`, cosine; sparse with IDF) unless it exists.
    async fn ensure(&self, collection: &str, dim: usize) -> Result<(), IndexError>;
    async fn upsert(&self, collection: &str, points: &[Point]) -> Result<(), IndexError>;
    /// Sets the state of every point of one document version.
    async fn set_state(
        &self,
        collection: &str,
        doc_key: &str,
        version: u32,
        state: PointState,
    ) -> Result<(), IndexError>;
    /// Deletes the points of a document (one version, or all of them).
    async fn delete_doc(&self, collection: &str, doc_key: &str, version: Option<u32>) -> Result<(), IndexError>;
    async fn drop_collection(&self, collection: &str) -> Result<(), IndexError>;
    /// A missing collection is not an error: there is nothing in it yet.
    async fn search(&self, collection: &str, req: &SearchRequest) -> Result<SearchResponse, IndexError>;
    /// Points in a collection, any state (tests and diagnostics).
    async fn count(&self, collection: &str) -> Result<usize, IndexError>;
}

/// Brute force over points in memory: cosine for the dense leg, BM25 with Qdrant's IDF formula
/// (over every point of the collection, as Qdrant computes it) for the sparse leg.
/// A collection in memory: its dimension and its points by id.
type MemCollection = (usize, HashMap<String, Point>);

#[derive(Default)]
pub struct MemoryIndex {
    collections: Mutex<HashMap<String, MemCollection>>,
}

impl MemoryIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every payload of a collection (tests).
    pub fn payloads(&self, collection: &str) -> Vec<PointPayload> {
        self.collections
            .lock()
            .get(collection)
            .map(|(_, m)| m.values().map(|p| p.payload.clone()).collect())
            .unwrap_or_default()
    }

    /// Every point of a collection (tests).
    pub fn points(&self, collection: &str) -> Vec<Point> {
        self.collections.lock().get(collection).map(|(_, m)| m.values().cloned().collect()).unwrap_or_default()
    }
}

pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (f64::from(*x), f64::from(*y));
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    #[allow(clippy::cast_possible_truncation)]
    let c = (dot / (na.sqrt() * nb.sqrt())) as f32;
    c
}

fn rank(mut hits: Vec<Hit>, limit: usize) -> Vec<Hit> {
    hits.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.id.cmp(&b.id)));
    hits.truncate(limit);
    hits
}

#[async_trait]
impl VectorIndex for MemoryIndex {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn ensure(&self, collection: &str, dim: usize) -> Result<(), IndexError> {
        let mut g = self.collections.lock();
        let e = g.entry(collection.to_owned()).or_insert_with(|| (dim, HashMap::new()));
        if e.0 != dim {
            return Err(IndexError::Backend(format!("collection {collection} holds {}-d vectors, not {dim}", e.0)));
        }
        Ok(())
    }

    async fn upsert(&self, collection: &str, points: &[Point]) -> Result<(), IndexError> {
        let mut g = self.collections.lock();
        let (dim, m) =
            g.get_mut(collection).ok_or_else(|| IndexError::Backend(format!("no collection {collection}")))?;
        for p in points {
            if p.dense.len() != *dim {
                return Err(IndexError::Backend(format!("a {}-d vector in a {dim}-d collection", p.dense.len())));
            }
            m.insert(p.id.clone(), p.clone());
        }
        Ok(())
    }

    async fn set_state(
        &self,
        collection: &str,
        doc_key: &str,
        version: u32,
        state: PointState,
    ) -> Result<(), IndexError> {
        if let Some((_, m)) = self.collections.lock().get_mut(collection) {
            for p in m.values_mut() {
                if p.payload.doc_key == doc_key && p.payload.doc_version == version {
                    p.payload.state = state;
                }
            }
        }
        Ok(())
    }

    async fn delete_doc(&self, collection: &str, doc_key: &str, version: Option<u32>) -> Result<(), IndexError> {
        if let Some((_, m)) = self.collections.lock().get_mut(collection) {
            m.retain(|_, p| !(p.payload.doc_key == doc_key && version.is_none_or(|v| v == p.payload.doc_version)));
        }
        Ok(())
    }

    async fn drop_collection(&self, collection: &str) -> Result<(), IndexError> {
        self.collections.lock().remove(collection);
        Ok(())
    }

    async fn search(&self, collection: &str, req: &SearchRequest) -> Result<SearchResponse, IndexError> {
        let g = self.collections.lock();
        let Some((_, m)) = g.get(collection) else { return Ok(SearchResponse::default()) };
        let hit = |p: &Point, score: f32| Hit {
            id: p.id.clone(),
            score,
            payload: p.payload.clone(),
            dense: req.with_vectors.then(|| p.dense.clone()),
        };
        let mut out = SearchResponse::default();
        if let Some(q) = &req.dense {
            let hits = m.values().filter(|p| req.filter.matches(&p.payload)).map(|p| hit(p, cosine(q, &p.dense)));
            out.dense = rank(hits.collect(), req.limit);
        }
        if let Some(q) = &req.sparse {
            // IDF over the whole collection, like Qdrant's `idf` modifier.
            let n = m.len();
            let weights: Vec<f32> = q
                .indices
                .iter()
                .map(|i| idf(n, m.values().filter(|p| p.sparse.indices.binary_search(i).is_ok()).count()))
                .collect();
            let weighted = SparseVec {
                indices: q.indices.clone(),
                values: q.values.iter().zip(&weights).map(|(v, w)| v * w).collect(),
            };
            let hits = m
                .values()
                .filter(|p| req.filter.matches(&p.payload))
                .map(|p| (p, p.sparse.dot(&weighted)))
                .filter(|(_, s)| *s > 0.0)
                .map(|(p, s)| hit(p, s));
            out.sparse = rank(hits.collect(), req.limit);
        }
        Ok(out)
    }

    async fn count(&self, collection: &str) -> Result<usize, IndexError> {
        Ok(self.collections.lock().get(collection).map_or(0, |(_, m)| m.len()))
    }
}
