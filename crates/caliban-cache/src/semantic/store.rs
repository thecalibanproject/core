//! Vector store abstraction for T2 entries, plus a brute-force in-memory implementation.
//!
//! Every query carries the tenant id and every implementation must filter on it: an entry of one
//! tenant is never a candidate for another, whatever the similarity (key-collision attacks,
//! arXiv 2601.23088).

use super::policy::EntryStats;
use async_trait::async_trait;
use caliban_types::cosine;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("vector store unavailable: {0}")]
    Unavailable(String),
    #[error("vector store error: {0}")]
    Backend(String),
}

/// How the cached body is shaped (decides how a hit is rehydrated and replayed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseShape {
    /// OpenAI chat completion (every upstream except native Anthropic passthrough).
    Openai,
    /// Anthropic message (native passthrough).
    Anthropic,
}

impl ResponseShape {
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseShape::Openai => "openai",
            ResponseShape::Anthropic => "anthropic",
        }
    }
}

/// Payload stored with each vector. Text fields are in surrogate form (never raw PII sent outside);
/// a hit is rehydrated with the vault of the request that hits it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryPayload {
    /// Tenant scope. Indexed with `is_tenant` in Qdrant; every query filters on it.
    pub tenant_id: String,
    /// `{model id}|{shape}`: the routed model and how its body is shaped.
    pub route: String,
    /// Hex hash of everything that must match exactly (route, context and params hash, numeric
    /// slots, PII surrogate set, PII mode). Filtered on, so only true peers are compared.
    pub partition: String,
    /// Hex hash of the request without its last user message (system prompt, history, params).
    pub params_hash: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds; expired entries are filtered out and swept.
    pub expires_at: i64,
    /// Catalogue model id that produced the response.
    pub model: String,
    pub shape: ResponseShape,
    /// The response body (JSON text), pseudonymised.
    pub response: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// Verifier statistics (see `policy`).
    #[serde(default)]
    pub stats: EntryStats,
    /// The entry's learned threshold when the stats were last written (informational; decisions
    /// recompute it from `stats` and the current policy).
    #[serde(default)]
    pub threshold: f32,
}

/// One nearest-neighbour result.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub id: String,
    /// Cosine similarity.
    pub score: f32,
    pub payload: EntryPayload,
}

#[derive(Debug, Clone, Copy)]
pub struct SearchQuery<'a> {
    pub collection: &'a str,
    pub tenant: &'a str,
    pub partition: &'a str,
    pub vector: &'a [f32],
    pub limit: usize,
    /// Unix seconds; entries with `expires_at <= now` are not returned.
    pub now: i64,
}

#[async_trait]
pub trait VectorStore: Send + Sync {
    /// Live entries of `tenant` in `partition`, most similar first. A missing collection is not an
    /// error (no entries yet).
    async fn search(&self, q: &SearchQuery<'_>) -> Result<Vec<Candidate>, StoreError>;
    /// Inserts or replaces an entry, creating the collection (sized to the vector) if needed.
    async fn upsert(&self, collection: &str, id: &str, vector: &[f32], payload: &EntryPayload) -> Result<(), StoreError>;
    /// Replaces an entry's verifier stats, only if it belongs to `tenant`.
    async fn update_stats(&self, collection: &str, tenant: &str, id: &str, stats: &EntryStats, threshold: f32) -> Result<(), StoreError>;
    /// Deletes entries with `expires_at <= now`.
    async fn delete_expired(&self, collection: &str, now: i64) -> Result<(), StoreError>;
    /// Deletes every entry of `tenant` in `collection` (tenant offboarding).
    async fn delete_tenant(&self, collection: &str, tenant: &str) -> Result<(), StoreError>;
}

type Points = HashMap<String, (Vec<f32>, EntryPayload)>;

/// Brute-force store for tests and single-process development (`store = "memory"`). Bounded:
/// when a collection is full, the entry closest to expiry is evicted.
pub struct MemoryStore {
    collections: Mutex<HashMap<String, Points>>,
    max_per_collection: usize,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new(100_000)
    }
}

impl MemoryStore {
    pub fn new(max_per_collection: usize) -> Self {
        Self { collections: Mutex::new(HashMap::new()), max_per_collection: max_per_collection.max(1) }
    }

    /// Number of entries across collections.
    pub fn len(&self) -> usize {
        self.collections.lock().values().map(HashMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copy of an entry's payload (tests and debugging).
    pub fn get(&self, collection: &str, id: &str) -> Option<EntryPayload> {
        self.collections.lock().get(collection).and_then(|c| c.get(id)).map(|(_, p)| p.clone())
    }

    /// Every `(collection, id, payload)` (tests and debugging).
    pub fn entries(&self) -> Vec<(String, String, EntryPayload)> {
        let g = self.collections.lock();
        g.iter().flat_map(|(c, m)| m.iter().map(move |(id, (_, p))| (c.clone(), id.clone(), p.clone()))).collect()
    }
}

#[async_trait]
impl VectorStore for MemoryStore {
    async fn search(&self, q: &SearchQuery<'_>) -> Result<Vec<Candidate>, StoreError> {
        let g = self.collections.lock();
        let Some(c) = g.get(q.collection) else { return Ok(vec![]) };
        let mut out: Vec<Candidate> = c
            .iter()
            .filter(|(_, (v, p))| p.tenant_id == q.tenant && p.partition == q.partition && p.expires_at > q.now && v.len() == q.vector.len())
            .map(|(id, (v, p))| Candidate { id: id.clone(), score: cosine(v, q.vector), payload: p.clone() })
            .collect();
        out.sort_by(|a, b| b.score.total_cmp(&a.score));
        out.truncate(q.limit);
        Ok(out)
    }

    async fn upsert(&self, collection: &str, id: &str, vector: &[f32], payload: &EntryPayload) -> Result<(), StoreError> {
        let mut g = self.collections.lock();
        let c = g.entry(collection.to_owned()).or_default();
        if let Some((_, (v, _))) = c.iter().next()
            && v.len() != vector.len()
        {
            return Err(StoreError::Backend(format!("collection {collection} holds {}-d vectors, got {}", v.len(), vector.len())));
        }
        if !c.contains_key(id) && c.len() >= self.max_per_collection {
            let victim = c.iter().min_by_key(|(_, (_, p))| p.expires_at).map(|(k, _)| k.clone());
            if let Some(k) = victim {
                c.remove(&k);
            }
        }
        c.insert(id.to_owned(), (vector.to_vec(), payload.clone()));
        Ok(())
    }

    async fn update_stats(&self, collection: &str, tenant: &str, id: &str, stats: &EntryStats, threshold: f32) -> Result<(), StoreError> {
        let mut g = self.collections.lock();
        if let Some((_, p)) = g.get_mut(collection).and_then(|c| c.get_mut(id))
            && p.tenant_id == tenant
        {
            p.stats = stats.clone();
            p.threshold = threshold;
        }
        Ok(())
    }

    async fn delete_expired(&self, collection: &str, now: i64) -> Result<(), StoreError> {
        if let Some(c) = self.collections.lock().get_mut(collection) {
            c.retain(|_, (_, p)| p.expires_at > now);
        }
        Ok(())
    }

    async fn delete_tenant(&self, collection: &str, tenant: &str) -> Result<(), StoreError> {
        if let Some(c) = self.collections.lock().get_mut(collection) {
            c.retain(|_, (_, p)| p.tenant_id != tenant);
        }
        Ok(())
    }
}
