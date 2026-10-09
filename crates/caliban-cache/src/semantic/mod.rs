//! T2 semantic cache: answers a request with the response to an earlier, semantically similar
//! request of the **same tenant**.
//!
//! What may be compared (the "partition", all exact matches):
//! - tenant (also a mandatory store filter), routed model and response shape;
//! - a hash of the whole protected request **except the last user message**: system prompt,
//!   earlier turns, sampling and output parameters, so different system prompts, histories or
//!   temperatures never share answers (MeanCache's context chains, arXiv 2403.02694);
//! - the numeric tokens of the last user message ("Q3 2025" never matches "Q3 2026");
//! - the set of PII surrogates in the request (tenant-scoped surrogates are deterministic, so
//!   the same people and accounts give the same set; a cached answer about someone else is never
//!   served, and every surrogate in a hit is restorable with the hitting request's vault);
//! - the PII mode.
//!
//! What is embedded: the last user message in surrogate form. Within a partition the nearest
//! entries are judged by the per-entry threshold policy in [`policy`].

pub mod policy;
pub mod qdrant;
pub mod store;

pub use policy::{Decision, EntryStats, ThresholdPolicy, VerifyKind};
pub use qdrant::QdrantStore;
pub use store::{Candidate, EntryPayload, MemoryStore, ResponseShape, SearchQuery, StoreError, VectorStore};

use caliban_types::{PiiMode, TenantId};
use parking_lot::Mutex;
use policy::TenantBudget;
use std::collections::HashMap;
use std::sync::Arc;

/// Nearest entries examined per lookup (a lower-ranked entry may have a lower learned threshold).
const CANDIDATES: usize = 3;
/// Expired entries are swept at most this often per collection (seconds).
const SWEEP_EVERY_SECS: i64 = 600;

/// Inputs that decide which earlier requests a request may be compared with.
#[derive(Debug, Clone, Copy)]
pub struct KeyParts<'a> {
    pub tenant: &'a TenantId,
    /// Catalogue id of the routed model.
    pub model: &'a str,
    pub shape: ResponseShape,
    /// Hash of the protected upstream request without the last user message's content.
    pub context_hash: blake3::Hash,
    /// The last user message, in surrogate form (the text that is embedded).
    pub prompt: &'a str,
    /// PII surrogates present in the request (any order).
    pub surrogates: &'a [&'a str],
    pub pii_mode: PiiMode,
}

/// Derived identifiers of one request's T2 key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticKey {
    pub tenant: String,
    pub route: String,
    pub shape: ResponseShape,
    pub params_hash: String,
    pub partition: String,
    /// Deterministic point id (UUID text): the same prompt in the same partition upserts the same
    /// entry instead of piling up duplicates.
    pub point_id: String,
}

impl SemanticKey {
    pub fn new(p: &KeyParts<'_>) -> Self {
        let route = format!("{}|{}", p.model, p.shape.as_str());
        let mut h = blake3::Hasher::new();
        h.update(b"caliban/t2/v1\0");
        h.update(p.tenant.as_str().as_bytes());
        h.update(&[0]);
        h.update(route.as_bytes());
        h.update(&[0]);
        h.update(p.context_hash.as_bytes());
        for s in numeric_slots(p.prompt) {
            h.update(s.as_bytes());
            h.update(&[0]);
        }
        h.update(&[1]);
        let mut surrogates: Vec<String> = p.surrogates.iter().map(|s| s.to_lowercase()).collect();
        surrogates.sort_unstable();
        surrogates.dedup();
        for s in &surrogates {
            h.update(s.as_bytes());
            h.update(&[0]);
        }
        h.update(&[p.pii_mode as u8]);
        let partition = h.finalize();
        let mut id = blake3::Hasher::new();
        id.update(partition.as_bytes());
        id.update(p.prompt.as_bytes());
        let id = id.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&id.as_bytes()[..16]);
        Self {
            tenant: p.tenant.to_string(),
            route,
            shape: p.shape,
            params_hash: p.context_hash.to_hex().to_string(),
            partition: partition.to_hex().to_string(),
            point_id: uuid::Uuid::from_bytes(b).to_string(),
        }
    }
}

/// Lower-cased alphanumeric tokens that contain a digit, sorted: numbers, dates, versions, IDs.
pub fn numeric_slots(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric() && c != '.' && c != ',')
        .map(|t| t.trim_matches(|c| c == '.' || c == ','))
        .filter(|t| t.chars().any(|c| c.is_ascii_digit()))
        .map(str::to_lowercase)
        .collect();
    v.sort_unstable();
    v
}

/// `{prefix}_{model}_{dim}`, with characters outside `[a-z0-9_-]` replaced by `_`.
pub fn collection_name(prefix: &str, embedding_model: &str, dim: usize) -> String {
    let model: String = embedding_model.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    format!("{prefix}_{model}_{dim}")
}

/// A candidate the policy accepted for serving or for verification.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub collection: String,
    pub id: String,
    pub similarity: f32,
    /// `None` for a hit to serve.
    pub verify: Option<VerifyKind>,
    pub payload: EntryPayload,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Lookup {
    /// Serve this entry.
    Hit(Match),
    /// Answer fresh, then compare the fresh answer with this entry's.
    Verify(Match),
    Miss,
}

/// A response to cache.
#[derive(Debug, Clone)]
pub struct NewEntry {
    pub model: String,
    /// JSON body, pseudonymised.
    pub response: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub ttl_secs: u64,
}

/// The T2 cache over a [`VectorStore`], with per-tenant error budgets (process-local).
pub struct SemanticCache {
    store: Arc<dyn VectorStore>,
    prefix: String,
    budgets: Mutex<HashMap<String, TenantBudget>>,
    last_sweep: Mutex<HashMap<String, i64>>,
}

impl SemanticCache {
    pub fn new(store: Arc<dyn VectorStore>, prefix: impl Into<String>) -> Self {
        Self { store, prefix: prefix.into(), budgets: Mutex::new(HashMap::new()), last_sweep: Mutex::new(HashMap::new()) }
    }

    pub fn store(&self) -> &Arc<dyn VectorStore> {
        &self.store
    }

    pub fn collection(&self, embedding_model: &str, dim: usize) -> String {
        collection_name(&self.prefix, embedding_model, dim)
    }

    /// Current tightening of a tenant's thresholds.
    pub fn tenant_offset(&self, tenant: &str) -> f32 {
        self.budgets.lock().get(tenant).map_or(0.0, TenantBudget::offset)
    }

    /// Finds the best entry for `vector` among the tenant's peers. `draw` is uniform in `[0, 1)`
    /// (exploration); `now` is unix seconds.
    pub async fn lookup(&self, key: &SemanticKey, embedding_model: &str, vector: &[f32], policy: &ThresholdPolicy, draw: f32, now: i64) -> Result<Lookup, StoreError> {
        let collection = self.collection(embedding_model, vector.len());
        let q = SearchQuery { collection: &collection, tenant: &key.tenant, partition: &key.partition, vector, limit: CANDIDATES, now };
        let candidates = self.store.search(&q).await?;
        let offset = self.tenant_offset(&key.tenant);
        let mut verify = None;
        for c in candidates {
            if c.payload.tenant_id != key.tenant {
                continue; // never trust a store that ignored the filter
            }
            let m = |kind| Match { collection: collection.clone(), id: c.id.clone(), similarity: c.score, verify: kind, payload: c.payload.clone() };
            match policy::decide(policy, &c.payload.stats, c.score, offset, draw) {
                Decision::Serve => return Ok(Lookup::Hit(m(None))),
                Decision::Verify(kind) if verify.is_none() => verify = Some(m(Some(kind))),
                Decision::Verify(_) | Decision::Miss => {}
            }
        }
        Ok(verify.map_or(Lookup::Miss, Lookup::Verify))
    }

    /// Stores a response under `key`. Also sweeps expired entries of the collection now and then.
    pub async fn insert(&self, key: &SemanticKey, embedding_model: &str, vector: &[f32], entry: NewEntry, policy: &ThresholdPolicy, now: i64) -> Result<(), StoreError> {
        let collection = self.collection(embedding_model, vector.len());
        let payload = EntryPayload {
            tenant_id: key.tenant.clone(),
            route: key.route.clone(),
            partition: key.partition.clone(),
            params_hash: key.params_hash.clone(),
            created_at: now,
            expires_at: now.saturating_add(i64::try_from(entry.ttl_secs).unwrap_or(i64::MAX)),
            model: entry.model,
            shape: key.shape,
            response: entry.response,
            prompt_tokens: entry.prompt_tokens,
            completion_tokens: entry.completion_tokens,
            stats: EntryStats::default(),
            threshold: policy.threshold,
        };
        self.store.upsert(&collection, &key.point_id, vector, &payload).await?;
        let sweep = {
            let mut g = self.last_sweep.lock();
            let last = g.entry(collection.clone()).or_insert(now);
            if now - *last >= SWEEP_EVERY_SECS {
                *last = now;
                true
            } else {
                false
            }
        };
        if sweep {
            self.store.delete_expired(&collection, now).await?;
        }
        Ok(())
    }

    /// Counts a served hit on the entry.
    pub async fn record_hit(&self, m: &Match, policy: &ThresholdPolicy) -> Result<(), StoreError> {
        let mut stats = m.payload.stats.clone();
        stats.hits = stats.hits.saturating_add(1);
        self.store.update_stats(&m.collection, &m.payload.tenant_id, &m.id, &stats, stats.threshold(policy)).await
    }

    /// Records whether the entry's answer was right for a prompt at `m.similarity`. Explore
    /// samples also feed the tenant's error budget. Returns the entry's new stats.
    pub async fn record_verification(&self, m: &Match, correct: bool, policy: &ThresholdPolicy) -> Result<EntryStats, StoreError> {
        let mut stats = m.payload.stats.clone();
        stats.observe(m.similarity, correct);
        if m.verify == Some(VerifyKind::Explore) {
            self.budgets.lock().entry(m.payload.tenant_id.clone()).or_default().observe(correct, policy);
        }
        self.store.update_stats(&m.collection, &m.payload.tenant_id, &m.id, &stats, stats.threshold(policy)).await?;
        Ok(stats)
    }

    /// Deletes a tenant's entries in the collections of `embedding_model` for each dimension given.
    pub async fn purge_tenant(&self, tenant: &str, embedding_model: &str, dims: &[usize]) -> Result<(), StoreError> {
        for d in dims {
            self.store.delete_tenant(&self.collection(embedding_model, *d), tenant).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tenant: &str, prompt: &str, ctx: &[u8]) -> SemanticKey {
        let t: TenantId = tenant.into();
        SemanticKey::new(&KeyParts {
            tenant: &t,
            model: "ext/mock",
            shape: ResponseShape::Openai,
            context_hash: blake3::hash(ctx),
            prompt,
            surrogates: &[],
            pii_mode: PiiMode::Reversible,
        })
    }

    fn entry(ttl_secs: u64) -> NewEntry {
        NewEntry { model: "ext/mock".into(), response: "{}".into(), prompt_tokens: 3, completion_tokens: 4, ttl_secs }
    }

    const P: ThresholdPolicy = ThresholdPolicy { threshold: 0.95, min_threshold: 0.90, grey_band: 0.03, max_error_rate: 0.02, verify_rate: 0.0 };

    #[test]
    fn partition_separates_tenants_context_numbers_and_people() {
        let a = key("a", "revenue in Q3 2025?", b"sys");
        assert_eq!(a.partition, key("a", "what was revenue in Q3 2025", b"sys").partition, "same slots, wording may differ");
        assert_ne!(a.partition, key("b", "revenue in Q3 2025?", b"sys").partition, "tenant");
        assert_ne!(a.partition, key("a", "revenue in Q3 2025?", b"other system prompt").partition, "context and params");
        assert_ne!(a.partition, key("a", "revenue in Q3 2026?", b"sys").partition, "numbers must match");
        assert_ne!(a.point_id, key("a", "what was revenue in Q3 2025", b"sys").point_id, "one point per prompt");
        assert_eq!(a.point_id, key("a", "revenue in Q3 2025?", b"sys").point_id);

        let t: TenantId = "a".into();
        let with = |s: &[&str]| {
            SemanticKey::new(&KeyParts { tenant: &t, model: "m", shape: ResponseShape::Openai, context_hash: blake3::hash(b"x"), prompt: "email them", surrogates: s, pii_mode: PiiMode::Reversible })
                .partition
        };
        assert_eq!(with(&["Ann Lee", "a@x.io"]), with(&["a@x.io", "ann lee"]));
        assert_ne!(with(&["Ann Lee"]), with(&["Bob Ray"]), "a different person never shares an answer");
    }

    #[test]
    fn numeric_slots_keep_numbers_dates_and_ids() {
        assert_eq!(numeric_slots("Revenue for Q3 2025, region EMEA-2 (v1.2)."), ["2", "2025", "q3", "v1.2"]);
        assert!(numeric_slots("what is the capital of france").is_empty());
        assert_eq!(numeric_slots("1,000 or 1000"), vec!["1,000", "1000"]);
    }

    #[test]
    fn collection_names_are_safe() {
        assert_eq!(collection_name("caliban_semcache", "local/Qwen3-Embed:0.6B", 1024), "caliban_semcache_local_qwen3-embed_0_6b_1024");
    }

    #[tokio::test]
    async fn tenant_b_never_gets_tenant_a_entry_for_an_identical_prompt() {
        let store = Arc::new(MemoryStore::default());
        let c = SemanticCache::new(store.clone(), "t");
        let v = [0.6f32, 0.8];
        let ka = key("a", "what is our refund policy?", b"sys");
        c.insert(&ka, "emb", &v, entry(60), &P, 1000).await.unwrap();
        assert!(matches!(c.lookup(&ka, "emb", &v, &P, 0.5, 1001).await.unwrap(), Lookup::Hit(_)));
        let kb = key("b", "what is our refund policy?", b"sys");
        assert_eq!(c.lookup(&kb, "emb", &v, &P, 0.5, 1001).await.unwrap(), Lookup::Miss);
        // Even with tenant B's partition forced to A's, the tenant filter holds.
        let forged = SemanticKey { tenant: "b".into(), ..ka.clone() };
        assert_eq!(c.lookup(&forged, "emb", &v, &P, 0.5, 1001).await.unwrap(), Lookup::Miss);
    }

    #[tokio::test]
    async fn expired_entries_are_not_served_and_get_swept() {
        let store = Arc::new(MemoryStore::default());
        let c = SemanticCache::new(store.clone(), "t");
        let k = key("a", "hi", b"");
        c.insert(&k, "emb", &[1.0, 0.0], entry(10), &P, 1000).await.unwrap();
        assert!(matches!(c.lookup(&k, "emb", &[1.0, 0.0], &P, 0.5, 1009).await.unwrap(), Lookup::Hit(_)));
        assert_eq!(c.lookup(&k, "emb", &[1.0, 0.0], &P, 0.5, 1010).await.unwrap(), Lookup::Miss);
        let k2 = key("a", "hello", b"");
        c.insert(&k2, "emb", &[0.0, 1.0], entry(10_000), &P, 1000 + SWEEP_EVERY_SECS).await.unwrap();
        assert_eq!(store.len(), 1, "the expired entry was swept");
    }

    #[tokio::test]
    async fn verification_feedback_moves_the_entry_threshold() {
        let store = Arc::new(MemoryStore::default());
        let c = SemanticCache::new(store.clone(), "t");
        let k = key("a", "q", b"");
        c.insert(&k, "emb", &[1.0, 0.0], entry(60), &P, 1000).await.unwrap();
        // cos = 0.93: grey zone for a fresh entry.
        let near = [0.93f32, (1.0f32 - 0.93 * 0.93).sqrt()];
        let Lookup::Verify(m) = c.lookup(&k, "emb", &near, &P, 0.5, 1001).await.unwrap() else { panic!("grey zone") };
        assert_eq!(m.verify, Some(VerifyKind::GreyZone));
        c.record_verification(&m, true, &P).await.unwrap();
        let Lookup::Verify(m) = c.lookup(&k, "emb", &near, &P, 0.5, 1001).await.unwrap() else { panic!("still grey after one") };
        let stats = c.record_verification(&m, true, &P).await.unwrap();
        assert_eq!(stats.verified_ok, 2);
        let Lookup::Hit(m) = c.lookup(&k, "emb", &near, &P, 0.5, 1001).await.unwrap() else { panic!("learned threshold now serves it") };
        c.record_hit(&m, &P).await.unwrap();
        let p = store.get(&m.collection, &m.id).unwrap();
        assert_eq!(p.stats.hits, 1);
        assert!((p.threshold - 0.93).abs() < 1e-3, "{}", p.threshold);
        // A wrong answer at 0.97 closes it again (and above).
        let m97 = Match { similarity: 0.97, verify: Some(VerifyKind::Explore), payload: p, ..m };
        c.record_verification(&m97, false, &P).await.unwrap();
        assert!(!matches!(c.lookup(&k, "emb", &near, &P, 0.5, 1001).await.unwrap(), Lookup::Hit(_)));
        assert!(matches!(c.lookup(&k, "emb", &[1.0, 0.0], &P, 0.5, 1001).await.unwrap(), Lookup::Hit(_)));
    }
}
