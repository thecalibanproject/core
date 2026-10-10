//! T2 semantic cache: answers a request with the response to an earlier, semantically similar
//! request of the **same tenant**.
//!
//! What may be compared (the "partition", all exact matches):
//! - tenant (also a mandatory store filter), routed model and response shape;
//! - a hash of the whole protected request **except the last user message**: system prompt,
//!   earlier turns, sampling and output parameters, so different system prompts, histories or
//!   temperatures never share answers (MeanCache's context chains, arXiv 2403.02694);
//! - the guard [`Signature`] of the last user message ([`guard`]): its slots in order (numbers,
//!   dates and IDs, currency codes, units, languages, codes and capitalised names: "Q3 2025" never
//!   matches "Q3 2026", "USD to EUR" never matches "EUR to USD", "into Spanish" never matches
//!   "into Italian") and its modifier classes ("briefly" never matches "in detail", "enable"
//!   never matches "disable", a negation never matches its absence) and its date and time
//!   format specs (`YYYY-MM-DD` never matches `DD/MM/YYYY`);
//! - the instruction prefix the prompt was embedded with (`[cache.semantic] query_prefix`), so
//!   vectors from different instructions are never compared;
//! - the set of PII surrogates in the request (tenant-scoped surrogates are deterministic, so
//!   the same people and accounts give the same set; a cached answer about someone else is never
//!   served, and every surrogate in a hit is restorable with the hitting request's vault);
//! - the PII mode.
//!
//! What is embedded: the last user message in surrogate form. Within a partition the nearest
//! entries are judged by the per-entry threshold policy in [`policy`].

pub mod guard;
pub mod policy;
pub mod qdrant;
pub mod store;

pub use guard::{Signature, signature};
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
    /// Instruction prepended to `prompt` before embedding (`""` when none).
    pub embed_prefix: &'a str,
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
        // v3: guard format specs, possessives and inflections (v2: ordered guard slots and modifier
        // classes; v1 hashed sorted numeric tokens only). A new version never compares with
        // entries written under an older one.
        h.update(b"caliban/t2/v3\0");
        h.update(p.tenant.as_str().as_bytes());
        h.update(&[0]);
        h.update(route.as_bytes());
        h.update(&[0]);
        h.update(p.context_hash.as_bytes());
        h.update(&(p.embed_prefix.len() as u64).to_le_bytes());
        h.update(p.embed_prefix.as_bytes());
        let sig = guard::signature(p.prompt);
        for s in &sig.slots {
            h.update(s.as_bytes());
            h.update(&[0]);
        }
        h.update(&[1]);
        h.update(&sig.modifiers.to_le_bytes());
        for f in &sig.formats {
            h.update(f.as_bytes());
            h.update(&[0]);
        }
        h.update(&[2]);
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

/// `{prefix}_{model}_{dim}`, with characters outside `[a-z0-9_-]` replaced by `_`.
pub fn collection_name(prefix: &str, embedding_model: &str, dim: usize) -> String {
    let model: String = embedding_model
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
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
        Self {
            store,
            prefix: prefix.into(),
            budgets: Mutex::new(HashMap::new()),
            last_sweep: Mutex::new(HashMap::new()),
        }
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
    pub async fn lookup(
        &self,
        key: &SemanticKey,
        embedding_model: &str,
        vector: &[f32],
        policy: &ThresholdPolicy,
        draw: f32,
        now: i64,
    ) -> Result<Lookup, StoreError> {
        let collection = self.collection(embedding_model, vector.len());
        let q = SearchQuery {
            collection: &collection,
            tenant: &key.tenant,
            partition: &key.partition,
            vector,
            limit: CANDIDATES,
            now,
        };
        let candidates = self.store.search(&q).await?;
        let offset = self.tenant_offset(&key.tenant);
        let mut verify = None;
        for c in candidates {
            if c.payload.tenant_id != key.tenant {
                continue; // never trust a store that ignored the filter
            }
            let m = |kind| Match {
                collection: collection.clone(),
                id: c.id.clone(),
                similarity: c.score,
                verify: kind,
                payload: c.payload.clone(),
            };
            match policy::decide(policy, &c.payload.stats, c.score, offset, draw) {
                Decision::Serve => return Ok(Lookup::Hit(m(None))),
                Decision::Verify(kind) if verify.is_none() => verify = Some(m(Some(kind))),
                Decision::Verify(_) | Decision::Miss => {}
            }
        }
        Ok(verify.map_or(Lookup::Miss, Lookup::Verify))
    }

    /// Stores a response under `key`. Also sweeps expired entries of the collection now and then.
    pub async fn insert(
        &self,
        key: &SemanticKey,
        embedding_model: &str,
        vector: &[f32],
        entry: NewEntry,
        policy: &ThresholdPolicy,
        now: i64,
    ) -> Result<(), StoreError> {
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
    pub async fn record_verification(
        &self,
        m: &Match,
        correct: bool,
        policy: &ThresholdPolicy,
    ) -> Result<EntryStats, StoreError> {
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

    /// Deletes a tenant's entries from every collection of this cache (`{prefix}_*`), whatever
    /// embedding model and dimension wrote them. Returns the number of collections visited.
    /// Idempotent: purging a tenant with no entries is a no-op, so several routers may purge the
    /// same tenant.
    pub async fn purge_tenant_everywhere(&self, tenant: &str) -> Result<usize, StoreError> {
        let own = format!("{}_", self.prefix);
        let collections: Vec<String> =
            self.store.list_collections().await?.into_iter().filter(|c| c.starts_with(&own)).collect();
        for c in &collections {
            self.store.delete_tenant(c, tenant).await?;
        }
        Ok(collections.len())
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
            embed_prefix: "",
        })
    }

    fn entry(ttl_secs: u64) -> NewEntry {
        NewEntry { model: "ext/mock".into(), response: "{}".into(), prompt_tokens: 3, completion_tokens: 4, ttl_secs }
    }

    const P: ThresholdPolicy = ThresholdPolicy {
        threshold: 0.95,
        min_threshold: 0.90,
        grey_band: 0.03,
        max_error_rate: 0.02,
        verify_rate: 0.0,
    };

    #[test]
    fn partition_separates_tenants_context_numbers_and_people() {
        let a = key("a", "revenue in Q3 2025?", b"sys");
        assert_eq!(
            a.partition,
            key("a", "what was revenue in Q3 2025", b"sys").partition,
            "same slots, wording may differ"
        );
        assert_ne!(a.partition, key("b", "revenue in Q3 2025?", b"sys").partition, "tenant");
        assert_ne!(
            a.partition,
            key("a", "revenue in Q3 2025?", b"other system prompt").partition,
            "context and params"
        );
        assert_ne!(a.partition, key("a", "revenue in Q3 2026?", b"sys").partition, "numbers must match");
        assert_ne!(a.point_id, key("a", "what was revenue in Q3 2025", b"sys").point_id, "one point per prompt");
        assert_eq!(a.point_id, key("a", "revenue in Q3 2025?", b"sys").point_id);

        let t: TenantId = "a".into();
        let with = |s: &[&str]| {
            SemanticKey::new(&KeyParts {
                tenant: &t,
                model: "m",
                shape: ResponseShape::Openai,
                context_hash: blake3::hash(b"x"),
                prompt: "email them",
                surrogates: s,
                pii_mode: PiiMode::Reversible,
                embed_prefix: "",
            })
            .partition
        };
        assert_eq!(with(&["Ann Lee", "a@x.io"]), with(&["a@x.io", "ann lee"]));
        assert_ne!(with(&["Ann Lee"]), with(&["Bob Ray"]), "a different person never shares an answer");
    }

    #[test]
    fn partition_separates_the_aws_false_hits_and_keeps_paraphrases() {
        let p = |prompt: &str| key("a", prompt, b"sys").partition;
        // The three false hits of the AWS run (bench/RESULTS-aws-2026-10.md).
        assert_ne!(p("Translate 'good morning' into Spanish."), p("Translate 'good morning' into Italian."));
        assert_ne!(p("Convert 100 USD to EUR."), p("Convert 100 EUR to USD."));
        assert_ne!(p("Explain the CAP theorem briefly."), p("Explain the CAP theorem in detail."));
        // Paraphrases still share a partition (the threshold decides).
        assert_eq!(p("Translate 'good morning' into Spanish."), p("How do you say 'good morning' in Spanish?"));
        assert_eq!(p("Convert 100 USD to EUR."), p("How much is 100 USD in EUR?"));
        assert_eq!(p("Explain the CAP theorem briefly."), p("Give me a brief explanation of the CAP theorem."));
        // Second AWS run (bench/RESULTS-aws-2026-10b.md): possessives, inflections and format specs.
        assert_eq!(p("What is the VAT rate in Germany?"), p("What's Germany's VAT rate?"));
        assert_eq!(
            p("Who approves expense reports over 5000 EUR?"),
            p("Who has to approve expense reports above 5000 EUR?")
        );
        assert_eq!(
            p("How do I format a date as YYYY-MM-DD in JavaScript?"),
            p("In JavaScript, how can I format a date as YYYY-MM-DD?")
        );
        assert_ne!(p("Format a date as DD/MM/YYYY"), p("Format a date as MM/DD/YYYY"), "format specs must match");
        assert_ne!(p("Show orders over 5"), p("Show orders under 5"));
    }

    #[test]
    fn embedding_prefix_is_part_of_the_partition() {
        let t: TenantId = "a".into();
        let with = |prefix: &str| {
            SemanticKey::new(&KeyParts {
                tenant: &t,
                model: "m",
                shape: ResponseShape::Openai,
                context_hash: blake3::hash(b"x"),
                prompt: "hi",
                surrogates: &[],
                pii_mode: PiiMode::Reversible,
                embed_prefix: prefix,
            })
            .partition
        };
        assert_ne!(with(""), with("Instruct: same question\nQuery: "));
    }

    #[test]
    fn collection_names_are_safe() {
        assert_eq!(
            collection_name("caliban_semcache", "local/Qwen3-Embed:0.6B", 1024),
            "caliban_semcache_local_qwen3-embed_0_6b_1024"
        );
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
    async fn purge_everywhere_removes_one_tenant_from_every_own_collection() {
        let store = Arc::new(MemoryStore::default());
        let c = SemanticCache::new(store.clone(), "t");
        // Two embedding models (an old and a new `embedding_model`), two tenants.
        for (tenant, model, v) in
            [("a", "emb", vec![1.0f32, 0.0]), ("a", "emb2", vec![1.0, 0.0, 0.0]), ("b", "emb", vec![0.0, 1.0])]
        {
            c.insert(&key(tenant, "hi", b""), model, &v, entry(60), &P, 1000).await.unwrap();
        }
        // Another deployment's collection in the same store is left alone.
        let other = SemanticCache::new(store.clone(), "u");
        other.insert(&key("a", "hi", b""), "emb", &[1.0, 0.0], entry(60), &P, 1000).await.unwrap();

        assert_eq!(c.purge_tenant_everywhere("a").await.unwrap(), 2);
        let left: Vec<(String, String)> = {
            let mut l: Vec<_> = store.entries().into_iter().map(|(col, _, p)| (col, p.tenant_id)).collect();
            l.sort();
            l
        };
        assert_eq!(left, [("t_emb_2".to_owned(), "b".to_owned()), ("u_emb_2".to_owned(), "a".to_owned())]);
        assert_eq!(c.purge_tenant_everywhere("a").await.unwrap(), 2, "idempotent");
        assert_eq!(store.len(), 2);
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
        let Lookup::Verify(m) = c.lookup(&k, "emb", &near, &P, 0.5, 1001).await.unwrap() else {
            panic!("still grey after one")
        };
        let stats = c.record_verification(&m, true, &P).await.unwrap();
        assert_eq!(stats.verified_ok, 2);
        let Lookup::Hit(m) = c.lookup(&k, "emb", &near, &P, 0.5, 1001).await.unwrap() else {
            panic!("learned threshold now serves it")
        };
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
