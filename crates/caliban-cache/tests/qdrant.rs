//! T2 store against a real Qdrant. Skipped unless `CALIBAN_TEST_QDRANT_URL` is set, e.g.
//!
//! ```sh
//! docker run -d --name caliban-qdrant-test -p 6333:6333 qdrant/qdrant:v1.19.1-unprivileged
//! CALIBAN_TEST_QDRANT_URL=http://127.0.0.1:6333 cargo test -p caliban-cache --test qdrant -- --nocapture
//! ```

use caliban_cache::semantic::{
    EntryPayload, EntryStats, KeyParts, Lookup, NewEntry, QdrantStore, ResponseShape, SearchQuery, SemanticCache, SemanticKey, ThresholdPolicy, VectorStore,
};
use caliban_types::{PiiMode, TenantId};
use std::sync::Arc;
use std::time::Instant;

fn url() -> Option<String> {
    std::env::var("CALIBAN_TEST_QDRANT_URL").ok().filter(|u| !u.is_empty())
}

fn prefix() -> String {
    format!("caltest_{}", uuid::Uuid::new_v4().simple())
}

async fn drop_collections(base: &str, prefix: &str) {
    let http = reqwest::Client::new();
    let v: serde_json::Value = http.get(format!("{base}/collections")).send().await.unwrap().json().await.unwrap();
    for c in v["result"]["collections"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        if name.starts_with(prefix) {
            http.delete(format!("{base}/collections/{name}")).send().await.unwrap();
        }
    }
}

fn key(tenant: &str, prompt: &str) -> SemanticKey {
    let t: TenantId = tenant.into();
    SemanticKey::new(&KeyParts {
        tenant: &t,
        model: "ext/mock",
        shape: ResponseShape::Openai,
        context_hash: blake3::hash(b"system prompt + params"),
        prompt,
        surrogates: &[],
        pii_mode: PiiMode::Reversible,
    })
}

fn unit(seed: u64, dim: usize) -> Vec<f32> {
    // xorshift; deterministic pseudo-random unit vector.
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut v: Vec<f32> = (0..dim)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            #[allow(clippy::cast_precision_loss)]
            let f = (x % 2000) as f32 / 1000.0 - 1.0;
            f
        })
        .collect();
    let n = v.iter().map(|a| a * a).sum::<f32>().sqrt();
    v.iter_mut().for_each(|a| *a /= n);
    v
}

/// Digit-free text for `i`, so every prompt of a tenant lands in the same partition.
fn words(i: usize) -> String {
    i.to_string().chars().map(|d| char::from(b'a' + d.to_digit(10).unwrap() as u8)).collect()
}

const P: ThresholdPolicy = ThresholdPolicy { threshold: 0.95, min_threshold: 0.90, grey_band: 0.03, max_error_rate: 0.02, verify_rate: 0.0 };

fn entry(text: &str) -> NewEntry {
    NewEntry { model: "ext/mock".into(), response: format!("{{\"answer\":\"{text}\"}}"), prompt_tokens: 10, completion_tokens: 5, ttl_secs: 3600 }
}

#[tokio::test]
async fn qdrant_store_isolates_tenants_and_learns() {
    let Some(base) = url() else {
        eprintln!("CALIBAN_TEST_QDRANT_URL not set; skipping");
        return;
    };
    let prefix = prefix();
    let store = Arc::new(QdrantStore::new(&base, None).unwrap());
    let cache = SemanticCache::new(store.clone(), prefix.clone());
    let now = 1_900_000_000;
    let v = unit(1, 64);

    // Missing collection: a miss, not an error.
    assert_eq!(cache.lookup(&key("acme", "refund policy?"), "emb", &v, &P, 0.5, now).await.unwrap(), Lookup::Miss);

    let ka = key("acme", "refund policy?");
    cache.insert(&ka, "emb", &v, entry("acme answer"), &P, now).await.unwrap();
    let Lookup::Hit(m) = cache.lookup(&ka, "emb", &v, &P, 0.5, now + 1).await.unwrap() else { panic!("identical vector hits") };
    assert!(m.similarity > 0.999);
    assert_eq!(m.payload.tenant_id, "acme");
    assert!(m.payload.response.contains("acme answer"));

    // Tenant B, identical prompt and vector: never sees tenant A's entry.
    let kb = key("globex", "refund policy?");
    assert_eq!(cache.lookup(&kb, "emb", &v, &P, 0.5, now + 1).await.unwrap(), Lookup::Miss);
    // Not even with A's partition: the tenant filter is in the query itself.
    let forged = SemanticKey { tenant: "globex".into(), ..ka.clone() };
    assert_eq!(cache.lookup(&forged, "emb", &v, &P, 0.5, now + 1).await.unwrap(), Lookup::Miss);
    let collection = cache.collection("emb", v.len());
    let raw = store.search(&SearchQuery { collection: &collection, tenant: "globex", partition: &ka.partition, vector: &v, limit: 10, now }).await.unwrap();
    assert!(raw.is_empty(), "{raw:?}");

    // B's own entry is separate; A still gets its own answer.
    cache.insert(&kb, "emb", &v, entry("globex answer"), &P, now).await.unwrap();
    let Lookup::Hit(mb) = cache.lookup(&kb, "emb", &v, &P, 0.5, now + 1).await.unwrap() else { panic!() };
    assert!(mb.payload.response.contains("globex answer"));
    let Lookup::Hit(ma) = cache.lookup(&ka, "emb", &v, &P, 0.5, now + 1).await.unwrap() else { panic!() };
    assert!(ma.payload.response.contains("acme answer"));

    // Stats updates are tenant-scoped: a forged update for B on A's point is a no-op.
    let bogus = EntryStats { hits: 999, ..Default::default() };
    store.update_stats(&collection, "globex", &ma.id, &bogus, 0.5).await.unwrap();
    cache.record_hit(&ma, &P).await.unwrap();
    let Lookup::Hit(ma) = cache.lookup(&ka, "emb", &v, &P, 0.5, now + 1).await.unwrap() else { panic!() };
    assert_eq!(ma.payload.stats.hits, 1);

    // TTL: expired entries are filtered out.
    assert_eq!(cache.lookup(&ka, "emb", &v, &P, 0.5, now + 3600).await.unwrap(), Lookup::Miss);

    // Grey zone and learning, persisted in the payload.
    let kg = key("acme", "grey");
    let base_v = unit(7, 64);
    cache.insert(&kg, "emb", &base_v, entry("g"), &P, now).await.unwrap();
    let near: Vec<f32> = {
        // cos(base, near) = 0.93
        let o = unit(8, 64);
        let d: f32 = o.iter().zip(&base_v).map(|(a, b)| a * b).sum();
        let mut perp: Vec<f32> = o.iter().zip(&base_v).map(|(a, b)| a - d * b).collect();
        let n = perp.iter().map(|a| a * a).sum::<f32>().sqrt();
        perp.iter_mut().for_each(|a| *a /= n);
        base_v.iter().zip(&perp).map(|(b, p)| 0.93 * b + (1.0f32 - 0.93 * 0.93).sqrt() * p).collect()
    };
    for _ in 0..2 {
        let Lookup::Verify(m) = cache.lookup(&kg, "emb", &near, &P, 0.5, now + 1).await.unwrap() else { panic!("grey zone") };
        cache.record_verification(&m, true, &P).await.unwrap();
    }
    let Lookup::Hit(m) = cache.lookup(&kg, "emb", &near, &P, 0.5, now + 1).await.unwrap() else { panic!("learned") };
    assert!((m.payload.threshold - 0.93).abs() < 0.01, "{}", m.payload.threshold);

    // Offboarding.
    cache.purge_tenant("acme", "emb", &[64]).await.unwrap();
    assert_eq!(cache.lookup(&kg, "emb", &near, &P, 0.5, now + 1).await.unwrap(), Lookup::Miss);
    assert!(matches!(cache.lookup(&kb, "emb", &v, &P, 0.5, now + 1).await.unwrap(), Lookup::Hit(_)));

    // Offboarding from every collection (as the data plane does when a snapshot drops a tenant):
    // globex also has an entry under a second embedding model.
    let v32 = unit(9, 32);
    cache.insert(&kb, "emb2", &v32, entry("globex answer, other model"), &P, now).await.unwrap();
    assert!(matches!(cache.lookup(&kb, "emb2", &v32, &P, 0.5, now + 1).await.unwrap(), Lookup::Hit(_)));
    assert_eq!(cache.purge_tenant_everywhere("globex").await.unwrap(), 2);
    assert_eq!(cache.lookup(&kb, "emb", &v, &P, 0.5, now + 1).await.unwrap(), Lookup::Miss);
    assert_eq!(cache.lookup(&kb, "emb2", &v32, &P, 0.5, now + 1).await.unwrap(), Lookup::Miss);

    drop_collections(&base, &prefix).await;
}

/// Search latency with 1,024-d vectors (Qwen3-Embedding-0.6B's size) and many tenants.
#[tokio::test]
async fn qdrant_lookup_latency() {
    let Some(base) = url() else {
        eprintln!("CALIBAN_TEST_QDRANT_URL not set; skipping");
        return;
    };
    let prefix = prefix();
    let store = Arc::new(QdrantStore::new(&base, None).unwrap());
    let cache = SemanticCache::new(store.clone(), prefix.clone());
    let dim = 1024;
    let now = 1_900_000_000;
    let tenants = 20;
    let per_tenant = 100;
    let started = Instant::now();
    for t in 0..tenants {
        for i in 0..per_tenant {
            let k = key(&format!("t{t}"), &format!("question {}", words(i)));
            cache.insert(&k, "emb", &unit((t * 10_000 + i) as u64, dim), entry("a"), &P, now).await.unwrap();
        }
    }
    let n_points = tenants * per_tenant;
    eprintln!("inserted {n_points} points in {:?} (wait=true, sequential)", started.elapsed());

    let mut samples = Vec::new();
    for i in 0..300u64 {
        let k = key(&format!("t{}", i % tenants as u64), &format!("question {}", words((i % per_tenant as u64) as usize)));
        let v = unit(i + 1_000_000, dim);
        let t0 = Instant::now();
        let _ = cache.lookup(&k, "emb", &v, &P, 0.5, now + 1).await.unwrap();
        samples.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    let pct = |p: f64| samples[((samples.len() as f64 - 1.0) * p) as usize];
    eprintln!("qdrant lookup (filter tenant+partition, 1024-d, {n_points} points, {per_tenant} per partition): p50 {:.2} ms, p90 {:.2} ms, p99 {:.2} ms", pct(0.5), pct(0.9), pct(0.99));
    assert!(pct(0.5) < 50.0, "lookup p50 within the default budget");

    // A payload matching another tenant's partition never leaks: sanity on the bulk data.
    let probe: EntryPayload = store
        .search(&SearchQuery { collection: &cache.collection("emb", dim), tenant: "t1", partition: &key("t1", &format!("question {}", words(1))).partition, vector: &unit(10_001, dim), limit: 1, now })
        .await
        .unwrap()
        .remove(0)
        .payload;
    assert_eq!(probe.tenant_id, "t1");
    drop_collections(&base, &prefix).await;
}
