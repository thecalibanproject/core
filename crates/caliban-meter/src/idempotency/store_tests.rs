//! One suite for every [`IdempotencyStore`]: always against [`MemoryIdempotency`], and against
//! Valkey when `CALIBAN_TEST_VALKEY_URL` is set (e.g. `redis://127.0.0.1:6379`), plus
//! Valkey-only tests (two routers racing for one key, the fallback when Valkey is unreachable).
//! Each Valkey test uses its own random key prefix.

use super::*;
use crate::quota::valkey::ValkeyOptions;
use std::sync::Arc;

fn response(body: &str) -> StoredResponse {
    StoredResponse { status: 200, headers: vec![("content-type".into(), "application/json".into())], body: body.into() }
}

fn started(b: Begin) -> Lease {
    match b {
        Begin::Started(l) => l,
        other => panic!("expected to start, got {other:?}"),
    }
}

async fn suite(s: &dyn IdempotencyStore) {
    // First request runs; a duplicate while it runs is refused.
    let lease = started(s.begin("t1", "k1", "fp-a").await.unwrap());
    assert_eq!(s.begin("t1", "k1", "fp-a").await.unwrap(), Begin::InProgress);
    // The same key with another request.
    assert_eq!(s.begin("t1", "k1", "fp-b").await.unwrap(), Begin::Mismatch);
    // Keys are per tenant.
    let other = started(s.begin("t2", "k1", "fp-b").await.unwrap());
    s.release(&other).await;

    // Completed: replayed, still checked against the fingerprint.
    s.complete(&lease, Some(response(r#"{"ok":true}"#))).await;
    assert_eq!(s.begin("t1", "k1", "fp-a").await.unwrap(), Begin::Replay(Some(response(r#"{"ok":true}"#))));
    assert_eq!(s.begin("t1", "k1", "fp-b").await.unwrap(), Begin::Mismatch);
    // A completed record cannot be released or completed again by the old lease.
    s.release(&lease).await;
    s.complete(&lease, Some(response("other"))).await;
    assert_eq!(s.begin("t1", "k1", "fp-a").await.unwrap(), Begin::Replay(Some(response(r#"{"ok":true}"#))));

    // Released (the request failed): the next attempt runs.
    let failed = started(s.begin("t1", "k2", "fp").await.unwrap());
    s.release(&failed).await;
    let retry = started(s.begin("t1", "k2", "fp").await.unwrap());
    assert_ne!(retry.token, failed.token);
    // The old lease cannot touch the new claim.
    s.complete(&failed, Some(response("stale"))).await;
    s.release(&failed).await;
    assert_eq!(s.begin("t1", "k2", "fp").await.unwrap(), Begin::InProgress);

    // Too large to keep: completed without a body.
    let big = started(s.begin("t1", "k3", "fp").await.unwrap());
    s.complete(&big, Some(response(&"x".repeat(MAX_STORED_BYTES + 1)))).await;
    assert_eq!(s.begin("t1", "k3", "fp").await.unwrap(), Begin::Replay(None));
}

#[tokio::test]
async fn memory_suite() {
    suite(&MemoryIdempotency::default()).await;
}

#[tokio::test]
async fn memory_leases_and_records_expire_and_the_budget_evicts_done_records() {
    let s = MemoryIdempotency::new(Duration::from_millis(30), Duration::from_millis(60), 10_000);
    let stale = started(s.begin("t", "k", "fp").await.unwrap());
    tokio::time::sleep(Duration::from_millis(40)).await;
    // The lease expired (its router died): the key can be claimed again.
    let fresh = started(s.begin("t", "k", "fp").await.unwrap());
    s.complete(&stale, Some(response("stale"))).await;
    assert_eq!(s.begin("t", "k", "fp").await.unwrap(), Begin::InProgress, "the stale lease changed nothing");
    s.complete(&fresh, Some(response("fresh"))).await;
    assert_eq!(s.begin("t", "k", "fp").await.unwrap(), Begin::Replay(Some(response("fresh"))));
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert!(matches!(s.begin("t", "k", "fp").await.unwrap(), Begin::Started(_)), "replay window over");

    // Budget: 10 kB; two 4 kB records fit, a third evicts the oldest.
    for k in ["a", "b", "c"] {
        let l = started(s.begin("t", k, "fp").await.unwrap());
        s.complete(&l, Some(response(&"y".repeat(4000)))).await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(matches!(s.begin("t", "a", "fp").await.unwrap(), Begin::Started(_)), "evicted");
    assert!(matches!(s.begin("t", "c", "fp").await.unwrap(), Begin::Replay(Some(_))));
}

fn valkey_url() -> Option<String> {
    let url = std::env::var("CALIBAN_TEST_VALKEY_URL").ok().filter(|u| !u.is_empty());
    if url.is_none() {
        eprintln!("skipped: set CALIBAN_TEST_VALKEY_URL to run the Valkey idempotency tests");
    }
    url
}

fn valkey(url: &str, prefix: &str) -> ValkeyIdempotency {
    let mut o = ValkeyOptions::new(url);
    o.key_prefix = prefix.to_owned();
    o.timeout = Duration::from_millis(500);
    ValkeyIdempotency::new(&o).unwrap()
}

fn prefix() -> String {
    format!("caliban-test-{}", uuid::Uuid::new_v4().simple())
}

#[tokio::test]
async fn valkey_suite() {
    let Some(url) = valkey_url() else { return };
    suite(&valkey(&url, &prefix())).await;
    suite(&FallbackIdempotency::new(valkey(&url, &prefix()))).await;
}

/// Routers sharing Valkey: of many concurrent first requests with one key, exactly one runs.
#[tokio::test]
async fn valkey_one_claim_across_routers() {
    let Some(url) = valkey_url() else { return };
    let p = prefix();
    let stores: Vec<Arc<ValkeyIdempotency>> = (0..4).map(|_| Arc::new(valkey(&url, &p))).collect();
    let mut tasks = Vec::new();
    for i in 0..32 {
        let s = Arc::clone(&stores[i % stores.len()]);
        tasks.push(tokio::spawn(async move { s.begin("t", "same", "fp").await.unwrap() }));
    }
    let mut started_n = 0;
    for t in tasks {
        match t.await.unwrap() {
            Begin::Started(_) => started_n += 1,
            Begin::InProgress => {}
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(started_n, 1);
}

/// Valkey unreachable: keys are still deduplicated on this router.
#[tokio::test]
async fn fallback_deduplicates_locally_while_valkey_is_down() {
    let mut o = ValkeyOptions::new("redis://127.0.0.1:1/0");
    o.timeout = Duration::from_millis(50);
    let s = FallbackIdempotency::with_retry_after(ValkeyIdempotency::new(&o).unwrap(), Duration::from_secs(60));
    let lease = started(s.begin("t", "k", "fp").await.unwrap());
    assert!(lease.local);
    assert_eq!(s.begin("t", "k", "fp").await.unwrap(), Begin::InProgress);
    s.complete(&lease, Some(response("ok"))).await;
    assert_eq!(s.begin("t", "k", "fp").await.unwrap(), Begin::Replay(Some(response("ok"))));
    assert_eq!(s.local().len(), 1);
}
