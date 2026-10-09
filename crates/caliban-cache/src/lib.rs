//! Response caches (docs/research/01-semantic-caching-and-rust-vector-stack.md): T1 exact
//! (below) and T2 semantic ([`semantic`]).
//!
//! Rules that hold for every tier:
//! - **No cross-tenant entries.** The tenant id is part of every key.
//! - Entries grounded in tenant data carry the caller's ACL fingerprint and the datasource
//!   epochs they depend on, so permission or data changes cause misses.
//! - Keys are computed over **pseudonymized** text; hits are rehydrated with the current
//!   request's vault.

use bytes::Bytes;
use caliban_types::{PiiMode, TenantId};
use std::sync::Arc;
use std::time::Duration;

pub mod semantic;

/// Inputs that determine whether two requests may share a cached response.
#[derive(Debug, Clone)]
pub struct CacheKeyParts<'a> {
    pub tenant: &'a TenantId,
    /// `ChatRequest::canonical_hash` of the pseudonymized request with the resolved model.
    pub request_hash: blake3::Hash,
    /// Hash of the (datasource, row/column policy) set the caller is entitled to; empty if ungrounded.
    pub acl_fingerprint: &'a [u8],
    /// `(datasource id, epoch)` pairs the answer depends on, sorted.
    pub datasource_epochs: &'a [(String, u64)],
    pub pii_mode: PiiMode,
}

pub type CacheKey = [u8; 32];

pub fn cache_key(p: &CacheKeyParts<'_>) -> CacheKey {
    let mut h = blake3::Hasher::new();
    h.update(b"caliban/t1/v1\0");
    h.update(p.tenant.as_str().as_bytes());
    h.update(&[0]);
    h.update(p.request_hash.as_bytes());
    h.update(&(p.acl_fingerprint.len() as u64).to_le_bytes());
    h.update(p.acl_fingerprint);
    for (ds, epoch) in p.datasource_epochs {
        h.update(ds.as_bytes());
        h.update(&[0]);
        h.update(&epoch.to_le_bytes());
    }
    h.update(&[p.pii_mode as u8]);
    *h.finalize().as_bytes()
}

/// A cached, still-pseudonymized OpenAI-format response body.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub body: Bytes,
    pub model: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
}

/// T1: exact-match cache. In-process (moka); a shared Valkey tier per tenant is a TODO.
#[derive(Clone)]
pub struct ExactCache {
    inner: moka::future::Cache<CacheKey, Arc<CachedResponse>>,
}

impl ExactCache {
    pub fn new(max_entries: u64, ttl: Duration) -> Self {
        Self { inner: moka::future::Cache::builder().max_capacity(max_entries).time_to_live(ttl).build() }
    }

    pub async fn get(&self, key: &CacheKey) -> Option<Arc<CachedResponse>> {
        self.inner.get(key).await
    }

    pub async fn put(&self, key: CacheKey, value: CachedResponse) {
        self.inner.insert(key, Arc::new(value)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts<'a>(t: &'a TenantId, acl: &'a [u8], eps: &'a [(String, u64)]) -> CacheKeyParts<'a> {
        CacheKeyParts {
            tenant: t,
            request_hash: blake3::hash(b"req"),
            acl_fingerprint: acl,
            datasource_epochs: eps,
            pii_mode: PiiMode::Reversible,
        }
    }

    #[test]
    fn key_changes_with_tenant_acl_and_epoch() {
        let a: TenantId = "a".into();
        let b: TenantId = "b".into();
        let e1 = vec![("dw".to_string(), 1)];
        let e2 = vec![("dw".to_string(), 2)];
        let base = cache_key(&parts(&a, b"acl", &e1));
        assert_ne!(base, cache_key(&parts(&b, b"acl", &e1)), "tenant isolation");
        assert_ne!(base, cache_key(&parts(&a, b"acl2", &e1)), "acl scoping");
        assert_ne!(base, cache_key(&parts(&a, b"acl", &e2)), "datasource invalidation");
        assert_eq!(base, cache_key(&parts(&a, b"acl", &e1)));
    }

    #[tokio::test]
    async fn exact_cache_round_trip() {
        let c = ExactCache::new(10, Duration::from_secs(60));
        let k = [7u8; 32];
        c.put(
            k,
            CachedResponse {
                body: Bytes::from_static(b"{}"),
                model: "m".into(),
                prompt_tokens: 1,
                completion_tokens: 2,
            },
        )
        .await;
        assert_eq!(c.get(&k).await.unwrap().completion_tokens, 2);
    }
}
