use axum::http::HeaderMap;
use caliban_config::{Snapshot, TenantConfig};
use caliban_types::{CalibanError, hash_api_key};

/// An authenticated caller: the tenant and the hash of the key used (for per-key limits; empty
/// for the tenant's own background work).
pub struct Caller<'a> {
    pub tenant: &'a TenantConfig,
    pub key_hash: String,
}

impl Caller<'_> {
    /// The key for per-key limits (`None` for the tenant's own background work).
    pub fn key(&self) -> Option<&str> {
        Some(self.key_hash.as_str()).filter(|k| !k.is_empty())
    }
}

/// A caller authenticated inside this process (a request extension; never set from the network):
/// node workers make their model calls through the pipeline as the run's tenant and invoking API
/// key. The key must still be active in the snapshot, so a revoked key stops its runs' calls.
/// An empty `key_hash` is the tenant's own background work (indexing documents for retrieval):
/// the tenant must be active, and only its tenant-wide limits apply.
#[derive(Debug, Clone)]
pub struct InternalCaller {
    pub tenant: String,
    pub key_hash: String,
    /// The node run the call is for: its usage event is tagged with it.
    pub node: Option<NodeTag>,
    /// What the call does on the tenant's behalf (`rag.ingest`, `rag.search`): the usage event's
    /// `purpose` and intent, so that spend is separable from client calls.
    pub purpose: Option<&'static str>,
}

/// Which node run a model call belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeTag {
    pub node: String,
    pub version: u32,
    pub run_id: String,
    /// `node/<name>@v<N>` when `caliban/auto` started the run (the usage event's `route`).
    pub route: Option<String>,
}

/// The caller of a request: the in-process caller when there is one, else the API key in the
/// headers.
pub fn resolve<'a>(
    snap: &'a Snapshot,
    headers: &HeaderMap,
    internal: Option<&InternalCaller>,
) -> Result<Caller<'a>, CalibanError> {
    let Some(i) = internal else { return caller(snap, headers) };
    if i.key_hash.is_empty() {
        let tenant = snap.tenant(&i.tenant.as_str().into()).ok_or(CalibanError::Unauthenticated)?;
        return Ok(Caller { tenant, key_hash: String::new() });
    }
    let tenant = snap
        .tenant_by_key_hash(&i.key_hash)
        .filter(|t| t.id.as_str() == i.tenant)
        .ok_or(CalibanError::Unauthenticated)?;
    Ok(Caller { tenant, key_hash: i.key_hash.clone() })
}

/// Resolves the tenant API key to a tenant. Accepts `Authorization: Bearer cal_…` (OpenAI SDKs)
/// and `x-api-key: cal_…` (Anthropic SDKs). Only key hashes are stored.
pub fn caller<'a>(snap: &'a Snapshot, headers: &HeaderMap) -> Result<Caller<'a>, CalibanError> {
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let key = bearer
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or(CalibanError::Unauthenticated)?;
    let key_hash = hash_api_key(key);
    let tenant = snap.tenant_by_key_hash(&key_hash).ok_or(CalibanError::Unauthenticated)?;
    // The tenant's eval key only serves evals, inside the worker (P3 decision 9): never a client.
    if tenant.eval_key_hashes.iter().any(|h| h.eq_ignore_ascii_case(&key_hash)) {
        return Err(CalibanError::Unauthenticated);
    }
    Ok(Caller { tenant, key_hash })
}

pub fn tenant<'a>(snap: &'a Snapshot, headers: &HeaderMap) -> Result<&'a TenantConfig, CalibanError> {
    caller(snap, headers).map(|c| c.tenant)
}
