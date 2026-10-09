use axum::http::HeaderMap;
use caliban_config::{Snapshot, TenantConfig};
use caliban_types::{CalibanError, hash_api_key};

/// An authenticated caller: the tenant and the hash of the key used (for per-key limits).
pub struct Caller<'a> {
    pub tenant: &'a TenantConfig,
    pub key_hash: String,
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
    Ok(Caller { tenant, key_hash })
}

pub fn tenant<'a>(snap: &'a Snapshot, headers: &HeaderMap) -> Result<&'a TenantConfig, CalibanError> {
    caller(snap, headers).map(|c| c.tenant)
}
