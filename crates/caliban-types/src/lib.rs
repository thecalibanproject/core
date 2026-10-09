//! Shared identifiers, enums and errors used across Caliban crates.

mod embed;

pub use embed::{EmbedError, Embedder, cosine};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
    };
}

id_type!(TenantId);
id_type!(ModelId);
id_type!(ProviderId);
id_type!(DatasourceId);

/// Unique per request; UUIDv7 so ids sort by time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub String);

impl RequestId {
    pub fn new() -> Self {
        Self(format!("req_{}", uuid::Uuid::now_v7().simple()))
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a model runs, which decides how much data protection a request needs.
/// See docs/research/05-anonymization-and-privacy.md §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Caliban-hosted or customer-hosted model inside the trust boundary.
    T0Sovereign,
    /// Model inside a verified, attested TEE.
    T1Attested,
    /// External provider under contract (DPA/BAA, zero retention).
    T2Contracted,
    /// Anything else.
    T3Public,
}

impl TrustTier {
    /// True when data leaves the customer's trust boundary.
    pub fn is_external(self) -> bool {
        matches!(self, TrustTier::T2Contracted | TrustTier::T3Public)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PiiMode {
    Off,
    Mask,
    #[default]
    Reversible,
}

/// How far a reversible surrogate stays the same (docs/architecture §9, "Surrogate scope").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PiiSurrogateScope {
    /// The same value in the same tenant always gets the same surrogate (keyed HMAC per tenant),
    /// so pseudonymised requests can hit the exact cache. Sessions within the tenant become
    /// linkable through their surrogates. Surrogates never cross tenants.
    #[default]
    Tenant,
    /// Fresh random surrogates for every request: nothing links two requests, and requests that
    /// carry PII bypass the exact cache.
    Session,
}

impl PiiSurrogateScope {
    pub fn as_str(self) -> &'static str {
        match self {
            PiiSurrogateScope::Tenant => "tenant",
            PiiSurrogateScope::Session => "session",
        }
    }

    pub fn is_default(&self) -> bool {
        *self == PiiSurrogateScope::Tenant
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    Off,
    #[default]
    Exact,
    Semantic,
}

/// Per-tenant switch for the T2 semantic cache (`[[tenants]] semantic_cache`). Off by default:
/// a tenant opts in once its hit quality has been measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCacheMode {
    #[default]
    Off,
    On,
}

impl SemanticCacheMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SemanticCacheMode::Off => "off",
            SemanticCacheMode::On => "on",
        }
    }

    pub fn is_default(&self) -> bool {
        *self == SemanticCacheMode::Off
    }
}

/// Which cache tier served a hit (`x-caliban-cache-tier`, `UsageEvent.cache_tier`).
/// `x-caliban-cache` stays `hit | miss | bypass` for clients that predate the semantic tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheTier {
    /// T1: byte-identical (protected) request.
    Exact,
    /// T2: a semantically similar earlier request of the same tenant.
    Semantic,
}

impl CacheTier {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheTier::Exact => "exact",
            CacheTier::Semantic => "semantic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStatus {
    Hit,
    Miss,
    Bypass,
}

impl CacheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheStatus::Hit => "hit",
            CacheStatus::Miss => "miss",
            CacheStatus::Bypass => "bypass",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Openai,
    Anthropic,
    /// Any OpenAI-compatible server: vLLM, SGLang, llama.cpp, Ollama, mistral.rs.
    OpenaiCompatible,
    AzureOpenai,
    Bedrock,
    Vertex,
}

/// Errors surfaced to API clients. `kind` maps to the OpenAPI `Error.type` field.
#[derive(Debug, thiserror::Error)]
pub enum CalibanError {
    #[error("{0}")]
    InvalidRequest(String),
    #[error("invalid or missing API key")]
    Unauthenticated,
    #[error("{0}")]
    PolicyViolation(String),
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal error: {0}")]
    Internal(String),
    /// Temporarily over capacity (e.g. the PII model's queue is full); retry later. 503.
    #[error("overloaded: {0}")]
    Overloaded(String),
}

impl CalibanError {
    pub fn kind(&self) -> &'static str {
        match self {
            CalibanError::InvalidRequest(_) => "invalid_request_error",
            CalibanError::Unauthenticated => "authentication_error",
            CalibanError::PolicyViolation(_) => "policy_violation",
            CalibanError::RateLimited(_) => "rate_limited",
            CalibanError::Upstream(_) => "upstream_error",
            CalibanError::Internal(_) => "internal_error",
            CalibanError::Overloaded(_) => "overloaded",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            CalibanError::InvalidRequest(_) => 400,
            CalibanError::Unauthenticated => 401,
            CalibanError::PolicyViolation(_) => 403,
            CalibanError::RateLimited(_) => 429,
            CalibanError::Upstream(_) => 502,
            CalibanError::Internal(_) => 500,
            CalibanError::Overloaded(_) => 503,
        }
    }
}

/// Only the SHA-256 hex of a tenant API key is ever stored.
pub fn hash_api_key(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_tier_serde_matches_openapi() {
        let s = serde_json::to_string(&TrustTier::T0Sovereign).unwrap();
        assert_eq!(s, "\"t0_sovereign\"");
    }

    #[test]
    fn api_key_hash_is_stable_hex() {
        let h = hash_api_key("cal_test");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_api_key("cal_test"));
    }
}
