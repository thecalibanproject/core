//! Shared identifiers, enums and errors used across Caliban crates.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    Off,
    #[default]
    Exact,
    Semantic,
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
