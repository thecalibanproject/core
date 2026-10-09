//! Text embeddings for Caliban's own consumers: the T2 semantic cache, the embedding-kNN intent
//! classifier, and later RAG and drift monitoring ("one embedding per request",
//! docs/architecture/caliban-reference-architecture.md §4).
//!
//! The trait lives here so any crate can take an `Arc<dyn Embedder>` without depending on the
//! gateway. The gateway's implementation (`caliban_gateway::embedder::ProviderEmbedder`) calls the
//! tenant's configured embedding model through the BYOK provider path, batches, applies a short
//! timeout and keeps an in-process LRU of recent vectors.

use crate::{ModelId, TenantId};
use async_trait::async_trait;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmbedError {
    /// The call did not finish within the embedder's timeout.
    #[error("embedding timed out")]
    Timeout,
    /// The model is unknown, not an embedding model, or not reachable by this tenant.
    #[error("embedding model unavailable: {0}")]
    Unavailable(String),
    /// Transport or upstream error.
    #[error("embedding upstream error: {0}")]
    Upstream(String),
    /// The upstream answered with something that is not one vector per input.
    #[error("invalid embedding response: {0}")]
    Invalid(String),
}

/// Embeds texts with a tenant's embedding model.
///
/// Contract:
/// - Returns exactly one vector per input text, in input order. All vectors of one call have the
///   same dimension. Vectors are returned as the model produced them (not normalised); use
///   [`cosine`] to compare.
/// - Texts are sent **as given** to the model's provider. Pass pseudonymised (surrogate-form)
///   text, as the semantic cache does, or use a sovereign (`t0`) embedding model: an external
///   embedding provider must never see raw PII.
/// - Implementations are cheap to call repeatedly with the same text (they cache), and fail fast:
///   callers on the request path treat any error as "no embedding" and carry on.
#[async_trait]
pub trait Embedder: Send + Sync {
    /// Embeds with the tenant's route to `model`: its own (BYOK) provider first, then a shared
    /// pool that serves the tenant.
    async fn embed(&self, tenant: &TenantId, model: &ModelId, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError>;

    /// Embeds through a **deployment** provider (a shared `[[providers]]` entry) only, never a
    /// tenant's own credentials. For vectors that must share one deployment-wide space, such as the
    /// kNN routing exemplars and the prompts compared with them.
    ///
    /// `tenant`: whose text this is. The shared provider must serve that tenant, and cached vectors
    /// stay per tenant, so a later [`Embedder::embed`] of the same text by the same tenant through
    /// the same endpoint reuses the vector. `None`: deployment-authored text (exemplars), embedded
    /// off the request path, so a long timeout applies.
    ///
    /// The default implementation has no shared path and always fails.
    async fn embed_shared(
        &self,
        tenant: Option<&TenantId>,
        model: &ModelId,
        texts: &[String],
    ) -> Result<Vec<Vec<f32>>, EmbedError> {
        let _ = (tenant, texts);
        Err(EmbedError::Unavailable(format!("no shared provider path for '{model}'")))
    }
}

/// Cosine similarity in `[-1, 1]`; `0.0` for empty, zero or mismatched vectors.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (f64::from(*x), f64::from(*y));
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    #[allow(clippy::cast_possible_truncation)]
    let c = (dot / (na.sqrt() * nb.sqrt())) as f32;
    c.clamp(-1.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_basics() {
        assert!((cosine(&[1.0, 0.0], &[2.0, 0.0]) - 1.0).abs() < 1e-6);
        assert!(cosine(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
        assert_eq!(cosine(&[1.0], &[1.0, 2.0]), 0.0);
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
    }
}
