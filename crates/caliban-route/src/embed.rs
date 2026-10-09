//! The embedder Stage 1 needs, as a trait local to this crate.
//!
//! The gateway implements it as an adapter over its single provider-backed embedder
//! (`caliban_types::Embedder`, shared-provider path; see `caliban-gateway/src/route_embed.rs`).
//! [`HashEmbedder`] is a deterministic, dependency-free stand-in for tests and latency
//! measurements: it hashes words and character trigrams into a fixed-size vector, so it only
//! captures lexical overlap and says nothing about real accuracy.

use async_trait::async_trait;

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum EmbedError {
    #[error("embedder unavailable: {0}")]
    Unavailable(String),
    #[error("embedding request failed: {0}")]
    Upstream(String),
    #[error("embedder returned {got} vectors for {want} texts")]
    Count { want: usize, got: usize },
}

/// Embeds prompts and exemplars into one vector space.
#[async_trait]
pub trait PromptEmbedder: Send + Sync {
    /// Identifies the vector space (embedding model, upstream model name, endpoint). Exemplar
    /// vectors are only comparable with prompt vectors from the same space, and the exemplar
    /// cache is keyed by it.
    fn space_id(&self) -> String;

    /// One vector per text, in input order.
    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError>;
}

/// Deterministic lexical embedder (feature hashing of words and character trigrams).
#[derive(Debug, Clone)]
pub struct HashEmbedder {
    pub dim: usize,
    /// Artificial latency per call, to exercise the routing budget in tests.
    pub delay: Option<std::time::Duration>,
}

impl Default for HashEmbedder {
    fn default() -> Self {
        Self { dim: 384, delay: None }
    }
}

impl HashEmbedder {
    pub fn with_delay(mut self, d: std::time::Duration) -> Self {
        self.delay = Some(d);
        self
    }
}

/// FNV-1a; stable across platforms and releases, unlike `DefaultHasher`.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// The vector [`HashEmbedder`] produces for `text` (L2-normalised; all zeros for empty text).
pub fn hash_embed(text: &str, dim: usize) -> Vec<f32> {
    let mut v = vec![0f32; dim.max(1)];
    let lower = text.to_lowercase();
    let mut add = |feature: &str, weight: f32| {
        let h = fnv1a(feature.as_bytes());
        #[allow(clippy::cast_possible_truncation)]
        let i = (h % v.len() as u64) as usize;
        let sign = if (h >> 63) == 0 { 1.0 } else { -1.0 };
        v[i] += sign * weight;
    };
    for w in lower.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()) {
        add(w, 1.0);
        let chars: Vec<char> = format!(" {w} ").chars().collect();
        for t in chars.windows(3) {
            add(&t.iter().collect::<String>(), 0.3);
        }
    }
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        v.iter_mut().for_each(|x| *x /= n);
    }
    v
}

#[async_trait]
impl PromptEmbedder for HashEmbedder {
    fn space_id(&self) -> String {
        format!("hash-embedder/{}", self.dim)
    }

    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        if let Some(d) = self.delay {
            tokio::time::sleep(d).await;
        }
        Ok(texts.iter().map(|t| hash_embed(t, self.dim)).collect())
    }
}
