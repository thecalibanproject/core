//! The lexical leg of hybrid retrieval: BM25 as sparse vectors in Qdrant.
//!
//! Note 06 names tantivy for BM25. Caliban's workers are stateless and share nothing but Postgres
//! and Qdrant, so a per-tenant tantivy index on a worker's disk would need its own replication.
//! Qdrant already stores sparse vectors next to the dense ones, and with the `idf` modifier it
//! computes the inverse document frequency over the collection at query time. The client sends
//! the BM25 term-frequency part for documents and a weight of 1 per query term, so the score is
//! BM25 (Okapi, k1 = 1.2, b = 0.75) up to Qdrant's IDF formula. Both legs then go through RRF.
//!
//! **Term ids are keyed.** A sparse index of plain term hashes is a bag of words anyone with a dump
//! can read back with a dictionary. Term ids here are a keyed BLAKE3 hash of the term, with a key
//! derived from the tenant's data key: unreadable without it, different per tenant, and destroyed
//! with the tenant's key.
//!
//! Tokenization: Unicode alphanumeric runs, lowercased; English stop words dropped; Harman's S
//! stemmer (plural forms); tokens of one letter dropped unless they are digits.

use std::collections::BTreeMap;

/// BM25 parameters.
pub const K1: f32 = 1.2;
pub const B: f32 = 0.75;
/// Average chunk length in terms, for length normalisation. A constant: chunk sizes are bounded
/// by the chunker, so a per-collection running average changes little.
pub const AVGDL: f32 = 150.0;

/// A sparse vector: sorted, distinct indices.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SparseVec {
    pub indices: Vec<u32>,
    pub values: Vec<f32>,
}

impl SparseVec {
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    fn from_map(m: BTreeMap<u32, f32>) -> Self {
        let (indices, values) = m.into_iter().unzip();
        Self { indices, values }
    }

    /// Sum of products over shared indices.
    pub fn dot(&self, other: &SparseVec) -> f32 {
        let (mut i, mut j, mut s) = (0, 0, 0.0);
        while i < self.indices.len() && j < other.indices.len() {
            match self.indices[i].cmp(&other.indices[j]) {
                std::cmp::Ordering::Less => i += 1,
                std::cmp::Ordering::Greater => j += 1,
                std::cmp::Ordering::Equal => {
                    s += self.values[i] * other.values[j];
                    i += 1;
                    j += 1;
                }
            }
        }
        s
    }
}

const STOP: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "can", "do", "does", "for", "from", "had", "has",
    "have", "how", "i", "if", "in", "into", "is", "it", "its", "of", "on", "or", "our", "so", "that", "the", "their",
    "them", "then", "there", "these", "they", "this", "to", "was", "we", "were", "what", "when", "where", "which",
    "who", "why", "will", "with", "you", "your",
];

/// Harman's S stemmer: plural forms to singular.
fn stem(w: &str) -> String {
    let n = w.len();
    if n > 4 && w.ends_with("ies") && !w.ends_with("eies") && !w.ends_with("aies") {
        return format!("{}y", &w[..n - 3]);
    }
    if n > 3 && w.ends_with("es") && !w.ends_with("aes") && !w.ends_with("ees") && !w.ends_with("oes") {
        return w[..n - 1].to_owned();
    }
    if n > 3 && w.ends_with('s') && !w.ends_with("us") && !w.ends_with("ss") {
        return w[..n - 1].to_owned();
    }
    w.to_owned()
}

/// The terms of `text`, in order (repeats kept).
pub fn terms(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.split(|c: char| !c.is_alphanumeric()) {
        if raw.is_empty() {
            continue;
        }
        let w = raw.to_lowercase();
        if w.chars().count() < 2 && !w.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if STOP.contains(&w.as_str()) {
            continue;
        }
        out.push(if w.chars().any(|c| c.is_ascii_digit()) { w } else { stem(&w) });
    }
    out
}

/// Maps terms to keyed ids (see the module docs).
#[derive(Clone)]
pub struct TermHasher {
    key: [u8; 32],
}

impl TermHasher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn id(&self, term: &str) -> u32 {
        let h = blake3::keyed_hash(&self.key, term.as_bytes());
        let b = h.as_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// A document (chunk) vector: the BM25 term-frequency weight of each term.
    pub fn document(&self, text: &str) -> SparseVec {
        let t = terms(text);
        #[allow(clippy::cast_precision_loss)]
        let dl = t.len() as f32;
        let mut tf: BTreeMap<u32, f32> = BTreeMap::new();
        for term in &t {
            *tf.entry(self.id(term)).or_default() += 1.0;
        }
        let norm = K1 * (1.0 - B + B * dl / AVGDL);
        for v in tf.values_mut() {
            *v = *v * (K1 + 1.0) / (*v + norm);
        }
        SparseVec::from_map(tf)
    }

    /// A query vector: weight 1 per distinct term (IDF comes from the index).
    pub fn query(&self, text: &str) -> SparseVec {
        SparseVec::from_map(terms(text).iter().map(|t| (self.id(t), 1.0)).collect())
    }
}

/// Qdrant's IDF for the `idf` modifier, used by the in-memory index: `ln(1 + (N - n + 0.5) / (n + 0.5))`.
pub fn idf(n_docs: usize, with_term: usize) -> f32 {
    #[allow(clippy::cast_precision_loss)]
    let (n, df) = (n_docs as f32, with_term as f32);
    (1.0 + (n - df + 0.5) / (df + 0.5)).ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_are_normalised() {
        assert_eq!(
            terms("The Policies for VPN-access, ERR-4471 and 2 laptops!"),
            vec!["policy", "vpn", "access", "err", "4471", "2", "laptop"]
        );
    }

    #[test]
    fn ids_are_keyed_per_tenant() {
        let a = TermHasher::new([1; 32]);
        let b = TermHasher::new([2; 32]);
        assert_eq!(a.id("vpn"), a.id("vpn"));
        assert_ne!(a.id("vpn"), b.id("vpn"), "another tenant's key gives other ids");
    }

    #[test]
    fn bm25_weights_saturate_and_normalise() {
        let h = TermHasher::new([1; 32]);
        let once = h.document("laptop");
        let thrice = h.document("laptop laptop laptop");
        assert!(thrice.values[0] > once.values[0] && thrice.values[0] < 3.0 * once.values[0]);
        let q = h.query("laptops laptop");
        assert_eq!(q.indices.len(), 1);
        assert!(q.dot(&once) > 0.0);
        assert!(idf(100, 1) > idf(100, 50));
    }
}
