//! Retrieval (docs/research/06-rag-and-token-efficiency.md).
//!
//! Implemented: reciprocal rank fusion and the token budget manager (stop at the reranker score
//! cliff, then reorder against "lost in the middle").
//! TODO: recursive chunker (256–512 tokens) with contextual headers; tantivy BM25 + Qdrant dense
//! index per tenant; cross-encoder reranker via `ort`; retrieval-mode head on the router.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Chunk {
    pub id: String,
    pub doc_id: String,
    /// Document version; cache entries and answers are keyed to it.
    pub doc_version: u64,
    pub text: String,
    pub tokens: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Scored {
    pub chunk: Chunk,
    pub score: f32,
}

#[async_trait]
pub trait Retriever: Send + Sync {
    async fn retrieve(&self, tenant: &str, query: &str, k: usize) -> Vec<Scored>;
}

/// Reciprocal rank fusion of several ranked lists of chunk ids (k = 60 per Cormack et al.).
pub fn rrf(lists: &[Vec<String>], k: f32) -> Vec<(String, f32)> {
    let mut scores: HashMap<&str, f32> = HashMap::new();
    for list in lists {
        for (rank, id) in list.iter().enumerate() {
            #[allow(clippy::cast_precision_loss)]
            let s = 1.0 / (k + rank as f32 + 1.0);
            *scores.entry(id.as_str()).or_default() += s;
        }
    }
    let mut v: Vec<(String, f32)> = scores.into_iter().map(|(id, s)| (id.to_owned(), s)).collect();
    v.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

/// Selects reranked chunks under a token budget. Stops early when the score drops by more than
/// `cliff` relative to the best chunk. Output order puts the strongest chunks at both ends.
pub fn budget_context(mut ranked: Vec<Scored>, max_tokens: u32, cliff: f32) -> Vec<Scored> {
    ranked.sort_by(|a, b| b.score.total_cmp(&a.score));
    let best = ranked.first().map_or(0.0, |s| s.score);
    let mut used = 0u32;
    let mut picked = Vec::new();
    for s in ranked {
        if best - s.score > cliff || used + s.chunk.tokens > max_tokens {
            break;
        }
        used += s.chunk.tokens;
        picked.push(s);
    }
    // Interleave: 1st, 3rd, 5th … then … 4th, 2nd (best evidence at the edges).
    let (mut front, mut back) = (Vec::new(), Vec::new());
    for (i, s) in picked.into_iter().enumerate() {
        if i % 2 == 0 { front.push(s) } else { back.push(s) }
    }
    back.reverse();
    front.extend(back);
    front
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(id: &str, score: f32, tokens: u32) -> Scored {
        Scored { chunk: Chunk { id: id.into(), doc_id: "d".into(), doc_version: 1, text: String::new(), tokens }, score }
    }

    #[test]
    fn rrf_rewards_agreement() {
        let fused = rrf(&[vec!["a".into(), "b".into()], vec!["b".into(), "c".into()]], 60.0);
        assert_eq!(fused[0].0, "b");
    }

    #[test]
    fn budget_stops_at_cliff_and_puts_best_at_edges() {
        let out = budget_context(vec![sc("a", 0.9, 100), sc("b", 0.85, 100), sc("c", 0.8, 100), sc("d", 0.2, 100)], 1000, 0.3);
        let ids: Vec<&str> = out.iter().map(|s| s.chunk.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "c", "b"]);
    }
}
