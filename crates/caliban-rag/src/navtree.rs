//! Navigation trees for long documents (NavTree, arXiv 2610.06902, preprint; note 06,
//! "iterative" strategy).
//!
//! RAPTOR builds a tree of LLM-written summaries; the NavTree ablation found the gain on long
//! documents comes from navigating a tree, not from the summaries: a deterministic balanced
//! segment tree over the chunks, with **zero LLM calls at indexing**, walked with a hybrid
//! lexical plus dense frontier that **emits only leaf chunks**, beat a matched RAPTOR at every
//! multi-chunk budget and was the only hierarchical method to beat BM25 on long-document multi-hop
//! QA.
//!
//! Here: consecutive chunks are grouped `FANOUT` at a time, level by level, up to one root. An
//! inner node's dense vector is the normalised mean of its chunks' vectors (no extra embedding
//! call) and its sparse vector is BM25 over the concatenation of its chunks' indexed text. Inner
//! nodes are points of kind `nav` in the same collection. The walk ([`crate::retrieve`]) starts
//! at the root, scores the children of the frontier with both legs fused by RRF, keeps the best
//! `BEAM` inner nodes, and collects the chunks it reaches.

/// Children per inner node.
pub const FANOUT: usize = 4;
/// Inner nodes kept per level of the walk.
pub const BEAM: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeNode {
    /// `n<level>.<i>`.
    pub key: String,
    pub level: u32,
    /// The chunks it covers: `first..=last`.
    pub first: u32,
    pub last: u32,
    pub parent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// The parent of each chunk, by chunk index.
    pub leaf_parent: Vec<String>,
    /// Inner nodes, bottom level first; the last one is the root.
    pub nodes: Vec<TreeNode>,
}

/// The chunk key of chunk `i`.
pub fn leaf_key(i: u32) -> String {
    format!("c{i}")
}

/// A balanced tree over `n` chunks (`None` below two chunks).
pub fn build(n: usize, fanout: usize) -> Option<Tree> {
    let fanout = fanout.max(2);
    if n < 2 {
        return None;
    }
    let n32 = |x: usize| u32::try_from(x).unwrap_or(u32::MAX);
    // The current level: (key, first, last), and where each entry sits in `nodes` (None: a leaf).
    let mut level: Vec<(String, u32, u32, Option<usize>)> =
        (0..n).map(|i| (leaf_key(n32(i)), n32(i), n32(i), None)).collect();
    let mut leaf_parent = vec![String::new(); n];
    let mut nodes: Vec<TreeNode> = Vec::new();
    let mut depth = 0u32;
    while level.len() > 1 {
        depth += 1;
        let mut next = Vec::new();
        for (j, group) in level.chunks(fanout).enumerate() {
            let key = format!("n{depth}.{j}");
            let (first, last) = (group[0].1, group[group.len() - 1].2);
            for (_, f, _, idx) in group {
                match idx {
                    None => leaf_parent[*f as usize] = key.clone(),
                    Some(i) => nodes[*i].parent = Some(key.clone()),
                }
            }
            nodes.push(TreeNode { key: key.clone(), level: depth, first, last, parent: None });
            next.push((key, first, last, Some(nodes.len() - 1)));
        }
        level = next;
    }
    Some(Tree { leaf_parent, nodes })
}

/// The normalised mean of vectors (a navigation node's dense vector).
pub fn mean(vectors: &[&Vec<f32>]) -> Vec<f32> {
    let Some(first) = vectors.first() else { return Vec::new() };
    let mut out = vec![0.0f32; first.len()];
    for v in vectors {
        for (o, x) in out.iter_mut().zip(v.iter()) {
            *o += x;
        }
    }
    let norm = out.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for o in &mut out {
            *o /= norm;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_balanced_tree_covers_every_chunk_once() {
        let t = build(10, 4).unwrap();
        // 10 chunks -> 3 nodes -> 1 root.
        assert_eq!(t.nodes.len(), 4);
        let root = t.nodes.last().unwrap();
        assert_eq!((root.first, root.last, root.parent.clone()), (0, 9, None));
        assert_eq!(t.leaf_parent[0], "n1.0");
        assert_eq!(t.leaf_parent[9], "n1.2");
        assert!(t.nodes[..3].iter().all(|n| n.parent.as_deref() == Some("n2.0")));
        assert_eq!((t.nodes[2].first, t.nodes[2].last), (8, 9));
        assert!(build(1, 4).is_none());
        let big = build(100, 4).unwrap();
        assert_eq!(big.nodes.last().unwrap().level, 4);
    }

    #[test]
    fn mean_is_normalised() {
        let (a, b) = (vec![1.0, 0.0], vec![0.0, 1.0]);
        let m = mean(&[&a, &b]);
        assert!((m[0] - m[1]).abs() < 1e-6 && (m[0] * m[0] + m[1] * m[1] - 1.0).abs() < 1e-5);
    }
}
