//! Retrieval quality measurement: recall@k and nDCG@k against graded relevance labels, and
//! deterministic stand-ins for the embedder and reranker so the pipeline can be measured without
//! a model server (`tests/eval.rs` holds the synthetic labelled set).
//!
//! The stand-ins are not models. [`concept_embed`] hashes concepts (a small synonym table maps
//! paraphrases to one concept), words and character trigrams into a fixed-size vector, and gives
//! identifiers such as `ERR-4471` little weight, like real dense embedders that handle rare codes
//! poorly. That makes the dense and lexical legs complementary in the way the literature reports,
//! so the measured differences between configurations show the mechanisms; the absolute numbers
//! say nothing about a real embedder. Point the eval at a real one before drawing quality
//! conclusions.

use crate::{CallScope, RagError, RagServices};
use caliban_config::Dek;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Graded relevance of results to a query: `(document id, heading path prefix) -> grade`.
#[derive(Debug, Clone, Default)]
pub struct Labels {
    pub relevant: Vec<(String, String, u32)>,
}

impl Labels {
    /// The grade of a result (0: not relevant). A label's heading path matches a result whose path
    /// starts with it (a label on a section covers its subsections).
    pub fn grade(&self, doc_id: &str, heading_path: &str) -> u32 {
        self.relevant
            .iter()
            .filter(|(d, h, _)| d == doc_id && heading_path.starts_with(h.as_str()))
            .map(|(_, _, g)| *g)
            .max()
            .unwrap_or(0)
    }
}

/// Share of the relevant labels (grade >= 1) found in the first `k` results.
pub fn recall_at(results: &[(String, String)], labels: &Labels, k: usize) -> f64 {
    let wanted: Vec<&(String, String, u32)> = labels.relevant.iter().filter(|l| l.2 >= 1).collect();
    if wanted.is_empty() {
        return 1.0;
    }
    let found = wanted
        .iter()
        .filter(|(d, h, _)| results.iter().take(k).any(|(rd, rh)| rd == d && rh.starts_with(h.as_str())))
        .count();
    #[allow(clippy::cast_precision_loss)]
    let r = found as f64 / wanted.len() as f64;
    r
}

/// nDCG@k with gains `2^grade - 1`; each label counts once (repeat hits on a label gain nothing).
pub fn ndcg_at(results: &[(String, String)], labels: &Labels, k: usize) -> f64 {
    let mut used: HashSet<usize> = HashSet::new();
    let mut dcg = 0.0;
    for (i, (d, h)) in results.iter().take(k).enumerate() {
        let best = labels
            .relevant
            .iter()
            .enumerate()
            .filter(|(j, (ld, lh, _))| !used.contains(j) && ld == d && h.starts_with(lh.as_str()))
            .max_by_key(|(_, (_, _, g))| *g);
        if let Some((j, (_, _, g))) = best {
            used.insert(j);
            #[allow(clippy::cast_precision_loss)]
            let gain = (2f64.powi(i32::try_from(*g).unwrap_or(0)) - 1.0) / ((i + 2) as f64).log2();
            dcg += gain;
        }
    }
    let mut grades: Vec<u32> = labels.relevant.iter().map(|l| l.2).collect();
    grades.sort_unstable_by(|a, b| b.cmp(a));
    let idcg: f64 = grades
        .iter()
        .take(k)
        .enumerate()
        .map(|(i, g)| {
            #[allow(clippy::cast_precision_loss)]
            let d = ((i + 2) as f64).log2();
            (2f64.powi(i32::try_from(*g).unwrap_or(0)) - 1.0) / d
        })
        .sum();
    if idcg == 0.0 { 1.0 } else { dcg / idcg }
}

/// Paraphrase groups of the stand-in embedder: every word of a group embeds as the group.
const CONCEPTS: &[&[&str]] = &[
    &["leave", "vacation", "holiday", "pto", "absence", "off"],
    &["laptop", "computer", "notebook", "device", "machine", "workstation"],
    &["salary", "pay", "compensation", "wage", "payroll", "paycheck"],
    &["password", "passphrase", "credential", "login"],
    &["refund", "reimbursement", "reimburse", "repay", "expense", "claim"],
    &["outage", "incident", "downtime", "failure", "disruption"],
    &["remote", "home", "telework", "wfh"],
    &["parental", "maternity", "paternity", "newborn", "baby", "child"],
    &["travel", "trip", "flight", "journey"],
    &["security", "safety", "protection"],
    &["fast", "quick", "rapid", "speedy"],
    &["broken", "damaged", "faulty", "defective"],
    &["cancel", "terminate", "end", "stop"],
    &["install", "setup", "configure", "deploy"],
    &["phone", "mobile", "smartphone", "cellphone"],
];

fn slot(feature: &str, dim: usize) -> (usize, f32) {
    let h = blake3::hash(feature.as_bytes());
    let b = h.as_bytes();
    let i = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let idx = usize::try_from(i % dim as u64).unwrap_or(0);
    (idx, if b[8] & 1 == 0 { 1.0 } else { -1.0 })
}

/// The stand-in dense embedder (see the module docs).
pub fn concept_embed(text: &str, dim: usize) -> Vec<f32> {
    let concept: HashMap<&str, usize> =
        CONCEPTS.iter().enumerate().flat_map(|(i, g)| g.iter().map(move |w| (*w, i))).collect();
    let mut v = vec![0.0f32; dim.max(8)];
    for t in crate::sparse::terms(text) {
        let digits = t.chars().any(|c| c.is_ascii_digit());
        let w = if digits { 0.15 } else { 1.0 };
        let feature = match concept.get(t.as_str()) {
            Some(c) => format!("concept:{c}"),
            None => format!("word:{t}"),
        };
        let (i, s) = slot(&feature, v.len());
        v[i] += s * w;
        if !digits && t.len() >= 4 {
            let chars: Vec<char> = t.chars().collect();
            for g in chars.windows(3) {
                let (i, s) = slot(&format!("tri:{}", g.iter().collect::<String>()), v.len());
                v[i] += s * 0.25;
            }
        }
    }
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        v.iter_mut().for_each(|x| *x /= n);
    }
    v
}

/// The stand-in reranker: query-term coverage of the passage (with concepts), plus a little for
/// heading matches. In `[0, 1]`.
pub fn lexical_rerank(query: &str, doc: &str) -> f32 {
    let concept: HashMap<&str, usize> =
        CONCEPTS.iter().enumerate().flat_map(|(i, g)| g.iter().map(move |w| (*w, i))).collect();
    let norm = |t: &str| concept.get(t).map_or_else(|| t.to_owned(), |c| format!("concept:{c}"));
    let q: HashSet<String> = crate::sparse::terms(query).iter().map(|t| norm(t)).collect();
    if q.is_empty() {
        return 0.0;
    }
    let d: HashSet<String> = crate::sparse::terms(doc).iter().map(|t| norm(t)).collect();
    #[allow(clippy::cast_precision_loss)]
    let cover = q.iter().filter(|t| d.contains(*t)).count() as f32 / q.len() as f32;
    cover.clamp(0.0, 1.0)
}

/// In-process [`RagServices`] for tests and the eval: one data key per tenant, an email masker
/// standing in for the PII engine, the stand-in embedder and reranker. Records what it was sent.
pub struct TestServices {
    keys: parking_lot::Mutex<HashMap<String, Arc<Dek>>>,
    pub dim: usize,
    /// Every text sent to the embedder.
    pub embedded: parking_lot::Mutex<Vec<String>>,
    /// Rerank calls.
    pub reranks: parking_lot::Mutex<usize>,
    /// Make embedding calls fail (as if the embedder were down).
    pub embed_down: std::sync::atomic::AtomicBool,
}

impl Default for TestServices {
    fn default() -> Self {
        Self::new(256)
    }
}

impl TestServices {
    pub fn new(dim: usize) -> Self {
        Self {
            keys: parking_lot::Mutex::new(HashMap::new()),
            dim,
            embedded: parking_lot::Mutex::new(Vec::new()),
            reranks: parking_lot::Mutex::new(0),
            embed_down: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn dek(&self, tenant: &str) -> Arc<Dek> {
        Arc::clone(self.keys.lock().entry(tenant.to_owned()).or_insert_with(|| Arc::new(Dek::generate())))
    }
}

/// Replaces email addresses with a tenant-stable surrogate (a stand-in for the PII engine).
pub fn mask_emails(text: &str) -> (String, usize) {
    let mut n = 0;
    let out = text
        .split(' ')
        .map(|w| {
            let core = w.trim_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '.');
            if core.contains('@') && core.contains('.') {
                n += 1;
                let h = &hex::encode(blake3::hash(core.as_bytes()).as_bytes())[..6];
                w.replace(core, &format!("person{h}@example.com"))
            } else {
                w.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    (out, n)
}

#[async_trait::async_trait]
impl RagServices for TestServices {
    fn data_key(&self, tenant: &str) -> Result<Arc<Dek>, RagError> {
        Ok(self.dek(tenant))
    }

    async fn protect(&self, _tenant: &str, texts: Vec<String>) -> Result<(Vec<String>, usize), RagError> {
        let mut n = 0;
        let out = texts
            .into_iter()
            .map(|t| {
                let (m, k) = mask_emails(&t);
                n += k;
                m
            })
            .collect();
        Ok((out, n))
    }

    async fn embed(&self, _scope: &CallScope, _model: &str, texts: &[String]) -> Result<Vec<Vec<f32>>, RagError> {
        if self.embed_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(RagError::Unavailable("the embedder is down".into()));
        }
        self.embedded.lock().extend(texts.iter().cloned());
        Ok(texts.iter().map(|t| concept_embed(t, self.dim)).collect())
    }

    async fn rerank(
        &self,
        _scope: &CallScope,
        _model: &str,
        query: &str,
        docs: &[String],
    ) -> Result<Vec<f32>, RagError> {
        *self.reranks.lock() += 1;
        Ok(docs.iter().map(|d| lexical_rerank(query, d)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(v: &[(&str, &str, u32)]) -> Labels {
        Labels { relevant: v.iter().map(|(d, h, g)| ((*d).into(), (*h).into(), *g)).collect() }
    }

    #[test]
    fn metrics_match_hand_computed_values() {
        let l = labels(&[("a", "X > Y", 2), ("b", "Z", 1)]);
        let r = vec![("c".to_owned(), "Q".to_owned()), ("a".into(), "X > Y > W".into()), ("b".into(), "Z".into())];
        assert!((recall_at(&r, &l, 2) - 0.5).abs() < 1e-9);
        assert!((recall_at(&r, &l, 3) - 1.0).abs() < 1e-9);
        // DCG = 3/log2(3) + 1/log2(4); IDCG = 3/log2(2) + 1/log2(3).
        let want = (3.0 / 3f64.log2() + 0.5) / (3.0 + 1.0 / 3f64.log2());
        assert!((ndcg_at(&r, &l, 10) - want).abs() < 1e-9);
        assert!((ndcg_at(&[("a".into(), "X > Y".into())], &labels(&[("a", "X", 1)]), 5) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn the_stand_in_embedder_maps_paraphrases_together() {
        let a = concept_embed("How much vacation do I get?", 256);
        let b = concept_embed("annual leave allowance", 256);
        let c = concept_embed("laptop replacement", 256);
        let cos = crate::index::cosine;
        assert!(cos(&a, &b) > cos(&a, &c), "{} vs {}", cos(&a, &b), cos(&a, &c));
        assert!(lexical_rerank("vacation days", "Annual leave: 25 days") > 0.9);
        assert_eq!(mask_emails("mail jane.roe@acme.example now").1, 1);
    }
}
