//! Stage-1 kNN intent classifier over exemplar embeddings.
//!
//! Same semantics as ml's `KnnIntentClassifier` (`ml/src/caliban_ml/router/knn.py`), so a
//! calibration fitted there transfers 1:1:
//!
//! ```text
//! neighbours  = top-k exemplars by cosine similarity
//! w_j         = exp(s_j / T)  (normalised over the k neighbours)           T = temperature
//! p_c         = (1 - eps) * sum_{j: y_j = c} w_j + eps / C                 C = visible intents
//! OOS         if top-1 similarity < oos_threshold (explicit abstain, never an argmax)
//! accept      if p_max >= thresholds[label] (else default_threshold)
//!             and, when set, p_max - p_second >= margin_threshold
//! ```
//!
//! Search is brute-force cosine over L2-normalised vectors in one contiguous buffer. Measured in a
//! release build on a laptop: tens of microseconds for the built-in 210 x 384 set, about 2 ms for
//! 5,000 x 1,024 (memory-bound: the scan reads 20 MB). At the few thousand exemplars a deployment
//! needs, an HNSW index would add a dependency, build time and recall loss for no useful gain;
//! revisit past roughly 20k exemplars visible to one tenant.

use std::collections::BTreeMap;

/// Built-in defaults when neither config nor a calibration artifact sets a value. Similarity
/// scales differ per embedder, so there is no default OOS gate.
pub const DEFAULT_K: usize = 5;
pub const DEFAULT_TEMPERATURE: f64 = 0.05;
pub const DEFAULT_SMOOTHING: f64 = 1e-3;
pub const DEFAULT_ABSTAIN_THRESHOLD: f64 = 0.5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OosScore {
    /// Cosine similarity of the nearest exemplar (ml `top1_similarity`).
    Top1Similarity,
    /// Calibrated probability of the winning intent (ml `max_probability`).
    MaxProbability,
}

/// Classifier constants. [`KnnParams::default`] are the built-in defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct KnnParams {
    pub k: usize,
    pub temperature: f64,
    pub smoothing: f64,
    /// Per-intent exit thresholds on the calibrated probability.
    pub thresholds: BTreeMap<String, f64>,
    pub default_threshold: f64,
    pub margin_threshold: Option<f64>,
    pub oos_threshold: Option<f64>,
    pub oos_score: OosScore,
}

impl Default for KnnParams {
    fn default() -> Self {
        Self {
            k: DEFAULT_K,
            temperature: DEFAULT_TEMPERATURE,
            smoothing: DEFAULT_SMOOTHING,
            thresholds: BTreeMap::new(),
            default_threshold: DEFAULT_ABSTAIN_THRESHOLD,
            margin_threshold: None,
            oos_threshold: None,
            oos_score: OosScore::Top1Similarity,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abstain {
    /// Below the OOS gate: nothing in the exemplar set is close enough.
    OutOfScope,
    /// The winning intent's vote share is below its threshold.
    LowConfidence,
    /// The top two intents are too close.
    LowMargin,
    /// Zero vector or no exemplars visible to the tenant.
    Empty,
}

impl Abstain {
    pub fn as_str(self) -> &'static str {
        match self {
            Abstain::OutOfScope => "abstain_oos",
            Abstain::LowConfidence => "abstain_confidence",
            Abstain::LowMargin => "abstain_margin",
            Abstain::Empty => "abstain_empty",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct KnnOutcome {
    /// Winning intent (also reported when abstaining, for the trace).
    pub intent: String,
    /// Calibrated probability of `intent`.
    pub confidence: f32,
    pub top1_similarity: f32,
    /// `p_max - p_second`.
    pub margin: f32,
    /// Neighbours actually used (≤ k).
    pub neighbours: usize,
    pub abstain: Option<Abstain>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum KnnError {
    #[error("vector has {got} dimensions, index has {want}")]
    Dim { want: usize, got: usize },
    #[error("exemplar vectors and labels do not line up")]
    Shape,
}

/// Exemplar vectors with their intent and owner (deployment-wide or one tenant).
#[derive(Debug, Clone)]
pub struct KnnIndex {
    dim: usize,
    /// `n * dim`, each row L2-normalised.
    vectors: Vec<f32>,
    labels: Vec<u32>,
    /// `u32::MAX` = deployment-wide, else an index into `tenants`.
    owners: Vec<u32>,
    intents: Vec<String>,
    tenants: Vec<String>,
    /// Distinct intents visible to deployment-wide queries and to each tenant (`C` in smoothing).
    classes_global: usize,
    classes_tenant: Vec<usize>,
}

const GLOBAL: u32 = u32::MAX;

/// Dot product with eight independent accumulators, so the compiler can vectorise it (a single
/// running float sum cannot be reordered, which keeps the loop scalar).
fn dot(a: &[f32], b: &[f32]) -> f32 {
    let mut acc = [0f32; 8];
    let ((ca, ra), (cb, rb)) = (a.as_chunks::<8>(), b.as_chunks::<8>());
    let tail: f32 = ra.iter().zip(rb).map(|(x, y)| x * y).sum();
    for (x, y) in ca.iter().zip(cb) {
        for i in 0..8 {
            acc[i] += x[i] * y[i];
        }
    }
    acc.iter().sum::<f32>() + tail
}

fn normalize(v: &mut [f32]) -> bool {
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 && n.is_finite() {
        v.iter_mut().for_each(|x| *x /= n);
        true
    } else {
        false
    }
}

impl KnnIndex {
    /// `rows[i]` is the vector for (`owners[i]`, `intents[i]`). Rows that are all zeros are dropped.
    pub fn build(rows: Vec<Vec<f32>>, intents: &[String], owners: &[Option<String>]) -> Result<Self, KnnError> {
        if rows.len() != intents.len() || rows.len() != owners.len() || rows.is_empty() {
            return Err(KnnError::Shape);
        }
        let dim = rows[0].len();
        let mut idx = KnnIndex {
            dim,
            vectors: Vec::with_capacity(rows.len() * dim),
            labels: Vec::with_capacity(rows.len()),
            owners: Vec::with_capacity(rows.len()),
            intents: Vec::new(),
            tenants: Vec::new(),
            classes_global: 0,
            classes_tenant: Vec::new(),
        };
        let mut intent_ix: BTreeMap<&str, u32> = BTreeMap::new();
        let mut tenant_ix: BTreeMap<&str, u32> = BTreeMap::new();
        for ((mut v, intent), owner) in rows.into_iter().zip(intents).zip(owners) {
            if v.len() != dim {
                return Err(KnnError::Dim { want: dim, got: v.len() });
            }
            if !normalize(&mut v) {
                continue;
            }
            let next = u32::try_from(intent_ix.len()).unwrap_or(u32::MAX);
            let l = *intent_ix.entry(intent.as_str()).or_insert(next);
            if l as usize == idx.intents.len() {
                idx.intents.push(intent.clone());
            }
            let o = match owner {
                None => GLOBAL,
                Some(t) => {
                    let next = u32::try_from(tenant_ix.len()).unwrap_or(u32::MAX - 1);
                    let o = *tenant_ix.entry(t.as_str()).or_insert(next);
                    if o as usize == idx.tenants.len() {
                        idx.tenants.push(t.clone());
                    }
                    o
                }
            };
            idx.vectors.extend_from_slice(&v);
            idx.labels.push(l);
            idx.owners.push(o);
        }
        if idx.labels.is_empty() {
            return Err(KnnError::Shape);
        }
        let classes = |pred: &dyn Fn(u32) -> bool| {
            let mut seen = vec![false; idx.intents.len()];
            for (l, o) in idx.labels.iter().zip(&idx.owners) {
                if pred(*o) {
                    seen[*l as usize] = true;
                }
            }
            seen.into_iter().filter(|s| *s).count()
        };
        idx.classes_global = classes(&|o| o == GLOBAL);
        idx.classes_tenant = (0..idx.tenants.len()).map(|t| classes(&|o| o == GLOBAL || o as usize == t)).collect();
        Ok(idx)
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    pub fn intents(&self) -> &[String] {
        &self.intents
    }

    /// Classifies `query` for `tenant` (deployment-wide exemplars plus the tenant's own).
    pub fn classify(&self, query: &[f32], tenant: Option<&str>, p: &KnnParams) -> Result<KnnOutcome, KnnError> {
        self.classify_excluding(query, tenant, p, None)
    }

    fn classify_excluding(
        &self,
        query: &[f32],
        tenant: Option<&str>,
        p: &KnnParams,
        exclude: Option<usize>,
    ) -> Result<KnnOutcome, KnnError> {
        if query.len() != self.dim {
            return Err(KnnError::Dim { want: self.dim, got: query.len() });
        }
        let empty = |intent: String| KnnOutcome {
            intent,
            confidence: 0.0,
            top1_similarity: 0.0,
            margin: 0.0,
            neighbours: 0,
            abstain: Some(Abstain::Empty),
        };
        let mut q = query.to_vec();
        if !normalize(&mut q) {
            return Ok(empty(String::new()));
        }
        let t_ix =
            tenant.and_then(|t| self.tenants.iter().position(|x| x == t)).map(|i| u32::try_from(i).unwrap_or(GLOBAL));
        let classes = t_ix.map_or(self.classes_global, |t| self.classes_tenant[t as usize]).max(1);

        // Top-k by similarity; ties keep the earlier exemplar (deterministic).
        let k = p.k.max(1);
        let mut top: Vec<(f32, usize)> = Vec::with_capacity(k + 1);
        for (i, row) in self.vectors.chunks_exact(self.dim).enumerate() {
            let o = self.owners[i];
            if Some(i) == exclude || !(o == GLOBAL || Some(o) == t_ix) {
                continue;
            }
            let s = dot(row, &q);
            if top.len() < k || s > top[top.len() - 1].0 {
                let pos = top.partition_point(|(ts, _)| *ts >= s);
                top.insert(pos, (s, i));
                top.truncate(k);
            }
        }
        if top.is_empty() {
            return Ok(empty(String::new()));
        }

        // Temperature softmax over the neighbours, summed per intent, with smoothing.
        let t = p.temperature.max(1e-6);
        let s_max = f64::from(top[0].0);
        let w: Vec<f64> = top.iter().map(|(s, _)| ((f64::from(*s) - s_max) / t).exp()).collect();
        let total: f64 = w.iter().sum();
        let mut votes: BTreeMap<u32, f64> = BTreeMap::new();
        for ((_, i), wj) in top.iter().zip(&w) {
            *votes.entry(self.labels[*i]).or_default() += wj / total;
        }
        #[allow(clippy::cast_precision_loss)]
        let floor = p.smoothing / classes as f64;
        let mut ranked: Vec<(f64, &str)> =
            votes.iter().map(|(l, v)| ((1.0 - p.smoothing) * v + floor, self.intents[*l as usize].as_str())).collect();
        // Highest probability first; equal probabilities resolve by intent id.
        ranked.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(b.1)));
        let (p_max, intent) = ranked[0];
        let p_second = ranked.get(1).map_or(floor, |r| r.0);
        let top1 = top[0].0;

        let oos_score = match p.oos_score {
            OosScore::Top1Similarity => f64::from(top1),
            OosScore::MaxProbability => p_max,
        };
        let threshold = p.thresholds.get(intent).copied().unwrap_or(p.default_threshold);
        let abstain = if p.oos_threshold.is_some_and(|g| oos_score < g) {
            Some(Abstain::OutOfScope)
        } else if p_max < threshold {
            Some(Abstain::LowConfidence)
        } else if p.margin_threshold.is_some_and(|m| p_max - p_second < m) {
            Some(Abstain::LowMargin)
        } else {
            None
        };
        #[allow(clippy::cast_possible_truncation)]
        Ok(KnnOutcome {
            intent: intent.to_owned(),
            confidence: p_max as f32,
            top1_similarity: top1,
            margin: (p_max - p_second) as f32,
            neighbours: top.len(),
            abstain,
        })
    }

    /// Leave-one-out evaluation over deployment-wide exemplars: each one is classified against
    /// all the others. Used by the offline eval hook (`tests/knn_eval.rs`).
    pub fn leave_one_out(&self, p: &KnnParams) -> LooReport {
        let mut r = LooReport::default();
        for i in 0..self.len() {
            if self.owners[i] != GLOBAL {
                continue;
            }
            let row = &self.vectors[i * self.dim..(i + 1) * self.dim];
            let Ok(out) = self.classify_excluding(row, None, p, Some(i)) else { continue };
            let truth = &self.intents[self.labels[i] as usize];
            let e = r.per_intent.entry(truth.clone()).or_default();
            e.n += 1;
            r.n += 1;
            if out.intent == *truth {
                r.top1_correct += 1;
                e.top1_correct += 1;
            }
            match out.abstain {
                Some(_) => r.abstained += 1,
                None => {
                    r.accepted += 1;
                    if out.intent == *truth {
                        r.accepted_correct += 1;
                        e.accepted_correct += 1;
                    }
                }
            }
            *r.confusion.entry((truth.clone(), out.intent.clone())).or_default() += 1;
        }
        r
    }
}

#[derive(Debug, Clone, Default)]
pub struct LooCounts {
    pub n: usize,
    pub top1_correct: usize,
    pub accepted_correct: usize,
}

#[derive(Debug, Clone, Default)]
pub struct LooReport {
    pub n: usize,
    /// Argmax correct, ignoring the abstain gate.
    pub top1_correct: usize,
    /// Not abstained.
    pub accepted: usize,
    pub accepted_correct: usize,
    pub abstained: usize,
    pub per_intent: BTreeMap<String, LooCounts>,
    /// (truth, predicted) → count.
    pub confusion: BTreeMap<(String, String), usize>,
}

impl LooReport {
    #[allow(clippy::cast_precision_loss)]
    pub fn top1_accuracy(&self) -> f64 {
        if self.n == 0 { 0.0 } else { self.top1_correct as f64 / self.n as f64 }
    }

    /// Precision of the decisions kNN accepted (the rest fall back to rules).
    #[allow(clippy::cast_precision_loss)]
    pub fn accepted_precision(&self) -> f64 {
        if self.accepted == 0 { 0.0 } else { self.accepted_correct as f64 / self.accepted as f64 }
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn abstain_rate(&self) -> f64 {
        if self.n == 0 { 0.0 } else { self.abstained as f64 / self.n as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> String {
        x.to_owned()
    }

    /// Three 2-d clusters: a along +x, b along +y, c along -x.
    fn index() -> KnnIndex {
        let rows =
            vec![vec![1.0, 0.0], vec![0.95, 0.05], vec![0.9, 0.1], vec![0.0, 1.0], vec![0.1, 0.9], vec![-1.0, 0.0]];
        let intents = [s("a"), s("a"), s("a"), s("b"), s("b"), s("c")];
        KnnIndex::build(rows, &intents, &[None, None, None, None, None, None]).unwrap()
    }

    #[test]
    fn distance_weighted_votes_pick_the_nearest_cluster() {
        let p = KnnParams { k: 5, temperature: 0.05, ..KnnParams::default() };
        let out = index().classify(&[1.0, 0.02], None, &p).unwrap();
        assert_eq!(out.intent, "a");
        assert!(out.confidence > 0.99, "{out:?}");
        assert!(out.abstain.is_none());
        let out = index().classify(&[0.2, 1.0], None, &p).unwrap();
        assert_eq!(out.intent, "b");
    }

    #[test]
    fn temperature_controls_vote_sharpness() {
        // Query between a and b, slightly closer to b. With k=5 there are 3 a's and 2 b's.
        let q = [0.70, 0.72];
        let sharp = index().classify(&q, None, &KnnParams { temperature: 0.01, ..KnnParams::default() }).unwrap();
        let flat = index()
            .classify(&q, None, &KnnParams { temperature: 100.0, default_threshold: 0.0, ..KnnParams::default() })
            .unwrap();
        assert_eq!(sharp.intent, "b");
        // Near-uniform weights: majority vote, so the three a's win.
        assert_eq!(flat.intent, "a");
        assert!(flat.confidence < 0.65 && sharp.confidence > flat.confidence);
    }

    #[test]
    fn abstains_below_confidence_margin_and_oos_gates() {
        let q = [0.70, 0.72];
        let flat = KnnParams { temperature: 100.0, ..KnnParams::default() };
        let low = index().classify(&q, None, &KnnParams { default_threshold: 0.9, ..flat.clone() }).unwrap();
        assert_eq!(low.abstain, Some(Abstain::LowConfidence));
        let margin = index()
            .classify(&q, None, &KnnParams { default_threshold: 0.0, margin_threshold: Some(0.5), ..flat.clone() })
            .unwrap();
        assert_eq!(margin.abstain, Some(Abstain::LowMargin));
        // Orthogonal to everything except c's opposite: top-1 similarity is low.
        let oos = index()
            .classify(&[0.0, -1.0], None, &KnnParams { oos_threshold: Some(0.5), ..KnnParams::default() })
            .unwrap();
        assert_eq!(oos.abstain, Some(Abstain::OutOfScope));
        // Per-label threshold overrides the default.
        let mut th = BTreeMap::new();
        th.insert(s("a"), 1.0);
        let per = index().classify(&[1.0, 0.0], None, &KnnParams { thresholds: th, ..KnnParams::default() }).unwrap();
        assert_eq!((per.intent.as_str(), per.abstain), ("a", Some(Abstain::LowConfidence)));
        // Zero query.
        assert_eq!(index().classify(&[0.0, 0.0], None, &KnnParams::default()).unwrap().abstain, Some(Abstain::Empty));
    }

    #[test]
    fn matches_ml_reference_probabilities() {
        // Same numbers as ml's KnnIntentClassifier.proba_from_neighbours for k=3, T=0.1, eps=1e-3:
        // sims [1.0, 0.995, 0.987] labels [a, a, a]... use mixed labels to check aggregation.
        let rows = vec![vec![1.0, 0.0], vec![0.8, 0.6], vec![0.6, 0.8]];
        let idx = KnnIndex::build(rows, &[s("a"), s("b"), s("b")], &[None, None, None]).unwrap();
        let p = KnnParams { k: 3, temperature: 0.1, smoothing: 1e-3, default_threshold: 0.0, ..KnnParams::default() };
        let out = idx.classify(&[1.0, 0.0], None, &p).unwrap();
        // w = softmax([1.0, 0.8, 0.6] / 0.1) = [0.8668, 0.1173, 0.0159]
        let w = [0.0f64, -2.0, -4.0].map(f64::exp);
        let tot: f64 = w.iter().sum();
        let pa = (1.0 - 1e-3) * (w[0] / tot) + 1e-3 / 2.0;
        assert_eq!(out.intent, "a");
        assert!((f64::from(out.confidence) - pa).abs() < 1e-6, "{} vs {pa}", out.confidence);
    }

    #[test]
    fn tenant_exemplars_are_private_to_the_tenant() {
        let rows = vec![vec![1.0, 0.0], vec![0.0, 1.0]];
        let idx = KnnIndex::build(rows, &[s("chat"), s("legal.review")], &[None, Some(s("acme"))]).unwrap();
        let p = KnnParams { k: 1, default_threshold: 0.0, ..KnnParams::default() };
        assert_eq!(idx.classify(&[0.0, 1.0], Some("acme"), &p).unwrap().intent, "legal.review");
        assert_eq!(idx.classify(&[0.0, 1.0], Some("globex"), &p).unwrap().intent, "chat");
        assert_eq!(idx.classify(&[0.0, 1.0], None, &p).unwrap().intent, "chat");
    }

    #[test]
    fn lane_split_dot_matches_the_plain_sum() {
        let a: Vec<f32> = (0..37).map(|i| (i as f32).sin()).collect();
        let b: Vec<f32> = (0..37).map(|i| (i as f32 * 0.7).cos()).collect();
        let plain: f32 = a.iter().zip(&b).map(|(x, y)| x * y).sum();
        assert!((dot(&a, &b) - plain).abs() < 1e-5);
    }

    #[test]
    fn dimension_mismatch_is_an_error() {
        assert_eq!(
            index().classify(&[1.0, 0.0, 0.0], None, &KnnParams::default()).unwrap_err(),
            KnnError::Dim { want: 2, got: 3 }
        );
    }

    #[test]
    fn leave_one_out_excludes_the_query_itself() {
        let r = index().leave_one_out(&KnnParams { k: 1, default_threshold: 0.0, ..KnnParams::default() });
        assert_eq!(r.n, 6);
        // "c" has a single exemplar: without it, its nearest neighbour is another intent.
        assert_eq!(r.top1_correct, 5);
        assert_eq!(r.per_intent["c"].top1_correct, 0);
    }
}
