//! Threshold policy for the T2 semantic cache.
//!
//! Background (docs/research/01-semantic-caching-and-rust-vector-stack.md, "Threshold strategy"):
//! one static cosine threshold gives unpredictable false hits (vCache, arXiv 2502.03771), so each
//! cached entry learns its own threshold from verification feedback, and each tenant has an error
//! budget δ.
//!
//! What is implemented, relative to vCache:
//! - **Same signal.** vCache labels each observation `(similarity s, was the cached answer
//!   correct for this new prompt)` and fits a per-entry sigmoid `P(correct | s)`. We collect the
//!   same labels per entry (`EntryStats`) but use the non-parametric limit of that fit: the
//!   entry's threshold is the lowest similarity at which its answer was verified correct, never
//!   at or below the highest similarity at which it was verified wrong, and never below
//!   `min_threshold`. Until an entry has `MIN_AGREEMENTS` verified-correct observations it uses
//!   the conservative starting threshold (0.95 by default).
//! - **Same exploration idea.** vCache sometimes calls the LLM instead of serving, to keep
//!   learning. Here a would-be hit is answered fresh with probability `verify_rate` (explore), and
//!   matches just below the threshold (`grey_band`) are always answered fresh; in both cases the
//!   fresh answer is compared with the cached one in the background (Krites-style asynchronous
//!   verification, arXiv 2602.13165) and the result updates the entry.
//! - **Error budget, enforced by measurement rather than by a confidence bound.** vCache picks
//!   the exploration probability so the error rate provably stays under δ. We instead estimate
//!   each tenant's served-hit error rate from the explore samples (an unbiased sample of hits) and
//!   tighten all of that tenant's thresholds by `OFFSET_STEP` as soon as a window of
//!   `BUDGET_WINDOW` samples holds more than `δ · BUDGET_WINDOW` wrong answers; a clean window
//!   relaxes it again. This gives a measured false-hit rate per tenant, not a formal guarantee.
//! - **Judge.** vCache compares responses for equality; we compare answer embeddings (cosine at
//!   least `verify_answer_similarity`) or exact text. An LLM judge for grey-zone pairs is a later
//!   step (see the README's known gaps).
//!
//! Hard guards that run before this policy (exact context/params hash, numeric slots, PII
//! surrogate set, tenant filter) are in the gateway and in the store query.

use serde::{Deserialize, Serialize};

/// Thresholds never go above this, so an entry with a verified-wrong match at 1.0 still exists
/// (it just only serves identical prompts, which T1 usually answers first).
pub const MAX_THRESHOLD: f32 = 0.999;
/// Distance kept above the highest similarity at which an entry was verified wrong.
pub const MARGIN: f32 = 0.005;
/// Verified-correct observations an entry needs before its threshold may drop below the start.
pub const MIN_AGREEMENTS: u32 = 2;
/// Explore samples per tenant budget window.
pub const BUDGET_WINDOW: u32 = 50;
/// How much a tenant's thresholds tighten when a window goes over budget.
pub const OFFSET_STEP: f32 = 0.01;
/// Largest tightening (on top of each entry's threshold).
pub const MAX_OFFSET: f32 = 0.04;

/// Knobs from `[cache.semantic]`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThresholdPolicy {
    /// Starting per-entry threshold (conservative).
    pub threshold: f32,
    /// Floor for learned thresholds.
    pub min_threshold: f32,
    /// Width of the grey zone below an entry's threshold.
    pub grey_band: f32,
    /// Tenant error budget δ.
    pub max_error_rate: f32,
    /// Probability of verifying a would-be hit instead of serving it.
    pub verify_rate: f32,
}

impl Default for ThresholdPolicy {
    fn default() -> Self {
        Self { threshold: 0.95, min_threshold: 0.93, grey_band: 0.03, max_error_rate: 0.02, verify_rate: 0.05 }
    }
}

/// Verification history of one cached entry; stored with the entry (Qdrant payload), so it is
/// shared by every router and survives restarts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EntryStats {
    /// Times the entry was served.
    #[serde(default)]
    pub hits: u64,
    #[serde(default)]
    pub verified_ok: u32,
    #[serde(default)]
    pub verified_bad: u32,
    /// Lowest similarity at which the cached answer was verified correct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lowest_ok: Option<f32>,
    /// Highest similarity at which the cached answer was verified wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_bad: Option<f32>,
}

impl EntryStats {
    /// The entry's learned threshold under `p` (before the tenant offset).
    pub fn threshold(&self, p: &ThresholdPolicy) -> f32 {
        let mut t = p.threshold;
        if self.verified_ok >= MIN_AGREEMENTS
            && let Some(lo) = self.lowest_ok
        {
            t = t.min(lo);
        }
        if let Some(bad) = self.highest_bad {
            t = t.max(bad + MARGIN);
        }
        t.clamp(p.min_threshold.min(MAX_THRESHOLD), MAX_THRESHOLD)
    }

    /// Records one verification of this entry's answer against a prompt at `similarity`.
    pub fn observe(&mut self, similarity: f32, correct: bool) {
        if correct {
            self.verified_ok = self.verified_ok.saturating_add(1);
            self.lowest_ok = Some(self.lowest_ok.map_or(similarity, |l| l.min(similarity)));
        } else {
            self.verified_bad = self.verified_bad.saturating_add(1);
            self.highest_bad = Some(self.highest_bad.map_or(similarity, |b| b.max(similarity)));
        }
    }
}

/// Why a candidate is answered fresh and then compared with the cached answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyKind {
    /// At or above the threshold, sampled with `verify_rate`: an unbiased sample of hits, so it
    /// counts towards the tenant's error budget.
    Explore,
    /// Just below the threshold: a correct answer here is what lowers the entry's threshold.
    GreyZone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Serve,
    Verify(VerifyKind),
    Miss,
}

/// Decides what to do with a candidate at `similarity`. `tenant_offset` comes from
/// [`TenantBudget::offset`]; `draw` is uniform in `[0, 1)`.
pub fn decide(p: &ThresholdPolicy, stats: &EntryStats, similarity: f32, tenant_offset: f32, draw: f32) -> Decision {
    let t = (stats.threshold(p) + tenant_offset).min(MAX_THRESHOLD);
    if similarity >= t {
        if draw < p.verify_rate { Decision::Verify(VerifyKind::Explore) } else { Decision::Serve }
    } else if similarity >= (t - p.grey_band).max(p.min_threshold) {
        Decision::Verify(VerifyKind::GreyZone)
    } else {
        Decision::Miss
    }
}

/// Per-tenant error budget over explore samples (process-local).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TenantBudget {
    ok: u32,
    bad: u32,
    offset: f32,
}

impl TenantBudget {
    /// Added to every entry threshold of the tenant.
    pub fn offset(&self) -> f32 {
        self.offset
    }

    /// Sampled error rate of the current window, if it has samples.
    pub fn error_rate(&self) -> Option<f32> {
        let n = self.ok + self.bad;
        #[allow(clippy::cast_precision_loss)]
        (n > 0).then(|| self.bad as f32 / n as f32)
    }

    /// Records the outcome of one explore verification.
    pub fn observe(&mut self, correct: bool, p: &ThresholdPolicy) {
        if correct {
            self.ok += 1;
        } else {
            self.bad += 1;
        }
        #[allow(clippy::cast_precision_loss)]
        let allowed = p.max_error_rate * BUDGET_WINDOW as f32;
        #[allow(clippy::cast_precision_loss)]
        if self.bad as f32 > allowed {
            // Over budget, even if the window is not full yet: tighten now.
            self.offset = (self.offset + OFFSET_STEP).min(MAX_OFFSET);
            self.ok = 0;
            self.bad = 0;
        } else if self.ok + self.bad >= BUDGET_WINDOW {
            if (self.bad as f32) <= allowed / 2.0 {
                self.offset = (self.offset - OFFSET_STEP / 2.0).max(0.0);
            }
            self.ok = 0;
            self.bad = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: ThresholdPolicy = ThresholdPolicy {
        threshold: 0.95,
        min_threshold: 0.90,
        grey_band: 0.03,
        max_error_rate: 0.02,
        verify_rate: 0.0,
    };

    #[test]
    fn fresh_entry_uses_the_conservative_threshold() {
        let s = EntryStats::default();
        assert_eq!(s.threshold(&P), 0.95);
        assert_eq!(decide(&P, &s, 0.96, 0.0, 0.5), Decision::Serve);
        assert_eq!(decide(&P, &s, 0.95, 0.0, 0.5), Decision::Serve);
        assert_eq!(decide(&P, &s, 0.93, 0.0, 0.5), Decision::Verify(VerifyKind::GreyZone));
        assert_eq!(decide(&P, &s, 0.919, 0.0, 0.5), Decision::Miss);
    }

    #[test]
    fn explore_samples_would_be_hits() {
        let p = ThresholdPolicy { verify_rate: 0.1, ..P };
        let s = EntryStats::default();
        assert_eq!(decide(&p, &s, 0.99, 0.0, 0.05), Decision::Verify(VerifyKind::Explore));
        assert_eq!(decide(&p, &s, 0.99, 0.0, 0.10), Decision::Serve);
        // Explore never applies below the threshold.
        assert_eq!(decide(&p, &s, 0.93, 0.0, 0.0), Decision::Verify(VerifyKind::GreyZone));
    }

    #[test]
    fn verified_agreement_lowers_the_threshold_but_not_below_the_floor() {
        let mut s = EntryStats::default();
        s.observe(0.93, true);
        assert_eq!(s.threshold(&P), 0.95, "one agreement is not enough");
        s.observe(0.94, true);
        assert_eq!(s.threshold(&P), 0.93, "lowest verified-correct similarity");
        assert_eq!(decide(&P, &s, 0.931, 0.0, 0.5), Decision::Serve);
        assert_eq!(decide(&P, &s, 0.91, 0.0, 0.5), Decision::Verify(VerifyKind::GreyZone));
        s.observe(0.85, true);
        assert_eq!(s.threshold(&P), 0.90, "floored at min_threshold");
        assert_eq!(decide(&P, &s, 0.899, 0.0, 0.5), Decision::Miss, "no grey zone below the floor");
    }

    #[test]
    fn a_wrong_answer_raises_the_threshold_above_it() {
        let mut s = EntryStats::default();
        s.observe(0.97, false);
        assert!((s.threshold(&P) - 0.975).abs() < 1e-6);
        assert_eq!(decide(&P, &s, 0.97, 0.0, 0.5), Decision::Verify(VerifyKind::GreyZone));
        assert_eq!(decide(&P, &s, 0.98, 0.0, 0.5), Decision::Serve);
        // Later agreements below the wrong one cannot pull it back under.
        s.observe(0.92, true);
        s.observe(0.93, true);
        assert!((s.threshold(&P) - 0.975).abs() < 1e-6);
        // Wrong even at identical similarity: capped, never above MAX_THRESHOLD.
        s.observe(1.0, false);
        assert_eq!(s.threshold(&P), MAX_THRESHOLD);
    }

    #[test]
    fn tenant_offset_tightens_every_entry() {
        let s = EntryStats::default();
        assert_eq!(decide(&P, &s, 0.955, 0.0, 0.5), Decision::Serve);
        assert_eq!(decide(&P, &s, 0.955, 0.01, 0.5), Decision::Verify(VerifyKind::GreyZone));
    }

    #[test]
    fn budget_tightens_when_errors_exceed_delta_and_relaxes_after_clean_windows() {
        let mut b = TenantBudget::default();
        // δ = 2% of a 50-sample window allows 1 error.
        b.observe(false, &P);
        assert_eq!(b.offset(), 0.0);
        b.observe(true, &P);
        b.observe(false, &P);
        assert!((b.offset() - OFFSET_STEP).abs() < 1e-6, "second error in the window is over budget");
        assert_eq!(b.error_rate(), None, "window reset");
        for _ in 0..BUDGET_WINDOW {
            b.observe(true, &P);
        }
        assert!((b.offset() - OFFSET_STEP / 2.0).abs() < 1e-6, "a clean window relaxes by half a step");
        for _ in 0..10 {
            for _ in 0..2 {
                b.observe(false, &P);
            }
        }
        assert!((b.offset() - MAX_OFFSET).abs() < 1e-6, "capped");
    }

    #[test]
    fn stats_round_trip_as_payload() {
        let mut s = EntryStats { hits: 3, ..Default::default() };
        s.observe(0.94, true);
        let v = serde_json::to_value(&s).unwrap();
        assert!(v.get("highest_bad").is_none());
        assert_eq!(serde_json::from_value::<EntryStats>(v).unwrap(), s);
        assert_eq!(serde_json::from_value::<EntryStats>(serde_json::json!({})).unwrap(), EntryStats::default());
    }
}
