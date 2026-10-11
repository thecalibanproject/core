//! Offline evaluation of a routing policy against an outcome matrix, with the baselines a policy
//! must beat before it is promoted (research note 02, "Gates").
//!
//! An outcome matrix records, per query, what every model of the pool scored on it and what it
//! cost (a RouterBench-style table, built from probe sets or audited production traffic). A policy
//! is evaluated by the model it chooses for each query. The report compares it with:
//!
//! - **a random two-model mix at matched cost** (the route's cheapest model and its most accurate
//!   model, mixed with the probability that gives the policy's cost). "Dynamic LLM Routers are Often
//!   Misguided" (arXiv 2610.02762, preprint) found that none of six commercial routers beat it, so a
//!   policy that does not beat it adds nothing over a coin flip between two models;
//! - **one model per intent** (each intent's most accurate model), the table that captures most of
//!   the task-type gain (LLMRouterBench, arXiv 2601.07206).
//!
//! **Cost is each model's mean cost per query** over the matrix, not the realized cost of each
//! answer: the realized-cost metric rewards routing short or easy queries to expensive models
//! (difficulty blindness, length reversal, routing by source; arXiv 2610.02762). Hard and easy
//! bands are reported separately when the matrix labels them.
//!
//! [`gate`] is the promotion rule (beat the mix overall, match it in every band). `core` has no promotion step for routing policies, exemplar sets
//! or calibrations yet (they come as `ml` artifacts and config); when it has one, it must call
//! [`gate`] on a held-out matrix and refuse the promotion when it fails. Until then the rule is
//! applied offline (`cargo test -p caliban-route --test route_eval`).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What one model did on one query.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ModelResult {
    /// 0 to 1 (1: correct).
    pub quality: f64,
    pub cost_usd: f64,
}

/// One row of an outcome matrix (JSON Lines: one object per line).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub id: String,
    /// The intent the query belongs to (for the per-intent baseline and Stage-4 policies).
    #[serde(default)]
    pub intent: Option<String>,
    /// `hard` or `easy` (or any band name): reported separately.
    #[serde(default)]
    pub band: Option<String>,
    /// The prompt, when a policy needs it (a classifier); absent in metric-only matrices.
    #[serde(default)]
    pub prompt: Option<String>,
    /// Model id to what it did. Every model of the pool must be present.
    pub results: BTreeMap<String, ModelResult>,
}

/// Mean quality and mean cost per query of a set of choices.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Point {
    pub quality: f64,
    pub cost_usd: f64,
    pub queries: usize,
}

/// The random two-model mix at the policy's cost.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Mix {
    /// The pool's cheapest model (by mean cost per query).
    pub cheap: String,
    /// The pool's most accurate model (by mean quality; the cheaper on a tie).
    pub strong: String,
    /// Probability of sending a query to `strong`.
    pub p_strong: f64,
    pub point: Point,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BandReport {
    pub policy: Point,
    pub mix: Mix,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub policy: Point,
    pub mix: Mix,
    /// Each intent's most accurate model (the cheaper on a tie), over the queries of that intent.
    pub one_model_per_intent: Option<Point>,
    /// Mean cost per query of every model of the pool (how every cost here is scored).
    pub mean_cost_usd: BTreeMap<String, f64>,
    pub mean_quality: BTreeMap<String, f64>,
    pub bands: BTreeMap<String, BandReport>,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EvalError {
    #[error("the matrix is empty")]
    Empty,
    #[error("query {0}: no result for model {1}")]
    Missing(String, String),
    #[error("{0} choices for {1} queries")]
    Length(usize, usize),
    #[error("the pool is empty")]
    EmptyPool,
}

fn mean(xs: impl Iterator<Item = f64>) -> f64 {
    let (s, n) = xs.fold((0.0, 0usize), |(s, n), x| (s + x, n + 1));
    if n == 0 { 0.0 } else { s / n as f64 }
}

/// Mean quality and mean cost per query of each pool model over `rows`.
fn per_model(rows: &[&Outcome], pool: &[String]) -> (BTreeMap<String, f64>, BTreeMap<String, f64>) {
    let q = pool.iter().map(|m| (m.clone(), mean(rows.iter().map(|r| r.results[m].quality)))).collect();
    let c = pool.iter().map(|m| (m.clone(), mean(rows.iter().map(|r| r.results[m].cost_usd)))).collect();
    (q, c)
}

/// The matched-cost mix of the pool's cheapest and most accurate models, at `cost`.
fn mix(pool: &[String], quality: &BTreeMap<String, f64>, cost: &BTreeMap<String, f64>, at_cost: f64) -> Mix {
    let by = |a: &&String, b: &&String, f: &BTreeMap<String, f64>| f[*a].total_cmp(&f[*b]);
    let cheap = pool.iter().min_by(|a, b| by(a, b, cost).then_with(|| by(b, a, quality))).expect("pool").clone();
    let strong = pool.iter().max_by(|a, b| by(a, b, quality).then_with(|| by(b, a, cost))).expect("pool").clone();
    let (cc, cs) = (cost[&cheap], cost[&strong]);
    let p = if cs > cc { ((at_cost - cc) / (cs - cc)).clamp(0.0, 1.0) } else { 0.0 };
    let point = Point {
        quality: p * quality[&strong] + (1.0 - p) * quality[&cheap],
        cost_usd: p * cs + (1.0 - p) * cc,
        queries: 0,
    };
    Mix { cheap, strong, p_strong: p, point }
}

/// Evaluates `choices` (the model chosen for each row, in order) over `rows` with `pool` as the
/// route's models. Costs are each model's mean cost per query over the rows considered.
pub fn evaluate(rows: &[Outcome], choices: &[String], pool: &[String]) -> Result<Report, EvalError> {
    if rows.is_empty() {
        return Err(EvalError::Empty);
    }
    if pool.is_empty() {
        return Err(EvalError::EmptyPool);
    }
    if rows.len() != choices.len() {
        return Err(EvalError::Length(choices.len(), rows.len()));
    }
    for r in rows {
        for m in pool.iter().chain(choices.iter()) {
            if !r.results.contains_key(m) {
                return Err(EvalError::Missing(r.id.clone(), m.clone()));
            }
        }
    }
    let all: Vec<&Outcome> = rows.iter().collect();
    let mut models: Vec<String> = pool.to_vec();
    for c in choices {
        if !models.contains(c) {
            models.push(c.clone());
        }
    }
    let (mean_quality, mean_cost_usd) = per_model(&all, &models);
    let point_of = |idx: &[usize], cost: &BTreeMap<String, f64>| Point {
        quality: mean(idx.iter().map(|&i| rows[i].results[&choices[i]].quality)),
        cost_usd: mean(idx.iter().map(|&i| cost[&choices[i]])),
        queries: idx.len(),
    };
    let every: Vec<usize> = (0..rows.len()).collect();
    let policy = point_of(&every, &mean_cost_usd);
    let pool_q: BTreeMap<String, f64> = pool.iter().map(|m| (m.clone(), mean_quality[m])).collect();
    let pool_c: BTreeMap<String, f64> = pool.iter().map(|m| (m.clone(), mean_cost_usd[m])).collect();
    let mut m = mix(pool, &pool_q, &pool_c, policy.cost_usd);
    m.point.queries = rows.len();

    // One model per intent: the most accurate pool model of each intent.
    let mut intents: BTreeMap<&str, Vec<&Outcome>> = BTreeMap::new();
    for r in rows {
        if let Some(i) = &r.intent {
            intents.entry(i.as_str()).or_default().push(r);
        }
    }
    let one_model_per_intent = (intents.values().map(Vec::len).sum::<usize>() == rows.len()).then(|| {
        let (mut q, mut c) = (0.0, 0.0);
        for group in intents.values() {
            let (gq, _) = per_model(group, pool);
            let best = pool
                .iter()
                .max_by(|a, b| gq[*a].total_cmp(&gq[*b]).then_with(|| mean_cost_usd[*b].total_cmp(&mean_cost_usd[*a])))
                .expect("pool");
            q += gq[best] * group.len() as f64;
            c += mean_cost_usd[best] * group.len() as f64;
        }
        Point { quality: q / rows.len() as f64, cost_usd: c / rows.len() as f64, queries: rows.len() }
    });

    // Bands: the policy and the mix within each band, costs still the pool's means over the band.
    let mut bands = BTreeMap::new();
    let mut by_band: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, r) in rows.iter().enumerate() {
        if let Some(b) = &r.band {
            by_band.entry(b.as_str()).or_default().push(i);
        }
    }
    for (band, idx) in by_band {
        let sub: Vec<&Outcome> = idx.iter().map(|&i| &rows[i]).collect();
        let (bq, bc) = per_model(&sub, &models);
        let p = point_of(&idx, &bc);
        let pq: BTreeMap<String, f64> = pool.iter().map(|m| (m.clone(), bq[m])).collect();
        let pc: BTreeMap<String, f64> = pool.iter().map(|m| (m.clone(), bc[m])).collect();
        let mut bm = mix(pool, &pq, &pc, p.cost_usd);
        bm.point.queries = idx.len();
        bands.insert(band.to_owned(), BandReport { policy: p, mix: bm });
    }
    Ok(Report { policy, mix: m, one_model_per_intent, mean_cost_usd, mean_quality, bands })
}

/// The promotion rule: overall, the policy must beat the matched-cost random two-model mix by
/// more than `margin` (quality points, e.g. 0.01); in each labelled band it must not fall below
/// that band's mix by more than `margin` (within one band the best single model is often an end of
/// the mix, so a band can only be matched, not beaten). `Err` lists why not.
pub fn gate(r: &Report, margin: f64) -> Result<(), Vec<String>> {
    let mut why = Vec::new();
    let mut check = |what: &str, p: &Point, m: &Mix, beat: bool| {
        let ok = if beat { p.quality > m.point.quality + margin } else { p.quality >= m.point.quality - margin };
        if !ok {
            why.push(format!(
                "{what}: quality {:.4} at ${:.6}/query {} the random mix of {} and {} ({:.0}% {}) at matched cost: \
                 {:.4} (margin {margin})",
                p.quality,
                p.cost_usd,
                if beat { "does not beat" } else { "falls below" },
                m.cheap,
                m.strong,
                m.p_strong * 100.0,
                m.strong,
                m.point.quality
            ));
        }
    };
    check("overall", &r.policy, &r.mix, true);
    for (band, b) in &r.bands {
        check(&format!("band {band}"), &b.policy, &b.mix, false);
    }
    if why.is_empty() { Ok(()) } else { Err(why) }
}

/// Reads an outcome matrix (JSON Lines; blank lines and `#` comments are skipped).
pub fn parse_matrix(text: &str) -> Result<Vec<Outcome>, String> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|(n, l)| serde_json::from_str(l).map_err(|e| format!("line {}: {e}", n + 1)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, intent: &str, band: &str, cheap: f64, strong: f64) -> Outcome {
        Outcome {
            id: id.into(),
            intent: Some(intent.into()),
            band: Some(band.into()),
            prompt: None,
            results: [
                ("cheap".to_owned(), ModelResult { quality: cheap, cost_usd: 0.001 }),
                ("strong".to_owned(), ModelResult { quality: strong, cost_usd: 0.010 }),
            ]
            .into(),
        }
    }

    /// 10 queries: the cheap model solves the 6 easy ones, the strong one solves all but one.
    fn matrix() -> Vec<Outcome> {
        let mut rows = Vec::new();
        for i in 0..6 {
            rows.push(row(&format!("e{i}"), "faq", "easy", 1.0, 1.0));
        }
        for i in 0..4 {
            rows.push(row(&format!("h{i}"), "code", "hard", 0.0, if i == 3 { 0.0 } else { 1.0 }));
        }
        rows
    }

    fn pool() -> Vec<String> {
        vec!["cheap".into(), "strong".into()]
    }

    #[test]
    fn a_policy_that_knows_difficulty_beats_the_matched_cost_mix() {
        let rows = matrix();
        // Easy to cheap, hard to strong: quality 0.9 at mean cost 0.4 * 0.010 + 0.6 * 0.001.
        let choices: Vec<String> =
            rows.iter().map(|r| if r.band.as_deref() == Some("easy") { "cheap" } else { "strong" }.into()).collect();
        let r = evaluate(&rows, &choices, &pool()).unwrap();
        assert!((r.policy.quality - 0.9).abs() < 1e-9 && (r.policy.cost_usd - 0.0046).abs() < 1e-12, "{r:?}");
        // The mix at that cost: 40% strong (0.9 quality), 60% cheap (0.6): 0.72.
        assert_eq!((r.mix.cheap.as_str(), r.mix.strong.as_str()), ("cheap", "strong"));
        assert!((r.mix.p_strong - 0.4).abs() < 1e-9 && (r.mix.point.quality - 0.72).abs() < 1e-9, "{:?}", r.mix);
        assert!(gate(&r, 0.01).is_ok(), "{r:?}");
        // One model per intent: faq -> cheap (tie, cheaper), code -> strong.
        let one = r.one_model_per_intent.unwrap();
        assert!((one.quality - 0.9).abs() < 1e-9 && (one.cost_usd - 0.0046).abs() < 1e-12);
        assert_eq!(r.bands.len(), 2);
    }

    #[test]
    fn a_difficulty_blind_policy_fails_the_gate() {
        let rows = matrix();
        // Routes by source: the first four queries (easy ones) to the strong model.
        let choices: Vec<String> = (0..rows.len()).map(|i| if i < 4 { "strong" } else { "cheap" }.into()).collect();
        let r = evaluate(&rows, &choices, &pool()).unwrap();
        let why = gate(&r, 0.0).unwrap_err();
        assert!(why[0].starts_with("overall") && why[0].contains("random mix of cheap and strong"), "{why:?}");
    }

    /// Cost is the model's mean cost per query: a policy cannot look cheap by sending the strong
    /// model only the queries where it happens to be cheap (length reversal).
    #[test]
    fn cost_is_the_mean_cost_per_query_not_the_realized_cost() {
        let mut rows = matrix();
        for (i, r) in rows.iter_mut().enumerate() {
            r.results.get_mut("strong").unwrap().cost_usd = if i < 6 { 0.001 } else { 0.019 };
        }
        let choices: Vec<String> =
            rows.iter().map(|r| if r.band.as_deref() == Some("easy") { "strong" } else { "cheap" }.into()).collect();
        let r = evaluate(&rows, &choices, &pool()).unwrap();
        // Realized cost would be 6 * 0.001 + 4 * 0.001 over 10; mean cost per query scores the
        // strong model at its mean, 0.0082.
        assert!((r.mean_cost_usd["strong"] - 0.0082).abs() < 1e-12);
        assert!((r.policy.cost_usd - (0.6 * 0.0082 + 0.4 * 0.001)).abs() < 1e-12, "{r:?}");
    }

    #[test]
    fn bad_matrices_are_refused_and_jsonl_parses() {
        let rows = matrix();
        assert_eq!(evaluate(&[], &[], &pool()), Err(EvalError::Empty));
        assert_eq!(evaluate(&rows, &[], &pool()), Err(EvalError::Length(0, 10)));
        let other: Vec<String> = vec!["nope".into(); rows.len()];
        assert!(matches!(evaluate(&rows, &other, &pool()), Err(EvalError::Missing(..))));
        let text = "# a matrix\n{\"id\": \"q1\", \"intent\": \"faq\", \"results\": {\"cheap\": {\"quality\": 1, \"cost_usd\": 0.001}}}\n\n";
        let m = parse_matrix(text).unwrap();
        assert_eq!((m.len(), m[0].results["cheap"].quality), (1, 1.0));
        assert!(parse_matrix("{").unwrap_err().starts_with("line 1"));
    }
}
