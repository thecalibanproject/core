//! Routing-policy evaluation against the matched-cost random two-model mix (research note 02,
//! "Gates"; arXiv 2610.02762). See `caliban_route::eval`.
//!
//! Always: core's Stage-4 policy (`policy::select`, route tables and quality floors) is evaluated
//! on a small built-in outcome matrix, and the report is printed with its baselines.
//!
//! On real data (skipped unless `CALIBAN_ROUTE_EVAL_MATRIX` is set): an outcome matrix (JSON
//! Lines, one `caliban_route::eval::Outcome` per line: `id`, `intent`, `band`, `results` per
//! model with `quality` and `cost_usd`), the Caliban config whose routing is evaluated
//! (`CALIBAN_ROUTE_EVAL_CONFIG`, default `config/caliban.example.toml`), the tenant
//! (`CALIBAN_ROUTE_EVAL_TENANT`, default the first), and `CALIBAN_ROUTE_EVAL_MARGIN` (default 0.01)
//! for the gate: the test fails when the policy does not beat the mix overall, or falls below it in a
//! band.
//!
//! ```text
//! CALIBAN_ROUTE_EVAL_MATRIX=held_out.jsonl CALIBAN_ROUTE_EVAL_CONFIG=caliban.toml \
//! cargo test -p caliban-route --test route_eval -- --nocapture
//! ```
//!
//! The intent comes from the matrix (Stage 1 is measured by `knn_eval`), so this measures the
//! model choice per intent; the pool is every model of the matrix. A matrix should be held out
//! (other tenants, intents or time windows than the policy was tuned on).

use caliban_config::{Config, Snapshot};
use caliban_ir::ChatRequest;
use caliban_route::eval::{self, Outcome, Report};
use caliban_route::policy::{self, QualitySource};
use caliban_route::{AlwaysHealthy, Constraints};

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

/// The model Stage 4 picks for each row (its labelled intent).
fn choices(snap: &Snapshot, tenant: &str, rows: &[Outcome]) -> Vec<String> {
    let t = snap.tenant(&tenant.into()).expect("tenant");
    let q = QualitySource { snap, profile: None };
    rows.iter()
        .map(|r| {
            let text = r.prompt.clone().unwrap_or_else(|| "x".into());
            let body = serde_json::json!({"model": "caliban/auto", "messages": [{"role": "user", "content": text}]});
            let req = ChatRequest::from_openai_json(body.to_string().as_bytes()).expect("request");
            let intent = r.intent.as_deref().unwrap_or(policy::DEFAULT_INTENT);
            let sel =
                policy::select(snap, t, &req, Constraints::default(), intent, &q, &AlwaysHealthy).expect("select");
            sel.candidates[0].to_string()
        })
        .collect()
}

fn print(r: &Report) {
    println!(
        "policy: quality {:.4} at ${:.6}/query ({} queries)",
        r.policy.quality, r.policy.cost_usd, r.policy.queries
    );
    println!(
        "random mix at matched cost: {:.0}% {} + {:.0}% {}: quality {:.4} at ${:.6}/query",
        r.mix.p_strong * 100.0,
        r.mix.strong,
        (1.0 - r.mix.p_strong) * 100.0,
        r.mix.cheap,
        r.mix.point.quality,
        r.mix.point.cost_usd
    );
    if let Some(o) = r.one_model_per_intent {
        println!("one model per intent: quality {:.4} at ${:.6}/query", o.quality, o.cost_usd);
    }
    for (band, b) in &r.bands {
        println!(
            "  band {band}: policy {:.4} at ${:.6}, mix {:.4} ({} queries)",
            b.policy.quality, b.policy.cost_usd, b.mix.point.quality, b.policy.queries
        );
    }
    for (m, c) in &r.mean_cost_usd {
        println!("  {m}: mean quality {:.4}, mean cost ${c:.6}/query", r.mean_quality[m]);
    }
}

const CONFIG: &str = r#"
[routing]
floors = { code = 0.8 }

[routing.quality."pool/small"]
faq = 0.9
code = 0.3

[routing.quality."pool/large"]
faq = 0.95
code = 0.9

[[providers]]
id = "pool"
kind = "openai_compatible"
base_url = "http://pool.invalid/v1"
trust_tier = "t0_sovereign"

[[models]]
id = "pool/small"
provider = "pool"
upstream_model = "small"
trust_tier = "t0_sovereign"
price_in_per_mtok = 0.1
price_out_per_mtok = 0.2

[[models]]
id = "pool/large"
provider = "pool"
upstream_model = "large"
trust_tier = "t0_sovereign"
price_in_per_mtok = 2.0
price_out_per_mtok = 6.0

[[tenants]]
id = "acme"
name = "Acme"
  [[tenants.routes]]
  intent = "default"
  models = ["pool/small", "pool/large"]
  [[tenants.routes]]
  intent = "faq"
  models = ["pool/small", "pool/large"]
  [[tenants.routes]]
  intent = "code"
  models = ["pool/small", "pool/large"]
"#;

/// FAQs are easy (the small model solves them), code questions are hard (only the large one).
fn built_in() -> Vec<Outcome> {
    let mut rows = Vec::new();
    for i in 0..12 {
        let (intent, band, small, large) =
            if i % 3 == 0 { ("code", "hard", 0.0, 1.0) } else { ("faq", "easy", 1.0, 1.0) };
        let line = serde_json::json!({"id": format!("q{i}"), "intent": intent, "band": band, "results": {
            "pool/small": {"quality": small, "cost_usd": 0.0002}, "pool/large": {"quality": large, "cost_usd": 0.004}}});
        rows.push(serde_json::from_value(line).unwrap());
    }
    rows
}

#[test]
fn stage_4_beats_the_matched_cost_random_mix_on_the_built_in_matrix() {
    let snap = Snapshot::new(Config::from_toml_str(CONFIG).unwrap(), "t");
    let rows = built_in();
    let chosen = choices(&snap, "acme", &rows);
    let pool = vec!["pool/small".to_owned(), "pool/large".to_owned()];
    let r = eval::evaluate(&rows, &chosen, &pool).unwrap();
    print(&r);
    // The floor sends code to the large model and FAQs to the cheapest: every query solved, at a
    // third of the large model's cost; the mix at that cost solves 0.67 + 0.33 * 0.33.
    assert!((r.policy.quality - 1.0).abs() < 1e-9, "{r:?}");
    assert!(eval::gate(&r, 0.01).is_ok(), "{r:?}");
    // Without the floor (route order only: the small model for everything) it is the cheap end of
    // the mix, so it cannot beat it.
    let blind: Vec<String> = vec!["pool/small".into(); rows.len()];
    let r = eval::evaluate(&rows, &blind, &pool).unwrap();
    assert!(eval::gate(&r, 0.0).is_err(), "{r:?}");
}

#[test]
fn a_held_out_matrix_against_the_configured_policy() {
    let Some(path) = env("CALIBAN_ROUTE_EVAL_MATRIX") else {
        eprintln!("CALIBAN_ROUTE_EVAL_MATRIX not set; skipping the routing gate on real data");
        return;
    };
    let rows = eval::parse_matrix(&std::fs::read_to_string(&path).expect("matrix")).expect("matrix");
    let cfg_path = env("CALIBAN_ROUTE_EVAL_CONFIG").unwrap_or_else(|| "../../config/caliban.example.toml".into());
    let cfg = Config::from_toml_str(&std::fs::read_to_string(&cfg_path).expect("config")).expect("config");
    let snap = Snapshot::new(cfg, "eval");
    let tenant = env("CALIBAN_ROUTE_EVAL_TENANT").unwrap_or_else(|| snap.config.tenants[0].id.to_string());
    let chosen = choices(&snap, &tenant, &rows);
    let pool: Vec<String> = rows[0].results.keys().cloned().collect();
    let r = eval::evaluate(&rows, &chosen, &pool).expect("evaluate");
    print(&r);
    let margin = env("CALIBAN_ROUTE_EVAL_MARGIN").and_then(|m| m.parse().ok()).unwrap_or(0.01);
    if let Err(why) = eval::gate(&r, margin) {
        panic!("the routing policy would not be promoted:\n{}", why.join("\n"));
    }
}
