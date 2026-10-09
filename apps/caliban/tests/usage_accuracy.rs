//! Usage accuracy: the gateway's metered usage (the JSONL usage WAL) against the "provider bill"
//! (the usage the mock upstream reported for every request it served), request by request,
//! across both dialects, streams, translation in both directions, native Anthropic passthrough
//! with prompt caching, provider-side prefix caching, exact-cache hits, fallbacks and PII.
//!
//! P0 exit criterion: "Usage matches provider bills within 1%". Token counts must match exactly
//! (no estimation is involved when the upstream reports usage). Cost is checked against the
//! gateway's own catalogue prices; two known gaps are `#[ignore]`d tests below.
//!
//! Set `USAGE_REPORT=path.md` to write the per-path table (scripts/bench.sh does).

use caliban_bench::harness::{Caliban, Launch, Reply, new_key};
use caliban_bench::mock::{Bill, Mock, MockConfig};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

const PRICES: [(&str, f64, f64); 3] = [("oa/m", 1.0, 2.0), ("anth/m", 3.0, 15.0), ("oa/fail", 1.0, 2.0)];

fn price(model: &str) -> (f64, f64) {
    PRICES.iter().find(|p| p.0 == model).map(|p| (p.1, p.2)).expect("priced model")
}

fn config(base: &str, hash: &str) -> String {
    let models: String = [("oa/m", "oa", "mock-oa"), ("anth/m", "anth", "claude-mock"), ("oa/fail", "oa", "mock-fail-500")]
        .iter()
        .map(|(id, p, up)| {
            let (i, o) = price(id);
            format!("[[models]]\nid = \"{id}\"\nprovider = \"{p}\"\nupstream_model = \"{up}\"\ntrust_tier = \"t2_contracted\"\nprice_in_per_mtok = {i}\nprice_out_per_mtok = {o}\n\n")
        })
        .collect();
    format!(
        r#"
[cache]
exact_enabled = true

{models}
[[tenants]]
id = "acct"
name = "Accounting"
pii_mode = "reversible"
api_key_hashes = ["{hash}"]
  [[tenants.providers]]
  id = "oa"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  api_key = {{ env = "ACCT_OA_KEY" }}
  [[tenants.providers]]
  id = "anth"
  kind = "anthropic"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  api_key = {{ env = "ACCT_ANTH_KEY" }}
  # Every route starts with a failing model: the fallback must not be billed twice.
  [[tenants.routes]]
  intent = "default"
  models = ["oa/fail", "oa/m"]
  [[tenants.routes]]
  intent = "chat"
  models = ["oa/fail", "oa/m"]
"#
    )
}

struct Env {
    mock: Mock,
    gw: Caliban,
    key: String,
}

async fn setup() -> Env {
    let mock = Mock::start("127.0.0.1:0", MockConfig { chunk_chars: 3, ..Default::default() }).await.unwrap();
    let (key, hash) = new_key("acct");
    let launch = Launch {
        config: config(&mock.base_url(), &hash),
        env: vec![("ACCT_OA_KEY".into(), "sk-oa".into()), ("ACCT_ANTH_KEY".into(), "sk-anth".into())],
        usage_wal: true,
        ..Default::default()
    };
    let gw = Caliban::start(Path::new(env!("CARGO_BIN_EXE_caliban")), &launch).await.unwrap();
    Env { mock, gw, key }
}

#[derive(Clone, Copy)]
enum Api {
    OpenAi,
    Anthropic,
}

/// One request and what it was metered and billed as.
struct Sample {
    label: &'static str,
    event: Value,
    bills: Vec<Bill>,
}

impl Sample {
    fn billed_prompt(&self) -> u64 {
        self.bills.iter().map(Bill::total_prompt_tokens).sum()
    }
    fn billed_completion(&self) -> u64 {
        self.bills.iter().map(|b| b.output_tokens).sum()
    }
    fn billed_cached(&self) -> u64 {
        self.bills.iter().map(|b| b.cache_read_tokens).sum()
    }
    fn metered(&self, k: &str) -> u64 {
        self.event[k].as_u64().unwrap_or(0)
    }
    /// The gateway's list-price cost for the billed tokens (what the event should say).
    fn expected_list_cost(&self) -> f64 {
        let (i, o) = price(self.event["model"].as_str().unwrap());
        (self.billed_prompt() as f64 * i + self.billed_completion() as f64 * o) / 1e6
    }
    /// What a provider would actually charge, with its prompt-cache pricing: Anthropic cache
    /// reads at 0.1x and writes at 1.25x the input price; OpenAI cached input at 0.5x.
    fn provider_cost(&self) -> f64 {
        let (i, o) = price(self.event["model"].as_str().unwrap());
        self.bills
            .iter()
            .map(|b| {
                let input = if b.anthropic {
                    b.input_tokens as f64 * i + b.cache_read_tokens as f64 * 0.1 * i + b.cache_creation_tokens as f64 * 1.25 * i
                } else {
                    (b.input_tokens - b.cache_read_tokens) as f64 * i + b.cache_read_tokens as f64 * 0.5 * i
                };
                (input + b.output_tokens as f64 * o) / 1e6
            })
            .sum()
    }
}

impl Env {
    /// Sends one request, reads it to the end, waits for its usage event, and pairs the event
    /// with the bills the mock recorded meanwhile. Requests are sequential, so the pairing is
    /// exact.
    async fn sample(&self, label: &'static str, api: Api, body: Value) -> Sample {
        let wal_before = self.gw.wal_events().len();
        let log_before = self.mock.len();
        let r: Reply = match api {
            Api::OpenAi => self.gw.chat(&self.key, &body).await,
            Api::Anthropic => self.gw.messages(&self.key, &body).await,
        };
        assert!(r.status.is_success(), "{label}: {} {}", r.status, r.text);
        let mut events = Vec::new();
        for _ in 0..200 {
            events = self.gw.wal_events();
            if events.len() > wal_before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(events.len(), wal_before + 1, "{label}: exactly one usage event");
        let event = events.pop().unwrap();
        assert_eq!(event["request_id"].as_str().unwrap(), r.request_id(), "{label}: event pairs with the response");
        let bills = self.mock.log()[log_before..].iter().filter_map(|e| e.bill).collect();
        Sample { label, event, bills }
    }
}

fn msgs(text: &str) -> Value {
    json!([{"role": "user", "content": text}])
}

const PROMPTS: [&str; 6] = [
    "hi",
    "Summarise the attached quarterly report in three bullet points for the board.",
    "Email jane.doe@acme.com about card 4111 1111 1111 1111 and call +1 415 555 0100 tomorrow.",
    "Write a haiku about distributed systems and the people who keep them running at night.",
    "Translate to French: the invoice is attached and payment is due within thirty days of receipt.",
    "List five risks of moving the data warehouse to a new region, with one mitigation each, and keep it short.",
];

async fn run_workload(e: &Env) -> Vec<Sample> {
    let mut out = Vec::new();
    for (i, p) in PROMPTS.iter().enumerate() {
        let tag = format!("{p} [{i}]");
        out.push(e.sample("OpenAI client, OpenAI-compatible upstream, JSON", Api::OpenAi, json!({"model": "oa/m", "messages": msgs(&tag)})).await);
        out.push(e.sample("OpenAI client, OpenAI-compatible upstream, stream", Api::OpenAi, json!({"model": "oa/m", "stream": true, "messages": msgs(&tag)})).await);
        out.push(e.sample("OpenAI client, Anthropic upstream (translated), JSON", Api::OpenAi, json!({"model": "anth/m", "messages": msgs(&tag)})).await);
        out.push(
            e.sample("OpenAI client, Anthropic upstream (translated), stream", Api::OpenAi, json!({"model": "anth/m", "stream": true, "messages": msgs(&tag)})).await,
        );
        out.push(
            e.sample("Anthropic client, OpenAI-compatible upstream (translated), JSON", Api::Anthropic, json!({"model": "oa/m", "max_tokens": 128, "messages": msgs(&tag)}))
                .await,
        );
        out.push(
            e.sample(
                "Anthropic client, OpenAI-compatible upstream (translated), stream",
                Api::Anthropic,
                json!({"model": "oa/m", "max_tokens": 128, "stream": true, "messages": msgs(&tag)}),
            )
            .await,
        );
        out.push(
            e.sample("Anthropic client, Anthropic upstream (native), JSON", Api::Anthropic, json!({"model": "anth/m", "max_tokens": 128, "messages": msgs(&tag)})).await,
        );
        out.push(
            e.sample(
                "Anthropic client, Anthropic upstream (native), stream",
                Api::Anthropic,
                json!({"model": "anth/m", "max_tokens": 128, "stream": true, "messages": msgs(&tag)}),
            )
            .await,
        );
        out.push(e.sample("caliban/auto with fallback (first candidate 500s)", Api::OpenAi, json!({"model": "caliban/auto", "messages": msgs(&tag)})).await);
    }
    // Native Anthropic prompt caching: a cache_control breakpoint on a long system prompt; the
    // first request writes the cache, repeats read it.
    let system = json!([{"type": "text", "text": "You are the finance assistant. ".repeat(40), "cache_control": {"type": "ephemeral"}}]);
    for stream in [false, false, true, true] {
        let body = json!({"model": "anth/m", "max_tokens": 128, "stream": stream, "system": system, "messages": msgs(&format!("What is due this week? stream={stream}"))});
        out.push(e.sample("Anthropic native with cache_control (cache write, then reads)", Api::Anthropic, body.clone()).await);
        out.push(e.sample("Anthropic native with cache_control (cache write, then reads)", Api::Anthropic, body).await);
    }
    // Provider-side prefix cache on the OpenAI-compatible upstream (repeats report cached_tokens).
    for stream in [false, true] {
        let body = json!({"model": "oa/m", "stream": stream, "messages": msgs(&format!("Repeated long prompt for the prefix cache. stream={stream}"))});
        for _ in 0..3 {
            out.push(e.sample("OpenAI-compatible upstream, provider prefix-cache hits (cached_tokens)", Api::OpenAi, body.clone()).await);
        }
    }
    // Exact-cache hits: no upstream call, nothing billed, nothing metered.
    let body = json!({"model": "oa/m", "temperature": 0, "messages": msgs("What is the capital of France?")});
    for _ in 0..3 {
        out.push(e.sample("Gateway exact-cache (1 miss, then hits: not billed)", Api::OpenAi, body.clone()).await);
    }
    out
}

fn report(samples: &[Sample]) -> String {
    #[derive(Default)]
    struct Agg {
        n: usize,
        bp: u64,
        mp: u64,
        bc: u64,
        mc: u64,
        bk: u64,
        mk: u64,
        cost_expected: f64,
        cost_metered: f64,
        cost_provider: f64,
        hits: usize,
    }
    let mut by: BTreeMap<&str, Agg> = BTreeMap::new();
    let mut order = Vec::new();
    for s in samples {
        if !by.contains_key(s.label) {
            order.push(s.label);
        }
        let a = by.entry(s.label).or_default();
        a.n += 1;
        a.bp += s.billed_prompt();
        a.mp += s.metered("prompt_tokens");
        a.bc += s.billed_completion();
        a.mc += s.metered("completion_tokens");
        a.bk += s.billed_cached();
        a.mk += s.metered("cached_prompt_tokens");
        a.cost_expected += s.expected_list_cost();
        a.cost_metered += s.event["cost_usd"].as_f64().unwrap_or(0.0);
        a.cost_provider += s.provider_cost();
        a.hits += usize::from(s.event["cache"] == "hit");
    }
    let mut o = String::new();
    let _ = writeln!(o, "| Path | Requests | Prompt tokens (billed / metered) | Completion (billed / metered) | Cached prompt (billed / metered) | Cost, list price (expected / metered) | Provider cost with cache pricing | Metered vs provider |");
    let _ = writeln!(o, "|---|---:|---:|---:|---:|---:|---:|---:|");
    let mut total = Agg::default();
    for l in order {
        let a = &by[l];
        let diff = if a.cost_provider > 0.0 { (a.cost_metered - a.cost_provider) / a.cost_provider * 100.0 } else { 0.0 };
        let _ = writeln!(
            o,
            "| {l} | {}{} | {} / {} | {} / {} | {} / {} | {:.6} / {:.6} | {:.6} | {diff:+.1}% |",
            a.n,
            if a.hits > 0 { format!(" ({} cache hits)", a.hits) } else { String::new() },
            a.bp,
            a.mp,
            a.bc,
            a.mc,
            a.bk,
            a.mk,
            a.cost_expected,
            a.cost_metered,
            a.cost_provider
        );
        total.n += a.n;
        total.bp += a.bp;
        total.mp += a.mp;
        total.bc += a.bc;
        total.mc += a.mc;
        total.bk += a.bk;
        total.mk += a.mk;
        total.cost_expected += a.cost_expected;
        total.cost_metered += a.cost_metered;
        total.cost_provider += a.cost_provider;
    }
    let diff = (total.cost_metered - total.cost_provider) / total.cost_provider * 100.0;
    let _ = writeln!(
        o,
        "| **Total** | {} | {} / {} | {} / {} | {} / {} | {:.6} / {:.6} | {:.6} | {diff:+.1}% |",
        total.n, total.bp, total.mp, total.bc, total.mc, total.bk, total.mk, total.cost_expected, total.cost_metered, total.cost_provider
    );
    o
}

/// Every request: metered prompt, completion and cached tokens equal the bill exactly, and the
/// metered cost equals the bill at the gateway's catalogue prices. Cache hits are metered as
/// zero tokens and zero cost (the provider was not called). Fallbacks bill once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metered_usage_matches_provider_bills() {
    let e = setup().await;
    let samples = run_workload(&e).await;
    let table = report(&samples);
    println!("{table}");
    if let Ok(path) = std::env::var("USAGE_REPORT") {
        std::fs::write(path, &table).unwrap();
    }
    for s in &samples {
        let l = s.label;
        if s.event["cache"] == "hit" {
            assert!(s.bills.is_empty(), "{l}: a cache hit reached the provider");
            assert_eq!((s.metered("prompt_tokens"), s.metered("completion_tokens")), (0, 0), "{l}");
            assert!(s.metered("tokens_saved") > 0, "{l}: hits record tokens saved");
            continue;
        }
        assert_eq!(s.bills.len(), 1, "{l}: billed exactly once (fallback included)");
        assert_eq!(s.metered("prompt_tokens"), s.billed_prompt(), "{l}: prompt tokens");
        assert_eq!(s.metered("completion_tokens"), s.billed_completion(), "{l}: completion tokens");
        assert_eq!(s.metered("cached_prompt_tokens"), s.billed_cached(), "{l}: cached prompt tokens");
        let cost = s.event["cost_usd"].as_f64().expect("priced model has a cost");
        assert!((cost - s.expected_list_cost()).abs() < 1e-12, "{l}: cost {cost} vs {}", s.expected_list_cost());
    }
    // The workload must actually exercise the cache paths.
    assert!(samples.iter().any(|s| s.billed_cached() > 0 && !s.bills[0].anthropic), "OpenAI-side cached tokens exercised");
    assert!(samples.iter().any(|s| s.bills.first().is_some_and(|b| b.cache_creation_tokens > 0)), "Anthropic cache writes exercised");
    assert!(samples.iter().any(|s| s.event["cache"] == "hit"), "gateway cache hits exercised");
}

/// KNOWN GAP: cost ignores provider prompt-cache pricing. The gateway prices every prompt token
/// at `price_in_per_mtok`, but providers charge cache reads at a discount (Anthropic 0.1x, OpenAI
/// 0.5x or less) and Anthropic cache writes at 1.25x. With prompt caching in play the metered
/// cost overstates the bill well beyond 1%. Fix: add cached-read and cache-write prices to the
/// catalogue and carry `cache_creation_input_tokens` in the usage event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "known gap: cost does not apply provider prompt-cache pricing (bench/RESULTS.md)"]
async fn cost_matches_provider_bill_with_prompt_caching() {
    let e = setup().await;
    let system = json!([{"type": "text", "text": "Long shared instructions. ".repeat(60), "cache_control": {"type": "ephemeral"}}]);
    for i in 0..4 {
        let body = json!({"model": "anth/m", "max_tokens": 64, "system": system, "messages": msgs("same question")});
        let s = e.sample("anthropic cached", Api::Anthropic, body).await;
        let metered = s.event["cost_usd"].as_f64().unwrap();
        let bill = s.provider_cost();
        assert!((metered - bill).abs() / bill <= 0.01, "request {i}: metered {metered} vs provider {bill}");
    }
}

/// KNOWN GAP: a streaming client that sets `stream_options.include_usage = false` turns usage off
/// upstream too (the gateway only adds `include_usage` when the client did not set it), so the
/// provider bills the request but the usage event records 0 tokens. The quota settlement falls
/// back to an estimate (prompt estimate + streamed bytes / 4), the usage event does not. Fix:
/// always request usage upstream and drop the usage-only chunk for clients that opted out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "known gap: streams with include_usage=false are metered as 0 tokens (bench/RESULTS.md)"]
async fn stream_without_client_usage_is_still_metered() {
    let e = setup().await;
    let body = json!({"model": "oa/m", "stream": true, "stream_options": {"include_usage": false}, "messages": msgs("count me")});
    let s = e.sample("opt-out stream", Api::OpenAi, body).await;
    assert_eq!(s.bills.len(), 1);
    assert_eq!(s.metered("prompt_tokens"), s.billed_prompt(), "prompt tokens of an opt-out stream");
    assert_eq!(s.metered("completion_tokens"), s.billed_completion(), "completion tokens of an opt-out stream");
}
