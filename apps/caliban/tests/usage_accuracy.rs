//! Usage accuracy: the gateway's metered usage (the JSONL usage WAL) against the "provider bill"
//! (the usage the mock upstream reported for every request it served), request by request,
//! across both dialects, streams, translation in both directions, native Anthropic passthrough
//! with prompt caching, provider-side prefix caching, exact-cache hits, fallbacks and PII.
//!
//! P0 exit criterion: "Usage matches provider bills within 1%". Token counts must match exactly
//! (no estimation is involved when the upstream reports usage, also for streams whose client did
//! not ask for usage). Cost must equal the provider's bill with prompt-cache pricing: the test
//! catalogue carries the cache prices the mock "provider" charges (Anthropic reads 0.1x, 5-minute
//! writes 1.25x, 1-hour writes 2x the input price; OpenAI-compatible cached input 0.5x).
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

/// Prompt-cache price multipliers of the mock providers (of the input price).
const ANTHROPIC_READ: f64 = 0.1;
const ANTHROPIC_WRITE_5M: f64 = 1.25;
const ANTHROPIC_WRITE_1H: f64 = 2.0;
const OPENAI_CACHED: f64 = 0.5;

fn price(model: &str) -> (f64, f64) {
    PRICES.iter().find(|p| p.0 == model).map(|p| (p.1, p.2)).expect("priced model")
}

fn config(base: &str, hash: &str) -> String {
    let models: String = [("oa/m", "oa", "mock-oa"), ("anth/m", "anth", "claude-mock"), ("oa/fail", "oa", "mock-fail-500")]
        .iter()
        .map(|(id, p, up)| {
            let (i, o) = price(id);
            // The catalogue's cache prices are the providers' (see the constants above).
            let cache = if *p == "anth" {
                format!("price_cache_read_per_mtok = {}\nprice_cache_write_per_mtok = {}\nprice_cache_write_1h_per_mtok = {}\n", i * ANTHROPIC_READ, i * ANTHROPIC_WRITE_5M, i * ANTHROPIC_WRITE_1H)
            } else {
                format!("price_cache_read_per_mtok = {}\n", i * OPENAI_CACHED)
            };
            format!("[[models]]\nid = \"{id}\"\nprovider = \"{p}\"\nupstream_model = \"{up}\"\ntrust_tier = \"t2_contracted\"\nprice_in_per_mtok = {i}\nprice_out_per_mtok = {o}\n{cache}\n")
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
    setup_with(MockConfig { chunk_chars: 3, ..Default::default() }).await
}

async fn setup_with(mock_cfg: MockConfig) -> Env {
    let mock = Mock::start("127.0.0.1:0", mock_cfg).await.unwrap();
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
    fn billed_writes(&self) -> u64 {
        self.bills.iter().map(|b| b.cache_creation_tokens).sum()
    }
    fn billed_writes_1h(&self) -> u64 {
        self.bills.iter().map(|b| b.cache_creation_1h_tokens).sum()
    }
    fn metered(&self, k: &str) -> u64 {
        self.event[k].as_u64().unwrap_or(0)
    }
    /// What the gateway metered before the metering fixes (the "before" column of the report):
    /// every billed token at the list price (no cache pricing), and 0 for streams whose client
    /// set `include_usage: false`.
    fn before_cost(&self) -> f64 {
        if self.bills.is_empty() || self.label.contains("include_usage: false") {
            return 0.0;
        }
        let (i, o) = price(self.event["model"].as_str().unwrap());
        (self.billed_prompt() as f64 * i + self.billed_completion() as f64 * o) / 1e6
    }
    /// What the provider charges, with its prompt-cache pricing: Anthropic cache reads at 0.1x,
    /// 5-minute writes at 1.25x and 1-hour writes at 2x the input price; OpenAI cached input at
    /// 0.5x. The usage event's `cost_usd` must equal this.
    fn provider_cost(&self) -> f64 {
        let (i, o) = price(self.event["model"].as_str().unwrap());
        self.bills
            .iter()
            .map(|b| {
                let input = if b.anthropic {
                    let w5 = b.cache_creation_tokens - b.cache_creation_1h_tokens;
                    b.input_tokens as f64 * i
                        + b.cache_read_tokens as f64 * ANTHROPIC_READ * i
                        + w5 as f64 * ANTHROPIC_WRITE_5M * i
                        + b.cache_creation_1h_tokens as f64 * ANTHROPIC_WRITE_1H * i
                } else {
                    (b.input_tokens - b.cache_read_tokens) as f64 * i + b.cache_read_tokens as f64 * OPENAI_CACHED * i
                };
                (input + b.output_tokens as f64 * o) / 1e6
            })
            .sum()
    }
    fn metered_cost(&self) -> f64 {
        self.event["cost_usd"].as_f64().unwrap_or(0.0)
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
        out.push(
            e.sample(
                "OpenAI client, OpenAI-compatible upstream, stream, include_usage: false",
                Api::OpenAi,
                json!({"model": "oa/m", "stream": true, "stream_options": {"include_usage": false}, "messages": msgs(&format!("{tag} opt-out"))}),
            )
            .await,
        );
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
    // The same with the 1-hour TTL (written at 2x, read at 0.1x).
    let system_1h = json!([{"type": "text", "text": "You are the treasury assistant. ".repeat(40), "cache_control": {"type": "ephemeral", "ttl": "1h"}}]);
    for stream in [false, true] {
        let body = json!({"model": "anth/m", "max_tokens": 128, "stream": stream, "system": system_1h, "messages": msgs(&format!("Which invoices are overdue? stream={stream}"))});
        out.push(e.sample("Anthropic native with cache_control, 1-hour TTL (write, then read)", Api::Anthropic, body.clone()).await);
        out.push(e.sample("Anthropic native with cache_control, 1-hour TTL (write, then read)", Api::Anthropic, body).await);
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
        bw: u64,
        mw: u64,
        cost_list: f64,
        cost_metered: f64,
        cost_provider: f64,
        hits: usize,
    }
    impl Agg {
        fn add(&mut self, a: &Agg) {
            self.n += a.n;
            self.bp += a.bp;
            self.mp += a.mp;
            self.bc += a.bc;
            self.mc += a.mc;
            self.bk += a.bk;
            self.mk += a.mk;
            self.bw += a.bw;
            self.mw += a.mw;
            self.cost_list += a.cost_list;
            self.cost_metered += a.cost_metered;
            self.cost_provider += a.cost_provider;
            self.hits += a.hits;
        }
        fn pct(x: f64, base: f64) -> f64 {
            if base > 0.0 { (x - base) / base * 100.0 } else { 0.0 }
        }
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
        a.bw += s.billed_writes();
        a.mw += s.metered("cache_write_tokens");
        a.cost_list += s.before_cost();
        a.cost_metered += s.metered_cost();
        a.cost_provider += s.provider_cost();
        a.hits += usize::from(s.event["cache"] == "hit");
    }
    let mut o = String::new();
    let _ = writeln!(
        o,
        "| Path | Requests | Prompt (billed / metered) | Completion (billed / metered) | Cache reads (billed / metered) | Cache writes (billed / metered) | Provider bill | Metered before | Before vs bill | Metered now | Now vs bill |"
    );
    let _ = writeln!(o, "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    let mut total = Agg::default();
    let row = |o: &mut String, label: &str, a: &Agg| {
        let _ = writeln!(
            o,
            "| {label} | {}{} | {} / {} | {} / {} | {} / {} | {} / {} | {:.6} | {:.6} | {:+.1}% | {:.6} | {:+.2}% |",
            a.n,
            if a.hits > 0 { format!(" ({} cache hits)", a.hits) } else { String::new() },
            a.bp,
            a.mp,
            a.bc,
            a.mc,
            a.bk,
            a.mk,
            a.bw,
            a.mw,
            a.cost_provider,
            a.cost_list,
            Agg::pct(a.cost_list, a.cost_provider),
            a.cost_metered,
            Agg::pct(a.cost_metered, a.cost_provider),
        );
    };
    for l in order {
        row(&mut o, l, &by[l]);
        total.add(&by[l]);
    }
    row(&mut o, "**Total**", &total);
    o
}

fn assert_cost_matches(s: &Sample) {
    let (metered, bill) = (s.metered_cost(), s.provider_cost());
    assert!((metered - bill).abs() <= 1e-12 + bill * 1e-9, "{}: metered {metered} vs provider bill {bill}", s.label);
}

/// Every request: metered prompt, completion, cache-read and cache-write tokens equal the bill
/// exactly, the usage comes from the provider, and the metered cost equals the provider's bill
/// with its prompt-cache pricing. Cache hits are metered as zero tokens and zero cost (the
/// provider was not called). Fallbacks bill once.
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
        assert_eq!(s.metered("cache_write_tokens"), s.billed_writes(), "{l}: cache-write tokens");
        assert_eq!(s.metered("cache_write_1h_tokens"), s.billed_writes_1h(), "{l}: 1-hour cache-write tokens");
        assert_eq!(s.event["usage_source"], "provider", "{l}: usage from the provider, not estimated");
        assert!(s.event["cost_usd"].is_number(), "{l}: priced model has a cost");
        assert_cost_matches(s);
    }
    let (metered, bill): (f64, f64) = samples.iter().fold((0.0, 0.0), |(m, b), s| (m + s.metered_cost(), b + s.provider_cost()));
    assert!((metered - bill).abs() / bill < 0.01, "total: metered {metered} vs provider bill {bill}");
    // The workload must actually exercise the cache paths.
    assert!(samples.iter().any(|s| s.billed_cached() > 0 && !s.bills[0].anthropic), "OpenAI-side cached tokens exercised");
    assert!(samples.iter().any(|s| s.bills.first().is_some_and(|b| b.cache_creation_tokens > 0)), "Anthropic cache writes exercised");
    assert!(samples.iter().any(|s| s.bills.first().is_some_and(|b| b.cache_creation_1h_tokens > 0)), "Anthropic 1-hour cache writes exercised");
    assert!(samples.iter().any(|s| s.event["cache"] == "hit"), "gateway cache hits exercised");
}

/// Cost follows the provider's prompt-cache pricing (formerly a known gap: every prompt token was
/// priced at the input price, +104% on Anthropic cache reads and under on cache writes): a cache
/// write, then reads, for both TTLs and both transports, each within 1% of the bill (exact here).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cost_matches_provider_bill_with_prompt_caching() {
    let e = setup().await;
    for ttl in [None, Some("1h")] {
        let mut cc = json!({"type": "ephemeral"});
        if let Some(t) = ttl {
            cc["ttl"] = json!(t);
        }
        let system = json!([{"type": "text", "text": format!("Long shared instructions {ttl:?}. ").repeat(60), "cache_control": cc}]);
        for (i, stream) in [false, false, true, true].into_iter().enumerate() {
            let body = json!({"model": "anth/m", "max_tokens": 64, "stream": stream, "system": system, "messages": msgs("same question")});
            let s = e.sample("anthropic cached", Api::Anthropic, body).await;
            let b = s.bills[0];
            if i == 0 {
                assert!(b.cache_creation_tokens > 0 && (ttl.is_none() || b.cache_creation_1h_tokens == b.cache_creation_tokens), "{ttl:?}: first request writes");
            } else {
                assert!(b.cache_read_tokens > 0, "{ttl:?}: later requests read");
            }
            let (metered, bill) = (s.metered_cost(), s.provider_cost());
            assert!((metered - bill).abs() / bill <= 0.01, "{ttl:?} request {i}: metered {metered} vs provider {bill}");
            assert_cost_matches(&s);
        }
    }
}

/// Streams whose client did not ask for usage (`include_usage: false`, or no `stream_options`)
/// are metered from the provider's usage (formerly a known gap: 0 tokens), and the client still
/// gets no usage chunk.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stream_without_client_usage_is_still_metered() {
    let e = setup().await;
    for (i, extra) in [json!({"stream_options": {"include_usage": false}}), json!({})].into_iter().enumerate() {
        let mut body = json!({"model": "oa/m", "stream": true, "messages": msgs(&format!("count me {i}"))});
        body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        let wal_before = e.gw.wal_events().len();
        let r = e.gw.chat(&e.key, &body).await;
        assert!(r.status.is_success());
        assert!(!r.text.contains("\"usage\""), "case {i}: the client did not ask for usage: {}", r.text);
        assert!(r.text.trim_end().ends_with("data: [DONE]"));
        let mut events = Vec::new();
        for _ in 0..200 {
            events = e.gw.wal_events();
            if events.len() > wal_before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let ev = events.last().unwrap();
        let bill = e.mock.log().last().unwrap().bill.unwrap();
        assert_eq!(ev["prompt_tokens"], bill.total_prompt_tokens(), "case {i}: prompt tokens of an opt-out stream");
        assert_eq!(ev["completion_tokens"], bill.output_tokens, "case {i}: completion tokens of an opt-out stream");
        assert_eq!(ev["usage_source"], "provider");
    }
}

/// A client that disconnects mid-stream is metered from an estimate (`usage_source:
/// "estimated"`): the prompt estimate plus the output streamed so far. The provider bills the
/// whole generation it produced (the mock finishes its response), so the estimate is a floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_disconnect_is_metered_as_an_estimate() {
    let e = setup_with(MockConfig { chunk_chars: 2, chunk_delay: Duration::from_millis(5), ..Default::default() }).await;
    let text = "Write a long answer about the quarterly close, the accruals, the reconciliations and the audit. ".repeat(3);
    let body = json!({"model": "oa/m", "stream": true, "messages": msgs(&text)});
    let wal_before = e.gw.wal_events().len();
    let mut resp = caliban_bench::harness::client()
        .post(format!("{}/v1/chat/completions", e.gw.dp))
        .bearer_auth(&e.key)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let first = resp.chunk().await.unwrap().expect("a first chunk");
    assert!(!first.is_empty());
    drop(resp);
    let mut events = Vec::new();
    for _ in 0..300 {
        events = e.gw.wal_events();
        if events.len() > wal_before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let ev = events.last().expect("a usage event for the disconnected stream");
    assert_eq!(ev["usage_source"], "estimated");
    let bill = e.mock.log().last().unwrap().bill.unwrap();
    let (prompt, completion) = (ev["prompt_tokens"].as_u64().unwrap(), ev["completion_tokens"].as_u64().unwrap());
    assert!(prompt > 0, "prompt estimate, not 0");
    assert!(completion > 0 && completion < bill.output_tokens, "estimated output {completion} is below the {} billed", bill.output_tokens);
    println!("disconnect: billed {} + {}, metered (estimated) {prompt} + {completion}", bill.total_prompt_tokens(), bill.output_tokens);
}
