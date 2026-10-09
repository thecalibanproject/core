//! Gateway overhead benchmark.
//!
//! Starts the mock upstream (its own process) and one or more real `caliban standalone`
//! processes in front of it, then, per scenario and concurrency level, measures latency
//! **direct to the mock** and **through the gateway** with the same closed-loop load generator.
//! Overhead at quantile q is `Q_gateway(q) - Q_direct(q)`. Runs are interleaved (direct, gateway,
//! direct, gateway, …) after a warm-up of both, so drift affects both sides alike.
//!
//! `scripts/bench.sh` builds the binaries and calls this; see `bench/RESULTS.md`.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use caliban_bench::harness::{Caliban, Launch, client, free_port, new_key};
use caliban_bench::load::{self, Stats, Target, ms};
use clap::Parser;
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

#[derive(Parser)]
#[command(about = "Caliban gateway overhead benchmark")]
struct Args {
    /// Release `caliban` binary (default features: regex PII tier).
    #[arg(long)]
    caliban: PathBuf,
    /// `caliban` built with `--features ner`; used with CALIBAN_PII_NER_DIR for the NER rows.
    #[arg(long)]
    caliban_ner: Option<PathBuf>,
    /// `mock-upstream` binary (default: next to this binary).
    #[arg(long)]
    mock: Option<PathBuf>,
    /// Concurrency levels.
    #[arg(long, value_delimiter = ',', default_value = "1,16,64")]
    concurrency: Vec<usize>,
    /// Measured requests per (scenario, concurrency, side).
    #[arg(long, default_value_t = 4000)]
    requests: usize,
    /// Warm-up requests per (scenario, concurrency, side).
    #[arg(long, default_value_t = 400)]
    warmup: usize,
    /// Interleaved rounds the measured requests are split into.
    #[arg(long, default_value_t = 2)]
    rounds: usize,
    /// Fixed mock latency (ms). 0 makes the overhead the whole difference.
    #[arg(long, default_value_t = 0.0)]
    mock_latency_ms: f64,
    /// Delay between chunks for the `paced` stream scenarios (a second mock), in ms. Real
    /// models emit tokens tens of milliseconds apart; with 0 delay every frame of a stream
    /// arrives in one read, which is the worst case for per-frame work.
    #[arg(long, default_value_t = 1.0)]
    paced_chunk_delay_ms: f64,
    /// Measured requests per side for the paced scenarios (each stream takes ~70 ms).
    #[arg(long, default_value_t = 600)]
    paced_requests: usize,
    /// Only run scenarios whose name contains one of these (comma-separated).
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    /// Markdown report path.
    #[arg(long, default_value = "bench/results/overhead.md")]
    out: PathBuf,
    /// Raw numbers (JSON).
    #[arg(long)]
    json: Option<PathBuf>,
    /// Free text for the report header (hardware, commit, …), one item per flag.
    #[arg(long)]
    note: Vec<String>,
}

const PROMPT: &str = "Please draft a short follow-up note to our customer about the renewal. Their contact is \
jane.doe@acme.com and the card on file is 4111 1111 1111 1111. Keep it friendly and under one hundred words, \
and mention that the invoice is attached.";

const UPSTREAM_KEY: &str = "sk-bench-upstream-0000";

/// Which gateway process a scenario runs against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Profile {
    /// Default build, usage WAL off.
    Default,
    /// Default build with `CALIBAN_USAGE_WAL` on.
    Wal,
    /// `ner` build with CALIBAN_PII_NER_DIR.
    Ner,
}

struct Scenario {
    name: &'static str,
    what: &'static str,
    profile: Profile,
    stream: bool,
    /// Gateway: (path, tenant key index, body).
    gw_path: &'static str,
    pii_tenant: bool,
    anthropic_client: bool,
    gw_body: Value,
    direct_path: &'static str,
    direct_body: Value,
    /// Seed the exact cache before measuring and expect hits.
    cache_hit: bool,
    /// Use the paced mock (delay between stream chunks).
    paced: bool,
    /// Keep 16 NER requests in flight on the same gateway while measuring.
    ner_background: bool,
}

fn messages() -> Value {
    json!([{"role": "user", "content": PROMPT}])
}

fn scenarios() -> Vec<Scenario> {
    let openai = |model: &str, stream: bool, temp0: bool| {
        let mut b = json!({"model": model, "messages": messages()});
        if stream {
            b["stream"] = json!(true);
        }
        if temp0 {
            b["temperature"] = json!(0);
        }
        b
    };
    let direct_openai = |stream: bool, temp0: bool| {
        let mut b = openai("mock-ext", stream, temp0);
        if stream {
            // What the gateway adds upstream, so both sides get identical streams.
            b["stream_options"] = json!({"include_usage": true});
        }
        b
    };
    let s = |name, what, profile, stream, pii_tenant| Scenario {
        name,
        what,
        profile,
        stream,
        gw_path: "/v1/chat/completions",
        pii_tenant,
        anthropic_client: false,
        gw_body: openai("ext/mock", stream, false),
        direct_path: "/v1/chat/completions",
        direct_body: direct_openai(stream, false),
        cache_hit: false,
        paced: false,
        ner_background: false,
    };
    let paced = |name, what, pii_tenant| Scenario {
        paced: true,
        gw_body: openai("ext/paced", true, false),
        direct_body: {
            let mut b = direct_openai(true, false);
            b["model"] = json!("mock-paced");
            b
        },
        ..s(name, what, Profile::Default, true, pii_tenant)
    };
    vec![
        s(
            "chat",
            "OpenAI chat, non-streaming, PII off",
            Profile::Default,
            false,
            false,
        ),
        s(
            "chat+pii",
            "OpenAI chat, non-streaming, PII reversible (regex tier), 2 entities",
            Profile::Default,
            false,
            true,
        ),
        s(
            "stream",
            "OpenAI chat, streaming, PII off",
            Profile::Default,
            true,
            false,
        ),
        s(
            "stream+pii",
            "OpenAI chat, streaming, PII reversible (regex tier), 2 entities, streaming rehydration",
            Profile::Default,
            true,
            true,
        ),
        Scenario {
            name: "cache-hit",
            what: "OpenAI chat, non-streaming, temperature 0, exact-cache hit (no upstream call)",
            cache_hit: true,
            gw_body: openai("ext/mock", false, true),
            direct_body: direct_openai(false, true),
            ..s("", "", Profile::Default, false, false)
        },
        Scenario {
            name: "anthropic-native",
            what: "Anthropic Messages client to Anthropic provider (native passthrough), non-streaming, PII off",
            gw_path: "/v1/messages",
            anthropic_client: true,
            gw_body: json!({"model": "anthropic/mock", "max_tokens": 256, "messages": messages()}),
            direct_path: "/v1/messages",
            direct_body: json!({"model": "claude-mock", "max_tokens": 256, "messages": messages()}),
            ..s("", "", Profile::Default, false, false)
        },
        paced(
            "stream-paced",
            "OpenAI chat, streaming with a delay between upstream chunks (see the paced chunk delay), PII off",
            false,
        ),
        paced(
            "stream-paced+pii",
            "As `stream-paced`, PII reversible (regex tier), streaming rehydration",
            true,
        ),
        s(
            "chat+wal",
            "OpenAI chat, non-streaming, PII off, usage JSONL WAL on",
            Profile::Wal,
            false,
            false,
        ),
        s(
            "chat+pii+ner",
            "OpenAI chat, non-streaming, PII reversible with the L1 NER model",
            Profile::Ner,
            false,
            true,
        ),
        s(
            "stream+pii+ner",
            "OpenAI chat, streaming, PII reversible with the L1 NER model",
            Profile::Ner,
            true,
            true,
        ),
        Scenario {
            ner_background: true,
            ..s(
                "chat-during-ner",
                "OpenAI chat, non-streaming, PII off, on the NER gateway while 16 NER requests from another tenant are in flight (collateral impact)",
                Profile::Ner,
                false,
                false,
            )
        },
    ]
}

fn config(base_url: &str, paced_url: &str, plain_hash: &str, pii_hash: &str) -> String {
    let providers = format!(
        r#"
  [[tenants.providers]]
  id = "mockext"
  kind = "openai_compatible"
  base_url = "{base_url}"
  trust_tier = "t2_contracted"
  api_key = {{ env = "BENCH_UPSTREAM_KEY" }}
  [[tenants.providers]]
  id = "mockpaced"
  kind = "openai_compatible"
  base_url = "{paced_url}"
  trust_tier = "t2_contracted"
  api_key = {{ env = "BENCH_UPSTREAM_KEY" }}
  [[tenants.providers]]
  id = "anthmock"
  kind = "anthropic"
  base_url = "{base_url}"
  trust_tier = "t2_contracted"
  api_key = {{ env = "BENCH_UPSTREAM_KEY" }}
  [[tenants.routes]]
  intent = "default"
  models = ["ext/mock"]
"#
    );
    format!(
        r#"
[cache]
exact_enabled = true

[[models]]
id = "ext/mock"
provider = "mockext"
upstream_model = "mock-ext"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0

[[models]]
id = "ext/paced"
provider = "mockpaced"
upstream_model = "mock-paced"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0

[[models]]
id = "anthropic/mock"
provider = "anthmock"
upstream_model = "claude-mock"
trust_tier = "t2_contracted"
price_in_per_mtok = 3.0
price_out_per_mtok = 15.0

[[tenants]]
id = "bench-plain"
name = "Bench plain"
pii_mode = "off"
api_key_hashes = ["{plain_hash}"]
{providers}
[[tenants]]
id = "bench-pii"
name = "Bench PII"
pii_mode = "reversible"
api_key_hashes = ["{pii_hash}"]
{providers}
"#
    )
}

struct MockProc(Child);

impl Drop for MockProc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn start_mock(
    bin: &PathBuf,
    latency_ms: f64,
    chunk_delay_ms: f64,
) -> Result<(MockProc, String)> {
    let port = free_port();
    let child = Command::new(bin)
        .args([
            "--addr",
            &format!("127.0.0.1:{port}"),
            "--latency-ms",
            &latency_ms.to_string(),
            "--chunk-delay-ms",
            &chunk_delay_ms.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {}", bin.display()))?;
    let proc = MockProc(child);
    let base = format!("http://127.0.0.1:{port}");
    let http = client();
    for _ in 0..200 {
        if http.get(format!("{base}/healthz")).send().await.is_ok() {
            return Ok((proc, base));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    bail!("mock upstream did not start")
}

struct Row {
    scenario: &'static str,
    concurrency: usize,
    direct: Stats,
    gateway: Stats,
}

const QS: [(f64, &str); 4] = [(0.5, "p50"), (0.9, "p90"), (0.99, "p99"), (1.0, "max")];

fn fmt_ms(v: f64) -> String {
    if v.is_nan() {
        "n/a".into()
    } else {
        format!("{v:.3}")
    }
}

fn overhead(g: &hdrhistogram::Histogram<u64>, d: &hdrhistogram::Histogram<u64>, q: f64) -> f64 {
    ms(g, q) - ms(d, q)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mock_bin = match &args.mock {
        Some(p) => p.clone(),
        None => std::env::current_exe()?.with_file_name("mock-upstream"),
    };
    let ner_dir = std::env::var("CALIBAN_PII_NER_DIR")
        .ok()
        .filter(|d| !d.trim().is_empty());
    let (mock, mock_base) = start_mock(&mock_bin, args.mock_latency_ms, 0.0).await?;
    let (paced_mock, paced_base) =
        start_mock(&mock_bin, args.mock_latency_ms, args.paced_chunk_delay_ms).await?;
    let base_url = format!("{mock_base}/v1");
    let (plain_key, plain_hash) = new_key("benchplain");
    let (pii_key, pii_hash) = new_key("benchpii");
    let cfg = config(
        &base_url,
        &format!("{paced_base}/v1"),
        &plain_hash,
        &pii_hash,
    );
    let env = vec![("BENCH_UPSTREAM_KEY".to_owned(), UPSTREAM_KEY.to_owned())];

    let wanted =
        |name: &str| args.only.is_empty() || args.only.iter().any(|o| name.contains(o.as_str()));
    let all = scenarios();
    let needs = |p: Profile| all.iter().any(|s| s.profile == p && wanted(s.name));

    let mut skipped: Vec<String> = Vec::new();
    let default_gw = Caliban::start(
        &args.caliban,
        &Launch {
            config: cfg.clone(),
            env: env.clone(),
            ..Default::default()
        },
    )
    .await?;
    let wal_gw = if needs(Profile::Wal) {
        Some(
            Caliban::start(
                &args.caliban,
                &Launch {
                    config: cfg.clone(),
                    env: env.clone(),
                    usage_wal: true,
                    ..Default::default()
                },
            )
            .await?,
        )
    } else {
        None
    };
    let ner_gw = match (&args.caliban_ner, &ner_dir) {
        _ if !needs(Profile::Ner) => None,
        (Some(bin), Some(dir)) => {
            let mut e = env.clone();
            e.push(("CALIBAN_PII_NER_DIR".into(), dir.clone()));
            let launch = Launch {
                config: cfg.clone(),
                env: e,
                startup_timeout: Some(Duration::from_secs(180)),
                ..Default::default()
            };
            match Caliban::start(bin, &launch).await {
                Ok(c) => Some(c),
                Err(e) => {
                    skipped.push(format!(
                        "NER rows: the `ner` build did not start: {}",
                        e.to_string().lines().next().unwrap_or_default()
                    ));
                    None
                }
            }
        }
        (None, _) => {
            skipped.push("NER rows: no `ner` build (`cargo build --release -p caliban --features ner` failed or was not requested)".into());
            None
        }
        (_, None) => {
            skipped.push("NER rows: CALIBAN_PII_NER_DIR is not set".into());
            None
        }
    };

    let http = client();
    let mut rows: Vec<Row> = Vec::new();
    let mut checks: Vec<String> = Vec::new();
    for sc in all.iter().filter(|s| wanted(s.name)) {
        let gw = match sc.profile {
            Profile::Default => &default_gw,
            Profile::Wal => match &wal_gw {
                Some(g) => g,
                None => continue,
            },
            Profile::Ner => match &ner_gw {
                Some(g) => g,
                None => continue,
            },
        };
        let key = if sc.pii_tenant { &pii_key } else { &plain_key };
        let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
        if sc.anthropic_client {
            headers.push(("x-api-key".into(), key.clone()));
            headers.push(("anthropic-version".into(), "2023-06-01".into()));
        } else {
            headers.push(("authorization".into(), format!("Bearer {key}")));
        }
        let expect = sc.stream.then(|| "[DONE]".to_owned());
        let gw_t = Target {
            url: format!("{}{}", gw.dp, sc.gw_path),
            headers,
            body: Bytes::from(sc.gw_body.to_string()),
            stream: sc.stream,
            expect: expect.clone(),
        };
        let mut dh = vec![("content-type".to_owned(), "application/json".to_owned())];
        if sc.anthropic_client {
            dh.push(("x-api-key".into(), UPSTREAM_KEY.into()));
        } else {
            dh.push(("authorization".into(), format!("Bearer {UPSTREAM_KEY}")));
        }
        let direct_base = if sc.paced { &paced_base } else { &mock_base };
        let direct_t = Target {
            url: format!("{direct_base}{}", sc.direct_path),
            headers: dh,
            body: Bytes::from(sc.direct_body.to_string()),
            stream: sc.stream,
            expect,
        };

        // Pre-flight: the gateway handles the scenario the way it claims to.
        let pre = gw
            .dp_post(
                sc.gw_path,
                &gw_t
                    .headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.clone()))
                    .collect::<Vec<_>>(),
                &sc.gw_body,
            )
            .await;
        if !pre.status.is_success() {
            bail!(
                "{}: pre-flight failed: {} {}",
                sc.name,
                pre.status,
                pre.text
            );
        }
        let text = if sc.stream {
            pre.stream_text()
        } else {
            pre.content()
        };
        let rehydrated = text.contains("jane.doe@acme.com") && text.contains("4111 1111 1111 1111");
        let pii = pre.header("x-caliban-pii-entities").unwrap_or_default();
        let mut cache = pre.header("x-caliban-cache").unwrap_or_default();
        if sc.cache_hit {
            let again = gw
                .dp_post(
                    sc.gw_path,
                    &gw_t
                        .headers
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.clone()))
                        .collect::<Vec<_>>(),
                    &sc.gw_body,
                )
                .await;
            cache = again.header("x-caliban-cache").unwrap_or_default();
            if cache != "hit" {
                bail!("{}: expected a cache hit, got {cache:?}", sc.name);
            }
        }
        if sc.pii_tenant && (pii.parse::<u32>().unwrap_or(0) < 2 || !rehydrated) {
            bail!(
                "{}: expected >= 2 PII entities and a rehydrated reply, got {pii} entities: {text}",
                sc.name
            );
        }
        checks.push(format!("`{}`: status {}, x-caliban-cache `{cache}`, x-caliban-pii-entities `{pii}`, reply rehydrated: {rehydrated}", sc.name, pre.status.as_u16()));

        // Background NER load from the PII tenant, for `chat-during-ner`.
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let background = sc.ner_background.then(|| {
            let t = Target {
                url: format!("{}/v1/chat/completions", gw.dp),
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    ("authorization".into(), format!("Bearer {pii_key}")),
                ],
                body: Bytes::from(json!({"model": "ext/mock", "messages": messages()}).to_string()),
                stream: false,
                expect: None,
            };
            let (http, stop) = (http.clone(), std::sync::Arc::clone(&stop));
            tokio::spawn(async move {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    load::run(&http, &t, 16, 64).await;
                }
            })
        });
        if background.is_some() {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        for &c in &args.concurrency {
            eprintln!("{} @ c={c}", sc.name);
            let (requests, warmup) = if sc.paced {
                (args.paced_requests, (args.warmup / 10).max(c))
            } else {
                (args.requests, args.warmup)
            };
            load::run(&http, &direct_t, c, warmup).await;
            load::run(&http, &gw_t, c, warmup).await;
            let (mut d, mut g) = (Stats::empty(), Stats::empty());
            let per = (requests / args.rounds.max(1)).max(1);
            for _ in 0..args.rounds.max(1) {
                d.merge(&load::run(&http, &direct_t, c, per).await);
                g.merge(&load::run(&http, &gw_t, c, per).await);
            }
            eprintln!(
                "  direct p50 {:.3} ms, gateway p50 {:.3} ms, overhead p50 {:.3} ms (errors {}/{})",
                ms(&d.total, 0.5),
                ms(&g.total, 0.5),
                overhead(&g.total, &d.total, 0.5),
                d.errors,
                g.errors
            );
            rows.push(Row {
                scenario: sc.name,
                concurrency: c,
                direct: d,
                gateway: g,
            });
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(b) = background {
            let _ = b.await;
        }
    }
    drop(mock);
    drop(paced_mock);

    let report = render(&args, &all, &rows, &checks, &skipped, ner_dir.as_deref());
    if let Some(dir) = args.out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&args.out, &report)?;
    eprintln!("wrote {}", args.out.display());
    if let Some(j) = &args.json {
        std::fs::write(j, serde_json::to_string_pretty(&raw(&rows))?)?;
    }
    Ok(())
}

fn raw(rows: &[Row]) -> Value {
    let q = |h: &hdrhistogram::Histogram<u64>| json!({"p50": ms(h, 0.5), "p90": ms(h, 0.9), "p99": ms(h, 0.99), "max": ms(h, 1.0), "n": h.len()});
    Value::Array(
        rows.iter()
            .map(|r| {
                json!({
                    "scenario": r.scenario, "concurrency": r.concurrency,
                    "direct": {"total": q(&r.direct.total), "ttfb": q(&r.direct.ttfb), "errors": r.direct.errors, "rps": r.direct.throughput()},
                    "gateway": {"total": q(&r.gateway.total), "ttfb": q(&r.gateway.ttfb), "errors": r.gateway.errors, "rps": r.gateway.throughput()},
                })
            })
            .collect(),
    )
}

fn render(
    args: &Args,
    all: &[Scenario],
    rows: &[Row],
    checks: &[String],
    skipped: &[String],
    ner_dir: Option<&str>,
) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "# Gateway overhead\n");
    for n in &args.note {
        let _ = writeln!(o, "- {n}");
    }
    let _ = writeln!(
        o,
        "- Requests per side per row: {} measured ({} for paced streams) in {} interleaved rounds, after {} warm-up; mock latency {} ms; paced chunk delay {} ms.",
        args.requests,
        args.paced_requests,
        args.rounds,
        args.warmup,
        args.mock_latency_ms,
        args.paced_chunk_delay_ms
    );
    let _ = writeln!(
        o,
        "- Overhead at quantile q = gateway latency at q minus direct latency at q, in milliseconds."
    );
    if let Some(d) = ner_dir {
        let _ = writeln!(o, "- NER artifact: `{d}`");
    }
    let _ = writeln!(o);

    // Summary. The P0 budget covers the gateway itself: NER rows (model inference, which the
    // budget excludes) are reported separately, and paced streams count by TTFB only (their total
    // is dominated by the timer jitter of ~60 sleeps on both sides).
    let mut worst = (f64::MIN, "", 0usize);
    let mut worst99 = (f64::MIN, "", 0usize);
    for r in rows.iter().filter(|r| !r.scenario.contains("ner")) {
        let paced = r.scenario.contains("paced");
        for (h_g, h_d) in [
            (&r.gateway.total, &r.direct.total),
            (&r.gateway.ttfb, &r.direct.ttfb),
        ] {
            if h_g.is_empty() || (paced && std::ptr::eq(h_g, &r.gateway.total)) {
                continue;
            }
            let p50 = overhead(h_g, h_d, 0.5);
            let p99 = overhead(h_g, h_d, 0.99);
            if p50 > worst.0 {
                worst = (p50, r.scenario, r.concurrency);
            }
            if p99 > worst99.0 {
                worst99 = (p99, r.scenario, r.concurrency);
            }
        }
    }
    let _ = writeln!(o, "## Summary\n");
    let _ = writeln!(
        o,
        "Gateway rows (NER rows and paced-stream totals excluded; see the comment in `render`):\n"
    );
    if worst.1.is_empty() {
        let _ = writeln!(o, "- No gateway rows in this run.\n");
    } else {
        let _ = writeln!(
            o,
            "- Worst p50 overhead: **{:.3} ms** (`{}`, concurrency {}). P0 target: under 3 ms. {}",
            worst.0,
            worst.1,
            worst.2,
            if worst.0 < 3.0 {
                "**Pass.**"
            } else {
                "**Fail.**"
            }
        );
        let _ = writeln!(
            o,
            "- Worst p99 overhead: **{:.3} ms** (`{}`, concurrency {}). Design budget (architecture section 4): under 10 ms.\n",
            worst99.0, worst99.1, worst99.2
        );
    }
    let ner: Vec<&Row> = rows.iter().filter(|r| r.scenario.contains("ner")).collect();
    if !ner.is_empty() {
        let _ = writeln!(
            o,
            "NER tier (L1 model inference; outside the 3 ms budget, design target 5 to 30 ms per 1k tokens):\n"
        );
        for r in ner {
            let _ = writeln!(
                o,
                "- `{}` at concurrency {}: p50 overhead {:.3} ms, p99 {:.3} ms, {:.0} req/s",
                r.scenario,
                r.concurrency,
                overhead(&r.gateway.total, &r.direct.total, 0.5),
                overhead(&r.gateway.total, &r.direct.total, 0.99),
                r.gateway.throughput()
            );
        }
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "## Scenarios\n");
    for s in all {
        let status = if rows.iter().any(|r| r.scenario == s.name) {
            ""
        } else {
            " (not run)"
        };
        let _ = writeln!(o, "- `{}`: {}{status}", s.name, s.what);
    }
    let _ = writeln!(o);
    if !skipped.is_empty() {
        let _ = writeln!(o, "Skipped:\n");
        for s in skipped {
            let _ = writeln!(o, "- {s}");
        }
        let _ = writeln!(o);
    }
    let _ = writeln!(
        o,
        "Pre-flight checks (one request each, before measuring):\n"
    );
    for c in checks {
        let _ = writeln!(o, "- {c}");
    }
    let _ = writeln!(o);

    let table = |o: &mut String, title: &str, ttfb: bool| {
        let _ = writeln!(o, "## {title}\n");
        let _ = writeln!(
            o,
            "| Scenario | Conc. | Direct p50 | Gateway p50 | Overhead p50 | Overhead p90 | Overhead p99 | Overhead max | Gateway req/s | Errors |"
        );
        let _ = writeln!(o, "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
        for r in rows {
            let (g, d) = if ttfb {
                (&r.gateway.ttfb, &r.direct.ttfb)
            } else {
                (&r.gateway.total, &r.direct.total)
            };
            if g.is_empty() {
                continue;
            }
            let ov: Vec<String> = QS.iter().map(|(q, _)| fmt_ms(overhead(g, d, *q))).collect();
            let _ = writeln!(
                o,
                "| `{}` | {} | {} | {} | **{}** | {} | {} | {} | {:.0} | {} |",
                r.scenario,
                r.concurrency,
                fmt_ms(ms(d, 0.5)),
                fmt_ms(ms(g, 0.5)),
                ov[0],
                ov[1],
                ov[2],
                ov[3],
                r.gateway.throughput(),
                r.gateway.errors + r.direct.errors
            );
        }
        let _ = writeln!(o);
    };
    table(&mut o, "Total latency overhead (ms)", false);
    table(&mut o, "Streaming: time-to-first-byte overhead (ms)", true);

    let _ = writeln!(o, "## Absolute latencies (ms)\n");
    let _ = writeln!(
        o,
        "| Scenario | Conc. | Side | p50 | p90 | p99 | max | req/s |"
    );
    let _ = writeln!(o, "|---|---:|---|---:|---:|---:|---:|---:|");
    for r in rows {
        for (side, s) in [("direct", &r.direct), ("gateway", &r.gateway)] {
            let q: Vec<String> = QS.iter().map(|(q, _)| fmt_ms(ms(&s.total, *q))).collect();
            let _ = writeln!(
                o,
                "| `{}` | {} | {side} | {} | {} | {} | {} | {:.0} |",
                r.scenario,
                r.concurrency,
                q[0],
                q[1],
                q[2],
                q[3],
                s.throughput()
            );
        }
    }
    o
}
