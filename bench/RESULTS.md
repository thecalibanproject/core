# P0 measurement results

The P0 exit criteria (reference architecture, section 8) are: **under 3 ms p50 overhead**, **isolation audit passes**, **usage matches provider bills within 1%**. This file records the first full measurement and what it found. Regenerate the raw report with `scripts/bench.sh` (it writes `bench/results/REPORT.md`, which is not committed).

## Verdict

| Criterion | Result |
|---|---|
| Under 3 ms p50 overhead | **Pass** for every non-streaming path (chat, PII regex tier, cache hit, native Anthropic, usage WAL) at concurrency 1, 16 and 64: worst p50 0.75 ms. **Pass** for streams at concurrency 1 and 16 (worst p50 1.17 ms total, 0.49 ms TTFB) and for paced streams at every level (TTFB p50 at most 0.57 ms). **Fail** in the first run for unpaced streams at concurrency 64: p50 4.1 ms (PII off) and 5.4 ms (PII on) in the full run, 2.9 ms in the quietest A/B round. **Borderline** after the stream passthrough (`perf/ner-and-streams`): 3.16 ms (PII off) and 3.40 ms (PII on), medians of three A/B rounds on a machine at load average 6 to 12, against 3.46 and 4.70 ms for the build before it in the same rounds; best rounds 2.62 and 3.15 ms. Gateway CPU per stream is down 27% (PII off) and 25% (PII on). See [Streaming at concurrency 64](#streaming-at-concurrency-64). The NER tier (model inference) is outside the 3 ms budget and is reported separately. |
| Isolation audit passes | **Pass**: 9 of 9 properties, through the real binary. No cross-tenant leak found. One property (datasources) is only partly testable today because the data plane does not consume datasources yet. |
| Usage within 1% of provider bills | **Pass** after the metering fixes (`fix/metering`): tokens and cost equal the provider's bill on every path, prompt-cache pricing included (81 requests, +0.00%; before the fixes the same workload was metered +21.8% above the bill, and the first measurement +33.0%). Streams whose client sets `include_usage: false` are metered from the provider's usage (were 0 tokens); client disconnects are metered as flagged estimates (were 0). See [Usage accuracy](#usage-accuracy). |

## Run

- Hardware: Apple M5, 10 cores (4 performance, 6 efficiency), 16 GiB, macOS 26.5.1. rustc 1.96.0.
- Commit measured: `652fc17` on `feat/bench` (branch point `409a138`, plus the two stream fixes listed below).
- Date: 2026-10-09. Load average before the run: 5.96 (other agents were compiling on the same machine earlier; see caveats).
- Release build (`lto = "thin"`, `codegen-units = 1`); NER rows use a `--features ner` build with `nym-pii-multilingual-small-int8` 3.0.0 (`CALIBAN_PII_NER_DIR`), default `NerOptions` (1 session, up to 4 intra-op threads; the defaults are now 4 sessions of 1 thread on this machine, see the NER section).
- The before and after tables for `perf/ner-and-streams` were measured later the same day, with the same harness, against `fix/metering` as "before".

## Method

- **Mock upstream** (`bench/src/mock.rs`, binary `mock-upstream`): OpenAI Chat Completions and Anthropic Messages, JSON and SSE, fixed latency (0 ms here) and deterministic usage (a pure function of the request). It echoes the last user message, so PII tests see what the upstream received and what the client got back. It also emulates provider prompt caches (vLLM-style prefix cache keyed by `cache_salt` or credential; Anthropic cache keyed by `x-api-key` and `cache_control`), and `mock-fail-500` for fallbacks.
- **Gateway**: the real `caliban standalone` release binary, in-memory store, generated config (two tenants, PII off and PII reversible, BYOK providers pointing at the mock, exact cache on). Log level `warn`, OTel off.
- **Load generator** (`bench/src/load.rs`, binary `caliban-bench`): closed loop, N workers each sending back-to-back requests over keep-alive HTTP/1.1 (reqwest), HDR histograms with 3 significant digits. Total latency is send to last body byte; TTFB is send to the first body chunk.
- **Overhead** at quantile q is `gateway(q) - direct(q)`, where direct sends the same upstream body straight to the mock with the same client. Per row: 400 warm-up requests per side, then 4000 measured per side in two interleaved rounds (direct, gateway, direct, gateway). Paced streams: 600 per side.
- **Scenarios**: 62-event streams (4 characters per delta) for a 230-character prompt carrying an email and a card number. `stream-paced` puts 1 ms between upstream chunks (a real model emits tokens tens of milliseconds apart); its total latency is dominated by the timer jitter of 62 sleeps on both sides, so only its TTFB counts.

## Overhead

Milliseconds, from the full run (`scripts/bench.sh`).

| Scenario | Conc. | Direct p50 | Gateway p50 | Overhead p50 | p90 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| chat (PII off) | 1 | 0.030 | 0.070 | **0.040** | 0.046 | 0.060 | 0.166 |
| | 16 | 0.132 | 0.278 | **0.146** | 0.173 | 0.196 | 0.209 |
| | 64 | 0.453 | 0.969 | **0.516** | 0.677 | 0.789 | 4.760 |
| chat + PII (regex, reversible) | 1 | 0.030 | 0.095 | **0.065** | 0.069 | 0.080 | -0.425 |
| | 16 | 0.115 | 0.307 | **0.191** | 0.240 | 0.328 | 0.838 |
| | 64 | 0.389 | 1.138 | **0.749** | 1.063 | 1.501 | 8.008 |
| stream, total (PII off) | 1 | 0.109 | 0.475 | **0.367** | 0.569 | 0.744 | 2.360 |
| | 16 | 0.499 | 1.672 | **1.174** | 1.931 | 3.275 | 20.234 |
| | 64 | 2.041 | 6.173 | **4.132** | 7.750 | 14.066 | 19.218 |
| stream, TTFB (PII off) | 1 | 0.083 | 0.161 | **0.078** | 0.154 | 0.344 | 1.284 |
| | 16 | 0.362 | 0.854 | **0.491** | 0.820 | 0.637 | -0.098 |
| | 64 | 1.366 | 2.619 | **1.253** | 2.759 | 5.911 | 17.531 |
| stream + PII, total | 1 | 0.149 | 0.625 | **0.476** | 0.676 | 0.995 | 2.925 |
| | 16 | 0.471 | 1.599 | **1.129** | 2.247 | 6.974 | 32.856 |
| | 64 | 1.983 | 7.336 | **5.352** | 12.399 | 25.301 | 73.933 |
| stream + PII, TTFB | 1 | 0.112 | 0.237 | **0.124** | 0.214 | 0.653 | 1.404 |
| | 16 | 0.346 | 0.810 | **0.464** | 1.010 | 3.187 | 31.103 |
| | 64 | 1.180 | 2.466 | **1.286** | 3.678 | 9.390 | 63.537 |
| paced stream, TTFB (PII off) | 1 | 2.925 | 3.492 | **0.567** | 0.440 | -0.279 | -10.396 |
| | 16 | 2.531 | 2.652 | **0.121** | 0.475 | 1.300 | 153.561 |
| | 64 | 2.726 | 3.277 | **0.551** | 0.911 | 0.664 | 147.812 |
| paced stream + PII, TTFB | 1 | 2.873 | 3.326 | **0.453** | 0.639 | 0.961 | 11.063 |
| | 16 | 2.644 | 2.687 | **0.043** | -0.057 | -1.288 | -2.071 |
| | 64 | 2.701 | 2.996 | **0.295** | 2.750 | 1.688 | 146.260 |
| cache hit (no upstream call) | 1 | 0.036 | 0.041 | **0.005** | 0.016 | 0.044 | 0.119 |
| | 16 | 0.135 | 0.159 | **0.025** | 0.041 | 0.050 | 0.096 |
| | 64 | 0.442 | 0.549 | **0.108** | 0.194 | 0.626 | 1.592 |
| Anthropic native passthrough | 1 | 0.035 | 0.086 | **0.050** | 0.100 | 0.176 | -0.606 |
| | 16 | 0.140 | 0.364 | **0.224** | 0.346 | 0.561 | 0.678 |
| | 64 | 0.488 | 1.063 | **0.574** | 0.715 | 0.643 | 3.822 |
| chat, usage WAL on | 1 | 0.030 | 0.087 | **0.057** | 0.059 | 0.041 | -0.296 |
| | 16 | 0.105 | 0.338 | **0.233** | 0.323 | 0.489 | 1.406 |
| | 64 | 0.355 | 1.119 | **0.764** | 1.085 | 1.716 | 5.003 |

Reading the table:

- A difference of quantiles is not a quantile of differences, so tails can come out negative (a slow direct sample) and `max` is a single-sample comparison. p50 and p90 are the stable numbers.
- The cache-hit "overhead" is near zero because the mock answers in about 30 microseconds; against a real upstream a hit saves the whole model call. The gateway's own cache-hit path costs about 40 microseconds end to end at concurrency 1.
- The usage WAL costs about 15 microseconds per request at concurrency 1 and 0.25 ms at 64 (the JSONL sink opens, appends and closes the file for every event, inline before the response is returned). Fixed on `fix/metering` with a background writer; see [Usage WAL](#usage-wal).

### NER tier (L1 model; outside the 3 ms budget)

| Scenario | Conc. | Overhead p50 | p99 | Gateway req/s |
|---|---:|---:|---:|---:|
| chat + PII with NER | 1 | 8.7 | 12.3 | 111 |
| | 16 | 141.8 | 343.2 | 107 |
| | 64 | 567.3 | 1053.5 | 109 |
| stream + PII with NER, TTFB | 1 | 10.7 | 21.2 | 82 |
| | 16 | 132.4 | 242.6 | 90 |
| | 64 | 317.0 | 1244.5 | 79 |
| PII-off chat on the NER gateway while 16 NER requests are in flight | 1 | 0.19 | **139.7** | 314 |
| | 16 | 0.34 | 1.8 | 25752 |
| | 64 | 1.59 | 4.8 | 24807 |

At concurrency 1 the model costs 8.7 ms for a 230-character prompt, inside the design target (5 to 30 ms per 1k tokens). Throughput is capped at about 110 requests per second because inference is serialised (default: one session). Above that, latency is queueing. The last three rows show the collateral damage: NER inference runs synchronously on tokio worker threads, and requests waiting for the session block their worker on a `std::sync::Mutex`, so unrelated PII-off traffic on the same gateway sees a 140 ms p99 at concurrency 1. Suggested fixes, in order:

1. Run `PiiEngine::protect` on a dedicated blocking pool (`spawn_blocking`, or a bounded rayon pool with a queue limit and a 429 or 503 when it is full), so async workers never wait on inference.
2. Size `CALIBAN_PII_NER_SESSIONS` to the cores available (for example cores divided by `intra_threads`) by default, not 1.
3. Skip the model when the regex tier already covers the text, or batch concurrent requests into one inference call.

#### After the inference pool (`perf/ner-and-streams`)

Fixes 1 and 2 are done (see [PII NER model](../README.md#inference-pool-and-backpressure) in the README):

- `PiiEngine::protect` runs on dedicated worker threads, one per ONNX session, never on tokio workers and never on tokio's blocking pool. Callers await a oneshot.
- Sessions default to `min(cores / 2, 4)` (4 here) with `cores / (2 × sessions)` intra-op threads each (1 here) and ONNX Runtime spin-waiting off.
- A bounded queue (128) sits in front of the workers. When it is full the default is fail closed: `503` with `retry-after`, nothing sent upstream. Degrading to the regex tier is an explicit opt-in (`CALIBAN_PII_NER_OVERFLOW=degrade`).

Same machine, back to back, 1000 requests per side per row in two interleaved rounds; "before" is `fix/metering` (`5e71b61`: 1 session, 4 intra-op threads, spinning on, inference inline). Overhead in ms (TTFB for the stream rows):

| Scenario | Conc. | p50 before | p50 after | p99 before | p99 after | req/s before | req/s after |
|---|---:|---:|---:|---:|---:|---:|---:|
| chat + PII with NER | 1 | 10.8 | 12.0 | 14.4 | 13.7 | 91 | 82 |
| | 16 | 167.8 | 119.1 | 227.6 | 210.2 | 95 | 127 |
| | 64 | 618.1 | 475.5 | 1089.9 | 540.2 | 97 | 133 |
| stream + PII with NER, TTFB | 1 | 10.3 | 12.4 | 13.2 | 16.6 | 90 | 78 |
| | 16 | 127.9 | 122.1 | 215.8 | 136.2 | 93 | 128 |
| | 64 | 321.2 | 490.1 | 941.0 | 543.0 | 92 | 129 |
| PII-off chat on the NER gateway while 16 NER requests are in flight | 1 | 0.08 | 0.11 | **63.8** | **0.18** | 749 | 4869 |
| | 16 | 0.26 | 0.30 | 0.35 | 0.47 | 39095 | 28334 |
| | 64 | 0.73 | 0.77 | 0.94 | 1.25 | 49134 | 39747 |

What changed:

- **Collateral damage is gone.** PII-off traffic on a gateway busy with NER keeps its normal latency: p99 0.18 ms at concurrency 1 (was 64 to 140 ms, because requests waiting for the session blocked their tokio worker). At concurrency 16 and 64 its throughput is lower than before because inference now uses 4 sessions' worth of cores instead of 1 (the background load is 16 NER requests); its latency stays under 1.3 ms p99.
- **NER throughput is up about 35%** (95 to 130 requests per second), and the p99 at concurrency 64 is halved. Throughput did not scale with the 4 sessions because the machine was shared: the 10 cores (4 performance, 6 efficiency) also ran the load generator, the mock and other agents' builds (load average 5 to 12). `ner_bench --pool` on the same machine gives 82 to 90 requests per second for 1 session and 122 to 140 for 2 to 8 sessions, so the pool is CPU-bound here. Expect it to scale with performance cores on a dedicated host.
- **Single-request latency** rose from about 10.8 to 12.0 ms: 1 intra-op thread per session instead of 4. For latency-sensitive, low-concurrency deployments, set `CALIBAN_PII_NER_THREADS=2` (10.2 ms at concurrency 1 in `ner_bench --pool`, at the cost of some throughput).
- No request was rejected in these runs: concurrency 64 stays within the default queue of 128.

### Streaming at concurrency 64

Unpaced streams at concurrency 64 are the one gateway path over budget. In this scenario the mock writes all 62 events of a stream back to back with no delay, about 9,000 streams per second through the gateway, which is roughly 560,000 SSE events per second. It is a stress case: a real model emits a token every 10 to 50 ms, and the paced rows (1 ms between chunks, still far faster than a model) show 0.1 to 0.6 ms TTFB overhead at every concurrency. At concurrency 1 the gateway spends about 6 microseconds per streamed event (0.37 ms for 62 events).

Profile (macOS `sample`, 8 s, `--profile profiling` build, 64 unpaced streams, share of busy samples, inclusive):

| Cost | Share |
|---|---:|
| `writev` to the client socket (one write per body frame) | 31% |
| Per-chunk stream task (`stream::openai_shaped`), all of the next four included | 42% |
| Stream task: serde_json parse of every chunk into a `Value` | 11% |
| Stream task: serde_json serialisation of the rewritten chunk | 10% |
| Stream task: `format!("data: {v}\n\n")` and string writes | 11% |
| Stream task: SSE parsing | 6% |
| Allocator (malloc, free, realloc) | 16% |
| Channel between the stream task and the response body | 4% |
| Request setup (`pipeline::run`: auth, route, PII, reservation) | 4% |

Fix suggestions (not done here, they change shared gateway code):

1. **Passthrough fast path** for OpenAI clients when no rehydration and no `<think>` splitting is needed: do not build a `serde_json::Value` per chunk. Parse only the top level into `Map<String, Box<RawValue>>` (or scan bytes) to swap `model` and to spot a `usage` object, and re-emit the rest verbatim. This removes about a third of the per-chunk CPU.
2. **Serialise into a reused buffer** (`serde_json::to_writer` into one `Vec<u8>` per stream) instead of `format!` plus a fresh `String` per event, and reuse the SSE parser's output strings. This targets most of the allocator share.
3. **Record `gen_ai.response.model` once per stream**, not on every chunk.
4. Write coalescing beyond one upstream read would add latency and is not recommended.

#### After the stream passthrough (`perf/ner-and-streams`)

Fixes 1 to 3 above are done, plus a few more. Write coalescing (point 4) is done only for data that has already arrived, which adds no waiting:

- **Passthrough** (`crates/caliban-gateway/src/passthrough.rs`). One serde_json pass over each chunk, with no tree and no allocation, finds the byte range of the top-level `model` value, whether `usage` is present, and the output text bytes for usage estimates. The chunk then goes out as received, with only the `model` literal replaced by the gateway's model id. The replacement is serialised by serde_json, so escaping is always correct. For clients that did not ask for usage, OpenAI's `"usage": null` member is cut out together with one adjacent comma (`metering::strip_usage` semantics). Chunks that carry usage, unusual chunks (not an object, duplicate keys, escaped keys, multi-line data, unexpected types), the Anthropic-client translation and semantic-cache capture take the general path, which is unchanged.
- **Surrogate restoring in place** (PII on). A chunk with one unfinished choice and a string `delta.content` (no reasoning fields) feeds the streaming rehydrator as before. Only the `content` literal is rewritten, and only when the restored text differs. Finishing, multi-choice and reasoning chunks go through `transform_chunk`.
- **Native Anthropic**. Content block start, delta and stop events and `ping` pass through as received when there is nothing to restore. `message_start` (model rewrite, usage) and `message_delta` (usage) take the general path.
- **Buffers**. Each stream writes into one `BytesMut` that batches are split off (`serde_json::to_writer` on the general path, no `format!`). The SSE parser hands out borrowed payloads (`SseParser::push_each`; a single `data:` line is not copied), finds event boundaries with memchr, and only rescans new bytes.
- **Coalescing**. After the first frame of a stream (sent at once, for time to first byte), upstream reads that are already waiting are merged into one body frame, up to 64 KiB.
- `gen_ai.response.model` is recorded once per stream.
- The per-request rehydrator builds a contiguous NFA instead of letting aho-corasick pick a DFA. Building it was 6% of busy samples on PII streams.

Correctness: unit tests feed a corpus through both paths (passthrough, and the general path forced with a test switch). The corpus covers unicode and surrogate-pair escapes, escaped quotes in content and in the upstream model name, key order and whitespace, `model: null`, no model, reasoning and tool-call deltas, `usage: null` (literal and escaped key), usage chunks, `[DONE]`, error events, non-JSON and non-object data, and multi-line data. Native Anthropic events and PII streams with surrogates split across chunks are also covered. Each case is split three ways: one read, one read per event, and 7-byte reads. The tests check the same client events (as JSON values), the same metered usage, and the same output-byte counts, with and without client usage.

A/B, same machine, back to back, three alternating rounds of 3000 requests per side, median of the rounds (load average 6 to 8). "Before" is `fix/metering` (`5e71b61`). Overhead in ms:

| Scenario | Conc. | p50 before | p50 after | p99 before | p99 after | TTFB p50 before | TTFB p50 after |
|---|---:|---:|---:|---:|---:|---:|---:|
| stream (PII off) | 1 | 0.276 | **0.191** | 0.355 | 0.259 | 0.051 | 0.052 |
| | 16 | 0.779 | **0.612** | 3.355 | 1.356 | 0.294 | 0.322 |
| | 64 | 3.463 | **3.158** | 9.380 | 7.328 | 0.685 | 1.055 |
| stream + PII (regex, reversible) | 1 | 0.338 | **0.246** | 0.422 | 0.293 | 0.080 | 0.074 |
| | 16 | 0.937 | **0.717** | 4.650 | 2.838 | 0.399 | 0.372 |
| | 64 | 4.704 | **3.404** | 17.474 | 11.514 | 0.740 | 1.141 |

Rounds at concurrency 64, p50: PII off 3.46 / 3.62 / 3.37 before, 2.62 / 3.25 / 3.16 after; PII on 4.70 / 5.17 / 4.65 before, 3.15 / 3.40 / 3.58 after.

Latency at concurrency 64 swings with the machine's load, so gateway CPU time per request is the steadier measure. It was read from the gateway process's CPU time over 21,000 streams at concurrency 64, alternating builds:

| Scenario | Before (µs/stream) | After (µs/stream) | Change |
|---|---:|---:|---:|
| stream (PII off) | 583 | 424 | -27% |
| stream + PII | 625, 674 | 495, 478 | -25% |

(An earlier, quieter pair gave 495 and 337 µs for PII off.)

- **Time to first byte at concurrency 64 rose** (0.69 to 1.06 ms) while total latency fell. With every upstream read of a stream already waiting, the stream task now processes them all in one go before yielding, so other streams' first frames wait a little longer for a worker. With a real model's pacing nothing is waiting to merge, and the paced and concurrency 1 and 16 rows do not show it.
- New profile (same method, PII off, concurrency 64). The stream task fell from 42% to 8% of busy samples; scanning chunks is about 5%. `writev` to the client is now 37%. Request setup (`pipeline::run`) is 10%, reqwest's connection-pool mutex 3.4%, and `uuid::now_v7`'s global mutex 1.5%. What remains is mostly HTTP plumbing on both legs and kernel writes, not per-chunk work.
- **Coalescing the first frame too** made no measurable difference to CPU (406 to 420 vs 400 to 412 µs per stream), so the first frame still leaves at once.
- **TCP_NODELAY, re-tested** (`CALIBAN_TCP_NODELAY=1`, new, off by default). Concurrency 64: 850 µs of CPU per stream and 8.8 to 9.0 ms p50 overhead, against 310 to 400 µs and 3.3 to 4.1 ms with it off. Concurrency 1: 0.19 ms against 0.22 ms. On loopback Nagle coalesces hyper's small writes, which helps far more than it hurts, so it stays off. **For the AWS run**: measure both settings over a real network, where a token frame can wait for a delayed ACK with Nagle on; at real token rates (one frame every 10 to 50 ms) that is the case that matters.

## Fixes made on this branch

Small, contained changes, with before and after numbers from the quietest A/B round (same machine, same day, 3000 requests per side, p50 total overhead in ms):

| Build | stream c=1 | stream c=64 | stream+PII c=1 | stream+PII c=64 |
|---|---:|---:|---:|---:|
| Branch point `409a138` | 0.282 | 3.427 | 0.361 | 4.030 |
| + SSE parser fix | 0.260 | 4.067 | 0.330 | 4.335 |
| + one write per upstream read (kept) | **0.260** | **2.932** | **0.315** | **4.006** |
| TCP_NODELAY on accepted sockets only (reverted) | 0.434 | 6.606 | 0.472 | 7.838 |

1. **SSE parser** (`crates/caliban-ir/src/sse.rs`): consumed bytes are dropped once per read instead of once per event. Draining each event from the front of the buffer moved the rest of the buffer every time, quadratic in the number of events per read (10.5% of busy samples at concurrency 64 before the fix). A unit test covers 100 events in one read with a partial tail.
2. **One write per upstream read** (`crates/caliban-gateway/src/stream.rs`, both stream paths): the events parsed from one upstream read go out as one channel message and one body frame instead of one per event. Events that arrive together leave together, so no latency is added.
3. **Tried and reverted: `TCP_NODELAY`** on the gateway's accepted sockets. On loopback it makes the benchmark worse (Nagle was coalescing hyper's per-frame writes). It is still worth testing on a real network: with Nagle on, a token frame can wait for the client's delayed ACK of the previous frame. Recommendation: measure over a real link before deciding.
4. A `profiling` cargo profile (release with symbols) for profilers.

## Isolation audit

`apps/caliban/tests/isolation.rs`, run by plain `cargo test`. Real binary, mock upstream, tenants `alpha` and `beta` (both PII reversible, each with BYOK providers including one with the **same provider id** `openai` and one `anthropic`), a shared salted pool, and a shared pool restricted to `alpha`.

| Property | Result | Test |
|---|---|---|
| A's key cannot list or use B's models, BYOK-only models or restricted shared pools (400 in both dialects, nothing sent upstream) | **Pass** | `routes_and_models_are_tenant_scoped` |
| `caliban/auto` follows the caller's own route table, for every intent | **Pass** | `routes_and_models_are_tenant_scoped` |
| BYOK credentials: the same catalogue model is reached with the caller's own key (JSON, stream, OpenAI-to-Anthropic translation, native Anthropic), including 60 interleaved concurrent requests | **Pass** | `byok_credentials_never_cross_tenants` |
| Exact cache: an entry seeded by A misses for B on an identical prompt (shared model and BYOK model, both dialects); B's request goes upstream | **Pass** | `exact_cache_entries_are_tenant_scoped` |
| `cache_salt` differs per tenant, is stable per tenant, is 32 hex characters and not the tenant id, is stable across restarts with the same `CALIBAN_KEK` and changes with another KEK; with the mock's salted prefix cache, B sees `cached_tokens: 0` for a prompt A already cached | **Pass** | `cache_salt_differs_per_tenant` |
| Usage events (WAL and `/api/v1/usage?tenant_id=`) are attributed only to the caller: 52 mixed requests (streams, both dialects, cache hits for both tenants) under concurrency, each event matched to its response by request id | **Pass** | `usage_is_attributed_to_the_calling_tenant` |
| PII: the same value gets different surrogates for A and B; B sending A's surrogate never gets A's original back (JSON and stream); 40 interleaved concurrent requests each get only their own originals back; the upstream never sees an original | **Pass** | `pii_surrogates_never_cross_tenants` |
| Revoked keys and a deleted tenant's keys get 401 on chat, messages, count_tokens, models and embeddings; the tenant's other key and other tenants keep working | **Pass** | `revoked_and_deleted_tenant_keys_get_401` |
| Admin API: 21 routes reject tenant keys (bearer and `x-api-key`) and missing auth with 401; the snapshot endpoint never returns 200 to a tenant key; the data plane does not serve `/api/v1/*`; the admin token is not a tenant key; a body cannot name another tenant (`caliban.tenant` is a 400) | **Pass** | `admin_endpoints_reject_tenant_keys` |
| Datasources: B's datasource id in A's `caliban.datasources` is not forwarded and has no effect | **Partly testable** | `datasource_ids_from_another_tenant_are_inert_today` |

No isolation bug was found. Notes for later phases:

- **Datasources are not consumed by the data plane yet.** `caliban.datasources` is parsed and ignored: it is not checked against the caller's tenant and is not part of the exact-cache key (the key gets empty ACL and epoch inputs, and the `caliban` extension is stripped before hashing). Harmless today. When grounding lands (P2), the gateway must reject another tenant's datasource with 403, and the cache key must include the ACL fingerprint and datasource epochs; the inert-today test should then be turned into that check.
- Surrogates are request-scoped today. The tenant-scoped surrogates work on another branch should keep the "different surrogates per tenant" and "never rehydrated across tenants" tests green; they are written to be scope-agnostic.
- `cache_salt` is sent only to providers marked `cache_salt = true` (vLLM, SGLang). For BYOK providers the tenant's own key isolates the provider's cache; no `prompt_cache_key` is set for OpenAI.

## Usage accuracy

`apps/caliban/tests/usage_accuracy.rs`: one sequential request at a time, each usage event paired with the bill the mock recorded for that request (the event's request id must match the response). Tokens must match exactly, and cost must equal the provider's bill with its prompt-cache pricing.

### First measurement (`652fc17`)

Tokens were exact on every path (71 requests). Cost was exact at catalogue list prices, but list prices are not what a provider charges once prompt caching is involved: the gateway priced every prompt token at `price_in_per_mtok`, so the run was metered **+33.0%** above the provider bill (+103.7% on the Anthropic cache-read rows, +19% on the OpenAI-compatible prefix-cache rows; a cache-write request alone was metered 19% below its bill). Two metering bugs: streams whose client set `include_usage: false` were metered as **0 tokens** (the provider billed them), and so were clients that disconnected mid-stream. Both, and the cache pricing, failed the 1% criterion.

### After the metering fixes (`fix/metering`)

Date: 2026-10-09, same machine. The workload now also covers `include_usage: false` streams and Anthropic cache writes with the 1-hour TTL (81 requests). The test catalogue carries the providers' cache prices (Anthropic reads 0.1x, 5-minute writes 1.25x, 1-hour writes 2x the input price; OpenAI-compatible cached input 0.5x). "Metered before" is what the gateway metered before the fixes for the same billed tokens (list price, and 0 for opt-out streams).

| Path | Requests | Prompt (billed / metered) | Completion | Cache reads | Cache writes | Provider bill | Metered before | Before vs bill | Metered now | Now vs bill |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OpenAI client, OpenAI-compatible upstream, JSON | 6 | 180 / 180 | 103 / 103 | 0 / 0 | 0 / 0 | 0.000386 | 0.000386 | +0.0% | 0.000386 | +0.00% |
| OpenAI client, OpenAI-compatible upstream, stream | 6 | 180 / 180 | 103 / 103 | 156 / 156 | 0 / 0 | 0.000308 | 0.000386 | +25.3% | 0.000308 | +0.00% |
| OpenAI client, OpenAI-compatible upstream, stream, `include_usage: false` | 6 | 192 / 192 | 109 / 109 | 0 / 0 | 0 / 0 | 0.000410 | 0.000000 | -100.0% | 0.000410 | +0.00% |
| OpenAI client, Anthropic upstream (translated), JSON | 6 | 180 / 180 | 103 / 103 | 0 / 0 | 0 / 0 | 0.002085 | 0.002085 | +0.0% | 0.002085 | +0.00% |
| OpenAI client, Anthropic upstream (translated), stream | 6 | 180 / 180 | 103 / 103 | 0 / 0 | 0 / 0 | 0.002085 | 0.002085 | +0.0% | 0.002085 | +0.00% |
| Anthropic client, OpenAI-compatible upstream (translated), JSON | 6 | 180 / 180 | 103 / 103 | 156 / 156 | 0 / 0 | 0.000308 | 0.000386 | +25.3% | 0.000308 | +0.00% |
| Anthropic client, OpenAI-compatible upstream (translated), stream | 6 | 180 / 180 | 103 / 103 | 156 / 156 | 0 / 0 | 0.000308 | 0.000386 | +25.3% | 0.000308 | +0.00% |
| Anthropic client, Anthropic upstream (native), JSON | 6 | 180 / 180 | 103 / 103 | 0 / 0 | 0 / 0 | 0.002085 | 0.002085 | +0.0% | 0.002085 | +0.00% |
| Anthropic client, Anthropic upstream (native), stream | 6 | 180 / 180 | 103 / 103 | 0 / 0 | 0 / 0 | 0.002085 | 0.002085 | +0.0% | 0.002085 | +0.00% |
| `caliban/auto` with fallback (first candidate 500s) | 6 | 180 / 180 | 103 / 103 | 156 / 156 | 0 / 0 | 0.000308 | 0.000386 | +25.3% | 0.000308 | +0.00% |
| Anthropic native with `cache_control` (write, then reads) | 8 | 2624 / 2624 | 72 / 72 | 1860 / 1860 | 620 / 620 | 0.004395 | 0.008952 | +103.7% | 0.004395 | +0.00% |
| Anthropic native with `cache_control`, 1-hour TTL (write, then read) | 4 | 1356 / 1356 | 32 / 32 | 640 / 640 | 640 / 640 | 0.004740 | 0.004548 | -4.1% | 0.004740 | +0.00% |
| OpenAI-compatible, provider prefix-cache hits | 6 | 138 / 138 | 66 / 66 | 76 / 76 | 0 / 0 | 0.000232 | 0.000270 | +16.4% | 0.000232 | +0.00% |
| Gateway exact cache (1 miss, then hits) | 3 (2 hits) | 17 / 17 | 9 / 9 | 0 / 0 | 0 / 0 | 0.000035 | 0.000035 | +0.0% | 0.000035 | +0.00% |
| **Total** | 81 | 5947 / 5947 | 1215 / 1215 | 3200 / 3200 | 1260 / 1260 | 0.019770 | 0.024075 | **+21.8%** | 0.019770 | **+0.00%** |

(PII prompts are counted after pseudonymisation, so prompt sizes vary by a token or two between runs. Several OpenAI-compatible rows show cache reads because the same prompt was sent on an earlier path and the mock's prefix cache, keyed by credential, served it. The 1-hour row is metered below its bill before the fix because writes cost 2x and reads 0.1x; the 5-minute row's single write is hidden by its three reads.)

**Verdict: pass.** Tokens and cost match the provider's bill exactly on every path, every request carries `usage_source: "provider"`, and the per-request cost difference is below 1e-12 USD. What changed:

- **Opt-out streams.** Streams always ask the upstream for usage (`stream_options.include_usage: true`, other `stream_options` keys kept). For an OpenAI client that did not ask for usage, the usage-only final chunk is dropped and `usage` (including OpenAI's per-chunk `"usage": null`) is removed, so the client sees what it asked for. Models whose server rejects `stream_options` are marked `capabilities.rejects_stream_options`: the field is not sent and their streams are metered from an estimate (flagged). Anthropic native streams already captured `message_start` and `message_delta` usage; that is now tested for both complete and interrupted streams.
- **Cache pricing.** The catalogue takes `price_cache_read_per_mtok`, `price_cache_write_per_mtok` and `price_cache_write_1h_per_mtok`. One cost function prices uncached input, cache reads, cache writes (1-hour writes separately) and output; `cost_usd`, `x-caliban-cost-usd`, quota settlement, `routed_model_cost_usd` and `flat_price_usd` all use it. Unset cache prices fall back to the input price (the previous behaviour), with a startup warning for priced OpenAI and Anthropic models and a once-per-model warning when a provider reports cache tokens for an unpriced model. Usage events gain `cache_write_tokens` and `cache_write_1h_tokens`.
- **Disconnects.** A stream that ends without a complete usage report (client disconnect, upstream error, no usage sent) is metered with the best numbers available and marked `usage_source: "estimated"`: the provider's prompt tokens when it already reported them (Anthropic `message_start`), otherwise the prompt estimate, plus completion tokens estimated from the output streamed so far. `client_disconnect_is_metered_as_an_estimate` disconnects after the first chunk: the provider billed 81 + 48 tokens, the gateway metered 79 + 1 (estimated). The provider bills the whole generation it produced before noticing the cancellation, so an estimate after a disconnect is a floor, not a bill; such events are flagged rather than claimed exact.

### Estimation paths

The gateway estimates in three places, and every estimated usage event says so (`usage_source: "estimated"`):

- **Quota reservation** before the call: prompt estimate at about 4 bytes per token plus per-message, image and tool overhead (`ChatRequest::estimate_prompt_tokens`), plus `max_tokens` or 1024. Settlement replaces it with the metered usage.
- **Streams without a complete usage report** (above): disconnects, upstream errors, and models with `rejects_stream_options`.
- **Responses without a usage object** (non-streaming chat, embeddings, rerank from an upstream that reports none): the prompt estimate plus output bytes divided by 4. Before, a non-streaming response without usage was metered as 0 tokens.

### Usage WAL

The JSONL sink opened, appended and closed the file for every event, inline before the response was returned (about 15 microseconds per request at concurrency 1 and 0.25 ms at 64). It is now a background writer: the request enqueues the event on a bounded queue (16,384 by default) and returns; the writer keeps the file open, appends in batches (flushing whenever the queue runs empty, at 256 KiB, and on graceful shutdown), and runs file I/O on the blocking pool. `fdatasync` is `off` by default as before (graceful shutdown always syncs) or after every batch with `CALIBAN_USAGE_WAL_FSYNC=batch`. A full queue makes a request wait at most 20 ms, then the event is dropped and counted; `/healthz` reports `usage_wal` counters (written, dropped, write errors, backpressure waits, queue depth). The format is unchanged and old lines still parse (`read_wal` test with a pre-fix line).

Overhead re-measured with the release build, `caliban-bench --only chat` (4000 requests per side, 2 interleaved rounds), on a loaded machine (load average about 40 from parallel builds, so absolute numbers are inflated and noisy; compare rows of the same run):

| Scenario | p50 overhead c=1 | c=16 | c=64 |
|---|---:|---:|---:|
| chat, WAL off | 0.119 | 0.282 | 0.916 |
| chat, WAL on | 0.129 | 0.224 | 0.788 |
| WAL on minus off, this run | +0.010 | -0.058 | -0.128 |
| WAL on minus off, first measurement (open per event) | +0.017 | +0.087 | +0.248 |

With the background writer the WAL's cost is within run-to-run noise at every concurrency.

## Caveats

- Localhost only: client, gateway and mock share one machine and its 10 cores, over loopback. Network latency, TLS and real provider jitter are absent, and loopback favours small writes (see TCP_NODELAY above).
- macOS: scheduler and timer behaviour differ from Linux servers; the 1 ms paced-stream sleeps have about 1 ms of jitter. Production numbers should come from Linux.
- The mock answers in about 30 microseconds and emits whole streams in one burst, which is a worst case for per-event gateway work and not representative of model pacing.
- Other agents were building on this machine during the day; the full run started at load average 6 and drifted. Concurrency 64 rows vary run to run (unpaced stream p50 between 2.9 and 4.2 ms across runs); concurrency 1 and 16 rows are stable to within about 0.1 ms.
- The provider cost column assumes Anthropic 0.1x reads and 1.25x writes and OpenAI 0.5x cached input; real discounts vary by model.

## Reproduce

```sh
scripts/bench.sh                               # report in bench/results/REPORT.md
CALIBAN_PII_NER_DIR=… scripts/bench.sh         # with the NER rows (builds --features ner)
QUICK=1 scripts/bench.sh                       # smoke check of the suite
cargo test -p caliban --test isolation         # isolation audit only
cargo test -p caliban --test usage_accuracy    # usage accuracy only
cargo build --profile profiling -p caliban     # symbols for `sample` or flamegraphs
caliban-bench --caliban … --only '=stream,=stream+pii'   # exact scenario names (`stream` alone matches every stream row)
cargo run --release -p caliban-pii --features ner --example ner_bench -- "$CALIBAN_PII_NER_DIR" --pool   # NER session sizing
```
