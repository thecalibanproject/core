# P0 measurement results

The P0 exit criteria (reference architecture, section 8) are: **under 3 ms p50 overhead**, **isolation audit passes**, **usage matches provider bills within 1%**. This file records the first full measurement and what it found. Regenerate the raw report with `scripts/bench.sh` (it writes `bench/results/REPORT.md`, which is not committed).

## Verdict

| Criterion | Result |
|---|---|
| Under 3 ms p50 overhead | **Pass** for every non-streaming path (chat, PII regex tier, cache hit, native Anthropic, usage WAL) at concurrency 1, 16 and 64: worst p50 0.75 ms. **Pass** for streams at concurrency 1 and 16 (worst p50 1.17 ms total, 0.49 ms TTFB) and for paced streams at every level (TTFB p50 at most 0.57 ms). **Fail** for unpaced streams at concurrency 64: p50 4.1 ms (PII off) and 5.4 ms (PII on) in the full run, 2.9 ms in the quietest A/B round. See [Streaming at concurrency 64](#streaming-at-concurrency-64). The NER tier (model inference) is outside the 3 ms budget and is reported separately. |
| Isolation audit passes | **Pass**: 9 of 9 properties, through the real binary. No cross-tenant leak found. One property (datasources) is only partly testable today because the data plane does not consume datasources yet. |
| Usage within 1% of provider bills | **Tokens: pass, exact** on every path (71 requests, 4390 prompt, 1074 completion and 2432 cached tokens, zero difference). **Cost: pass at catalogue list prices, fail against real provider pricing when prompt caching is involved** (+33% over the run; up to +104% on Anthropic cache reads, and an undercharge on cache writes). One metering bug: streams whose client sets `include_usage: false` are metered as 0 tokens. |

## Run

- Hardware: Apple M5, 10 cores (4 performance, 6 efficiency), 16 GiB, macOS 26.5.1. rustc 1.96.0.
- Commit measured: `652fc17` on `feat/bench` (branch point `409a138`, plus the two stream fixes listed below).
- Date: 2026-10-09. Load average before the run: 5.96 (other agents were compiling on the same machine earlier; see caveats).
- Release build (`lto = "thin"`, `codegen-units = 1`); NER rows use a `--features ner` build with `nym-pii-multilingual-small-int8` 3.0.0 (`CALIBAN_PII_NER_DIR`), default `NerOptions` (1 session, up to 4 intra-op threads).

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
- The usage WAL costs about 15 microseconds per request at concurrency 1 and 0.25 ms at 64 (the JSONL sink opens, appends and closes the file for every event, inline before the response is returned).

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

`apps/caliban/tests/usage_accuracy.rs`: one sequential request at a time, each usage event paired with the bill the mock recorded for that request (the event's request id must match the response). Tokens must match exactly; cost must equal the bill at the gateway's catalogue prices.

| Path | Requests | Prompt (billed / metered) | Completion | Cached prompt | Cost at list price (expected / metered) | Provider cost with cache pricing | Metered vs provider |
|---|---:|---:|---:|---:|---:|---:|---:|
| OpenAI client, OpenAI-compatible upstream, JSON | 6 | 178 / 178 | 103 / 103 | 0 / 0 | 0.000384 / 0.000384 | 0.000384 | +0.0% |
| OpenAI client, OpenAI-compatible upstream, stream | 6 | 180 / 180 | 103 / 103 | 124 / 124 | 0.000386 / 0.000386 | 0.000324 | +19.1% |
| OpenAI client, Anthropic upstream (translated), JSON | 6 | 179 / 179 | 103 / 103 | 0 / 0 | 0.002082 / 0.002082 | 0.002082 | +0.0% |
| OpenAI client, Anthropic upstream (translated), stream | 6 | 179 / 179 | 103 / 103 | 0 / 0 | 0.002082 / 0.002082 | 0.002082 | +0.0% |
| Anthropic client, OpenAI-compatible upstream (translated), JSON | 6 | 179 / 179 | 103 / 103 | 124 / 124 | 0.000385 / 0.000385 | 0.000323 | +19.2% |
| Anthropic client, OpenAI-compatible upstream (translated), stream | 6 | 179 / 179 | 103 / 103 | 124 / 124 | 0.000385 / 0.000385 | 0.000323 | +19.2% |
| Anthropic client, Anthropic upstream (native), JSON | 6 | 178 / 178 | 103 / 103 | 0 / 0 | 0.002079 / 0.002079 | 0.002079 | +0.0% |
| Anthropic client, Anthropic upstream (native), stream | 6 | 180 / 180 | 103 / 103 | 0 / 0 | 0.002085 / 0.002085 | 0.002085 | +0.0% |
| `caliban/auto` with fallback (first candidate 500s) | 6 | 179 / 179 | 103 / 103 | 124 / 124 | 0.000385 / 0.000385 | 0.000323 | +19.2% |
| Anthropic native with `cache_control` (write, then reads) | 8 | 2624 / 2624 | 72 / 72 | 1860 / 1860 | 0.008952 / 0.008952 | 0.004395 | +103.7% |
| OpenAI-compatible, provider prefix-cache hits | 6 | 138 / 138 | 66 / 66 | 76 / 76 | 0.000270 / 0.000270 | 0.000232 | +16.4% |
| Gateway exact cache (1 miss, then hits) | 3 (2 hits) | 17 / 17 | 9 / 9 | 0 / 0 | 0.000035 / 0.000035 | 0.000035 | +0.0% |
| **Total** | 71 | 4390 / 4390 | 1074 / 1074 | 2432 / 2432 | 0.019510 / 0.019510 | 0.014667 | +33.0% |

(PII prompts are counted after pseudonymisation, so prompt sizes vary by a token or two between runs. Several OpenAI-compatible rows show cached tokens because the same prompt was sent on an earlier path and the mock's prefix cache, keyed by credential, served it.)

What this shows:

- **Tokens are exact everywhere**: both dialects, streams, translation in both directions, native passthrough with cache reads and writes, provider prefix-cache hits, fallbacks (billed once; the 500 is not billed), PII. Anthropic's `input_tokens` excludes cache tokens; the gateway adds `cache_read_input_tokens` and `cache_creation_input_tokens` back, which matches the provider's total.
- **Cache hits** are metered as zero tokens and zero cost with `tokens_saved` set; the provider is not called, so nothing is billed.
- **Cost at list prices is exact**, but it is not what a provider charges once prompt caching is involved. `cost_usd` prices every prompt token at `price_in_per_mtok`; providers charge cache reads at a discount (Anthropic 0.1x; OpenAI 0.5x on older models and less on newer ones; the comparison above uses 0.5x) and Anthropic cache writes at 1.25x. Over this run the metered cost is 33% above the provider bill (104% on the Anthropic cache rows), and a cache-write request alone is metered 19% below its bill. **This fails the 1% criterion whenever prompt caching is in play.** Fix: add cache-read and cache-write prices to the model catalogue, carry `cache_creation_input_tokens` in `UsageEvent`, and price the three classes separately. Tracked by the ignored test `cost_matches_provider_bill_with_prompt_caching`.

### Estimation paths

No estimation is used when the upstream reports usage, which is every path above. The gateway estimates in two places, and only for quota, never for the usage event:

- **Quota reservation** before the call: prompt estimate at about 4 bytes per token plus per-message, image and tool overhead (`ChatRequest::estimate_prompt_tokens`), plus `max_tokens` or 1024. Settlement replaces it with the reported usage.
- **Settlement of a stream that ended without usage** (client disconnect, upstream that sends none): prompt estimate plus streamed bytes divided by 4.

**Bug: streams with `stream_options.include_usage: false` are metered as 0 tokens.** The gateway adds `include_usage: true` upstream only when the client did not set `stream_options`; a client that sets it to `false` turns usage off upstream as well, so the provider bills the request while the usage event says 0 prompt and 0 completion tokens (quota settlement uses the estimate above). The same applies to a client that disconnects mid-stream: the event records 0 tokens, while the provider bills what it generated. Fix: always request usage upstream, strip the usage-only chunk for clients that opted out, and record the estimate in the usage event (flagged as estimated) when no usage arrives. Tracked by the ignored test `stream_without_client_usage_is_still_metered`.

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
cargo test -p caliban --test usage_accuracy    # usage accuracy only (add -- --ignored for the known gaps)
cargo build --profile profiling -p caliban     # symbols for `sample` or flamegraphs
```
