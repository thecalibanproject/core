# AWS measurement results, October 2026 (second run)

The second run of the deploy repo's AWS testbed (`deploy/aws/testbed`), on 2026-10-10. It re-measures on real hardware what core merged after [the first run](RESULTS-aws-2026-10.md) (`TCP_NODELAY` on by default with headers sent with the first SSE frame, semantic-cache guards and `min_threshold = 0.93`, the cache `query_prefix`, the calibrated `[routing]` block, `Idempotency-Key`, per-tenant DEKs and KEK rotation, OIDC single sign-on and roles, cache-hit billing for `caliban/auto`). It also covers what the first run skipped: split mode, NER on x86 and the zero-egress install.

## Verdict

| Question | Answer |
|---|---|
| What does intent classification (`caliban/auto`) add end to end? | **About 5 ms to the first token when the GPU is otherwise idle; up to the 25 ms budget under load.** Paired against the same prompts with the model pinned: **+5.0 ms** TTFT p50 at c = 1 (95% CI 4.4 to 5.3 ms; Stage 1 itself 5.4 ms), **+8 to +9 ms** at c = 8. While vLLM decodes for other users: +3.5 ms at c = 1 (Stage 1 takes 8.9 ms, but part of it hides in vLLM's step boundary), **+12 to +18 ms** at c = 8. At c = 32 Stage 1 hits its 25 ms budget on 59 to 65% of requests and falls back to the keyword rules, so it never adds more than about 27 ms; the TTFT difference there is lost in vLLM scheduling noise (±50 to 300 ms between rounds). A repeated prompt costs nothing measurable (embedding cache hit: Stage 1 0.04 ms, TTFT difference -0.01 ms, CI ±0.6 ms). The bottleneck is the embedder sharing the GPU with the chat model, not the gateway. |
| Gateway overhead with the real model, pinned | **About 1 ms.** TTFT p50 +1.2 ms against vLLM direct at c = 1 (CI 0.6 to 1.5 ms), +1.1 ms with the GPU busy; throughput identical. |
| Semantic cache with the new guards | **No false hits.** 0 of 38 near-misses hit (3 of 38 before); 14 of 36 paraphrases hit at the defaults (16 before). With the cache `query_prefix` at the same thresholds: the same 14 and 0. **With the prefix and `threshold = min_threshold = 0.91`: 24 of 36 (67%) and still 0 false hits.** A hit is served in 6.5 to 7.3 ms p50 (against 2.6 s for a fresh 64-token answer); a miss costs **+5.1 ms** p50 (+5.3 ms with the prefix). |
| Intent kNN through the gateway with `query_prefix` | **0.952 top-1** (accepted precision 0.957, abstain 1.4% at 0.5), against 0.838 raw, through Caliban's `/v1/embeddings`. Matches the first run's direct measurement (0.948). |
| Cache-hit billing for `caliban/auto` | **Correct, 27 of 27 checks.** Miss billed at the flat price; exact and semantic hits cost 0, are billed 20% of the flat price of the cached answer, `saved_usd` is the other 80%, and the `GET /api/v1/usage` totals add up. |
| Single sign-on with a real IdP | **Works, 26 of 26 checks against Dex**, plus a headless-browser sign-in through the console: login through the IdP, owner role from a group, CSRF and Origin enforcement, a viewer bound through the API reads but is refused writes, the audit log and other tenants (403), logout, audit entries with a verified chain. |
| Split mode (control plane, 2 routers, shared Valkey) | **Works.** Signed snapshots on both routers; one `requests_per_minute = 20` limit held across both routers (exactly 20 of 40 allowed); `Idempotency-Key` replayed across routers, 409 for a concurrent duplicate, 422 for a reused key; fail-static with the control plane down, including a router restart from its cached snapshot; new keys reach routers in about 3 s; KEK rotation per the README procedure with BYOK keys working at every step. |
| Streaming overhead with the new defaults (no env var) | **Nagle stall gone; c = 64 unchanged.** Unpaced streams at c = 64: **3.39 ms** p50 (3.45 before), p99 8.96 ms. Paced at 20 ms per chunk, first-token overhead **0.20 ms** at c = 1 (was +23.8 ms with Nagle on). Holding the headers until the first frame fixes it even with `CALIBAN_TCP_NODELAY=0` (+0.21 ms). TTFB for unpaced streams at c = 1 dropped from 0.33 to 0.10 ms. |
| NER on x86 vs Graviton | **x86 (Sapphire Rapids, AVX-512 VNNI/AMX) is 1.8 times faster per inference: 43 ms against 77 ms**, and saturates at 96 req/s against 41 on 8 vCPU. **2 intra-op threads per session: 29.7 ms and 103 req/s** (4 sessions x 2 threads); 2 sessions x 2 threads (the default's core budget) gives 29 ms at c = 1 but only 71 req/s. The M5 laptop is still faster (12 ms). |
| Zero-egress install | **Works, after two fixes found here.** An x86 gateway in the isolated subnet installed from a minisign-signed bundle and served requests to a model server in the VPC. Flow logs over its whole life: 105 flows left the VPC, all through the S3 gateway endpoint (3.8 MB); none through the internet gateway or anywhere else. Every egress attempt from the host and from the Caliban container failed. |

## Setup

- **Region and placement**: eu-central-1, one AZ (eu-central-1a). Phase 1 in the public subnet, phase 2 with the gateway in the isolated subnet. Access through SSM only. All hosts on spot this time (`cpu_use_spot = true`): same hardware, half the price; none was interrupted.
- **Phase 1** (scenarios 1 to 6): gateway and loadgen c8g.2xlarge (Graviton4, 8 vCPU), GPU host g6e.xlarge (1 x L40S 46 GB, driver 595.91.07), two routers c8g.xlarge (4 vCPU) for scenario 5 only.
- **Phase 2** (scenarios 7 and 8): loadgen c7i.2xlarge (Intel Xeon Platinum 8488C, Sapphire Rapids, 8 vCPU; `avx512_vnni`, `amx_int8`) in the public subnet, gateway c7i.2xlarge in the isolated subnet.
- **Caliban**: core `c37e7a2`, web `c5185df`, deploy `6fe9de8` (all main), built on the hosts (arm64 in 1 min 27 s on the gateway; amd64 in 2 min 46 s on the c7i). Compose stack: Postgres 17.11, Valkey 9.1.2, Qdrant 1.19.1.
- **Models**: unchanged from the first run (Qwen3.8-27B-FP8 at `017b9c7` on vLLM 0.30.0, Qwen3-Embedding-0.6B on TEI 1.9.4, Qwen3-Reranker-0.6B on vLLM). One change: `QWEN3_LARGE_MAX_MODEL_LEN=32768` (see [caveats](#caveats)); with it vLLM had 5.15 GiB of KV cache (129,858 tokens), more than the first run's 4.21 GiB.
- **Gateway config for the GPU scenarios**: the deploy `caliban.toml` with the `[routing]` block uncommented (`query_prefix`, `temperature = 0.1`, `abstain_threshold = 0.6`, `oos_threshold = 0.64`, default `budget_ms = 25`), `auto_price_in_per_mtok = 3.0` and `auto_price_out_per_mtok = 12.0`, `[cache.semantic] enabled = true` (defaults: `threshold = 0.95`, `min_threshold = 0.93`), and `CALIBAN_LOG=info,caliban_route=debug` for the Stage-1 timings.
- **Scripts**: [`bench/scripts/`](scripts) (stdlib Python; committed with this file). They read the host addresses from `GATEWAY_IP`, `GPU_IP`, `LOADGEN_IP` and `ROUTER_IPS`, which the testbed profile exports.

## 1. `caliban/auto` end to end with the real model

### Method

`scripts/auto_bench.py` streams the same prompts (the 18 realistic prompts of the first run, 64 output tokens with `ignore_eos`, temperature 0.7, thinking off) to three targets: vLLM directly, Caliban with the model pinned (`local/qwen3.8-27b`), and Caliban with `caliban/auto`. The tenant has PII and the semantic cache off and routes every intent to the same model, so the only difference between pinned and auto is the routing decision. Streams are never cached (T1 skips streams).

- **c = 1, paired**: request *i* sends the same prompt to the three targets back to back, in an order that rotates with *i*; the statistic is the per-request difference, with a bootstrap 95% CI of its median. 40 triples per condition.
- **c = 8 and 32**: each target runs as its own closed-loop level of 96 requests, in rotating order, 2 rounds, the same prompt sequence for every target within a round.
- **Unique prompts**: every request gets a unique ticket number appended (`"... (ticket idleu-108-3)"`), identical across the three targets. Without it the gateway's embedding cache answers repeated prompts (first pass, reported separately).
- **GPU busy**: a separate process keeps 8 streams of 512 tokens running directly against vLLM for the whole run.
- **Stage-1 cost**: from the gateway's debug route log (`knn_us`: embed plus kNN classify wall time), matched to the run's requests by order (`scripts/knn_log.py`, `scripts/s1_analyze.py`).

### Results

Milliseconds. TTFT is the time to the first content token.

| GPU | Conc. | TTFT p50 direct | pinned | auto | **auto - pinned** | Stage 1 p50 / p90 | kNN decided / abstained / budget timeout | E2E p50 direct / pinned / auto |
|---|---:|---:|---:|---:|---:|---:|---|---:|
| idle | 1 | 87.6 | 87.9 | 92.9 | **+5.01** (paired, CI 4.37 to 5.28) | 5.37 / 5.57 | 24 / 16 / 0 | 2621 / 2620 / 2625 |
| idle | 8 | 479.6 | 477.1 | 478.2 | **+9.4, +8.2** (per round) | 17.0 / 24.4 | 124 / 55 / 13 (7%) | 3248 / 3250 / 3250 |
| idle | 32 | 1210.0 | 1216.6 | 1258.4 | +35.5, -9.1 (per round; noise) | 25.8 / 26.3 | 49 / 19 / 124 (65%) | 4893 / 4876 / 4977 |
| busy | 1 | 178.2 | 179.8 | 182.9 | **+3.51** (paired, CI 2.80 to 4.09) | 8.86 / 10.06 | 25 / 15 / 0 | 3019 / 3017 / 3022 |
| busy | 8 | 520.2 | 518.5 | 533.3 | **+17.8, +12.3** (per round) | 23.6 / 26.4 | 74 / 31 / 87 (45%) | 3524 / 3553 / 3541 |
| busy | 32 | 4862.6 | 4423.5 | 4546.2 | -291, -10 (per round; noise) | 26.0 / 26.7 | 56 / 22 / 114 (59%) | 8430 / 8217 / 8294 |

Repeated prompts (the first pass, no ticket numbers, GPU idle): Stage 1 p50 **0.04 ms** (p99 15 ms, the first sight of each prompt), auto - pinned TTFT at c = 1 **-0.01 ms** (CI -0.50 to +0.66).

Gateway overhead, pinned against direct, paired at c = 1: **+1.19 ms** TTFT p50 idle (CI 0.59 to 1.51), +1.09 ms busy. Output throughput was identical across the three targets at every level (157, 340 tokens/s idle at c = 8 and 32; 143, 247 busy). No request failed in any run.

Reading it:

- **At c = 1 the routing decision costs one embedding**: 5.4 ms of Stage 1 shows up as 5.0 ms of TTFT. This is the honest number for "intent classification adds X ms" on an otherwise idle GPU.
- **When vLLM is already decoding, the embedding gets slower but the user sees less of it.** Stage 1 takes 8.9 ms, TTFT grows by 3.5 ms: a new request joins vLLM's batch at the next step boundary anyway, and part of the classification time overlaps that wait.
- **Under concurrency the embedder is the bottleneck.** TEI shares the L40S with vLLM, and concurrent embeddings queue (next table). At c = 8 Stage 1 is 17 to 24 ms p50 and adds 8 to 18 ms; at c = 32 it reaches the 25 ms budget on most requests, which then route by keyword rules. The budget works as designed: no request waited more than about 27 ms for routing. The cost is accuracy: those requests got the keyword rules instead of the kNN (0.952 top-1 offline; the keyword rules were not evaluated here).
- At c = 32 the TTFT differences between targets are vLLM scheduling (prefill of 32 prompts, plus 8 background streams when busy: 40 sequences for 32 slots, hence 4.4 to 4.9 s), not routing.

### The embedder under load

Single embeddings of short unique queries (`scripts/embed_tools.py latency`), TEI directly and through Caliban's `/v1/embeddings`, while vLLM serves 0, 8 or 32 background streams. Milliseconds.

| Background streams on vLLM | Path | c = 1 p50 / p99 | c = 8 p50 / p99 | Embeddings/s at c = 8 |
|---:|---|---:|---:|---:|
| 0 | TEI direct | 4.25 / 4.78 | 12.06 / 13.53 | 656 |
| 0 | Caliban | 5.09 / 7.99 | 11.88 / 14.70 | 664 |
| 8 | TEI direct | 7.88 / 9.72 | 24.05 / 25.41 | 332 |
| 8 | Caliban | 7.88 / 10.71 | 23.95 / 25.52 | 334 |
| 32 | TEI direct | 7.93 / 10.20 | 24.20 / 27.78 | 331 |
| 32 | Caliban | 7.94 / 10.53 | 24.20 / 25.70 | 332 |

A decoding vLLM halves TEI's throughput on the shared GPU, and 8 concurrent classifications already take 24 ms each. The gateway's own embedder client adds nothing measurable (it has no concurrency limit; it batches and caches).

## 2. Semantic cache re-measured

Same 36 paraphrase and 38 near-miss pairs as the first run (`scripts/semcache_pairs.py`), end to end through the gateway with Qwen3.8-27B answers (`scripts/semcache_e2e.py hits`): every seed first, then every probe, temperature 0, 64 tokens. A fresh tenant per configuration. The miss cost (`misslat`) is measured against a zero-latency mock, 300 unique prompts alternating between a tenant with the semantic cache on and one with it off.

| Configuration | Paraphrases hit (semantic) | Near-misses hit (false hits) | Hit latency p50 / p90 | Added latency of a miss p50 / p90 |
|---|---:|---:|---:|---:|
| First run: threshold 0.95, min 0.90, no guards beyond numeric slots | 16 / 36 | **3 / 38** | 6 to 13 ms | +5.1 / +5.4 ms |
| Defaults now: 0.95, min 0.93, guards | 14 / 36 | **0 / 38** | 6.9 / 10.3 ms | +5.1 / +5.2 ms |
| With the cache `query_prefix`, 0.95 / 0.93 | 14 / 36 | **0 / 38** | 7.3 / 12.3 ms | +5.3 / +5.5 ms |
| With the cache `query_prefix`, 0.91 / 0.91 | **24 / 36 (67%)** | **0 / 38** | 6.5 / 6.9 ms | not measured (same embedding cost) |

A miss to the real model took 2.61 s p50 in every configuration. One more paraphrase probe per run was an exact (T1) hit, because its text is also a seed.

- **The three false hits of the first run are gone** ("Spanish" vs "Italian", "USD to EUR" vs "EUR to USD", "briefly" vs "in detail"), and no new one appeared.
- **The guards cost three paraphrases that hit before** (same thresholds, same embedder): "What's Germany's VAT rate?" (possessive against "Germany"), "Who has to approve expense reports above 5000 EUR?" ("above" against "over") and "In JavaScript, how can I format a date as YYYY-MM-DD?" (the format string). One new one hits. These look like guard false positives on possessives, synonymous comparatives and format tokens; the per-request guard verdict is not logged, so this is inferred from the pairs.
- **The prefix only pays off with a lower threshold.** At 0.95 it changes which paraphrases hit but not how many. At 0.91 it hits 67% of paraphrases with no false hit on this adversarial set: fewer hits than the offline prediction (81% at 5% false hits, made without the new guards), and no false hit.

**Intent kNN through the gateway** (core `knn_eval`, leave-one-out on the built-in 210 exemplars, k = 5, through Caliban's `/v1/embeddings`):

| Configuration | Top-1 | Accepted precision | Abstain (0.5) | code | extraction | reasoning | chat | others |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `query_prefix`, T = 0.1 (the shipped block) | **0.952** | 0.957 | 0.014 | 0.867 | 0.900 | 0.933 | 0.967 | 1.000 |
| Raw text, T = 0.05 | 0.838 | 0.881 | 0.076 | 0.567 | 0.900 | 0.800 | 0.767 | 0.97 to 0.90 |

Out-of-scope top-1 similarity with the prefix: p50 0.658, p90 0.728, max 0.779 (10 examples), as in the first run.

## 3. Cache-hit billing for `caliban/auto`

`scripts/bill.py`: a fresh tenant (semantic cache on, PII off, `auto_cache_hit_fraction` at the deployment default 0.2, flat price 3 / 12 USD per million tokens) sends through `caliban/auto`: "Explain what a mutex is." (miss, 19 prompt and 48 completion tokens), the same request again (T1 hit, 1.4 ms) and "Can you explain what a mutex is?" (T2 hit, 11.7 ms). Then `GET /api/v1/usage?tenant_id=...`.

| Event | `cost_usd`, `routed_model_cost_usd` | tokens metered | `flat_price_usd` | `billed_usd` | `saved_usd` | `x-caliban-cost-usd` |
|---|---:|---:|---:|---:|---:|---:|
| miss | 0 (the on-prem model's price is 0) | 19 + 48 | 0.000633 | 0.000633 | absent | 0 |
| exact hit | 0 | 0 + 0 | 0.000633 | 0.0001266 (20%) | 0.0005064 | 0 |
| semantic hit | 0 | 0 + 0 | 0.000633 | 0.0001266 (20%) | 0.0005064 | 0 |

Totals: `auto_requests` 3, `auto_cache_hits` 2, `semantic_cache_hits` 1, `flat_price_usd` 0.001899, `billed_usd` 0.0008862 (= flat x 1.4), `auto_saved_usd` = `saved_usd` = 0.0010128, `routed_model_cost_usd` 0, `margin_usd` 0.0008862. All 27 checks pass. Two observations: an exact hit through `caliban/auto` still pays for the routing decision (classification runs before the cache lookup), and with an on-prem model priced at 0 the margin equals the billed amount.

## 4. Single sign-on with a real identity provider

Dex v2.43.1 on the gateway host (`scripts/sso_dex_testbed.sh`), with two connectors: `mock` (user "Kilgore Trout", group `authors`, mapped to owner with `CALIBAN_OIDC_OWNER_GROUPS`) and the password DB (viewer@example.com, no groups). The compose stack's `CALIBAN_OIDC_*` settings, plain http inside the VPC (the control plane warns that the issuer and cookies are not secure, as it should). `scripts/sso_e2e.py` from the loadgen, a cookie jar per user, the full authorization-code flow through Dex:

| Check | Result |
|---|---|
| `/auth/config` reports SSO; owner login through the IdP ends in a session; role `owner` from the group | pass |
| Write without `X-CSRF-Token`: 403; with it: 201; with a foreign `Origin`: 403 | pass |
| Second user logs in with no role; refused a tenant read (403) | pass |
| Owner binds the user as `viewer` on one tenant through `POST /api/v1/role-bindings`; effective on the next request | pass |
| Viewer reads the tenant's routes (200); refused `PUT` routes, minting an API key, the audit log and another tenant (403) | pass |
| Logout for both (200), session gone afterwards (401) | pass |
| Audit: both logins with the `email <issuer#subject>` actor, logouts, `role_binding.create`, `tenant.create` by the SSO user, `auth.break_glass` for the token used to read it; hash chain verified | pass |

**Console UI**: `scripts/ui_login.py` in the official Playwright container on the loadgen (headless Chromium): open the console, click "Sign in with SSO", pick the Dex connector, land back on the console signed in. `/auth/me` from the browser context shows a session for Kilgore Trout with the owner role, and the console shows the user and the role badge. One cosmetic issue: the Overview "Cost" tile renders `-$0.00` on a fresh control plane.

## 5. Split mode

Gateway (control plane plus its own router, compose) and two `caliban router` hosts polling it (`CALIBAN_SNAPSHOT_POLL_SECS` default 10 s), all on the gateway's Valkey (`[limits] store = "valkey"`, the compose default). Mock upstreams on the loadgen. `scripts/split.py`:

| Check | Result |
|---|---|
| Signed snapshots | Both routers verified and served the control plane's version (`cp-41` at start); Valkey quota store `ok` on all three nodes |
| Shared quota | Tenant limit `requests_per_minute = 20` (`[limits.tenants.<id>]`); 40 requests alternating between the routers in 0.06 s: **exactly 20 allowed** (10 per router), 20 got 429 |
| `Idempotency-Key` across routers | Router A answers, router B replays it (`Idempotent-Replayed: true`, same `x-caliban-request-id`, identical body); different body with the same key on B: **422** `idempotency_key_reused`; same key on B while A still waits on a 2 s upstream: **409** `idempotency_key_in_use`, `Retry-After: 1`; after A completes, B replays (1.5 ms) |
| BYOK through routers | A tenant provider key (sealed under the tenant DEK) is opened by the gateway and both routers; the upstream received the right credential |
| Fail-static | Control plane stopped: both routers keep serving (200). Router restarted while it is down: loads `snapshot.json` from its cache (`loaded cached snapshot ... version=cp-47`), warns, serves |
| Recovery and propagation | Control plane started again; a newly minted API key works on the routers after **2.8 and 3.1 s** |
| KEK rotation (README procedure) | New KEK plus `CALIBAN_KEK_PREVIOUS` on both routers, then the control plane: BYOK works everywhere. `caliban keys rotate`: both tenant DEKs re-wrapped (`tenant_keys_rewrapped`), `keys status` then shows `previous_keks_still_needed: []`, `rotation_complete: true`. `CALIBAN_KEK_PREVIOUS` removed on the routers, then the control plane: BYOK still works on all three nodes. Idempotency and quotas unaffected |

For the rotation the new KEK was derived on each host from the old one (HMAC-SHA256 with a fixed label), so no key material moved between hosts; that is a shortcut for a test, not a way to generate production keys (`caliban gen-kek`).

One gap for operators: the snapshot version label did not change after `keys rotate` (`cp-49` before and after), yet the routers already received the re-wrapped envelopes (they opened BYOK keys with only the new KEK). Step 3 of the README ("wait until every router has polled the new snapshot") therefore cannot be checked by version today.

## 6. Streaming overhead with the new defaults (CPU only)

The first run's cross-host `caliban-bench` run, unchanged, with **no `CALIBAN_TCP_NODELAY` in the environment**: load generator on the loadgen, mock and gateway on the gateway host (the compose stack idle next to it), 4000 measured requests per side per row. Overhead p50 in milliseconds; the first run's `TCP_NODELAY=1` numbers in brackets.

| Scenario | c = 1 | c = 16 | c = 64 | c = 64 p99 | Gateway req/s at c = 64 |
|---|---:|---:|---:|---:|---:|
| chat | 0.067 (0.083) | 0.111 (0.092) | 0.482 (0.470) | 0.883 (0.937) | 64989 |
| chat + PII | 0.114 (0.097) | 0.189 (0.177) | 0.900 (0.880) | 1.442 (1.474) | 45649 |
| stream | 0.701 (0.672) | 0.555 (0.551) | **3.394 (3.450)** | 8.960 (8.599) | 13285 |
| stream + PII | 0.785 (0.738) | 0.721 (0.710) | **3.980 (4.332)** | 7.639 (10.729) | 11563 |
| stream TTFB | **0.102 (0.334)** | 0.317 (0.354) | 0.744 (0.787) | | |
| stream + PII TTFB | **0.145 (0.398)** | 0.457 (0.470) | 1.015 (1.037) | | |
| cache hit | 0.017 (0.025) | 0.019 (0.031) | 0.052 (0.050) | | 121881 |
| Anthropic native | 0.073 (0.077) | 0.112 (0.134) | 0.623 (0.600) | | 56396 |
| usage WAL | 0.078 (0.104) | 0.136 (0.138) | 0.581 (0.622) | | 59873 |
| paced (1 ms) TTFB | 0.137 (0.102) | 0.199 (-0.035) | 0.487 (0.543) | | |

The chat c = 64 row is from a rerun: the first pass had one 52 ms p99 and half the throughput (32198 req/s), which did not repeat (0.88 ms p99, 64989 req/s).

**Paced at 20 ms per chunk** (TTFB overhead p50 / p99, ms):

| Setting | c = 1 | c = 16 | c = 64 | c = 1 with PII | c = 16 with PII | c = 64 with PII |
|---|---:|---:|---:|---:|---:|---:|
| default (no env var) | **0.20** / 0.25 | 0.18 / 0.15 | 0.97 / 1.03 | 0.25 / 0.28 | 0.25 / 0.03 | 0.87 / 1.05 |
| `CALIBAN_TCP_NODELAY=0` | **0.21** / 0.31 | 0.31 / 0.03 | | 0.30 / 0.54 | 0.48 / 0.28 | |
| first run, Nagle on | 23.79 / 33.37 | 23.95 / 31.36 | 1.98 / 37.80 | 23.64 / 29.18 | 24.13 / 28.34 | 2.28 / 29.13 |

- The Nagle stall is gone with the default, and also with `TCP_NODELAY` turned off: the headers now leave in the same write as the first frame, so there is no small segment waiting for a delayed ACK.
- Unpaced streams at c = 64 are where they were (3.39 ms p50, CPU-bound on 8 vCPU shared with the mock). The 3 ms target still holds for every paced row and every non-streaming row.
- With the bench's fixed-length mock replies, paced PII totals are now comparable: 0 to 3 ms over 1.37 s streams at 20 ms pacing (the first run: +84 to 108 ms, a bench artifact).

## 7. NER on x86 against Graviton

Same method as the first run: `caliban-bench --only ner` on one host, built and run in a `rust:1-trixie` container (`--features ner`), `nym-pii-multilingual-small-int8` 3.0.0, 1000 requests per side. Overhead p50 in ms, gateway requests per second in brackets.

| Host and NER setting | c = 1 | c = 16 | c = 64 | PII-off chat beside NER, c = 64 p50 / p99 |
|---|---:|---:|---:|---:|
| c8g.2xlarge (Graviton4), default 4 sessions x 1 thread (first run) | 77.0 (13) | 385.0 (41) | 1537.8 (41) | 1.05 / 43.57 |
| **c7i.2xlarge (Sapphire Rapids), default 4 x 1** | **42.9 (23)** | 165.8 (96) | 665.4 (96) | 1.78 / 2.90 |
| c7i.2xlarge, `CALIBAN_PII_NER_THREADS=2` (4 x 2) | **29.7 (33)** | 154.3 (103) | 611.5 (103) | 1.66 / -1.44 |
| c7i.2xlarge, `CALIBAN_PII_NER_SESSIONS=2`, `THREADS=2` | 29.0 (34) | 221.9 (71) | 897.2 (71) | 1.45 / 2.49 |
| M5 laptop, default (RESULTS.md) | 12.0 (82) | 119.1 (127) | 475.5 (133) | |

Streamed NER rows (TTFB) match the chat rows within 2 ms.

- **x86 with VNNI is 1.8 times faster per inference and 2.3 times higher in throughput than Graviton4** with the same build and model. The first run's suspicion (the prebuilt ONNX Runtime lacks fast int8 kernels on aarch64) fits, but this run did not profile it.
- **2 intra-op threads per session help latency at low concurrency** (43 to 30 ms) and slightly raise throughput (96 to 103 req/s), at the price of using all 8 cores at c >= 16. With the default's core budget (2 sessions x 2 threads) throughput drops to 71 req/s: sessions matter more than threads once requests queue.
- Isolation from non-NER traffic holds on x86 (PII-off chat at c = 64: 1.4 to 1.8 ms p50 while NER saturates the pool, on the same host as the load generator and the mock).

## 8. Zero-egress install

Phase 2 put the gateway (c7i.2xlarge, `image_source = "s3"` forced by the isolated tier) in the isolated subnet: no internet gateway route, no NAT, only the S3 gateway endpoint and the three SSM interface endpoints, with VPC Flow Logs on. The amd64 bundle was built on the connected x86 loadgen (`images/build.sh`, then `airgap/bundle.sh --profile none --platform linux/amd64 --sign minisign`, 846 MB) with a fresh minisign key; only the public key went into the testbed (`bundle_pubkey`).

| Step | Result |
|---|---|
| Docker from the Amazon Linux 2023 repository through the S3 endpoint | **Failed, then fixed**: the endpoint policy required `aws:PrincipalAccount`, but dnf reads that bucket anonymously, so every package download got 403. See [Testbed and deploy fixes](#testbed-and-deploy-fixes) |
| Bundle download, checksum and minisign signature (`load.sh`) | **Failed, then fixed**: `load.sh` aborted with exit 141 (SIGPIPE). Then: checksum OK, "Signature and comment signature verified", images loaded, stack up in 38 s |
| `scripts/smoke.sh` with `MINT_KEY=1` | 7 of 7 after removing its `/metrics` check (no such endpoint in core) |
| Chat completions from the loadgen through the isolated gateway to a model server in the VPC | 200 for a pinned model and for `caliban/auto` |
| Egress from the host: `https://example.com`, `http://1.1.1.1`, Hugging Face, ghcr.io, S3 in eu-west-1, STS | all time out |
| Egress from inside the Caliban container (`nsenter`): example.com, 1.1.1.1 | both time out |
| Listing an AWS-owned bucket through the endpoint | denied; the testbed bucket readable (expected) |
| DNS | still resolves public names (documented limit; needs Route 53 Resolver DNS Firewall) |

**Flow logs**, isolated subnet, from the gateway's first boot to the end of the tests (45 min window; CloudWatch Logs Insights):

| Direction, action, path | Flows | Bytes |
|---|---:|---:|
| egress to outside the VPC, ACCEPT, path 7 (S3 gateway endpoint) | 105 | 3.8 MB |
| egress to outside the VPC, any other path or action | **0** | |
| egress inside the VPC, ACCEPT, path 1 | 85 | 0.4 MB |
| ingress, ACCEPT (S3 responses: bundle and packages, and requests from the loadgen) | 193 | 1.93 GB |

No record has path 8 (internet gateway). The blocked attempts left no `REJECT` records: the hosts security group denies them before they become flows, so the evidence is the absence of any non-endpoint egress, plus the failed attempts above.

## Testbed and deploy fixes

Found by this run and fixed on the deploy branch `aws-2026-10b-fixes` (documented in the testbed README):

- **`airgap/load.sh` aborted on every large bundle, and its path-traversal check could be bypassed.** It ran `tar -tf | head -1` and `tar -tf | grep -q` under `pipefail`; with a listing larger than the pipe buffer, the reader exits early and tar dies of SIGPIPE (exit 141). Reproduced with GNU tar 1.34: the layout check aborts the install, and a bundle with a `../` member passes the traversal check because the pipeline "fails". GNU tar strips `../` on extraction by default, so this defeated a defence-in-depth check rather than enabling a write outside the directory. Now the listing goes to a file first. This affects customer air-gapped installs, not only the testbed.
- **The S3 endpoint policy blocked the Amazon Linux repository and SSM Agent buckets** for anonymous reads (`aws:PrincipalAccount` condition), so isolated hosts could not install Docker. That statement now allows `s3:GetObject` on exactly those AWS-owned buckets without the condition (read-only, cannot carry data out); the testbed bucket statement keeps it.
- **Adding or removing any host replaced every other host.** Each host's user data carried the enabled peers' addresses, the router list and the bundle public key, with `user_data_replace_on_change`. Hosts now get the planned peer addresses whether or not the peer is enabled, no router list, and the public key only when they load a bundle. Verified live: adding the isolated gateway left the running loadgen untouched. Two `tofu test` cases cover it, and a precondition rejects routers without the gateway. Toggling the GPU still replaces the gateway, whose model URLs depend on it.
- **Routers pointed at Qdrant's gRPC port** (6334); Caliban speaks REST (6333) and warned about it.
- **`scripts/smoke.sh` always failed** on a `/metrics` check (core has no metrics endpoint yet), and its hint pointed at API key hashes in the config file, which Postgres ignores after the first start.
- `loadgen.sh` had the same SIGPIPE pattern (`cargo metadata | grep -q`).
- README: the flow-log query failed (`sum(bytes) as bytes`), it predicted `REJECT` rows that do not appear, the Valkey quota store is on main now, plus runbooks for the KEK rotation on routers, single sign-on with Dex, uploading bundles from the bucket's `results/` prefix, and the vLLM start-order issue below.

## Caveats

- One run, one day, one AZ, spot hosts (same hardware as on-demand). Per-round differences at c = 8 and 32 vary by tens of milliseconds; only c = 1 is paired.
- **vLLM start order**: at first start the 27B model profiled its memory while the reranker was still starting and got 1.21 GiB of KV cache, not enough for one 131072-token sequence, and crash-looped. The restart used `QWEN3_LARGE_MAX_MODEL_LEN=32768` after the other two models had loaded, and got 5.15 GiB. Same model revision (`017b9c7`), image and driver as the first run, which started with the defaults. Both factors changed at once, so which one mattered is not established. The prompts here are short, so the lower limit does not affect any number above.
- The unique ticket number on every prompt lowers the classifier's confidence (40% abstained at c = 1 against 16% for the plain prompts); it does not change the Stage-1 timing, which is embed plus classify whatever the outcome.
- Stage-1 timings come from the debug route log, matched to requests by order; the warm-up requests (repeated prompts) are excluded by position.
- The semantic-cache pairs are adversarial and hand-written; the guard verdict per request is not logged, so which guard blocked a paraphrase is inferred.
- The NER rows ran with the load generator and the mock on the same 8 vCPUs, as in the first run, and alongside the zero-egress tests on another host (light traffic to the same loadgen).
- In split mode the routers' usage events stay on the routers (usage shipping is not implemented), so the shared-quota test is the cross-router check; `/api/v1/usage` was checked in standalone mode only.

## Recommendations

1. **Give Stage 1 headroom when the embedder shares the GPU.** On one L40S with the chat model, 8 concurrent classifications take 24 ms and at 32 most requests fall back to keyword rules. Options: raise `budget_ms` (35 to 40 ms would likely keep most c = 8 requests on the kNN, since 8 concurrent embeddings took 24 to 28 ms at p99, at a cost the user hardly sees next to a 0.5 to 5 s TTFT), run the embeddings pool on its own GPU or MIG slice for `caliban/auto` deployments, or batch concurrent classifications in the gateway. Report the fallback rate (`x-caliban-intent ... knn=timeout`) as a metric.
2. **Ship the cache `query_prefix` with threshold 0.91** (and `min_threshold = 0.91`) for Qwen3-Embedding-0.6B: 67% of paraphrases hit with no false hit on this set, against 39% at the current defaults. Re-check on real traffic before making it the default.
3. **Loosen three guards**: possessives ("Germany's" = "Germany"), synonymous comparatives ("over" = "above") and format tokens such as "YYYY-MM-DD" cost paraphrase hits here without stopping any near-miss. Log the guard verdict at debug level so the next run can attribute misses.
4. **NER on x86 for NER-heavy tenants** (1.8 times faster per inference than Graviton4), and consider `CALIBAN_PII_NER_THREADS=2` as the default when cores allow: 30 ms instead of 43 ms at low concurrency.
5. **Expose the KEK id behind the snapshot** (or bump the snapshot version on `keys rotate`), so operators can confirm step 3 of the rotation procedure on every router before removing `CALIBAN_KEK_PREVIOUS`.
6. **vLLM on the 48 GB tier**: start the large model after the embedder and reranker are healthy (compose `depends_on: condition: service_healthy`), or lower `QWEN3_LARGE_MAX_MODEL_LEN` there; then re-check which of the two the first start needed.
7. Fix the console's `-$0.00` cost tile (web).

## Cost

Spot prices in eu-central-1a on 2026-10-10 (from the spot price history), instance time from launch to stop or termination:

| Item | Hours | Price | Cost |
|---|---:|---:|---:|
| gpu g6e.xlarge (10:38 to 12:23 UTC, then stopped) | 1.75 | $1.7704/h | $3.10 |
| gateway c8g.2xlarge (phase 1) | 2.13 | $0.2023/h | $0.43 |
| loadgen c8g.2xlarge (phase 1) | 2.13 | $0.2023/h | $0.43 |
| 2 routers c8g.xlarge (12:24 to 12:35, then stopped) | 2 x 0.19 | $0.1045/h | $0.04 |
| loadgen c7i.2xlarge (phase 2) | 0.51 | $0.2151/h | $0.11 |
| gateway c7i.2xlarge, isolated (phase 2) | 0.26 | $0.2151/h | $0.06 |
| gp3 volumes (about 670 GB-hours) | | $0.0952/GB-month | $0.09 |
| public IPv4 (about 7 address-hours) | | $0.005/h | $0.04 |
| SSM interface endpoints (3 x 0.3 h) | | $0.012/h | $0.01 |
| VPC Flow Logs, S3, CloudWatch Logs Insights, EventBridge Scheduler, IAM, VPC | | | about $0.01 |
| **Total** | | | **about $4.30** |

The GPU was 72% of it. Running the CPU hosts on spot saved about $0.90 against on-demand.

## Reproduce

Testbed: `deploy/aws/testbed` on branch `aws-2026-10b-fixes`, phase 1 with `gpu_enabled = true`, `cpu_use_spot = true`, `results_upload = true` (routers added later with `router_count = 2`); phase 2 with `cpu_arch = "x86_64"`, `role_network_mode = { gateway = "isolated" }`, `enable_flow_logs = true` and `bundle_pubkey`. On the loadgen, with the scripts from `bench/scripts/`:

```sh
# 1. caliban/auto vs pinned vs direct (tenant routes every intent to the model; PII and semantic cache off)
python3 tb_admin.py tenant --admin "$ADMIN" --name auto-bench --sem off > auto_tenant.json
python3 auto_bench.py run --direct http://$GPU_IP:8000,Qwen/Qwen3.8-27B-FP8 --gateway http://$GATEWAY_IP:8080 \
  --key "$KEY" --concurrency 1,8,32 --pairs 40 --requests 96 --rounds 2 --max-tokens 64 --unique --label idleu --out s1-idleu.json
python3 auto_bench.py bg --url http://$GPU_IP:8000,Qwen/Qwen3.8-27B-FP8 --streams 8 --max-tokens 512 &   # GPU busy
# gateway host: docker logs caliban-caliban-1 | sed 's/\x1b\[[0-9;]*m//g' | grep "route decision" | gzip > idleu.route.log.gz
python3 s1_analyze.py <dir with s1-idleu.json and idleu.route.log.gz> idleu

# 2. semantic cache, misses, kNN through the gateway
python3 semcache_e2e.py setup --admin "$ADMIN" --suffix g1 > keys-g1.json
python3 semcache_e2e.py hits --keys keys-g1.json --out hits-g1.json
python3 semcache_e2e.py misslat --keys keys-g1.json --n 300 --out misslat-g1.json
CALIBAN_KNN_EVAL_URL=http://$GATEWAY_IP:8080/v1 CALIBAN_KNN_EVAL_MODEL=local/qwen3-embedding-0.6b CALIBAN_KNN_EVAL_API_KEY=$KEY \
CALIBAN_KNN_EVAL_PREFIX=$'Instruct: Given a user request, identify the type of task it asks for\nQuery: ' \
CALIBAN_KNN_EVAL_TEMPERATURE=0.1 cargo test --release -p caliban-route --test knn_eval -- --nocapture

# 3. billing; 4. SSO (sso_dex_testbed.sh on the gateway first); 5. split mode
python3 bill.py --admin "$ADMIN"
python3 sso_e2e.py --cp http://$GATEWAY_IP:8081 --admin "$ADMIN"
python3 split.py setup --admin "$ADMIN" > split.json && python3 split.py quota && python3 split.py idem && python3 split.py byok

# 6. streaming: as in RESULTS-aws-2026-10.md, without CALIBAN_TCP_NODELAY in the serve environment
```
