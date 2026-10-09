# AWS measurement results, October 2026

The first run of the deploy repo's AWS testbed (`deploy/aws/testbed`), on 2026-10-09: (a) the gateway overhead benchmark on Linux, and (c) the GPU open-model tier (chat model, embedder and reranker on one 48 GB GPU) with the gateway in front of it. The Mac results in [`RESULTS.md`](RESULTS.md) are unchanged; this file adds Linux and real-model numbers next to them.

## Verdict

| Question | Answer |
|---|---|
| Unpaced streaming p50 overhead at c=64 under 3 ms on Linux? | **No.** Load generator on another host, with `CALIBAN_TCP_NODELAY=1`: **3.45 ms** (PII off) and **4.33 ms** (PII on). On one host: 3.96 and 4.78 ms (the Mac: 3.16 and 3.40). Across hosts, every non-streaming path stays under 1 ms p50 at c=64 (worst: chat + PII, 0.88 ms; 1.16 ms on one host), and time to first byte stays under 1.1 ms at every level. |
| `CALIBAN_TCP_NODELAY` on Linux | **Turn it on.** With Nagle on (the default), a stream's first SSE frame waits for the client's delayed ACK. Across hosts the first token of a stream paced at 20 ms per chunk (a real model's rate) arrives **24 ms late** at c=1 and c=16 (p99 +29 to 38 ms); with it on, +0.07 to 0.25 ms. On one host every stream took about **50 ms** longer. The Mac result (Nagle helps) does not carry over to Linux. |
| Gateway overhead with a real model | **Within noise.** Qwen3.8-27B-FP8 on vLLM: TTFT p50 86.3 ms through Caliban against 85.9 ms direct at c=1; identical inter-token latency (40.24 ms) and throughput (25, 171 and 365 output tokens/s at c=1, 8 and 32). |
| Embedding latency (Qwen3-Embedding-0.6B on the L40S) | **4.8 ms p50** through Caliban (4.3 ms direct; 275 ms on CPU before). A semantic-cache miss adds **5.1 ms** p50 (budget: 50 ms). |
| Intent kNN accuracy (leave-one-out, built-in set) | **0.838** top-1 as configured today (raw text, T = 0.05). **0.948** with a Qwen3 query instruction (`[routing] query_prefix`) and T = 0.1. |
| Semantic cache thresholds for Qwen3-Embedding-0.6B | Keep `threshold = 0.95`, raise **`min_threshold` to 0.93**. End to end at 0.95: 16 of 36 paraphrases hit (44%), 3 of 38 near-misses hit (8%). The numeric-slot guard blocked every near-miss that differed only in a number. No threshold separates the remaining near-misses (swapped direction, language or modifier). |

## Setup

- **Region and placement**: eu-central-1, one AZ (eu-central-1a), one public subnet; hosts talk over private IPs in the same subnet. Access through SSM only.
- **Gateway host and load generator**: 2 × c8g.2xlarge (AWS Graviton4, 8 vCPU, 16 GiB), on-demand. AMI `al2023-ami-2023.12.20260930.0-kernel-6.18-arm64` (kernel 6.18.51). rustc 1.99.0.
- **GPU host**: g6e.xlarge (1 × NVIDIA L40S 46 GB usable, 4 vCPU, 32 GiB), spot at $1.744/h. AMI "Deep Learning Base OSS Nvidia Driver GPU AMI (Ubuntu 24.04) 20261006", driver 595.91.07, CUDA 13.2. 150 GB gp3.
- **Caliban**: core `f173d17` (main) plus the bench changes committed with this file; web `d8d39e4`; deploy `4717d44` with the fixes listed under [Testbed fixes](#testbed-fixes). The gateway host ran the compose stack (Caliban image `caliban/caliban:0.1.0` built on the host, Postgres 17.11, Valkey 9.1.2, Qdrant 1.19.1).
- **Model servers** (compose profiles `qwen3-large embeddings reranker`, deploy `docker-compose.yml`):
  - chat: `Qwen/Qwen3.8-27B-FP8` (HF `main`, `017b9c7`), vLLM 0.30.0 (`vllm/vllm-openai:v0.30.0`), max-model-len 131072, fp8 KV cache, `--gpu-memory-utilization=0.82`, `--max-num-seqs=32` (see [Testbed fixes](#testbed-fixes));
  - embeddings: `Qwen/Qwen3-Embedding-0.6B` (`97b0c61`), TEI 1.9.4 (`text-embeddings-inference:cuda-1.9.4`, sha256 `c831a5ce…`), float16;
  - reranker: `Qwen/Qwen3-Reranker-0.6B` (`e61197e`), vLLM 0.30.0 pooling runner, 0.10 of the GPU.
  - All three served; GPU memory in use 42.7 GB of 46 GB.
- **PII NER**: `nym-pii-multilingual-small-int8` 3.0.0 (fetched with ml's `scripts/fetch_pii_ner.py`; licence review still pending, used for development only, as on the Mac).
- **Model substitutions: none.** Every model id in `models.lock.yaml` and the compose file exists on Hugging Face under Apache-2.0 (the NER model: MIT) and loaded once the vLLM settings were fixed.

## Method

### (a) Gateway overhead

The `caliban-bench` suite from `bench/` (method in [`RESULTS.md`](RESULTS.md#method)): mock upstream, real `caliban standalone` release binary with an in-memory store, closed-loop load generator, overhead = gateway latency minus direct-to-mock latency at the same quantile. 4000 measured requests per side per row (600 for paced streams) in 2 interleaved rounds after 400 warm-up; the Nagle-on runs used 1000 (300 paced) to keep the 50 ms stalls affordable.

`caliban-bench` only ran on one host before. This run adds a serve/remote split (`--serve` starts the mocks and gateways and writes their URLs and keys; `--remote` measures them from another host) and fixed ports (`--mock-ports`, `--gateway-ports`), because the testbed's security group admits only fixed service ports. Topologies:

- **Across hosts**: load generator on the loadgen host; mock and gateway on the gateway host. The gateway calls the mock over loopback; the load generator reaches both over the VPC, so the direct and gateway paths cross the same link.
- **One host**: mock, gateway and load generator on the gateway host (loopback), as on the Mac.
- **Paced at 20 ms**: a separate serve with `--paced-chunk-delay-ms 20` (a token every 20 ms, inside the 10 to 50 ms range of real models), `stream-paced` scenarios only, 40 requests per side at c=1 and 256 at c=16 and 64.

Each topology ran with `CALIBAN_TCP_NODELAY=1` and with it unset.

### (c) GPU tier

- **Real-model throughput**: a stdlib Python streaming client on the loadgen (keep-alive HTTP/1.1, one connection per worker) against vLLM directly and against Caliban (`local/qwen3.8-27b`, a tenant with PII off). 18 realistic prompts (questions, an email, SQL, code review, extraction, two documents of about 400 tokens), `max_tokens` 128 with `ignore_eos` so every reply is 128 tokens, `temperature` 0.7, thinking off. Warm-up: every prompt once per side (fills each side's prefix cache; Caliban adds a per-tenant `cache_salt`, so the two sides do not share it). Then c = 1, 8 and 32, 2 interleaved rounds per level, 16, 32 and 128 requests per side. TTFT is the time to the first content token.
- **Embedding latency**: single short queries, unique per request, 400 per side, c = 1 and 8, TEI directly and Caliban's `/v1/embeddings`.
- **Intent kNN**: core's `knn_eval` test (`cargo test -p caliban-route --test knn_eval`) against TEI directly and through Caliban, plus a Python replica of `knn.rs` (same results to three decimals) to sweep the temperature, the abstain threshold and the OOS gate.
- **Semantic cache thresholds**: 36 paraphrase pairs (should hit) and 38 near-miss pairs (must not hit: different numbers, entities, direction, polarity or intent), embedded raw (the cache embeds the last user message with no instruction), cosine similarity per pair.
- **Semantic cache end to end**: `[cache.semantic]` enabled on the gateway (Qdrant from the compose stack, `embedding_model = "local/qwen3-embedding-0.6b"`, defaults otherwise: threshold 0.95, min 0.90, grey band 0.03, verify rate 0.05). A tenant with `semantic_cache = "on"` sent the first prompt of every pair (temperature 0, 64 tokens, Qwen3.8-27B), then the second; `x-caliban-cache-tier: semantic` counts as a hit. The added latency of a miss was measured against a mock upstream on the loadgen: 300 unique prompts, alternating between that tenant and one with the semantic cache off.

## (a) Gateway overhead on Linux

### Across hosts

Milliseconds. The main columns are with `CALIBAN_TCP_NODELAY=1`; the last three are the same rows with it unset (Nagle on). Paced rows count by time to first byte only (as on the Mac).

| Scenario | Conc. | Direct p50 | Gateway p50 | Overhead p50 | p90 | p99 | TTFB overhead p50 | TTFB p99 | Gateway req/s | Nagle on: overhead p50 | Nagle on: p99 | Nagle on: TTFB p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| chat (PII off) | 1 | 0.355 | 0.438 | **0.083** | 0.088 | 0.141 |  |  | 2271 | 0.085 | 0.072 |  |
|  | 16 | 0.413 | 0.505 | **0.092** | 0.043 | 0.053 |  |  | 30807 | 0.129 | 0.250 |  |
|  | 64 | 0.438 | 0.908 | **0.470** | 0.690 | 0.937 |  |  | 65806 | 0.515 | 0.916 |  |
| chat + PII (regex, reversible) | 1 | 0.357 | 0.454 | **0.097** | 0.102 | 0.106 |  |  | 2198 | 0.121 | 0.134 |  |
|  | 16 | 0.401 | 0.578 | **0.177** | 0.171 | 0.263 |  |  | 26663 | 0.203 | 0.338 |  |
|  | 64 | 0.432 | 1.312 | **0.880** | 1.191 | 1.474 |  |  | 46693 | 0.872 | 1.431 |  |
| stream (PII off) | 1 | 0.646 | 1.318 | **0.672** | 0.588 | 0.605 | 0.334 | 0.410 | 749 | 0.747 | 49.428 | 0.244 |
|  | 16 | 0.694 | 1.245 | **0.551** | 0.803 | 1.265 | 0.354 | 0.838 | 12107 | 0.755 | 49.367 | 0.293 |
|  | 64 | 0.933 | 4.383 | **3.450** | 6.429 | 8.599 | 0.787 | 2.442 | 13309 | 0.980 | 56.605 | 0.433 |
| stream + PII | 1 | 0.659 | 1.398 | **0.738** | 0.791 | 0.903 | 0.398 | 0.586 | 698 | 0.817 | 49.170 | 0.311 |
|  | 16 | 0.703 | 1.413 | **0.710** | 1.035 | 1.448 | 0.470 | 1.082 | 10637 | 0.864 | 59.129 | 0.381 |
|  | 64 | 0.928 | 5.259 | **4.332** | 8.083 | 10.729 | 1.037 | 3.410 | 11009 | 0.943 | 57.615 | 0.449 |
| cache hit | 1 | 0.358 | 0.382 | **0.025** | 0.026 | 0.029 |  |  | 2609 | 0.017 | 0.022 |  |
|  | 16 | 0.382 | 0.413 | **0.031** | -0.003 | -0.010 |  |  | 37053 | 0.023 | -0.014 |  |
|  | 64 | 0.439 | 0.488 | **0.050** | 0.048 | 0.090 |  |  | 121304 | 0.045 | 0.182 |  |
| Anthropic native | 1 | 0.370 | 0.447 | **0.077** | 0.081 | 0.132 |  |  | 2229 | 0.100 | 0.107 |  |
|  | 16 | 0.397 | 0.530 | **0.134** | 0.136 | 0.163 |  |  | 29111 | 0.150 | 0.262 |  |
|  | 64 | 0.424 | 1.023 | **0.600** | 0.788 | 1.069 |  |  | 58951 | 0.604 | 1.077 |  |
| paced stream (1 ms), PII off | 1 | 134.152 | 134.480 |  |  |  | **0.102** | 0.125 | 7 |  |  | 43.481 |
|  | 16 | 134.742 | 135.660 |  |  |  | **-0.035** | 0.207 | 116 |  |  | 35.518 |
|  | 64 | 137.363 | 137.888 |  |  |  | **0.543** | 0.672 | 433 |  |  | 34.841 |
| paced stream (1 ms) + PII | 1 | 134.218 | 142.737 |  |  |  | **0.158** | 0.279 | 7 |  |  | 43.645 |
|  | 16 | 135.135 | 143.917 |  |  |  | **-0.018** | 0.309 | 110 |  |  | 35.867 |
|  | 64 | 136.315 | 145.228 |  |  |  | **0.520** | 1.362 | 411 |  |  | 34.761 |
| chat, usage WAL on | 1 | 0.346 | 0.450 | **0.104** | 0.113 | 0.121 |  |  | 2214 | 0.087 | 0.176 |  |
|  | 16 | 0.399 | 0.538 | **0.138** | 0.117 | 0.433 |  |  | 27803 | 0.141 | 0.160 |  |
|  | 64 | 0.456 | 1.077 | **0.622** | 0.862 | 34.318 |  |  | 38247 | 0.524 | 1.098 |  |

Reading it:

- **Streaming at c=64 is over budget with `TCP_NODELAY` on**: 3.45 ms p50 (PII off), 4.33 ms (PII on), p99 8.6 and 10.7 ms. The gateway host is CPU-bound here: it serves about 13,300 unpaced streams per second at c=64 (62 events each, about 820,000 SSE events per second) and also runs the mock on the same 8 vCPUs. This is the same stress case as on the Mac (every event of a stream arrives in one burst); real model pacing does not produce it (see the paced rows and [the real model](#c-gpu-tier)).
- **With Nagle on, the unpaced p50 looks better (0.98 ms) and is not**: p99 is 49 to 59 ms at every concurrency, and the closed loop only completes 4,330 streams per second at c=64 against 13,309 with `TCP_NODELAY` on. A fraction of streams stall for a delayed ACK. The paced rows show the same stall on the first frame: +35 to 44 ms.
- Time to first byte is at most 1.04 ms p50 everywhere with `TCP_NODELAY` on.
- The cache hit costs 25 to 50 µs end to end across hosts.
- `chat, usage WAL on` at c=64 had one p99 of 34 ms in this run (p90 0.86 ms; the Nagle-on run of the same row: p99 1.1 ms). It did not repeat and was not investigated further.
- The paced PII rows' totals are not comparable (see [Caveats](#caveats)); their TTFB is.

### Paced at 20 ms per chunk, across hosts

| `CALIBAN_TCP_NODELAY` | Scenario | Conc. | Direct TTFB p50 | Gateway TTFB p50 | TTFB overhead p50 | TTFB overhead p99 | Requests per side |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | paced stream, PII off | 1 | 21.61 | 21.76 | **0.15** | 0.21 | 40 |
| | | 16 | 21.86 | 21.94 | **0.08** | -0.05 | 256 |
| | | 64 | 22.32 | 22.38 | **0.07** | 0.85 | 256 |
| | paced stream + PII | 1 | 21.76 | 21.84 | **0.08** | 0.10 | 40 |
| | | 16 | 21.82 | 22.07 | **0.25** | 0.10 | 256 |
| | | 64 | 21.94 | 22.77 | **0.84** | 1.49 | 256 |
| unset (Nagle on) | paced stream, PII off | 1 | 21.63 | 45.42 | **23.79** | 33.37 | 40 |
| | | 16 | 21.89 | 45.84 | **23.95** | 31.36 | 256 |
| | | 64 | 21.58 | 23.56 | **1.98** | 37.80 | 256 |
| | paced stream + PII | 1 | 21.77 | 45.42 | **23.64** | 29.18 | 40 |
| | | 16 | 21.84 | 45.97 | **24.13** | 28.34 | 256 |
| | | 64 | 21.77 | 24.05 | **2.28** | 29.13 | 256 |

The gateway sends the response headers as soon as the upstream answers, and the first SSE frame about 20 ms later. With Nagle on, that frame waits until the client acknowledges the headers segment, and the client delays the ACK (Linux: 40 ms minimum), so the first token arrives about 45 ms after the request instead of 22 ms. Once the stream is flowing, the per-token pacing is not affected (the PII-off totals match direct to within 0 to 2 ms). The real model below did not show it because its first token came 86 ms after the request, after the delayed ACK had already fired. Prompts that are answered faster than about 40 ms (short prompts on a warm prefix cache, small models, semantic-cache hits replayed as streams) do pay it.

### One host (comparable to the Mac)

`CALIBAN_TCP_NODELAY=1`. Milliseconds; the Mac column is the latest p50 for the same row in [`RESULTS.md`](RESULTS.md) (after the stream passthrough and the WAL writer; TTFB for paced rows).

| Scenario | Conc. | Overhead p50 | p90 | p99 | TTFB overhead p50 | Gateway req/s | Mac p50 |
|---|---:|---:|---:|---:|---:|---:|---:|
| chat (PII off) | 1 | **0.077** | 0.087 | 0.159 |  | 8955 | 0.040 |
|  | 16 | **0.208** | 0.309 | 0.434 |  | 43009 | 0.146 |
|  | 64 | **0.729** | 0.903 | 1.139 |  | 54598 | 0.516 |
| chat + PII (regex, reversible) | 1 | **0.115** | 0.121 | 0.130 |  | 6812 | 0.065 |
|  | 16 | **0.313** | 0.431 | 0.601 |  | 34235 | 0.191 |
|  | 64 | **1.155** | 1.449 | 1.609 |  | 39816 | 0.749 |
| stream (PII off) | 1 | **0.189** | 0.212 | 0.252 | 0.088 | 2210 | 0.191 |
|  | 16 | **1.023** | 1.301 | 1.590 | 0.529 | 9267 | 0.612 |
|  | 64 | **3.958** | 5.374 | 5.210 | 1.631 | 10344 | 3.158 |
| stream + PII | 1 | **0.328** | 0.366 | 0.408 | 0.140 | 1681 | 0.246 |
|  | 16 | **1.215** | 1.502 | 1.422 | 0.652 | 8179 | 0.717 |
|  | 64 | **4.777** | 6.994 | 9.032 | 1.666 | 9058 | 3.404 |
| cache hit | 1 | **0.016** | 0.018 | 0.022 |  | 21082 | 0.005 |
|  | 16 | **0.038** | 0.189 | 0.244 |  | 76520 | 0.025 |
|  | 64 | **0.118** | 0.243 | 0.426 |  | 105566 | 0.108 |
| Anthropic native | 1 | **0.077** | 0.085 | 0.091 |  | 9059 | 0.050 |
|  | 16 | **0.238** | 0.342 | 0.518 |  | 39340 | 0.224 |
|  | 64 | **0.717** | 0.726 | 0.882 |  | 51729 | 0.574 |
| paced stream (1 ms), PII off | 1 |  |  |  | **0.119** | 7 | 0.567 |
|  | 16 |  |  |  | **0.184** | 116 | 0.121 |
|  | 64 |  |  |  | **0.506** | 430 | 0.551 |
| paced stream (1 ms) + PII | 1 |  |  |  | **0.195** | 7 | 0.453 |
|  | 16 |  |  |  | **0.227** | 110 | 0.043 |
|  | 64 |  |  |  | **0.743** | 405 | 0.295 |
| chat, usage WAL on | 1 | **0.089** | 0.095 | 0.135 |  | 8309 | 0.129 |
|  | 16 | **0.230** | 0.334 | 0.432 |  | 41024 | 0.224 |
|  | 64 | **0.776** | 0.963 | 1.271 |  | 53380 | 0.788 |

On one host, 8 Graviton4 vCPUs are 20 to 40% slower per request than the Mac's 10 cores at c=16 and 64 (load generator, gateway and mock compete for the same cores), and about the same at c=1. Linux timers are precise: a paced stream takes 134 ms on both sides (62 sleeps of about 2.1 ms), so the paced TTFB rows are stable.

The same suite on one host with `TCP_NODELAY` **unset**, stream rows (1000 requests per side):

| Scenario | Conc. | Overhead p50 | p99 | TTFB overhead p50 | TTFB p99 | Gateway req/s |
|---|---:|---:|---:|---:|---:|---:|
| stream (PII off) | 1 | 49.765 | 59.777 | 0.303 | 0.622 | 21 |
| | 16 | 49.411 | 58.437 | 0.802 | 59.114 | 346 |
| | 64 | 45.538 | 56.502 | 1.105 | 57.434 | 1735 |
| stream + PII | 1 | 49.765 | 59.704 | 0.390 | 0.704 | 20 |
| | 16 | 49.351 | 58.353 | 1.064 | 58.673 | 371 |
| | 64 | 47.557 | 56.429 | 1.734 | 57.678 | 1575 |
| paced stream (1 ms) | 1 | 0.131 | 0.262 | 43.457 | 57.645 | 7 |
| | 16 | 24.510 | 34.341 | 35.207 | 41.124 | 94 |
| | 64 | 21.103 | 32.637 | 34.533 | 37.030 | 317 |

Over loopback on Linux, every unpaced stream stalls about 50 ms on its last frames: Nagle holds them for an ACK the client delays. The non-streaming rows are unaffected (within 0.02 ms of the `TCP_NODELAY=1` run). On the Mac's loopback the opposite held: Nagle coalesced hyper's writes and `TCP_NODELAY` cost 5 ms p50 at c=64. So the recommendation differs per platform, and Linux is the production one.

### NER tier (one host, in a container)

The `ner` feature does not link on Amazon Linux 2023: the prebuilt static ONNX Runtime that `ort` downloads needs GCC 13/14 libstdc++ symbols (`__cxa_call_terminate`, `_M_replace_cold`) and AL2023 ships GCC 11. These rows were built and run in a `rust:1-trixie` container (host network) on the gateway host, the toolchain of the Caliban image. Default NER sessions (`min(cores / 2, 4)` = 4, 1 intra-op thread each), `CALIBAN_TCP_NODELAY=1`, 1000 requests per side.

| Scenario | Conc. | Overhead p50 | p99 | Gateway req/s | Mac p50 / req/s (after the inference pool) |
|---|---:|---:|---:|---:|---:|
| chat + PII with NER | 1 | 77.0 | 78.0 | 13 | 12.0 / 82 |
| | 16 | 385.0 | 387.3 | 41 | 119.1 / 127 |
| | 64 | 1537.8 | 1548.8 | 41 | 475.5 / 133 |
| stream + PII with NER, TTFB | 1 | 77.2 | | 13 | 12.4 / 78 |
| | 16 | 384.2 | | 42 | 122.1 / 128 |
| | 64 | 1535.7 | | 41 | 490.1 / 129 |
| PII-off chat on the NER gateway while 16 NER requests are in flight | 1 | 0.09 | 0.13 | 8164 | 0.11 |
| | 16 | 0.47 | 1.21 | 20426 | 0.30 |
| | 64 | 1.05 | 43.57 | 13925 | 0.77 |

One NER inference takes **77 ms on a Graviton4 core against 12 ms on the M5**, and the pool saturates at about 41 requests per second on 8 vCPUs (shared with the load generator and the mock). The isolation from other traffic holds (PII-off p50 at most 1.05 ms), apart from one 44 ms p99 at c=64. Before sizing NER on arm64 servers, profile ONNX Runtime's int8 kernels on aarch64 (the prebuilt binary may lack the dot-product kernels), compare with an x86 host with VNNI (c7i), and try 2 intra-op threads per session.

## (c) GPU tier

### Real model through Caliban vs direct

Qwen3.8-27B-FP8 on vLLM 0.30.0 (one L40S, shared with the embedder and the reranker). 128 output tokens per request, milliseconds except throughput.

| Conc. | Requests per side | TTFT p50 direct | TTFT p50 Caliban | Difference | TTFT p90 direct | TTFT p90 Caliban | Inter-token p50 direct | Inter-token p50 Caliban | Output tok/s direct | Output tok/s Caliban | E2E p50 direct | E2E p50 Caliban |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 16 | 85.9 | 86.3 | +0.5 | 182.8 | 183.6 | 40.24 | 40.24 | 25 | 25 | 5197 | 5197 |
| 8 | 32 | 432.4 | 429.4 | -3.1 | 509.1 | 511.5 | 43.98 | 43.98 | 170 | 171 | 6013 | 6003 |
| 32 | 128 | 1042.3 | 1103.0 | +60.8 | 8565.0 | 8419.3 | 54.49 | 55.17 | 366 | 365 | 7988 | 8106 |

- At c=1 the gateway adds about 0.5 ms to the time to first token and nothing measurable afterwards. Errors: none.
- At c=32 the TTFT is set by vLLM's scheduler (prefill of 32 prompts interleaved with decoding, and requests waiting for a slot: p90 8.5 s on both sides). The per-round p50s were 1042 and 1122 ms direct against 1236 and 1103 ms through Caliban, so the +61 ms is scheduling noise, not gateway cost.
- The model decodes at 40 ms per token for one stream (25 tokens/s) and reaches 366 output tokens/s at c=32.
- This run left `CALIBAN_TCP_NODELAY` unset on the compose gateway. The model's 86 ms TTFT is past the delayed-ACK timer, so Nagle cost nothing here (see the paced rows for when it does).

### Embedding latency

| Path | Conc. | p50 | p90 | p99 | max | req/s |
|---|---:|---:|---:|---:|---:|---:|
| TEI direct | 1 | 4.29 | 4.47 | 6.85 | 7.54 | 228 |
| Caliban `/v1/embeddings` | 1 | 4.83 | 5.01 | 5.72 | 6.48 | 206 |
| TEI direct | 8 | 12.00 | 12.71 | 13.85 | 14.53 | 662 |
| Caliban `/v1/embeddings` | 8 | 11.79 | 12.55 | 13.42 | 14.59 | 675 |

One short query embeds in under 5 ms through the gateway, about 55 times faster than the 275 ms measured on CPU and well inside the semantic cache's 50 ms lookup budget and the router's 25 ms budget. The gateway adds about 0.5 ms at c=1.

### Intent classifier (kNN, leave-one-out)

Built-in exemplar set: 210 exemplars, 7 intents (30 each), k = 5, 10 out-of-scope examples. `knn_eval` output, TEI direct:

| Configuration | Top-1 | Accepted precision | Abstain rate (threshold 0.5) |
|---|---:|---:|---:|
| Raw text, T = 0.05 (today's defaults) | **0.838** | 0.881 | 0.076 |
| Raw text, through Caliban's `/v1/embeddings` | 0.843 | 0.881 | 0.076 |
| Query instruction, T = 0.05 | 0.933 | 0.938 | 0.005 |
| Query instruction, T = 0.1 | **0.948** | 0.952 | 0.010 |

The instruction is `"Instruct: Given a user request, identify the type of task it asks for\nQuery: "`, the format Qwen3-Embedding expects for queries (the catalogue comment for `local/qwen3-embedding-0.6b` already says so). It adds 10 points of top-1. The one-exemplar difference through Caliban comes from batching differences in TEI (float16), not from the gateway.

Per intent (top-1):

| Intent | Raw, T = 0.05 | Instruction, T = 0.1 |
|---|---:|---:|
| analytics | 0.967 | 1.000 |
| chat | 0.767 | 0.967 |
| code | **0.567** | 0.833 |
| extraction | 0.900 | 0.900 |
| reasoning | 0.800 | 0.933 |
| summarize | 0.967 | 1.000 |
| translate | 0.900 | 1.000 |

Most frequent confusions. Raw: code → extraction 4, reasoning → analytics 4, chat → summarize 3, code → analytics 3, chat → translate 2, code → reasoning 2, code → translate 2, extraction → summarize 2. With the instruction: extraction → summarize 3, code → extraction 2, then single cases (chat → translate, code → analytics, code → reasoning, code → summarize, reasoning → analytics, reasoning → summarize).

Temperature and abstain threshold (k = 5), as abstain rate / accepted precision:

| Configuration | T | Top-1 | 0.5 | 0.6 | 0.7 | 0.8 |
|---|---:|---:|---:|---:|---:|---:|
| Raw | 0.05 | 0.838 | 0.08 / 0.881 | 0.14 / 0.901 | 0.23 / 0.926 | 0.37 / 0.955 |
| Raw | 0.1 | 0.852 | 0.10 / 0.910 | 0.17 / 0.909 | 0.27 / 0.942 | 0.40 / 0.960 |
| Instruction | 0.05 | 0.933 | 0.00 / 0.938 | 0.04 / 0.950 | 0.08 / 0.964 | 0.13 / 0.973 |
| Instruction | 0.1 | 0.948 | 0.01 / 0.952 | 0.05 / 0.970 | 0.11 / 0.968 | 0.17 / 0.971 |
| Instruction | 0.2 | 0.957 | 0.01 / 0.962 | 0.05 / 0.970 | 0.13 / 0.973 | 0.17 / 0.971 |

Out-of-scope spread (top-1 cosine to the nearest exemplar; in-scope = each exemplar's nearest other exemplar, a pessimistic stand-in for real in-scope prompts):

| | OOS min | OOS p50 | OOS p90 | OOS max | In-scope p01 | p05 | p10 | p50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Raw | 0.472 | 0.590 | 0.621 | 0.643 | 0.394 | 0.433 | 0.463 | 0.604 |
| Instruction | 0.544 | 0.658 | 0.728 | 0.779 | 0.617 | 0.654 | 0.683 | 0.779 |

With raw text the two distributions overlap almost completely: an OOS gate that rejects half of the OOS examples (0.58) also rejects 41% of in-scope exemplars. With the instruction: 0.64 rejects 4 of 10 OOS and 1.4% of in-scope; 0.66 rejects 6 of 10 and 6.2%.

**Suggested `[routing]` values for Qwen3-Embedding-0.6B:**

```toml
[routing]
embedding_model = "local/qwen3-embedding-0.6b"
query_prefix = "Instruct: Given a user request, identify the type of task it asks for\nQuery: "
k = 5
temperature = 0.1
abstain_threshold = 0.6   # 5% abstain, accepted precision 0.970
oos_threshold = 0.64      # 4 of 10 OOS rejected, 1.4% of in-scope; only with query_prefix
```

Without `query_prefix`, use `temperature = 0.1` and `abstain_threshold = 0.6` (top-1 0.852, 17% abstain at 0.909 precision) and no `oos_threshold`. The OOS gate rests on 10 examples; calibrate it with ml's `knn-eval` on a larger out-of-scope set before relying on it. A `query_prefix` means the semantic cache cannot reuse the routing vector (it embeds the raw prompt), so a request that goes through both pays two embeddings (about 5 ms each on this GPU).

### Semantic cache

#### Similarity distributions (Qwen3-Embedding-0.6B, raw prompts)

| Set | n | min | p10 | p50 | p90 | max |
|---|---:|---:|---:|---:|---:|---:|
| Paraphrases (should hit) | 36 | 0.781 | 0.894 | 0.945 | 0.976 | 0.984 |
| Near-misses (must not hit) | 38 | 0.656 | 0.740 | 0.854 | 0.975 | 0.997 |

The highest near-misses: "expense reports over 5000 EUR / over 500 EUR" 0.997, "Convert 100 USD to EUR / 1000 USD to EUR" 0.996, "Explain the CAP theorem briefly / in detail" 0.989, "Convert 100 USD to EUR / 100 EUR to USD" 0.988, "order 12345 / order 12346" 0.969, "sales for Q3 2025 / Q3 2024" 0.962, "Translate 'good morning' into Spanish / into Italian" 0.952. The lowest paraphrases: "Translate 'good morning' into Spanish / How do you say 'good morning' in Spanish?" 0.781, "vacation days for new employees / annual leave for new hires" 0.792, a typo-ridden "hi, how do i reset my pasword" 0.800.

The gateway's numeric-slot guard (numbers, dates and IDs in the prompt must match exactly) removes 6 of the 38 near-misses, including all the number changes above, and 1 of the 36 paraphrases ("2FA" counts as a numeric token). Threshold sweep with that guard applied, as the gateway decides:

| Threshold | Paraphrase hit rate | Near-miss false-hit rate |
|---:|---:|---:|
| 0.85 | 0.89 | 0.37 |
| 0.88 | 0.89 | 0.26 |
| 0.90 | 0.83 | 0.21 |
| 0.91 | 0.81 | 0.18 |
| 0.92 | 0.72 | 0.16 |
| 0.93 | 0.67 | **0.08** |
| 0.94 | 0.58 | 0.08 |
| 0.95 | 0.47 | 0.08 |
| 0.96 | 0.42 | 0.05 |
| 0.97 | 0.28 | 0.05 |

The false-hit rate falls from 16% to 8% between 0.92 and 0.93 and then stays flat until 0.96: the three near-misses left above 0.95 ("in detail" vs "briefly", reversed currency direction, Spanish vs Italian) are not separable by any threshold.

Embedded with a query instruction (`"Instruct: Given a user question, retrieve questions that ask exactly the same thing\nQuery: "`) and the guard, the trade-off is better: 0.91 gives 81% hits at 5% false hits, 0.92 gives 75% at 5%. The cache has no prefix option today.

#### End to end through the gateway

Threshold 0.95 (default), min 0.90, Qdrant, Qwen3.8-27B answers:

| | Probes | Semantic hits | Rate |
|---|---:|---:|---:|
| Paraphrases | 36 | 16 | 44% (offline prediction at 0.95: 47%) |
| Near-misses | 38 | 3 | 8% (prediction: 8%) |

- False hits: "Translate 'good morning' into Spanish." answered "…into Italian."; "Convert 100 USD to EUR." answered "Convert 100 EUR to USD."; "Explain the CAP theorem briefly." answered "…in detail.". Every number-only near-miss went upstream, including the 0.997 and 0.996 pairs.
- A hit was served in 6 to 13 ms (one at 1.2 ms), against about 2.6 s for a fresh 64-token answer.
- **Added latency on a miss**: 6.53 ms p50 (6.96 p90, 7.46 p99) with the semantic cache on against 1.40 ms (1.53, 1.69) off, both through the gateway to a zero-latency mock: **+5.1 ms p50, +5.4 ms p90** for the embedding and the Qdrant search. The insert happens after the response.

**Suggested `[cache.semantic]` values for Qwen3-Embedding-0.6B:**

```toml
[cache.semantic]
embedding_model = "local/qwen3-embedding-0.6b"
threshold = 0.95      # unchanged: 47% of paraphrases, 8% false hits on this adversarial set
min_threshold = 0.93  # was 0.90; below 0.93 the false-hit rate doubles (16% at 0.92, 21% at 0.90)
```

With the default grey band (0.03), probes between 0.92 and 0.95 are answered fresh and verified, which is where most of the remaining paraphrases sit (0.89 to 0.95). The three false hits above 0.95 need guards a threshold cannot provide; see the recommendations.

## Recommendations

1. **Turn `TCP_NODELAY` on for Linux deployments**: make `CALIBAN_TCP_NODELAY` default to on (or on for Linux), or write the response headers together with the first SSE frame. With Nagle on, the first token waits for the client's delayed ACK whenever the upstream answers within about 40 ms (24 ms added at 20 ms pacing, 35 to 50 ms in the stress rows). The deploy compose file now passes the variable through and documents the recommendation; its default is still off.
2. **Streaming at c=64 is CPU-bound**: 3.45 ms p50 across hosts, about 13,300 unpaced streams per second on 8 vCPUs shared with the mock. The remaining costs per the Mac profile are `writev` per frame and request setup. Either accept that the 3 ms target holds for paced traffic (it does: TTFB at most 0.84 ms, totals within 2 ms) or measure the gateway on its own host with the mock elsewhere before more optimisation.
3. **Set `[routing] query_prefix` for Qwen3-Embedding** (and ship it in `config/open-models.example.toml` and the deploy config): +10 points of kNN top-1 and a usable OOS gate. Values above.
4. **Semantic cache**: raise `min_threshold` to 0.93. Add guards for what a threshold cannot catch: ordered slots, so that "USD to EUR" differs from "EUR to USD" (the numeric slots are sorted today, and currency codes are not slots); language and entity names; and polarity or scope modifiers ("briefly" vs "in detail", "enable" vs "disable"). The planned LLM judge for the grey band would cover the rest. Consider a `query_prefix` for the cache embedder (same model, an instruction for "same question").
5. **NER on arm64**: 77 ms per inference on Graviton4. Profile ORT on aarch64 before recommending Graviton for NER-heavy tenants, and make the `ner` build work on AL2023 (static libstdc++ from a newer GCC, or document the container build).
6. **Bench**: make the mock's reply independent of the prompt length (or send the surrogate form on the direct side), so that paced PII totals become comparable; see the caveat below.

## Testbed fixes

Found by this run and fixed in the deploy repo:

- The gateway's compose override named a bridge `br-caliban-tbout` (16 characters; Linux allows 15), so Docker refused to create the network and the gateway bootstrap failed. Renamed.
- `airgap/bundle.sh` rejected model directories with a slash, but `models.lock.yaml` puts the NER model under `pii/…` and every fetch selects it, so the GPU host's weight download failed. Nested relative paths are accepted now.
- vLLM 0.30 could not start Qwen3.8-27B-FP8 with the compose defaults on 48 GB next to the embedder and reranker. With the default max-num-seqs, profiling the CUDA graphs ran out of memory (it tried to allocate 12.25 GiB). With `--max-num-seqs=32` the KV cache at 0.80 was 4.21 GiB, short of the 4.31 GiB one 131072-token sequence needs. The compose file, `.env.example` and the Helm values now set `max-num-seqs` 32 and 0.82 for compose (Helm's dedicated-GPU pool keeps 0.85).
- `bench_ref` defaulted to the `feat/bench` branch; the bench is on `main`.
- README: per-AZ spot capacity (the module's AZ choice ignores it), an SSM agent that did not register until a reboot, `tofu test` reading `terraform.tfvars`, the NER build on AL2023, observed prices, and the scenario (a) and (c) runbooks.

## Cost

Instance hours from launch to stop or termination, prices for eu-central-1 on 2026-10-09:

| Item | Hours | Price | Cost |
|---|---:|---:|---:|
| gateway c8g.2xlarge, on-demand | 1.44 | $0.3628/h | $0.52 |
| loadgen c8g.2xlarge, on-demand | 1.44 | $0.3628/h | $0.52 |
| gpu g6e.xlarge, spot (eu-central-1a) | 1.14 | $1.7443/h | $2.00 |
| gp3 volumes (60 + 60 + 150 GB) | | $0.0952/GB-month | $0.05 |
| public IPv4 (3) | 4.0 address-hours | $0.005/h | $0.02 |
| S3, SSM, EventBridge Scheduler, IAM, VPC | | | about $0 |
| **Total** | | | **about $3.10** |

Hosts ran from 13:21 to 14:48 UTC. The GPU host was stopped at 14:40 once its measurements were done. On-demand g6e.xlarge was $2.327/h; spot was $1.74 in 1a, $2.07 in 1c and $2.33 in 1b, so spot saved little. Spot capacity in 1a was short for the first minutes; the provider's retries launched it after about 10 minutes.

## Caveats

- One run, one day, one AZ. Concurrency 64 rows vary run to run (on the Mac by about ±0.5 ms).
- The mock emits a whole stream in one burst for the unpaced rows: the worst case for per-frame work, not real model behaviour.
- **Paced PII totals are a bench artifact**: the mock echoes the last user message, and through the gateway that message is the surrogate form, which is longer (72 prompt tokens against 69 direct; 68 SSE events against 65). The gateway side therefore streams 3 to 5 more paced chunks: +8.5 ms total at 1 ms pacing, +84 to 108 ms at 20 ms. Time to first byte for those rows is unaffected and is what the tables report. Fixed after this run: the benchmark now starts the mock with `--reply-chars 248`, which cuts or pads every reply to 248 characters (the PII-off reply length), so both sides stream the same number of chunks and paced PII totals become comparable.
- In the across-hosts topology the gateway and the mock share the gateway host's 8 vCPUs; the direct path only uses the mock. That penalises the gateway at high concurrency, as on the Mac.
- The real-model test used 128-token replies, 18 prompts and 2 rounds; c=32 TTFT is dominated by vLLM scheduling.
- The kNN numbers use the built-in 210-exemplar set; its OOS set has 10 examples. The semantic-cache pairs are hand-written and adversarial (38 near-misses for 36 paraphrases), not a traffic sample, so the false-hit rates are upper bounds for this kind of prompt rather than an expected rate.
- The NER rows ran inside a container on the gateway host, with the load generator and the mock on the same 8 vCPUs.
- The vLLM settings that made the model start (max-num-seqs 32, 0.82) cap the chat pool at 32 concurrent sequences on this card.

## Reproduce

Testbed: `deploy/aws/testbed` (README, scenarios a and c), with `gpu_enabled = true`, `bench_ref = "main"` and `results_upload = true`.

```sh
# loadgen: build the gateway and the bench
cargo build --release -p caliban -p caliban-bench

# one host
CALIBAN_TCP_NODELAY=1 caliban-bench --caliban ./caliban --concurrency 1,16,64 --out local.md --json local.json

# two hosts: on the gateway host, then on the loadgen with ep.json copied over
CALIBAN_TCP_NODELAY=1 caliban-bench --caliban ./caliban --bind 0.0.0.0 --advertise <gateway private IP> \
  --mock-ports 9000,9001 --gateway-ports 8000,8001,8002 [--paced-chunk-delay-ms 20] --serve ep.json
caliban-bench --remote ep.json --concurrency 1,16,64 --out cross.md --json cross.json

# intent kNN against the GPU host's TEI
CALIBAN_KNN_EVAL_URL=http://<gpu private IP>:8001/v1 CALIBAN_KNN_EVAL_MODEL=Qwen/Qwen3-Embedding-0.6B \
CALIBAN_KNN_EVAL_PREFIX=$'Instruct: Given a user request, identify the type of task it asks for\nQuery: ' \
CALIBAN_KNN_EVAL_TEMPERATURE=0.1 cargo test --release -p caliban-route --test knn_eval -- --nocapture
```

The real-model, embedding and semantic-cache scripts (stdlib Python) were run from the testbed's loadgen and are not committed; their method is described above.
