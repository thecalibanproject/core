<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/thecalibanproject/website/main/public/brand/logo-white.svg">
  <img alt="Caliban" src="https://raw.githubusercontent.com/thecalibanproject/website/main/public/brand/logo.svg" width="200">
</picture>

# Caliban Core

The Rust workspace behind Caliban: one binary, `caliban`, that runs the gateway data plane, the control plane, or both.

[Docs](https://github.com/thecalibanproject/docs) · [Deploy](https://github.com/thecalibanproject/deploy) · [Web console](https://github.com/thecalibanproject/web) · [TypeScript SDK](https://github.com/thecalibanproject/sdk-typescript) · [Python SDK](https://github.com/thecalibanproject/sdk-python) · [ML](https://github.com/thecalibanproject/ml)

## What this is

Caliban is a sovereign AI gateway: one OpenAI- and Anthropic-compatible endpoint for a whole company. Requests are authenticated per tenant, screened for PII (and pseudonymised before anything reaches an outside provider), routed by intent to an allowed model, cached, metered and rate-limited. Upstream access is BYOK only: each tenant brings its own provider keys or uses on-prem open-weight models, and keys are never pooled. A deployment can run entirely on-prem with zero egress.

This repo is the server. It holds the `caliban` binary, the crates it is built from, and the contracts the other repos depend on (the OpenAPI spec, the node schema, the config format and the Postgres migrations). Container images, compose stacks and the Helm chart live in [deploy](https://github.com/thecalibanproject/deploy); the admin console lives in [web](https://github.com/thecalibanproject/web).

**Status:** in active development with design partners. Nothing is published to a package or image registry; build from source. [Status and roadmap](#status-and-roadmap) lists what is done and what is not.

Design: [reference architecture](https://github.com/thecalibanproject/docs/blob/main/architecture/caliban-reference-architecture.md). Conventions: [repos and conventions](https://github.com/thecalibanproject/docs/blob/main/architecture/repos-and-conventions.md).

## Architecture

### Planes and ports

| Command | Runs | Default address |
|---|---|---|
| `caliban router` | Data plane: the OpenAI- and Anthropic-compatible API | `0.0.0.0:8080` (`[server] router_addr`) |
| `caliban control-plane` | Control plane: admin API and web console | `0.0.0.0:8081` (`[server] control_plane_addr`) |
| `caliban standalone` | Both in one process (the on-prem default) | both of the above |

Data-plane endpoints (`:8080`, tenant `cal_…` key as bearer token):

| Endpoint | Purpose |
|---|---|
| `POST /v1/chat/completions` | OpenAI Chat Completions, streaming included |
| `POST /v1/messages`, `POST /v1/messages/count_tokens` | Anthropic Messages, streaming included |
| `POST /v1/embeddings` | Embeddings |
| `POST /v1/rerank` | Reranking |
| `GET /v1/models` | Models this tenant can use |
| `GET /healthz` | Liveness, config version, the snapshot served (`snapshot.version`, and `snapshot.kek_ids` in split mode), and quota store state (`quota.state` is `degraded` while a shared store is unreachable; the probe still returns `200`) |
| `GET /metrics` | Prometheus text format: `caliban_snapshot_info{version,kek_ids}`, and the usage WAL and usage shipping counters. No tenant data, no authentication (like `/healthz`) |

The model id `caliban/auto` lets Caliban choose: the request is classified into an intent (embedding kNN, with keyword rules as the fallback) and served by the cheapest model the tenant may use that meets the intent's quality floor, or by the tenant's ordered candidates when no floor is set. Naming a catalogue model id pins the model, subject to the tenant's policy. See [Routing (`caliban/auto`)](#routing-calibanauto).

Every chat response carries these headers (all exposed to browsers through CORS):

| Header | Value |
|---|---|
| `x-caliban-request-id` | Request id (also `request-id` on `/v1/messages`, which Anthropic SDKs surface as `_request_id`) |
| `x-caliban-routed-model` | Catalogue id of the model that answered |
| `x-caliban-intent` | `<intent>;confidence=<0..1>;stage=<rules\|knn\|keyword>`, plus `;knn=<reason>` (`timeout`, `embed_error`, `unavailable`, `no_text`, `abstain_oos`, `abstain_confidence`, `abstain_margin`, `abstain_empty`) when kNN was on but did not decide. The intent is `pinned` for a named model |
| `x-caliban-cache` | `hit`, `miss` (a cache applied but had no answer) or `bypass` (no cache applies) |
| `x-caliban-cache-tier` | Only on hits: `exact` or `semantic` |
| `x-caliban-pii-entities` | Number of PII entities protected |
| `x-caliban-cost-usd` | Cost in USD, on non-streaming responses when the model has prices (`0.00000000` on a cache hit); the same number as the usage event's `cost_usd`, prompt-cache prices included |

`x-caliban-cache` stays `hit` for both cache tiers, so SDKs and dashboards that count `hit | miss | bypass` keep working (the Python SDK's usage model and the console's filters only accept those three values); usage events add `cache_tier` the same way.

Control-plane endpoints (`:8081`) live under `/api/v1/*` and are specified in [`api/openapi.yaml`](api/openapi.yaml): tenants, tenant API keys, BYOK provider keys, routes, the model catalogue and shared providers (with health checks and model discovery), datasources and introspection, the ontology review queue, nodes, usage, the audit log, users and role bindings, health, and signed snapshots for split-mode routers. Login lives under `/auth/*` (see [Admin access](#admin-access-sso-and-roles)). When a built console is available (`CALIBAN_WEB_DIR` or `[server] web_dir`), it is served at `/`.

`PATCH /api/v1/tenants/{tenantId}` changes a tenant's `pii_default`, `pii_surrogate_scope` and `semantic_cache` (audited as `tenant.update`; routers apply it with their next snapshot).

Deletes (each needs its permission, see [Admin access](#admin-access-sso-and-roles)):

| Endpoint | Effect |
|---|---|
| `DELETE /api/v1/tenants/{tenantId}` | Tombstones the tenant (`status: deleted`; the id is never reused), revokes all its API keys, destroys its BYOK credentials, removes its routes, and soft-deletes its datasources and nodes. Each data plane then purges the tenant's semantic-cache entries (see [Tenant offboarding](#tenant-offboarding-semantic-cache)) |
| `DELETE /api/v1/tenants/{tenantId}/api-keys/{keyId}` | Revokes the key: the row is kept with `revoked_at`, and the key is rejected (`401`) on the data plane |
| `DELETE /api/v1/tenants/{tenantId}/provider-keys/{keyId}` | Removes a BYOK credential (`409` while a route still needs it) |
| `DELETE /api/v1/tenants/{tenantId}/datasources/{datasourceId}` | Soft-deletes the datasource and wipes its stored connection settings |
| `DELETE /api/v1/tenants/{tenantId}/nodes/{nodeId}` | Soft-deletes one node version (its version number is not reused) |
| `DELETE /api/v1/models/{modelId}`, `DELETE /api/v1/providers/{providerId}` | Removes a catalogue model or shared provider (`409` while referenced) |

Every delete returns `204` and writes one audit row. An unknown id, an id that belongs to another tenant, or one that was already deleted returns `404` in the standard error envelope, so a repeat delete is always `404` and is not audited. Revoked keys and deleted tenants are hidden from listings unless asked for (`?include_revoked=true`, `?include_deleted=true`).

### Request pipeline

One pipeline serves both API shapes. OpenAI and Anthropic requests are decoded into a canonical IR (unknown fields pass through), then:

1. **Auth and limits.** Tenant API key lookup (keys are stored as SHA-256 hashes). GCRA request rate per tenant and per key; token and USD budgets with reservation and settlement. Exceeding a limit returns `429` with `retry-after`. Quota state lives in each router's memory, or in Valkey so that all routers share it (see [Shared quotas](#shared-quotas-valkey)).
2. **Routing.** Rules and policy (pinned model, trust tier), then Stage-1 intent classification (embedding kNN over labelled exemplars within a latency budget, falling back to keyword rules), then model selection: the cheapest eligible model at or above the intent's quality floor, else the tenant's default route. Routing runs before PII protection, so the prompt it embeds is masked first whenever the routing embedder is outside the trust boundary. Details in [Routing (`caliban/auto`)](#routing-calibanauto).
3. **PII.** L0: regexes with validators (Luhn, IBAN, SSN), tenant dictionaries, and credential detection (a prompt carrying credentials is refused). L1, optional (`ner` feature): an in-process multilingual NER model. Each tenant's `pii_mode` is `off`, `mask` or `reversible`. In `reversible` mode, values are replaced with realistic surrogates (valid Luhn and IBAN numbers) before an external model sees them, and the response, streams included, is rehydrated with a hold-back buffer. Sovereign (`t0_sovereign`) models receive the raw text.

   Surrogates are a keyed HMAC-SHA256 of (entity type, normalised value). Each tenant's `pii_surrogate_scope` (config, or `PATCH /api/v1/tenants/{tenantId}`) picks the key:
   - `tenant` (default): a per-tenant key, HKDF-SHA256 over `CALIBAN_KEK` with the tenant id as info. The same value in the same tenant always gets the same surrogate, so a repeated PII prompt is byte-identical after protection and can hit the exact cache. Every router that shares `CALIBAN_KEK` derives the same keys. The cost: the upstream can link sessions of one tenant through their surrogates (linkable, not identifiable).
   - `session`: a random key per request. Nothing links two requests, and requests carrying PII bypass both cache tiers.

   Surrogates never cross tenants. No surrogate-to-original table is stored: each request's reverse map is built from the values seen in that request, and only those values are restored in the response (any other surrogate, for example in a cached answer, is left as it is). Within a request, two values never share a surrogate (deterministic re-draw, then a typed placeholder). Across requests, small formats such as names can collide; that never breaks rehydration. Derivation, formats and collision probabilities are documented in [`crates/caliban-pii/src/surrogate.rs`](crates/caliban-pii/src/surrogate.rs). Without `CALIBAN_KEK`, the key comes from a random per-process secret, so surrogates are stable within one process only.
4. **Cache.** Two tiers, checked in order. Entries of both are stored pseudonymised and rehydrated with the vault of the request that hits them, and never cross tenants.
   - **T1 exact** (in-process moka): the protected upstream body (never raw PII sent outside), keyed by tenant, ACL and datasource epoch. Needs `temperature = 0`, no tools, non-streaming.
   - **T2 semantic** (Qdrant, or an in-memory store for one process): answers with the response to an earlier, *semantically similar* request of the same tenant. Off unless `[cache.semantic] enabled` and the tenant has `semantic_cache = "on"`.
     - *What must match exactly* (a hash used as a store filter, together with `tenant_id`): the routed model and response shape; the whole protected request except the last user message (system prompt, earlier turns, temperature and every other parameter), so different system prompts, histories or temperatures never share answers; deterministic guards on the last user message ([`guard.rs`](crates/caliban-cache/src/semantic/guard.rs)), for what no threshold separates: its slots in order of appearance (numbers, dates and IDs, currency codes and names, units next to a number, language names, acronyms and capitalised names that do not start a sentence: "Q3 2025" never matches "Q3 2026", "USD to EUR" never matches "EUR to USD", "into Spanish" never matches "into Italian"; a possessive is its entity, so "Germany's VAT rate" has the slots of "the VAT rate in Germany"), its modifier classes (negation, "briefly" vs "in detail", enable/disable, increase/decrease, over/above vs under/below and other opposite pairs; English plus common German, French, Spanish, Italian, Portuguese and Dutch words) and its date and time format specs as a set (`YYYY-MM-DD` never matches `DD/MM/YYYY`, but its position in the sentence does not matter). A rule can only turn a hit into a miss; a word it does not know leaves the pair to the threshold. Over the AWS runs' 36 paraphrase and 38 near-miss pairs, the guards alone keep 33 paraphrases comparable and rule out 24 near-misses (`cargo test -p caliban-cache --test guard_pairs -- --nocapture`); the instruction the prompt was embedded with (`query_prefix`, below); the set of PII surrogates in the request (tenant-scoped surrogates are deterministic, so an answer about one person is never served for another, and every surrogate in a hit is restorable); the PII mode.
     - *What is embedded*: the last user message in surrogate form, with the deployment's `embedding_model` (one Qdrant collection per embedding model and dimension).
     - *Eligible requests*: T1's PII rules (no PII, tenant-scoped surrogates or masking; session-scoped PII bypasses); no tools, tool calls or tool results; `n` unset or 1; a text-only last user message; not `zdr`; `temperature <= max_temperature` (default 0.3; unset means sampling), unless the request sends `caliban.cache = "semantic"`, which opts in at any temperature. `caliban.cache = "exact"` or `"off"` skips T2. Streaming and non-streaming both qualify: a streamed miss is captured and cached, and a hit on a streaming request is replayed as a stream (one content delta, then the finish chunk, with usage when the client asked for it).
     - *Threshold policy* (vCache-style, [research note 01](https://github.com/thecalibanproject/docs/blob/main/research/01-semantic-caching-and-rust-vector-stack.md), "Threshold strategy"): every entry starts at a cosine threshold (`threshold`: 0.91 with the default `query_prefix`, 0.95 without one) and learns its own from verification. Matches just below it (`grey_band`, 0.03) are answered fresh and the fresh answer is compared with the cached one in the background; two agreements let the entry serve down to the lowest verified-correct similarity (never below `min_threshold`: 0.91 with the default prefix; 0.93 without one, below which the first AWS run measured twice the false hits). A wrong answer moves the entry's threshold above that similarity for good. A share of would-be hits (`verify_rate`, 5%) is also answered fresh and checked; those samples measure each tenant's false-hit rate, and when a window of 50 samples holds more wrong answers than `max_error_rate` (2%) allows, all of that tenant's thresholds tighten by 0.01 (up to 0.04), relaxing again after a clean window. Answers count as the same when their texts match or their embeddings have cosine at least `verify_answer_similarity` (0.90). Compared with vCache, the per-entry signal is the same (similarity, was the cached answer right), but the threshold is the non-parametric bound instead of a fitted sigmoid, and the error budget is enforced by measurement and tightening rather than a formal bound. Entry statistics live in the Qdrant payload (shared by routers, last writer wins); the tenant budget is per router.
     - *Failure policy*: embedding plus search must finish within `lookup_budget_ms` (50 ms), or the request goes on as a miss. A late embedding is still used to cache the fresh answer. Errors never fail a request.
     - *Measured* on an Apple-silicon laptop (release build; Qdrant 1.19.1 and TEI 1.9.4 CPU in Docker):

       | What | p50 | p99 |
       |---|---|---|
       | Qdrant lookup (1,024-d, 2,000 points over 20 tenants, tenant and partition filter) | 0.7 ms | 1.7 ms |
       | Added on a miss, embedding mocked (HTTP round trip and search only) | 0.5 to 1.0 ms | 1.6 to 2.5 ms |
       | Embedding one prompt, `BAAI/bge-small-en-v1.5` (384-d, ONNX) | 6.1 ms | 10.8 ms |
       | Added on a miss, bge-small plus Qdrant, end to end | 10.3 ms | 23.0 ms |
       | Embedding one prompt, `Qwen/Qwen3-Embedding-0.6B` (1,024-d, candle) | 275 ms | 304 ms |

       So on CPU, a small embedding model fits the budget and Qwen3-Embedding-0.6B does not: with it every lookup times out (50 ms added, no hits on rephrasings) until it runs on a GPU. Pick a small model for cache keys on CPU-only sites, or raise `lookup_budget_ms` knowingly.
     - *Embeddings* go through the one embedder Caliban uses internally, `ProviderEmbedder` ([`crates/caliban-gateway/src/embedder.rs`](crates/caliban-gateway/src/embedder.rs), behind the `Embedder` trait in `caliban-types`): T2 uses the tenant's route to the embedding model (its own provider, or a shared pool it may use), with one batched call per request, a 2 s timeout (`embed_timeout_ms`) and an in-process LRU. kNN routing uses the same embedder through its shared-provider path. The LRU is keyed by tenant, model, endpoint and text, so when routing already embedded the same prompt with the same model and endpoint, T2 reuses that vector and the request makes one embedding call, not two. They embed different text, and so make two calls, when the routing and cache prefixes differ (the cache prefix is on by default, so a kNN-routed request with T2 embeds twice unless `[routing] query_prefix` is the same text or `[cache.semantic] query_prefix = ""`; the second AWS run measured a miss at +5.3 ms p50 with the prefix against +5.1 ms without), when the prompt is over 2,000 characters or has surrounding whitespace (routing trims and truncates), or when it carries PII (routing masks it, T2 embeds surrogates).
     - *Tenant offboarding*: when a tenant is deleted, every data plane purges its entries (see [Tenant offboarding](#tenant-offboarding-semantic-cache)).
   - **Headers and metering, both tiers.** A hit returns `x-caliban-cache: hit` and `x-caliban-cache-tier: exact` or `semantic`, and calls no model: its usage event has no prompt or completion tokens, `cost_usd` 0 (and `x-caliban-cost-usd: 0` on JSON responses), `cache_tier`, and the cached answer's tokens as `tokens_saved`. What the hit is billed and what it saved are recorded next to each other (see [Pricing and metering of cache hits](#pricing-and-metering-of-cache-hits)). The control plane's usage totals count both tiers in `cache_hits` and add `semantic_cache_hits`.
5. **Upstream.** BYOK calls to OpenAI-compatible servers (OpenAI, vLLM, SGLang, llama.cpp, Ollama, TEI) or to Anthropic, either as native passthrough (`cache_control` kept) or translated. `security.egress = "deny_by_default"` limits calls to declared `base_url`s. Shared vLLM and SGLang pools can receive a per-tenant `cache_salt` for prefix-cache isolation.
6. **Metering and tracing.** Every request emits one usage event with its cost. Events go to an in-memory ring, optionally a JSONL write-ahead log, and, in split mode, to the control plane (see [Usage shipping](#usage-shipping)). OpenTelemetry GenAI spans are exported only when configured, and prompt and response content is never recorded. Details:
   - **Tokens come from the provider.** Streams always ask the upstream for usage (`stream_options.include_usage: true`), also when the client set it to `false` or did not set it, because the provider bills the request either way. An OpenAI client that did not ask for usage gets exactly what it asked for: the usage-only final chunk is dropped and the `usage` field (including OpenAI's per-chunk `"usage": null`) is removed. Anthropic streams carry usage in `message_start` (input and cache tokens) and `message_delta` (output tokens); both are captured. Such events have `usage_source: "provider"`.
   - **Estimates are flagged.** When no complete usage report arrives, the event has `usage_source: "estimated"`: the client disconnected mid-stream, the upstream stream failed or ended without usage, or the model is marked `capabilities.rejects_stream_options` (for servers that reject the field; it is then not sent). Prompt tokens come from the provider's partial report when there is one (Anthropic `message_start`), otherwise from the request estimate (about 4 bytes per token plus per-message overhead); completion tokens are the output bytes streamed so far divided by 4. After a disconnect the provider may bill more than the estimate: dropping the upstream connection cancels the generation, but the provider bills what it produced until it noticed. Quota settlement uses the same numbers. `GET /api/v1/usage` totals add `cached_prompt_tokens`, `cache_write_tokens` and `estimated_requests`.
   - **Cost applies prompt-cache prices.** `cost_usd` = uncached prompt tokens x `price_in_per_mtok` + cache reads (`cached_prompt_tokens`) x `price_cache_read_per_mtok` + cache writes (`cache_write_tokens`, Anthropic `cache_creation_input_tokens`) x `price_cache_write_per_mtok`, with the part written at Anthropic's 1-hour TTL (`cache_write_1h_tokens`) at `price_cache_write_1h_per_mtok`, + completion x `price_out_per_mtok`. Unset cache prices fall back to the input price (the 1-hour price to the 5-minute one), so a model without them costs what it did before. The router warns at startup for priced OpenAI and Anthropic models without cache prices, and once per model when a provider reports cache tokens for a priced model without them. The `x-caliban-cost-usd` header, quota settlement and the `caliban/auto` `routed_model_cost_usd` and `flat_price_usd` use the same function (the flat price has no cache prices, so cache tokens count at its input price). Cache writes survive translation for OpenAI clients of Anthropic models as `usage.prompt_tokens_details.cache_write_tokens`.
   - **The WAL** (`--usage-wal`) is written by a background task: the request only enqueues the event on a bounded queue (`--usage-wal-queue`, default 16,384). The writer keeps the file open and appends in batches, flushing whenever the queue runs empty (an idle router writes each event within microseconds), when 256 KiB are buffered, and on graceful shutdown (SIGTERM or Ctrl-C), which also waits up to 2 s for streams still finishing. `--usage-wal-fsync off` (default) leaves write-back to the OS (survives a process crash, not a power loss; graceful shutdown syncs); `batch` calls `fdatasync` after every batch. When the queue is full, a request waits at most 20 ms for room, then the event is dropped and counted. The data plane's `/healthz` reports `usage_wal: {written, dropped, write_errors, backpressure_waits, queue_depth, queue_capacity, fsync}`. The format is unchanged (one JSON object per line, appended in order), and log rotation by renaming the file works: the writer reopens the path within a second.

### Workspace layout

The binary is in `apps/caliban`; everything else is in `crates/`, except the P0 measurement suite (mock upstream, load generator, process harness), which is in `bench/` (crate `caliban-bench`).

| Crate | Status | Role |
|---|---|---|
| `caliban-types` | Done | Ids, trust tiers, PII and cache modes, errors |
| `caliban-config` | Done | TOML config to an indexed `Snapshot` behind `ArcSwap`; secret references (`env`, `file`, `sealed` under the KEK keyring, and `tenant_sealed` envelopes under per-tenant DEKs, AES-256-GCM); Ed25519 snapshot signing |
| `caliban-ir` | Done (OpenAI, Anthropic) | Canonical request IR, unknown-field passthrough, canonical hashing for cache keys, Anthropic Messages codecs (requests, responses, stream events), SSE parser |
| `caliban-pii` | L0 done; L1 NER done behind `ner` | Regexes and validators, tenant dictionaries, in-process multilingual NER (ONNX, MIT-licensed weights, hash-verified artifact; see [`crates/caliban-pii/MODELS.md`](crates/caliban-pii/MODELS.md)), surrogates, vault, streaming rehydration |
| `caliban-cache` | Exact and semantic caches done; plan cache planned | T1 exact cache (moka) with tenant, ACL and datasource-epoch keys; T2 semantic cache: `VectorStore` trait with Qdrant (REST) and in-memory stores, per-entry learned thresholds, tenant error budgets |
| `caliban-route` | Rules, Stage-1 kNN and quality-floor selection done; ONNX classifier and LLM fallback planned | Staged router: pinned rules, embedding kNN with ml-calibrated thresholds, keyword fallback, cheapest model above a per-intent quality floor (ml router profiles or config), allow-lists, BYOK and trust-tier filters, fallbacks |
| `caliban-providers` | OpenAI-compatible and Anthropic done; Bedrock and Vertex planned | BYOK upstream calls; Anthropic native passthrough or translation |
| `caliban-meter` | Done | Usage events, cost (prompt-cache prices included), in-memory ring and JSONL WAL (background writer); GCRA rate limits and token and USD budgets, in memory (`governor`) or shared in Valkey (atomic Lua scripts, local fallback) |
| `caliban-ontology` | Compiler done; store and retrieval planned | Caliban Semantic Model (CSM) types and the **CQIR compiler**: typed queries lowered to a MongoDB aggregation pipeline (with lint) or to SQL for the CDC replica; a pure-function lane planner |
| `caliban-connect` | MongoDB done; SQL and REST sources planned | Connector trait. MongoDB: read-only privilege check, stratified sampling into path statistics, reference discovery, ontology bootstrap (`proposed` elements), native-lane executor with an `explain` gate, epochs |
| `caliban-replica` | v1 done | CDC replica: snapshot plus change streams to Arrow and Parquet, queried with DataFusion; the watermark is the last applied `clusterTime` |
| `caliban-nodes` | Spec and budgets done; executor planned | Node (agent) spec validation (pinned tools, bounded cycles), hierarchical budget ledger |
| `caliban-rag` | Fusion and budgeting done; index planned | Reciprocal rank fusion, token-budgeted context selection |
| `caliban-mcp` | Pinning done; MCP client planned | Tool-manifest pinning against description poisoning |
| `caliban-gateway` | Done | Data-plane HTTP app: the pipeline above, embeddings, rerank, rate limits, OTel tracing; the provider-backed embedder shared by routing and the semantic cache; tenant purges from the semantic cache |
| `caliban-cp` | Done | Control plane: admin API per `api/openapi.yaml`, in-memory and Postgres stores, hash-chained audit log, signed snapshots for split-mode routers, web console hosting |

### Contracts owned here

- [`api/openapi.yaml`](api/openapi.yaml): the HTTP contract used by [web](https://github.com/thecalibanproject/web), [sdk-typescript](https://github.com/thecalibanproject/sdk-typescript) and [sdk-python](https://github.com/thecalibanproject/sdk-python).
- [`schemas/node.schema.json`](schemas/node.schema.json): the node spec, vendored by the SDKs and the web app.
- [`config/caliban.example.toml`](config/caliban.example.toml): the config format, used by [deploy](https://github.com/thecalibanproject/deploy). [`config/open-models.example.toml`](config/open-models.example.toml) is a complete on-prem config with a catalogue of open-weight models.
- [`migrations/`](migrations): the control plane's Postgres schema, embedded in the binary and applied at start-up. Applied migrations are checksummed in `caliban_schema_migrations`, and the binary refuses to start if one was edited: add a new `000N_*.sql` file and list it in `crates/caliban-cp/src/store/postgres.rs`. Each listed version that is not yet recorded is applied, in list order, so a gap in the numbering is allowed (a reserved version can land later and is applied on the next start); migrations must therefore not depend on one another's order beyond what is already on main. Tested against Postgres 17.

## Quick start

Requirements: a stable Rust toolchain (selected by `rust-toolchain.toml`; edition 2024, `rust-version` 1.85), plus an OpenAI-compatible model server or a provider key to route to.

```sh
cargo build -p caliban
cp config/caliban.example.toml caliban.toml
./target/debug/caliban keygen          # prints a cal_… tenant key and its hash
```

Edit `caliban.toml`: put the hash in `tenants.api_key_hashes`, and point the `local-llm` provider's `base_url` at your model server (or keep the `openai` BYOK provider and export `ACME_OPENAI_API_KEY`). Then:

```sh
export CALIBAN_CONFIG=caliban.toml CALIBAN_ADMIN_TOKEN=dev-admin
export CALIBAN_KEK=$(./target/debug/caliban gen-kek)
./target/debug/caliban check-config
./target/debug/caliban standalone
```

```sh
curl localhost:8080/v1/chat/completions \
  -H "authorization: Bearer cal_…" -H 'content-type: application/json' \
  -d '{"model":"caliban/auto","messages":[{"role":"user","content":"hello"}]}'
```

Any OpenAI SDK works with `base_url=http://<host>:8080/v1` and a `cal_…` key. Any Anthropic SDK works with `base_url=http://<host>:8080` and `api_key=cal_…`.

The admin API listens on `:8081`. Without single sign-on, `CALIBAN_ADMIN_TOKEN` is the bearer token (and the console's login); with it, people log in through the identity provider and the token becomes break-glass (see [Admin access](#admin-access-sso-and-roles)). Without `CALIBAN_DATABASE_URL` the control plane uses an in-memory store seeded from the config file, so changes made through the API are lost on restart.

For container images, compose and Kubernetes, see [deploy](https://github.com/thecalibanproject/deploy).

## Commands

| Command | What it does |
|---|---|
| `caliban standalone` | Data plane and control plane in one process |
| `caliban router` | Data plane only, config from `$CALIBAN_CONFIG` |
| `caliban router --control-plane-url http://cp:8081` | Split mode: config from signed control-plane snapshots, no config file |
| `caliban control-plane` | Control plane only |
| `caliban check-config` | Validate `$CALIBAN_CONFIG` and exit |
| `caliban keygen` | New tenant API key and its hash |
| `caliban gen-kek` | New base64 32-byte key-encryption key for `CALIBAN_KEK` |
| `caliban keys status` | Postgres store: which KEK wraps each tenant data key, what still waits for migration, whether the keys in `CALIBAN_KEK_PREVIOUS` are still needed by stored data, and which split-mode routers still serve a snapshot sealed under one (read-only, JSON; also `GET /api/v1/keys/status`) |
| `caliban keys rotate` | Postgres store: re-wrap every tenant data key and re-seal shared provider keys under the current `CALIBAN_KEK`; all or nothing, idempotent, audited as `keys.rotate`. See [KEK rotation](#kek-rotation) |
| `caliban gen-signing-key` | New Ed25519 snapshot signing key (control plane) and its public key (routers) |
| `caliban healthcheck [--addr 127.0.0.1:8080] [--path /healthz]` | Exit 0 on a 2xx response, 1 otherwise; for container healthchecks in the shell-less image |

Global flags: `--config` (`CALIBAN_CONFIG`, default `/etc/caliban/caliban.toml`), `--usage-wal` (`CALIBAN_USAGE_WAL`: append usage events to a JSONL file), `--usage-wal-fsync` (`CALIBAN_USAGE_WAL_FSYNC`: `off` or `batch`) and `--usage-wal-queue` (`CALIBAN_USAGE_WAL_QUEUE`, default 16384). See [Request pipeline](#request-pipeline), step 6.

## Configuration

### Config file

[`config/caliban.example.toml`](config/caliban.example.toml) is annotated. Its sections:

- `[server]`: `router_addr`, `control_plane_addr`, `web_dir`.
- `[security]`: `egress = "deny_by_default"`, `admin_token` (break-glass once SSO works) and `break_glass` (default `true`).
- `[security.oidc]` and `[[security.oidc.role_mappings]]`: single sign-on and group to role mappings (see [Admin access](#admin-access-sso-and-roles)).
- `[cache]`: exact cache on or off, size and TTL.
- `[cache.semantic]`: `enabled`, `store` (`qdrant` or `memory`), `qdrant_url`, `qdrant_api_key`, `collection_prefix`, `embedding_model`, `threshold`, `min_threshold`, `grey_band`, `max_error_rate`, `verify_rate`, `verify_answer_similarity`, `max_temperature`, `ttl_secs`, `lookup_budget_ms`, `embed_timeout_ms`, `query_prefix` (an instruction prepended before embedding; unset means the Qwen3-Embedding default `"Instruct: Given a user question, retrieve questions that ask exactly the same thing\nQuery: "` when the embedding model's catalogue `family` is `qwen3-embedding` (other embedders get no prefix: the instruction is written and calibrated for that model only), `""` turns it off, any other text replaces it; unless it equals `[routing] query_prefix`, a kNN-routed request embeds its prompt twice). `threshold` and `min_threshold` default to 0.91 with the default prefix (the second AWS run, end to end with the guards: 24 of 36 paraphrases hit, 0 of 38 near-misses; 14 of 36 without a prefix at 0.95 / 0.93) and to 0.95 / 0.93 with no prefix or a prefix of your own, which is not calibrated. Changing the prefix starts a cold cache: the prefix is part of the key, so entries embedded under another one are never compared (see [Cache](#request-pipeline) above and the annotated example). Caliban talks to Qdrant's REST port (6333), not gRPC (6334). The store and its URL are read at start-up; the switches, thresholds and budgets follow the live snapshot (split-mode routers get them from the control plane).
- `[pii]`: `default_mode` (`off`, `mask` or `reversible`).
- `[limits]` and `[limits.tenants.<id>]`: `requests_per_minute`, `key_requests_per_minute`, `tokens_per_minute`, `tokens_per_day`, `usd_per_day`. Unset means unlimited. `[limits]` also takes `store` (`memory` or `valkey`), `valkey_key_prefix` and `valkey_timeout_ms` (see [Shared quotas](#shared-quotas-valkey)).
- `[routing]` and `[routing.tenants.<id>]`: `caliban/auto` routing (embedder, kNN, floors, quality, flat price). See [Routing (`caliban/auto`)](#routing-calibanauto).
- `[[providers]]`: deployment-wide model servers shared by tenants (see `open-models.example.toml`).
- `[[models]]`: the catalogue (provider, `upstream_model`, trust tier, licence, context window, prices, capabilities). Prices are USD per million tokens: `price_in_per_mtok`, `price_out_per_mtok`, and for providers with prompt caching `price_cache_read_per_mtok`, `price_cache_write_per_mtok` and `price_cache_write_1h_per_mtok` (Anthropic's 1-hour TTL). No list prices ship with Caliban; copy them from your provider. `capabilities.rejects_stream_options = true` marks a server that rejects `stream_options` (its streams are metered from an estimate).
- `[[tenants]]`, with `pii_mode`, `pii_surrogate_scope` (`tenant` or `session`), `semantic_cache` (`off` or `on`, default `off`), `[[tenants.providers]]` (BYOK) and `[[tenants.routes]]` (intent to ordered models).

Secrets are never written inline: use `{ env = "VAR" }`, `{ file = "/path" }`, or a value sealed under `CALIBAN_KEK` (`{ sealed = "..." }`, opened with any key of the keyring). Keys added through the admin API are sealed by the control plane (see [Secrets and keys](#secrets-and-keys)). Trust tiers run from `t0_sovereign` to `t3_public`.

### Routing (`caliban/auto`)

Stages, in order (`crates/caliban-route`):

1. **Rules.** A pinned model id exits here, subject to the tenant's catalogue and the trust-tier constraint.
2. **Embedding kNN.** The last user message (first 2,000 characters) is embedded and compared, by brute-force cosine, with labelled exemplars held in memory: the built-in set ([`crates/caliban-route/data/exemplars.default.json`](crates/caliban-route/data/exemplars.default.json), 30 synthetic prompts each for `chat`, `code`, `analytics`, `summarize`, `extraction`, `translate` and `reasoning`), plus deployment and tenant exemplars from config. The k nearest neighbours vote with temperature-softmax weights; the classifier abstains below the OOS gate (top-1 similarity), below the intent's confidence threshold, or below the margin threshold. The semantics match ml's `KnnIntentClassifier`, so ml calibrations apply unchanged. Embed plus kNN must finish within `budget_ms` (default 25); on abstain, timeout, embedder error or a missing index, the keyword rules decide.
3. **Model selection.** Candidates are the tenant's route for the intent (else its `default` route; a tenant without routes gets every chat model it can reach), filtered to chat models reachable through its own or a shared provider, with a credential (or a keyless OpenAI-compatible endpoint), within the trust-tier constraint and healthy, then narrowed by tools, vision and context-window fit. With a floor for the intent, models whose quality is at or above it are ordered by estimated request cost (cheapest first, unpriced last), then quality, route position and id; if none qualifies, the tenant's `default` route is used in its own order. Without a floor, the route order is kept.

```toml
[routing]
embedding_model = "local/bge-small"        # catalogue embedding model on a shared [[providers]] entry
embedder_artifact = "bge-small@1.0.0"      # the ml embedder artifact it corresponds to (gates the calibration)
query_prefix = "query: "                   # prepended to prompts and exemplars alike (E5 needs "query: ")
budget_ms = 25
calibration_dir = "/opt/caliban/artifacts/intent_head/knn-default/1.0.0"   # ml `router knn-eval` output
profile_dir = "/opt/caliban/artifacts/router_profile/core/1.0.0"         # ml `router profile` output (cluster id = intent)
exemplar_cache_dir = "/var/lib/caliban/knn"  # exemplar vectors cached by vector space and exemplar set
# k, temperature, abstain_threshold, margin_threshold and oos_threshold override the calibration.
# Qwen3-Embedding-0.6B, measured on the built-in set (bench/RESULTS-aws-2026-10.md): query_prefix =
# "Instruct: Given a user request, identify the type of task it asks for\nQuery: ", temperature = 0.1,
# abstain_threshold = 0.6 and, only with that prefix, oos_threshold = 0.64 (based on 10 OOS examples);
# config/open-models.example.toml ships these values.
auto_price_in_per_mtok = 3.0               # flat price of caliban/auto, metered next to the real cost
auto_price_out_per_mtok = 12.0
auto_cache_hit_fraction = 0.2              # share of the flat price billed for a cache hit (default 0.2)

[routing.floors]                            # quality floor per intent, 0..1; "*" covers the rest
code = 0.8
reasoning = 0.85
"*" = 0.6

[routing.quality."openai/gpt-5-mini"]      # per-model quality per intent; overrides the profile
code = 0.86

[routing.tenants.acme]                      # floors, prices, `knn = false`, and the tenant's own exemplars
floors = { code = 0.9 }
exemplars = { "legal.review" = ["review this NDA clause for risky terms", "check the liability cap in this MSA"] }
```

- The routing embedder must be served by a shared (deployment) provider, typically an on-prem TEI or vLLM embedding server: exemplars are embedded once for the deployment, never with a tenant's BYOK key, even when a tenant has its own provider under the same id. A tenant that the shared provider does not serve routes by the keyword rules. If that provider is outside the trust boundary, prompts are PII-masked before embedding, which adds latency; prefer a `t0_sovereign` embedder.
- Embedding calls go through the same `ProviderEmbedder` as the semantic cache (its shared-provider path), with its batching (32 inputs per upstream request, the TEI default) and LRU. The vector space id (model id, upstream model, provider `base_url`) keys the exemplar cache. Pointing `[cache.semantic] embedding_model` at the same model lets one embedding serve both (see [Cache](#request-pipeline)).
- Routing assets are built at startup in the background and rebuilt when the snapshot changes the exemplar set, the embedder or the artifact paths. Floors, quality, thresholds and prices apply per request and never re-embed anything. Until the index is ready, or if the embedder is down (retried every 30 s), `caliban/auto` routes by the keyword rules. Artifacts are verified against their `manifest.json` hashes; a calibration whose `requires` embedder does not match `embedder_artifact` is not applied (built-in defaults are used, with a warning).
- The decision trace (stage, kNN outcome and timing, floor, each candidate's verdict, quality and estimated cost) is logged at debug level under the `caliban_route` target, without prompt text. The `route` span carries the intent, confidence, stage, policy, kNN fallback reason and kNN time.
- Metering: usage events for chat requests add `requested_model`, `intent_confidence` and `route_stage`; `caliban/auto` events add `routed_model_cost_usd` (the routed model's real cost, the same number as `cost_usd`, prompt-cache prices included), `flat_price_usd` (the flat auto price for the same tokens, through the same cost function) and `billed_usd` (what the customer is billed: the flat price on a miss, the discounted price on a cache hit). `GET /api/v1/usage` totals include `auto_requests`, `auto_cache_hits`, `flat_price_usd`, `billed_usd`, `auto_saved_usd`, `routed_model_cost_usd` and `margin_usd` (`billed_usd - routed_model_cost_usd`). Fields are omitted when unset, so older consumers are unaffected; migrations `0005` and `0010` add matching nullable columns to `usage_event`.

#### Pricing and metering of cache hits

`caliban/auto` is sold at a flat price (`auto_price_in_per_mtok`, `auto_price_out_per_mtok`, per million tokens). When the exact (T1) or semantic (T2) cache answers, no model is called, so the customer is billed a fraction of the flat price (reference architecture §9, decided 2026-10-09):

| Request | `cost_usd`, `routed_model_cost_usd` | `flat_price_usd` | `billed_usd` | `saved_usd` |
| --- | --- | --- | --- | --- |
| `caliban/auto`, miss | the routed model's real cost | flat price of the request's tokens | `flat_price_usd` | absent |
| `caliban/auto`, cache hit (either tier) | 0 | flat price of the cached answer's tokens (what a miss would have billed) | `flat_price_usd` x the cache-hit fraction | `flat_price_usd - billed_usd` |
| Pinned model (BYOK), miss | the model's cost | absent | absent | absent |
| Pinned model (BYOK), cache hit | `cost_usd` 0 (nothing reaches the provider) | absent | absent | the model cost the hit avoided |

- The fraction is `[routing] auto_cache_hit_fraction` (default `0.2`), overridden per tenant by the tenant's `auto_cache_hit_fraction` (config file, `POST /api/v1/tenants` or `PATCH /api/v1/tenants/{id}`, where `null` clears the override; audited as `tenant.update` and shipped to routers in the signed snapshot). Validation accepts 0 to 1; the pricing decision put it at 10 to 25%.
- A hit is priced from the prompt and completion tokens stored with the cache entry (the answer's original request), at the flat input and output price; the avoided model cost of a pinned-model hit uses the model's input and output price (whether the original call read the provider's prompt cache is not stored). T2 entries match a similar but not identical prompt, so the full price is that of the cached answer's request.
- Margin is `billed_usd - routed_model_cost_usd`; on a hit the routed cost is 0, so the margin is the discounted price. Events written before cache-hit billing have no `billed_usd` and count as billed at `flat_price_usd` (their hits recorded 0 for both).
- `saved_usd` (all requests) and `auto_saved_usd` (`caliban/auto` only) in the usage totals sum what hits saved customers. Quota settlement is unchanged: a hit consumes no tokens and no model spend.
- Offline check of an exemplar set under a real embedder (leave-one-out kNN accuracy, per-intent accuracy, confusions, OOS similarity): `CALIBAN_KNN_EVAL_URL=http://host:port/v1 CALIBAN_KNN_EVAL_MODEL=<model> cargo test -p caliban-route --test knn_eval -- --nocapture`. Without the variable the test is skipped.

### Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `CALIBAN_CONFIG` | all | Config file path (default `/etc/caliban/caliban.toml`) |
| `CALIBAN_ADMIN_TOKEN` | control plane | Bootstrap admin token (break-glass once SSO works), unless `[security] admin_token` resolves it another way. Optional when SSO is configured |
| `CALIBAN_BREAK_GLASS` | control plane | `false` refuses the admin token (overrides `[security] break_glass`); needs SSO |
| `CALIBAN_OIDC_ISSUER`, `CALIBAN_OIDC_CLIENT_ID`, `CALIBAN_OIDC_CLIENT_SECRET`, `CALIBAN_OIDC_REDIRECT_URL` | control plane | Single sign-on without a `[security.oidc]` section, or overrides of it |
| `CALIBAN_OIDC_SCOPES`, `CALIBAN_OIDC_GROUPS_CLAIM`, `CALIBAN_OIDC_API_AUDIENCE`, `CALIBAN_OIDC_CA_FILE` | control plane | Same, optional fields |
| `CALIBAN_OIDC_OWNER_GROUPS`, `CALIBAN_OIDC_ADMIN_GROUPS`, `CALIBAN_OIDC_AUDITOR_GROUPS` | control plane | IdP groups (comma separated) that get the deployment role |
| `CALIBAN_KEK` | all | Current base64 32-byte key-encryption key: wraps the per-tenant data keys and seals shared provider keys, and derives the cache-salt key and the per-tenant PII surrogate keys. Rotating it changes every tenant's surrogates (only costs cache misses). See [Secrets and keys](#secrets-and-keys) |
| `CALIBAN_KEK_PREVIOUS` | all | Retired KEKs (base64, comma separated), only used to open what is still wrapped or sealed under them during a [KEK rotation](#kek-rotation). Remove once `caliban keys status` shows they are no longer needed |
| `CALIBAN_DATABASE_URL` | control plane | Postgres store; unset means in-memory |
| `CALIBAN_VALKEY_URL` | data plane | Valkey for shared quotas, required with `[limits] store = "valkey"`: `redis://[:password@]host:6379[/db]`, or `rediss://` for TLS |
| `CALIBAN_VALKEY_PASSWORD` | data plane | Valkey password, if it is not in the URL (overrides the URL's) |
| `CALIBAN_WEB_DIR` | control plane | Built web console (overrides `[server] web_dir`) |
| `CALIBAN_USAGE_WAL` | data plane | JSONL usage log path |
| `CALIBAN_USAGE_WAL_FSYNC` | data plane | `off` (default) or `batch` (`fdatasync` after every written batch) |
| `CALIBAN_USAGE_WAL_QUEUE` | data plane | Usage events queued for the WAL writer before requests wait (up to 20 ms) or drop and count (default 16384) |
| `CALIBAN_USAGE_SHIP`, `CALIBAN_USAGE_SHIP_*`, `CALIBAN_USAGE_SPOOL_*` | data plane | Usage shipping to the control plane; see [Usage shipping](#usage-shipping) |
| `CALIBAN_QDRANT_URL` | data plane | Qdrant REST endpoint for the semantic cache, e.g. `http://qdrant:6333` (overrides `[cache.semantic] qdrant_url`) |
| `CALIBAN_QDRANT_API_KEY` | data plane | Qdrant API key, used when `[cache.semantic] qdrant_api_key` is unset |
| `CALIBAN_LOG` | all | Log filter (default `info,tower_http=info`) |
| `CALIBAN_PII_NER_DIR` | data plane | Verified NER artifact directory; needs a `ner` build |
| `CALIBAN_PII_NER_SESSIONS` | data plane | NER inference sessions, which is also the number of PII worker threads (default `min(cores / 2, 4)`) |
| `CALIBAN_PII_NER_THREADS` | data plane | ONNX Runtime intra-op threads per session (default 2, or 1 on a single-core machine) |
| `CALIBAN_PII_NER_QUEUE` | data plane | Requests that may wait for a PII worker (default 128) |
| `CALIBAN_PII_NER_QUEUE_WAIT_MS` | data plane | How long a request waits for a queue slot when the queue is full (default 0) |
| `CALIBAN_PII_NER_OVERFLOW` | data plane | `reject` (default: 503, fail closed) or `degrade` (regex tier only); see [PII NER model](#pii-ner-model-ner-feature) |
| `CALIBAN_TCP_NODELAY` | all | `TCP_NODELAY` on accepted connections, on by default; `0`, `false` or `off` turns it off. On Linux, with Nagle on, a stream's first frame waits for the client's delayed ACK (24 ms per stream at real model pacing, up to 50 ms; `bench/RESULTS-aws-2026-10.md`). Streams also hold their headers back until the first frame is ready (at most 250 ms), so headers and first token leave in one write either way. On macOS loopback it cost about 5 ms p50 at concurrency 64 in the stress bench (Nagle coalesced the frames there); production is Linux |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | all | Turns on OTLP/HTTP trace export (off when unset). `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME` and `OTEL_SDK_DISABLED` are honoured |

Split-mode variables are listed under [Split mode](#split-mode).

### PII NER model (`ner` feature)

The L1 detector is off by default, so the workspace builds without ONNX Runtime.

```sh
cargo build -p caliban --features ner
```

Fetch and verify the model with [`scripts/fetch_pii_ner.py`](https://github.com/thecalibanproject/ml/blob/main/scripts/fetch_pii_ner.py) from the ml repo, then set `CALIBAN_PII_NER_DIR` to the artifact directory. If the variable is set and the artifact fails hash verification, or the binary was built without `ner`, Caliban refuses to start rather than run without the detector. The `ort` crate downloads a prebuilt ONNX Runtime at build time only; for air-gapped builds, set `ORT_LIB_LOCATION`. Model choice, licences and the open licence item are in [`crates/caliban-pii/MODELS.md`](crates/caliban-pii/MODELS.md).

#### Inference pool and backpressure

Model inference costs milliseconds of CPU per request, so it never runs on the async runtime that serves HTTP:

- **Workers.** A fixed set of dedicated threads (`caliban-pii-N`), one per ONNX session. Each session holds its own copy of the weights (about 100 MB for the int8 models). Defaults: `min(cores / 2, 4)` sessions (`CALIBAN_PII_NER_SESSIONS`) of 2 intra-op threads each (`CALIBAN_PII_NER_THREADS`). With every session busy, inference can use `2 x sessions` cores, which is all of an 8-vCPU host; on such a host (x86) 2 threads per session cut a request from 43 to 30 ms and raised throughput from 96 to 103 req/s against 1 thread, and requests with PII off stayed at 1.7 ms p50 while NER saturated the pool (`bench/RESULTS-aws-2026-10b.md`, section 7). To keep cores free for other work, lower the threads to 1; to save memory, lower the sessions (sessions matter more than threads once requests queue: 2 sessions of 2 threads gave 71 req/s against 103 for 4 of 2). ONNX Runtime's spin-waiting is off, so idle sessions do not burn cores. Requests with PII off, and engines without the model, never touch the pool.
- **Hardware.** For NER-heavy tenants, prefer recent x86 CPUs with AVX-512 VNNI or AMX (for example AWS c7i, Sapphire Rapids) over Arm (Graviton4): with the same build and int8 model on 8 vCPU, one request took 43 ms against 77 ms (1.8 times faster), throughput saturated at 96 against 41 req/s, and with 2 threads per session x86 reached 29.7 ms and 103 req/s. The prebuilt ONNX Runtime likely lacks fast int8 kernels on aarch64 (not profiled).
- **Bounded queue.** At most `CALIBAN_PII_NER_QUEUE` requests (default 128) wait for a worker. A request whose client disconnects while it waits is dropped without running the model.
- **When the queue is full**, a request waits up to `CALIBAN_PII_NER_QUEUE_WAIT_MS` (default 0) for a slot, then `CALIBAN_PII_NER_OVERFLOW` applies:
  - `reject` (default): **fail closed.** The request gets `503` with `retry-after: 1` (OpenAI `type: overloaded`, Anthropic `overloaded_error`) and nothing is sent upstream. This is the right default for a privacy gateway: the alternative sends text upstream that the model has not screened.
  - `degrade`: the request is screened by the regex tier only (emails, phone numbers, cards, IBANs, credentials and the tenant dictionaries) and goes upstream. **Names, organisations and places are then not pseudonymised.** Only choose this when availability matters more than screening for every request; each degraded request is logged at `warn` and marked `caliban.pii.degraded` on its `pii` span.

A model failure (as opposed to a full queue) always blocks the request with `403`, whatever the policy. An unknown `CALIBAN_PII_NER_OVERFLOW` value, or a non-numeric size, refuses to start.

### Shared quotas (Valkey)

By default each router keeps its quota state in memory, which is exact for one router but lets N routers admit up to N times the limit. With `[limits] store = "valkey"`, every router of a deployment shares one Valkey (8 or 9; any RESP server with Lua scripting works) and enforces the same rate limits and budgets.

```toml
[limits]
store = "valkey"
valkey_key_prefix = "caliban"   # default; give each deployment its own if they share a Valkey
valkey_timeout_ms = 30          # default
requests_per_minute = 600
tokens_per_day = 20000000
```

- **Connection.** `CALIBAN_VALKEY_URL` (required) and optionally `CALIBAN_VALKEY_PASSWORD`. `rediss://` enables TLS (rustls), verified against the platform trust store; add a private CA with `SSL_CERT_FILE`. One multiplexed connection per router, reconnected automatically. `store = "valkey"` without the URL refuses to start; the store setting is read when the router starts.
- **Atomicity.** Each quota operation is one Lua script run on the server (`EVALSHA`, with `EVAL` when the server's script cache is cold): GCRA for the tenant and key rates (all or nothing), reserve (checks tokens/day, USD/day and the minute bucket, then reserves), and settle (swaps the reservation for actual usage: refund, or debt when the estimate was low). Concurrent routers cannot double-spend. Scripts use the server clock, so router clock skew does not matter.
- **Keys.** `<prefix>:{<tenant>}:rpm`, `…:key:<key hash>:rpm`, `…:tpm` and `…:day`. The braces are a cluster hash tag, so one tenant's keys share a slot. Every key has a TTL: rate keys expire once their theoretical arrival time passes, minute buckets once refilled, day counters after the UTC day.
- **Failure policy: fail open on shared state, never unlimited.** Each call waits at most `valkey_timeout_ms`. On an error or timeout the router serves that call from its own in-memory limiter with the same limits, and for the next 2 s skips Valkey entirely (no added latency); then one call probes Valkey again, and shared limits resume when it answers. A `429` from Valkey is final. During an outage each router enforces the full limits on its own (so the deployment-wide ceiling is up to N times the limit), local day budgets start from zero, and settlements of reservations made in Valkey are skipped, so those stay charged (conservative). The router logs one warning when it degrades, at most one every 30 s after that, and one line when Valkey is back; `GET /healthz` shows `quota.state` (`ok` or `degraded`), the last error, and counters for local fallbacks and lost settlements.
- **Latency.** Three round trips per request (rate check, reserve, settle). Measured on a laptop through Docker Desktop's port forwarding (release build, sequential): p50 0.6 to 0.8 ms and p99 2 to 3 ms, the same as three bare `PING`s on that path; the in-memory store costs about 1 µs. Same-host or same-zone Valkey on Linux is faster.

### Idempotency-Key

`POST /v1/chat/completions`, `/v1/messages`, `/v1/embeddings` and `/v1/rerank` honour an `Idempotency-Key` header (1 to 255 visible ASCII characters), so a client can retry without being charged twice ([`crates/caliban-gateway/src/idempotency.rs`](crates/caliban-gateway/src/idempotency.rs)). Records are per tenant and key:

| Situation | Response |
|---|---|
| First request with the key | Runs. It runs to completion even if the client disconnects (a stream is read to its end), so the retry can be answered from the record. |
| Same key while the first is still running | `409`, `Retry-After: 1`, code `idempotency_key_in_use`. The gateway does not hold the duplicate open: a stream can take minutes. |
| Same key after a `2xx` (within 24 h) | The stored response: same status, headers and body, plus `Idempotent-Replayed: true`. Streams are stored as sent (every SSE event, after rehydration) and replayed as one SSE body. Nothing runs upstream, no usage event is recorded and no quota is used. |
| Same key, different method, path or body | `422`, code `idempotency_key_reused`. |
| The first request failed (non-`2xx`, or a stream that ended with an error event or without its final event) | The key is freed; the retry runs again. |
| The first response was over 4 MiB | Not kept; duplicates get `409`, code `idempotency_response_not_stored`. |

Records live in Valkey when `[limits] store = "valkey"` (keys `<prefix>:idem:{<hash of tenant and key>}`, one Lua script each to claim, complete and release; shared by all routers), otherwise in the router's memory (256 MiB budget, oldest completed records dropped first). While Valkey is unreachable, keys are deduplicated by the router that sees them, as quotas are limited locally. A claim whose router dies expires after 15 minutes. A replay carries the original `x-caliban-request-id`. Without the header nothing changes.

### Tenant offboarding (semantic cache)

Deleting a tenant on the control plane removes it from the next data-plane snapshot. Each data plane checks its snapshot every 2 s, and when a tenant id disappears it deletes that tenant's entries from every collection of its semantic cache (`{collection_prefix}_*`, so entries written under an earlier `embedding_model` go too).

- **Why the data plane.** The control plane holds no semantic cache: in split mode it never talks to the vector store (`CALIBAN_QDRANT_URL` is a data-plane setting), and an in-memory store lives inside each router. Every router already learns about a delete from its snapshot: in `standalone`, the control plane publishes the post-delete state into the snapshot the data plane reads; in split mode, routers apply it with their next poll. The same code path covers both, and both stores.
- **Idempotent and retried.** With Qdrant every router purges the same tenant; a second purge deletes nothing. A purge that fails (store unreachable) is retried every 2 s until it succeeds.
- **Gap.** Only a router running when the snapshot changes triggers the purge. If no router is up at that moment, the tenant's entries stay until they expire (`ttl_secs`). Tenant ids are never reused, so such entries can never be served to another tenant.

### Control-plane store

`CALIBAN_DATABASE_URL` set means Postgres; unset means in-memory (for development and demos). The startup log says which, and so does `GET /api/v1/health` (field `store`).

With Postgres, the config file seeds the database **once**, on the first start against an empty database (marker row `cp_meta.seeded_at`). From then on the database is the source of truth for tenants, API keys, BYOK credentials, shared providers, models, routes, datasources, nodes and the ontology: `[[tenants]]`, `[[models]]` and `[[providers]]` in the file are ignored (and the startup log says so). All other sections (`[server]`, `[security]`, `[cache]`, `[pii]`, `[limits]`, …) always come from the control plane's file and are shipped to split-mode routers inside the snapshot. Without Postgres, the file seeds memory at every start.

Every mutation is one transaction: apply the change, render and validate the data-plane config (an invalid result, such as deleting a model a route uses, rolls back with 409 or 422), append an `audit_log` row (`hash = sha256(prev_hash ‖ canonical row)`, append-only trigger), commit. `GET /api/v1/audit?limit=` returns the newest rows and `chain_verified`. BYOK keys and datasource credentials are sealed under the tenant's data key before they reach the store (see [Secrets and keys](#secrets-and-keys)); `{env}` and `{file}` references from the file are stored as references.

Deletes keep what audit needs and drop secrets. A revoked API key keeps its row (`revoked_at`); a deleted tenant stays as a tombstone (`status = 'deleted'`, `deleted_at`), and its audit rows are never touched; deleted datasources and nodes keep their rows (`deleted_at`). A deleted tenant's `provider_credential` rows (the sealed BYOK ciphertext) and its `tenant_dek` row (its data key, which crypto-shreds everything sealed under it) are deleted in the same transaction, and a deleted datasource's `connection` is replaced with `{}`. Triggers make revocations and tombstones final. Revoked keys and deleted tenants are left out of the rendered snapshot: in `standalone` the data plane rejects them on the next request, and a split-mode router rejects them once it applies its next snapshot poll. With the in-memory store, the config file reseeds tenants and keys at every start, so a revoked config-file key is valid again after a restart until its hash is removed from the file.

Several control-plane replicas can share one database. Writes are serialised with an advisory lock, and each replica reloads when the audit head moves (every 5 s, and on every snapshot request). The control plane connects as the schema owner (or a `BYPASSRLS` role); row-level security policies apply to tenant-scoped roles.

### Admin access (SSO and roles)

The control plane logs people in through the customer's own OpenID Connect provider (Keycloak, Entra ID, Okta, ADFS, Authentik, Dex, ...) and contacts nothing else. It acts as the backend for the console: authorization code flow with PKCE, ID token validation (signature through a cached JWKS that follows key rotation, issuer, audience, nonce, expiry with clock skew), and a server-side session in an `HttpOnly`, `SameSite=Strict` cookie with absolute and idle expiry, revocation and CSRF tokens. Access tokens from the same issuer for `api_audience` work as bearer tokens for CI and scripts. The bootstrap token stays as break-glass (owner rights, every use audited when SSO is on, `break_glass = false` turns it off).

Roles: `owner`, `admin` and `auditor` for the whole deployment; `tenant_admin`, `developer`, `viewer` and `billing` per tenant. They come from IdP groups (`[[security.oidc.role_mappings]]`) and from bindings to users or groups stored through `/api/v1/role-bindings`. Every admin route has an explicit permission and anything without one is refused; lists only show the tenants the caller may see. The audit actor is the user (`email <issuer#subject>`), and logins, logouts, failed logins and role changes are audited in the same hash chain.

[docs/sso.md](docs/sso.md) has the full route to permission table, the configuration, and setup guides for Keycloak and Microsoft Entra ID. `scripts/sso-dex-smoke.sh` logs in against a throwaway Dex container.

### Secrets and keys

```text
KEK keyring   CALIBAN_KEK (current) + CALIBAN_KEK_PREVIOUS (retired, open only)
  └─ tenant data key (DEK), one per tenant, stored wrapped in tenant_dek
       AES-256-GCM, associated data = tenant id + KEK id
       └─ the tenant's secrets: BYOK provider keys, datasource credentials
            AES-256-GCM, associated data = tenant id
```

- **KEK ids.** A KEK is identified by a fingerprint (`kek_` + 16 hex characters of a SHA-256 over the key), never by a name or number you have to manage. `tenant_dek.kek_id` records which KEK wraps each data key.
- **Data keys.** A tenant gets a random 256-bit DEK with its first secret (audited as `tenant_key.create`, KEK id only). Deleting the tenant deletes the DEK in the same transaction (`tenant.delete` records `tenant_key_destroyed`). Wrapping binds the DEK to the tenant and the KEK id, and sealing binds each secret to the tenant, so a ciphertext copied to another tenant's row does not open.
- **BYOK keys** are sealed under the DEK and never returned (the API shows `last4`). Shared provider keys belong to no tenant and are sealed directly under the current KEK.
- **Datasource credentials.** Values of credential fields (`password`, `api_key`, `client_secret`, `token`, `private_key`, `credentials`, `connection_string`, ...), URIs with a password (`mongodb://user:pw@host`), secret query parameters and `Password=...;` pairs are sealed under the DEK as `{"$sealed": ...}`. `{"env": ...}` and `{"file": ...}` references stay references. Responses show the redacted form (`mongodb://user:****@host`, `****`).
- **Routers.** The signed snapshot carries each BYOK key as a self-contained envelope (`tenant_sealed`: tenant, KEK id, wrapped DEK, ciphertext) that a router opens per request with its own keyring. The trust model is unchanged: routers hold the KEK, keys never travel in clear, and the control plane never sends a plaintext DEK.
- **Migration.** Migration `0008` adds `provider_credential.sealed_by`. On every start the control plane (with `CALIBAN_KEK` set) re-seals BYOK keys still sealed directly under the KEK by earlier releases, and seals datasource credentials stored in clear, under tenant DEKs. It is idempotent (nothing to do means no write and no audit row), runs as one audited transaction (`keys.migrate`), and anything it cannot open is logged and left for `caliban keys status`. `caliban keys rotate` performs the same migration.

#### KEK rotation

Rotating the KEK is what makes a deleted tenant unrecoverable from older backups: those backups hold its wrapped DEK, which opens only with the KEK that wrapped it. The procedure (Postgres store):

1. `caliban gen-kek` for a new key. On every router and control plane set `CALIBAN_KEK=<new>` and `CALIBAN_KEK_PREVIOUS=<old>`, and restart the routers first, then the control planes. Everything keeps working: retired keys still open what they wrap.
2. Run `caliban keys rotate` once (for example `docker compose exec control-plane caliban keys rotate`, or `kubectl exec` into a control-plane pod). It re-wraps every live DEK and re-seals shared provider keys under the new KEK, in one audited transaction, and refuses to start if anything cannot be opened.
3. `caliban keys status` (or `GET /api/v1/keys/status`) shows `"previous_keks_still_needed": []` once stored data no longer needs the old KEK, and `"routers_on_previous_keks": []` once every active router serves the re-wrapped snapshot; `rotation_complete` is true when both hold. Then remove `CALIBAN_KEK_PREVIOUS` everywhere and restart. `routers_without_current_kek` lists routers that still lack the new KEK (step 1 not done there).
4. Destroy the old KEK when your backup retention allows (below).

The trade-off: after rotation, every backup taken before it needs the retired KEK for **every** tenant, not only the deleted one, because all DEKs in it are wrapped by the old key. Keep a retired KEK (offline, like the current one) only as long as you keep backups that predate the rotation, and destroy it when the last of them expires. If you destroy it earlier, restoring such a backup restores tenants whose BYOK keys, datasource credentials and shared provider keys cannot be opened: delete and re-enter them after the restore. To shred a deleted tenant promptly, rotate right after deleting it and shorten the retention of older backups accordingly.

The PII surrogate keys and the per-tenant `cache_salt` are derived from the current KEK, so a rotation changes them (cache misses only, no data loss). Values written as `{ sealed = "..." }` in the config file are not rewritten by `keys rotate`; keep their KEK in `CALIBAN_KEK_PREVIOUS` or replace them with `{ env }` or `{ file }` references. The in-memory store keeps nothing across restarts, so `caliban keys` needs `CALIBAN_DATABASE_URL`.

### Split mode

In split mode, routers run without a config file and poll the control plane for signed snapshots.

```sh
caliban gen-signing-key      # prints CALIBAN_SNAPSHOT_SIGNING_KEY=… and CALIBAN_SNAPSHOT_PUBLIC_KEY=…

# control plane
CALIBAN_DATABASE_URL=postgres://… CALIBAN_SNAPSHOT_SIGNING_KEY=… CALIBAN_ROUTER_TOKEN=… CALIBAN_KEK=… \
  caliban control-plane

# each router (same CALIBAN_KEK, and CALIBAN_KEK_PREVIOUS during a rotation, to open BYOK keys)
CALIBAN_SNAPSHOT_PUBLIC_KEY=… CALIBAN_ROUTER_TOKEN=… CALIBAN_KEK=… \
  caliban router --control-plane-url http://cp:8081 --snapshot-cache /var/lib/caliban/snapshot.json
```

`GET /api/v1/snapshot` (router token, not the admin token) returns `{key_id, payload, signature}`. The payload is base64 of `{version, issued_at_ms, config, kek_ids}`, signed with Ed25519 (domain-separated). `kek_ids` names the KEKs (`kek_` fingerprints) that sealed the snapshot's secrets: the KEK of each `tenant_sealed` envelope, and of each value sealed directly under a KEK. The ETag is the config digest, so a router sending `If-None-Match` gets `304` while nothing has changed. A router verifies the signature, validates the config, refuses snapshots issued before the one it serves (anti-rollback), then swaps the new one in.

**Router check-in.** With every poll a router sends its id (`CALIBAN_ROUTER_ID`, else its host name), the version and `kek_ids` of the snapshot it serves, and its own keyring ids (`x-caliban-router-*` headers; after applying a new snapshot it polls once more right away to report it). The control plane records them (Postgres table `router_status`, migration `0011`; at most one write a minute per router while nothing changes) for `caliban keys status`. The router also shows them on `/healthz` (`snapshot`) and `/metrics` (`caliban_snapshot_info`). Telemetry only: a failed write never fails the poll.

**Fail-static.** On any error (control plane down, bad signature, invalid config) the router logs it and keeps serving its last good snapshot. With `CALIBAN_SNAPSHOT_CACHE`, that snapshot is persisted (mode 0600, re-verified on load), so a router restarted while the control plane is down still serves. Sealed secrets stay sealed inside the snapshot (BYOK keys as tenant envelopes, opened with the router's keyring); `{env}` and `{file}` references resolve on the router host. When a release adds config fields, upgrade routers before the control plane.

| Variable | Where | Meaning |
|---|---|---|
| `CALIBAN_SNAPSHOT_SIGNING_KEY` | control plane | Base64 32-byte Ed25519 seed (`caliban gen-signing-key`) |
| `CALIBAN_ROUTER_TOKEN` | control plane and routers | Bearer token for `GET /api/v1/snapshot` |
| `CALIBAN_SNAPSHOT_PUBLIC_KEY` | routers | Base64 public key; a comma-separated list allows rotation |
| `CALIBAN_CONTROL_PLANE_URL` | routers | Same as `--control-plane-url` |
| `CALIBAN_SNAPSHOT_POLL_SECS` | routers | Poll interval, default 10 (±20% jitter) |
| `CALIBAN_SNAPSHOT_CACHE` | routers | Path for the last good signed snapshot |
| `CALIBAN_ROUTER_ADDR` | routers | Listen address in split mode, default `0.0.0.0:8080` |
| `CALIBAN_ROUTER_ID` | routers | Id reported to the control plane (default: the host name, `HOSTNAME`) |

#### Usage shipping

Routers deliver their usage events to the control plane, so `GET /api/v1/usage` and its billing totals (`billed_usd`, `saved_usd`, `auto_cache_hits`, `margin_usd`, ...) include all router traffic.

- **Endpoint.** `POST /api/v1/usage/ingest` on the control plane, with the router token (the snapshot's credential, not the admin token): `{router_id, events: [UsageEvent]}`, at most 5,000 events, answered with `{accepted, duplicates, rejected}`.
- **At least once, never billed twice.** The control plane stores each `request_id` once (Postgres: `usage_event` primary key with `ON CONFLICT DO NOTHING`; memory store: the last 200,000 ids), so a batch sent again after a lost acknowledgement, a timeout or a router restart counts once, whichever control-plane replica receives it. Invalid events (empty or oversized ids) are refused and counted (`rejected`), never retried.
- **Batching.** A router sends a batch when `CALIBAN_USAGE_SHIP_BATCH` events (default 500, at most 5,000) are waiting, or `CALIBAN_USAGE_SHIP_INTERVAL_MS` (default 1,000) after the first event of a batch. The request path only enqueues (`CALIBAN_USAGE_SHIP_QUEUE`, default 10,000 events; when full, the event is dropped and counted, the request never waits).
- **Control plane down: fail-static, nothing lost.** The router keeps serving. Undelivered batches go to a spool, one JSONL file per batch (mode 0600, directory 0700) in `CALIBAN_USAGE_SPOOL_DIR` (default: `usage-spool` next to `CALIBAN_SNAPSHOT_CACHE`; without either, in memory and lost on restart, with a warning at startup). The spool holds `CALIBAN_USAGE_SPOOL_MAX` events (default 100,000: about 100 s of 1,000 requests per second, or a day of one per second); beyond it events are dropped, counted and logged at `warn`. Delivery is retried with exponential backoff (1 to 30 s); once the control plane answers, the spool is sent oldest first and each file is deleted after its acknowledgement (a crash in between sends it again, deduplicated). A restarted router delivers the spool it finds.
- **Graceful shutdown** (SIGTERM, Ctrl-C) sends what is queued for up to 5 s; what cannot be sent stays in the spool directory.
- **Visibility.** `/healthz` reports `usage_shipping: {delivered, duplicates, rejected, dropped, send_errors, backlog, backlog_max, spool, queue_depth, queue_capacity, last_error}`; `/metrics` has `caliban_usage_shipped_total`, `caliban_usage_ship_dropped_total`, `caliban_usage_ship_errors_total`, `caliban_usage_ship_backlog` and the duplicate and rejected counters.
- **Who computes the bill.** The router, exactly as in standalone mode: the same pipeline code fills `cost_usd`, `flat_price_usd`, `billed_usd` (the cache-hit fraction on hits) and `saved_usd` from the prices and per-tenant fraction of the snapshot it served the request under, and the control plane stores them as received. Recomputing on the control plane would need what only the router saw (the cached answer's token counts on a hit, the routed model) and would price events delivered after an outage at whatever price applies at delivery time, not the one that applied when the request was served. Routers are already trusted with the KEK and with enforcing quotas.
- **Stores.** With Postgres, `GET /api/v1/usage` reads `usage_event` (events newest first, totals aggregated in SQL), so every control-plane replica sees every router and totals survive restarts; a standalone process ships its own events there through the same batching (at most `CALIBAN_USAGE_SHIP_INTERVAL_MS` behind). With the in-memory store, totals cover the process's last 10,000 events, the router events included.
- `CALIBAN_USAGE_SHIP=false` keeps events on the router (WAL and ring) as before; the control plane then does not bill them. A control plane of an earlier release answers `404`; the router keeps those events in its spool and retries until the control plane is upgraded, so upgrade both in the same window (routers first, as usual).


## Testing

```sh
cargo test                   # unit tests in every crate; Docker-backed tests skip themselves
cargo clippy --all-targets
./scripts/smoke.sh           # end to end: real binary + mock upstream (honours CARGO_TARGET_DIR)
./scripts/split-smoke.sh     # split mode: Postgres (Docker) + control-plane + router processes
./scripts/mongo-it.sh        # MongoDB connector + CDC replica against a real replica set (Docker)
./scripts/bench.sh           # P0 measurement suite: overhead benchmark, isolation audit, usage accuracy

# The isolation audit and usage-accuracy check alone (also part of plain `cargo test`):
cargo test -p caliban --test isolation
cargo test -p caliban --test usage_accuracy

# Valkey quota and Idempotency-Key tests (the memory stores' suites plus concurrency, TTL and outage tests):
docker run -d --rm -p 56379:6379 --name caliban-valkey-test valkey/valkey:9.1.2
CALIBAN_TEST_VALKEY_URL=redis://127.0.0.1:56379 cargo test -p caliban-meter -- --nocapture quota:: idempotency::

# Postgres store parity tests (the memory store's suite, run against Postgres), and SSO sessions
# shared by two control-plane replicas:
docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=x --name caliban-pg-test postgres:17-alpine
CALIBAN_TEST_DATABASE_URL=postgres://postgres:x@127.0.0.1:55432/postgres cargo test -p caliban-cp

# Semantic cache against a real Qdrant (tenant isolation, TTL, learning, latency):
docker run -d --rm -p 56333:6333 --name caliban-qdrant-test qdrant/qdrant:v1.19.1-unprivileged
CALIBAN_TEST_QDRANT_URL=http://127.0.0.1:56333 cargo test -p caliban-cache --test qdrant -- --nocapture
CALIBAN_TEST_QDRANT_URL=http://127.0.0.1:56333 cargo test --release -p caliban-gateway semantic_miss_latency -- --nocapture
# Routing latency report; CALIBAN_TEST_PERF=1 also enforces the 25 ms kNN p99 budget (plain
# `cargo test` only prints it, so a loaded machine does not fail the run):
CALIBAN_TEST_PERF=1 cargo test --release -p caliban-gateway knn_latency -- --nocapture
```

- **Valkey quota tests** ([`crates/caliban-meter/src/quota/store_tests.rs`](crates/caliban-meter/src/quota/store_tests.rs)) run one behavioural suite against the in-memory store and, with `CALIBAN_TEST_VALKEY_URL`, against Valkey. The Valkey-only tests check that 400 concurrent calls through two store instances never exceed a rate or a day budget, that reserve and settle from two instances leave the server counters at exactly the actual usage, that idle keys expire, that a cut connection (a TCP proxy in front of Valkey) falls back to local limits and recovers with the shared state intact, and print the added latency. Without the variable they print a skip message and pass.
- **`scripts/smoke.sh`** runs `caliban standalone` against `scripts/mock_upstream.py`. It checks that PII never reaches an external model, responses and streams are rehydrated, sovereign models get raw text, the exact cache hits, credentials in prompts are blocked, the semantic cache (in-memory store) serves a rephrased question, replays it as a stream and keeps it from another tenant, the Anthropic Messages API works (translated and native passthrough), rate limits return `429` with `retry-after`, keys and BYOK credentials created through the control plane work on the data plane, and a revoked key or a deleted tenant's key gets `401`. Needs `python3`, `curl` and `shasum`. With `CALIBAN_PII_NER_DIR` set, it builds with `ner` and adds name-protection checks.
- **Tenant offboarding** ([`apps/caliban/src/purge_tests.rs`](apps/caliban/src/purge_tests.rs), part of `cargo test`): with the in-memory control-plane store and the in-memory vector store, a tenant deleted through the admin API has its semantic-cache entries purged from every collection, in `standalone` (shared snapshot) and in split mode (after the router applies the next signed snapshot), and other tenants' entries stay.
- **`scripts/split-smoke.sh`** checks that the control plane seeds Postgres and signs snapshots; that a router with no config file picks up a tenant, key and BYOK credential created on the control plane within the poll interval; that the audit chain verifies; that killing the control plane leaves the router serving; that a router restarted while the control plane is down serves from its snapshot cache; that a restarted control plane keeps its state; and that a key revoked and a tenant deleted on the control plane get `401` from the router after its next poll. Needs Docker, `python3` and `curl`. Set `SPLIT_DATABASE_URL` to use an existing database.
- **`scripts/bench.sh`** measures the P0 exit criteria (reference architecture section 8) and writes `bench/results/REPORT.md`; the latest numbers and their caveats are in [`bench/RESULTS.md`](bench/RESULTS.md) (laptop) and [`bench/RESULTS-aws-2026-10.md`](bench/RESULTS-aws-2026-10.md) (Linux on AWS, plus the GPU tier with a real model, embedding latency, intent kNN accuracy and semantic-cache thresholds). It builds release binaries, starts the Rust mock upstream (`bench/`, binary `mock-upstream`: OpenAI Chat Completions and Anthropic Messages, streaming and not, fixed latency, deterministic usage) and `caliban standalone` with a generated config, then measures latency through the gateway and direct to the mock at concurrency 1, 16 and 64 with the `caliban-bench` load generator (HDR histograms, warm-up, interleaved rounds). Scenarios: non-streaming and streaming chat (time to first byte and total) with PII off and on (regex tier), the exact-cache hit path, native Anthropic passthrough, streams paced like a real model, the usage WAL, and the NER tier when `CALIBAN_PII_NER_DIR` is set (a `ner` build is made for it; otherwise those rows are reported as skipped). Overhead is reported as gateway minus direct at p50, p90, p99 and max. Knobs: `QUICK=1`, `BENCH_CONCURRENCY`, `BENCH_REQUESTS`, `BENCH_WARMUP`, `BENCH_PACED_REQUESTS`, `BENCH_OUT`. Needs only cargo. To put the load generator on another host, run `caliban-bench --serve ep.json --bind 0.0.0.0 --advertise <host>` (optionally `--mock-ports`, `--gateway-ports`) next to the gateway and `caliban-bench --remote ep.json` on the load host. For profiling, `cargo build --profile profiling -p caliban` keeps symbols.
- **`apps/caliban/tests/isolation.rs`** runs the real binary against the mock with two tenants and a shared pool, and proves that a tenant key cannot list or use another tenant's models, routes, BYOK credentials or restricted shared pools (also under interleaved concurrent load); that exact-cache entries seeded by one tenant miss for the other on an identical prompt; that the per-tenant `cache_salt` differs across tenants, is stable per tenant and across restarts with the same `CALIBAN_KEK`, and that the mock's salted prefix cache gives the other tenant no `cached_tokens` signal; that usage events (WAL and `/api/v1/usage`) are attributed only to the caller; that PII surrogates differ per tenant and one tenant's surrogate is never rehydrated to another tenant's original; that revoked keys and a deleted tenant's keys get `401` on every data-plane endpoint; and that every admin route rejects tenant keys.
- **`apps/caliban/tests/usage_accuracy.rs`** sends a varied sequential workload (both dialects, streams including `include_usage: false`, translation both ways, native Anthropic with `cache_control` at both TTLs, provider prefix-cache hits, exact-cache hits, fallbacks, PII) and pairs each usage event with the mock's bill for that request: prompt, completion, cache-read and cache-write tokens must match exactly with `usage_source: "provider"`, and cost must equal the bill with the provider's prompt-cache pricing. It also checks that clients that did not ask for stream usage get none while the event is still exact, and that a client disconnect is metered as an estimate below what the provider billed.
- **Gateway metering tests** ([`crates/caliban-gateway/src/metering_tests.rs`](crates/caliban-gateway/src/metering_tests.rs)) cover the same behaviour in process: usage requested upstream and stripped for the client, disconnects on both stream paths, a model that rejects `stream_options`, and cache-priced cost through the header, the event and the WAL. The WAL writer has its own tests in `caliban-meter` (order, replay of old and new lines, rotation, drops never blocking).
- **`scripts/mongo-it.sh`** starts `mongo:8` as a single-node replica set with auth (container `caliban-mongo-test`, port 27018), runs `cargo test -p caliban-replica --test mongo_it -- --nocapture`, then removes the container. The test ([`crates/caliban-replica/tests/mongo_it.rs`](crates/caliban-replica/tests/mongo_it.rs)) seeds `orders` (embedded `lines`, `customerId` references) and `customers`, creates a read-only user, and checks that:
  1. `verify_read_only` accepts the `read`-role user and refuses the admin user, and the replica set is detected;
  2. introspection and `bootstrap::propose` find `Order`, `OrderLine` (embedded), `Customer`, the attribute bindings, and `Order.customer_id->Customer`;
  3. the reference CQIR query, compiled with `plan` and `mongo::lower`, passes the `explain` gate (IXSCAN on `createdAt_1`; a COLLSCAN query is rejected under a strict policy) and runs natively with a row cap;
  4. after a replica snapshot, `sql::lower` output on DataFusion returns **the same rows as the native lane** for three query shapes;
  5. inserts, updates (`$set`, and `$push` into the embedded array) and deletes flow through the change stream, the replica converges to the native answer, and the watermark advances.

  Knobs: `CALIBAN_MONGO_IMAGE` (for example `mongo:7`), `CALIBAN_MONGO_TEST_PORT`, `CALIBAN_MONGO_CONTAINER`, and `KEEP=1` to keep the container. Without `CALIBAN_MONGO_TEST_URI` the test prints a skip message and passes, so plain `cargo test` needs no Docker.

## Status and roadmap

Known gaps:

- Usage reports with the in-memory control-plane store cover the last 10,000 events of the process (development and demos); use Postgres for billing. Usage shipping is at least once with dedupe by `request_id`: events beyond the spool bound (default 100,000 per router) or the in-memory queue are dropped and counted, and a router without a spool directory loses its undelivered events when it stops.
- Deleting a tenant destroys its data key, but Postgres keeps dead row versions until `VACUUM`, and WAL archives, backups and router snapshot caches keep copies of the wrapped key. They stay openable until the KEK is rotated and the retired KEK destroyed (see [KEK rotation](#kek-rotation)).
- KEKs come from environment variables only; PKCS#11, KMS and Vault backends are not built. Rotation re-wraps DEKs but never replaces them (a DEK lives as long as its tenant).
- Datasource credentials are detected by field name and URI shape; a secret in a field with an unusual name is stored as given (use an `{ env }` or `{ file }` reference for those).
- Revocation in split mode takes effect on the router's next snapshot poll (`CALIBAN_SNAPSHOT_POLL_SECS`, default 10 s), not instantly.
- Quotas default to in-memory per router process; set `[limits] store = "valkey"` to share them. While Valkey is unreachable each router limits on its own (see [Shared quotas](#shared-quotas-valkey)), and changing `store` needs a router restart.
- The data plane's `/metrics` covers the snapshot and usage delivery only (no request, latency or quota metrics yet), and the control plane has none.
- SSO: roles come from token claims only (no userinfo or Microsoft Graph calls, so Entra group overage is not followed); no refresh tokens, back-channel logout or multiple issuers. Another control-plane replica sees a role binding change within its 5 s refresh.
- Semantic cache: the default thresholds (0.91 with the default prefix) are calibrated for Qwen3-Embedding-0.6B on one hand-written set of 74 pairs, not per embedding model; some models place unrelated text close together (bge-small scored random-word prompts above 0.95), so calibrate on your traffic before switching tenants on. The verifier is an answer-embedding comparison, not an LLM judge (Krites-style judging of grey-zone pairs is next); thresholds are not yet per intent category (the note's category-aware caching), and there is no near-hit-as-hint tier (T2b). Datasource epochs and ACL fingerprints are not wired into T2 keys yet (no grounded answers reach it today). Entries are not encrypted per tenant. A deleted tenant's entries are purged only by routers running at the time (see [Tenant offboarding](#tenant-offboarding-semantic-cache)). No per-tenant entry quota. Internal embedding calls are not metered. The tenant error budget is per router, and concurrent stat updates to one entry are last-writer-wins. Hits replay instantly, which is a timing signal within a tenant (research note, open question 6).
- Routing: Stage 2 (ONNX classifier) and Stage 3 (LLM fallback) are not built; kNN abstentions go straight to the keyword rules. The built-in kNN defaults (k 5, temperature 0.05, abstain below 0.5, no OOS gate) are not calibrated for any particular embedder until ml ships an `intent_head` calibration for it. Model health is not tracked on the data plane yet (the policy has a hook; every model counts as healthy). Router-profile centroids are ignored (clusters are matched by intent id). Tenant exemplars come from config only, not yet from the control plane. Artifact signatures (`manifest.json.minisig`) are not checked, only file hashes.
- `usage_event` (Postgres) grows without bound: no retention, roll-up or partitioning yet. Migration `0007` adds `cache_tier`, `usage_source`, `cache_write_tokens` and `cache_write_1h_tokens` to it (next to the routing columns from `0005`) and the cache prices to `model`; `0010` adds `billed_usd` and `saved_usd` (and the tenant's `auto_cache_hit_fraction`).
- Metering estimates are byte-based (about 4 bytes per token, no tokenizer). They apply only to events marked `usage_source: "estimated"`: client disconnects (the provider may bill more than the estimate), upstream streams that fail or end without usage, and models marked `rejects_stream_options`.
- Cost needs per-model prices in the catalogue, cache prices included, and no list prices ship with Caliban. Providers that price cache reads differently per model (OpenAI, Anthropic) need the right value per model; unset cache prices meter cache tokens at the input price (with a warning).

Next, in order:

1. Control plane: push (long-poll) instead of polling (faster revocation in split mode), tenant admins granting roles on their own tenant.
2. MongoDB connector: wire `introspect` and `propose` into the control plane's introspection job; `$jsonSchema`-declared types; map and scalar-array attributes; per-shard sampling.
3. CDC replica and planner: connect the planner to the `explain` gate and replica lag in a query service; delta Parquet with compaction instead of whole-table rewrites; resume from the manifest after a restart (today it re-snapshots); parallel `_id`-range snapshots; arrays nested in arrays.
4. PII: licence sign-off on the NER model's fine-tuning data (see `MODELS.md`); FF1 format-preserving encryption for structured IDs; coreference so a first name maps to the surrogate's first name.
5. Gateway: tokenizer-based estimates, rate-limit headers on successful responses, the ONNX intent classifier (Stage 2), model health on the data plane, control-plane management of routing exemplars and floors, and for the semantic cache an async LLM judge, per-intent thresholds and per-tenant entry encryption.

## Related repositories

| Repo | What it holds |
|---|---|
| [docs](https://github.com/thecalibanproject/docs) | Reference architecture and research notes |
| [deploy](https://github.com/thecalibanproject/deploy) | Container image build, compose stack, Helm chart, air-gapped bundles, open-model serving |
| [web](https://github.com/thecalibanproject/web) | Admin console, served by the control plane |
| [sdk-typescript](https://github.com/thecalibanproject/sdk-typescript) | TypeScript SDK (Apache-2.0) |
| [sdk-python](https://github.com/thecalibanproject/sdk-python) | Python SDK (Apache-2.0) |
| [ml](https://github.com/thecalibanproject/ml) | Offline training, evaluation and ONNX export for the in-process models (embedder, intent heads, PII NER) |

## Licence

Copyright 2026 Elie Sfeir. All rights reserved.

This repository is proprietary and source-available. It is public for reference and evaluation only and is not open source. No right to use, copy, modify or distribute it is granted except under a written agreement with the copyright holder. See [LICENSE](LICENSE). For licensing, contact [elie@internalizable.dev](mailto:elie@internalizable.dev).
