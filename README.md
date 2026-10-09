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
| `GET /healthz` | Liveness, config version, and quota store state (`quota.state` is `degraded` while a shared store is unreachable; the probe still returns `200`) |

The model id `caliban/auto` lets Caliban choose: the request is classified into an intent and routed through the tenant's ordered candidates for that intent. Naming a catalogue model id pins the model, subject to the tenant's policy.

Control-plane endpoints (`:8081`) live under `/api/v1/*` and are specified in [`api/openapi.yaml`](api/openapi.yaml): tenants, tenant API keys, BYOK provider keys, routes, the model catalogue and shared providers (with health checks and model discovery), datasources and introspection, the ontology review queue, nodes, usage, the audit log, health, and signed snapshots for split-mode routers. When a built console is available (`CALIBAN_WEB_DIR` or `[server] web_dir`), it is served at `/`.

Deletes (admin token):

| Endpoint | Effect |
|---|---|
| `DELETE /api/v1/tenants/{tenantId}` | Tombstones the tenant (`status: deleted`; the id is never reused), revokes all its API keys, destroys its BYOK credentials, removes its routes, and soft-deletes its datasources and nodes |
| `DELETE /api/v1/tenants/{tenantId}/api-keys/{keyId}` | Revokes the key: the row is kept with `revoked_at`, and the key is rejected (`401`) on the data plane |
| `DELETE /api/v1/tenants/{tenantId}/provider-keys/{keyId}` | Removes a BYOK credential (`409` while a route still needs it) |
| `DELETE /api/v1/tenants/{tenantId}/datasources/{datasourceId}` | Soft-deletes the datasource and wipes its stored connection settings |
| `DELETE /api/v1/tenants/{tenantId}/nodes/{nodeId}` | Soft-deletes one node version (its version number is not reused) |
| `DELETE /api/v1/models/{modelId}`, `DELETE /api/v1/providers/{providerId}` | Removes a catalogue model or shared provider (`409` while referenced) |

Every delete returns `204` and writes one audit row. An unknown id, an id that belongs to another tenant, or one that was already deleted returns `404` in the standard error envelope, so a repeat delete is always `404` and is not audited. Revoked keys and deleted tenants are hidden from listings unless asked for (`?include_revoked=true`, `?include_deleted=true`).

### Request pipeline

One pipeline serves both API shapes. OpenAI and Anthropic requests are decoded into a canonical IR (unknown fields pass through), then:

1. **Auth and limits.** Tenant API key lookup (keys are stored as SHA-256 hashes). GCRA request rate per tenant and per key; token and USD budgets with reservation and settlement. Exceeding a limit returns `429` with `retry-after`. Quota state lives in each router's memory, or in Valkey so that all routers share it (see [Shared quotas](#shared-quotas-valkey)).
2. **PII.** L0: regexes with validators (Luhn, IBAN, SSN), tenant dictionaries, and credential detection (a prompt carrying credentials is refused). L1, optional (`ner` feature): an in-process multilingual NER model. Each tenant's `pii_mode` is `off`, `mask` or `reversible`. In `reversible` mode, values are replaced with realistic surrogates (valid Luhn and IBAN numbers) before an external model sees them, and the response, streams included, is rehydrated with a hold-back buffer. Sovereign (`t0_sovereign`) models receive the raw text.
3. **Routing.** Rules and policy (pinned model, trust tier, licence), then intent classification (a placeholder keyword classifier today), then the tenant's ordered candidates with fallbacks.
4. **Cache.** Exact cache over a canonical request hash, keyed by tenant, ACL and datasource epoch.
5. **Upstream.** BYOK calls to OpenAI-compatible servers (OpenAI, vLLM, SGLang, llama.cpp, Ollama, TEI) or to Anthropic, either as native passthrough (`cache_control` kept) or translated. `security.egress = "deny_by_default"` limits calls to declared `base_url`s. Shared vLLM and SGLang pools can receive a per-tenant `cache_salt` for prefix-cache isolation.
6. **Metering and tracing.** Usage events with cost go to an in-memory ring and, optionally, a JSONL write-ahead log. OpenTelemetry GenAI spans are exported only when configured, and prompt and response content is never recorded.

### Workspace layout

The binary is in `apps/caliban`; everything else is in `crates/`.

| Crate | Status | Role |
|---|---|---|
| `caliban-types` | Done | Ids, trust tiers, PII and cache modes, errors |
| `caliban-config` | Done | TOML config to an indexed `Snapshot` behind `ArcSwap`; secret references (`env`, `file`, and `sealed` with AES-256-GCM under `CALIBAN_KEK`); Ed25519 snapshot signing |
| `caliban-ir` | Done (OpenAI, Anthropic) | Canonical request IR, unknown-field passthrough, canonical hashing for cache keys, Anthropic Messages codecs (requests, responses, stream events), SSE parser |
| `caliban-pii` | L0 done; L1 NER done behind `ner` | Regexes and validators, tenant dictionaries, in-process multilingual NER (ONNX, MIT-licensed weights, hash-verified artifact; see [`crates/caliban-pii/MODELS.md`](crates/caliban-pii/MODELS.md)), surrogates, vault, streaming rehydration |
| `caliban-cache` | Exact cache done; semantic cache planned | Exact cache (moka) with tenant, ACL and datasource-epoch keys; semantic cache trait |
| `caliban-route` | Rules and placeholder classifier done; kNN and ONNX classifier planned | Intent to ordered candidates, trust-tier constraints, fallbacks |
| `caliban-providers` | OpenAI-compatible and Anthropic done; Bedrock and Vertex planned | BYOK upstream calls; Anthropic native passthrough or translation |
| `caliban-meter` | Done | Usage events, cost, in-memory ring and JSONL WAL; GCRA rate limits and token and USD budgets, in memory (`governor`) or shared in Valkey (atomic Lua scripts, local fallback) |
| `caliban-ontology` | Compiler done; store and retrieval planned | Caliban Semantic Model (CSM) types and the **CQIR compiler**: typed queries lowered to a MongoDB aggregation pipeline (with lint) or to SQL for the CDC replica; a pure-function lane planner |
| `caliban-connect` | MongoDB done; SQL and REST sources planned | Connector trait. MongoDB: read-only privilege check, stratified sampling into path statistics, reference discovery, ontology bootstrap (`proposed` elements), native-lane executor with an `explain` gate, epochs |
| `caliban-replica` | v1 done | CDC replica: snapshot plus change streams to Arrow and Parquet, queried with DataFusion; the watermark is the last applied `clusterTime` |
| `caliban-nodes` | Spec and budgets done; executor planned | Node (agent) spec validation (pinned tools, bounded cycles), hierarchical budget ledger |
| `caliban-rag` | Fusion and budgeting done; index planned | Reciprocal rank fusion, token-budgeted context selection |
| `caliban-mcp` | Pinning done; MCP client planned | Tool-manifest pinning against description poisoning |
| `caliban-gateway` | Done | Data-plane HTTP app: the pipeline above, embeddings, rerank, rate limits, OTel tracing |
| `caliban-cp` | Done | Control plane: admin API per `api/openapi.yaml`, in-memory and Postgres stores, hash-chained audit log, signed snapshots for split-mode routers, web console hosting |

### Contracts owned here

- [`api/openapi.yaml`](api/openapi.yaml): the HTTP contract used by [web](https://github.com/thecalibanproject/web), [sdk-typescript](https://github.com/thecalibanproject/sdk-typescript) and [sdk-python](https://github.com/thecalibanproject/sdk-python).
- [`schemas/node.schema.json`](schemas/node.schema.json): the node spec, vendored by the SDKs and the web app.
- [`config/caliban.example.toml`](config/caliban.example.toml): the config format, used by [deploy](https://github.com/thecalibanproject/deploy). [`config/open-models.example.toml`](config/open-models.example.toml) is a complete on-prem config with a catalogue of open-weight models.
- [`migrations/`](migrations): the control plane's Postgres schema, embedded in the binary and applied at start-up. Applied migrations are checksummed in `caliban_schema_migrations`, and the binary refuses to start if one was edited: add a new `000N_*.sql` file and list it in `crates/caliban-cp/src/store/postgres.rs`. Tested against Postgres 17.

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

The admin API listens on `:8081` with `CALIBAN_ADMIN_TOKEN` as bearer token. Without `CALIBAN_DATABASE_URL` the control plane uses an in-memory store seeded from the config file, so changes made through the API are lost on restart.

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
| `caliban gen-signing-key` | New Ed25519 snapshot signing key (control plane) and its public key (routers) |
| `caliban healthcheck [--addr 127.0.0.1:8080] [--path /healthz]` | Exit 0 on a 2xx response, 1 otherwise; for container healthchecks in the shell-less image |

Global flags: `--config` (`CALIBAN_CONFIG`, default `/etc/caliban/caliban.toml`) and `--usage-wal` (`CALIBAN_USAGE_WAL`: append usage events to a JSONL file).

## Configuration

### Config file

[`config/caliban.example.toml`](config/caliban.example.toml) is annotated. Its sections:

- `[server]`: `router_addr`, `control_plane_addr`, `web_dir`.
- `[security]`: `egress = "deny_by_default"` and `admin_token`.
- `[cache]`: exact cache on or off, size and TTL.
- `[pii]`: `default_mode` (`off`, `mask` or `reversible`).
- `[limits]` and `[limits.tenants.<id>]`: `requests_per_minute`, `key_requests_per_minute`, `tokens_per_minute`, `tokens_per_day`, `usd_per_day`. Unset means unlimited. `[limits]` also takes `store` (`memory` or `valkey`), `valkey_key_prefix` and `valkey_timeout_ms` (see [Shared quotas](#shared-quotas-valkey)).
- `[[providers]]`: deployment-wide model servers shared by tenants (see `open-models.example.toml`).
- `[[models]]`: the catalogue (provider, `upstream_model`, trust tier, licence, context window, prices, capabilities).
- `[[tenants]]`, with `[[tenants.providers]]` (BYOK) and `[[tenants.routes]]` (intent to ordered models).

Secrets are never written inline: use `{ env = "VAR" }`, `{ file = "/path" }`, or a value sealed under `CALIBAN_KEK`. Trust tiers run from `t0_sovereign` to `t3_public`.

### Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `CALIBAN_CONFIG` | all | Config file path (default `/etc/caliban/caliban.toml`) |
| `CALIBAN_ADMIN_TOKEN` | control plane | Admin bearer token, unless `[security] admin_token` resolves it another way |
| `CALIBAN_KEK` | all | Base64 32-byte key-encryption key: seals and opens BYOK keys, derives the cache-salt key |
| `CALIBAN_DATABASE_URL` | control plane | Postgres store; unset means in-memory |
| `CALIBAN_VALKEY_URL` | data plane | Valkey for shared quotas, required with `[limits] store = "valkey"`: `redis://[:password@]host:6379[/db]`, or `rediss://` for TLS |
| `CALIBAN_VALKEY_PASSWORD` | data plane | Valkey password, if it is not in the URL (overrides the URL's) |
| `CALIBAN_WEB_DIR` | control plane | Built web console (overrides `[server] web_dir`) |
| `CALIBAN_USAGE_WAL` | data plane | JSONL usage log path |
| `CALIBAN_LOG` | all | Log filter (default `info,tower_http=info`) |
| `CALIBAN_PII_NER_DIR` | data plane | Verified NER artifact directory; needs a `ner` build |
| `CALIBAN_PII_NER_SESSIONS` | data plane | Number of NER inference sessions |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | all | Turns on OTLP/HTTP trace export (off when unset). `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME` and `OTEL_SDK_DISABLED` are honoured |

Split-mode variables are listed under [Split mode](#split-mode).

### PII NER model (`ner` feature)

The L1 detector is off by default, so the workspace builds without ONNX Runtime.

```sh
cargo build -p caliban --features ner
```

Fetch and verify the model with [`scripts/fetch_pii_ner.py`](https://github.com/thecalibanproject/ml/blob/main/scripts/fetch_pii_ner.py) from the ml repo, then set `CALIBAN_PII_NER_DIR` to the artifact directory (and optionally `CALIBAN_PII_NER_SESSIONS`). If the variable is set and the artifact fails hash verification, or the binary was built without `ner`, Caliban refuses to start rather than run without the detector. The `ort` crate downloads a prebuilt ONNX Runtime at build time only; for air-gapped builds, set `ORT_LIB_LOCATION`. Model choice, licences and the open licence item are in [`crates/caliban-pii/MODELS.md`](crates/caliban-pii/MODELS.md).

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

### Control-plane store

`CALIBAN_DATABASE_URL` set means Postgres; unset means in-memory (for development and demos). The startup log says which, and so does `GET /api/v1/health` (field `store`).

With Postgres, the config file seeds the database **once**, on the first start against an empty database (marker row `cp_meta.seeded_at`). From then on the database is the source of truth for tenants, API keys, BYOK credentials, shared providers, models, routes, datasources, nodes and the ontology: `[[tenants]]`, `[[models]]` and `[[providers]]` in the file are ignored (and the startup log says so). All other sections (`[server]`, `[security]`, `[cache]`, `[pii]`, `[limits]`, …) always come from the control plane's file and are shipped to split-mode routers inside the snapshot. Without Postgres, the file seeds memory at every start.

Every mutation is one transaction: apply the change, render and validate the data-plane config (an invalid result, such as deleting a model a route uses, rolls back with 409 or 422), append an `audit_log` row (`hash = sha256(prev_hash ‖ canonical row)`, append-only trigger), commit. `GET /api/v1/audit?limit=` returns the newest rows and `chain_verified`. BYOK keys are sealed with AES-256-GCM under `CALIBAN_KEK` before they reach the store; `{env}` and `{file}` references from the file are stored as references.

Deletes keep what audit needs and drop secrets. A revoked API key keeps its row (`revoked_at`); a deleted tenant stays as a tombstone (`status = 'deleted'`, `deleted_at`), and its audit rows are never touched; deleted datasources and nodes keep their rows (`deleted_at`). A deleted tenant's `provider_credential` rows (the sealed BYOK ciphertext) and `tenant_dek` row are deleted, and a deleted datasource's `connection` is replaced with `{}`. Triggers make revocations and tombstones final. Revoked keys and deleted tenants are left out of the rendered snapshot: in `standalone` the data plane rejects them on the next request, and a split-mode router rejects them once it applies its next snapshot poll. With the in-memory store, the config file reseeds tenants and keys at every start, so a revoked config-file key is valid again after a restart until its hash is removed from the file.

Several control-plane replicas can share one database. Writes are serialised with an advisory lock, and each replica reloads when the audit head moves (every 5 s, and on every snapshot request). The control plane connects as the schema owner (or a `BYPASSRLS` role); row-level security policies apply to tenant-scoped roles.

### Split mode

In split mode, routers run without a config file and poll the control plane for signed snapshots.

```sh
caliban gen-signing-key      # prints CALIBAN_SNAPSHOT_SIGNING_KEY=… and CALIBAN_SNAPSHOT_PUBLIC_KEY=…

# control plane
CALIBAN_DATABASE_URL=postgres://… CALIBAN_SNAPSHOT_SIGNING_KEY=… CALIBAN_ROUTER_TOKEN=… CALIBAN_KEK=… \
  caliban control-plane

# each router (same CALIBAN_KEK, to open sealed BYOK keys)
CALIBAN_SNAPSHOT_PUBLIC_KEY=… CALIBAN_ROUTER_TOKEN=… CALIBAN_KEK=… \
  caliban router --control-plane-url http://cp:8081 --snapshot-cache /var/lib/caliban/snapshot.json
```

`GET /api/v1/snapshot` (router token, not the admin token) returns `{key_id, payload, signature}`. The payload is base64 of `{version, issued_at_ms, config}`, signed with Ed25519 (domain-separated). The ETag is the config digest, so a router sending `If-None-Match` gets `304` while nothing has changed. A router verifies the signature, validates the config, refuses snapshots issued before the one it serves (anti-rollback), then swaps the new one in.

**Fail-static.** On any error (control plane down, bad signature, invalid config) the router logs it and keeps serving its last good snapshot. With `CALIBAN_SNAPSHOT_CACHE`, that snapshot is persisted (mode 0600, re-verified on load), so a router restarted while the control plane is down still serves. Sealed secrets stay sealed inside the snapshot; `{env}` and `{file}` references resolve on the router host. When a release adds config fields, upgrade routers before the control plane.

| Variable | Where | Meaning |
|---|---|---|
| `CALIBAN_SNAPSHOT_SIGNING_KEY` | control plane | Base64 32-byte Ed25519 seed (`caliban gen-signing-key`) |
| `CALIBAN_ROUTER_TOKEN` | control plane and routers | Bearer token for `GET /api/v1/snapshot` |
| `CALIBAN_SNAPSHOT_PUBLIC_KEY` | routers | Base64 public key; a comma-separated list allows rotation |
| `CALIBAN_CONTROL_PLANE_URL` | routers | Same as `--control-plane-url` |
| `CALIBAN_SNAPSHOT_POLL_SECS` | routers | Poll interval, default 10 (±20% jitter) |
| `CALIBAN_SNAPSHOT_CACHE` | routers | Path for the last good signed snapshot |
| `CALIBAN_ROUTER_ADDR` | routers | Listen address in split mode, default `0.0.0.0:8080` |

## Testing

```sh
cargo test                   # unit tests in every crate; Docker-backed tests skip themselves
cargo clippy --all-targets
./scripts/smoke.sh           # end to end: real binary + mock upstream
./scripts/split-smoke.sh     # split mode: Postgres (Docker) + control-plane + router processes
./scripts/mongo-it.sh        # MongoDB connector + CDC replica against a real replica set (Docker)

# Valkey quota tests (the memory store's suite plus concurrency, TTL and outage tests):
docker run -d --rm -p 56379:6379 --name caliban-valkey-test valkey/valkey:9.1.2
CALIBAN_TEST_VALKEY_URL=redis://127.0.0.1:56379 cargo test -p caliban-meter quota:: -- --nocapture

# Postgres store parity tests (the memory store's suite, run against Postgres):
docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=x --name caliban-pg-test postgres:17-alpine
CALIBAN_TEST_DATABASE_URL=postgres://postgres:x@127.0.0.1:55432/postgres cargo test -p caliban-cp
```

- **Valkey quota tests** ([`crates/caliban-meter/src/quota/store_tests.rs`](crates/caliban-meter/src/quota/store_tests.rs)) run one behavioural suite against the in-memory store and, with `CALIBAN_TEST_VALKEY_URL`, against Valkey. The Valkey-only tests check that 400 concurrent calls through two store instances never exceed a rate or a day budget, that reserve and settle from two instances leave the server counters at exactly the actual usage, that idle keys expire, that a cut connection (a TCP proxy in front of Valkey) falls back to local limits and recovers with the shared state intact, and print the added latency. Without the variable they print a skip message and pass.
- **`scripts/smoke.sh`** runs `caliban standalone` against `scripts/mock_upstream.py`. It checks that PII never reaches an external model, responses and streams are rehydrated, sovereign models get raw text, the exact cache hits, credentials in prompts are blocked, the Anthropic Messages API works (translated and native passthrough), rate limits return `429` with `retry-after`, keys and BYOK credentials created through the control plane work on the data plane, and a revoked key or a deleted tenant's key gets `401`. Needs `python3`, `curl` and `shasum`. With `CALIBAN_PII_NER_DIR` set, it builds with `ner` and adds name-protection checks.
- **`scripts/split-smoke.sh`** checks that the control plane seeds Postgres and signs snapshots; that a router with no config file picks up a tenant, key and BYOK credential created on the control plane within the poll interval; that the audit chain verifies; that killing the control plane leaves the router serving; that a router restarted while the control plane is down serves from its snapshot cache; that a restarted control plane keeps its state; and that a key revoked and a tenant deleted on the control plane get `401` from the router after its next poll. Needs Docker, `python3` and `curl`. Set `SPLIT_DATABASE_URL` to use an existing database.
- **`scripts/mongo-it.sh`** starts `mongo:8` as a single-node replica set with auth (container `caliban-mongo-test`, port 27018), runs `cargo test -p caliban-replica --test mongo_it -- --nocapture`, then removes the container. The test ([`crates/caliban-replica/tests/mongo_it.rs`](crates/caliban-replica/tests/mongo_it.rs)) seeds `orders` (embedded `lines`, `customerId` references) and `customers`, creates a read-only user, and checks that:
  1. `verify_read_only` accepts the `read`-role user and refuses the admin user, and the replica set is detected;
  2. introspection and `bootstrap::propose` find `Order`, `OrderLine` (embedded), `Customer`, the attribute bindings, and `Order.customer_id->Customer`;
  3. the reference CQIR query, compiled with `plan` and `mongo::lower`, passes the `explain` gate (IXSCAN on `createdAt_1`; a COLLSCAN query is rejected under a strict policy) and runs natively with a row cap;
  4. after a replica snapshot, `sql::lower` output on DataFusion returns **the same rows as the native lane** for three query shapes;
  5. inserts, updates (`$set`, and `$push` into the embedded array) and deletes flow through the change stream, the replica converges to the native answer, and the watermark advances.

  Knobs: `CALIBAN_MONGO_IMAGE` (for example `mongo:7`), `CALIBAN_MONGO_TEST_PORT`, `CALIBAN_MONGO_CONTAINER`, and `KEEP=1` to keep the container. Without `CALIBAN_MONGO_TEST_URI` the test prints a skip message and passes, so plain `cargo test` needs no Docker.

## Status and roadmap

Known gaps:

- Usage events stay on each router (its WAL and in-memory ring); in split mode, the control plane's `/usage` only sees its own process.
- No per-tenant data-encryption keys yet (`tenant_dek` is unused): BYOK keys are sealed directly under `CALIBAN_KEK`.
- Deleting a tenant removes its sealed BYOK ciphertext from the live tables, but Postgres keeps dead row versions until `VACUUM`, and WAL archives and backups keep their copies. Crypto-shredding needs per-tenant DEKs (above).
- Revocation in split mode takes effect on the router's next snapshot poll (`CALIBAN_SNAPSHOT_POLL_SECS`, default 10 s), not instantly.
- Quotas default to in-memory per router process; set `[limits] store = "valkey"` to share them. While Valkey is unreachable each router limits on its own (see [Shared quotas](#shared-quotas-valkey)), and changing `store` needs a router restart.
- No Prometheus metrics endpoint yet.

Next, in order:

1. Control plane: per-tenant DEKs (so a tenant delete crypto-shreds its BYOK keys), OIDC actors in the audit log, usage shipping from routers to the control plane, push (long-poll) instead of polling (faster revocation in split mode).
2. MongoDB connector: wire `introspect` and `propose` into the control plane's introspection job; `$jsonSchema`-declared types; map and scalar-array attributes; per-shard sampling.
3. CDC replica and planner: connect the planner to the `explain` gate and replica lag in a query service; delta Parquet with compaction instead of whole-table rewrites; resume from the manifest after a restart (today it re-snapshots); parallel `_id`-range snapshots; arrays nested in arrays.
4. PII: tenant-scoped surrogates so pseudonymised requests can hit the cache; licence sign-off on the NER model's fine-tuning data (see `MODELS.md`).
5. Gateway: tokenizer-based estimates, rate-limit headers on successful responses, tool-call argument rehydration in streams, `Idempotency-Key`, the semantic cache, and the embedding kNN and ONNX intent classifiers.

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
