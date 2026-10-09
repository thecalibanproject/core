# caliban/core

Rust workspace for Caliban: one binary, `caliban`, runs the **data plane** (OpenAI-compatible gateway, `:8080`), the **control plane** (admin API + web console, `:8081`), or both (`standalone`, the on-prem default).

Design: [`../docs/architecture/caliban-reference-architecture.md`](../docs/architecture/caliban-reference-architecture.md). Conventions: [`../docs/architecture/repos-and-conventions.md`](../docs/architecture/repos-and-conventions.md).

## Quick start

```sh
cargo build
export CALIBAN_ADMIN_TOKEN=dev-admin CALIBAN_KEK=$(./target/debug/caliban gen-kek)
./target/debug/caliban keygen                  # prints a tenant key + the hash to put in the config
CALIBAN_CONFIG=config/caliban.example.toml ./target/debug/caliban standalone
```

```sh
curl localhost:8080/v1/chat/completions -H "authorization: Bearer cal_…" -H 'content-type: application/json' \
  -d '{"model":"caliban/auto","messages":[{"role":"user","content":"hello"}]}'
```

Any OpenAI SDK works: set `base_url=http://<host>:8080/v1` and use a `cal_…` key. Any Anthropic SDK works too: set `base_url=http://<host>:8080` and `api_key=cal_…` (`POST /v1/messages`, streaming included).

Rate limits and token budgets: `[limits]` (defaults) and `[limits.tenants.<id>]` (overrides) in the config; exceeding one returns `429` with `retry-after`. Tracing: OpenTelemetry GenAI spans are exported over OTLP/HTTP only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (off by default); prompt and response content is never recorded.

## Commands

| Command | What it does |
|---|---|
| `caliban standalone` | Data plane + control plane in one process |
| `caliban router` / `caliban control-plane` | Run one plane only (router config from `$CALIBAN_CONFIG`) |
| `caliban router --control-plane-url http://cp:8081` | Split mode: router config from signed control-plane snapshots (no config file) |
| `caliban check-config` | Validate `$CALIBAN_CONFIG` |
| `caliban keygen` / `caliban gen-kek` | New tenant API key (+ hash) / new base64 KEK |
| `caliban gen-signing-key` | New Ed25519 snapshot signing key (CP) + its public key (routers) |
| `caliban healthcheck --addr 127.0.0.1:8080` | Exit 0/1, for distroless container healthchecks |

## Layout

| Crate | Status | Role |
|---|---|---|
| `caliban-types` | ✅ | Ids, trust tiers, PII/cache modes, errors |
| `caliban-config` | ✅ | TOML config → indexed `Snapshot` behind `ArcSwap`; secret refs (`env`, `file`, `sealed` AES-256-GCM under `CALIBAN_KEK`) |
| `caliban-ir` | ✅ OpenAI · ✅ Anthropic | Canonical request IR; unknown fields pass through; canonical hashing for cache keys; Anthropic Messages ⇄ IR codecs (requests, responses, stream events); SSE parser |
| `caliban-pii` | ✅ L0 · ✅ L1 NER (`ner` feature) | Regex + validators (Luhn, IBAN, SSN), tenant dictionaries, **in-process multilingual NER** (ONNX, MIT-licensed model, hash-verified artifact; see `crates/caliban-pii/MODELS.md`), realistic surrogates (valid Luhn/IBAN), vault, streaming rehydration with hold-back |
| `caliban-cache` | ✅ T1 · ⏳ T2 | Exact cache (moka), tenant + ACL + datasource-epoch keys; semantic cache trait |
| `caliban-route` | ✅ rules + placeholder classifier · ⏳ kNN/ONNX | Intent → ordered candidates, trust-tier constraints, fallbacks |
| `caliban-providers` | ✅ OpenAI-compatible · ✅ Anthropic · ⏳ Bedrock/Vertex | BYOK upstream calls; covers vLLM, SGLang, llama.cpp, Ollama; Anthropic native passthrough (`cache_control` kept) or translation |
| `caliban-meter` | ✅ · ⏳ Valkey quotas | Usage events, cost, in-memory ring + JSONL WAL; quotas: GCRA request rate (`governor`), token/USD budgets with reservation + settlement (in-memory; Valkey store stubbed) |
| `caliban-ontology` | ✅ compiler · ⏳ store/retrieval | CSM types + **CQIR compiler** → MongoDB pipeline (with lint) or SQL for the CDC replica |
| `caliban-connect` | ✅ MongoDB · ⏳ SQL/REST sources | Connector trait; MongoDB connector: read-only privilege check, stratified sampling → path stats, reference discovery, ontology bootstrap (`proposed` elements), native-lane executor + `explain` gate, epochs |
| `caliban-replica` | ✅ v1 | CDC replica: snapshot + change streams → Arrow → Parquet, queried with DataFusion; watermark = last applied clusterTime |
| `caliban-nodes` | ✅ spec/budgets · ⏳ executor | Node spec validation (pinned tools, bounded cycles), hierarchical budget ledger |
| `caliban-rag` | ✅ RRF/budget · ⏳ index | Rank fusion, token-budgeted context selection |
| `caliban-mcp` | ✅ pinning · ⏳ rmcp | Tool-manifest pinning against description poisoning |
| `caliban-gateway` | ✅ | Data-plane HTTP app: one pipeline for `/v1/chat/completions` and Anthropic `/v1/messages` (+ `count_tokens`), embeddings, rate limits, OTel GenAI tracing (`telemetry::init`) |
| `caliban-cp` | ✅ memory + Postgres stores, audit chain, signed snapshots | Admin API per `api/openapi.yaml`; every mutation is one transaction + one hash-chained audit row; republishes the data-plane snapshot on change; serves signed snapshots to split-mode routers and the web console |

## Contracts owned here
- `api/openapi.yaml`: the HTTP contract used by `web/`, `sdk-typescript/` and `sdk-python/`.
- `schemas/node.schema.json`: node spec, vendored by the SDKs and the web app.
- `config/caliban.example.toml`: config format, used by `deploy/`.
- `migrations/`: Postgres schema for the control plane, embedded in the binary and applied at startup (checksummed in `caliban_schema_migrations`; never edit an applied file, add `000N_*.sql` and list it in `crates/caliban-cp/src/store/postgres.rs`). Tested against Postgres 17.

## Control-plane store and split mode

**Store.** `CALIBAN_DATABASE_URL` set → Postgres; unset → in-memory (dev/demo; the log says which, and so does `GET /api/v1/health` → `store`).

Precedence with Postgres: the config file seeds the database **once**, on the first start against an empty database (marker row `cp_meta.seeded_at`). From then on the database is the source of truth for tenants, API keys, BYOK credentials, shared providers, models, routes, datasources, nodes and ontology; `[[tenants]]`, `[[models]]` and `[[providers]]` in the file are ignored (logged at startup). Every other section of the file (`[server]`, `[security]`, `[cache]`, `[pii]`, `[limits]`, …) always comes from the control plane's file and is shipped to split-mode routers inside the snapshot. Without Postgres the file seeds memory at every start and runtime changes are lost.

Every mutation is one transaction: apply → render + validate the data-plane config (an invalid result, e.g. deleting a model a route uses, rolls back with 409/422) → append an `audit_log` row (`hash = sha256(prev_hash ‖ canonical row)`, append-only trigger) → commit. `GET /api/v1/audit?limit=` (admin) returns the newest rows and `chain_verified`. BYOK keys are sealed (AES-256-GCM, `CALIBAN_KEK`) before they reach the store (`sealed_key`); `{env}`/`{file}` references from the file are stored as references. Several CP replicas can share one database: writes are serialized with an advisory lock and each replica reloads when the audit head moves (every 5 s, and on every snapshot request). The CP connects as the schema owner (or a `BYPASSRLS` role); RLS policies apply to tenant-scoped roles.

**Split mode.** Routers run without a config file and poll the CP:

```sh
./target/debug/caliban gen-signing-key            # prints CALIBAN_SNAPSHOT_SIGNING_KEY=… and CALIBAN_SNAPSHOT_PUBLIC_KEY=…
# control plane
CALIBAN_DATABASE_URL=postgres://… CALIBAN_SNAPSHOT_SIGNING_KEY=… CALIBAN_ROUTER_TOKEN=… CALIBAN_KEK=… caliban control-plane
# each router (same CALIBAN_KEK, to open sealed BYOK keys)
CALIBAN_SNAPSHOT_PUBLIC_KEY=… CALIBAN_ROUTER_TOKEN=… CALIBAN_KEK=… \
  caliban router --control-plane-url http://cp:8081 --snapshot-cache /var/lib/caliban/snapshot.json
```

`GET /api/v1/snapshot` (router token, not the admin token) returns `{key_id, payload, signature}`: `payload` is base64 of `{version, issued_at_ms, config}` and is signed with Ed25519 (domain-separated). The ETag is the config digest; routers send `If-None-Match` and get 304 while nothing changed. The router verifies the signature, validates the config, refuses snapshots issued before the one it serves (anti-rollback), then swaps it in. **Fail-static:** on any error (CP down, bad signature, invalid config) it logs and keeps serving the last good snapshot; with `CALIBAN_SNAPSHOT_CACHE` the last good signed snapshot is persisted (0600, re-verified on load) so a router restarted while the CP is down still serves. Sealed secrets stay sealed in the snapshot; `{env}`/`{file}` secret references resolve on the router host. Upgrade routers before the CP when the config format gains fields.

| Env var | Where | Meaning |
|---|---|---|
| `CALIBAN_DATABASE_URL` | CP | Postgres store (unset = in-memory) |
| `CALIBAN_SNAPSHOT_SIGNING_KEY` | CP | base64 32-byte Ed25519 seed (`caliban gen-signing-key`) |
| `CALIBAN_ROUTER_TOKEN` | CP + routers | Bearer token for `GET /api/v1/snapshot` |
| `CALIBAN_SNAPSHOT_PUBLIC_KEY` | routers | base64 public key; comma-separated list for rotation |
| `CALIBAN_CONTROL_PLANE_URL` | routers | Same as `--control-plane-url` |
| `CALIBAN_SNAPSHOT_POLL_SECS` | routers | Poll interval, default 10 (±20% jitter) |
| `CALIBAN_SNAPSHOT_CACHE` | routers | Path for the last good signed snapshot |
| `CALIBAN_ROUTER_ADDR` | routers | Listen address in split mode, default `0.0.0.0:8080` |

Known gaps: usage events stay on each router (WAL / its own ring); the CP's `/usage` only sees its own process in split mode. No per-tenant DEKs yet (`tenant_dek` is unused). Delete endpoints for tenants/keys/datasources/nodes are still missing.

## Tests

```sh
cargo test                 # unit tests in every crate
cargo clippy --all-targets
./scripts/smoke.sh         # end-to-end: real binary + mock upstream (PII, streaming, cache, BYOK, Anthropic API, 429s, CP→DP)
./scripts/split-smoke.sh   # split mode: Postgres (Docker) + CP + router processes; pickup, fail-static, cache restart
# Postgres store parity tests (same suite as the memory store; skipped without the env var):
docker run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=x --name caliban-pg-test postgres:17-alpine
CALIBAN_TEST_DATABASE_URL=postgres://postgres:x@127.0.0.1:55432/postgres cargo test -p caliban-cp
./scripts/mongo-it.sh      # MongoDB connector + CDC replica against a real replica set (Docker)
```

### MongoDB integration test

`scripts/mongo-it.sh` starts `mongo:8` as a single-node replica set with auth (container
`caliban-mongo-test`, port 27018, keyfile generated in the container), creates an admin user, runs
`cargo test -p caliban-replica --test mongo_it -- --nocapture`, and removes the container. The
test (`crates/caliban-replica/tests/mongo_it.rs`) seeds `orders` (embedded `lines`, `customerId`
references) and `customers` to match the ontology compiler fixture, creates a read-only user, and checks:

1. `verify_read_only` accepts the `read`-role user and refuses the admin user; replica set detected.
2. Introspection + `bootstrap::propose`: `Order`, `OrderLine` (embedded), `Customer`, the
   fixture's attribute bindings, and `Order.customer_id->Customer` (100% overlap).
3. The reference CQIR compiled with `plan` + `mongo::lower`: `explain` gate (IXSCAN on
   `createdAt_1`; a COLLSCAN query is rejected under a strict policy) and native execution with a row cap.
4. Replica snapshot, then `sql::lower` output on DataFusion: **both lanes return the same rows**
   for three query shapes (child grain + reference join + policy, same-element child filter, root grain by dimension).
5. Insert, update (`$set` and `$push` into the embedded array) and delete through the change stream:
   the replica converges to the native answer and the watermark advances.

Knobs: `CALIBAN_MONGO_IMAGE=mongo:7`, `CALIBAN_MONGO_TEST_PORT`, `KEEP=1` (keep the container).
Without `CALIBAN_MONGO_TEST_URI` the test prints a skip message and passes, so plain `cargo test` needs no Docker.

## Next (in order)
1. ~~Postgres store; signed snapshots for split deployments~~ ✅. Left: per-tenant DEKs (`tenant_dek`), OIDC actors in the audit log, usage shipping from routers to the CP, push (long-poll) instead of polling, delete endpoints.
2. ~~MongoDB connector~~ ✅ (`caliban-connect::mongo`). Left: wire `introspect`/`propose` into `caliban-cp`'s introspection job; `$jsonSchema`-declared types; map attributes and scalar-array attributes; per-shard sampling.
3. CDC replica ✅ v1 (`caliban-replica`), immutable per-flush file generations (queries never see a file being replaced). Planner ✅ as a pure function (`caliban_ontology::compile::planner`); left: wiring it to `explain_gate` + `lag_secs` in a query service; delta Parquet + compaction instead of whole-table rewrites; resume from the manifest after restart (today: re-snapshot); parallel `_id`-range snapshot; arrays nested in arrays.
4. L1 PII NER ✅: build with `cargo build -p caliban --features ner`, fetch the model with `ml/scripts/fetch_pii_ner.py`, set `CALIBAN_PII_NER_DIR` (optional `CALIBAN_PII_NER_SESSIONS`). The binary refuses to start if the variable is set but the artifact fails hash verification. `CALIBAN_PII_NER_DIR=… ./scripts/smoke.sh` adds name-protection checks. Left: tenant-scoped surrogates so pseudonymized requests can hit the cache; licence sign-off on the model's CC-BY-SA fine-tuning text (MODELS.md).
5. ~~Anthropic `/v1/messages`, quotas, OTel GenAI spans~~ ✅. Left: Valkey quota store for multi-router deployments, tokenizer-based estimates, rate-limit headers on successful responses, tool-call argument rehydration in streams, `Idempotency-Key`.
