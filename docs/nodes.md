# Nodes

A node is an AI sub-app a tenant declares as config: a prompt, a model policy, pinned tools,
datasource scopes, budgets and, for workflows, a graph. The control plane versions and publishes
nodes; the data plane runs them on a durable journal, and every model call a node makes goes
through the same request pipeline as client traffic. This page describes what P3 milestones M1
(deployable versions) and M2 (journal and executor) ship. The plan and its decisions are in
`docs/architecture/p3-nodes-plan.md` (docs repository).

## The spec

The spec is JSON, described by [`schemas/node.schema.json`](../schemas/node.schema.json) and
checked by `NodeSpec::validate` (`crates/caliban-nodes`). The parts the core enforces:

| Field | Meaning |
|---|---|
| `kind` | `workflow` (an explicit graph) or `agent` (a bounded tool loop) |
| `prompt.system` | System prompt of the node's model calls |
| `prompt.input_schema`, `prompt.output_schema` | Checked against the run input and the run output |
| `model_policy.model` | The model the calls ask for; default: the first `candidates` entry that is a model id (not `tier:...`), else `caliban/auto` |
| `tools` | `mcp://server/tool#sha256:<hash>` (pinned, see below) or `node://name@vN` (another node of the tenant, pinned to a version) |
| `datasources.scopes` | `<datasource>.<object>:<read\|write>` |
| `budgets` | `steps`, `tokens`, `wall_clock_s`, optional `usd`; `depth` (subnode nesting, default 3) and `fanout` (map concurrency, default 8). See [Budgets](#budgets) |
| `guards` | `max_repeats` (loop guard, default 3), `tool_retries` (default 2). See [Guards](#guards) |
| `graph` | `entry` (default: the first vertex), `vertices`, `edges` (`from`, `to`, optional `when`) |
| `agent.max_turns` | Agent nodes: model turns at most (default `budgets.steps`) |

Unknown sections (`guardrails`, `exposure`, `eval`, ...) are kept and hashed but not enforced yet.

### Vertices

Each vertex receives the value on the edge it came in by (the run input for the entry vertex) and
produces a value; `router` and `verify` also produce a label. When a vertex declares
`config.input_schema` or `config.output_schema`, the value is checked against it.

| Type | Config | Does |
|---|---|---|
| `llm` | `prompt` (template, default: the input), `system`, `model`, `temperature` (0), `max_tokens` (1024, capped by the tokens left), `output_schema` | One model call. With `output_schema` the answer must be JSON matching it (one corrective retry, then the run fails) |
| `router` | `routes` (label to description), `default`, `prompt` | A model call that picks one label; the output is the input with `route` set; the label selects the edge |
| `tool` | `tool` (a reference declared in `tools`), `args` (JSON template, default: the input) | Calls the tool; `node://` runs the node inside this run |
| `map` | `over` (JSON pointer to an array, default: the input), `body` (a vertex, not `map` or `human`), `concurrency` | Applies `body` to every item, concurrently (at most `budgets.fanout` at once); the output is the array of results, in input order |
| `reduce` | `mode`: `concat` (default, flattens one level), `merge` (objects), `llm` (a model call, like `llm`) | Joins a fan-out |
| `verify` | `check`: `schema` (with `schema`) or `llm` (with `criteria`, `prompt`) | Label `pass` (output: the input) or `fail` (output: `{previous, feedback}`) |
| `human` | `question` (template), `timeout_s`, `default` | Suspends the run until `POST /v1/runs/{id}/input` answers it; the output is the input with `answer` set. Past `timeout_s` the `default` is used, or the run fails |
| `subnode` | `node` (`node://name@vN`), `input` (template) | Runs the node inside this run under a child budget |
| `code` | | Not yet supported (WASM sandbox, P3 M8): refused when the version is created |

**Edges.** After a vertex, the first outgoing edge (in declaration order) whose `when` is absent or
equals the label is taken; no matching edge ends the run with the last value. Fan-out happens only
inside `map`. **Loops**: every cycle must contain a vertex with `max_iterations`; such a vertex runs
at most that many times, and once it has, its edges back into vertices already visited are no
longer taken (the run continues on another matching edge, or ends with the last value and a note
in `stop_reason`).

**Templates.** `{{input}}`, `{{input.a.b}}`, `{{outputs.<vertex>}}` (the latest output of a vertex of
the same node), with `.field` and `.<index>` segments. Strings are inserted as is, other values as
compact JSON. In a JSON template, a string that is exactly one placeholder becomes the value itself.

**Schemas.** Edge and output schemas use a JSON Schema subset: `type`, `enum`, `const`,
`properties`, `required`, `additionalProperties`, `items`, `minItems`, `maxItems`, `minLength`,
`maxLength`, `pattern`, `minimum`, `maximum`, `anyOf`, `allOf`, plus annotations. Any other keyword
(`$ref`, `oneOf`, ...) is refused when the version is created, so a schema is never silently weaker
than it reads.

**Agent nodes** run a bounded ReAct-style loop: each turn is one model call with the node's tools
offered as functions; tool calls run as steps and their results go back to the model; an answer
without tool calls is the final answer (parsed against `prompt.output_schema` when there is one).
A failing tool returns an error object to the model; an unknown tool name is reported to the model;
a tool that cannot be resolved refuses the run before the first call.

**Tools.** `node://name@vN` is handled by the executor. Other references go through a tool
registry (`ToolRegistry`): this release has no MCP client, so `mcp://` tools are refused at run
time with a clear error (they arrive in P3 M4 with the approved tool registry, minted per-call
tokens and the egress allowlist). Any other scheme is an unknown tool kind.

## Versions and their lifecycle

A **version** is immutable. Its **content hash** is `sha256:<hex>` over the spec in canonical JSON
(object keys sorted by their UTF-8 bytes at every level, no whitespace), so two specs that differ
only in key order or formatting hash the same, and any change of a value changes it. Changing a
node means creating a new version.

States move `draft` -> `published` -> `retired`, never back (Postgres triggers enforce it, and that
spec and hash never change). Each node has a **promotion pointer** naming its live version: what a
run without a version runs.

| Step | Endpoint (control plane) | Permission | Audit |
|---|---|---|---|
| Create a draft (version = latest + 1) | `POST /api/v1/tenants/{t}/nodes/{name}/versions` (or `POST /api/v1/nodes`) | `nodes.write` | `node.create` (with the hash) |
| List versions, the live one | `GET /api/v1/tenants/{t}/nodes/{name}/versions` | `nodes.read` | |
| Get a version (spec, hash, state) | `GET /api/v1/tenants/{t}/nodes/{name}/versions/{v}` | `nodes.read` | |
| Publish (and promote, by default) | `POST .../versions/{v}/publish` `{"promote": true}` | `nodes.publish` | `node.publish` |
| Promote another published version (rollback) | `POST /api/v1/tenants/{t}/nodes/{name}/promote` `{"version": v}` | `nodes.publish` | `node.promote` (with the previous live version) |
| Retire a published version | `POST .../versions/{v}/retire` | `nodes.publish` | `node.retire` |
| Diff two versions | `GET /api/v1/tenants/{t}/nodes/{name}/diff?from=a&to=b` | `nodes.read` | |
| Delete a draft or retired version | `DELETE /api/v1/tenants/{t}/nodes/{record id}` | `nodes.write` | `node.delete` |

**Publish-time validation**, against the tenant, in the same transaction as the publish (a failure
is a `422` listing every problem):

- the static checks again;
- every `node://name@vN` the version calls (tools and `subnode` vertices) is a **published** version
  of the same tenant, and node-to-node references form no cycle;
- every datasource scope names a live datasource of the tenant and `*` or an approved ontology
  entity bound to it (by collection or entity name);
- the budgets fit inside the tenant's **node caps**: `node_caps` on the tenant (`PATCH
  /api/v1/tenants/{t}`, `null` restores the defaults: steps 200, tokens 2,000,000, wall_clock_s
  3,600, depth 5, fanout 32). Promoting a version checks the current caps again;
- `mcp://` tools are pinned. TODO(M4): resolving them against the tenant's approved tool registry
  happens in the `PublishContext::check_tool` hook, which accepts every pinned reference today.

Retiring a version that another published version calls is a `409`, as is deleting a published
version (retire it first).

**Retiring drains.** Runs already started finish on the version they started on; only new runs
are refused (`404`). A run carries what it needs: when it is created, the spec of its version and
of every version it can reach through `node://` references are stored with it (`node_run.specs`,
sealed under the tenant's data key with the run id as associated data), so a worker can resume it
after the version left the snapshot.

**What the data plane receives.** Only published versions travel to routers and workers, in the
signed snapshot, with the spec sealed under the tenant's data key (a self-contained `tenant_sealed`
envelope, like BYOK keys; the key is created on the tenant's first secret or publish, and
publishing needs `CALIBAN_KEK`). The snapshot also carries the tenant's wrapped data key (workers
seal run data with it) and the node allowlists of API keys. A worker opens a spec with its keyring
and checks it against the version's hash before running it. Snapshots of tenants without nodes are
unchanged; routers of an earlier release refuse snapshots that carry nodes (and keep serving their
last good one), so upgrade routers before publishing nodes.

## Permissions

| Role | `nodes.read` | `nodes.write` | `nodes.publish` | `nodes.run` |
|---|---|---|---|---|
| `owner`, `admin` | yes | yes | yes | yes |
| `tenant_admin` | yes | yes | yes | yes |
| `developer` | yes | yes | no | yes |
| `viewer`, `auditor` | yes | no | no | no |
| `billing` | no | no | no | no |

Runs are started with tenant **API keys**. A key may carry a **node allowlist** (`nodes` when it is
created: `POST /api/v1/tenants/{t}/api-keys {"name": ..., "nodes": ["triage"]}`). Without one it may
run every published node of its tenant; `[]` runs none. Granting node access to a key needs
`nodes.run` on the tenant: a key created by someone without it runs no nodes.

## Running a node

Data plane, tenant API key as bearer token, the key allowed to run the node:

| Endpoint | Does |
|---|---|
| `POST /v1/nodes/{name}/runs` `{"input": ..., "version"?: v, "async"?: false, "wait_s"?: s, "budget"?: {...}}` | Starts a run of the live version (or `version`). Sync by default: waits until the run ends or waits for a human, at most `CALIBAN_NODE_SYNC_WAIT_SECS` (default 60) or `wait_s`; `200` when it ended, else `202` with the run so far. `"async": true` answers `202` at once. `Idempotency-Key` returns the run the first request created (`Idempotent-Replayed: true`); the same key with another body is a `422`. The input is checked against `prompt.input_schema` (`400`) |
| `GET /v1/runs/{id}` | The run: `status`, `output`, `partial`, `error`, `stop_reason`, `awaiting` (`step`, `question`), `budget` (limits and spend), `cost_usd`, `steps` (id, vertex, kind, status, tokens, usd, duration) |
| `POST /v1/runs/{id}/input` `{"answer": ..., "step"?: id}` | Answers the human step the run waits for; `202`, the run resumes. `409` when it is not waiting |

Statuses: `pending`, `running`, `sleeping`, `input_required`, `succeeded`, `failed`,
`budget_exhausted` (ended gracefully: `output` holds the partial result, `stop_reason` says why).
Other codes: `401` (key), `403` (`node_not_allowed`), `404` (`node_not_found`: not published, or no
live version), `503` (`nodes_not_enabled`).

### Where runs execute

| Mode | Node runs |
|---|---|
| `caliban standalone` | In the process: the Postgres journal with `CALIBAN_DATABASE_URL`, else in memory. Needs `CALIBAN_KEK` (otherwise nothing can be published, and runs are disabled) |
| `caliban router` (split mode) | Forwarded to workers (`CALIBAN_WORKER_URLS`). The router authenticates the key and the allowlist first, holds no database and keeps no run state |
| `caliban worker` | Executes runs: the control plane's signed snapshot (like a router), the Postgres journal, its own gateway for model calls, usage shipped to the control plane like a router. Serves the run API to routers only (`x-caliban-worker-token`), plus `/healthz` and `/metrics` |

```sh
# each worker (same CALIBAN_KEK as the routers; the journal shares the control plane's database)
CALIBAN_DATABASE_URL=postgres://… CALIBAN_SNAPSHOT_PUBLIC_KEY=… CALIBAN_ROUTER_TOKEN=… CALIBAN_KEK=… \
CALIBAN_WORKER_TOKEN=… caliban worker --control-plane-url http://cp:8081

# each router
CALIBAN_WORKER_URLS=http://worker-1:8082,http://worker-2:8082 CALIBAN_WORKER_TOKEN=… \
  caliban router --control-plane-url http://cp:8081 …
```

A router sends a run request to the next worker in turn and moves on when one cannot be reached.
Workers share the journal, so any worker answers for any run, and an async run is picked up by
whichever worker claims it first.

**The control plane owns migrations.** A worker never changes the schema: at startup it checks
that the database holds exactly the migrations it was built with (same versions, same checksums)
and refuses to start otherwise, saying whether to upgrade the control plane first (the schema is
behind) or the worker (the schema is ahead). Upgrade the control plane, then the workers. A worker
needs no DDL rights; its database role needs:

```sql
GRANT USAGE ON SCHEMA public TO caliban_worker;  -- the schema holding Caliban's tables
GRANT SELECT ON caliban_schema_migrations TO caliban_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_run, node_step, node_event TO caliban_worker;
GRANT SELECT, INSERT, UPDATE ON node_spend TO caliban_worker;
ALTER ROLE caliban_worker BYPASSRLS;  -- the journal tables have per-tenant row-level security; a worker serves every tenant
```

(`DELETE` on `node_run` is for the retention purge, which removes a finished run's steps and
events with it; `node_spend` holds the tenants' spend per day, see [Budgets](#budgets). No
sequence grants are needed: `node_step.seq` is an identity column. Workers write nothing else:
usage goes to the control plane over HTTP, and tools reach them in the snapshot. The test
`postgres_worker_grants_are_enough` runs a worker's journal operations as a role with exactly these
grants.)

**More than one worker needs Valkey.** Exactly-once model calls across workers (a run taken over
after a crash replays its in-flight call against the stored response) need the shared
`Idempotency-Key` store: `[limits] store = "valkey"` with `CALIBAN_VALKEY_URL`. With the in-memory
store the guarantee holds within one worker only, and a worker that starts with it logs a
prominent warning.

| Variable | Where | Meaning |
|---|---|---|
| `CALIBAN_WORKER_URLS` | routers | Worker base URLs, comma separated |
| `CALIBAN_WORKER_TOKEN` | routers and workers | Shared secret on router-to-worker requests |
| `CALIBAN_WORKER_ADDR` | workers | Listen address, default `0.0.0.0:8082` |
| `CALIBAN_WORKER_ID` | workers, standalone | The worker's stable name, used as is for snapshot check-ins and usage shipping (default: the host name). Leases are owned by this name plus a random per-process suffix, so two processes with the same name never share a lease |
| `CALIBAN_NODE_SYNC_WAIT_SECS` | workers, standalone, routers | Longest a sync run request waits, default 60 |
| `CALIBAN_NODE_LEASE_SECS` | workers, standalone | Lease on a running run, default 30, renewed every third of it |
| `CALIBAN_NODE_POLL_MS` | workers, standalone | How often an idle worker looks for runnable runs, default 500 |
| `CALIBAN_NODE_MAX_RUNS` | workers, standalone | Runs executed at once per process, default 64 |
| `CALIBAN_NODE_RUN_RETENTION_DAYS` | workers, standalone | Days finished runs (with their steps and events) are kept, default 30; 0 keeps them |
| `CALIBAN_NODE_BREAKER_FAILURES` | workers, standalone | Consecutive failed calls that open a tool's circuit breaker, default 5 |
| `CALIBAN_NODE_BREAKER_COOLDOWN_SECS` | workers, standalone | How long an open breaker refuses calls before a trial call, default 30 |

### Model calls go through the pipeline

Every model call of a run is a Chat Completions request dispatched **in-process** through the
worker's own HTTP router (`/v1/chat/completions` on the same gateway), not over the network and not
to a provider directly. The run's tenant and invoking API key travel as a request extension, which
the network cannot set; the key must still be active in the snapshot, so revoking it stops its
runs' model calls. PII protection, both caches, routing (`caliban/auto` included), quotas,
metering, usage shipping and tracing therefore apply to node traffic exactly as to client traffic.
An HTTP hop to a router was considered and rejected: it adds latency and a second credential path,
and the worker is already a full gateway.

Each call carries `Idempotency-Key: caliban-node-<hash(run id, step id)>`. A step that ran but was
not checkpointed before its worker died is called again with the same key when the run is replayed,
and gets the stored response (or waits while the first call is still in flight) instead of paying
twice; the replay is not metered again. Across workers this needs the shared Idempotency-Key store
(`[limits] store = "valkey"`); with the in-memory store the guarantee holds within one process. A
rate-limited call (`429`, a tenant quota) does not hold the worker: the run sleeps durably until
`Retry-After` and is resumed by whichever worker claims it then (at most five times per step).

## The journal

Decided: a minimal Postgres journal following the Absurd model (`caliban-nodes::journal`), with an
in-memory implementation of the same behaviour for standalone without a database; one parity suite
runs against both. Tables (`migrations/0013_node_journal.sql`):

| Table | Holds |
|---|---|
| `node_run` | Run id, tenant, node, version, spec hash, invoker (`api_key:<hash prefix>`) and the key's hash, sealed input and output, status, `wake_at`, `awaiting` and the sealed question, budget (limits and spend), lease owner and expiry, claim count, error, stop reason, `Idempotency-Key` and request fingerprint, timestamps |
| `node_step` | Run id, step id, attempt, vertex, kind, input hash, status, sealed result, tokens, USD, start and end |
| `node_event` | Awaited events: human answers (named after the step, sealed) and timers (`<step>:deadline`, `<step>:throttled:<n>`) |

- **Claims.** Workers claim the oldest runnable run with `UPDATE ... WHERE id = (SELECT ... FOR UPDATE
  SKIP LOCKED)`, so two workers never claim the same run. Runnable: `pending`; `sleeping` or
  `input_required` whose `wake_at` passed; `running` whose lease expired (its worker died). The
  lease is renewed every third of `CALIBAN_NODE_LEASE_SECS`; times come from the database clock.
- **Fencing.** Every write a worker makes for a run (steps, suspension, the end) requires
  `lease_owner = <worker> AND status = 'running'`, so a worker that lost its run records nothing.
- **Checkpoints.** Every step is one row, written once (first write wins), together with the run's
  budget. About a millisecond per step, against model calls in the hundreds.
- **Replay.** A claimed run is executed from the start with its recorded steps loaded: step ids are
  deterministic (`classify#0`, `fanout#0/3`, `call#0>inner#0`, `agent#2.1`, `x#0~r1`), a recorded
  step returns its recorded result and re-charges its recorded tokens without calling anything, and
  only unrecorded steps run. A recorded step whose input hash no longer matches fails the run (the
  run diverged from its journal). Pure transforms (`reduce` concat and merge, `verify` against a
  schema) are recomputed, not journaled.
- **Sealing.** Inputs, outputs, step results, questions and answers are sealed under the tenant's
  data key, with the tenant and the run id as associated data (a value cannot be moved to another
  tenant or run). Deleting a tenant destroys its data key, which makes its journal unreadable.
- **Idempotency.** `(tenant, Idempotency-Key)` is unique on `node_run`.

## Budgets

Budgets nest: **tenant** (daily and monthly spend caps) above the **node version** (its
`budgets`) above the **run** (the run request may lower the version's budget) above each
**subnode** (a child gets at most what its parent has left).

| Dimension | Spent by | Where it is set |
|---|---|---|
| `steps` | Every vertex execution that calls something (a model, a tool, a human) | `budgets.steps`; run `budget.steps` |
| `tokens` | Prompt plus completion of every model call | `budgets.tokens`; run `budget.tokens` |
| `usd` | Every model call, priced as the metering prices it: the flat `caliban/auto` price (a cache hit at the tenant's discounted fraction) or the pinned model's price | `budgets.usd` (optional); run `budget.usd` |
| wall clock | Execution time (not time waiting for a human or a timer), across workers | `budgets.wall_clock_s`; run `budget.wall_clock_s` |
| depth | One level per `subnode` vertex or `node://` tool | `budgets.depth` (default 3) |
| fan-out | The most `map` branches running at once | `budgets.fanout` (default 8) |

A run request may send `"budget": {"steps"?, "tokens"?, "usd"?, "wall_clock_s"?}`: each value
lowers the version's limit for that run (a larger value is ignored). A `subnode` or `node://` tool
runs under a child ledger: steps, tokens and USD it spends count against every ancestor, and its
limits, depth, fan-out and deadline are the smaller of its own budgets and what the parent has
left. The tenant's `node_caps` (publish time) can include `usd`: every version must then declare a
`budgets.usd` within it.

**The spend is persisted.** Every checkpoint writes the run's budget (limits and spend, including
USD, the deepest nesting and the widest map reached) with the step. A resumed run (after a human
answer, a durable sleep, or on another worker after a crash) rebuilds its ledger by replaying its
steps, which charges their recorded tokens and USD again, and continues the wall clock from the
persisted value, so it keeps what it already spent. The USD of each step comes from the model
call's `x-caliban-billed-usd` (the billed amount; a replayed call returns the stored header, so a
call paid once is counted once).

**Tenant spend caps.** `PATCH /api/v1/tenants/{t}` with `{"node_spend_caps": {"daily_usd": 50,
"monthly_usd": 1000}}` (either may be omitted; `null` removes the caps; shipped to workers in the
snapshot). Days and months are UTC. Every step's cost is added to `node_spend` (tenant, day) in the
same transaction that checkpoints the step, and before every model call the executor compares the
tenant's spend today and this month with the caps: the journal is the source of truth, so the caps
hold across workers. Calls already in flight when the cap is reached complete (the overshoot is at
most one call per run in flight).

**Overruns end gracefully.** Status `budget_exhausted`, the last completed value in `output`
(`partial: true`), the reason in `stop_reason` (`USD budget exhausted ($0.003 spent of $0.0025)`,
`the tenant's daily node spend cap is reached ...`). `GET /v1/runs/{id}` shows `budget` and
`cost_usd` (what the run spent so far).

### Guards

| Guard | Spec | Does |
|---|---|---|
| Loop guard | `guards.max_repeats` (default 3, at least 1) | A vertex that receives the same input (same vertex, same input hash, same `map` branch, same subnode path) more than this many times ends the run (`budget_exhausted`, `stop_reason: loop guard: ...`). Iteration counters do not count as a difference, so a loop that makes no progress trips it; an agent that calls the same tool with the same arguments again and again too |
| Tool retries | `guards.tool_retries` (default 2) | A tool call that fails transiently (network, a 5xx) is retried this many times, with a short backoff, then counts as failed |
| Circuit breaker | `CALIBAN_NODE_BREAKER_FAILURES` (default 5), `CALIBAN_NODE_BREAKER_COOLDOWN_SECS` (default 30) | Per tool and tenant, in each worker process: after that many failed calls in a row the breaker opens and calls fail at once without reaching the tool; after the cool-down one trial call goes through (half-open); success closes it, failure opens it again |

## Usage and retention

**Usage per run and per node.** Every model call of a run is metered like any other request, and
its usage event carries `node`, `node_version` and `run_id` (a subnode's calls carry the run's
root node: the run pays for them). `GET /api/v1/usage` takes `node` and `run_id` filters next to
`tenant_id`, and returns `by_node` (the totals per node version) next to `totals`. `charged_usd`
is what the customer is charged (the billed `caliban/auto` price, discounted on cache hits; the
model's cost otherwise): over a run's events it equals the run's `cost_usd`.

**Retention of finished runs.** Every worker (and a standalone process) deletes runs that finished
more than `CALIBAN_NODE_RUN_RETENTION_DAYS` ago (default 30; 0 keeps them), with their steps and
events, hourly and in batches of 500 (`FOR UPDATE SKIP LOCKED`, so workers purging at once take
different rows). Runs not finished are never purged. The tenants' daily spend (`node_spend`) is
not purged with them.

**Retention of usage events.** The control plane (Postgres store) moves raw usage events older
than `CALIBAN_USAGE_RETENTION_DAYS` (default 90 whole UTC days; 0 keeps them) into `usage_daily`,
one row per (tenant, day, node, node version) with every total, hourly. Each batch deletes the raw
events and adds them to their day in one statement, so an event is counted raw or rolled up,
never both; reports add the two, so all-time totals (per tenant and per node) are the same before
and after a purge. One control plane at a time does it (an advisory lock; the others skip the
round). Rolled-up days keep no run ids or event rows: `run_id` filters and the event list cover
the raw retention only. An event delivered later than the retention (a router offline for months)
is refused at ingestion and counted as `rejected`: its day may be rolled up already, and a retry
could no longer be told from a new event.

## The reference node

[`config/nodes/triage.node.json`](../config/nodes/triage.node.json) (P3 decision 6): a `router`
vertex classifies the case (clinical, administrative, billing), a `human` vertex asks one
clarifying question, the pinned catalogue tool finds matching services, and an `llm` vertex returns
a recommendation that must match the output schema. With the tenant in `mask` PII mode, no model
call sees the person's identifiers. The end-to-end test (`apps/caliban/src/nodes_tests.rs`) runs it
against the mock model server with the catalogue tool stubbed in-process.

## Not in this release

- **P3 M4:** the MCP client and the per-tenant approved tool registry (`mcp://` tools refuse to run;
  `PublishContext::check_tool` is the publish-time hook), minted per-call tokens, the egress
  allowlist, taint labels.
- **P3 M5:** streaming run events (SSE), `model: "node/<name>"` on chat completions, the MCP server,
  run listing and cancellation.
- **P3 M8:** `code` vertices (WASM), the console views, evals as promotion gates.
- The journal is not purged yet (rows of a deleted tenant stay, unreadable). Node specs are stored in
  clear in the control-plane database, as before; they are sealed only in snapshots and journals.
