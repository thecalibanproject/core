# Nodes

A node is an AI sub-app a tenant declares as config: a prompt, a model policy, pinned tools,
datasource scopes, budgets and, for workflows, a graph. The control plane versions and publishes
nodes; the data plane runs them on a durable journal, and every model call a node makes goes
through the same request pipeline as client traffic. This page describes what P3 milestones M1
(deployable versions), M2 (journal and executor), M3 (budgets and guards), M4 (tools), M5
(exposure: the run API, event streams, the chat shortcut, the MCP server, the console endpoints)
and M6 (`caliban/auto` picks a node) ship; the tools themselves (the MCP client, the tool registry, minted tokens, egress, taint) are in
[`tools.md`](tools.md). The plan and its decisions are in `docs/architecture/p3-nodes-plan.md`
(docs repository).

## The spec

The spec is JSON, described by [`schemas/node.schema.json`](../schemas/node.schema.json) and
checked by `NodeSpec::validate` (`crates/caliban-nodes`). The parts the core enforces:

| Field | Meaning |
|---|---|
| `kind` | `workflow` (an explicit graph) or `agent` (a bounded tool loop) |
| `prompt.system` | System prompt of the node's model calls |
| `description` | What the node does (the MCP server's tool description) |
| `prompt.input_schema`, `prompt.output_schema` | Checked against the run input and the run output; the input schema is also the MCP tool's input schema and decides how chat messages become the input ([Chat shortcut](#the-chat-shortcut-model-nodename)) |
| `model_policy.model` | The model the calls ask for; default: the first `candidates` entry that is a model id (not `tier:...`), else `caliban/auto` |
| `tools` | `{"ref", "effect": "read"\|"write", "allow_tainted"?: [label patterns]}`. `ref`: `mcp://server/tool#sha256:<hash>` (an approved, pinned manifest of a registered server; see [tools.md](tools.md)), `node://name@vN` (another node of the tenant, pinned to a version) or `builtin://datasource_query` (read only) |
| `datasources.scopes` | `<datasource>.<object>:<read\|write>` |
| `budgets` | `steps`, `tokens`, `wall_clock_s`, optional `usd`; `depth` (subnode nesting, default 3) and `fanout` (map concurrency, default 8). See [Budgets](#budgets) |
| `guards` | `max_repeats` (loop guard, default 3), `tool_retries` (default 2). See [Guards](#guards) |
| `graph` | `entry` (default: the first vertex), `vertices`, `edges` (`from`, `to`, optional `when`) |
| `agent.max_turns` | Agent nodes: model turns at most (default `budgets.steps`) |

| `exposure.chat_input` | Without an input schema: `"text"` (default) or `"messages"`, see [Chat shortcut](#the-chat-shortcut-model-nodename) |

Other unknown sections (`guardrails`, the rest of `exposure`, `eval`, ...) are kept and hashed but
not enforced yet.

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

**Tools.** `node://name@vN` is handled by the executor. Other references go through the data
plane's tool registry: `mcp://` resolves only to an approved manifest of a server the tenant
registered, `builtin://datasource_query` to the built-in query tool; any other scheme is an
unknown tool kind. A tool not trusted with personal data gets PII surrogates in its arguments; tool
results are anonymized as they enter the run; values carry taint labels, and a write with tainted
arguments needs an allowlist entry or a human approval. All of this is in [tools.md](tools.md).

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
is a `422` listing every problem: `error.message` joins them, and `error.problems` lists them one
by one as `{"kind", "message", "path"?}` with `kind` one of `spec`, `tool`, `datasource_scope`,
`budget`, `node_ref`, `cycle`; creating a version and promoting one answer the same way):

- the static checks again;
- every `node://name@vN` the version calls (tools and `subnode` vertices) is a **published** version
  of the same tenant, and node-to-node references form no cycle;
- every datasource scope names a live datasource of the tenant and `*` or an approved ontology
  entity bound to it (by collection or entity name);
- the budgets fit inside the tenant's **node caps**: `node_caps` on the tenant (`PATCH
  /api/v1/tenants/{t}`, `null` restores the defaults: steps 200, tokens 2,000,000, wall_clock_s
  3,600, depth 5, fanout 32). Promoting a version checks the current caps again;
- every `mcp://server/tool#sha256:...` names an approved manifest, with exactly that pin, of a
  server the tenant registered (the tool registry, [tools.md](tools.md)); `builtin://` tools are
  read only, and `builtin://datasource_query` needs `datasources.scopes`.

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

| Role | `nodes.read` | `nodes.write` | `nodes.publish` | `nodes.run` | `runs.read` | `runs.data` | `runs.answer` |
|---|---|---|---|---|---|---|---|
| `owner`, `admin` | yes | yes | yes | yes | yes | yes | yes |
| `tenant_admin` | yes | yes | yes | yes | yes | yes | yes |
| `developer` | yes | yes | no | yes | yes | yes | no |
| `viewer` | yes | no | no | no | yes | no | no |
| `auditor` | yes | no | no | no | yes | no | no |
| `billing` | no | no | no | no | no | no | no |

The `runs.*` permissions are for the [console endpoints](#console-endpoints): `runs.read` shows run
metadata, `runs.data` run content, `runs.answer` lets a user answer questions and approve or deny
tainted writes as themselves.

Runs are started with tenant **API keys**. A key may carry a **node allowlist** (`nodes` when it is
created: `POST /api/v1/tenants/{t}/api-keys {"name": ..., "nodes": ["triage"]}`). Without one it may
run every published node of its tenant; `[]` runs none. Granting node access to a key needs
`nodes.run` on the tenant: a key created by someone without it runs no nodes.

The allowlist and the key's datasource scopes can be changed after creation:
`PATCH /api/v1/tenants/{t}/api-keys/{key}` `{"nodes": ["triage"] | null, "datasource_scopes": [...] |
null}` (absent fields are kept; `null` lifts the restriction). It needs `api_keys.write`, and
`nodes.run` to change node access; it is audited as `api_key.update` with the old and new values,
and routers apply it with their next snapshot.

## Running a node

Data plane, tenant API key as bearer token, the key allowed to run the node:

| Endpoint | Does |
|---|---|
| `POST /v1/nodes/{name}/runs` `{"input": ..., "version"?: v, "async"?: false, "stream"?: false, "wait_s"?: s, "budget"?: {...}}` | Starts a run of the live version (or `version`). Sync by default: waits until the run ends or waits for a human, at most `CALIBAN_NODE_SYNC_WAIT_SECS` (default 60) or `wait_s`; `200` when it ended, else `202` with the run so far. `"async": true` answers `202` at once. `"stream": true` answers with the run's [events](#streaming-run-events) (SSE) until it ends or waits for a human. Instead of `input`, `"chat": {"messages": [...]}` gives chat messages that are mapped to the node's input as the [chat shortcut](#the-chat-shortcut-model-nodename) does. `Idempotency-Key` returns the run the first request created (`Idempotent-Replayed: true`); the same key with another body is a `422`. The input is checked against `prompt.input_schema` (`400`) |
| `GET /v1/runs` | The tenant's runs the key may see (its node allowlist), newest first: `?node=`, `?status=` (comma separated), `?created_after=`, `?created_before=` (RFC 3339), `?limit=` (default 50, at most 200), `?cursor=` (`next_cursor` of the previous page). Summaries only (no content, no steps) |
| `GET /v1/runs/{id}` | The run: `status`, `output`, `partial`, `error`, `stop_reason`, `awaiting` (`step`, `question`), `budget` (limits and spend), `cost_usd`, `usage` (prompt and completion tokens of its model calls), `steps` (id, vertex, kind, status, tokens, usd, taint labels, start, duration), `origin`, `cancel_requested`, `last_event` |
| `GET /v1/runs/{id}/events` | The run's [events](#streaming-run-events) (SSE), resumable with `Last-Event-ID` (or `?after=`) |
| `POST /v1/runs/{id}/input` `{"answer": ..., "step"?: id}` | Answers the human step the run waits for; `202`, the run resumes. `409` when it is not waiting |
| `POST /v1/runs/{id}/cancel` | Cancels the run (see [Cancellation](#cancellation)): `200` when it ended at once (or was already cancelled), `202` when a running run was asked to stop, `409` (`run_already_ended`) when it ended otherwise |

Statuses: `pending`, `running`, `sleeping`, `input_required`, `succeeded`, `failed`,
`budget_exhausted` (ended gracefully: `output` holds the partial result, `stop_reason` says why),
`cancelled` (`stop_reason`: who cancelled it; `output` holds the partial result). Other codes:
`401` (key), `403` (`node_not_allowed`), `404` (`node_not_found`: not published, or no live
version; `run_not_found`), `503` (`nodes_not_enabled`). Every run response carries the
`Caliban-Run-Id` header.

### Streaming run events

`POST /v1/nodes/{name}/runs` with `"stream": true`, and `GET /v1/runs/{id}/events`, answer with
Server-Sent Events. Events come from the journal (`node_run_event`), numbered from 1 per run in the
order the journal committed them, so a client that loses its connection reconnects to any worker
(or router) with `Last-Event-ID` and gets exactly what it missed. Each event:

```
id: 3
event: step.finished
data: {"id": 3, "type": "step.finished", "run_id": "run_...", "at": "...", "data": {...}, "run": {...}?}
```

| Type | `data` |
|---|---|
| `run.created` | `node`, `version` |
| `step.started` | `step`, `vertex`, `kind`, `labels` (taint labels of what the step consumes) |
| `step.finished` | `step`, `vertex`, `kind`, `status`, `tokens`, `prompt_tokens`, `completion_tokens`, `usd`, `cost_usd` (the run's spend so far), `labels` (of its output), `duration_ms` |
| `run.input_required` | `step`, `question`, `wake_at`, `cost_usd` |
| `run.sleeping` | `wake_at`, `cost_usd` (a durable sleep, for example a rate limit) |
| `run.input_received` | `step`, `by` (who answered) |
| `run.cancel_requested` | `by` |
| `run.finished` | `status`, `error`, `stop_reason`, `cost_usd` |

Events never carry step content (step results, inputs). The only content is the question of
`run.input_required`, which the journal keeps sealed and the server opens for the caller: on the
data plane the caller is an API key that may run the node, which may read the run anyway. The
stream ends after `run.finished`, or after `run.input_required` while the run still waits for that
answer; that last event carries the run as `GET /v1/runs/{id}` shows it, in `run`. Keep-alive
comments are sent every 15 seconds. Events written on the same worker reach the stream at once;
events of a run executing on another worker are seen at the next poll (`CALIBAN_NODE_POLL_MS`).

### Cancellation

`POST /v1/runs/{id}/cancel` is durable and works whichever worker runs the run:

- a run that waits (`pending`, `sleeping`, `input_required`) is `cancelled` at once, and a later
  answer is refused (`409`);
- a running run is asked to stop (`cancel_requested_at` in the journal): its worker checks before
  every new step (the write of `step.started` is fenced by the request), so it stops at the next
  step boundary, records the step in flight (it was paid for) and ends `cancelled` with the last
  completed value as its partial output. A model call in flight is not interrupted, and a model call
  that fails transiently is not retried once the run is cancelled. A run whose worker died is
  ended by the worker that takes it over.

Cancellations are audited (`node.run.cancel`, once per run).

### The chat shortcut (`model: "node/<name>"`)

`model: "node/<name>"` (the live version) or `"node/<name>@v<N>"` (a published version) on
`POST /v1/chat/completions` and `POST /v1/messages` runs the node, so existing OpenAI and
Anthropic SDK users need no new client. Same API key and allowlist as the run API.

**Input.** The conversation becomes the run input:

- the node declares `prompt.input_schema`: the last user message, if it is JSON matching the schema,
  is the input as is; otherwise its text goes where the schema expects text: the whole input for a
  `string` schema, or the one string property of an object schema that has exactly one (its only
  required property, or its only property). The reference triage node gets `{"case": "<text>"}`.
  Any other schema refuses the request (`400 invalid_input`), saying what it expects;
- no input schema: `exposure.chat_input` decides: `"text"` (default) is the last user message's
  text; `"messages"` is `{"messages": [{"role", "content"}, ...]}` with the text of every message,
  system messages included.

**Answer.** The node's output is the assistant message (a string as is, other JSON compact).
`finish_reason` (OpenAI) / `stop_reason` (Anthropic) is `stop` / `end_turn` when the run succeeded
and `length` / `max_tokens` when it ended on its budget (partial output). A run that fails is a
`502` (`node_run_failed`), a cancelled one a `409` (`node_run_cancelled`); a non-streaming request
whose run is still going after `CALIBAN_NODE_SYNC_WAIT_SECS` is a `504` (`node_run_timeout`) and the
run carries on (follow it with the run API). `usage` is the sum of the run's model calls so far
(`prompt_tokens`, `completion_tokens`; Anthropic `input_tokens`, `output_tokens`). The response
carries `Caliban-Run-Id`, `x-caliban-route: node/<name>@v<N>` and `x-caliban-run-status`, and a
`caliban` object (`run_id`, `status`, `node`, `version`, `cost_usd`, `awaiting`, `stop_reason`)
that the SDKs keep as an extra field (`completion.model_extra["caliban"]` in the OpenAI Python SDK).

**Human steps.** When the run stops at a human step, the question is the assistant message with
`finish_reason` / `stop_reason` `input_required`, and `caliban.status` is `input_required`. To
answer, send the next request with the header `Caliban-Run-Id: <run id>` and the answer as the last
user message (JSON objects, booleans and numbers are passed as JSON, anything else as text; an
approval of a tainted write takes `{"approve": true}` or `yes`). The response is the rest of the
run. With the OpenAI Python SDK:

```python
r = client.chat.completions.create(model="node/triage", messages=[{"role": "user", "content": "Chest pain since Tuesday"}])
if r.choices[0].finish_reason == "input_required":
    run_id = r.model_extra["caliban"]["run_id"]
    r = client.chat.completions.create(
        model="node/triage",
        messages=[{"role": "user", "content": "Two days, nobody in danger"}],
        extra_headers={"Caliban-Run-Id": run_id},
    )
```

**Streams** (`"stream": true`): the first chunk carries the run id (`caliban.run_id`; Anthropic:
`message_start.message.caliban`), then comments (OpenAI, ignored by SDKs) or `ping` events
(Anthropic) while steps run, then the answer as a content delta, the finish reason with the
`caliban` object, usage (OpenAI: with `stream_options.include_usage`) and the end of the stream, in
the client's dialect. A node's own model calls cannot name a node (`400`; use a `node://` tool or a
`subnode` vertex).

### The MCP server

Every data plane (standalone, routers) serves the MCP server at `/mcp`: Streamable HTTP,
stateless, so any router answers any request and a fleet behind a load balancer needs no session
affinity. Routers forward the runs to workers like the run API.

- **Auth**: the tenant API key as bearer token (`Authorization: Bearer cal_...`, or `x-api-key`);
  without a valid key the answer is `401` before MCP is spoken.
- **`tools/list`**: the live version of each published node of the key's tenant that the key may run.
  Name: the node's name; description: the spec's `description`; input schema: the node's
  `prompt.input_schema` when it is an object schema, another schema wrapped as `{"input": <schema>}`,
  else `{"input": <any JSON>}`. Specs are sealed, so a router opens them with its `CALIBAN_KEK`;
  without one, tools are listed with the generic `{"input"}` schema.
- **`tools/call`**: runs the node and waits at most `CALIBAN_NODE_SYNC_WAIT_SECS`. The result is the
  node's output as text, plus `structuredContent` when it is an object. A failed or cancelled run is
  an error result. A run that waits for a human, or is still going, returns its state
  (`structuredContent.run` with the run id, and the question): answer it through the run API.
- **Tasks** (`CALIBAN_MCP_TASKS=true`, off by default: the spec marks Tasks experimental): a client
  that declares the tasks extension gets a task for every `tools/call` instead of waiting. The task
  id is the run id, so tasks are as durable as runs and any router answers for any task. `tasks/get`
  maps the run (`working`, `input_required` with the question as an elicitation request whose key
  is the step, `completed` with the tool result, `cancelled`); `tasks/update` with
  `{"<step>": {"action": "accept", "content": {"answer": ...}}}` answers it; `tasks/cancel` cancels
  the run. A stateless server learns the client's capabilities from each request, so Tasks needs
  clients on the `2026-07-28` protocol (per-request metadata).
- `CALIBAN_MCP_ALLOWED_HOSTS`: the `Host` values accepted (DNS-rebinding protection), comma
  separated; unset accepts any (every request needs an API key anyway).

### `caliban/auto` picks a node

A tenant maps intents to nodes: in the config file,

```toml
[routing.tenants.acme.routes]
triage = "node/triage"              # the live version; "node/triage@published" is the same
"billing.refund" = "node/refunds@v3"
```

and as a tenant setting on the control plane, `PATCH /api/v1/tenants/{t}` `{"node_routes":
{"triage": "node/triage"}}` (`null` clears it; shipped in the snapshot; it overrides the file intent
by intent; audited as `tenant.update`). The intents are the tenant's `caliban/auto` intents (its own
exemplars in `[routing.tenants.<id>.exemplars]`, and the deployment's).

When a `caliban/auto` request classifies into an intent that maps to a node, the node runs instead of
a model call, through the same path as `model: "node/<name>"` (the run's `origin` is
`auto:<intent>`). The request is classified once: the node path and the fallback both use the
routing decision the request already has, and a node's own model calls never hand off to a node.
Otherwise a model answers, and the response says why in `x-caliban-route-fallback`:

| Reason | When |
|---|---|
| `low_confidence` | Stage-1 kNN did not decide the intent (it abstained: confidence or margin under the thresholds, or out of scope; it timed out, or it is off), so the keyword rules did |
| `no_node_for_intent` | The intent maps to no node |
| `node_not_allowed` | The API key may not run the node |
| `node_unavailable` | The node has no published version (live, or the pinned one), or no worker answers |
| `nodes_not_enabled` | This data plane runs no nodes (no `CALIBAN_KEK`, or a router without workers) |
| `node_over_budget` | The tenant's node spend caps are reached, or leave less than the version's `budgets.usd` |
| `node_input_invalid` | The conversation does not fit the node's input schema |

`x-caliban-route` names the path taken: `node/<name>@v<N>`, or `model:<id>` (set on every
`caliban/auto` answer of a tenant that maps intents to nodes). Usage events record it: the node's
model calls carry `route: node/<name>@v<N>` (next to `node`, `node_version`, `run_id`), a model
answer carries `route: model:<id>` and `route_fallback`. A run that started is never replaced by a
model call: its failure is the answer. Streams work on both paths. To continue a run that
`caliban/auto` started, send `model: "caliban/auto"` with `Caliban-Run-Id`: it goes on with the
run's node, without classifying again.

### Console endpoints

The admin API (SSO with roles, or the break-glass token) shows node runs to the console. The control
plane reads the node journal: the database's in Postgres mode (shared with the workers), or the
in-memory journal of a standalone process. A control plane without a database that is not
standalone has no runs to show and answers `503`.

| Endpoint | Permission | Does |
|---|---|---|
| `GET /api/v1/tenants/{t}/runs` | `runs.read` | The tenant's runs, newest first (same filters and cursor as `GET /v1/runs`) |
| `GET /api/v1/tenants/{t}/runs/{id}` | `runs.read` | The run: status, invoker, origin, budget, cost, usage, steps (vertex, kind, status, start, duration, tokens, cost, taint labels). With `runs.data` also the content: `input`, `output`, each step's `output`, the awaited `question` (`content_visible` says which) |
| `GET /api/v1/tenants/{t}/inbox` | `runs.read` | Runs waiting for a human, oldest wait first: `kind` `question` or `approval` (a tainted write), `step`, `waiting_since`, `expires_at`; `question` with `runs.data` |
| `POST /api/v1/tenants/{t}/runs/{id}/input` `{"answer": ..., "step"?: id}` | `runs.answer` | Answers the question, or approves (`{"approve": true}`) or denies a tainted write, as the signed-in user; `202` with the run, `409` when it is not waiting |

Who reads what: run **metadata** (`runs.read`) is for every role but `billing`. Run **content**
(`runs.data`) is the tenant's data and may hold personal data, so only the roles that build and run
nodes see it (`owner`, `admin`, `tenant_admin`, `developer`); auditors and viewers see what happened,
not what was said. **Answering** (`runs.answer`) decides what a node may do, so it is kept apart
from building nodes, like approving tools: `owner`, `admin`, `tenant_admin`. An answer from the
console is journaled with the user's identity (the audit actor, e.g. `jo@example.com
<issuer#subject>`) and recorded in the audit chain at once.

### Audit of run decisions

Decisions made on the data plane go into the control plane's hash-chained audit log:

| Action | Recorded when |
|---|---|
| `node.run.answer` | A human step is answered (API key, chat continuation, MCP task, console) |
| `node.write.approve`, `node.write.deny` | A tainted write is approved or denied |
| `node.run.cancel` | A run is cancelled |
| `tool.approve`, `tool.revoke` | A tool manifest is approved or revoked (on the control plane itself, see [tools.md](tools.md)) |

The actor is who decided (`api_key:<hash prefix>`, or the console user); the target is the run;
the detail names the node, version and step. A worker writes the event in the transaction of the
decision, into the journal's outbox (`node_audit`), and ships the outbox to
`POST /api/v1/audit/ingest` (router token) at least once: an entry is held while it is sent
(60 s, then another worker may take it) and deleted only after the control plane acknowledged it.
Each event has a stable id (`<run>/<step>/answer`, `<run>/cancel`), and the control plane records an
id once (`audit_ingest`), so a redelivery appends nothing and `chain_verified` holds. A standalone
process delivers to its own control plane in-process; the console's answers are recorded directly.

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
whichever worker claims it first. Routers relay event streams as they come, and run the chat
shortcut, the MCP server and `caliban/auto` themselves, starting and following runs through the
workers' run API.

**The control plane owns migrations.** A worker never changes the schema: at startup it checks
that the database holds exactly the migrations it was built with (same versions, same checksums)
and refuses to start otherwise, saying whether to upgrade the control plane first (the schema is
behind) or the worker (the schema is ahead). Upgrade the control plane, then the workers. A worker
needs no DDL rights; its database role needs:

```sql
GRANT USAGE ON SCHEMA public TO caliban_worker;  -- the schema holding Caliban's tables
GRANT SELECT ON caliban_schema_migrations TO caliban_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_run, node_step, node_event, node_run_event, node_audit TO caliban_worker;
GRANT SELECT, INSERT, UPDATE ON node_spend TO caliban_worker;
ALTER ROLE caliban_worker BYPASSRLS;  -- the journal tables have per-tenant row-level security; a worker serves every tenant
```

(`DELETE` on `node_run` is for the retention purge, which removes a finished run's steps and
events with it; `DELETE` on `node_audit` empties the audit outbox once the control plane has it; `node_spend` holds the tenants' spend per day, see [Budgets](#budgets). No
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
| `CALIBAN_MCP_TASKS` | routers, standalone | `true` turns on MCP Tasks for the MCP server (off by default) |
| `CALIBAN_MCP_ALLOWED_HOSTS` | routers, standalone | `Host` values the MCP server accepts, comma separated (unset: any) |

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
| `node_run_event` (0021) | The run's [events](#streaming-run-events), numbered per run under the run row's lock (`node_run.event_seq`); `node_run` also has `cancel_requested_at`, `cancelled_by` and `origin`, and `node_step` the prompt and completion tokens and taint labels |
| `node_audit` (0021) | The [audit outbox](#audit-of-run-decisions) |

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
against the mock model server, with the catalogue as a real MCP server (`rmcp`, Streamable HTTP):
registered, discovered, scanned and approved through the control plane, then called with tokens
minted per call that the server verifies against Caliban's JWKS. Neither the client's API key nor
the person's email reaches the tool server.

## Not in this release

- **P3 M8:** `code` vertices (WASM), the console views themselves (the endpoints are here), evals as
  promotion gates, A2A.
- Cancelling a run from the console (cancel it with the run API).
- MCP: the human step of a synchronous `tools/call` is answered through the run API (MCP's
  multi-round-trip input requests are not used); MCP Tasks need the `2026-07-28` protocol.
- RAG search as a built-in tool: `caliban-rag` has no retriever yet (TODO; the `retrieved` taint
  label is reserved for it).
- Journal rows of a deleted tenant stay until retention purges them (unreadable meanwhile: its data
  key is destroyed). Node specs are stored in clear in the control-plane database, as before; they
  are sealed only in snapshots and journals.
