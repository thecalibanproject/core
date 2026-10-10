# Node tools

A node calls tools in three ways: another node (`node://name@vN`, see [nodes.md](nodes.md)), a
built-in tool (`builtin://datasource_query`), or a tool of an MCP server the tenant registered
(`mcp://server/tool#sha256:<pin>`). Caliban is the MCP client of those servers and the single
place where their use is enforced: which servers exist, which manifests are approved, which
addresses can be reached, which credentials are sent, which data may leave, and which writes need
a human. All of it is in Rust, none of it in prompts. This page describes P3 milestone M4.

## The tool registry (control plane)

Per tenant, in the control-plane store (migration `0019_tool_registry.sql`; memory and Postgres
stores behave the same).

| Step | Endpoint | Permission | Audit |
|---|---|---|---|
| Register a server | `POST /api/v1/tenants/{t}/tool-servers` `{"name", "url", "auth"?, "credential"?, "trusted"?}` | `tools.write` | `tool_server.create` |
| List servers | `GET /api/v1/tenants/{t}/tool-servers` | `tools.read` | |
| Delete a server | `DELETE /api/v1/tenants/{t}/tool-servers/{server}` (`409` while a published version uses it) | `tools.write` | `tool_server.delete` |
| Discover its tools | `POST .../tool-servers/{server}/discover` | `tools.write` | `tool.discover` |
| Import manifests (a server the control plane cannot reach) | `POST .../tool-servers/{server}/tools` `{"manifests": [{"name", "description", "input_schema"}]}` | `tools.write` | `tool.discover` |
| List manifests (pins, findings, status) | `GET .../tool-servers/{server}/tools` | `tools.read` | |
| Approve a manifest | `POST .../tools/{tool}/approve` `{"pin", "acknowledge_findings"?}` | `tools.approve` | `tool.approve` (with the findings) |
| Revoke an approval | `POST .../tools/{tool}/revoke` `{"pin"}` | `tools.approve` | `tool.revoke` |

| Role | `tools.read` | `tools.write` | `tools.approve` |
|---|---|---|---|
| `owner`, `admin`, `tenant_admin` | yes | yes | yes |
| `developer` | yes | yes | no |
| `viewer`, `auditor` | yes | no | no |
| `billing` | no | no | no |

Approving is kept apart from registering: a developer can register and discover a server, but a
tool only becomes callable when someone who may approve (the same people who may publish nodes)
has looked at it.

**A server.** `name` follows node-name rules and is the `server` in `mcp://server/tool#...`. `url`
is a Streamable HTTP endpoint (`http` or `https`; no stdio, see below), checked against the egress
rules when it is registered. `auth`:

| `method` | Caliban sends | Server side |
|---|---|---|
| `caliban_token` (default), `{"audience"?}` | A token minted for this call (below) as `Authorization: Bearer` | Verifies it with Caliban's JWKS |
| `api_key`, `{"header"?}` | The key the server issued, in `header` (default `Authorization: Bearer`) | Its own check |
| `oauth_client_credentials`, `{"token_url", "client_id", "scope"?}` | An access token from `token_url` (client credentials, cached until shortly before it expires; `scope` to down-scope) | Its authorization server |
| `none` | Nothing | A server on a private network that needs no authentication |

`credential` (the API key or the OAuth client secret) is sealed under the tenant's data key before
it reaches the store, never returned by the API (only `has_credential`), shipped sealed in the
snapshot and opened by the worker for the call; deleting the server wipes it. `trusted: true`
means the tenant trusts the server with personal data (see [Personal data](#personal-data)).

**Discovery, pins and the scan.** Discovery connects through the same egress guard as a call
(with a token minted for `tenant:<t>/node:discovery`), lists the server's tools and records each
manifest with its **pin** (`sha256` over the canonical JSON of name, description and input schema)
and the findings of the **injection scan**:

| Finding | Looks for |
|---|---|
| `instruction` | Text addressed to the model rather than describing the tool: "ignore previous instructions", "before using this tool ...", "do not tell the user", role markers (`<IMPORTANT>`, `system:`) |
| `hidden_unicode` | Zero-width, bidirectional-control and Unicode-tag characters (they hide text from the approver); the rules also run on the text without them |
| `url` | Links, `www.` hosts, e-mail addresses |
| `exfiltration` | Requests for secrets (keys, passwords, `~/.ssh`, `.env`) or to send data somewhere |

Every string the model would see is scanned: the name, the description, and every description,
title, default, enum value and property name of the input schema. A flagged manifest can still be
approved, only with `acknowledge_findings: true`; the audit row records the findings and the
acknowledgement. The scan is a heuristic in front of the human; pinning and taint tracking do not
depend on it.

**Rug pulls.** A manifest is approved by pin. When the server changes a tool (any byte of its name,
description or schema), discovery records a new manifest, `discovered`, which needs its own
approval; the old approval still names the old pin. At run time every call lists the server's
tools again and refuses the call when the tool's manifest no longer has the approved pin
(`manifest changed since it was approved; it needs re-approval`). The model only ever sees the
approved manifest, never what the server says now. `tools/list_changed` notifications are never
trusted: nothing is re-approved on the server's say-so.

**Publishing.** A node version can only be published when every `mcp://server/tool#pin` it
declares names an approved manifest, with exactly that pin, of a live registered server. Approved
manifests and registered servers travel to routers and workers in the signed snapshot
(`tool_servers`, `tools`), credentials sealed.

## The MCP client

The official Rust SDK, `rmcp` 3.5.1, Streamable HTTP transport only (`caliban-mcp`). Each call opens
its own connection to the registered URL, initializes, lists tools, checks the pin, calls the tool,
and closes. A transport failure (unreachable, a 5xx, a timeout) is transient and retried
(`guards.tool_retries`), and counts against the tool's circuit breaker; a tool that reports an
error (`isError`) fails the call (an agent gets the error as a tool result).

**No stdio servers.** MCP also defines a stdio transport, where the client spawns the server as a
child process. Caliban does not support it: spawning tenant-chosen executables from the gateway
would put them inside the data plane's trust boundary (its keyring, its network position, its
memory) with no egress control. Run such servers behind a Streamable HTTP endpoint (many SDKs and
proxies do this) and register the endpoint.

## Tokens: no passthrough

Client tokens are never forwarded: not the run's API key, not anything a client sent. For a
`caliban_token` server, the worker mints a JWT (JWS compact, `EdDSA` over Ed25519) for each call:

| Claim | Value |
|---|---|
| `iss` | `CALIBAN_TOOL_TOKEN_ISSUER` (default `caliban`) |
| `aud` | The server's registered `audience`, default its URL's origin (`https://crm.internal:8443`) |
| `sub` | `tenant:<tenant>/node:<name>@v<version>` (the run's node) |
| `scope` | `tool:<tool>`: the one tool being called |
| `tenant`, `node`, `node_version`, `run_id`, `tool` | The same, as separate claims |
| `iat`, `nbf`, `exp` | Now, now, now + 60 s |
| `jti` | The step's idempotency key: unique per call, the same when a step is replayed (a server can deduplicate writes on it) |

The header carries `kid`. A server verifies the signature against the JWKS, then `iss`, `aud`,
the validity window and that `scope` names the tool being called; `caliban_mcp::token::verify` is
a reference implementation.

**The key.** `CALIBAN_TOOL_TOKEN_KEY` is a base64 Ed25519 seed (`caliban gen-tool-token-key`
prints one and its public key). Workers and standalone processes need it to call `caliban_token`
servers; the control plane needs it for discovery and to publish the JWKS. Without it, such calls
fail with a clear error.

**The JWKS.** The control plane serves `GET /.well-known/caliban-tool-jwks.json` (public, no
authentication): the current key and the previous ones, as RFC 8037 OKP keys. A server that cannot
reach the control plane can be configured with the public key printed by
`gen-tool-token-key` instead.

**Rotation.** Generate a new key; put the old key's public key (base64) in
`CALIBAN_TOOL_TOKEN_PREVIOUS_KEYS` (comma separated) and the new seed in `CALIBAN_TOOL_TOKEN_KEY`
on every process; restart. The JWKS then lists both. Tokens live 60 seconds, so a few minutes after
every worker runs the new key, remove the previous one.

## Egress

| Rule | Why |
|---|---|
| Only registered URLs are reached; redirects are not followed; proxies from the environment are not used | The registry is the allowlist: nothing a model, a tool result or a server response names |
| The host is resolved once per connection, every address it resolves to is checked, and the connection is pinned to the checked address; a host with any refused address is refused | DNS rebinding cannot move a connection to another address after the check |
| Link-local (`169.254.0.0/16`, `fe80::/10`) and cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) are always refused, as are unspecified, broadcast and multicast addresses | The classic SSRF targets |
| Loopback is refused unless `CALIBAN_MCP_ALLOW_LOOPBACK=true` (development, tests) | A tenant-registered URL must not reach services on the gateway's own host |
| Private ranges (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`, CGNAT) are allowed | On-prem tool servers usually live there; registering a server is the explicit, audited human decision that allows it |

The same rules apply to OAuth token endpoints and to discovery from the control plane. TLS uses the
platform trust store (an internal CA can be added there, or through `SSL_CERT_FILE` on Linux).

## Personal data

- **Arguments.** A tool not trusted with personal data (the default) receives its arguments with
  PII replaced as the tenant's PII mode says: the same surrogates the node's model calls see
  (`reversible`, tenant-scoped surrogates), or masks (`mask`). A server registered with
  `trusted: true` receives the values. A tenant in PII mode `off` has asked for no protection. If
  the PII engine fails on the arguments, the call is refused: nothing leaves unchecked.
- **Results** are anonymized as they enter the run, like any untrusted input: personal data a tool
  returns becomes surrogates or masks before a model or a later tool sees it.

## Taint (CaMeL-lite)

The executor labels values by origin (P3 decision 3: every node with write tools gets this by
default; full CaMeL is an opt-in template later):

| Label | Carried by |
|---|---|
| `tool:<server>/<tool>` | The output of an MCP tool |
| `datasource` | Rows from the built-in query tool |
| `retrieved` | Retrieved documents (reserved: there is no RAG tool yet) |
| `pii` | A run input that holds personal data |

Labels flow with the value on each edge, and a vertex also consumes the labels of every earlier
output its config names (`{{outputs.<vertex>}}`). Model calls are not sanitizers: an `llm`,
`router`, `verify` or `reduce` vertex passes on the labels of what it consumed; a subnode returns
its output's labels; a `map` joins its branches'. An agent's conversation accumulates the labels of
every tool result the model saw, so every call it makes afterwards carries them. Branch choices are
not labelled (data flow only). Tool steps journal their output labels, so a replayed run sees the
same labels.

**The rule.** A tool declared `effect: write` whose arguments carry any label other than `pii`
needs either:

- an **allowlist entry** on the tool in the node spec: `"allow_tainted": ["tool:crm/*",
  "datasource"]` (exact labels, prefixes ending in `*`, or `*`); every label must match; or
- a **human approval**: the run stops in `input_required`, awaiting `<step>@approve`, with a
  question naming the tool, the labels and the arguments. `POST /v1/runs/{id}/input
  {"step": "<step>@approve", "answer": {"approve": true}}` approves (`false` refuses: the call
  fails; an agent gets the refusal as a tool result). The decision is a journaled `approval` step
  with the labels and who answered (`api_key:<hash prefix>`, recorded with every answer), and is
  logged on the `caliban::audit` tracing target.

`pii` is handled by the personal-data rules above rather than by approvals: an untrusted tool never
receives personal data, write or read.

## Built-in tools

**`builtin://datasource_query`** (read only; the node must declare `datasources.scopes`). The model
writes a query in CQIR (ontology ids only; never a collection, a path or an operator), passed as
`{"query": {...}}`. Before it runs:

1. every root entity it touches (its metrics' grains, its dimensions' and filters' attributes)
   must be inside the node's read scopes **and** the invoking API key's datasource scopes, when the
   key has any (`POST /api/v1/tenants/{t}/api-keys {"datasource_scopes": ["shop.orders:read"]}`;
   absent: the key may use every scope of the nodes it runs);
2. an entity with a row-level policy is refused: its predicate needs a user principal, which a node
   run (an API key) does not have, so the tool fails closed;
3. the query is validated and compiled against the tenant's approved ontology by the deterministic
   CQIR compiler and lowered for the native lane.

It runs on the native MongoDB lane through a connector that checks its principal is read only (a
principal that can write is refused), with the compiler's `maxTimeMS`, at most 200 rows. Other
datasource kinds are refused until their lane exists. The datasources (credentials sealed) and the
approved ontology reach the data plane only when a published node of the tenant uses the tool.

RAG search is not built in yet: `caliban-rag` has no retriever (TODO).

## Settings

| Variable | Where | Meaning |
|---|---|---|
| `CALIBAN_TOOL_TOKEN_KEY` | workers, standalone, control plane | Base64 Ed25519 seed that signs minted tool tokens |
| `CALIBAN_TOOL_TOKEN_ISSUER` | same | `iss` of minted tokens, default `caliban` |
| `CALIBAN_TOOL_TOKEN_PREVIOUS_KEYS` | same | Retired public keys still listed in the JWKS during a rotation (base64, comma separated) |
| `CALIBAN_MCP_ALLOW_LOOPBACK` | workers, standalone, control plane | `true` lets tool servers live on loopback (development only) |
