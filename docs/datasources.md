# Datasources

A datasource is a tenant's connection to one of its databases. The control plane stores it (the
credentials sealed under the tenant's data key), introspects it, and keeps the ontology built from
it; nodes query it through `builtin://datasource_query` ([tools.md](tools.md#built-in-tools)).
MongoDB is the first kind with a query lane (research notes 03 and 08).

## Connection

`POST /api/v1/tenants/{t}/datasources` `{"name", "kind": "mongodb", "connection": {...}}`. For
MongoDB, `connection` is:

| Field | Meaning |
|---|---|
| `uri` | A `mongodb://` or `mongodb+srv://` URI. The password is sealed and shown redacted. Use `{"env": ...}` or `{"file": ...}` to keep it out of the store. |
| `database` | The database the ontology describes. |
| `read_preference` | Optional: `primary`, `primaryPreferred`, `secondary`, `secondaryPreferred` or `nearest`. When set, it wins over the read preference compiled into queries. |
| `read_tag` | Optional, with `read_preference`: one tag set, `"workload:analytics"` or `{"workload": "analytics"}`. |
| `max_time_ms` | Optional upper bound for `maxTimeMS` on every operation (default 15000). |

The principal must be read only: the connector checks `connectionStatus` and refuses a user that
holds any write or admin action.

## Read preference

Compiled queries read from a **tagged analytics secondary**: `readPreference: secondary` with the
tag `{workload: analytics}` (note 08, "Workload isolation"), so a node's queries never compete
with the application on the primary. Introspection samples with `secondaryPreferred`.

| Deployment | What to do |
|---|---|
| Replica set with a member tagged `workload: analytics` (hidden or not), or an Atlas analytics node | Nothing. |
| Replica set without such a member | Tag one: `cfg = rs.conf(); cfg.members[2].tags = {workload: "analytics"}; rs.reconfig(cfg)`. Or set `"read_preference": "secondaryPreferred"` on the connection. |
| A single server, or a connection with `directConnection=true` | Set `"read_preference": "primary"` (the driver talks to that one server either way). |

Without a matching member, every query fails after the driver's server-selection timeout (10 s)
with an error naming the read preference it looked for and these two fixes
(`no MongoDB member matches the read preference secondary with tags {workload: analytics}: ...`).

## Introspection (the ontology bootstrap)

`POST /api/v1/datasources/{id}/introspect` (`datasources.write`) starts the bootstrap of note 08
("Schema inference & ontology bootstrap") and answers `202` with the job (`409` while one runs for
the datasource). The control plane opens the connection's credentials with the tenant's data key,
checks the principal is read only, samples every collection (stratified: `$sample`, the newest
and the oldest documents by `_id`, never natural order; `secondaryPreferred`), infers the paths,
probes references against target `_id`s, and proposes elements: one entity per collection,
embedded entities for arrays of documents, subtype entities for discriminators, attributes, and
unverified reference relations. They are written as `proposed`, in one ontology version, for a
human to review (below).

`GET /api/v1/datasources/{id}/introspection` (`datasources.read`) shows the newest job:
`status` (`running`, `succeeded`, `failed`), `objects`, `proposed`, `skipped`, `version`,
`error`, `started_at`, `finished_at`. The newest job of each datasource is stored, so every
control-plane replica answers and refuses a second start (`409`) while one runs, wherever it
runs; the datasource's `status` follows it (`introspecting`, then `ready` or `failed`). A job
whose control plane stopped before it ended shows as `failed` once it is older than the job
timeout (10 minutes) and a minute, and may be started again. Each start and end is audited as
`datasource.introspection` (counts and outcome, never the error text).

**Re-runs** keep human decisions: element ids are deterministic, and a proposal whose element was
already reviewed (approved, rejected, deprecated, stale) is skipped, as is one identical to the
pending proposal. A re-run that finds nothing new makes no version.

Only the MongoDB kind can be introspected (`422` for others). The LLM proposal pass (names,
descriptions and PII classes from redacted samples) is not part of the job yet: names come from
deterministic rules (`orders` becomes `Order`, `createdAt` becomes `created_at`).

**Proposals made elsewhere** (an exported model, a curated file):
`POST /api/v1/tenants/{t}/ontology/proposals` `{"elements": [...]}` (`ontology.review`) writes
them as `proposed` in one version (`status` may be left out; whatever status they carry is
ignored). An element whose spec, name and description match the tenant's is skipped, so posting
the same model again makes no version and keeps every review decision (synonyms, confidence and
provenance are not compared). A changed element goes back to `proposed`: over an approved element
that withdraws it until it is approved again, refused with `409` when that breaks a published node
version, unless `acknowledge_breaking: true`. The response gives `version`, `proposed`,
`skipped` and `breaking` (the published node versions a withdrawal affects); `400` for an empty
batch or an empty, too long or repeated id, `404` for an unknown tenant.

## Ontology review

Element ids belong to a tenant: two tenants may both have an element `Service` (introspection
proposes entity names from collection names). Every review names the tenant:

| Endpoint | Does |
|---|---|
| `GET /api/v1/tenants/{t}/ontology` | The tenant's ontology: its version and elements (also `GET /api/v1/ontology?tenant_id=`) |
| `POST /api/v1/tenants/{t}/ontology/review` `{"decisions": [{"id", "decision"}], "acknowledge_breaking"?}` | A batch of decisions (`approve`, `reject`, `deprecate`) as **one** new version |
| `POST /api/v1/tenants/{t}/ontology/elements/{id}/review` `{"decision", "acknowledge_breaking"?}` | One decision (a batch of one) |
| `POST /api/v1/ontology/elements/{id}/review` `{"tenant_id", "decision"}` | The same; `tenant_id` is required |

A batch that changes nothing (re-approving an approved element) makes no version. Reviews need
`ontology.review` on the tenant and are audited as `ontology.review` with the decisions.

## Ontology versions and published nodes

A CQIR query names the ontology version it was written for (`"ontology_version": "acme@52"`), and
node specs often fix their queries (the reference triage node does). Each element records the
version in which its definition (spec) or approval last changed (`changed_in`). The rules:

1. **A version is a review batch, a proposal, or an introspection run**, never one element at a
   time.
2. **Compatible changes keep published nodes working.** A query written for version N compiles on
   any later version of the same tenant as long as nothing it touches (its metrics and their
   grains and attributes, its dimensions and filters and their entities, the relations it joins
   along) changed after N. Approving new elements, rejecting proposals, or editing elements the
   query does not use are compatible. Policies always apply as they are now.
3. **Breaking changes are flagged at review time.** A decision that withdraws an approved element
   that a published node version's fixed query touches is refused with `409`, naming the elements
   and the node versions (`triage@v3`), unless the request says `acknowledge_breaking: true`. The
   error has `code: "ontology_breaking_change"` and a `breaking` list next to the message
   (`element`, `change`, `nodes` as `name@vN`, and `versions` as `{"node", "version"}`); proposals
   that change approved elements are refused the same way. The
   affected versions then fail on that query (`'Service.city' changed in version 53: rebuild the
   query on the current version`) until a version written on the new ontology is published.
4. **Publishing checks the version.** Every fixed CQIR query of a spec must name a version of the
   tenant's ontology that exists and that the query still compiles on (`ontology_version`
   problems, with the JSON pointer of the query). Filter values may be templates, filled when the
   node runs: the whole `v` (`{"type": "string_list", "v": "{{outputs.assess.cities}}"}`), an
   element of a list or range, or the whole typed `value`. At publish a template stands for a
   value of the declared type, so the ids, operators, value types and structure are still checked;
   the values themselves are checked when the node runs. A template anywhere else (an id, an
   operator, `limit`) is refused.
5. A query names a version newer than the current one, another tenant's, or a malformed one: refused.

This follows note 08's validation step 1 (every id exists in the published ontology version) and
note 03's versioned, append-only ontology with publish as a pointer move.
