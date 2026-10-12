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
