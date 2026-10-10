-- 0011: split-mode routers report which snapshot they serve (KEK rotation, README "KEK rotation").
--
-- Never edit an applied migration; add a new one.
--
-- One row per router, upserted when the router polls GET /api/v1/snapshot (at most once a minute
-- while nothing changes). Not audited: it is telemetry, not control-plane state. `caliban keys
-- status` and GET /api/v1/keys/status read it to say whether a router still serves a snapshot
-- sealed under a retired KEK.
--   router_id         CALIBAN_ROUTER_ID, else the router's host name.
--   snapshot_version  Version label of the snapshot the router serves (cp-N).
--   snapshot_kek_ids  KEKs that sealed the secrets in that snapshot (kek_ fingerprints).
--   keyring_ids       The router's own keyring (CALIBAN_KEK first, then CALIBAN_KEK_PREVIOUS).
CREATE TABLE router_status (
    router_id         TEXT PRIMARY KEY,
    last_seen         TIMESTAMPTZ NOT NULL,
    snapshot_version  TEXT NOT NULL,
    snapshot_kek_ids  TEXT[] NOT NULL DEFAULT '{}',
    keyring_ids       TEXT[] NOT NULL DEFAULT '{}'
);
