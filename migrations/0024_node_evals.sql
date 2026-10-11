-- 0024: node evals and the injection suite (P3 exit criteria). See crates/caliban-nodes/src/eval/,
-- crates/caliban-nodes/src/journal/evals.rs and docs/evals.md.
--
-- Never edit an applied migration; add a new one.
--
-- Everything here sits next to the node journal (shared by the control plane and the workers):
-- - `node_golden_set`: the golden set of one node version, sealed under the tenant's data key (the
--   cases are tenant content). Written by the control plane only.
-- - `node_eval_policy`: the promotion bar of a node (what its latest evals must reach before a
--   version is promoted). Written by the control plane only.
-- - `node_eval`: one eval run (a golden-set eval or the injection suite) of one published node
--   version. The control plane creates it with its plan sealed under the tenant's data key; workers
--   claim it like runs (FOR UPDATE SKIP LOCKED, a lease they renew), start its node runs through
--   the executor and record the result: metrics only (`summary`), never content.
-- - `node_eval_trial`: one trial (a case run once) of an eval: its node run, cost, latency and
--   verdict; what the scorers said about the content is sealed (`detail`).
-- - `node_event` gains the kind `observation`: what a sandboxed tool of an injection run received.
--
-- Like the journal, these tables have no foreign key to tenant, and per-tenant row-level security.

CREATE TABLE node_golden_set (
    tenant_id   TEXT NOT NULL,
    node        TEXT NOT NULL,
    version     INTEGER NOT NULL,
    cases       TEXT NOT NULL,
    case_count  INTEGER NOT NULL,
    hash        TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_by  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, node, version)
);

CREATE TABLE node_eval_policy (
    tenant_id   TEXT NOT NULL,
    node        TEXT NOT NULL,
    policy      JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_by  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, node)
);

CREATE TABLE node_eval (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    node                 TEXT NOT NULL,
    version              INTEGER NOT NULL,
    spec_hash            TEXT NOT NULL,
    -- 'adaptive' is reserved for an adaptive attacker stage (black-box search for injections
    -- against the node, AutoDojo, arXiv 2606.15057): not built yet, and never a promotion gate.
    suite                TEXT NOT NULL CHECK (suite IN ('golden', 'injection', 'adaptive')),
    k                    INTEGER NOT NULL CHECK (k > 0),
    concurrency          INTEGER NOT NULL CHECK (concurrency > 0),
    created_by           TEXT NOT NULL,
    -- The API key its node runs (and judge calls) are made, limited and metered as.
    api_key_id           TEXT,
    invoker_key_hash     TEXT NOT NULL,
    plan                 TEXT NOT NULL,
    case_count           INTEGER NOT NULL,
    status               TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
    lease_owner          TEXT,
    lease_expires_at     TIMESTAMPTZ,
    claims               INTEGER NOT NULL DEFAULT 0,
    summary              JSONB,
    error                TEXT,
    cancel_requested_at  TIMESTAMPTZ,
    cancelled_by         TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    started_at           TIMESTAMPTZ,
    finished_at          TIMESTAMPTZ,
    CHECK ((status = 'running') = (lease_owner IS NOT NULL))
);
CREATE INDEX node_eval_tenant ON node_eval (tenant_id, node, version, created_at DESC);
CREATE INDEX node_eval_claimable ON node_eval (created_at, id) WHERE status IN ('pending', 'running');

CREATE TABLE node_eval_trial (
    eval_id      TEXT NOT NULL REFERENCES node_eval(id) ON DELETE CASCADE,
    case_id      TEXT NOT NULL,
    trial        INTEGER NOT NULL,
    tenant_id    TEXT NOT NULL,
    run_id       TEXT,
    status       TEXT NOT NULL CHECK (status IN ('running', 'passed', 'failed', 'error')),
    cost_usd     DOUBLE PRECISION NOT NULL DEFAULT 0,
    latency_ms   BIGINT NOT NULL DEFAULT 0,
    tokens       BIGINT NOT NULL DEFAULT 0,
    verdict      JSONB NOT NULL DEFAULT '{}',
    detail       TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    finished_at  TIMESTAMPTZ,
    PRIMARY KEY (eval_id, case_id, trial)
);

ALTER TABLE node_event DROP CONSTRAINT node_event_kind_check;
ALTER TABLE node_event ADD CONSTRAINT node_event_kind_check CHECK (kind IN ('input', 'timer', 'observation'));

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['node_golden_set', 'node_eval_policy', 'node_eval', 'node_eval_trial']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
                     USING (tenant_id = current_setting('app.tenant_id', true))$p$, t);
  END LOOP;
END $$;
