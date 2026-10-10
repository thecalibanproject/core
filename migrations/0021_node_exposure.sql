-- 0021: node runs exposed to clients (P3 M5, M6). See crates/caliban-nodes/src/journal/ and
-- docs/nodes.md ("Run API", "Streaming", "Audit of run decisions").
--
-- Never edit an applied migration; add a new one.
--
-- - A run can be cancelled: status `cancelled`; a running run is asked to stop
--   (`cancel_requested_at`) and its worker stops at the next step boundary.
-- - `origin`: what started the run when it was not a run request (`auto:<intent>` when
--   caliban/auto handed a chat request to a node).
-- - Run events (`node_run_event`): what event streams read, so a client can resume on any worker
--   with Last-Event-ID. Numbered per run under the run row's lock (`event_seq`), so numbers follow
--   commit order. Event data is metadata (steps, costs, taint labels); the only sealed value is
--   the question of `run.input_required`, under the tenant's data key like the rest of the journal.
-- - Steps keep their prompt and completion tokens (a run's usage) and their taint labels.
-- - The audit outbox (`node_audit`): human answers, approvals of tainted writes and cancellations,
--   written by workers in the transaction of the decision, shipped to the control plane's
--   hash-chained audit log at least once (deduplicated there by id), then deleted.

ALTER TABLE node_run DROP CONSTRAINT node_run_status_check;
ALTER TABLE node_run ADD CONSTRAINT node_run_status_check
    CHECK (status IN ('pending', 'running', 'sleeping', 'input_required', 'succeeded', 'failed', 'budget_exhausted',
                      'cancelled'));
ALTER TABLE node_run
    ADD COLUMN cancel_requested_at TIMESTAMPTZ,
    ADD COLUMN cancelled_by        TEXT,
    ADD COLUMN origin              TEXT,
    ADD COLUMN event_seq           BIGINT NOT NULL DEFAULT 0;
-- Run listing by node, and the inbox (runs waiting for a human).
CREATE INDEX node_run_tenant_node ON node_run (tenant_id, node, created_at DESC);
CREATE INDEX node_run_awaiting ON node_run (tenant_id, created_at DESC) WHERE status = 'input_required';

ALTER TABLE node_step
    ADD COLUMN prompt_tokens     BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN completion_tokens BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN labels            JSONB NOT NULL DEFAULT '[]';

CREATE TABLE node_run_event (
    run_id      TEXT NOT NULL REFERENCES node_run(id) ON DELETE CASCADE,
    seq         BIGINT NOT NULL,
    tenant_id   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (run_id, seq)
);

CREATE TABLE node_audit (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT,
    detail        JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    -- A worker shipping it holds it until then; another worker takes over after that.
    claimed_by    TEXT,
    claimed_until TIMESTAMPTZ
);
CREATE INDEX node_audit_created ON node_audit (created_at);

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['node_run_event', 'node_audit']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
                     USING (tenant_id = current_setting('app.tenant_id', true))$p$, t);
  END LOOP;
END $$;
