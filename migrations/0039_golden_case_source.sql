-- 0039: where a captured golden case came from, so it follows its run's retention and erasure.
-- See crates/caliban-nodes/src/eval/capture.rs and docs/evals.md ("Cases from runs").
--
-- Never edit an applied migration; add a new one.
--
-- node_golden_case_source: one row per golden case built from a run (`POST .../golden-case`, and
-- a `PUT` of a set that keeps or copies a captured case of an existing run). A case copies the
-- run's content (its input, answers and output), so it may not outlive the run: the workers'
-- hourly retention purge removes the case from its set once the run finished more than
-- CALIBAN_NODE_RUN_RETENTION_DAYS ago (`run_finished_at`), and erasing a run
-- (`DELETE .../runs/{id}`) removes it at once. The set is rewritten (resealed, new hash) and the
-- change audited as `node.golden_set.scrub`. Rows are written in the transaction of the set's
-- write and go with the set when it is deleted. Ids and times only, never content.
--
-- Workers rewrite golden sets for retention, so they get SELECT, INSERT, UPDATE on
-- node_golden_set and SELECT, INSERT, DELETE on this table (docs/nodes.md).

CREATE TABLE node_golden_case_source (
    tenant_id        TEXT NOT NULL,
    node             TEXT NOT NULL,
    version          INTEGER NOT NULL,
    case_id          TEXT NOT NULL,
    run_id           TEXT NOT NULL,
    run_finished_at  TIMESTAMPTZ NOT NULL,
    captured_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, node, version, case_id)
);
CREATE INDEX node_golden_case_source_run ON node_golden_case_source (tenant_id, run_id);
CREATE INDEX node_golden_case_source_expiry ON node_golden_case_source (run_finished_at);

ALTER TABLE node_golden_case_source ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON node_golden_case_source
    USING (tenant_id = current_setting('app.tenant_id', true));
