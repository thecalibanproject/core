-- 0017: retention of finished node runs (P3 M3). See crates/caliban-nodes/src/journal/ and
-- docs/nodes.md ("Retention").
--
-- Never edit an applied migration; add a new one.
--
-- Workers (and standalone processes) delete finished runs older than CALIBAN_NODE_RUN_RETENTION_DAYS
-- (default 30) in small batches; their steps and events go with them (ON DELETE CASCADE). This
-- index makes the scan for them cheap.

CREATE INDEX node_run_finished ON node_run (finished_at) WHERE finished_at IS NOT NULL;
