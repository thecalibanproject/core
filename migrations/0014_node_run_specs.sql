-- 0014: a run keeps the node versions it started on (P3 M3). See crates/caliban-nodes/src/journal/
-- and docs/nodes.md ("Retiring a version").
--
-- Never edit an applied migration; add a new one.
--
-- Retiring a version drains it: runs already started finish on the version they started on, and
-- only new runs are refused. The data plane only receives published versions, so a run carries
-- what it needs itself: `specs` holds, sealed under the tenant's data key (tenant and run id as
-- associated data), the spec of the run's version and of every version it can reach through
-- node:// references, each with its content hash. Runs created before this migration have none
-- and resolve versions from the snapshot, as before.

ALTER TABLE node_run ADD COLUMN specs TEXT;
