-- 0020: datasource scopes on API keys (P3 M4). See crates/caliban-cp/src/store/mod.rs
-- (ApiKeyRecord) and docs/tools.md ("Built-in tools").
--
-- Never edit an applied migration; add a new one.
--
-- The built-in datasource query tool reads only what both the node (its datasources.scopes) and
-- the invoking API key allow. NULL: the key may use every scope of the nodes it runs.

ALTER TABLE api_key ADD COLUMN datasource_scopes TEXT[];
