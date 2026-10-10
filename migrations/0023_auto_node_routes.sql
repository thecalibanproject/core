-- 0023: caliban/auto hands requests to nodes (P3 M6). See crates/caliban-gateway/src/pipeline.rs and
-- docs/nodes.md ("caliban/auto picks a node").
--
-- Never edit an applied migration; add a new one.
--
-- - tenant.node_routes: the tenant's intent to node map (`{"triage": "node/triage"}`), a tenant
--   setting shipped to routers in the snapshot (it overrides `[routing.tenants.<id>.routes]` of the
--   config file, intent by intent).
-- - usage_event.route and route_fallback: which path a caliban/auto request of such a tenant took
--   (`node/<name>@v<N>`, carried by the run's model calls, or `model:<id>`), and why it did not go
--   to a node.

ALTER TABLE tenant ADD COLUMN node_routes JSONB;
ALTER TABLE usage_event
    ADD COLUMN route          TEXT,
    ADD COLUMN route_fallback TEXT;
