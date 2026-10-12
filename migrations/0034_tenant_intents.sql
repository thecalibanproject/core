-- 0034: a tenant's caliban/auto intents and exemplars, managed on the control plane at runtime
-- (research note 02: tenant-defined routes, kNN over labelled exemplars). See
-- docs/nodes.md ("caliban/auto picks a node") and README ("Routing").
--
-- Never edit an applied migration; add a new one.
--
-- intents: {intent: [exemplar, ...]} set through /api/v1/tenants/{t}/intents. Rendered into the
-- snapshot's [routing.tenants.<id>.exemplars] over the config file's, intent by intent (the file
-- stays the bootstrap source); an empty list removes a file intent for the tenant. Routers rebuild
-- their kNN index when the snapshot's exemplars change, without a restart. NULL: none.

ALTER TABLE tenant ADD COLUMN intents JSONB;
