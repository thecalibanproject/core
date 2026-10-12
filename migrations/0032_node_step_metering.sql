-- 0032: what a node step's model call cost and how much personal data it protected, so a node's
-- chat answer carries the documented headers (x-caliban-cost-usd, x-caliban-pii-entities). See
-- docs/nodes.md ("The chat shortcut").
--
-- Never edit an applied migration; add a new one.
--
-- node_step.usd stays what the call is billed (the flat caliban/auto price for runs that
-- caliban/auto started, cache hits discounted; the model's price otherwise). model_cost_usd is the
-- real cost of the routed model (the two differ only for caliban/auto). NULL on rows written
-- before this migration: readers use usd then. pii_entities: personal-data entities the gateway
-- protected in the call (0 on older rows).

ALTER TABLE node_step
    ADD COLUMN model_cost_usd DOUBLE PRECISION,
    ADD COLUMN pii_entities   INTEGER NOT NULL DEFAULT 0;
