-- 0015: the tenants' node spend, per day (P3 M3). See crates/caliban-nodes/src/budget.rs,
-- crates/caliban-nodes/src/journal/ and docs/nodes.md ("Budgets").
--
-- Never edit an applied migration; add a new one.
--
-- node_spend: what the tenant's node runs spent on model calls per UTC day, in USD (priced like
-- the metering). Every worker adds a step's cost here in the same transaction that checkpoints the
-- step (a step is written once, so its cost is counted once), and checks the tenant's daily and
-- monthly caps against it before every model call: the journal, not a process, is the source of
-- truth, so the caps hold across workers. Rows are not purged with finished runs.
--
-- The caps themselves are a tenant setting (0016).

CREATE TABLE node_spend (
    tenant_id  TEXT NOT NULL,
    day        DATE NOT NULL,
    usd        DOUBLE PRECISION NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day)
);
ALTER TABLE node_spend ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON node_spend USING (tenant_id = current_setting('app.tenant_id', true));
