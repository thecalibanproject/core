-- 0016: tenant node spend caps (P3 M3). See crates/caliban-cp/src/store/mod.rs (Tenant) and
-- docs/nodes.md ("Budgets").
--
-- Never edit an applied migration; add a new one.
--
-- {"daily_usd": ..., "monthly_usd": ...} (either may be absent); NULL: no cap. A tenant setting
-- (PATCH /api/v1/tenants/{id}) shipped to workers in the snapshot; workers check it against
-- node_spend (0015) before every model call.

ALTER TABLE tenant ADD COLUMN node_spend_caps JSONB;
