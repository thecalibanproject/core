-- 0028: routing decisions are content-class data (research note 02; arXiv 2610.09981). See
-- crates/caliban-cp/src/store/usage.rs and the README ("Usage and routing records").
--
-- Never edit an applied migration; add a new one.
--
-- Which intent a request was classified into, and how often, reveals sensitive topics per user even
-- with content logging off. Usage events therefore no longer keep the per-request routing facts
-- (intent, its confidence, the deciding stage, the node-or-model path and the fallback reason):
-- usage_route_daily keeps counts per (tenant, UTC day, intent, stage, fallback) instead. Billing
-- fields (model, tokens, prices, node, run) are unchanged. Existing rows are counted into the
-- aggregate, then their routing facts are cleared.

CREATE TABLE usage_route_daily (
    tenant_id       TEXT NOT NULL,
    day             DATE NOT NULL,
    intent          TEXT NOT NULL DEFAULT '',
    route_stage     TEXT NOT NULL DEFAULT '',
    route_fallback  TEXT NOT NULL DEFAULT '',
    requests        BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day, intent, route_stage, route_fallback)
);
ALTER TABLE usage_route_daily ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON usage_route_daily USING (tenant_id = current_setting('app.tenant_id', true));

INSERT INTO usage_route_daily (tenant_id, day, intent, route_stage, route_fallback, requests)
SELECT tenant_id, (ts AT TIME ZONE 'UTC')::date, COALESCE(intent, ''), COALESCE(route_stage, ''),
       COALESCE(route_fallback, ''), count(*)
FROM usage_event
WHERE intent IS NOT NULL OR route_stage IS NOT NULL OR route_fallback IS NOT NULL
GROUP BY 1, 2, 3, 4, 5;

UPDATE usage_event SET intent = NULL, intent_confidence = NULL, route_stage = NULL, route = NULL, route_fallback = NULL
WHERE intent IS NOT NULL OR intent_confidence IS NOT NULL OR route_stage IS NOT NULL OR route IS NOT NULL
      OR route_fallback IS NOT NULL;
