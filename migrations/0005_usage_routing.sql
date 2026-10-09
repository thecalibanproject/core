-- 0005: caliban/auto metering (docs/architecture/caliban-reference-architecture.md §9, flat price).
--
-- Never edit an applied migration; add a new one.
--
-- caliban/auto metering: the routed model's real cost next to the flat auto price, plus the
-- routing facts needed to compute margin per intent and stage. All nullable, so existing rows and
-- writers that do not set them stay valid.
ALTER TABLE usage_event
    ADD COLUMN requested_model        TEXT,
    ADD COLUMN intent_confidence      REAL,
    ADD COLUMN route_stage            TEXT,
    ADD COLUMN routed_model_cost_usd  DOUBLE PRECISION,
    ADD COLUMN flat_price_usd         DOUBLE PRECISION;
