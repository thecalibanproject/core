-- 0010: cache hits on caliban/auto are billed at a discounted flat price
-- (docs/architecture/caliban-reference-architecture.md §9, decided 2026-10-09).
--
-- Never edit an applied migration; add a new one. (0009 is reserved for SSO. The runner applies
-- each embedded migration whose version is not yet recorded, in list order, so this file works
-- with or without 0009 present, and 0009 applies on a later start if it lands after this one.)
--
-- All columns are nullable, so existing rows and writers that do not set them stay valid.

-- Usage events.
--   billed_usd  caliban/auto only: what the customer is billed. flat_price_usd on a miss; on a
--               cache hit of either tier, flat_price_usd (the full flat price of the cached
--               answer's tokens) times the tenant's cache-hit fraction. NULL on rows written
--               before this migration (they billed flat_price_usd).
--   saved_usd   Cache hits only: what the hit saved the customer. caliban/auto: flat_price_usd -
--               billed_usd. Other models: the model cost the hit avoided. NULL otherwise.
ALTER TABLE usage_event
    ADD COLUMN billed_usd  DOUBLE PRECISION,
    ADD COLUMN saved_usd   DOUBLE PRECISION;

-- Per-tenant override of [routing] auto_cache_hit_fraction (default 0.20): the fraction of the
-- flat caliban/auto price billed for a cache hit. NULL: the deployment value.
ALTER TABLE tenant
    ADD COLUMN auto_cache_hit_fraction DOUBLE PRECISION
        CHECK (auto_cache_hit_fraction >= 0 AND auto_cache_hit_fraction <= 1);
