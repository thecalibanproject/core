-- 0007: metering accuracy (bench/RESULTS.md, "Usage accuracy"): cache tier, usage source, prompt
-- cache writes on usage events, and prompt-cache prices in the model catalogue.
--
-- Never edit an applied migration; add a new one.
--
-- All columns are nullable or defaulted, so existing rows and writers that do not set them stay
-- valid.

-- Usage events.
--   cache_tier             On gateway cache hits: 'exact' (T1) or 'semantic' (T2). `cache` stays
--                          'hit' for both, so existing consumers keep working.
--   usage_source           'provider' when the token counts are the provider's own usage report;
--                          'estimated' when the gateway had to estimate them (the client
--                          disconnected mid-stream, the upstream stream ended without usage, or the
--                          model rejects `stream_options`). NULL on cache hits and on rows written
--                          before this migration.
--   cache_write_tokens     Prompt tokens written to the provider's prompt cache (Anthropic
--                          `cache_creation_input_tokens`); part of prompt_tokens.
--   cache_write_1h_tokens  The part of cache_write_tokens written with the 1-hour TTL.
ALTER TABLE usage_event
    ADD COLUMN cache_tier             TEXT CHECK (cache_tier IN ('exact', 'semantic')),
    ADD COLUMN usage_source           TEXT CHECK (usage_source IN ('provider', 'estimated')),
    ADD COLUMN cache_write_tokens     BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN cache_write_1h_tokens  BIGINT NOT NULL DEFAULT 0;

-- Model catalogue: prompt-cache prices (USD per million tokens). NULL means "price as uncached
-- input" (`price_in_per_mtok`; the 1-hour write price falls back to the 5-minute one).
ALTER TABLE model
    ADD COLUMN price_cache_read_per_mtok      DOUBLE PRECISION CHECK (price_cache_read_per_mtok >= 0),
    ADD COLUMN price_cache_write_per_mtok     DOUBLE PRECISION CHECK (price_cache_write_per_mtok >= 0),
    ADD COLUMN price_cache_write_1h_per_mtok  DOUBLE PRECISION CHECK (price_cache_write_1h_per_mtok >= 0);
