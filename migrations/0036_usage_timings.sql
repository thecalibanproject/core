-- 0036: per-stage durations of a request, the numbers of its `Server-Timing` response header.
-- See crates/caliban-gateway/src/timing.rs and the README ("Stage timings").
--
-- Never edit an applied migration; add a new one.
--
-- usage_event.timings: a JSON object of milliseconds (auth_ms, route_ms, embed_ms, pii_ms,
-- cache_ms, upstream_ms, upstream_total_ms, total_ms), a key per stage that ran. Durations only:
-- which classifier stage decided is content-class (0028) and is not stored. NULL on events
-- written before this migration and when the router recorded none.

ALTER TABLE usage_event ADD COLUMN timings JSONB;
