-- 0018: usage of node runs, and the daily usage roll-up (P3 M3). See
-- crates/caliban-cp/src/store/usage.rs and docs/nodes.md ("Usage and retention").
--
-- Never edit an applied migration; add a new one.
--
-- Usage events of node model calls carry the run's node, version and run id, so cost per run and
-- per node fall out of usage data.
--
-- usage_daily: totals per (tenant, UTC day, node, node version) of usage events that are older
-- than the raw retention (CALIBAN_USAGE_RETENTION_DAYS, default 90). The control plane moves whole
-- days of raw events into it, in one statement per batch (DELETE ... RETURNING feeding an upsert),
-- so an event is counted either raw or rolled up, never both; all-time totals read both and stay
-- the same after a purge. Events without a node use node = '' and node_version = 0.

ALTER TABLE usage_event
    ADD COLUMN node         TEXT,
    ADD COLUMN node_version INTEGER,
    ADD COLUMN run_id       TEXT;
CREATE INDEX usage_event_node ON usage_event (tenant_id, node) WHERE node IS NOT NULL;
CREATE INDEX usage_event_run ON usage_event (run_id) WHERE run_id IS NOT NULL;
CREATE INDEX usage_event_ts ON usage_event (ts);

CREATE TABLE usage_daily (
    tenant_id              TEXT NOT NULL,
    day                    DATE NOT NULL,
    node                   TEXT NOT NULL DEFAULT '',
    node_version           INTEGER NOT NULL DEFAULT 0,
    requests               BIGINT NOT NULL DEFAULT 0,
    prompt_tokens          BIGINT NOT NULL DEFAULT 0,
    completion_tokens      BIGINT NOT NULL DEFAULT 0,
    cached_prompt_tokens   BIGINT NOT NULL DEFAULT 0,
    cache_write_tokens     BIGINT NOT NULL DEFAULT 0,
    estimated_requests     BIGINT NOT NULL DEFAULT 0,
    cache_hits             BIGINT NOT NULL DEFAULT 0,
    saved_usd              DOUBLE PRECISION NOT NULL DEFAULT 0,
    semantic_cache_hits    BIGINT NOT NULL DEFAULT 0,
    tokens_saved           BIGINT NOT NULL DEFAULT 0,
    cost_usd               DOUBLE PRECISION NOT NULL DEFAULT 0,
    charged_usd            DOUBLE PRECISION NOT NULL DEFAULT 0,
    auto_requests          BIGINT NOT NULL DEFAULT 0,
    auto_cache_hits        BIGINT NOT NULL DEFAULT 0,
    flat_price_usd         DOUBLE PRECISION NOT NULL DEFAULT 0,
    billed_usd             DOUBLE PRECISION NOT NULL DEFAULT 0,
    auto_saved_usd         DOUBLE PRECISION NOT NULL DEFAULT 0,
    routed_model_cost_usd  DOUBLE PRECISION NOT NULL DEFAULT 0,
    margin_usd             DOUBLE PRECISION NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day, node, node_version)
);
ALTER TABLE usage_daily ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON usage_daily USING (tenant_id = current_setting('app.tenant_id', true));
