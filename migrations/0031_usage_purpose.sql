-- 0031: what Caliban spent on the tenant's behalf, separable from client traffic. See
-- crates/caliban-cp/src/store/usage.rs and docs/rag.md ("Metering").
--
-- Never edit an applied migration; add a new one.
--
-- usage_event.purpose: the work an internal call did for the tenant: 'rag.ingest' (embedding
-- documents of a collection), 'rag.search' (embedding and reranking a node's retrieval query).
-- NULL for client calls and node model calls. Billing-class, not content-class: it says which
-- feature spent, never what a request was about (intents stay out of stored events, 0028).
--
-- usage_daily keeps the purpose in its key, so rolled-up days stay separable ('' when none).

ALTER TABLE usage_event ADD COLUMN purpose TEXT;
CREATE INDEX usage_event_purpose ON usage_event (tenant_id, purpose) WHERE purpose IS NOT NULL;

ALTER TABLE usage_daily ADD COLUMN purpose TEXT NOT NULL DEFAULT '';
ALTER TABLE usage_daily DROP CONSTRAINT usage_daily_pkey;
ALTER TABLE usage_daily ADD PRIMARY KEY (tenant_id, day, node, node_version, purpose);
