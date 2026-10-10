-- 0022: decisions the data plane records into the control plane's audit log (P3 M5). See
-- crates/caliban-cp/src/store/ and docs/nodes.md ("Audit of run decisions").
--
-- Never edit an applied migration; add a new one.
--
-- Workers write human answers, approvals and denials of tainted writes, and cancellations to
-- their journal's outbox and ship them to POST /api/v1/audit/ingest at least once. Each event has
-- a stable id; this table remembers the ids already recorded (with the audit row they became), so
-- a retried delivery appends nothing and the hash chain holds every decision once.

CREATE TABLE audit_ingest (
    event_id    TEXT PRIMARY KEY,
    seq         BIGINT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
