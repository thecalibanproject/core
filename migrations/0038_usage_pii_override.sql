-- 0038: a request that asked for weaker personal-data protection than its tenant's policy. See
-- crates/caliban-gateway/src/pipeline.rs and the README ("PII").
--
-- Never edit an applied migration; add a new one.
--
-- usage_event.pii_override_ignored: the request's `caliban.pii` (`off`, `reversible`) when it was
-- weaker than the tenant's mode (raised to any `caliban.pii_floor`) and was therefore ignored: a
-- per-request mode only ever makes the policy stricter (research note 05, section 4: the policy
-- engine decides what leaves the trust boundary, not the caller). Policy-class, not content-class:
-- it says what the caller asked for, never what the request said. NULL when the request asked for
-- nothing weaker, and on events written before this migration.

ALTER TABLE usage_event ADD COLUMN pii_override_ignored TEXT;
CREATE INDEX usage_event_pii_override ON usage_event (tenant_id, ts) WHERE pii_override_ignored IS NOT NULL;
