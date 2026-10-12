-- 0030: personal-data protection on models inside the trust boundary (founder decision
-- 2026-10-11; research note 05, section 4). See crates/caliban-config (Snapshot::pii_protection).
--
-- Never edit an applied migration; add a new one.
--
-- pii_on_sovereign: when true, the tenant's PII mode also applies to t0_sovereign and t1_attested
-- models. Off by default: those models receive the text as is, since it never leaves the
-- boundary. External models (t2, t3) always get the tenant's mode. A node spec's guardrails.pii
-- raises the mode for its own model calls on every model class, whatever this says.

ALTER TABLE tenant ADD COLUMN pii_on_sovereign BOOLEAN NOT NULL DEFAULT false;
