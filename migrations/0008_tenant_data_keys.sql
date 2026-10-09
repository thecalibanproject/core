-- 0008: per-tenant data keys (envelope encryption). See crates/caliban-cp/src/keys.rs.
--
-- Never edit an applied migration; add a new one.
--
-- Each tenant's secrets are sealed under its own DEK; the DEK is stored in tenant_dek (from
-- 0001), wrapped by a KEK of the keyring (CALIBAN_KEK, CALIBAN_KEK_PREVIOUS) and identified by
-- kek_id (a fingerprint of the KEK). Deleting a tenant deletes its tenant_dek row in the same
-- transaction as the tombstone (crypto-shredding).
--
-- sealed_by says what provider_credential.sealed_key is sealed under: 'kek' (rows written before
-- this migration, sealed directly under CALIBAN_KEK) or 'tenant_dek'. Existing rows stay 'kek'
-- here; SQL cannot re-seal them because it never sees a key. The control plane re-seals them under
-- the tenant DEK at startup (and `caliban keys rotate` does too), together with datasource
-- credentials still stored in clear in datasource.connection. Both steps are idempotent.

ALTER TABLE provider_credential
    ADD COLUMN sealed_by TEXT NOT NULL DEFAULT 'kek' CHECK (sealed_by IN ('kek', 'tenant_dek')),
    ADD CONSTRAINT provider_credential_dek_sealed CHECK (sealed_by = 'kek' OR (sealed_key IS NOT NULL AND secret_ref IS NULL));

-- `caliban keys status` and rotation look DEKs up by the KEK that wraps them.
CREATE INDEX tenant_dek_kek_id ON tenant_dek (kek_id);
