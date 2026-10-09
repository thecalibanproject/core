-- 0003: soft deletes for the control plane (tenant tombstones, API key revocation, datasource and
-- node deletes). See crates/caliban-cp/src/store/mod.rs.
--
-- Never edit an applied migration; add a new one.
--
-- Rows that matter for audit are kept: a revoked API key keeps its row (revoked_at, from 0001),
-- a deleted tenant becomes a tombstone (status = 'deleted'; its id is never reused), and deleted
-- datasources and nodes keep their rows (deleted_at). audit_log is untouched. Secrets are not
-- kept: a deleted tenant's provider_credential rows (sealed BYOK keys) and tenant_dek row are
-- deleted, and a deleted datasource's connection is replaced with '{}'.

ALTER TABLE tenant
    ADD COLUMN status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'deleted')),
    ADD COLUMN deleted_at TIMESTAMPTZ,
    ADD CONSTRAINT tenant_tombstone CHECK ((status = 'deleted') = (deleted_at IS NOT NULL));

ALTER TABLE datasource ADD COLUMN deleted_at TIMESTAMPTZ;
ALTER TABLE node       ADD COLUMN deleted_at TIMESTAMPTZ;

-- A deleted datasource frees its name; only live datasources are unique per tenant.
ALTER TABLE datasource DROP CONSTRAINT datasource_tenant_id_name_key;
CREATE UNIQUE INDEX datasource_live_name ON datasource (tenant_id, name) WHERE deleted_at IS NULL;

-- Deletes are final: a revoked key, a tenant tombstone, or a deleted datasource or node cannot be
-- brought back by an UPDATE.
CREATE FUNCTION caliban_delete_is_final() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'api_key' THEN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
      RAISE EXCEPTION 'api_key %: revocation is final', OLD.id;
    END IF;
  ELSIF TG_TABLE_NAME = 'tenant' THEN
    IF OLD.status = 'deleted' AND (NEW.status <> 'deleted' OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at) THEN
      RAISE EXCEPTION 'tenant %: deletion is final', OLD.id;
    END IF;
  ELSIF OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
    RAISE EXCEPTION '% %: deletion is final', TG_TABLE_NAME, OLD.id;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER api_key_revoke_is_final BEFORE UPDATE ON api_key
  FOR EACH ROW EXECUTE FUNCTION caliban_delete_is_final();
CREATE TRIGGER tenant_delete_is_final BEFORE UPDATE ON tenant
  FOR EACH ROW EXECUTE FUNCTION caliban_delete_is_final();
CREATE TRIGGER datasource_delete_is_final BEFORE UPDATE ON datasource
  FOR EACH ROW EXECUTE FUNCTION caliban_delete_is_final();
CREATE TRIGGER node_delete_is_final BEFORE UPDATE ON node
  FOR EACH ROW EXECUTE FUNCTION caliban_delete_is_final();
