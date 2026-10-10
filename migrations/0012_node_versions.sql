-- 0012: node versions become deployable (P3 M1). See crates/caliban-cp/src/store/mod.rs
-- (NodeRecord) and docs/nodes.md.
--
-- Never edit an applied migration; add a new one.
--
-- A node version is immutable and content-hashed (sha256 over its canonical spec JSON). Its state
-- moves draft -> published -> retired, never back. A published version carries its spec sealed
-- under the tenant's data key (sealed_spec: nonce || ciphertext), which is what the data-plane
-- snapshot ships to routers and workers. The promotion pointer (node_promotion) names the live
-- version of each (tenant, node name). Versions created before this migration become drafts; their
-- hash is computed by the control plane when it loads them.

ALTER TABLE node
    ADD COLUMN state        TEXT NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'retired')),
    ADD COLUMN hash         TEXT,
    ADD COLUMN sealed_spec  BYTEA,
    ADD COLUMN created_by   TEXT,
    ADD COLUMN published_at TIMESTAMPTZ,
    ADD COLUMN retired_at   TIMESTAMPTZ,
    ADD CONSTRAINT node_published_is_sealed CHECK (state = 'draft' OR (sealed_spec IS NOT NULL AND published_at IS NOT NULL)),
    ADD CONSTRAINT node_retired_at CHECK ((state = 'retired') = (retired_at IS NOT NULL));

CREATE INDEX node_tenant_name ON node (tenant_id, name, version);

-- Versions are immutable: the spec, its hash and its identity never change, and a state never
-- moves backwards.
CREATE FUNCTION caliban_node_version_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.spec IS DISTINCT FROM OLD.spec OR NEW.tenant_id <> OLD.tenant_id OR NEW.name <> OLD.name
     OR NEW.version <> OLD.version OR (OLD.hash IS NOT NULL AND NEW.hash IS DISTINCT FROM OLD.hash) THEN
    RAISE EXCEPTION 'node %: versions are immutable', OLD.id;
  END IF;
  IF (OLD.state = 'retired' AND NEW.state <> 'retired') OR (OLD.state = 'published' AND NEW.state = 'draft') THEN
    RAISE EXCEPTION 'node %: state % cannot become %', OLD.id, OLD.state, NEW.state;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER node_version_immutable BEFORE UPDATE ON node
  FOR EACH ROW EXECUTE FUNCTION caliban_node_version_immutable();

-- The live version of each node: what a run of the node without a version runs.
CREATE TABLE node_promotion (
    tenant_id    TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      INTEGER NOT NULL,
    promoted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    promoted_by  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, name)
);
ALTER TABLE node_promotion ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON node_promotion USING (tenant_id = current_setting('app.tenant_id', true));

-- Upper bounds on the budgets of every node version the tenant publishes (NULL: the defaults).
ALTER TABLE tenant ADD COLUMN node_caps JSONB;

-- Node allowlist of an API key: the node names it may run. NULL: every published node of its
-- tenant; an empty list: none.
ALTER TABLE api_key ADD COLUMN nodes TEXT[];
