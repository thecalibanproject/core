-- 0035: the newest introspection job of each datasource, stored so every control-plane replica
-- answers GET /api/v1/datasources/{id}/introspection and refuses a second job while one runs
-- (research note 08, "Schema inference & ontology bootstrap"). See crates/caliban-cp/src/introspect.rs
-- and docs/datasources.md.
--
-- Never edit an applied migration; add a new one.
--
-- job: the job as the API shows it (id, status, counts, the ontology version, error, start and
-- end). One row per datasource, replaced by each new job. A running job whose control plane
-- stopped stays `running` here; readers report it failed once it is older than the job timeout
-- and a minute.

CREATE TABLE introspection_job (
    datasource_id TEXT PRIMARY KEY REFERENCES datasource(id) ON DELETE CASCADE,
    tenant_id     TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    job           JSONB NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE introspection_job ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON introspection_job USING (tenant_id = current_setting('app.tenant_id', true));
