-- 0019: the per-tenant MCP tool registry (P3 M4). See crates/caliban-cp/src/tools.rs and
-- docs/tools.md.
--
-- Never edit an applied migration; add a new one.
--
-- tool_server: a tenant's registered MCP server (Streamable HTTP URL, how Caliban authenticates
-- to it, whether it is trusted with personal data). Registering a server is what allows egress
-- to it. Its credential (API key, OAuth client secret) is sealed under the tenant's data key
-- (nonce || ciphertext), wiped when the server is deleted. Soft delete.
--
-- tool_manifest: every manifest discovered on a server (or imported), with its pin, the
-- findings of the injection scan, and whether a human approved it (who, when, whether they
-- acknowledged the findings). Only approved manifests reach the data plane; a manifest the
-- server changes is a new row that needs its own approval.

CREATE TABLE tool_server (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL REFERENCES tenant(id),
    name           TEXT NOT NULL,
    url            TEXT NOT NULL,
    auth           JSONB NOT NULL,
    sealed_secret  BYTEA,
    trusted        BOOLEAN NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL,
    created_by     TEXT NOT NULL,
    deleted_at     TIMESTAMPTZ,
    ord            BIGSERIAL
);
CREATE UNIQUE INDEX tool_server_live_name ON tool_server (tenant_id, name) WHERE deleted_at IS NULL;

CREATE TABLE tool_manifest (
    id                     TEXT PRIMARY KEY,
    tenant_id              TEXT NOT NULL REFERENCES tenant(id),
    server                 TEXT NOT NULL,
    name                   TEXT NOT NULL,
    description            TEXT NOT NULL,
    input_schema           JSONB NOT NULL,
    pin                    TEXT NOT NULL,
    findings               JSONB NOT NULL DEFAULT '[]',
    status                 TEXT NOT NULL CHECK (status IN ('discovered', 'approved', 'revoked')),
    discovered_at          TIMESTAMPTZ NOT NULL,
    approved_at            TIMESTAMPTZ,
    approved_by            TEXT,
    findings_acknowledged  BOOLEAN NOT NULL DEFAULT false,
    ord                    BIGSERIAL,
    UNIQUE (tenant_id, server, name, pin)
);

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['tool_server', 'tool_manifest']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
                     USING (tenant_id = current_setting('app.tenant_id', true))$p$, t);
  END LOOP;
END $$;
