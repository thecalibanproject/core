-- Caliban control-plane schema (Postgres 15+).
-- Applied at startup by the control plane when CALIBAN_DATABASE_URL is set (crates/caliban-cp/src/store/postgres.rs);
-- 0002 adds what the store needs on top of this baseline.
-- Every tenant-owned table carries tenant_id and is protected by row-level security.

CREATE TABLE tenant (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    region       TEXT,
    pii_default  TEXT NOT NULL DEFAULT 'reversible' CHECK (pii_default IN ('off', 'mask', 'reversible')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tenant data-encryption keys, wrapped by the KEK (env, HSM/PKCS#11, or KMS).
-- Deleting a row crypto-shreds everything sealed under it.
CREATE TABLE tenant_dek (
    tenant_id    TEXT PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    wrapped_dek  BYTEA NOT NULL,
    kek_id       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_key (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    sha256       TEXT NOT NULL UNIQUE,          -- only the hash is stored
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ
);

-- BYOK provider credentials and local model endpoints.
CREATE TABLE provider_credential (
    tenant_id    TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    id           TEXT NOT NULL,                 -- referenced by the model catalogue (e.g. local-llm)
    kind         TEXT NOT NULL,
    label        TEXT NOT NULL,
    base_url     TEXT,
    trust_tier   TEXT NOT NULL CHECK (trust_tier IN ('t0_sovereign', 't1_attested', 't2_contracted', 't3_public')),
    sealed_key   BYTEA,                         -- AES-256-GCM under the tenant DEK; NULL for keyless local endpoints
    last4        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE model (
    id                  TEXT PRIMARY KEY,
    provider_id         TEXT NOT NULL,
    upstream_model      TEXT NOT NULL,
    trust_tier          TEXT NOT NULL,
    licence             TEXT,
    context_window      INTEGER,
    price_in_per_mtok   DOUBLE PRECISION,
    price_out_per_mtok  DOUBLE PRECISION
);

CREATE TABLE route (
    tenant_id    TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    intent       TEXT NOT NULL,
    models       TEXT[] NOT NULL,
    version      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, intent)
);

CREATE TABLE datasource (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    kind               TEXT NOT NULL,
    name               TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    connection         JSONB NOT NULL,          -- secrets inside are replaced by sealed references
    epoch              BIGINT NOT NULL DEFAULT 0,  -- bumped by CDC/watermarks; part of cache keys
    replica_watermark  TIMESTAMPTZ,             -- last applied change-stream clusterTime (accelerated lane)
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

-- ───────────── Ontology: append-only, versioned (docs/research/08 "ontology store") ─────────────
CREATE TABLE ontology_commit (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    parent_id    BIGINT REFERENCES ontology_commit(id),
    author       TEXT NOT NULL,
    message      TEXT NOT NULL,
    eval_delta   JSONB,                         -- golden-set result vs parent; regressions block publish
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ontology_element (
    tenant_id          TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    id                 TEXT NOT NULL,
    commit_id          BIGINT NOT NULL REFERENCES ontology_commit(id),
    kind               TEXT NOT NULL CHECK (kind IN ('entity', 'attribute', 'relation', 'metric', 'dimension',
                                                     'glossary_term', 'policy', 'verified_query')),
    name               TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('proposed', 'approved', 'rejected', 'stale', 'deprecated')),
    provenance         TEXT NOT NULL CHECK (provenance IN ('introspect', 'profile', 'query_log', 'llm', 'human')),
    confidence         REAL,
    body               JSONB NOT NULL,          -- ElementSpec (see crates/caliban-ontology/src/model.rs)
    bound_schema_hash  TEXT,                    -- marks the element stale when the source schema drifts
    PRIMARY KEY (tenant_id, id, commit_id)
);
CREATE INDEX ontology_element_status ON ontology_element (tenant_id, status);

-- The published version per tenant is a pointer move; data planes receive the compiled model in
-- the signed config snapshot.
CREATE TABLE ontology_head (
    tenant_id    TEXT PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    commit_id    BIGINT NOT NULL REFERENCES ontology_commit(id),
    published_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE node (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      INTEGER NOT NULL,
    spec         JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name, version)
);

-- Usage events (append-only). High-volume deployments ship these to ClickHouse instead.
CREATE TABLE usage_event (
    request_id            TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    model                 TEXT NOT NULL,
    intent                TEXT,
    prompt_tokens         BIGINT NOT NULL,
    completion_tokens     BIGINT NOT NULL,
    cached_prompt_tokens  BIGINT NOT NULL DEFAULT 0,
    tokens_saved          BIGINT NOT NULL DEFAULT 0,
    cache                 TEXT NOT NULL,
    pii_entities          INTEGER NOT NULL DEFAULT 0,
    cost_usd              DOUBLE PRECISION,
    latency_ms            BIGINT NOT NULL,
    ts                    TIMESTAMPTZ NOT NULL
);
CREATE INDEX usage_event_tenant_ts ON usage_event (tenant_id, ts DESC);

-- Tamper-evident audit log: each row hashes the previous row (hash chain). No raw prompt content.
CREATE TABLE audit_log (
    seq          BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT,
    detail       JSONB NOT NULL DEFAULT '{}',
    prev_hash    BYTEA,
    hash         BYTEA NOT NULL,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Row-level security: the application sets `SET app.tenant_id = '...'` per transaction.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['api_key', 'provider_credential', 'route', 'datasource', 'ontology_commit',
                           'ontology_element', 'ontology_head', 'node', 'usage_event']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
                     USING (tenant_id = current_setting('app.tenant_id', true))$p$, t);
  END LOOP;
END $$;
