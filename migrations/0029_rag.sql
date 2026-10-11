-- 0029: retrieval (RAG) collections and the document registry. See crates/caliban-rag/ and
-- docs/rag.md.
--
-- Never edit an applied migration; add a new one.
--
-- These tables sit next to the node journal (shared by the control plane and the workers):
-- - `rag_collection`: a tenant's named document collection: its embedding model, optional rerank
--   model and settings. Written by the control plane; workers read it and record when they have
--   dropped a deleted collection's vectors (`purged_at`).
-- - `rag_document`: one version of one document. The control plane inserts it with its content
--   sealed under the tenant's data key; workers claim pending versions (FOR UPDATE SKIP LOCKED,
--   under a lease), index them into the vector store and record the outcome. Only `ready`
--   versions are served (fail closed). The sealed content is wiped once a version is superseded,
--   deleted or failed. `doc_key` is a keyed hash of the document id: the vector store only ever
--   sees that.
--
-- Like the journal, these tables have per-tenant row-level security. Audit events of the admin
-- API go through the `node_audit` outbox (0021) in the same transaction.

CREATE TABLE rag_collection (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    name             TEXT NOT NULL,
    description      TEXT,
    embedding_model  TEXT NOT NULL,
    rerank_model     TEXT,
    settings         JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    created_by       TEXT NOT NULL,
    deleted_at       TIMESTAMPTZ,
    purged_at        TIMESTAMPTZ
);
CREATE UNIQUE INDEX rag_collection_live_name ON rag_collection (tenant_id, name) WHERE deleted_at IS NULL;
CREATE INDEX rag_collection_to_drop ON rag_collection (deleted_at) WHERE deleted_at IS NOT NULL AND purged_at IS NULL;

CREATE TABLE rag_document (
    tenant_id              TEXT NOT NULL,
    collection_id          TEXT NOT NULL REFERENCES rag_collection(id),
    doc_id                 TEXT NOT NULL,
    version                INTEGER NOT NULL CHECK (version > 0),
    doc_key                TEXT NOT NULL,
    content_type           TEXT NOT NULL,
    source                 TEXT,
    trust                  TEXT NOT NULL CHECK (trust IN ('trusted', 'untrusted')),
    content                TEXT,
    content_hash           TEXT NOT NULL,
    bytes                  BIGINT NOT NULL,
    valid_from             TIMESTAMPTZ,
    valid_to               TIMESTAMPTZ,
    status                 TEXT NOT NULL CHECK (status IN ('pending', 'indexing', 'ready', 'quarantined', 'failed',
                                                           'superseded', 'deleted')),
    chunks                 INTEGER NOT NULL DEFAULT 0,
    tokens                 BIGINT NOT NULL DEFAULT 0,
    pii_entities           BIGINT NOT NULL DEFAULT 0,
    findings               JSONB NOT NULL DEFAULT '[]',
    findings_acknowledged  BOOLEAN NOT NULL DEFAULT false,
    error                  TEXT,
    attempts               INTEGER NOT NULL DEFAULT 0,
    retry_at               TIMESTAMPTZ,
    lease_owner            TEXT,
    lease_expires_at       TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    created_by             TEXT NOT NULL,
    indexed_at             TIMESTAMPTZ,
    released_by            TEXT,
    released_at            TIMESTAMPTZ,
    points_purged          BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, collection_id, doc_id, version),
    CHECK ((status = 'indexing') = (lease_owner IS NOT NULL))
);
CREATE INDEX rag_document_claimable ON rag_document (created_at) WHERE status IN ('pending', 'indexing');
CREATE INDEX rag_document_purge ON rag_document (created_at)
    WHERE NOT points_purged AND status IN ('superseded', 'deleted', 'failed');
CREATE INDEX rag_document_key ON rag_document (tenant_id, collection_id, doc_key, version);

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['rag_collection', 'rag_document']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
                     USING (tenant_id = current_setting('app.tenant_id', true))$p$, t);
  END LOOP;
END $$;
