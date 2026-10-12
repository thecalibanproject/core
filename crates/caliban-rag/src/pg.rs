//! [`RagStore`] on Postgres (migration 0029), shared by the control plane and the workers.

use crate::store::*;
use caliban_nodes::journal::AuditEvent;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgRow};
use sqlx::types::Json;
use sqlx::{PgConnection, Row};
use std::collections::HashSet;
use std::time::Duration;

/// The migration that creates the tables (the control plane applies it with the others).
pub const MIGRATION: &str = include_str!("../../../migrations/0029_rag.sql");

#[derive(Clone)]
pub struct PgRagStore {
    pool: PgPool,
}

fn db(e: sqlx::Error) -> RagStoreError {
    if let sqlx::Error::Database(d) = &e
        && d.code().as_deref() == Some("23505")
    {
        return RagStoreError::Conflict("already exists (a concurrent write?)".into());
    }
    RagStoreError::Backend(e.to_string())
}

fn get<'r, T>(r: &'r PgRow, col: &str) -> SResult<T>
where
    T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    r.try_get(col).map_err(|e| RagStoreError::Backend(format!("{col}: {e}")))
}

fn u32_of(r: &PgRow, col: &str) -> SResult<u32> {
    Ok(u32::try_from(get::<i32>(r, col)?).unwrap_or_default())
}

fn u64_of(r: &PgRow, col: &str) -> SResult<u64> {
    Ok(u64::try_from(get::<i64>(r, col)?).unwrap_or_default())
}

fn i32_of(n: u32) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

fn i64_of(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

macro_rules! collection_columns {
    () => {
        "id, tenant_id, name, description, embedding_model, rerank_model, settings, created_at, created_by, deleted_at, \
         purged_at"
    };
}

macro_rules! doc_columns {
    () => {
        "tenant_id, collection_id, doc_id, version, doc_key, content_type, source, trust, content_hash, bytes, \
         valid_from, valid_to, status, chunks, tokens, pii_entities, findings, findings_acknowledged, error, attempts, \
         retry_at, lease_owner, lease_expires_at, created_at, created_by, indexed_at, released_by, released_at, \
         points_purged"
    };
}

fn collection_row(r: &PgRow) -> SResult<CollectionRecord> {
    Ok(CollectionRecord {
        id: get(r, "id")?,
        tenant_id: get(r, "tenant_id")?,
        name: get(r, "name")?,
        description: get(r, "description")?,
        embedding_model: get(r, "embedding_model")?,
        rerank_model: get(r, "rerank_model")?,
        settings: serde_json::from_value(get::<Json<serde_json::Value>>(r, "settings")?.0)
            .map_err(|e| RagStoreError::Backend(format!("settings: {e}")))?,
        created_at: get(r, "created_at")?,
        created_by: get(r, "created_by")?,
        deleted_at: get(r, "deleted_at")?,
        purged_at: get(r, "purged_at")?,
    })
}

fn doc_row(r: &PgRow) -> SResult<DocumentRecord> {
    let status: String = get(r, "status")?;
    let trust: String = get(r, "trust")?;
    Ok(DocumentRecord {
        tenant_id: get(r, "tenant_id")?,
        collection_id: get(r, "collection_id")?,
        doc_id: get(r, "doc_id")?,
        version: u32_of(r, "version")?,
        doc_key: get(r, "doc_key")?,
        content_type: get(r, "content_type")?,
        source: get(r, "source")?,
        trust: Trust::parse(&trust).unwrap_or_default(),
        content_hash: get(r, "content_hash")?,
        bytes: u64_of(r, "bytes")?,
        valid_from: get(r, "valid_from")?,
        valid_to: get(r, "valid_to")?,
        status: DocStatus::parse(&status).ok_or_else(|| RagStoreError::Backend(format!("status '{status}'")))?,
        chunks: u32_of(r, "chunks")?,
        tokens: u64_of(r, "tokens")?,
        pii_entities: u64_of(r, "pii_entities")?,
        findings: serde_json::from_value(get::<Json<serde_json::Value>>(r, "findings")?.0).unwrap_or_default(),
        findings_acknowledged: get(r, "findings_acknowledged")?,
        error: get(r, "error")?,
        attempts: u32_of(r, "attempts")?,
        retry_at: get(r, "retry_at")?,
        lease_owner: get(r, "lease_owner")?,
        lease_expires_at: get(r, "lease_expires_at")?,
        created_at: get(r, "created_at")?,
        created_by: get(r, "created_by")?,
        indexed_at: get(r, "indexed_at")?,
        released_by: get(r, "released_by")?,
        released_at: get(r, "released_at")?,
        points_purged: get(r, "points_purged")?,
    })
}

async fn push_audit(tx: &mut PgConnection, a: Option<&AuditEvent>) -> SResult<()> {
    let Some(a) = a else { return Ok(()) };
    sqlx::query(
        "INSERT INTO node_audit (id, tenant_id, actor, action, target, detail, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING",
    )
    .bind(&a.id)
    .bind(&a.tenant_id)
    .bind(&a.actor)
    .bind(&a.action)
    .bind(&a.target)
    .bind(Json(&a.detail))
    .bind(a.at)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    Ok(())
}

impl PgRagStore {
    pub async fn connect(url: &str) -> SResult<Self> {
        let opts: PgConnectOptions =
            url.parse().map_err(|e: sqlx::Error| RagStoreError::Backend(format!("database url: {e}")))?;
        Self::connect_with(opts).await
    }

    pub async fn connect_with(opts: PgConnectOptions) -> SResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(opts)
            .await
            .map_err(|e| RagStoreError::Backend(format!("connecting to postgres: {e}")))?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// A store in a new schema of its own with the journal and RAG tables (tests).
    #[doc(hidden)]
    pub async fn isolated(url: &str) -> SResult<Self> {
        let schema = format!("r_{}", uuid::Uuid::now_v7().simple());
        let admin = PgPool::connect(url).await.map_err(db)?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}"))).execute(&admin).await.map_err(db)?;
        admin.close().await;
        let opts: PgConnectOptions = url
            .parse::<PgConnectOptions>()
            .map_err(|e| RagStoreError::Backend(format!("database url: {e}")))?
            .options([("search_path", schema.as_str())]);
        let s = Self::connect_with(opts).await?;
        for m in caliban_nodes::journal::postgres::MIGRATIONS.iter().copied().chain([MIGRATION]) {
            sqlx::raw_sql(m).execute(&s.pool).await.map_err(db)?;
        }
        Ok(s)
    }

    async fn latest(&self, tenant: &str, collection_id: &str, doc_id: &str) -> SResult<Vec<DocumentRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            doc_columns!(),
            " FROM rag_document WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3
             ORDER BY version DESC"
        ))
        .bind(tenant)
        .bind(collection_id)
        .bind(doc_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(doc_row).collect()
    }
}

#[async_trait::async_trait]
impl RagStore for PgRagStore {
    fn name(&self) -> &'static str {
        "postgres"
    }

    async fn create_collection(&self, c: CollectionRecord, audit: Option<AuditEvent>) -> SResult<CollectionRecord> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let settings = serde_json::to_value(&c.settings).map_err(|e| RagStoreError::Invalid(e.to_string()))?;
        let r = sqlx::query(
            "INSERT INTO rag_collection (id, tenant_id, name, description, embedding_model, rerank_model, settings,
                                         created_at, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&c.id)
        .bind(&c.tenant_id)
        .bind(&c.name)
        .bind(&c.description)
        .bind(&c.embedding_model)
        .bind(&c.rerank_model)
        .bind(Json(settings))
        .bind(c.created_at)
        .bind(&c.created_by)
        .execute(&mut *tx)
        .await;
        if let Err(e) = r {
            return Err(match db(e) {
                RagStoreError::Conflict(_) => {
                    RagStoreError::Conflict(format!("a collection named '{}' exists", c.name))
                }
                other => other,
            });
        }
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(c)
    }

    async fn collections(&self, tenant: &str) -> SResult<Vec<CollectionRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            collection_columns!(),
            " FROM rag_collection WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY name"
        ))
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(collection_row).collect()
    }

    async fn collection(&self, tenant: &str, name: &str) -> SResult<Option<CollectionRecord>> {
        let row = sqlx::query(concat!(
            "SELECT ",
            collection_columns!(),
            " FROM rag_collection WHERE tenant_id = $1 AND name = $2 AND deleted_at IS NULL"
        ))
        .bind(tenant)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.as_ref().map(collection_row).transpose()
    }

    async fn delete_collection(
        &self,
        tenant: &str,
        name: &str,
        at: DateTime<Utc>,
        audit: Option<AuditEvent>,
    ) -> SResult<bool> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let id: Option<String> = sqlx::query_scalar(
            "UPDATE rag_collection SET deleted_at = $3 WHERE tenant_id = $1 AND name = $2 AND deleted_at IS NULL
             RETURNING id",
        )
        .bind(tenant)
        .bind(name)
        .bind(at)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let Some(id) = id else { return Ok(false) };
        sqlx::query(
            "UPDATE rag_document SET status = 'deleted', content = NULL, lease_owner = NULL, lease_expires_at = NULL
             WHERE tenant_id = $1 AND collection_id = $2",
        )
        .bind(tenant)
        .bind(&id)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    async fn delete_tenant(&self, tenant: &str, at: DateTime<Utc>) -> SResult<u64> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let n = sqlx::query("UPDATE rag_collection SET deleted_at = $2 WHERE tenant_id = $1 AND deleted_at IS NULL")
            .bind(tenant)
            .bind(at)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected();
        sqlx::query(
            "UPDATE rag_document SET status = 'deleted', content = NULL, lease_owner = NULL, lease_expires_at = NULL
             WHERE tenant_id = $1",
        )
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(n)
    }

    async fn put_document(&self, d: NewDocument, audit: Option<AuditEvent>) -> SResult<(DocumentRecord, bool)> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        // Serialises ingests of one collection (the version number and the no-op check).
        let live: Option<String> = sqlx::query_scalar(
            "SELECT id FROM rag_collection WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(&d.tenant_id)
        .bind(&d.collection_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if live.is_none() {
            return Err(RagStoreError::NotFound("collection".into()));
        }
        let rows = sqlx::query(concat!(
            "SELECT ",
            doc_columns!(),
            " FROM rag_document WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3
             ORDER BY version DESC"
        ))
        .bind(&d.tenant_id)
        .bind(&d.collection_id)
        .bind(&d.doc_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let versions: Vec<DocumentRecord> = rows.iter().map(doc_row).collect::<SResult<_>>()?;
        if let Some(x) = versions.iter().find(|x| !matches!(x.status, DocStatus::Deleted | DocStatus::Failed))
            && same_input(x, &d)
        {
            return Ok((x.clone(), false));
        }
        let version = versions.first().map_or(0, |x| x.version) + 1;
        let row = sqlx::query(concat!(
            "INSERT INTO rag_document (tenant_id, collection_id, doc_id, version, doc_key, content_type, source, trust,
                                       content, content_hash, bytes, valid_from, valid_to, status, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending', $14)
             RETURNING ",
            doc_columns!()
        ))
        .bind(&d.tenant_id)
        .bind(&d.collection_id)
        .bind(&d.doc_id)
        .bind(i32_of(version))
        .bind(&d.doc_key)
        .bind(&d.content_type)
        .bind(&d.source)
        .bind(d.trust.as_str())
        .bind(&d.sealed_content)
        .bind(&d.content_hash)
        .bind(i64_of(d.bytes))
        .bind(d.valid_from)
        .bind(d.valid_to)
        .bind(&d.created_by)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let rec = doc_row(&row)?;
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok((rec, true))
    }

    async fn document_counts(
        &self,
        tenant: &str,
    ) -> SResult<std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>>> {
        let rows = sqlx::query(
            "SELECT collection_id, status, count(*) AS n FROM (
               SELECT DISTINCT ON (collection_id, doc_id) collection_id, status FROM rag_document
               WHERE tenant_id = $1 ORDER BY collection_id, doc_id, version DESC
             ) latest WHERE status <> 'deleted' GROUP BY 1, 2",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut out: std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>> = Default::default();
        for r in &rows {
            let n: i64 = get(r, "n")?;
            out.entry(get(r, "collection_id")?).or_default().insert(get(r, "status")?, u64::try_from(n).unwrap_or(0));
        }
        Ok(out)
    }

    async fn documents(&self, tenant: &str, collection_id: &str, q: &DocQuery) -> SResult<Vec<DocumentSummary>> {
        let rows = sqlx::query(concat!("SELECT * FROM (
               SELECT DISTINCT ON (doc_id) ", doc_columns!(), ",
                      (SELECT max(r.version) FROM rag_document r WHERE r.tenant_id = d.tenant_id
                         AND r.collection_id = d.collection_id AND r.doc_id = d.doc_id AND r.status = 'ready') AS live_version
               FROM rag_document d WHERE tenant_id = $1 AND collection_id = $2 AND ($3::TEXT IS NULL OR doc_id > $3)
               ORDER BY doc_id, version DESC
             ) latest
             WHERE status <> 'deleted' AND ($4::TEXT IS NULL OR status = $4)
             ORDER BY doc_id LIMIT $5"))
        .bind(tenant)
        .bind(collection_id)
        .bind(&q.after)
        .bind(q.status.map(DocStatus::as_str))
        .bind(i64_of(q.limit as u64))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                let live: Option<i32> = get(r, "live_version")?;
                Ok(DocumentSummary { latest: doc_row(r)?, live_version: live.and_then(|v| u32::try_from(v).ok()) })
            })
            .collect()
    }

    async fn document(&self, tenant: &str, collection_id: &str, doc_id: &str) -> SResult<Vec<DocumentRecord>> {
        self.latest(tenant, collection_id, doc_id).await
    }

    async fn delete_document(
        &self,
        tenant: &str,
        collection_id: &str,
        doc_id: &str,
        _at: DateTime<Utc>,
        audit: Option<AuditEvent>,
    ) -> SResult<bool> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let n = sqlx::query(
            "UPDATE rag_document SET status = 'deleted', content = NULL, lease_owner = NULL, lease_expires_at = NULL,
                                     points_purged = false
             WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND status <> 'deleted'",
        )
        .bind(tenant)
        .bind(collection_id)
        .bind(doc_id)
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected();
        if n == 0 {
            return Ok(false);
        }
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    async fn release(
        &self,
        r: &DocRef,
        by: &str,
        at: DateTime<Utc>,
        audit: Option<AuditEvent>,
    ) -> SResult<DocumentRecord> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT status FROM rag_document WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND version = $4
             FOR UPDATE",
        )
        .bind(&r.tenant_id)
        .bind(&r.collection_id)
        .bind(&r.doc_id)
        .bind(i32_of(r.version))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        match current.as_deref() {
            None => return Err(RagStoreError::NotFound("document version".into())),
            Some("quarantined") => {}
            Some(s) => return Err(RagStoreError::Conflict(format!("the document is {s}, not quarantined"))),
        }
        let row = sqlx::query(concat!(
            "UPDATE rag_document SET status = 'pending', findings_acknowledged = true, released_by = $5,
                                     released_at = $6, retry_at = NULL, attempts = 0
             WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND version = $4
             RETURNING ",
            doc_columns!()
        ))
        .bind(&r.tenant_id)
        .bind(&r.collection_id)
        .bind(&r.doc_id)
        .bind(i32_of(r.version))
        .bind(by)
        .bind(at)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let rec = doc_row(&row)?;
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(rec)
    }

    async fn claim(&self, worker: &str, lease: Duration) -> SResult<Option<(DocumentRecord, String)>> {
        let row = sqlx::query(concat!(
            "UPDATE rag_document d SET status = 'indexing', lease_owner = $1,
                    lease_expires_at = now() + make_interval(secs => $2), attempts = attempts + 1
             WHERE (tenant_id, collection_id, doc_id, version) = (
               SELECT x.tenant_id, x.collection_id, x.doc_id, x.version FROM rag_document x
               JOIN rag_collection c ON c.id = x.collection_id AND c.deleted_at IS NULL
               WHERE x.content IS NOT NULL
                 AND ((x.status = 'pending' AND (x.retry_at IS NULL OR x.retry_at <= now()))
                      OR (x.status = 'indexing' AND x.lease_expires_at < now()))
               ORDER BY x.created_at LIMIT 1 FOR UPDATE OF x SKIP LOCKED)
             RETURNING ",
            doc_columns!(),
            ", content"
        ))
        .bind(worker)
        .bind(lease.as_secs_f64())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some((doc_row(&r)?, get::<Option<String>>(&r, "content")?.unwrap_or_default()))),
        }
    }

    async fn heartbeat(&self, r: &DocRef, worker: &str, lease: Duration) -> SResult<bool> {
        let n = sqlx::query(
            "UPDATE rag_document SET lease_expires_at = now() + make_interval(secs => $6)
             WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND version = $4
               AND status = 'indexing' AND lease_owner = $5",
        )
        .bind(&r.tenant_id)
        .bind(&r.collection_id)
        .bind(&r.doc_id)
        .bind(i32_of(r.version))
        .bind(worker)
        .bind(lease.as_secs_f64())
        .execute(&self.pool)
        .await
        .map_err(db)?
        .rows_affected();
        Ok(n == 1)
    }

    async fn finish(&self, r: &DocRef, worker: &str, outcome: IndexOutcome) -> SResult<bool> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let held: Option<String> = sqlx::query_scalar(
            "SELECT status FROM rag_document WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND version = $4
               AND status = 'indexing' AND lease_owner = $5 FOR UPDATE",
        )
        .bind(&r.tenant_id)
        .bind(&r.collection_id)
        .bind(&r.doc_id)
        .bind(i32_of(r.version))
        .bind(worker)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if held.is_none() {
            return Ok(false);
        }
        let ready = matches!(outcome, IndexOutcome::Ready { .. });
        let k = (&r.tenant_id, &r.collection_id, &r.doc_id, i32_of(r.version));
        match outcome {
            IndexOutcome::Ready { chunks, tokens, pii_entities, findings }
            | IndexOutcome::Quarantined { chunks, tokens, pii_entities, findings } => {
                let newer_ready: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM rag_document WHERE tenant_id = $1 AND collection_id = $2
                                      AND doc_id = $3 AND version > $4 AND status = 'ready')",
                )
                .bind(k.0)
                .bind(k.1)
                .bind(k.2)
                .bind(k.3)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
                let status = if !ready {
                    DocStatus::Quarantined
                } else if newer_ready {
                    DocStatus::Superseded
                } else {
                    DocStatus::Ready
                };
                let findings = serde_json::to_value(&findings).map_err(|e| RagStoreError::Invalid(e.to_string()))?;
                sqlx::query(
                    "UPDATE rag_document SET status = $5, chunks = $6, tokens = $7, pii_entities = $8, findings = $9,
                            indexed_at = now(), error = NULL, lease_owner = NULL, lease_expires_at = NULL,
                            content = CASE WHEN $5 = 'superseded' THEN NULL ELSE content END
                     WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND version = $4",
                )
                .bind(k.0)
                .bind(k.1)
                .bind(k.2)
                .bind(k.3)
                .bind(status.as_str())
                .bind(i32_of(chunks))
                .bind(i64_of(tokens))
                .bind(i64_of(pii_entities))
                .bind(Json(findings))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                if status == DocStatus::Ready {
                    sqlx::query(
                        "UPDATE rag_document SET status = 'superseded', content = NULL
                         WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND version < $4
                           AND status = 'ready'",
                    )
                    .bind(k.0)
                    .bind(k.1)
                    .bind(k.2)
                    .bind(k.3)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
                }
            }
            IndexOutcome::Failed { error } => {
                sqlx::query(
                    "UPDATE rag_document SET status = 'failed', error = $5, content = NULL, lease_owner = NULL,
                            lease_expires_at = NULL
                     WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND version = $4",
                )
                .bind(k.0)
                .bind(k.1)
                .bind(k.2)
                .bind(k.3)
                .bind(error)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            }
            IndexOutcome::Retry { error, after } => {
                sqlx::query(
                    "UPDATE rag_document SET status = 'pending', error = $5,
                            retry_at = now() + make_interval(secs => $6), lease_owner = NULL, lease_expires_at = NULL
                     WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND version = $4",
                )
                .bind(k.0)
                .bind(k.1)
                .bind(k.2)
                .bind(k.3)
                .bind(error)
                .bind(after.as_secs_f64())
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            }
        }
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    async fn visible(
        &self,
        tenant: &str,
        collection_id: &str,
        refs: &[(String, u32)],
    ) -> SResult<HashSet<(String, u32)>> {
        if refs.is_empty() {
            return Ok(HashSet::new());
        }
        let keys: Vec<String> = refs.iter().map(|(k, _)| k.clone()).collect();
        let rows = sqlx::query(
            "SELECT doc_key, version FROM rag_document
             WHERE tenant_id = $1 AND collection_id = $2 AND doc_key = ANY($3) AND status = 'ready'",
        )
        .bind(tenant)
        .bind(collection_id)
        .bind(&keys)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut out = HashSet::new();
        for r in &rows {
            let k: (String, u32) = (get(r, "doc_key")?, u32_of(r, "version")?);
            if refs.contains(&k) {
                out.insert(k);
            }
        }
        Ok(out)
    }

    async fn purge_queue(&self, limit: usize) -> SResult<Vec<DocumentRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            doc_columns!(),
            " FROM rag_document d
             WHERE NOT points_purged AND status IN ('superseded', 'deleted', 'failed')
               AND EXISTS (SELECT 1 FROM rag_collection c WHERE c.id = d.collection_id AND c.deleted_at IS NULL)
             ORDER BY created_at LIMIT $1"
        ))
        .bind(i64_of(limit as u64))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(doc_row).collect()
    }

    async fn mark_purged(&self, r: &DocRef) -> SResult<()> {
        sqlx::query(
            "UPDATE rag_document SET points_purged = true
             WHERE tenant_id = $1 AND collection_id = $2 AND doc_id = $3 AND version = $4",
        )
        .bind(&r.tenant_id)
        .bind(&r.collection_id)
        .bind(&r.doc_id)
        .bind(i32_of(r.version))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn collections_to_drop(&self, limit: usize) -> SResult<Vec<CollectionRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            collection_columns!(),
            " FROM rag_collection WHERE deleted_at IS NOT NULL AND purged_at IS NULL
             ORDER BY deleted_at LIMIT $1"
        ))
        .bind(i64_of(limit as u64))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(collection_row).collect()
    }

    async fn mark_dropped(&self, tenant: &str, id: &str, at: DateTime<Utc>) -> SResult<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("UPDATE rag_collection SET purged_at = $3 WHERE tenant_id = $1 AND id = $2")
            .bind(tenant)
            .bind(id)
            .bind(at)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE rag_document SET points_purged = true WHERE tenant_id = $1 AND collection_id = $2")
            .bind(tenant)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    async fn claim_audit(&self, owner: &str, hold: Duration, limit: usize) -> SResult<Vec<AuditEvent>> {
        let rows = sqlx::query(
            "UPDATE node_audit SET claimed_by = $1, claimed_until = now() + make_interval(secs => $2)
             WHERE id IN (SELECT id FROM node_audit WHERE claimed_until IS NULL OR claimed_until < now()
                          ORDER BY created_at LIMIT $3 FOR UPDATE SKIP LOCKED)
             RETURNING id, tenant_id, actor, action, target, detail, created_at",
        )
        .bind(owner)
        .bind(hold.as_secs_f64())
        .bind(i64_of(limit as u64))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut out: Vec<AuditEvent> = rows
            .iter()
            .map(|r| {
                Ok(AuditEvent {
                    id: get(r, "id")?,
                    tenant_id: get(r, "tenant_id")?,
                    actor: get(r, "actor")?,
                    action: get(r, "action")?,
                    target: get(r, "target")?,
                    detail: get::<Json<serde_json::Value>>(r, "detail")?.0,
                    at: get(r, "created_at")?,
                })
            })
            .collect::<SResult<_>>()?;
        out.sort_by_key(|a| a.at);
        Ok(out)
    }

    async fn ack_audit(&self, ids: &[String]) -> SResult<()> {
        sqlx::query("DELETE FROM node_audit WHERE id = ANY($1)").bind(ids).execute(&self.pool).await.map_err(db)?;
        Ok(())
    }
}
