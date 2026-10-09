//! Postgres backend (`CALIBAN_DATABASE_URL`). Runtime queries only (no compile-time macros).
//!
//! Writes are serialized with a transaction-scoped advisory lock (control-plane write volume is
//! tiny, and the audit hash chain needs a total order anyway). Each mutation, in one transaction:
//! load the current state → apply the shared in-memory semantics (`memory::apply_to`: the same
//! conflicts / not-found errors as the memory backend) → write the delta → reload → validate the
//! rendered data-plane config → append the audit row → commit. Any error rolls everything back.

use super::audit::{AuditDraft, AuditEntry, now_micros};
use super::{ApiKeyRecord, Backend, Check, DatasourceRecord, Mutation, NodeRecord, ProviderKeyRecord, State, StoreError, Tenant, TenantStatus};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use caliban_config::{ModelEntry, ProviderConfig, RouteConfig, SecretRef, SharedProvider};
use caliban_ontology::{Element, Ontology};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions, PgRow};
use sqlx::types::Json;
use sqlx::{Postgres, Row};
use std::time::Duration;

/// `(version, name, sql)`; applied in order, each recorded in `caliban_schema_migrations`.
pub const MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "init", include_str!("../../../../migrations/0001_init.sql")),
    (2, "control_plane_store", include_str!("../../../../migrations/0002_control_plane_store.sql")),
    (3, "soft_delete", include_str!("../../../../migrations/0003_soft_delete.sql")),
    (4, "pii_surrogate_scope", include_str!("../../../../migrations/0004_pii_surrogate_scope.sql")),
    // 0005 is reserved.
    (6, "tenant_semantic_cache", include_str!("../../../../migrations/0006_tenant_semantic_cache.sql")),
];

/// Advisory lock keys ("calibn" + n).
const MIGRATE_LOCK: i64 = 0x6361_6c69_626e_0001;
const WRITE_LOCK: i64 = 0x6361_6c69_626e_0002;

pub struct PgBackend {
    pool: PgPool,
}

fn db(e: sqlx::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn get<'r, T>(r: &'r PgRow, col: &str) -> Result<T, StoreError>
where
    T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    r.try_get::<T, _>(col).map_err(|e| StoreError::Backend(format!("column {col}: {e}")))
}

fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

fn parse<T: DeserializeOwned>(v: Value) -> Result<T, StoreError> {
    serde_json::from_value(v).map_err(|e| StoreError::Backend(format!("decoding stored value: {e}")))
}

fn parse_enum<T: DeserializeOwned>(s: String) -> Result<T, StoreError> {
    parse(Value::String(s))
}

fn i64_of(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Sealed secrets go to `sealed_key` (raw nonce ‖ ciphertext); `{env}`/`{file}` references to
/// `secret_ref`.
/// `(sealed_key, secret_ref)` column values.
type SecretColumns = (Option<Vec<u8>>, Option<Json<Value>>);

fn split_secret(s: Option<&SecretRef>) -> Result<SecretColumns, StoreError> {
    match s {
        None => Ok((None, None)),
        Some(SecretRef::Sealed { sealed }) => {
            let raw = B64.decode(sealed).map_err(|e| StoreError::Invalid(format!("sealed secret is not base64: {e}")))?;
            Ok((Some(raw), None))
        }
        Some(other) => Ok((None, Some(Json(serde_json::to_value(other).map_err(|e| StoreError::Backend(e.to_string()))?)))),
    }
}

fn join_secret(sealed: Option<Vec<u8>>, reference: Option<Json<Value>>) -> Result<Option<SecretRef>, StoreError> {
    match (sealed, reference) {
        (Some(raw), _) => Ok(Some(SecretRef::Sealed { sealed: B64.encode(raw) })),
        (None, Some(Json(v))) => parse(v).map(Some),
        (None, None) => Ok(None),
    }
}

impl PgBackend {
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let opts: PgConnectOptions = url.parse().map_err(|e: sqlx::Error| StoreError::Backend(format!("CALIBAN_DATABASE_URL: {e}")))?;
        Self::connect_with(opts).await
    }

    pub async fn connect_with(opts: PgConnectOptions) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(opts)
            .await
            .map_err(|e| StoreError::Backend(format!("connecting to postgres: {e}")))?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Applies pending migrations; refuses to start if an applied migration was edited.
    pub async fn migrate(&self) -> Result<Vec<i64>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(MIGRATE_LOCK).execute(&mut *tx).await.map_err(db)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS caliban_schema_migrations (
                 version BIGINT PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL,
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        )
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        let mut applied = Vec::new();
        for &(version, name, sql) in MIGRATIONS {
            let checksum = hex::encode(Sha256::digest(sql.as_bytes()));
            let existing: Option<String> = sqlx::query_scalar("SELECT checksum FROM caliban_schema_migrations WHERE version = $1")
                .bind(version)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
            match existing {
                Some(c) if c == checksum => continue,
                Some(_) => {
                    return Err(StoreError::Backend(format!(
                        "migration {version:04}_{name} was modified after it was applied; add a new migration instead"
                    )));
                }
                None => {}
            }
            sqlx::raw_sql(sql).execute(&mut *tx).await.map_err(|e| StoreError::Backend(format!("migration {version:04}_{name}: {e}")))?;
            sqlx::query("INSERT INTO caliban_schema_migrations (version, name, checksum) VALUES ($1, $2, $3)")
                .bind(version)
                .bind(name)
                .bind(checksum)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            tracing::info!(version, name, "applied migration");
            applied.push(version);
        }
        tx.commit().await.map_err(db)?;
        Ok(applied)
    }

    /// Writes `seed` if the database has never been seeded. Returns whether it did.
    pub async fn seed_if_empty(&self, seed: &State) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(WRITE_LOCK).execute(&mut *tx).await.map_err(db)?;
        let seeded: Option<String> =
            sqlx::query_scalar("SELECT value FROM cp_meta WHERE key = 'seeded_at'").fetch_optional(&mut *tx).await.map_err(db)?;
        if seeded.is_some() {
            return Ok(false);
        }
        let c: &mut PgConnection = &mut tx;
        for t in &seed.tenants {
            insert_tenant(c, t).await?;
        }
        for k in &seed.api_keys {
            insert_api_key(c, k).await?;
        }
        for p in &seed.provider_keys {
            insert_provider_key(c, p).await?;
        }
        for p in &seed.shared_providers {
            insert_shared_provider(c, p).await?;
        }
        for m in &seed.models {
            insert_model(c, m).await?;
        }
        for (tenant, routes) in &seed.routes {
            set_routes(c, tenant, routes).await?;
        }
        sqlx::query("INSERT INTO cp_meta (key, value) VALUES ('seeded_at', $1)")
            .bind(now_micros().to_rfc3339())
            .execute(&mut *c)
            .await
            .map_err(db)?;
        append_audit(c, "system", &super::memory::seed_draft(seed)).await?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }
}

#[async_trait::async_trait]
impl Backend for PgBackend {
    fn name(&self) -> &'static str {
        "postgres"
    }

    async fn load(&self) -> Result<State, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *tx).await.map_err(db)?;
        let st = load_state(&mut tx).await?;
        tx.commit().await.map_err(db)?;
        Ok(st)
    }

    async fn head(&self) -> Result<u64, StoreError> {
        let mut c = self.pool.acquire().await.map_err(db)?;
        audit_head(&mut c).await
    }

    async fn apply(&self, actor: &str, m: &Mutation, check: Check<'_>) -> Result<State, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(WRITE_LOCK).execute(&mut *tx).await.map_err(db)?;
        let mut next = load_state(&mut tx).await?;
        let draft = m.audit(&next);
        super::memory::apply_to(&mut next, m)?;
        persist(&mut tx, m, &next).await?;
        let mut post = load_state(&mut tx).await?;
        check(&post).map_err(StoreError::Invalid)?;
        post.audit_head = append_audit(&mut tx, actor, &draft).await?.seq;
        tx.commit().await.map_err(db)?;
        Ok(post)
    }

    async fn audit(&self, limit: usize) -> Result<Vec<AuditEntry>, StoreError> {
        let rows = sqlx::query(
            "SELECT seq, ts, tenant_id, actor, action, target, detail, prev_hash, hash
             FROM audit_log ORDER BY seq DESC LIMIT $1",
        )
        .bind(i64_of(limit as u64))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut out = rows.iter().map(audit_row).collect::<Result<Vec<_>, _>>()?;
        out.reverse();
        Ok(out)
    }
}

// ───────────────────────────── writes ─────────────────────────────

/// Writes the delta of `m`. `next` is the state after the in-memory semantics were applied (used
/// for values the store assigns, e.g. node versions).
async fn persist(c: &mut PgConnection, m: &Mutation, next: &State) -> Result<(), StoreError> {
    match m {
        Mutation::CreateTenant(t) => insert_tenant(c, t).await,
        Mutation::CreateApiKey(k) => insert_api_key(c, k).await,
        Mutation::RevokeApiKey { tenant_id, id, at } => {
            let q = "UPDATE api_key SET revoked_at = $3 WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL";
            exec(c, sqlx::query(q).bind(tenant_id).bind(id).bind(at)).await
        }
        Mutation::DeleteTenant { id, at } => delete_tenant(c, id, *at).await,
        Mutation::UpdateTenant { id, .. } => {
            let t = next.tenant(id).ok_or_else(|| StoreError::NotFound("tenant".into()))?;
            let q = "UPDATE tenant SET pii_default = $2, pii_surrogate_scope = $3, semantic_cache = $4 WHERE id = $1 AND status = 'active'";
            exec(c, sqlx::query(q).bind(id).bind(enum_str(&t.pii_default)).bind(t.pii_surrogate_scope.as_str()).bind(t.semantic_cache.as_str())).await
        }
        Mutation::CreateProviderKey(p) => insert_provider_key(c, p).await,
        Mutation::DeleteProviderKey { tenant_id, id } => {
            exec(c, sqlx::query("DELETE FROM provider_credential WHERE tenant_id = $1 AND id = $2").bind(tenant_id).bind(id)).await
        }
        Mutation::CreateModel(model) => insert_model(c, model).await,
        Mutation::DeleteModel(id) => exec(c, sqlx::query("DELETE FROM model WHERE id = $1").bind(id)).await,
        Mutation::CreateSharedProvider(p) => insert_shared_provider(c, p).await,
        Mutation::DeleteSharedProvider(id) => exec(c, sqlx::query("DELETE FROM shared_provider WHERE id = $1").bind(id)).await,
        Mutation::SetRoutes { tenant_id, routes } => set_routes(c, tenant_id, routes).await,
        Mutation::CreateDatasource(ds) => insert_datasource(c, ds).await,
        Mutation::SetDatasourceStatus { id, status } => {
            exec(c, sqlx::query("UPDATE datasource SET status = $2 WHERE id = $1").bind(id).bind(status)).await
        }
        Mutation::DeleteDatasource { tenant_id, id, at } => {
            let q = "UPDATE datasource SET deleted_at = $3, connection = '{}' WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";
            exec(c, sqlx::query(q).bind(tenant_id).bind(id).bind(at)).await
        }
        Mutation::DeleteNode { tenant_id, id, at } => {
            let q = "UPDATE node SET deleted_at = $3 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL";
            exec(c, sqlx::query(q).bind(tenant_id).bind(id).bind(at)).await
        }
        Mutation::CreateNode(n) => {
            let assigned = next.nodes.iter().find(|x| x.id == n.id).ok_or_else(|| StoreError::Backend("node not applied".into()))?;
            insert_node(c, assigned).await
        }
        Mutation::ProposeOntology { tenant_id, elements } => {
            ontology_commit(c, tenant_id, "ontology.propose", elements).await
        }
        Mutation::ReviewOntologyElement { id, status } => {
            let (tenant, e) = next
                .ontologies
                .iter()
                .find_map(|(t, o)| o.elements.iter().find(|e| &e.id == id).map(|e| (t.clone(), e.clone())))
                .ok_or_else(|| StoreError::NotFound("ontology element".into()))?;
            ontology_commit(c, &tenant, &format!("review {id}: {}", enum_str(status)), std::slice::from_ref(&e)).await
        }
    }
}

/// Tenant tombstone and its cascade, matching `memory::apply_to`. Audit rows are untouched (the
/// table is append-only), and the tenant row stays so its id is never reused.
async fn delete_tenant(c: &mut PgConnection, id: &str, at: DateTime<Utc>) -> Result<(), StoreError> {
    let tenant_at = |sql: &'static str| sqlx::query(sql).bind(id).bind(at);
    exec(c, tenant_at("UPDATE tenant SET status = 'deleted', deleted_at = $2 WHERE id = $1 AND status = 'active'")).await?;
    exec(c, tenant_at("UPDATE api_key SET revoked_at = $2 WHERE tenant_id = $1 AND revoked_at IS NULL")).await?;
    exec(c, tenant_at("UPDATE datasource SET deleted_at = $2, connection = '{}' WHERE tenant_id = $1 AND deleted_at IS NULL")).await?;
    exec(c, tenant_at("UPDATE node SET deleted_at = $2 WHERE tenant_id = $1 AND deleted_at IS NULL")).await?;
    let tenant = |sql: &'static str| sqlx::query(sql).bind(id);
    exec(c, tenant("DELETE FROM route WHERE tenant_id = $1")).await?;
    // BYOK: drop the sealed ciphertext with its rows, and the tenant's wrapped DEK if one exists
    // (crypto-shredding once per-tenant DEKs are in use).
    exec(c, tenant("DELETE FROM provider_credential WHERE tenant_id = $1")).await?;
    exec(c, tenant("DELETE FROM tenant_dek WHERE tenant_id = $1")).await
}

async fn exec<'q>(c: &mut PgConnection, q: sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments>) -> Result<(), StoreError> {
    q.execute(&mut *c).await.map(|_| ()).map_err(db)
}

async fn insert_tenant(c: &mut PgConnection, t: &Tenant) -> Result<(), StoreError> {
    exec(
        c,
        sqlx::query(
            "INSERT INTO tenant (id, name, region, pii_default, pii_surrogate_scope, semantic_cache, settings, created_at, status, deleted_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&t.id)
        .bind(&t.name)
        .bind(&t.region)
        .bind(enum_str(&t.pii_default))
        .bind(t.pii_surrogate_scope.as_str())
        .bind(t.semantic_cache.as_str())
        .bind(Json(Value::Object(t.settings.clone())))
        .bind(t.created_at)
        .bind(t.status.as_str())
        .bind(t.deleted_at),
    )
    .await
}

async fn insert_api_key(c: &mut PgConnection, k: &ApiKeyRecord) -> Result<(), StoreError> {
    exec(
        c,
        sqlx::query("INSERT INTO api_key (id, tenant_id, name, prefix, sha256, created_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(&k.id)
            .bind(&k.tenant_id)
            .bind(&k.name)
            .bind(&k.prefix)
            .bind(&k.hash)
            .bind(k.created_at)
            .bind(k.revoked_at),
    )
    .await
}

async fn insert_provider_key(c: &mut PgConnection, p: &ProviderKeyRecord) -> Result<(), StoreError> {
    let (sealed, reference) = split_secret(p.secret.as_ref())?;
    exec(
        c,
        sqlx::query(
            "INSERT INTO provider_credential
                 (tenant_id, id, kind, label, base_url, trust_tier, sealed_key, secret_ref, last4, cache_salt, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&p.tenant_id)
        .bind(&p.id)
        .bind(enum_str(&p.kind))
        .bind(&p.label)
        .bind(&p.base_url)
        .bind(enum_str(&p.trust_tier))
        .bind(sealed)
        .bind(reference)
        .bind(&p.last4)
        .bind(p.cache_salt)
        .bind(p.created_at),
    )
    .await
}

async fn insert_shared_provider(c: &mut PgConnection, sp: &SharedProvider) -> Result<(), StoreError> {
    let p = &sp.provider;
    let (sealed, reference) = split_secret(p.api_key.as_ref())?;
    exec(
        c,
        sqlx::query(
            "INSERT INTO shared_provider (id, kind, base_url, trust_tier, cache_salt, sealed_key, secret_ref, tenants)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(p.id.to_string())
        .bind(enum_str(&p.kind))
        .bind(&p.base_url)
        .bind(enum_str(&p.trust_tier))
        .bind(p.cache_salt)
        .bind(sealed)
        .bind(reference)
        .bind(sp.tenants.iter().map(ToString::to_string).collect::<Vec<_>>()),
    )
    .await
}

async fn insert_model(c: &mut PgConnection, m: &ModelEntry) -> Result<(), StoreError> {
    exec(
        c,
        sqlx::query(
            "INSERT INTO model (id, provider_id, upstream_model, kind, family, capabilities, trust_tier, licence,
                                context_window, price_in_per_mtok, price_out_per_mtok)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(m.id.to_string())
        .bind(m.provider.to_string())
        .bind(&m.upstream_model)
        .bind(enum_str(&m.kind))
        .bind(&m.family)
        .bind(Json(serde_json::to_value(&m.capabilities).map_err(|e| StoreError::Backend(e.to_string()))?))
        .bind(enum_str(&m.trust_tier))
        .bind(&m.licence)
        .bind(m.context_window.map(|n| i32::try_from(n).unwrap_or(i32::MAX)))
        .bind(m.price_in_per_mtok)
        .bind(m.price_out_per_mtok),
    )
    .await
}

async fn set_routes(c: &mut PgConnection, tenant: &str, routes: &[RouteConfig]) -> Result<(), StoreError> {
    exec(c, sqlx::query("DELETE FROM route WHERE tenant_id = $1").bind(tenant)).await?;
    for (i, r) in routes.iter().enumerate() {
        exec(
            c,
            sqlx::query("INSERT INTO route (tenant_id, intent, models, position) VALUES ($1, $2, $3, $4)")
                .bind(tenant)
                .bind(&r.intent)
                .bind(r.models.iter().map(ToString::to_string).collect::<Vec<_>>())
                .bind(i32::try_from(i).unwrap_or(i32::MAX)),
        )
        .await?;
    }
    Ok(())
}

async fn insert_datasource(c: &mut PgConnection, d: &DatasourceRecord) -> Result<(), StoreError> {
    exec(
        c,
        sqlx::query(
            "INSERT INTO datasource (id, tenant_id, kind, name, status, connection, epoch, deleted_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&d.id)
        .bind(&d.tenant_id)
        .bind(&d.kind)
        .bind(&d.name)
        .bind(&d.status)
        .bind(Json(d.connection.clone()))
        .bind(i64_of(d.epoch))
        .bind(d.deleted_at),
    )
    .await
}

async fn insert_node(c: &mut PgConnection, n: &NodeRecord) -> Result<(), StoreError> {
    exec(
        c,
        sqlx::query("INSERT INTO node (id, tenant_id, name, version, spec, created_at, deleted_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(&n.id)
            .bind(&n.tenant_id)
            .bind(&n.name)
            .bind(i32::try_from(n.version).unwrap_or(i32::MAX))
            .bind(Json(n.spec.clone()))
            .bind(n.created_at)
            .bind(n.deleted_at),
    )
    .await
}

/// One ontology commit: the given elements (full bodies) on top of the current head, then the
/// head moves. The tenant's ontology version is its number of commits.
async fn ontology_commit(c: &mut PgConnection, tenant: &str, message: &str, elements: &[Element]) -> Result<(), StoreError> {
    let commit: i64 = sqlx::query_scalar(
        "INSERT INTO ontology_commit (tenant_id, parent_id, author, message)
         VALUES ($1, (SELECT commit_id FROM ontology_head WHERE tenant_id = $1), 'control-plane', $2) RETURNING id",
    )
    .bind(tenant)
    .bind(message)
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    for e in elements {
        let body = serde_json::to_value(e).map_err(|e| StoreError::Backend(e.to_string()))?;
        let kind = body.get("kind").and_then(Value::as_str).unwrap_or_default().to_owned();
        exec(
            c,
            sqlx::query(
                "INSERT INTO ontology_element (tenant_id, id, commit_id, kind, name, status, provenance, confidence, body)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(tenant)
            .bind(&e.id)
            .bind(commit)
            .bind(kind)
            .bind(&e.name)
            .bind(enum_str(&e.status))
            .bind(enum_str(&e.provenance))
            .bind(e.confidence)
            .bind(Json(body)),
        )
        .await?;
    }
    exec(
        c,
        sqlx::query(
            "INSERT INTO ontology_head (tenant_id, commit_id) VALUES ($1, $2)
             ON CONFLICT (tenant_id) DO UPDATE SET commit_id = EXCLUDED.commit_id, published_at = now()",
        )
        .bind(tenant)
        .bind(commit),
    )
    .await
}

async fn append_audit(c: &mut PgConnection, actor: &str, d: &AuditDraft) -> Result<AuditEntry, StoreError> {
    let prev = sqlx::query(
        "SELECT seq, ts, tenant_id, actor, action, target, detail, prev_hash, hash FROM audit_log ORDER BY seq DESC LIMIT 1",
    )
    .fetch_optional(&mut *c)
    .await
    .map_err(db)?
    .map(|r| audit_row(&r))
    .transpose()?;
    let e = AuditEntry::next(prev.as_ref(), actor, d, now_micros());
    let hex_bytes = |h: &str| hex::decode(h).map_err(|e| StoreError::Backend(e.to_string()));
    exec(
        c,
        sqlx::query(
            "INSERT INTO audit_log (seq, tenant_id, actor, action, target, detail, prev_hash, hash, ts)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(i64_of(e.seq))
        .bind(&e.tenant_id)
        .bind(&e.actor)
        .bind(&e.action)
        .bind(&e.target)
        .bind(Json(e.detail.clone()))
        .bind(e.prev_hash.as_deref().map(hex_bytes).transpose()?)
        .bind(hex_bytes(&e.hash)?)
        .bind(e.ts),
    )
    .await?;
    Ok(e)
}

// ───────────────────────────── reads ─────────────────────────────

fn audit_row(r: &PgRow) -> Result<AuditEntry, StoreError> {
    Ok(AuditEntry {
        seq: u64::try_from(get::<i64>(r, "seq")?).unwrap_or_default(),
        ts: get::<DateTime<Utc>>(r, "ts")?,
        tenant_id: get(r, "tenant_id")?,
        actor: get(r, "actor")?,
        action: get(r, "action")?,
        target: get(r, "target")?,
        detail: get::<Json<Value>>(r, "detail")?.0,
        prev_hash: get::<Option<Vec<u8>>>(r, "prev_hash")?.map(hex::encode),
        hash: hex::encode(get::<Vec<u8>>(r, "hash")?),
    })
}

async fn audit_head(c: &mut PgConnection) -> Result<u64, StoreError> {
    let n: i64 = sqlx::query_scalar("SELECT coalesce(max(seq), 0)::BIGINT FROM audit_log").fetch_one(&mut *c).await.map_err(db)?;
    Ok(u64::try_from(n).unwrap_or_default())
}

async fn rows(c: &mut PgConnection, sql: &'static str) -> Result<Vec<PgRow>, StoreError> {
    sqlx::query(sql).fetch_all(&mut *c).await.map_err(db)
}

async fn load_state(c: &mut PgConnection) -> Result<State, StoreError> {
    let mut st = State::default();

    for r in rows(c, "SELECT id, name, region, pii_default, pii_surrogate_scope, semantic_cache, settings, created_at, status, deleted_at FROM tenant ORDER BY ord").await? {
        st.tenants.push(Tenant {
            id: get(&r, "id")?,
            name: get(&r, "name")?,
            region: get(&r, "region")?,
            pii_default: parse_enum(get(&r, "pii_default")?)?,
            pii_surrogate_scope: parse_enum(get(&r, "pii_surrogate_scope")?)?,
            semantic_cache: parse_enum(get(&r, "semantic_cache")?)?,
            created_at: get(&r, "created_at")?,
            status: match get::<String>(&r, "status")?.as_str() {
                "deleted" => TenantStatus::Deleted,
                _ => TenantStatus::Active,
            },
            deleted_at: get(&r, "deleted_at")?,
            settings: match get::<Json<Value>>(&r, "settings")?.0 {
                Value::Object(m) => m,
                _ => serde_json::Map::new(),
            },
        });
    }

    // Revoked keys are loaded too (listed with `include_revoked`); `render` leaves them out.
    for r in rows(c, "SELECT id, tenant_id, name, prefix, sha256, created_at, revoked_at FROM api_key ORDER BY ord").await? {
        st.api_keys.push(ApiKeyRecord {
            id: get(&r, "id")?,
            tenant_id: get(&r, "tenant_id")?,
            name: get(&r, "name")?,
            prefix: get(&r, "prefix")?,
            hash: get(&r, "sha256")?,
            created_at: get(&r, "created_at")?,
            revoked_at: get(&r, "revoked_at")?,
        });
    }

    for r in rows(
        c,
        "SELECT tenant_id, id, kind, label, base_url, trust_tier, sealed_key, secret_ref, last4, cache_salt, created_at
         FROM provider_credential ORDER BY ord",
    )
    .await?
    {
        st.provider_keys.push(ProviderKeyRecord {
            id: get(&r, "id")?,
            tenant_id: get(&r, "tenant_id")?,
            kind: parse_enum(get(&r, "kind")?)?,
            label: get(&r, "label")?,
            base_url: get(&r, "base_url")?,
            trust_tier: parse_enum(get(&r, "trust_tier")?)?,
            last4: get(&r, "last4")?,
            cache_salt: get(&r, "cache_salt")?,
            created_at: get(&r, "created_at")?,
            secret: join_secret(get(&r, "sealed_key")?, get(&r, "secret_ref")?)?,
        });
    }

    for r in rows(c, "SELECT id, kind, base_url, trust_tier, cache_salt, sealed_key, secret_ref, tenants FROM shared_provider ORDER BY ord")
        .await?
    {
        st.shared_providers.push(SharedProvider {
            provider: ProviderConfig {
                id: get::<String>(&r, "id")?.as_str().into(),
                kind: parse_enum(get(&r, "kind")?)?,
                base_url: get(&r, "base_url")?,
                trust_tier: parse_enum(get(&r, "trust_tier")?)?,
                api_key: join_secret(get(&r, "sealed_key")?, get(&r, "secret_ref")?)?,
                cache_salt: get(&r, "cache_salt")?,
            },
            tenants: get::<Vec<String>>(&r, "tenants")?.iter().map(|t| t.as_str().into()).collect(),
        });
    }

    for r in rows(
        c,
        "SELECT id, provider_id, upstream_model, kind, family, capabilities, trust_tier, licence, context_window,
                price_in_per_mtok, price_out_per_mtok
         FROM model ORDER BY ord",
    )
    .await?
    {
        st.models.push(ModelEntry {
            id: get::<String>(&r, "id")?.as_str().into(),
            provider: get::<String>(&r, "provider_id")?.as_str().into(),
            upstream_model: get(&r, "upstream_model")?,
            kind: parse_enum(get(&r, "kind")?)?,
            family: get(&r, "family")?,
            capabilities: parse(get::<Json<Value>>(&r, "capabilities")?.0)?,
            trust_tier: parse_enum(get(&r, "trust_tier")?)?,
            licence: get(&r, "licence")?,
            context_window: get::<Option<i32>>(&r, "context_window")?.and_then(|n| u32::try_from(n).ok()),
            price_in_per_mtok: get(&r, "price_in_per_mtok")?,
            price_out_per_mtok: get(&r, "price_out_per_mtok")?,
        });
    }

    for r in rows(c, "SELECT tenant_id, intent, models FROM route ORDER BY tenant_id, position, intent").await? {
        let tenant: String = get(&r, "tenant_id")?;
        st.routes.entry(tenant).or_default().push(RouteConfig {
            intent: get(&r, "intent")?,
            models: get::<Vec<String>>(&r, "models")?.iter().map(|m| m.as_str().into()).collect(),
        });
    }

    for r in rows(c, "SELECT id, tenant_id, kind, name, status, connection, epoch, deleted_at FROM datasource ORDER BY ord").await? {
        st.datasources.push(DatasourceRecord {
            id: get(&r, "id")?,
            tenant_id: get(&r, "tenant_id")?,
            kind: get(&r, "kind")?,
            name: get(&r, "name")?,
            status: get(&r, "status")?,
            epoch: u64::try_from(get::<i64>(&r, "epoch")?).unwrap_or_default(),
            connection: get::<Json<Value>>(&r, "connection")?.0,
            deleted_at: get(&r, "deleted_at")?,
        });
    }

    for r in rows(c, "SELECT id, tenant_id, name, version, spec, created_at, deleted_at FROM node ORDER BY ord").await? {
        st.nodes.push(NodeRecord {
            id: get(&r, "id")?,
            tenant_id: get(&r, "tenant_id")?,
            name: get(&r, "name")?,
            version: u32::try_from(get::<i32>(&r, "version")?).unwrap_or_default(),
            spec: get::<Json<Value>>(&r, "spec")?.0,
            created_at: get(&r, "created_at")?,
            deleted_at: get(&r, "deleted_at")?,
        });
    }

    for r in rows(
        c,
        "SELECT h.tenant_id,
                (SELECT count(*) FROM ontology_commit oc WHERE oc.tenant_id = h.tenant_id AND oc.id <= h.commit_id)::BIGINT AS version
         FROM ontology_head h",
    )
    .await?
    {
        let tenant: String = get(&r, "tenant_id")?;
        let version = u64::try_from(get::<i64>(&r, "version")?).unwrap_or_default();
        st.ontologies.insert(tenant.clone(), Ontology { tenant_id: tenant, version, elements: vec![] });
    }
    // Latest body of each element at or before the head, in first-insertion order.
    for r in rows(
        c,
        "SELECT tenant_id, body FROM (
             SELECT DISTINCT ON (e.tenant_id, e.id) e.tenant_id, e.body,
                    min(e.ord) OVER (PARTITION BY e.tenant_id, e.id) AS first_ord
             FROM ontology_element e JOIN ontology_head h ON h.tenant_id = e.tenant_id AND e.commit_id <= h.commit_id
             ORDER BY e.tenant_id, e.id, e.commit_id DESC
         ) x ORDER BY tenant_id, first_ord",
    )
    .await?
    {
        let tenant: String = get(&r, "tenant_id")?;
        let element: Element = parse(get::<Json<Value>>(&r, "body")?.0)?;
        if let Some(o) = st.ontologies.get_mut(&tenant) {
            o.elements.push(element);
        }
    }

    st.audit_head = audit_head(c).await?;
    Ok(st)
}
