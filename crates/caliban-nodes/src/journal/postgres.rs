//! Postgres journal (`CALIBAN_DATABASE_URL`): the tables of `migrations/0013_node_journal.sql`,
//! which the control plane's migration runner applies (workers only check the schema version).
//!
//! Workers claim with `UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED)`: a row locked by
//! one claimer is skipped by the others, so concurrent workers never claim the same run, and the
//! lease (owner, expiry) is renewed by heartbeats. Every write a worker makes for a run is fenced
//! by `lease_owner = <worker> AND status = 'running'` in the same statement or transaction. Times
//! come from the database clock (`now()`), so workers on hosts with skewed clocks agree on leases.

use super::*;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgRow};
use sqlx::types::Json;
use sqlx::{Postgres, Row};

/// The journal's migrations, in order (also registered in the control plane's migration list,
/// which applies them; workers only check the schema version).
pub const MIGRATIONS: &[&str] = &[
    include_str!("../../../../migrations/0013_node_journal.sql"),
    include_str!("../../../../migrations/0014_node_run_specs.sql"),
    include_str!("../../../../migrations/0015_node_spend.sql"),
    include_str!("../../../../migrations/0017_node_run_retention.sql"),
    include_str!("../../../../migrations/0021_node_exposure.sql"),
    include_str!("../../../../migrations/0024_node_evals.sql"),
    include_str!("../../../../migrations/0025_node_run_input_labels.sql"),
    include_str!("../../../../migrations/0032_node_step_metering.sql"),
    include_str!("../../../../migrations/0037_node_run_mast_label.sql"),
];

/// Columns of `node_step` rows ([`step_row`]).
macro_rules! step_columns {
    () => {
        "run_id, tenant_id, step_id, attempt, vertex, kind, input_hash, status, result, tokens, prompt_tokens, \
         completion_tokens, usd, labels, started_at, finished_at, model_cost_usd, pii_entities"
    };
}

macro_rules! run_columns {
    () => {
        "id, tenant_id, node, version, spec_hash, invoker, invoker_key_hash, input, specs, output, status, wake_at, awaiting, \
         prompt, budget, lease_owner, lease_expires_at, claims, error, stop_reason, idempotency_key, \
         idempotency_fingerprint, created_at, updated_at, started_at, finished_at, cancel_requested_at, \
         cancelled_by, origin, event_seq, input_labels, mast_label"
    };
}

/// The claim rule (see `memory::runnable`).
macro_rules! runnable {
    () => {
        "((status = 'pending' AND (wake_at IS NULL OR wake_at <= now()))
          OR (status IN ('sleeping', 'input_required') AND wake_at IS NOT NULL AND wake_at <= now())
          OR (status = 'running' AND (lease_expires_at IS NULL OR lease_expires_at < now())))"
    };
}

/// What a claim sets.
macro_rules! take {
    () => {
        "status = 'running', lease_owner = $1, lease_expires_at = now() + make_interval(secs => $2),
         claims = claims + 1, started_at = COALESCE(started_at, now()), wake_at = NULL, awaiting = NULL,
         prompt = NULL, updated_at = now()"
    };
}

pub struct PgJournal {
    pool: PgPool,
}

fn db(e: sqlx::Error) -> JournalError {
    JournalError(e.to_string())
}

fn get<'r, T>(r: &'r PgRow, col: &str) -> JResult<T>
where
    T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>,
{
    r.try_get::<T, _>(col).map_err(|e| JournalError(format!("column {col}: {e}")))
}

fn secs(ttl: Duration) -> f64 {
    ttl.as_secs_f64()
}

fn i32_of(n: u32) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

fn run_row(r: &PgRow) -> JResult<RunRecord> {
    let status: String = get(r, "status")?;
    Ok(RunRecord {
        id: get(r, "id")?,
        tenant_id: get(r, "tenant_id")?,
        node: get(r, "node")?,
        version: u32::try_from(get::<i32>(r, "version")?).unwrap_or_default(),
        spec_hash: get(r, "spec_hash")?,
        invoker: get(r, "invoker")?,
        invoker_key_hash: get(r, "invoker_key_hash")?,
        input: get(r, "input")?,
        specs: get(r, "specs")?,
        output: get(r, "output")?,
        status: RunStatus::parse(&status).ok_or_else(|| JournalError(format!("unknown run status {status}")))?,
        wake_at: get(r, "wake_at")?,
        awaiting: get(r, "awaiting")?,
        prompt: get(r, "prompt")?,
        budget: serde_json::from_value(get::<Json<serde_json::Value>>(r, "budget")?.0)
            .map_err(|e| JournalError(format!("budget: {e}")))?,
        lease_owner: get(r, "lease_owner")?,
        lease_expires_at: get(r, "lease_expires_at")?,
        claims: u32::try_from(get::<i32>(r, "claims")?).unwrap_or_default(),
        error: get(r, "error")?,
        stop_reason: get(r, "stop_reason")?,
        idempotency_key: get(r, "idempotency_key")?,
        idempotency_fingerprint: get(r, "idempotency_fingerprint")?,
        created_at: get(r, "created_at")?,
        updated_at: get(r, "updated_at")?,
        started_at: get(r, "started_at")?,
        finished_at: get(r, "finished_at")?,
        cancel_requested_at: get(r, "cancel_requested_at")?,
        cancelled_by: get(r, "cancelled_by")?,
        origin: get(r, "origin")?,
        input_labels: serde_json::from_value(get::<Json<serde_json::Value>>(r, "input_labels")?.0)
            .map_err(|e| JournalError(format!("input_labels: {e}")))?,
        last_event: u64::try_from(get::<i64>(r, "event_seq")?).unwrap_or_default(),
        mast_label: get(r, "mast_label")?,
    })
}

fn u64_of(r: &PgRow, col: &str) -> JResult<u64> {
    Ok(u64::try_from(get::<i64>(r, col)?).unwrap_or_default())
}

fn i64_of(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Appends an event to a run inside `tx` (which holds or takes the run row's lock): the run's
/// `event_seq` numbers it, so numbers follow commit order.
async fn push_event(tx: &mut sqlx::PgConnection, run_id: &str, kind: &str, data: &serde_json::Value) -> JResult<()> {
    sqlx::query(
        "WITH r AS (UPDATE node_run SET event_seq = event_seq + 1 WHERE id = $1 RETURNING id, tenant_id, event_seq)
         INSERT INTO node_run_event (run_id, seq, tenant_id, kind, data) SELECT id, event_seq, tenant_id, $2, $3 FROM r",
    )
    .bind(run_id)
    .bind(kind)
    .bind(Json(data))
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    Ok(())
}

async fn push_audit(tx: &mut sqlx::PgConnection, a: Option<&AuditEvent>) -> JResult<()> {
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

fn step_row(r: &PgRow) -> JResult<StepRecord> {
    let status: String = get(r, "status")?;
    Ok(StepRecord {
        run_id: get(r, "run_id")?,
        tenant_id: get(r, "tenant_id")?,
        step_id: get(r, "step_id")?,
        attempt: u32::try_from(get::<i32>(r, "attempt")?).unwrap_or_default(),
        vertex: get(r, "vertex")?,
        kind: get(r, "kind")?,
        input_hash: get(r, "input_hash")?,
        status: if status == "completed" { StepStatus::Completed } else { StepStatus::Failed },
        result: get(r, "result")?,
        tokens: u64_of(r, "tokens")?,
        prompt_tokens: u64_of(r, "prompt_tokens")?,
        completion_tokens: u64_of(r, "completion_tokens")?,
        usd: get(r, "usd")?,
        model_cost_usd: get::<Option<f64>>(r, "model_cost_usd")?.unwrap_or(get(r, "usd")?),
        pii_entities: u64::try_from(get::<i32>(r, "pii_entities")?).unwrap_or(0),
        labels: serde_json::from_value(get::<Json<serde_json::Value>>(r, "labels")?.0).unwrap_or_default(),
        started_at: get(r, "started_at")?,
        finished_at: get(r, "finished_at")?,
    })
}

fn budget_json(b: &BudgetState) -> JResult<Json<serde_json::Value>> {
    serde_json::to_value(b).map(Json).map_err(|e| JournalError(e.to_string()))
}

impl PgJournal {
    pub async fn connect(url: &str) -> JResult<Self> {
        let opts: PgConnectOptions =
            url.parse().map_err(|e: sqlx::Error| JournalError(format!("database url: {e}")))?;
        Self::connect_with(opts).await
    }

    pub async fn connect_with(opts: PgConnectOptions) -> JResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect_with(opts)
            .await
            .map_err(|e| JournalError(format!("connecting to postgres: {e}")))?;
        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// A journal in a new schema of its own, with the journal tables created (tests: many
    /// journals in one database). Production journals use the tables the migration runner made.
    #[doc(hidden)]
    pub async fn isolated(url: &str) -> JResult<Self> {
        let schema = format!("j_{}", uuid::Uuid::now_v7().simple());
        let admin = PgPool::connect(url).await.map_err(db)?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}"))).execute(&admin).await.map_err(db)?;
        admin.close().await;
        let opts: PgConnectOptions = url
            .parse::<PgConnectOptions>()
            .map_err(|e| JournalError(format!("database url: {e}")))?
            .options([("search_path", schema.as_str())]);
        let j = Self::connect_with(opts).await?;
        for m in MIGRATIONS {
            sqlx::raw_sql(*m).execute(&j.pool).await.map_err(db)?;
        }
        Ok(j)
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Takes outbox rows (all actions, or only `actions`).
    async fn claim_audit_rows(
        &self,
        worker: &str,
        ttl: Duration,
        limit: usize,
        actions: Option<&[&str]>,
    ) -> JResult<Vec<AuditEvent>> {
        let actions: Option<Vec<String>> = actions.map(|a| a.iter().map(|s| (*s).to_owned()).collect());
        let rows = sqlx::query(
            "UPDATE node_audit SET claimed_by = $1, claimed_until = now() + make_interval(secs => $2)
             WHERE id IN (SELECT id FROM node_audit WHERE (claimed_until IS NULL OR claimed_until < now())
                            AND ($4::text[] IS NULL OR action = ANY($4))
                          ORDER BY created_at LIMIT $3 FOR UPDATE SKIP LOCKED)
             RETURNING id, tenant_id, actor, action, target, detail, created_at",
        )
        .bind(worker)
        .bind(secs(ttl))
        .bind(i64_of(limit as u64))
        .bind(actions)
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
            .collect::<JResult<_>>()?;
        out.sort_by_key(|a| a.at);
        Ok(out)
    }

    async fn one(
        &self,
        q: sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments>,
    ) -> JResult<Option<RunRecord>> {
        q.fetch_optional(&self.pool).await.map_err(db)?.as_ref().map(run_row).transpose()
    }
}

#[async_trait::async_trait]
impl Journal for PgJournal {
    fn name(&self) -> &'static str {
        "postgres"
    }

    async fn create_run(&self, run: NewRun) -> JResult<Created> {
        let (key, fp) = run.idempotency.clone().map_or((None, None), |(k, f)| (Some(k), Some(f)));
        let mut tx = self.pool.begin().await.map_err(db)?;
        let inserted = sqlx::query(concat!(
            "INSERT INTO node_run (id, tenant_id, node, version, spec_hash, invoker, invoker_key_hash, input, status,
                                   budget, idempotency_key, idempotency_fingerprint, specs, origin, event_seq,
                                   input_labels)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11, $12, $13, 1, $14)
             ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
             RETURNING ",
            run_columns!()
        ))
        .bind(&run.id)
        .bind(&run.tenant_id)
        .bind(&run.node)
        .bind(i32_of(run.version))
        .bind(&run.spec_hash)
        .bind(&run.invoker)
        .bind(&run.invoker_key_hash)
        .bind(&run.input)
        .bind(budget_json(&run.budget)?)
        .bind(&key)
        .bind(&fp)
        .bind(&run.specs)
        .bind(&run.origin)
        .bind(Json(serde_json::json!(run.input_labels)))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if let Some(r) = inserted {
            let rec = run_row(&r)?;
            sqlx::query("INSERT INTO node_run_event (run_id, seq, tenant_id, kind, data) VALUES ($1, 1, $2, $3, $4)")
                .bind(&rec.id)
                .bind(&rec.tenant_id)
                .bind(event::RUN_CREATED)
                .bind(Json(serde_json::json!({"node": rec.node, "version": rec.version})))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            tx.commit().await.map_err(db)?;
            return Ok(Created::New(rec));
        }
        tx.rollback().await.map_err(db)?;
        // The key was used before by this tenant.
        let existing = sqlx::query(concat!(
            "SELECT ",
            run_columns!(),
            " FROM node_run WHERE tenant_id = $1 AND idempotency_key = $2"
        ))
        .bind(&run.tenant_id)
        .bind(&key)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .as_ref()
        .map(run_row)
        .transpose()?
        .ok_or_else(|| JournalError("idempotent run vanished".into()))?;
        Ok(if existing.idempotency_fingerprint == fp { Created::Existing(existing) } else { Created::KeyReused })
    }

    async fn get_run(&self, tenant: &str, id: &str) -> JResult<Option<RunRecord>> {
        self.one(
            sqlx::query(concat!("SELECT ", run_columns!(), " FROM node_run WHERE id = $1 AND tenant_id = $2"))
                .bind(id)
                .bind(tenant),
        )
        .await
    }

    async fn steps(&self, run_id: &str) -> JResult<Vec<StepRecord>> {
        let rows = sqlx::query(concat!("SELECT ", step_columns!(), " FROM node_step WHERE run_id = $1 ORDER BY seq"))
            .bind(run_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter().map(step_row).collect()
    }

    async fn claim_next(&self, worker: &str, ttl: Duration) -> JResult<Option<RunRecord>> {
        let q = sqlx::query(concat!(
            "UPDATE node_run SET ",
            take!(),
            " WHERE id = (SELECT id FROM node_run WHERE ",
            runnable!(),
            " ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING ",
            run_columns!()
        ));
        self.one(q.bind(worker).bind(secs(ttl))).await
    }

    async fn claim(&self, run_id: &str, worker: &str, ttl: Duration) -> JResult<Option<RunRecord>> {
        let q = sqlx::query(concat!(
            "UPDATE node_run SET ",
            take!(),
            " WHERE id = $3 AND ",
            runnable!(),
            " RETURNING ",
            run_columns!()
        ));
        self.one(q.bind(worker).bind(secs(ttl)).bind(run_id)).await
    }

    async fn heartbeat(&self, run_id: &str, worker: &str, ttl: Duration) -> JResult<bool> {
        let r = sqlx::query(
            "UPDATE node_run SET lease_expires_at = now() + make_interval(secs => $3)
             WHERE id = $1 AND lease_owner = $2 AND status = 'running'",
        )
        .bind(run_id)
        .bind(worker)
        .bind(secs(ttl))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(r.rows_affected() == 1)
    }

    async fn release(&self, run_id: &str, worker: &str) -> JResult<bool> {
        let r = sqlx::query(
            "UPDATE node_run SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
             WHERE id = $1 AND lease_owner = $2 AND status = 'running'",
        )
        .bind(run_id)
        .bind(worker)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(r.rows_affected() == 1)
    }

    async fn put_step(&self, worker: &str, step: StepRecord, budget: &BudgetState) -> JResult<StepWrite> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        // Fence: lock the run row while we hold its lease (a claimer waits for this transaction).
        let held = sqlx::query(
            "UPDATE node_run SET budget = $3, updated_at = now()
             WHERE id = $1 AND lease_owner = $2 AND status = 'running'",
        )
        .bind(&step.run_id)
        .bind(worker)
        .bind(budget_json(budget)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if held.rows_affected() == 0 {
            return Ok(StepWrite::LeaseLost);
        }
        let inserted = sqlx::query(
            "INSERT INTO node_step (run_id, step_id, tenant_id, attempt, vertex, kind, input_hash, status, result, tokens,
                                    usd, started_at, finished_at, prompt_tokens, completion_tokens, labels,
                                    model_cost_usd, pii_entities)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
             ON CONFLICT (run_id, step_id) DO NOTHING",
        )
        .bind(&step.run_id)
        .bind(&step.step_id)
        .bind(&step.tenant_id)
        .bind(i32_of(step.attempt))
        .bind(&step.vertex)
        .bind(&step.kind)
        .bind(&step.input_hash)
        .bind(match step.status {
            StepStatus::Completed => "completed",
            StepStatus::Failed => "failed",
        })
        .bind(&step.result)
        .bind(i64::try_from(step.tokens).unwrap_or(i64::MAX))
        .bind(step.usd)
        .bind(step.started_at)
        .bind(step.finished_at)
        .bind(i64_of(step.prompt_tokens))
        .bind(i64_of(step.completion_tokens))
        .bind(Json(&step.labels))
        .bind(step.model_cost_usd)
        .bind(i32::try_from(step.pii_entities).unwrap_or(i32::MAX))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        let out = if inserted.rows_affected() == 1 {
            push_event(&mut tx, &step.run_id, event::STEP_FINISHED, &step_event(&step, budget.usd)).await?;
            // The step's cost counts towards the tenant's spend once: the step is written once.
            if step.usd > 0.0 {
                sqlx::query(
                    "INSERT INTO node_spend (tenant_id, day, usd) VALUES ($1, (now() AT TIME ZONE 'UTC')::date, $2)
                     ON CONFLICT (tenant_id, day) DO UPDATE SET usd = node_spend.usd + EXCLUDED.usd",
                )
                .bind(&step.tenant_id)
                .bind(step.usd)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            }
            StepWrite::Written
        } else {
            let r =
                sqlx::query(concat!("SELECT ", step_columns!(), " FROM node_step WHERE run_id = $1 AND step_id = $2"))
                    .bind(&step.run_id)
                    .bind(&step.step_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db)?;
            StepWrite::Existing(Box::new(step_row(&r)?))
        };
        tx.commit().await.map_err(db)?;
        Ok(out)
    }

    async fn suspend(&self, run_id: &str, worker: &str, s: Suspend) -> JResult<bool> {
        if !matches!(s.status, RunStatus::Sleeping | RunStatus::InputRequired) {
            return Err(JournalError(format!("cannot suspend a run as {}", s.status.as_str())));
        }
        let (kind, data) = suspend_event(&s);
        let mut tx = self.pool.begin().await.map_err(db)?;
        let r = sqlx::query(
            "UPDATE node_run SET status = $3, awaiting = $4, prompt = $5, wake_at = $6, budget = $7,
                                 lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
             WHERE id = $1 AND lease_owner = $2 AND status = 'running' AND cancel_requested_at IS NULL",
        )
        .bind(run_id)
        .bind(worker)
        .bind(s.status.as_str())
        .bind(&s.awaiting)
        .bind(&s.prompt)
        .bind(s.wake_at)
        .bind(budget_json(&s.budget)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if r.rows_affected() != 1 {
            return Ok(false);
        }
        push_event(&mut tx, run_id, kind, &data).await?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    async fn finish(&self, run_id: &str, worker: &str, f: Finish) -> JResult<bool> {
        if !f.status.is_terminal() {
            return Err(JournalError(format!("cannot finish a run as {}", f.status.as_str())));
        }
        let data = finish_event(f.status, f.error.as_deref(), f.stop_reason.as_deref(), f.budget.usd);
        let mut tx = self.pool.begin().await.map_err(db)?;
        let r = sqlx::query(
            "UPDATE node_run SET status = $3, output = $4, error = $5, stop_reason = $6, budget = $7,
                                 lease_owner = NULL, lease_expires_at = NULL, wake_at = NULL,
                                 updated_at = now(), finished_at = now()
             WHERE id = $1 AND lease_owner = $2 AND status = 'running'",
        )
        .bind(run_id)
        .bind(worker)
        .bind(f.status.as_str())
        .bind(&f.output)
        .bind(&f.error)
        .bind(&f.stop_reason)
        .bind(budget_json(&f.budget)?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if r.rows_affected() != 1 {
            return Ok(false);
        }
        push_event(&mut tx, run_id, event::RUN_FINISHED, &data).await?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    async fn purge_finished(&self, older_than: Duration, batch: usize) -> JResult<u64> {
        // SKIP LOCKED: several workers purging at once take different rows.
        let r = sqlx::query(
            "DELETE FROM node_run WHERE id IN (
                 SELECT id FROM node_run
                 WHERE status IN ('succeeded', 'failed', 'budget_exhausted', 'cancelled') AND finished_at IS NOT NULL
                       AND finished_at < now() - make_interval(secs => $1)
                 ORDER BY finished_at LIMIT $2 FOR UPDATE SKIP LOCKED)",
        )
        .bind(secs(older_than))
        .bind(i64::try_from(batch).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(r.rows_affected())
    }

    async fn tenant_spend(&self, tenant: &str) -> JResult<TenantSpend> {
        let (today, month): (f64, f64) = sqlx::query_as(
            "SELECT COALESCE(SUM(usd) FILTER (WHERE day = (now() AT TIME ZONE 'UTC')::date), 0)::FLOAT8,
                    COALESCE(SUM(usd), 0)::FLOAT8
             FROM node_spend
             WHERE tenant_id = $1 AND day >= date_trunc('month', now() AT TIME ZONE 'UTC')::date",
        )
        .bind(tenant)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        Ok(TenantSpend { today_usd: today, month_usd: month })
    }

    async fn event(&self, run_id: &str, name: &str) -> JResult<Option<EventRecord>> {
        let r = sqlx::query(
            "SELECT run_id, name, kind, payload, created_at FROM node_event WHERE run_id = $1 AND name = $2",
        )
        .bind(run_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        r.map(|r| {
            Ok(EventRecord {
                run_id: get(&r, "run_id")?,
                name: get(&r, "name")?,
                kind: EventKind::parse(&get::<String>(&r, "kind")?),
                payload: get(&r, "payload")?,
                created_at: get(&r, "created_at")?,
            })
        })
        .transpose()
    }

    async fn put_event(
        &self,
        tenant: &str,
        run_id: &str,
        name: &str,
        kind: EventKind,
        payload: Option<String>,
    ) -> JResult<bool> {
        let r = sqlx::query(
            "INSERT INTO node_event (run_id, name, tenant_id, kind, payload)
             SELECT id, $3, tenant_id, $4, $5 FROM node_run WHERE id = $1 AND tenant_id = $2
             ON CONFLICT (run_id, name) DO NOTHING",
        )
        .bind(run_id)
        .bind(tenant)
        .bind(name)
        .bind(kind.as_str())
        .bind(&payload)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        if r.rows_affected() == 1 {
            return Ok(true);
        }
        if self.get_run(tenant, run_id).await?.is_none() {
            return Err(JournalError(format!("run {run_id} not found")));
        }
        Ok(false)
    }

    async fn deliver_input(
        &self,
        tenant: &str,
        run_id: &str,
        step: &str,
        payload: String,
        by: Option<&str>,
        audit: Option<AuditEvent>,
    ) -> JResult<Delivered> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let woken = sqlx::query(
            "UPDATE node_run SET status = 'pending', wake_at = NULL, awaiting = NULL, prompt = NULL, updated_at = now()
             WHERE id = $1 AND tenant_id = $2 AND status = 'input_required' AND awaiting = $3",
        )
        .bind(run_id)
        .bind(tenant)
        .bind(step)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if woken.rows_affected() == 0 {
            let exists: Option<String> = sqlx::query_scalar("SELECT id FROM node_run WHERE id = $1 AND tenant_id = $2")
                .bind(run_id)
                .bind(tenant)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
            return Ok(if exists.is_some() { Delivered::NotAwaiting } else { Delivered::NotFound });
        }
        sqlx::query(
            "INSERT INTO node_event (run_id, name, tenant_id, kind, payload) VALUES ($1, $2, $3, 'input', $4)
             ON CONFLICT (run_id, name) DO NOTHING",
        )
        .bind(run_id)
        .bind(step)
        .bind(tenant)
        .bind(&payload)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        push_event(&mut tx, run_id, event::RUN_INPUT_RECEIVED, &serde_json::json!({"step": step, "by": by})).await?;
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(Delivered::Accepted)
    }

    async fn start_step(&self, run_id: &str, worker: &str, data: serde_json::Value) -> JResult<StepStart> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        // Fenced like a checkpoint; the row lock orders the event.
        let held: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
            "SELECT cancel_requested_at FROM node_run WHERE id = $1 AND lease_owner = $2 AND status = 'running'
             FOR UPDATE",
        )
        .bind(run_id)
        .bind(worker)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let out = match held {
            None => StepStart::LeaseLost,
            Some(Some(_)) => StepStart::Cancelled,
            Some(None) => {
                push_event(&mut tx, run_id, event::STEP_STARTED, &data).await?;
                StepStart::Started
            }
        };
        tx.commit().await.map_err(db)?;
        Ok(out)
    }

    async fn cancel_requested(&self, run_id: &str) -> JResult<bool> {
        let r: Option<bool> = sqlx::query_scalar("SELECT cancel_requested_at IS NOT NULL FROM node_run WHERE id = $1")
            .bind(run_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        Ok(r.unwrap_or(false))
    }

    async fn set_mast_label(&self, tenant: &str, run_id: &str, label: Option<&str>) -> JResult<bool> {
        let n = sqlx::query("UPDATE node_run SET mast_label = $3 WHERE id = $1 AND tenant_id = $2")
            .bind(run_id)
            .bind(tenant)
            .bind(label)
            .execute(&self.pool)
            .await
            .map_err(db)?
            .rows_affected();
        Ok(n > 0)
    }

    async fn cancel(&self, tenant: &str, run_id: &str, by: &str, audit: Option<AuditEvent>) -> JResult<Cancelled> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let row: Option<(String, Option<DateTime<Utc>>, Json<serde_json::Value>)> = sqlx::query_as(
            "SELECT status, cancel_requested_at, budget FROM node_run WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(run_id)
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let Some((status, requested, budget)) = row else { return Ok(Cancelled::NotFound) };
        let status = RunStatus::parse(&status).ok_or_else(|| JournalError(format!("unknown run status {status}")))?;
        let out = match status {
            s if s.is_terminal() => return Ok(Cancelled::AlreadyEnded(s)),
            RunStatus::Running if requested.is_some() => return Ok(Cancelled::Requested),
            RunStatus::Running => {
                sqlx::query(
                    "UPDATE node_run SET cancel_requested_at = now(), cancelled_by = $2, updated_at = now() WHERE id = $1",
                )
                .bind(run_id)
                .bind(by)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                push_event(&mut tx, run_id, event::RUN_CANCEL_REQUESTED, &serde_json::json!({"by": by})).await?;
                Cancelled::Requested
            }
            _ => {
                let reason = format!("cancelled by {by}");
                sqlx::query(
                    "UPDATE node_run SET status = 'cancelled', cancel_requested_at = now(), cancelled_by = $2,
                                         stop_reason = $3, wake_at = NULL, awaiting = NULL, prompt = NULL,
                                         updated_at = now(), finished_at = now()
                     WHERE id = $1",
                )
                .bind(run_id)
                .bind(by)
                .bind(&reason)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                let usd = budget.0.get("usd").and_then(serde_json::Value::as_f64).unwrap_or(0.0);
                let data = finish_event(RunStatus::Cancelled, None, Some(&reason), usd);
                push_event(&mut tx, run_id, event::RUN_FINISHED, &data).await?;
                Cancelled::Ended
            }
        };
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(out)
    }

    async fn events(&self, tenant: &str, run_id: &str, after: u64, limit: usize) -> JResult<Vec<RunEvent>> {
        let rows = sqlx::query(
            "SELECT run_id, seq, kind, data, created_at FROM node_run_event
             WHERE run_id = $1 AND tenant_id = $2 AND seq > $3 ORDER BY seq LIMIT $4",
        )
        .bind(run_id)
        .bind(tenant)
        .bind(i64_of(after))
        .bind(i64_of(limit as u64))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(RunEvent {
                    run_id: get(r, "run_id")?,
                    seq: u64_of(r, "seq")?,
                    kind: get(r, "kind")?,
                    data: get::<Json<serde_json::Value>>(r, "data")?.0,
                    created_at: get(r, "created_at")?,
                })
            })
            .collect()
    }

    async fn list_runs(&self, q: &RunQuery) -> JResult<Vec<RunRecord>> {
        let statuses: Vec<&str> = q.statuses.iter().map(|s| s.as_str()).collect();
        let (before_at, before_id) = q.before.clone().map_or((None, None), |(t, id)| (Some(t), Some(id)));
        let rows = sqlx::query(concat!(
            "SELECT ",
            run_columns!(),
            " FROM node_run
             WHERE tenant_id = $1
               AND ($2::TEXT[] IS NULL OR node = ANY($2))
               AND ($3::TEXT IS NULL OR node = $3)
               AND (cardinality($4::TEXT[]) = 0 OR status = ANY($4))
               AND ($5::TIMESTAMPTZ IS NULL OR created_at >= $5)
               AND ($6::TIMESTAMPTZ IS NULL OR created_at < $6)
               AND ($7::TIMESTAMPTZ IS NULL OR (created_at, id) < ($7, $8))
               AND ($10::INTEGER IS NULL OR version = $10)
             ORDER BY created_at DESC, id DESC LIMIT $9"
        ))
        .bind(&q.tenant)
        .bind(&q.nodes)
        .bind(&q.node)
        .bind(&statuses)
        .bind(q.created_after)
        .bind(q.created_before)
        .bind(before_at)
        .bind(before_id)
        .bind(i64_of(q.limit as u64))
        .bind(q.version.map(i32_of))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(run_row).collect()
    }

    async fn claim_audit(&self, worker: &str, ttl: Duration, limit: usize) -> JResult<Vec<AuditEvent>> {
        self.claim_audit_rows(worker, ttl, limit, None).await
    }

    async fn claim_audit_of(
        &self,
        worker: &str,
        ttl: Duration,
        limit: usize,
        actions: &[&str],
    ) -> JResult<Vec<AuditEvent>> {
        self.claim_audit_rows(worker, ttl, limit, Some(actions)).await
    }

    async fn ack_audit(&self, ids: &[String]) -> JResult<()> {
        sqlx::query("DELETE FROM node_audit WHERE id = ANY($1)").bind(ids).execute(&self.pool).await.map_err(db)?;
        Ok(())
    }
}

// ───────────────────────────── evals ─────────────────────────────

use super::evals::*;

macro_rules! eval_columns {
    () => {
        "id, tenant_id, node, version, spec_hash, suite, k, concurrency, created_by, api_key_id, invoker_key_hash, plan, \
         case_count, status, lease_owner, lease_expires_at, claims, summary, error, cancel_requested_at, cancelled_by, \
         created_at, updated_at, started_at, finished_at"
    };
}

macro_rules! trial_columns {
    () => {
        "eval_id, tenant_id, case_id, trial, run_id, status, cost_usd, latency_ms, tokens, verdict, detail, created_at, \
         finished_at"
    };
}

fn u32_of(r: &PgRow, col: &str) -> JResult<u32> {
    Ok(u32::try_from(get::<i32>(r, col)?).unwrap_or_default())
}

fn eval_row(r: &PgRow) -> JResult<EvalRecord> {
    let status: String = get(r, "status")?;
    let suite: String = get(r, "suite")?;
    Ok(EvalRecord {
        id: get(r, "id")?,
        tenant_id: get(r, "tenant_id")?,
        node: get(r, "node")?,
        version: u32_of(r, "version")?,
        spec_hash: get(r, "spec_hash")?,
        suite: Suite::parse(&suite).ok_or_else(|| JournalError(format!("unknown eval suite {suite}")))?,
        k: u32_of(r, "k")?,
        concurrency: u32_of(r, "concurrency")?,
        created_by: get(r, "created_by")?,
        api_key_id: get(r, "api_key_id")?,
        invoker_key_hash: get(r, "invoker_key_hash")?,
        plan: get(r, "plan")?,
        case_count: u32_of(r, "case_count")?,
        status: EvalStatus::parse(&status).ok_or_else(|| JournalError(format!("unknown eval status {status}")))?,
        lease_owner: get(r, "lease_owner")?,
        lease_expires_at: get(r, "lease_expires_at")?,
        claims: u32_of(r, "claims")?,
        summary: get::<Option<Json<serde_json::Value>>>(r, "summary")?.map(|j| j.0),
        error: get(r, "error")?,
        cancel_requested_at: get(r, "cancel_requested_at")?,
        cancelled_by: get(r, "cancelled_by")?,
        created_at: get(r, "created_at")?,
        updated_at: get(r, "updated_at")?,
        started_at: get(r, "started_at")?,
        finished_at: get(r, "finished_at")?,
    })
}

fn trial_row(r: &PgRow) -> JResult<TrialRecord> {
    let status: String = get(r, "status")?;
    Ok(TrialRecord {
        eval_id: get(r, "eval_id")?,
        tenant_id: get(r, "tenant_id")?,
        case_id: get(r, "case_id")?,
        trial: u32_of(r, "trial")?,
        run_id: get(r, "run_id")?,
        status: TrialStatus::parse(&status).ok_or_else(|| JournalError(format!("unknown trial status {status}")))?,
        cost_usd: get(r, "cost_usd")?,
        latency_ms: u64_of(r, "latency_ms")?,
        tokens: u64_of(r, "tokens")?,
        verdict: get::<Json<serde_json::Value>>(r, "verdict")?.0,
        detail: get(r, "detail")?,
        created_at: get(r, "created_at")?,
        finished_at: get(r, "finished_at")?,
    })
}

fn golden_row(r: &PgRow) -> JResult<GoldenSetRecord> {
    Ok(GoldenSetRecord {
        tenant_id: get(r, "tenant_id")?,
        node: get(r, "node")?,
        version: u32_of(r, "version")?,
        cases: get(r, "cases")?,
        case_count: u32_of(r, "case_count")?,
        hash: get(r, "hash")?,
        updated_at: get(r, "updated_at")?,
        updated_by: get(r, "updated_by")?,
    })
}

const GOLDEN_COLUMNS: &str = "tenant_id, node, version, cases, case_count, hash, updated_at, updated_by";

#[async_trait::async_trait]
impl EvalStore for PgJournal {
    async fn put_golden_set(&self, g: GoldenSetRecord, audit: Option<AuditEvent>) -> JResult<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query(
            "INSERT INTO node_golden_set (tenant_id, node, version, cases, case_count, hash, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (tenant_id, node, version) DO UPDATE
             SET cases = EXCLUDED.cases, case_count = EXCLUDED.case_count, hash = EXCLUDED.hash,
                 updated_by = EXCLUDED.updated_by, updated_at = clock_timestamp()",
        )
        .bind(&g.tenant_id)
        .bind(&g.node)
        .bind(i32_of(g.version))
        .bind(&g.cases)
        .bind(i32_of(g.case_count))
        .bind(&g.hash)
        .bind(&g.updated_by)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)
    }

    async fn replace_golden_set_if(
        &self,
        g: GoldenSetRecord,
        expected: Option<&str>,
        audit: Option<AuditEvent>,
    ) -> JResult<bool> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let current: Option<String> = sqlx::query_scalar(
            "SELECT hash FROM node_golden_set WHERE tenant_id = $1 AND node = $2 AND version = $3 FOR UPDATE",
        )
        .bind(&g.tenant_id)
        .bind(&g.node)
        .bind(i32_of(g.version))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        // No row yet: two writers can both see none, and the unique key lets one insert.
        let written = sqlx::query(
            "INSERT INTO node_golden_set (tenant_id, node, version, cases, case_count, hash, updated_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (tenant_id, node, version) DO UPDATE
             SET cases = EXCLUDED.cases, case_count = EXCLUDED.case_count, hash = EXCLUDED.hash,
                 updated_by = EXCLUDED.updated_by, updated_at = clock_timestamp()
             WHERE node_golden_set.hash IS NOT DISTINCT FROM $8",
        )
        .bind(&g.tenant_id)
        .bind(&g.node)
        .bind(i32_of(g.version))
        .bind(&g.cases)
        .bind(i32_of(g.case_count))
        .bind(&g.hash)
        .bind(&g.updated_by)
        .bind(expected)
        .execute(&mut *tx)
        .await
        .map_err(db)?
        .rows_affected();
        if written == 0 {
            return Ok(false);
        }
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    async fn golden_set(&self, tenant: &str, node: &str, version: u32) -> JResult<Option<GoldenSetRecord>> {
        let q =
            format!("SELECT {GOLDEN_COLUMNS} FROM node_golden_set WHERE tenant_id = $1 AND node = $2 AND version = $3");
        sqlx::query(sqlx::AssertSqlSafe(q))
            .bind(tenant)
            .bind(node)
            .bind(i32_of(version))
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .as_ref()
            .map(golden_row)
            .transpose()
    }

    async fn golden_sets(&self, tenant: &str, node: &str) -> JResult<Vec<GoldenSetRecord>> {
        let q =
            format!("SELECT {GOLDEN_COLUMNS} FROM node_golden_set WHERE tenant_id = $1 AND node = $2 ORDER BY version");
        let rows =
            sqlx::query(sqlx::AssertSqlSafe(q)).bind(tenant).bind(node).fetch_all(&self.pool).await.map_err(db)?;
        rows.iter().map(golden_row).collect()
    }

    async fn delete_golden_set(
        &self,
        tenant: &str,
        node: &str,
        version: u32,
        audit: Option<AuditEvent>,
    ) -> JResult<bool> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let r = sqlx::query("DELETE FROM node_golden_set WHERE tenant_id = $1 AND node = $2 AND version = $3")
            .bind(tenant)
            .bind(node)
            .bind(i32_of(version))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let gone = r.rows_affected() == 1;
        if gone {
            push_audit(&mut tx, audit.as_ref()).await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(gone)
    }

    async fn put_eval_policy(&self, p: EvalPolicyRecord, audit: Option<AuditEvent>) -> JResult<()> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query(
            "INSERT INTO node_eval_policy (tenant_id, node, policy, updated_by) VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, node) DO UPDATE
             SET policy = EXCLUDED.policy, updated_by = EXCLUDED.updated_by, updated_at = clock_timestamp()",
        )
        .bind(&p.tenant_id)
        .bind(&p.node)
        .bind(Json(&p.policy))
        .bind(&p.updated_by)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)
    }

    async fn eval_policy(&self, tenant: &str, node: &str) -> JResult<Option<EvalPolicyRecord>> {
        let r = sqlx::query(
            "SELECT tenant_id, node, policy, updated_at, updated_by FROM node_eval_policy
             WHERE tenant_id = $1 AND node = $2",
        )
        .bind(tenant)
        .bind(node)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        r.map(|r| {
            Ok(EvalPolicyRecord {
                tenant_id: get(&r, "tenant_id")?,
                node: get(&r, "node")?,
                policy: get::<Json<serde_json::Value>>(&r, "policy")?.0,
                updated_at: get(&r, "updated_at")?,
                updated_by: get(&r, "updated_by")?,
            })
        })
        .transpose()
    }

    async fn create_eval(&self, e: NewEval, audit: Option<AuditEvent>) -> JResult<EvalRecord> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let r = sqlx::query(concat!(
            "INSERT INTO node_eval (id, tenant_id, node, version, spec_hash, suite, k, concurrency, created_by,
                                    api_key_id, invoker_key_hash, plan, case_count, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending') RETURNING ",
            eval_columns!()
        ))
        .bind(&e.id)
        .bind(&e.tenant_id)
        .bind(&e.node)
        .bind(i32_of(e.version))
        .bind(&e.spec_hash)
        .bind(e.suite.as_str())
        .bind(i32_of(e.k))
        .bind(i32_of(e.concurrency))
        .bind(&e.created_by)
        .bind(&e.api_key_id)
        .bind(&e.invoker_key_hash)
        .bind(&e.plan)
        .bind(i32_of(e.case_count))
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let rec = eval_row(&r)?;
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(rec)
    }

    async fn get_eval(&self, tenant: &str, id: &str) -> JResult<Option<EvalRecord>> {
        sqlx::query(concat!("SELECT ", eval_columns!(), " FROM node_eval WHERE id = $1 AND tenant_id = $2"))
            .bind(id)
            .bind(tenant)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .as_ref()
            .map(eval_row)
            .transpose()
    }

    async fn list_evals(&self, q: &EvalQuery) -> JResult<Vec<EvalRecord>> {
        let statuses: Vec<&str> = q.statuses.iter().map(|s| s.as_str()).collect();
        let (before_at, before_id) = q.before.clone().map_or((None, None), |(t, id)| (Some(t), Some(id)));
        let rows = sqlx::query(concat!(
            "SELECT ",
            eval_columns!(),
            " FROM node_eval
             WHERE tenant_id = $1
               AND ($2::TEXT IS NULL OR node = $2)
               AND ($3::INTEGER IS NULL OR version = $3)
               AND ($4::TEXT IS NULL OR suite = $4)
               AND (cardinality($5::TEXT[]) = 0 OR status = ANY($5))
               AND ($6::TIMESTAMPTZ IS NULL OR (created_at, id) < ($6, $7))
             ORDER BY created_at DESC, id DESC LIMIT $8"
        ))
        .bind(&q.tenant)
        .bind(&q.node)
        .bind(q.version.map(i32_of))
        .bind(q.suite.map(Suite::as_str))
        .bind(&statuses)
        .bind(before_at)
        .bind(before_id)
        .bind(i64_of(q.limit as u64))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(eval_row).collect()
    }

    async fn claim_eval(&self, worker: &str, ttl: Duration) -> JResult<Option<EvalRecord>> {
        sqlx::query(concat!(
            "UPDATE node_eval SET status = 'running', lease_owner = $1,
                                  lease_expires_at = now() + make_interval(secs => $2), claims = claims + 1,
                                  started_at = COALESCE(started_at, now()), updated_at = now()
             WHERE id = (SELECT id FROM node_eval
                         WHERE status = 'pending' OR (status = 'running' AND (lease_expires_at IS NULL OR lease_expires_at < now()))
                         ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
             RETURNING ",
            eval_columns!()
        ))
        .bind(worker)
        .bind(secs(ttl))
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .as_ref()
        .map(eval_row)
        .transpose()
    }

    async fn heartbeat_eval(&self, id: &str, worker: &str, ttl: Duration) -> JResult<bool> {
        let r = sqlx::query(
            "UPDATE node_eval SET lease_expires_at = now() + make_interval(secs => $3)
             WHERE id = $1 AND lease_owner = $2 AND status = 'running'",
        )
        .bind(id)
        .bind(worker)
        .bind(secs(ttl))
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(r.rows_affected() == 1)
    }

    async fn cancel_eval(&self, tenant: &str, id: &str, by: &str, audit: Option<AuditEvent>) -> JResult<EvalCancel> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT status, cancel_requested_at FROM node_eval WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(id)
        .bind(tenant)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let Some((status, requested)) = row else { return Ok(EvalCancel::NotFound) };
        let status = EvalStatus::parse(&status).ok_or_else(|| JournalError(format!("unknown eval status {status}")))?;
        let out = match status {
            s if s.is_terminal() => return Ok(EvalCancel::AlreadyEnded(s)),
            EvalStatus::Running if requested.is_some() => return Ok(EvalCancel::Requested),
            EvalStatus::Running => {
                sqlx::query(
                    "UPDATE node_eval SET cancel_requested_at = now(), cancelled_by = $2, updated_at = now() WHERE id = $1",
                )
                .bind(id)
                .bind(by)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                EvalCancel::Requested
            }
            _ => {
                sqlx::query(
                    "UPDATE node_eval SET status = 'cancelled', cancel_requested_at = now(), cancelled_by = $2,
                                          updated_at = now(), finished_at = now()
                     WHERE id = $1",
                )
                .bind(id)
                .bind(by)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                EvalCancel::Ended
            }
        };
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(out)
    }

    async fn finish_eval(&self, id: &str, worker: &str, f: EvalFinish, audit: Option<AuditEvent>) -> JResult<bool> {
        bad_finish(&f)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let r = sqlx::query(
            "UPDATE node_eval SET status = $3, summary = $4, error = $5, lease_owner = NULL, lease_expires_at = NULL,
                                  updated_at = now(), finished_at = now()
             WHERE id = $1 AND lease_owner = $2 AND status = 'running'",
        )
        .bind(id)
        .bind(worker)
        .bind(f.status.as_str())
        .bind(f.summary.as_ref().map(Json))
        .bind(&f.error)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if r.rows_affected() != 1 {
            return Ok(false);
        }
        push_audit(&mut tx, audit.as_ref()).await?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    async fn put_trial(&self, worker: &str, t: TrialRecord) -> JResult<TrialWrite> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        // Fence: lock the eval row while we hold its lease.
        let held: Option<String> = sqlx::query_scalar(
            "SELECT id FROM node_eval WHERE id = $1 AND lease_owner = $2 AND status = 'running' FOR UPDATE",
        )
        .bind(&t.eval_id)
        .bind(worker)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if held.is_none() {
            return Ok(TrialWrite::LeaseLost);
        }
        let written = sqlx::query(
            "INSERT INTO node_eval_trial (eval_id, case_id, trial, tenant_id, run_id, status, cost_usd, latency_ms, tokens,
                                          verdict, detail, finished_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CASE WHEN $6 = 'running' THEN NULL ELSE now() END)
             ON CONFLICT (eval_id, case_id, trial) DO UPDATE
             SET run_id = EXCLUDED.run_id, status = EXCLUDED.status, cost_usd = EXCLUDED.cost_usd,
                 latency_ms = EXCLUDED.latency_ms, tokens = EXCLUDED.tokens, verdict = EXCLUDED.verdict,
                 detail = EXCLUDED.detail, finished_at = EXCLUDED.finished_at
             WHERE node_eval_trial.status = 'running'",
        )
        .bind(&t.eval_id)
        .bind(&t.case_id)
        .bind(i32_of(t.trial))
        .bind(&t.tenant_id)
        .bind(&t.run_id)
        .bind(t.status.as_str())
        .bind(t.cost_usd)
        .bind(i64_of(t.latency_ms))
        .bind(i64_of(t.tokens))
        .bind(Json(&t.verdict))
        .bind(&t.detail)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        let out = if written.rows_affected() == 1 {
            TrialWrite::Written
        } else {
            let r = sqlx::query(concat!(
                "SELECT ",
                trial_columns!(),
                " FROM node_eval_trial WHERE eval_id = $1 AND case_id = $2 AND trial = $3"
            ))
            .bind(&t.eval_id)
            .bind(&t.case_id)
            .bind(i32_of(t.trial))
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            TrialWrite::Existing(Box::new(trial_row(&r)?))
        };
        tx.commit().await.map_err(db)?;
        Ok(out)
    }

    async fn trials(&self, eval_id: &str) -> JResult<Vec<TrialRecord>> {
        let rows = sqlx::query(concat!(
            "SELECT ",
            trial_columns!(),
            " FROM node_eval_trial WHERE eval_id = $1 ORDER BY case_id COLLATE \"C\", trial"
        ))
        .bind(eval_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(trial_row).collect()
    }

    async fn purge_eval_content(&self, older_than: Duration, batch: usize) -> JResult<u64> {
        let limit = i64::try_from(batch).unwrap_or(i64::MAX);
        // SKIP LOCKED: several workers purging at once take different rows.
        let trials = sqlx::query(
            "UPDATE node_eval_trial SET detail = NULL WHERE (eval_id, case_id, trial) IN (
                 SELECT eval_id, case_id, trial FROM node_eval_trial
                 WHERE detail IS NOT NULL AND finished_at IS NOT NULL
                       AND finished_at < now() - make_interval(secs => $1)
                 ORDER BY finished_at LIMIT $2 FOR UPDATE SKIP LOCKED)",
        )
        .bind(secs(older_than))
        .bind(limit)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        let evals = sqlx::query(
            "UPDATE node_eval SET plan = '' WHERE id IN (
                 SELECT id FROM node_eval
                 WHERE status IN ('succeeded', 'failed', 'cancelled') AND plan <> '' AND finished_at IS NOT NULL
                       AND finished_at < now() - make_interval(secs => $1)
                 ORDER BY finished_at LIMIT $2 FOR UPDATE SKIP LOCKED)",
        )
        .bind(secs(older_than))
        .bind(limit)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(trials.rows_affected() + evals.rows_affected())
    }
}
