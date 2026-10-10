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
];

macro_rules! run_columns {
    () => {
        "id, tenant_id, node, version, spec_hash, invoker, invoker_key_hash, input, specs, output, status, wake_at, awaiting, \
         prompt, budget, lease_owner, lease_expires_at, claims, error, stop_reason, idempotency_key, \
         idempotency_fingerprint, created_at, updated_at, started_at, finished_at"
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
    })
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
        tokens: u64::try_from(get::<i64>(r, "tokens")?).unwrap_or_default(),
        usd: get(r, "usd")?,
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
        let inserted = sqlx::query(concat!(
            "INSERT INTO node_run (id, tenant_id, node, version, spec_hash, invoker, invoker_key_hash, input, status,
                                   budget, idempotency_key, idempotency_fingerprint, specs)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11, $12)
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
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        if let Some(r) = inserted {
            return Ok(Created::New(run_row(&r)?));
        }
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
        let rows = sqlx::query(
            "SELECT run_id, tenant_id, step_id, attempt, vertex, kind, input_hash, status, result, tokens, usd,
                    started_at, finished_at
             FROM node_step WHERE run_id = $1 ORDER BY seq",
        )
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
                                    usd, started_at, finished_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        let out = if inserted.rows_affected() == 1 {
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
            let r = sqlx::query(
                "SELECT run_id, tenant_id, step_id, attempt, vertex, kind, input_hash, status, result, tokens, usd,
                        started_at, finished_at
                 FROM node_step WHERE run_id = $1 AND step_id = $2",
            )
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
        let r = sqlx::query(
            "UPDATE node_run SET status = $3, awaiting = $4, prompt = $5, wake_at = $6, budget = $7,
                                 lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
             WHERE id = $1 AND lease_owner = $2 AND status = 'running'",
        )
        .bind(run_id)
        .bind(worker)
        .bind(s.status.as_str())
        .bind(&s.awaiting)
        .bind(&s.prompt)
        .bind(s.wake_at)
        .bind(budget_json(&s.budget)?)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(r.rows_affected() == 1)
    }

    async fn finish(&self, run_id: &str, worker: &str, f: Finish) -> JResult<bool> {
        if !f.status.is_terminal() {
            return Err(JournalError(format!("cannot finish a run as {}", f.status.as_str())));
        }
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
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(r.rows_affected() == 1)
    }

    async fn purge_finished(&self, older_than: Duration, batch: usize) -> JResult<u64> {
        // SKIP LOCKED: several workers purging at once take different rows.
        let r = sqlx::query(
            "DELETE FROM node_run WHERE id IN (
                 SELECT id FROM node_run
                 WHERE status IN ('succeeded', 'failed', 'budget_exhausted') AND finished_at IS NOT NULL
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
                kind: if get::<String>(&r, "kind")? == "timer" { EventKind::Timer } else { EventKind::Input },
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

    async fn deliver_input(&self, tenant: &str, run_id: &str, step: &str, payload: String) -> JResult<Delivered> {
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
        tx.commit().await.map_err(db)?;
        Ok(Delivered::Accepted)
    }
}
