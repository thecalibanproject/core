//! Node runs in the console (P3 M5): the run list of a tenant, a run's detail, the inbox of runs
//! waiting for a human (questions and approvals of tainted writes), and answering them as the
//! signed-in user.
//!
//! The control plane reads the node journal: the database's in Postgres mode (shared with the
//! workers), or a standalone process's in-memory journal. A control plane without either (no
//! database, not standalone) answers `503 runs_unavailable`.
//!
//! **Who sees what** (see `auth::rbac`):
//! - `runs.read` (owner, admin, auditor, tenant_admin, developer, viewer): the run list, the inbox,
//!   and a run's metadata: status, steps (vertex, kind, status, timings, tokens, cost, taint
//!   labels), budget, usage, errors and stop reasons.
//! - `runs.data` (owner, admin, tenant_admin, developer): also run content, which is the tenant's
//!   data and can hold personal data: the input, the output, step outputs, the awaited question.
//!   Auditors and viewers audit what happened, not what was said.
//! - `runs.answer` (owner, admin, tenant_admin): answer a question, approve or deny a tainted
//!   write, as the signed-in user. Kept apart from building nodes, like approving tools.
//!
//! An answer is recorded with the user as its author (journaled with the answer, and in the audit
//! log as `node.run.answer`, `node.write.approve` or `node.write.deny`, once).

use crate::auth::Principal;
use crate::auth::rbac::Perm;
use crate::{ApiError, ApiResult, Cp, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use caliban_config::Dek;
use caliban_nodes::executor::{RunSummary, RunUsage, StepView};
use caliban_nodes::journal::{Delivered, Journal, RunRecord, RunStatus, encode_cursor, run_query};
use caliban_nodes::seal::{DekSealer, Sealer};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

fn journal(cp: &Cp) -> ApiResult<Arc<dyn Journal>> {
    cp.journal().ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "node runs are read from the node journal: this control plane has none (set CALIBAN_DATABASE_URL, \
             shared with the workers)"
                .into(),
        )
    })
}

/// Opens run content with the tenant's data key (unwrapped with the control plane's keyring).
fn sealer(cp: &Cp) -> ApiResult<impl Sealer> {
    let keyring = cp.keyring.clone().ok_or_else(|| bad("run content cannot be opened: CALIBAN_KEK is not set"))?;
    let state = cp.store.state();
    Ok(DekSealer::new(move |tenant: &str| -> Result<Arc<Dek>, String> {
        let d = state.deks.get(tenant).ok_or_else(|| format!("tenant {tenant} has no data key"))?;
        keyring.unwrap_dek(tenant, &d.wrapped).map(Arc::new)
    }))
}

fn journal_error(e: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %e, "node journal error");
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "node journal error".into())
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListQuery {
    node: Option<String>,
    /// Comma-separated statuses.
    status: Option<String>,
    created_after: Option<DateTime<Utc>>,
    created_before: Option<DateTime<Utc>>,
    limit: Option<usize>,
    cursor: Option<String>,
}

/// `GET /api/v1/tenants/{t}/runs`: the tenant's runs, newest first (`runs.read`).
pub(crate) async fn list(
    State(cp): State<Cp>,
    Path(tenant_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let query = run_query(
        &tenant_id,
        None,
        q.node,
        q.status.as_deref(),
        (q.created_after, q.created_before),
        q.limit,
        q.cursor.as_deref(),
    )
    .map_err(bad)?;
    let page = j.list_runs(&query).await.map_err(journal_error)?;
    let next = (page.len() == query.limit).then(|| page.last().map(|r| encode_cursor(r.created_at, &r.id))).flatten();
    let data: Vec<RunSummary> = page.iter().map(RunSummary::of).collect();
    Ok(Json(json!({"object": "list", "data": data, "next_cursor": next})))
}

/// The run as the console shows it; content only with `content`.
async fn detail(cp: &Cp, j: &Arc<dyn Journal>, r: &RunRecord, content: bool) -> ApiResult<Value> {
    let steps = j.steps(&r.id).await.map_err(journal_error)?;
    let mut v = json!({
        "id": r.id,
        "object": "node.run",
        "node": r.node,
        "version": r.version,
        "hash": r.spec_hash,
        "status": r.status,
        "invoker": r.invoker,
        "origin": r.origin,
        "error": r.error,
        "stop_reason": r.stop_reason,
        "partial": r.status == RunStatus::BudgetExhausted,
        "awaiting": r.awaiting.as_ref().map(|s| json!({"step": s, "kind": kind_of(s)})),
        "cancel_requested": r.cancel_requested_at.is_some() && !r.status.is_terminal(),
        "cancelled_by": r.cancelled_by,
        "budget": r.budget,
        "cost_usd": r.budget.usd,
        "usage": RunUsage::of(&steps),
        "claims": r.claims,
        "last_event": r.last_event,
        "created_at": r.created_at,
        "started_at": r.started_at,
        "finished_at": r.finished_at,
        "content_visible": content,
        "steps": steps.iter().map(StepView::of).collect::<Vec<_>>(),
    });
    if content {
        let s = sealer(cp)?;
        let open = |sealed: &Option<String>| -> Value {
            sealed
                .as_deref()
                .and_then(|x| s.open(&r.tenant_id, &r.id, x).ok())
                .map_or(Value::Null, |t| serde_json::from_str(&t).unwrap_or(Value::String(t)))
        };
        v["input"] = open(&Some(r.input.clone()));
        v["output"] = open(&r.output);
        if let Some(a) = v.get_mut("awaiting").filter(|a| a.is_object()) {
            a["question"] = open(&r.prompt);
        }
        for (view, rec) in v["steps"].as_array_mut().into_iter().flatten().zip(&steps) {
            view["output"] = open(&rec.result).get("output").cloned().unwrap_or(Value::Null);
        }
    }
    Ok(v)
}

/// `question` (a human step) or `approval` (a tainted write waiting for a decision).
fn kind_of(step: &str) -> &'static str {
    if step.ends_with("@approve") { "approval" } else { "question" }
}

/// `GET /api/v1/tenants/{t}/runs/{id}` (`runs.read`; content with `runs.data`).
pub(crate) async fn get(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let r = j.get_run(&tenant_id, &id).await.map_err(journal_error)?.ok_or_else(|| not_found("run"))?;
    let content = p.allows(Perm::RunsData, Some(&tenant_id));
    Ok(Json(detail(&cp, &j, &r, content).await?))
}

/// `GET /api/v1/tenants/{t}/inbox`: runs waiting for a human, oldest wait first (`runs.read`; the
/// question with `runs.data`).
pub(crate) async fn inbox(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let q = run_query(&tenant_id, None, None, Some("input_required"), (None, None), Some(200), None).map_err(bad)?;
    let mut waiting = j.list_runs(&q).await.map_err(journal_error)?;
    waiting.sort_by_key(|r| r.updated_at);
    let content = p.allows(Perm::RunsData, Some(&tenant_id));
    let s = if content { Some(sealer(&cp)?) } else { None };
    let items: Vec<Value> = waiting
        .iter()
        .map(|r| {
            let step = r.awaiting.clone().unwrap_or_default();
            let question =
                s.as_ref().and_then(|s| r.prompt.as_deref().and_then(|x| s.open(&r.tenant_id, &r.id, x).ok()));
            json!({
                "run_id": r.id,
                "node": r.node,
                "version": r.version,
                "step": step,
                "kind": kind_of(&step),
                "question": question,
                "invoker": r.invoker,
                "waiting_since": r.updated_at,
                "expires_at": r.wake_at,
            })
        })
        .collect();
    Ok(Json(json!({"object": "list", "data": items, "content_visible": content})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnswerBody {
    /// The answer; for an approval `{"approve": true}` or `{"approve": false}`.
    answer: Value,
    /// The step answered (default: the one the run waits for).
    step: Option<String>,
}

/// `POST /api/v1/tenants/{t}/runs/{id}/input`: answers a question, or approves or denies a tainted
/// write, as the signed-in user (`runs.answer`). Audited at once in the hash chain.
pub(crate) async fn answer(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, id)): Path<(String, String)>,
    Json(body): Json<AnswerBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let s = sealer(&cp)?;
    match caliban_nodes::executor::deliver(&j, &s, &tenant_id, &id, body.step.as_deref(), &body.answer, Some(&p.actor))
        .await
        .map_err(journal_error)?
    {
        Delivered::Accepted => {}
        Delivered::NotAwaiting => {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "the run is not waiting for input (or not for this step)".into(),
            ));
        }
        Delivered::NotFound => return Err(not_found("run")),
    }
    // Recorded in the audit chain now, as a worker's shipper would (it would record nothing more:
    // the event id is the same), with any other entry waiting in the outbox.
    let pending =
        j.claim_audit("control-plane", std::time::Duration::from_secs(60), 1000).await.map_err(journal_error)?;
    let ids: Vec<String> = pending.iter().map(|e| e.id.clone()).collect();
    cp.store.ingest_audit(pending).await?;
    j.ack_audit(&ids).await.map_err(journal_error)?;
    let r = j.get_run(&tenant_id, &id).await.map_err(journal_error)?.ok_or_else(|| not_found("run"))?;
    let content = p.allows(Perm::RunsData, Some(&tenant_id));
    Ok((StatusCode::ACCEPTED, Json(detail(&cp, &j, &r, content).await?)))
}
