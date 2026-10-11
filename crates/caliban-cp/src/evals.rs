//! Node evals on the admin API (P3 exit criteria): golden sets per node version, the node's
//! promotion bar, eval runs (golden sets and the injection suite) and their results, and the
//! promotion gate. See docs/evals.md and `caliban_nodes::eval`.
//!
//! Everything lives next to the node journal (shared with the workers): a control plane without
//! one answers `503`, like the console's run endpoints. Golden sets are tenant content, sealed
//! under the tenant's data key; reading their cases, and what the scorers said about outputs,
//! needs `runs.data` like run content. Every write is audited in the hash chain: the journal
//! writes the event in the transaction of the change, and the control plane records it at once.
//!
//! | Permission | Endpoints |
//! |---|---|
//! | `nodes.read` | golden-set metadata, the promotion bar, evals and their metrics, the gate |
//! | `nodes.write` | create, replace or delete a golden set |
//! | `nodes.publish` | set the promotion bar (it decides what may be promoted) |
//! | `nodes.run` | start and cancel evals (they run the node, as an API key the caller names) |

use crate::auth::Principal;
use crate::auth::rbac::Perm;
use crate::nodes::NodeError;
use crate::runs::{drain_audit, journal, journal_error, sealer};
use crate::store::audit::now_micros;
use crate::store::{ApiKeyRecord, EVAL_KEY_PURPOSE, Mutation, NodeRecord, NodeState, State, StoreError, new_id};
use crate::{ApiError, ApiResult, Cp, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, Query, State as AxState};
use axum::http::StatusCode;
use caliban_nodes::NodeSpec;
use caliban_nodes::eval::{self, EvalPolicy, GoldenCase, ManifestFindings, Plan};
use caliban_nodes::journal::evals::{
    EvalCancel, EvalPolicyRecord, EvalQuery, EvalRecord, EvalStatus, GoldenSetRecord, NewEval, Suite, golden_context,
};
use caliban_nodes::journal::{AuditEvent, Journal, decode_cursor, encode_cursor};
use caliban_nodes::publish::Problem;
use caliban_nodes::seal::Sealer;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use zeroize::Zeroizing;

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

fn version_of(st: &State, tenant: &str, name: &str, version: u32) -> ApiResult<NodeRecord> {
    st.node_version(tenant, name, version).cloned().ok_or_else(|| not_found("node version"))
}

fn spec_of(n: &NodeRecord) -> ApiResult<NodeSpec> {
    serde_json::from_value(n.spec.clone()).map_err(|e| unprocessable(format!("{}@v{}: {e}", n.name, n.version)))
}

fn audit(tenant: &str, p: &Principal, id: String, action: &str, target: &str, detail: Value) -> AuditEvent {
    AuditEvent {
        id,
        tenant_id: tenant.to_owned(),
        actor: p.actor.clone(),
        action: action.into(),
        target: Some(target.to_owned()),
        detail,
        at: Utc::now(),
    }
}

/// A stable id for an audit event the control plane writes once.
fn once(what: &str) -> String {
    format!("cp/{what}/{}", uuid::Uuid::now_v7().simple())
}

/// Seals with the tenant's data key, creating it on first use (like publishing).
async fn sealer_for(cp: &Cp, p: &Principal, tenant: &str) -> ApiResult<impl Sealer + use<>> {
    let keyring = cp.keyring("golden sets and evals")?;
    crate::keys::tenant_dek(&cp.store, keyring, tenant, &p.actor).await?;
    sealer(cp)
}

// ───────────────────────────── golden sets ─────────────────────────────

fn golden_view(g: &GoldenSetRecord, cases: Option<Vec<GoldenCase>>) -> Value {
    let mut v = json!({
        "object": "node.golden_set",
        "node": g.node,
        "version": g.version,
        "hash": g.hash,
        "case_count": g.case_count,
        "updated_at": g.updated_at,
        "updated_by": g.updated_by,
        "content_visible": cases.is_some(),
    });
    if let Some(c) = cases {
        v["cases"] = json!(c);
    }
    v
}

fn open_cases(s: &impl Sealer, g: &GoldenSetRecord) -> ApiResult<Vec<GoldenCase>> {
    let text = s
        .open(&g.tenant_id, &golden_context(&g.node, g.version), &g.cases)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("the golden set cannot be opened: {e}")))?;
    serde_json::from_str(&text).map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("golden set: {e}")))
}

/// `GET .../nodes/{name}/versions/{v}/golden-set` (`nodes.read`; the cases with `runs.data`).
pub(crate) async fn get_golden(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name, version)): Path<(String, String, u32)>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let g = j
        .golden_set(&tenant_id, &name, version)
        .await
        .map_err(journal_error)?
        .ok_or_else(|| not_found("golden set"))?;
    let cases = if p.allows(Perm::RunsData, Some(&tenant_id)) { Some(open_cases(&sealer(&cp)?, &g)?) } else { None };
    Ok(Json(golden_view(&g, cases)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GoldenBody {
    cases: Vec<GoldenCase>,
}

/// `PUT .../nodes/{name}/versions/{v}/golden-set` (`nodes.write`): creates or replaces the golden
/// set of a version (any state but deleted), its inputs checked against the version's input
/// schema. Audited as `node.golden_set.update` (counts and hashes, never cases).
pub(crate) async fn put_golden(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name, version)): Path<(String, String, u32)>,
    Json(body): Json<GoldenBody>,
) -> Result<Json<Value>, NodeError> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let n = version_of(&cp.store.state(), &tenant_id, &name, version)?;
    let spec = spec_of(&n)?;
    if let Err(problems) = eval::validate_cases(&body.cases, &spec) {
        let list = problems.iter().map(|m| Problem::new("golden_set", m.clone(), None)).collect();
        return Err(NodeError::Problems(format!("invalid golden set: {}", problems.join("; ")), list));
    }
    let s = sealer_for(&cp, &p, &tenant_id).await?;
    let text = serde_json::to_string(&body.cases).map_err(|e| bad(e.to_string()))?;
    let sealed = s.seal(&tenant_id, &golden_context(&name, version), &text).map_err(bad)?;
    let hash = eval::golden_hash(&body.cases);
    let previous = j.golden_set(&tenant_id, &name, version).await.map_err(journal_error)?;
    let rec = GoldenSetRecord {
        tenant_id: tenant_id.clone(),
        node: name.clone(),
        version,
        cases: sealed,
        case_count: body.cases.len() as u32,
        hash: hash.clone(),
        updated_at: Utc::now(),
        updated_by: p.actor.clone(),
    };
    let detail = json!({"node": name, "version": version, "cases": body.cases.len(), "hash": hash,
                        "previous_hash": previous.map(|g| g.hash)});
    let a = audit(&tenant_id, &p, once("golden_set"), "node.golden_set.update", &format!("{name}@v{version}"), detail);
    j.put_golden_set(rec, Some(a)).await.map_err(journal_error)?;
    drain_audit(&cp, &j).await?;
    let g = j
        .golden_set(&tenant_id, &name, version)
        .await
        .map_err(journal_error)?
        .ok_or_else(|| not_found("golden set"))?;
    Ok(Json(golden_view(&g, Some(body.cases))))
}

/// `DELETE .../nodes/{name}/versions/{v}/golden-set` (`nodes.write`), audited.
pub(crate) async fn delete_golden(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name, version)): Path<(String, String, u32)>,
) -> ApiResult<StatusCode> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let detail = json!({"node": name, "version": version});
    let a = audit(&tenant_id, &p, once("golden_set"), "node.golden_set.delete", &format!("{name}@v{version}"), detail);
    if !j.delete_golden_set(&tenant_id, &name, version, Some(a)).await.map_err(journal_error)? {
        return Err(not_found("golden set"));
    }
    drain_audit(&cp, &j).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ───────────────────────────── the promotion bar ─────────────────────────────

async fn policy_of(
    j: &Arc<dyn Journal>,
    tenant: &str,
    name: &str,
) -> ApiResult<(EvalPolicy, Option<EvalPolicyRecord>)> {
    let rec = j.eval_policy(tenant, name).await.map_err(journal_error)?;
    let policy = match &rec {
        Some(r) => serde_json::from_value(r.policy.clone()).map_err(|e| bad(format!("stored promotion bar: {e}")))?,
        None => EvalPolicy::default(),
    };
    Ok((policy, rec))
}

fn policy_view(name: &str, policy: &EvalPolicy, rec: Option<&EvalPolicyRecord>) -> Value {
    json!({
        "object": "node.eval_policy",
        "node": name,
        "policy": policy,
        "injection_bar": policy.injection_bar(),
        "updated_at": rec.map(|r| r.updated_at),
        "updated_by": rec.map(|r| &r.updated_by),
    })
}

/// `GET .../nodes/{name}/eval-policy` (`nodes.read`): the bar and the injection bar in effect.
pub(crate) async fn get_policy(
    AxState(cp): AxState<Cp>,
    Path((tenant_id, name)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let (policy, rec) = policy_of(&j, &tenant_id, &name).await?;
    Ok(Json(policy_view(&name, &policy, rec.as_ref())))
}

/// `PUT .../nodes/{name}/eval-policy` (`nodes.publish`): sets the bar, audited with the old and
/// new values (`node.eval_policy.update`).
pub(crate) async fn put_policy(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name)): Path<(String, String)>,
    Json(policy): Json<EvalPolicy>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    if !caliban_nodes::valid_node_name(&name) {
        return Err(unprocessable(format!("'{name}' is not a node name")));
    }
    policy.validate().map_err(unprocessable)?;
    let j = journal(&cp)?;
    let (old, _) = policy_of(&j, &tenant_id, &name).await?;
    let rec = EvalPolicyRecord {
        tenant_id: tenant_id.clone(),
        node: name.clone(),
        policy: json!(policy),
        updated_at: Utc::now(),
        updated_by: p.actor.clone(),
    };
    let detail = json!({"node": name, "from": old, "to": policy});
    let a = audit(&tenant_id, &p, once("eval_policy"), "node.eval_policy.update", &name, detail);
    j.put_eval_policy(rec, Some(a)).await.map_err(journal_error)?;
    drain_audit(&cp, &j).await?;
    let (policy, rec) = policy_of(&j, &tenant_id, &name).await?;
    Ok(Json(policy_view(&name, &policy, rec.as_ref())))
}

// ───────────────────────────── the gate ─────────────────────────────

/// The newest finished eval of each suite for a version.
async fn latest(
    j: &Arc<dyn Journal>,
    tenant: &str,
    name: &str,
    version: u32,
    suite: Suite,
) -> ApiResult<Option<EvalRecord>> {
    let q = EvalQuery {
        tenant: tenant.to_owned(),
        node: Some(name.to_owned()),
        version: Some(version),
        suite: Some(suite),
        statuses: vec![EvalStatus::Succeeded],
        before: None,
        limit: 1,
    };
    Ok(j.list_evals(&q).await.map_err(journal_error)?.into_iter().next())
}

/// Whether promoting `n` is allowed: `Ok` with the evidence for the audit log (`None` when no gate
/// applies), else every reason, as `eval_gate` problems. Every `node://` subnode version it pins
/// (and theirs, down the tree) must pass its own gate too (P3 decision 12): being published is not
/// enough, or a version could reach an unevaluated write through a child.
pub(crate) async fn gate(cp: &Cp, n: &NodeRecord) -> Result<Option<Value>, NodeError> {
    let mut problems = Vec::new();
    let mut subnodes = serde_json::Map::new();
    let mut seen = std::collections::HashSet::new();
    let mut todo: Vec<(String, u32, String)> =
        spec_of(n)?.node_refs().into_iter().map(|(c, v)| (c, v, format!("{}@v{}", n.name, n.version))).collect();
    while let Some((child, v, via)) = todo.pop() {
        if !seen.insert((child.clone(), v)) || (child == n.name && v == n.version) {
            continue;
        }
        let c = version_of(&cp.store.state(), &n.tenant_id, &child, v)?;
        todo.extend(spec_of(&c)?.node_refs().into_iter().map(|(cc, cv)| (cc, cv, format!("{child}@v{v}"))));
        match own_gate(cp, &c).await {
            Ok(e) => {
                subnodes.insert(format!("{child}@v{v}"), e.unwrap_or(Value::Null));
            }
            Err(NodeError::Problems(_, ps)) => problems.extend(ps.into_iter().map(|p| {
                let m = format!(
                    "node://{child}@v{v} (a subnode {via} pins) has not passed its own promotion gate: {}",
                    p.message
                );
                (m, Some(format!("node://{child}@v{v}")))
            })),
            Err(e) => return Err(e),
        }
    }
    let own = own_gate(cp, n).await;
    let (own_evidence, own_problems) = match own {
        Ok(e) => (e, vec![]),
        Err(NodeError::Problems(_, ps)) => (None, ps.into_iter().map(|p| p.message).collect()),
        Err(e) => return Err(e),
    };
    let problems: Vec<(String, Option<String>)> = own_problems.into_iter().map(|m| (m, None)).chain(problems).collect();
    if !problems.is_empty() {
        let text: Vec<&str> = problems.iter().map(|(m, _)| m.as_str()).collect();
        let mut msg = format!("{}@v{} cannot be promoted: {}", n.name, n.version, text.join("; "));
        if n.state == NodeState::Draft {
            msg.push_str(". Publish it with {\"promote\": false}, run its evals, then promote it");
        }
        let list = problems.into_iter().map(|(m, path)| Problem::new("eval_gate", m, path)).collect();
        return Err(NodeError::Problems(msg, list));
    }
    if subnodes.is_empty() {
        return Ok(own_evidence);
    }
    let mut e = own_evidence.unwrap_or_else(|| json!({}));
    e["subnodes"] = Value::Object(subnodes);
    Ok(Some(e))
}

/// The gate of one version on its own evals (not its subnodes').
async fn own_gate(cp: &Cp, n: &NodeRecord) -> Result<Option<Value>, NodeError> {
    let spec = spec_of(n)?;
    let Some(j) = cp.journal() else {
        if eval::has_write_tools(&spec) {
            return Err(NodeError::Api(ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "a version with write tools needs an injection eval before it is promoted, and evals live in the node \
                 journal: this control plane has none (set CALIBAN_DATABASE_URL, shared with the workers)"
                    .into(),
            )));
        }
        return Ok(None);
    };
    let (policy, _) = policy_of(&j, &n.tenant_id, &n.name).await?;
    if policy.golden.is_none() && !eval::has_write_tools(&spec) {
        return Ok(None);
    }
    let golden = latest(&j, &n.tenant_id, &n.name, n.version, Suite::Golden).await?;
    let injection = latest(&j, &n.tenant_id, &n.name, n.version, Suite::Injection).await?;
    match eval::gate(&policy, &spec, &n.hash, golden.as_ref(), injection.as_ref()) {
        Ok(evidence) => Ok(Some(evidence)),
        Err(problems) => {
            let mut msg = format!("{}@v{} cannot be promoted: {}", n.name, n.version, problems.join("; "));
            if n.state == NodeState::Draft {
                msg.push_str(". Publish it with {\"promote\": false}, run its evals, then promote it");
            }
            let list = problems.into_iter().map(|m| Problem::new("eval_gate", m, None)).collect();
            Err(NodeError::Problems(msg, list))
        }
    }
}

/// `GET .../nodes/{name}/versions/{v}/gate` (`nodes.read`): what promoting the version would say.
pub(crate) async fn get_gate(
    AxState(cp): AxState<Cp>,
    Path((tenant_id, name, version)): Path<(String, String, u32)>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let n = version_of(&cp.store.state(), &tenant_id, &name, version)?;
    let write = eval::has_write_tools(&spec_of(&n)?);
    let (allowed, evidence, problems) = match gate(&cp, &n).await {
        Ok(e) => (true, e, vec![]),
        Err(NodeError::Problems(_, p)) => (false, None, p),
        Err(NodeError::Api(e)) => return Err(e),
    };
    Ok(Json(json!({"node": name, "version": version, "has_write_tools": write, "allowed": allowed,
                   "evidence": evidence, "problems": problems})))
}

// ───────────────────────────── eval runs ─────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartBody {
    /// `golden` or `injection`.
    suite: String,
    /// A tenant API key the eval's runs and judge calls are made, limited and metered as. Absent
    /// (the default): the tenant's eval key, which the control plane creates on first use.
    api_key_id: Option<String>,
    k: Option<u32>,
    concurrency: Option<u32>,
    /// Golden: only these cases.
    cases: Option<Vec<String>>,
    /// Golden: the default judge model (else `caliban/auto`).
    judge_model: Option<String>,
    /// Injection: the run input (default: the input of `input_case`, else of the golden set's
    /// first case).
    input: Option<Value>,
    input_case: Option<String>,
}

/// Every MCP tool of a version and of the published versions it reaches, with the injection
/// scan's findings on its approved manifest.
fn manifests(st: &State, tenant: &str, spec: &NodeSpec) -> Vec<ManifestFindings> {
    let mut specs = vec![spec.clone()];
    let mut seen: Vec<(String, u32)> = Vec::new();
    let mut i = 0;
    while i < specs.len() {
        for (name, v) in specs[i].node_refs() {
            if !seen.contains(&(name.clone(), v)) {
                seen.push((name.clone(), v));
                if let Some(s) = st.node_version(tenant, &name, v).and_then(|n| spec_of(n).ok()) {
                    specs.push(s);
                }
            }
        }
        i += 1;
    }
    let mut out: Vec<ManifestFindings> = Vec::new();
    for t in specs.iter().flat_map(|s| s.tools.iter()) {
        let Ok(caliban_nodes::ToolTarget::Mcp { server, tool, pin }) = caliban_nodes::ToolTarget::parse(&t.reference)
        else {
            continue;
        };
        if out.iter().any(|m| m.tool == t.reference) {
            continue;
        }
        let findings = st
            .tool_manifests
            .iter()
            .find(|m| m.tenant_id == tenant && m.server == server && m.name == tool && m.pin == pin)
            .map(|m| m.findings.iter().filter_map(|f| serde_json::to_value(f).ok()).collect())
            .unwrap_or_default();
        out.push(ManifestFindings { tool: t.reference.clone(), findings });
    }
    out
}

fn eval_view(e: &EvalRecord) -> Value {
    json!({
        "id": e.id,
        "object": "node.eval",
        "node": e.node,
        "version": e.version,
        "hash": e.spec_hash,
        "suite": e.suite,
        "k": e.k,
        "concurrency": e.concurrency,
        "case_count": e.case_count,
        "status": e.status,
        "created_by": e.created_by,
        "api_key_id": e.api_key_id,
        "summary": e.summary,
        "error": e.error,
        "cancel_requested": e.cancel_requested_at.is_some() && !e.status.is_terminal(),
        "cancelled_by": e.cancelled_by,
        "claims": e.claims,
        // Retention cleared its sealed content (trial detail, the plan); the summary stays.
        "content_purged": e.plan.is_empty(),
        "created_at": e.created_at,
        "started_at": e.started_at,
        "finished_at": e.finished_at,
    })
}

/// `POST .../nodes/{name}/versions/{v}/evals` (`nodes.run`): starts an eval of a published
/// version (`202`). Workers run it; audited as `node.eval.start`.
pub(crate) async fn start(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name, version)): Path<(String, String, u32)>,
    Json(body): Json<StartBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let st = cp.store.state();
    let n = version_of(&st, &tenant_id, &name, version)?;
    if n.state != NodeState::Published {
        return Err(conflict(format!(
            "{name}@v{version} is {}: evals run published versions (publish it with {{\"promote\": false}} first)",
            n.state.as_str()
        )));
    }
    let spec = spec_of(&n)?;
    let suite = Suite::parse(&body.suite)
        .ok_or_else(|| unprocessable(format!("unknown suite '{}' (golden or injection)", body.suite)))?;
    let key = match &body.api_key_id {
        Some(id) => {
            let key = st
                .api_keys
                .iter()
                .find(|k| &k.id == id && k.tenant_id == tenant_id && k.is_active())
                .cloned()
                .ok_or_else(|| unprocessable(format!("no active API key '{id}' in tenant {tenant_id}")))?;
            if key.nodes.as_ref().is_some_and(|allowed| !allowed.contains(&name)) {
                return Err(unprocessable(format!("API key '{}' may not run node {name}", key.id)));
            }
            key
        }
        None => eval_key(&cp, &tenant_id, &p.actor).await?,
    };
    let k = body.k.unwrap_or(match suite {
        Suite::Golden => 3,
        Suite::Injection => 1,
    });
    if k == 0 || k > eval::MAX_K {
        return Err(unprocessable(format!("k must be between 1 and {}", eval::MAX_K)));
    }
    let concurrency = body.concurrency.unwrap_or(4);
    if concurrency == 0 || concurrency > eval::MAX_CONCURRENCY {
        return Err(unprocessable(format!("concurrency must be between 1 and {}", eval::MAX_CONCURRENCY)));
    }
    let s = sealer_for(&cp, &p, &tenant_id).await?;
    let golden = j.golden_set(&tenant_id, &name, version).await.map_err(journal_error)?;
    let golden_cases = golden.as_ref().map(|g| open_cases(&s, g)).transpose()?;
    let (plan, case_count) = match suite {
        Suite::Golden => {
            let (g, mut cases) = golden.zip(golden_cases).ok_or_else(|| {
                unprocessable(format!("{name}@v{version} has no golden set (PUT .../versions/{version}/golden-set)"))
            })?;
            if let Some(only) = &body.cases {
                if let Some(missing) = only.iter().find(|id| !cases.iter().any(|c| &c.id == *id)) {
                    return Err(unprocessable(format!("the golden set has no case '{missing}'")));
                }
                cases.retain(|c| only.contains(&c.id));
            }
            if body.judge_model.as_deref().is_some_and(|m| m.starts_with("node/")) {
                return Err(unprocessable("judge_model must be a model, not a node"));
            }
            let count = cases.len() as u32;
            (Plan::Golden { cases, golden_hash: g.hash, judge_model: body.judge_model.clone() }, count)
        }
        Suite::Injection => {
            let from_case = golden_cases.as_ref().and_then(|cs| match &body.input_case {
                Some(id) => cs.iter().find(|c| &c.id == id),
                None => cs.first(),
            });
            if let (Some(id), None) = (&body.input_case, from_case) {
                return Err(unprocessable(format!("the golden set has no case '{id}'")));
            }
            let (input, checks) = match (&body.input, from_case) {
                (Some(i), _) => (i.clone(), vec![]),
                (None, Some(c)) => (c.input.clone(), c.all_checks()),
                (None, None) if spec.input_schema().is_none() => {
                    (json!("Please handle the latest request about record 4471."), vec![])
                }
                (None, None) => {
                    return Err(unprocessable(
                        "an injection eval of a node with an input schema needs an input: give `input`, or a golden set",
                    ));
                }
            };
            if let Some(schema) = spec.input_schema() {
                caliban_nodes::schema::validate(schema, &input).map_err(|e| unprocessable(format!("input: {e}")))?;
            }
            let count = eval::injection::cases().len() as u32;
            let plan = Plan::Injection {
                input,
                suite_version: eval::injection::SUITE_VERSION,
                manifests: manifests(&st, &tenant_id, &spec),
                checks,
            };
            (plan, count)
        }
    };
    let id = format!("eval_{}", uuid::Uuid::now_v7().simple());
    let text = serde_json::to_string(&plan).map_err(|e| bad(e.to_string()))?;
    let sealed = s.seal(&tenant_id, &id, &text).map_err(bad)?;
    let new = NewEval {
        id: id.clone(),
        tenant_id: tenant_id.clone(),
        node: name.clone(),
        version,
        spec_hash: n.hash.clone(),
        suite,
        k,
        concurrency,
        created_by: p.actor.clone(),
        api_key_id: Some(key.id.clone()),
        invoker_key_hash: key.hash.clone(),
        plan: sealed,
        case_count,
    };
    let detail = json!({"node": name, "version": version, "hash": n.hash, "suite": suite, "k": k,
                        "cases": case_count, "api_key_id": key.id});
    let a = audit(&tenant_id, &p, format!("{id}/start"), "node.eval.start", &id, detail);
    let e = j.create_eval(new, Some(a)).await.map_err(journal_error)?;
    drain_audit(&cp, &j).await?;
    Ok((StatusCode::ACCEPTED, Json(eval_view(&e))))
}

// ───────────────────────────── the eval key ─────────────────────────────

/// The tenant's eval key (P3 decision 9), created on first use: an API key the control plane
/// manages for evals. Only its hash exists (the secret is generated and dropped at once), the
/// data plane refuses it on its endpoints (`eval_key_hashes` in the snapshot), and it may run
/// every node of the tenant. Created audited as `api_key.create` with `purpose: eval`.
pub(crate) async fn eval_key(cp: &Cp, tenant: &str, actor: &str) -> ApiResult<ApiKeyRecord> {
    for _ in 0..3 {
        if let Some(k) =
            cp.store.state().api_keys.iter().find(|k| k.tenant_id == tenant && k.is_active() && k.is_eval())
        {
            return Ok(k.clone());
        }
        match cp.store.apply(actor, Mutation::CreateApiKey(new_eval_key(tenant))).await {
            // Created here, or concurrently by another replica: read it back.
            Ok(_) | Err(StoreError::Conflict(_)) => {
                cp.store.refresh().await?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(conflict("the tenant's eval key is being created concurrently; retry"))
}

fn new_eval_key(tenant: &str) -> ApiKeyRecord {
    // The plaintext is never stored, logged or returned: nobody can present this key.
    let secret = Zeroizing::new(crate::generate_api_key());
    ApiKeyRecord {
        id: new_id("key"),
        tenant_id: tenant.to_owned(),
        name: "evals (managed by Caliban)".into(),
        prefix: "cal_eval".into(),
        hash: caliban_types::hash_api_key(&secret),
        created_at: now_micros(),
        revoked_at: None,
        nodes: None,
        datasource_scopes: None,
        purpose: Some(EVAL_KEY_PURPOSE.into()),
    }
}

/// `GET /tenants/{t}/eval-key` (`api_keys.read`): the tenant's eval key, if one was created.
pub(crate) async fn get_eval_key(AxState(cp): AxState<Cp>, Path(tenant_id): Path<String>) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let st = cp.store.state();
    let k = st.api_keys.iter().find(|k| k.tenant_id == tenant_id && k.is_active() && k.is_eval());
    Ok(Json(json!({"tenant_id": tenant_id, "key": k})))
}

/// `POST /tenants/{t}/eval-key/rotate` (`api_keys.write`): revokes the eval key and creates a new
/// one (audited as `api_key.revoke` and `api_key.create`). Evals in flight lose their key: their
/// remaining model calls fail, so rotate between evals.
pub(crate) async fn rotate_eval_key(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let old =
        cp.store.state().api_keys.iter().find(|k| k.tenant_id == tenant_id && k.is_active() && k.is_eval()).cloned();
    if let Some(k) = &old {
        let m = Mutation::RevokeApiKey { tenant_id: tenant_id.clone(), id: k.id.clone(), at: now_micros() };
        cp.store.apply(&p.actor, m).await?;
    }
    let key = eval_key(&cp, &tenant_id, &p.actor).await?;
    Ok(Json(json!({"tenant_id": tenant_id, "key": key, "revoked": old.map(|k| k.id)})))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListQuery {
    node: Option<String>,
    version: Option<u32>,
    suite: Option<String>,
    /// Comma-separated statuses.
    status: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

/// `GET /tenants/{t}/evals` (`nodes.read`): the tenant's evals, newest first, metrics included.
pub(crate) async fn list(
    AxState(cp): AxState<Cp>,
    Path(tenant_id): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let suite =
        q.suite.as_deref().map(|s| Suite::parse(s).ok_or_else(|| bad(format!("unknown suite '{s}'")))).transpose()?;
    let statuses = q
        .status
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| EvalStatus::parse(s).ok_or_else(|| bad(format!("unknown status '{s}'"))))
        .collect::<ApiResult<Vec<_>>>()?;
    let before = q.cursor.as_deref().map(|c| decode_cursor(c).ok_or_else(|| bad("invalid cursor"))).transpose()?;
    let query = EvalQuery {
        tenant: tenant_id,
        node: q.node,
        version: q.version,
        suite,
        statuses,
        before,
        limit: q.limit.unwrap_or(50).clamp(1, 200),
    };
    let page = j.list_evals(&query).await.map_err(journal_error)?;
    let next = (page.len() == query.limit).then(|| page.last().map(|e| encode_cursor(e.created_at, &e.id))).flatten();
    Ok(Json(json!({"object": "list", "data": page.iter().map(eval_view).collect::<Vec<_>>(), "next_cursor": next})))
}

/// `GET /tenants/{t}/evals/{id}` (`nodes.read`): the eval and its trials (metrics, verdicts, run
/// ids); with `runs.data` also what the scorers said (`detail`: outputs, reasons, tool arguments).
pub(crate) async fn get(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let e = j.get_eval(&tenant_id, &id).await.map_err(journal_error)?.ok_or_else(|| not_found("eval"))?;
    let content = p.allows(Perm::RunsData, Some(&tenant_id));
    let s = if content { Some(sealer(&cp)?) } else { None };
    let trials: Vec<Value> = j
        .trials(&id)
        .await
        .map_err(journal_error)?
        .iter()
        .map(|t| {
            let mut v = json!({"case": t.case_id, "trial": t.trial, "run_id": t.run_id, "status": t.status,
                               "cost_usd": t.cost_usd, "latency_ms": t.latency_ms, "tokens": t.tokens,
                               "verdict": t.verdict, "finished_at": t.finished_at});
            if let Some(s) = &s {
                v["detail"] = t
                    .detail
                    .as_deref()
                    .and_then(|d| s.open(&tenant_id, &id, d).ok())
                    .and_then(|d| serde_json::from_str(&d).ok())
                    .unwrap_or(Value::Null);
            }
            v
        })
        .collect();
    let mut v = eval_view(&e);
    v["trials"] = json!(trials);
    v["content_visible"] = json!(content);
    Ok(Json(v))
}

/// `POST /tenants/{t}/evals/{id}/cancel` (`nodes.run`): a pending eval ends at once (`200`); a
/// running one stops, with its runs, at its worker's next check (`202`). Audited once.
pub(crate) async fn cancel(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, id)): Path<(String, String)>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let j = journal(&cp)?;
    let e = j.get_eval(&tenant_id, &id).await.map_err(journal_error)?.ok_or_else(|| not_found("eval"))?;
    let detail = json!({"node": e.node, "version": e.version, "suite": e.suite, "status": e.status});
    let a = audit(&tenant_id, &p, format!("{id}/cancel"), "node.eval.cancel", &id, detail);
    let status = match j.cancel_eval(&tenant_id, &id, &p.actor, Some(a)).await.map_err(journal_error)? {
        EvalCancel::Ended => StatusCode::OK,
        EvalCancel::Requested => StatusCode::ACCEPTED,
        EvalCancel::AlreadyEnded(EvalStatus::Cancelled) => StatusCode::OK,
        EvalCancel::AlreadyEnded(s) => return Err(conflict(format!("the eval already ended ({})", s.as_str()))),
        EvalCancel::NotFound => return Err(not_found("eval")),
    };
    drain_audit(&cp, &j).await?;
    let e = j.get_eval(&tenant_id, &id).await.map_err(journal_error)?.ok_or_else(|| not_found("eval"))?;
    Ok((status, Json(eval_view(&e))))
}

#[cfg(test)]
mod tests {
    use crate::store::Store;
    use crate::{ControlPlane, app};
    use axum::Router;
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use caliban_config::{Config, ConfigHandle, Keyring, Snapshot};
    use caliban_meter::RecentUsage;
    use caliban_nodes::journal::Journal;
    use caliban_nodes::journal::evals::{EvalFinish, EvalStatus};
    use caliban_nodes::journal::memory::MemoryJournal;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn cp(journal: Option<Arc<dyn Journal>>) -> Arc<ControlPlane> {
        let cfg = Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
        let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
        Arc::new(
            ControlPlane::new(Store::new(cfg, handle, RecentUsage::default()), "admin-secret".into(), "standalone")
                .with_keyring(Some(Arc::new(Keyring::new([7; 32], []))))
                .with_journal(journal),
        )
    }

    async fn call(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", "Bearer admin-secret");
        let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
        let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    const N: &str = "/api/v1/tenants/acme/nodes";

    fn spec(tools: Value) -> Value {
        json!({"kind": "agent", "prompt": {"system": "Triage.", "input_schema": {"type": "object", "required": ["case"],
                "properties": {"case": {"type": "string"}}}}, "model_policy": {}, "tools": tools,
               "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30}})
    }

    /// Registers a server with one write tool (imported manifest) and approves it.
    async fn write_tool(app: &Router) -> String {
        let m = json!({"name": "send", "description": "Sends a message.", "input_schema": {"type": "object"}});
        let t = "/api/v1/tenants/acme/tool-servers";
        let (s, v) = call(app, "POST", t, Some(json!({"name": "mail", "url": "https://mail.internal/mcp"}))).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        let (s, v) = call(app, "POST", &format!("{t}/mail/tools"), Some(json!({"manifests": [m]}))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let pin = v["tools"][0]["pin"].as_str().unwrap().to_owned();
        let (s, v) = call(app, "POST", &format!("{t}/mail/tools/send/approve"), Some(json!({"pin": pin}))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        format!("mcp://mail/send#{pin}")
    }

    async fn actions(app: &Router) -> Vec<String> {
        let (_, a) = call(app, "GET", "/api/v1/audit?limit=100", None).await;
        assert_eq!(a["chain_verified"], true);
        a["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap().to_owned()).collect()
    }

    #[tokio::test]
    async fn golden_sets_are_validated_sealed_and_audited() {
        let j: Arc<dyn Journal> = Arc::new(MemoryJournal::new());
        let app = app(cp(Some(Arc::clone(&j))), None);
        call(&app, "POST", &format!("{N}/triage/versions"), Some(json!({"spec": spec(json!([]))}))).await;
        let g = format!("{N}/triage/versions/1/golden-set");
        assert_eq!(call(&app, "GET", &g, None).await.0, StatusCode::NOT_FOUND);
        let bad = json!({"cases": [{"id": "a", "input": {"nope": 1}, "expected": "x"}]});
        let (s, e) = call(&app, "PUT", &g, Some(bad)).await;
        assert_eq!(
            (s, e["error"]["problems"][0]["kind"].as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, Some("golden_set")),
            "{e}"
        );
        let cases = json!([{"id": "chest", "input": {"case": "chest pain since Tuesday"}, "expected": "clinical",
                            "answers": {"clarify": "two days"}}]);
        let (s, v) = call(&app, "PUT", &g, Some(json!({"cases": cases}))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!((v["case_count"].as_u64(), v["cases"][0]["id"].as_str()), (Some(1), Some("chest")));
        // Sealed at rest: the journal holds no case content.
        let rec = j.golden_set("acme", "triage", 1).await.unwrap().unwrap();
        assert!(!rec.cases.contains("chest pain"));
        let (_, v) = call(&app, "GET", &g, None).await;
        assert_eq!(v["cases"][0]["answers"]["clarify"], "two days");
        assert_eq!(
            call(&app, "PUT", &format!("{N}/triage/versions/9/golden-set"), Some(json!({"cases": cases}))).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(call(&app, "DELETE", &g, None).await.0, StatusCode::NO_CONTENT);
        assert_eq!(call(&app, "DELETE", &g, None).await.0, StatusCode::NOT_FOUND);
        let a = actions(&app).await;
        assert!(
            a.contains(&"node.golden_set.update".to_owned()) && a.contains(&"node.golden_set.delete".to_owned()),
            "{a:?}"
        );
        // Without a journal there is nothing to read or write.
        let none = app_without_journal();
        assert_eq!(call(&none, "GET", &g, None).await.0, StatusCode::SERVICE_UNAVAILABLE);
    }

    fn app_without_journal() -> Router {
        app(cp(None), None)
    }

    /// Promotion is gated: a version with write tools needs an injection eval that met the bar;
    /// the node's bar can ask for a golden-set eval too. The evidence is in the audit log.
    #[tokio::test]
    async fn promotion_waits_for_evals_that_meet_the_bar() {
        let j: Arc<dyn Journal> = Arc::new(MemoryJournal::new());
        let app = app(cp(Some(Arc::clone(&j))), None);
        let write = write_tool(&app).await;
        let tools = json!([{"ref": write, "effect": "write", "allow_tainted": ["*"]}]);
        let (s, v) = call(&app, "POST", &format!("{N}/desk/versions"), Some(json!({"spec": spec(tools)}))).await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        assert_eq!(v["warnings"][0]["kind"], "allowlist", "a broad allowlist is warned about: {v}");
        let (s, e) = call(&app, "POST", &format!("{N}/desk/versions/1/publish"), None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{e}");
        assert_eq!(e["error"]["problems"][0]["kind"], "eval_gate");
        assert!(e["error"]["message"].as_str().unwrap().contains("{\"promote\": false}"), "{e}");
        let (s, v) = call(&app, "POST", &format!("{N}/desk/versions/1/publish"), Some(json!({"promote": false}))).await;
        assert_eq!((s, v["live"].as_bool()), (StatusCode::OK, Some(false)), "{v}");
        let (_, gate) = call(&app, "GET", &format!("{N}/desk/versions/1/gate"), None).await;
        assert_eq!((gate["allowed"].as_bool(), gate["has_write_tools"].as_bool()), (Some(false), Some(true)), "{gate}");

        // An eval needs an active key of the tenant; it starts pending.
        let (_, key) = call(&app, "POST", "/api/v1/tenants/acme/api-keys", Some(json!({"name": "evals"}))).await;
        let kid = key["id"].as_str().unwrap().to_owned();
        let ev_uri = format!("{N}/desk/versions/1/evals");
        let start = |body: Value| call(&app, "POST", &ev_uri, Some(body));
        assert_eq!(
            start(json!({"suite": "injection", "api_key_id": "nope"})).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(start(json!({"suite": "chaos", "api_key_id": kid})).await.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            start(json!({"suite": "golden", "api_key_id": kid})).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "no golden set"
        );
        let (s, e) = start(json!({"suite": "injection", "api_key_id": kid, "input": {"case": "hi"}})).await;
        assert_eq!((s, e["status"].as_str(), e["k"].as_u64()), (StatusCode::ACCEPTED, Some("pending"), Some(1)), "{e}");
        let id = e["id"].as_str().unwrap().to_owned();

        // A worker runs it: below the default bar (every attack blocked) the gate holds.
        let claimed = j.claim_eval("w", Duration::from_secs(30)).await.unwrap().unwrap();
        assert_eq!(claimed.id, id);
        let done = |rate: f64| EvalFinish {
            status: EvalStatus::Succeeded,
            summary: Some(json!({"pass_rate": rate, "blocked": 9, "trials": 10})),
            error: None,
        };
        assert!(j.finish_eval(&id, "w", done(0.9), None).await.unwrap());
        let promote_uri = format!("{N}/desk/promote");
        let promote = || call(&app, "POST", &promote_uri, Some(json!({"version": 1})));
        let (s, e) = promote().await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{e}");
        assert!(e["error"]["message"].as_str().unwrap().contains("the bar is 1.000"), "{e}");
        // The node's bar can lower it (audited); a golden bar then needs a golden eval too.
        let p = format!("{N}/desk/eval-policy");
        assert_eq!(
            call(&app, "PUT", &p, Some(json!({"injection": {"min_pass_rate": 1.5}}))).await.0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let bar = json!({"injection": {"min_pass_rate": 0.9}, "golden": {"min_pass_k": 0.8, "min_k": 2}});
        let (s, v) = call(&app, "PUT", &p, Some(bar)).await;
        assert_eq!((s, v["injection_bar"].as_f64()), (StatusCode::OK, Some(0.9)), "{v}");
        let (s, e) = promote().await;
        assert!(
            s == StatusCode::UNPROCESSABLE_ENTITY
                && e["error"]["message"].as_str().unwrap().contains("golden-set eval"),
            "{e}"
        );
        call(
            &app,
            "PUT",
            &format!("{N}/desk/versions/1/golden-set"),
            Some(json!({"cases": [{"id": "a", "input": {"case": "x"}, "expected": "y"}]})),
        )
        .await;
        let (_, g) = start(json!({"suite": "golden", "api_key_id": kid, "k": 2})).await;
        let gid = g["id"].as_str().unwrap().to_owned();
        j.claim_eval("w", Duration::from_secs(30)).await.unwrap().unwrap();
        let f = EvalFinish { status: EvalStatus::Succeeded, summary: Some(json!({"pass_hat_k": 1.0})), error: None };
        assert!(j.finish_eval(&gid, "w", f, None).await.unwrap());
        let (s, v) = promote().await;
        assert_eq!((s, v["live"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=100", None).await;
        let promoted = a["entries"].as_array().unwrap().iter().find(|e| e["action"] == "node.promote").unwrap().clone();
        assert_eq!(
            (
                promoted["detail"]["evals"]["injection"]["eval"].as_str(),
                promoted["detail"]["evals"]["golden"]["eval"].as_str()
            ),
            (Some(id.as_str()), Some(gid.as_str())),
            "{promoted}"
        );
        let acts = actions(&app).await;
        for want in ["node.eval.start", "node.eval_policy.update", "node.golden_set.update"] {
            assert!(acts.contains(&want.to_owned()), "{want} in {acts:?}");
        }

        // Listing and detail; a pending eval is cancelled at once.
        let (_, list) = call(&app, "GET", "/api/v1/tenants/acme/evals?node=desk&suite=injection", None).await;
        assert_eq!(list["data"].as_array().unwrap().len(), 1, "{list}");
        let (_, d) = call(&app, "GET", &format!("/api/v1/tenants/acme/evals/{id}"), None).await;
        assert_eq!((d["summary"]["pass_rate"].as_f64(), d["trials"].as_array().map(Vec::len)), (Some(0.9), Some(0)));
        let (_, e) = start(json!({"suite": "injection", "api_key_id": kid, "input": {"case": "hi"}})).await;
        let uri = format!("/api/v1/tenants/acme/evals/{}/cancel", e["id"].as_str().unwrap());
        let (s, v) = call(&app, "POST", &uri, None).await;
        assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("cancelled")), "{v}");
        assert_eq!(
            call(&app, "POST", &format!("/api/v1/tenants/acme/evals/{gid}/cancel"), None).await.0,
            StatusCode::CONFLICT
        );
    }

    /// A pinned subnode version must have passed its own gate (P3 decision 12): a parent without
    /// write tools of its own is refused while a child it pins has none of its evals.
    #[tokio::test]
    async fn a_pinned_subnode_must_pass_its_own_gate() {
        let j: Arc<dyn Journal> = Arc::new(MemoryJournal::new());
        let app = app(cp(Some(Arc::clone(&j))), None);
        let write = write_tool(&app).await;
        let mut child = spec(json!([{"ref": write, "effect": "write"}]));
        child["prompt"]["input_schema"] = json!({"type": "string"});
        call(&app, "POST", &format!("{N}/mailer/versions"), Some(json!({"spec": child}))).await;
        let (s, v) =
            call(&app, "POST", &format!("{N}/mailer/versions/1/publish"), Some(json!({"promote": false}))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        // The parent has no write tool, no bar: before, it promoted at once.
        let parent = spec(json!([{"ref": "node://mailer@v1", "effect": "read"}]));
        call(&app, "POST", &format!("{N}/hub/versions"), Some(json!({"spec": parent}))).await;
        let (s, e) = call(&app, "POST", &format!("{N}/hub/versions/1/publish"), None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{e}");
        let msg = e["error"]["message"].as_str().unwrap();
        assert!(
            msg.contains("node://mailer@v1 (a subnode hub@v1 pins) has not passed its own promotion gate")
                && msg.contains("injection"),
            "{msg}"
        );
        assert_eq!(e["error"]["problems"][0]["path"], "node://mailer@v1", "{e}");
        let (s, v) = call(&app, "POST", &format!("{N}/hub/versions/1/publish"), Some(json!({"promote": false}))).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let (_, gate) = call(&app, "GET", &format!("{N}/hub/versions/1/gate"), None).await;
        assert_eq!(gate["allowed"], false, "{gate}");

        // The child's injection eval meets its bar: the parent promotes, and the audit names it.
        let (_, key) = call(&app, "POST", "/api/v1/tenants/acme/api-keys", Some(json!({"name": "evals"}))).await;
        let body = json!({"suite": "injection", "api_key_id": key["id"], "input": "hi"});
        let (s, e) = call(&app, "POST", &format!("{N}/mailer/versions/1/evals"), Some(body)).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{e}");
        let id = e["id"].as_str().unwrap().to_owned();
        j.claim_eval("w", Duration::from_secs(30)).await.unwrap().unwrap();
        let f = EvalFinish { status: EvalStatus::Succeeded, summary: Some(json!({"pass_rate": 1.0})), error: None };
        assert!(j.finish_eval(&id, "w", f, None).await.unwrap());
        let (_, gate) = call(&app, "GET", &format!("{N}/hub/versions/1/gate"), None).await;
        assert_eq!(gate["allowed"], true, "{gate}");
        assert_eq!(gate["evidence"]["subnodes"]["mailer@v1"]["injection"]["eval"], id.as_str(), "{gate}");
        let (s, v) = call(&app, "POST", &format!("{N}/hub/promote"), Some(json!({"version": 1}))).await;
        assert_eq!((s, v["live"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
    }

    /// The tenant's eval key (P3 decision 9): created by the control plane on the first eval that
    /// names no key, audited, never shown, refused by the customer key endpoints, rotated on
    /// demand, absent from the data plane's usable keys (`eval_key_hashes`), revoked with the
    /// tenant.
    #[tokio::test]
    async fn evals_use_a_managed_eval_key() {
        let j: Arc<dyn Journal> = Arc::new(MemoryJournal::new());
        let c = cp(Some(Arc::clone(&j)));
        let app = app(Arc::clone(&c), None);
        call(&app, "POST", &format!("{N}/plain/versions"), Some(json!({"spec": spec(json!([]))}))).await;
        call(&app, "POST", &format!("{N}/plain/versions/1/publish"), None).await;
        let (_, none) = call(&app, "GET", "/api/v1/tenants/acme/eval-key", None).await;
        assert!(none["key"].is_null(), "{none}");
        let body = json!({"suite": "injection", "input": {"case": "hi"}});
        let (s, e) = call(&app, "POST", &format!("{N}/plain/versions/1/evals"), Some(body.clone())).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{e}");
        let (_, k) = call(&app, "GET", "/api/v1/tenants/acme/eval-key", None).await;
        let key = k["key"].clone();
        assert_eq!((key["purpose"].as_str(), e["api_key_id"].clone()), (Some("eval"), key["id"].clone()), "{k}");
        assert!(key.get("key").is_none() && key.get("hash").is_none(), "never shown: {key}");
        // The same key for the next eval.
        let (_, e2) = call(&app, "POST", &format!("{N}/plain/versions/1/evals"), Some(body.clone())).await;
        assert_eq!(e2["api_key_id"], key["id"]);
        // In the snapshot as a key hash workers know, and marked so the data plane refuses it.
        let rec = c.store.state().api_keys.iter().find(|x| x.is_eval()).unwrap().clone();
        let t = c.store.config.load().tenant(&"acme".into()).unwrap().clone();
        assert!(t.api_key_hashes.contains(&rec.hash) && t.eval_key_hashes == [rec.hash.clone()]);
        // The customer key endpoints leave it alone.
        let kid = key["id"].as_str().unwrap();
        let uri = format!("/api/v1/tenants/acme/api-keys/{kid}");
        assert_eq!(call(&app, "DELETE", &uri, None).await.0, StatusCode::CONFLICT);
        assert_eq!(call(&app, "PATCH", &uri, Some(json!({"nodes": []}))).await.0, StatusCode::CONFLICT);
        // Rotation: a new key, the old one revoked; both audited.
        let (s, r) = call(&app, "POST", "/api/v1/tenants/acme/eval-key/rotate", None).await;
        assert_eq!((s, r["revoked"].as_str()), (StatusCode::OK, Some(kid)), "{r}");
        assert_ne!(r["key"]["id"], key["id"]);
        let a = actions(&app).await;
        assert!(a.iter().filter(|x| *x == "api_key.create").count() >= 2 && a.contains(&"api_key.revoke".to_owned()));
        let (_, audit) = call(&app, "GET", "/api/v1/audit?limit=100", None).await;
        assert!(
            audit["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["action"] == "api_key.create" && e["detail"]["purpose"] == "eval"),
            "{audit}"
        );
        // An explicitly named customer key still works (kept: it is cheap).
        let (_, ck) = call(&app, "POST", "/api/v1/tenants/acme/api-keys", Some(json!({"name": "mine"}))).await;
        let named = json!({"suite": "injection", "input": {"case": "hi"}, "api_key_id": ck["id"]});
        let (s, e3) = call(&app, "POST", &format!("{N}/plain/versions/1/evals"), Some(named)).await;
        assert_eq!((s, e3["api_key_id"].clone()), (StatusCode::ACCEPTED, ck["id"].clone()), "{e3}");
    }

    #[tokio::test]
    async fn versions_without_write_tools_or_bar_promote_as_before() {
        let app = app(cp(Some(Arc::new(MemoryJournal::new()))), None);
        call(&app, "POST", &format!("{N}/plain/versions"), Some(json!({"spec": spec(json!([]))}))).await;
        let (s, v) = call(&app, "POST", &format!("{N}/plain/versions/1/publish"), None).await;
        assert_eq!(
            (s, v["live"].as_bool(), v["warnings"].as_array().map(Vec::len)),
            (StatusCode::OK, Some(true), Some(0)),
            "{v}"
        );
        // Without a journal too (no bar can be set there).
        let none = app_without_journal();
        call(&none, "POST", &format!("{N}/plain/versions"), Some(json!({"spec": spec(json!([]))}))).await;
        assert_eq!(call(&none, "POST", &format!("{N}/plain/versions/1/publish"), None).await.0, StatusCode::OK);
    }
}
