//! Retrieval collections and documents on the admin API. See docs/rag.md and `caliban-rag`.
//!
//! The control plane only writes the registry (next to the node journal, shared with the
//! workers): a collection names an embedding model the tenant can use (and optionally a rerank
//! model); ingesting a document seals it under the tenant's data key and leaves it `pending`.
//! Workers (or a standalone process) index it; it becomes visible to `builtin://rag_search` only
//! when indexing completes and its checks pass. Document content is never returned.
//!
//! Every write is audited in the hash chain (the registry writes the event in the transaction of
//! the change; the control plane records it at once).
//!
//! | Permission | Endpoints |
//! |---|---|
//! | `rag.read` | list and read collections, list documents and read their versions (state, findings) |
//! | `rag.write` | create and delete collections, ingest and delete documents |
//! | `rag.approve` | release a quarantined document version |

use crate::auth::Principal;
use crate::store::{NodeState, State};
use crate::{ApiError, ApiResult, Cp, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, Query, State as AxState};
use axum::http::StatusCode;
use caliban_config::ModelKind;
use caliban_nodes::journal::AuditEvent;
use caliban_rag::ingest::{IngestRequest, prepare};
use caliban_rag::store::{
    CollectionRecord, CollectionSettings, DocQuery, DocRef, DocStatus, RagStore, RagStoreError, valid_collection_name,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// Largest ingest request body.
pub const INGEST_MAX_BYTES: usize = 8 * 1024 * 1024;

pub(crate) fn rag(cp: &Cp) -> ApiResult<Arc<dyn RagStore>> {
    cp.rag().ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "retrieval is not configured on this control plane (set CALIBAN_DATABASE_URL, shared with the workers)"
                .into(),
        )
    })
}

fn rag_error(e: RagStoreError) -> ApiError {
    match e {
        RagStoreError::NotFound(w) => not_found(&w),
        RagStoreError::Conflict(m) => ApiError(StatusCode::CONFLICT, m),
        RagStoreError::Invalid(m) => ApiError(StatusCode::UNPROCESSABLE_ENTITY, m),
        RagStoreError::Backend(m) => {
            tracing::error!(error = %m, "document registry error");
            ApiError(StatusCode::INTERNAL_SERVER_ERROR, "document registry error".into())
        }
    }
}

fn unprocessable(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

fn event(tenant: &str, p: &Principal, action: &str, target: &str, detail: Value) -> AuditEvent {
    AuditEvent {
        id: format!("cp/{action}/{}", uuid::Uuid::now_v7().simple()),
        tenant_id: tenant.to_owned(),
        actor: p.actor.clone(),
        action: action.into(),
        target: Some(target.to_owned()),
        detail,
        at: Utc::now(),
    }
}

/// Moves the registry's audit events into the hash chain now.
async fn drain(cp: &Cp, r: &Arc<dyn RagStore>) -> ApiResult<()> {
    let pending = r.claim_audit("control-plane", std::time::Duration::from_secs(60), 1000).await.map_err(rag_error)?;
    if pending.is_empty() {
        return Ok(());
    }
    let ids: Vec<String> = pending.iter().map(|e| e.id.clone()).collect();
    cp.store.ingest_audit(pending).await?;
    r.ack_audit(&ids).await.map_err(rag_error)
}

async fn collection_of(r: &Arc<dyn RagStore>, tenant: &str, name: &str) -> ApiResult<CollectionRecord> {
    r.collection(tenant, name).await.map_err(rag_error)?.ok_or_else(|| not_found("collection"))
}

/// Published node versions of the tenant whose scopes name the collection.
pub(crate) fn users_of(st: &State, tenant: &str, collection: &str) -> Vec<String> {
    let scope = format!("{}.{collection}:read", caliban_nodes::RAG_SCOPE);
    st.nodes
        .iter()
        .filter(|n| n.tenant_id == tenant && n.is_live() && n.state == NodeState::Published)
        .filter(|n| {
            n.spec
                .pointer("/datasources/scopes")
                .and_then(Value::as_array)
                .is_some_and(|a| a.iter().any(|s| s == &scope))
        })
        .map(|n| format!("{}@v{}", n.name, n.version))
        .collect()
}

/// Checks a model the tenant would use for a collection: in the catalogue, of `kind`, reachable.
fn check_model(cp: &Cp, tenant: &str, id: &str, kind: ModelKind, what: &str) -> ApiResult<()> {
    let snap = cp.store.config.load();
    let t = snap.tenant(&tenant.into()).ok_or_else(|| not_found("tenant"))?;
    let m =
        snap.model(&id.into()).ok_or_else(|| unprocessable(format!("{what} '{id}' is not in the model catalogue")))?;
    if m.kind != kind {
        return Err(unprocessable(format!(
            "{what} '{id}' is not a{} model",
            match kind {
                ModelKind::Embedding => "n embedding",
                ModelKind::Rerank => " rerank",
                _ => " suitable",
            }
        )));
    }
    if snap.provider_for(t, &m.provider).is_none() {
        return Err(unprocessable(format!("{what} '{id}' is not reachable by this tenant (no provider serves it)")));
    }
    Ok(())
}

pub(crate) async fn list_collections(
    AxState(cp): AxState<Cp>,
    Path(tenant_id): Path<String>,
) -> ApiResult<Json<Vec<CollectionRecord>>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    Ok(Json(rag(&cp)?.collections(&tenant_id).await.map_err(rag_error)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CollectionCreate {
    name: String,
    #[serde(default)]
    description: Option<String>,
    embedding_model: String,
    #[serde(default)]
    rerank_model: Option<String>,
    #[serde(default)]
    settings: Option<CollectionSettings>,
}

pub(crate) async fn create_collection(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path(tenant_id): Path<String>,
    Json(body): Json<CollectionCreate>,
) -> ApiResult<(StatusCode, Json<CollectionRecord>)> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let r = rag(&cp)?;
    if !valid_collection_name(&body.name) {
        return Err(unprocessable("name must be 1 to 64 characters of [a-z0-9_], starting with a letter or digit"));
    }
    if body.description.as_ref().is_some_and(|d| d.chars().count() > 1000) {
        return Err(unprocessable("description is longer than 1000 characters"));
    }
    check_model(&cp, &tenant_id, &body.embedding_model, ModelKind::Embedding, "embedding_model")?;
    if let Some(m) = &body.rerank_model {
        check_model(&cp, &tenant_id, m, ModelKind::Rerank, "rerank_model")?;
    }
    let settings = body.settings.unwrap_or_default();
    settings.validate().map_err(unprocessable)?;
    let c = CollectionRecord {
        id: format!("ragc_{}", uuid::Uuid::now_v7().simple()),
        tenant_id: tenant_id.clone(),
        name: body.name,
        description: body.description,
        embedding_model: body.embedding_model,
        rerank_model: body.rerank_model,
        settings,
        created_at: Utc::now(),
        created_by: p.actor.clone(),
        deleted_at: None,
        purged_at: None,
    };
    let detail = json!({"name": c.name, "embedding_model": c.embedding_model, "rerank_model": c.rerank_model,
                        "settings": c.settings});
    let a = event(&tenant_id, &p, "rag.collection.create", &c.id, detail);
    let c = r.create_collection(c, Some(a)).await.map_err(rag_error)?;
    drain(&cp, &r).await?;
    Ok((StatusCode::CREATED, Json(c)))
}

pub(crate) async fn get_collection(
    AxState(cp): AxState<Cp>,
    Path((tenant_id, name)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let r = rag(&cp)?;
    let c = collection_of(&r, &tenant_id, &name).await?;
    let mut v = serde_json::to_value(&c).unwrap_or_default();
    v["used_by"] = json!(users_of(&cp.store.state(), &tenant_id, &name));
    Ok(Json(v))
}

/// Refused while a published node version names the collection in its scopes (retire it first);
/// a `rag.*:read` scope does not hold it.
pub(crate) async fn delete_collection(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let r = rag(&cp)?;
    let c = collection_of(&r, &tenant_id, &name).await?;
    let users = users_of(&cp.store.state(), &tenant_id, &name);
    if !users.is_empty() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("collection '{name}' is searched by published node versions: {}", users.join(", ")),
        ));
    }
    let a = event(&tenant_id, &p, "rag.collection.delete", &c.id, json!({"name": name}));
    if !r.delete_collection(&tenant_id, &name, Utc::now(), Some(a)).await.map_err(rag_error)? {
        return Err(not_found("collection"));
    }
    drain(&cp, &r).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct DocList {
    status: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}

/// The newest version of each document (by id), with the version being served.
pub(crate) async fn list_documents(
    AxState(cp): AxState<Cp>,
    Path((tenant_id, name)): Path<(String, String)>,
    Query(q): Query<DocList>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let r = rag(&cp)?;
    let c = collection_of(&r, &tenant_id, &name).await?;
    let status = match q.status.as_deref() {
        None => None,
        Some(s) => Some(DocStatus::parse(s).ok_or_else(|| bad(format!("unknown status '{s}'")))?),
    };
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let query = DocQuery { status, after: q.cursor.clone(), limit };
    let page = r.documents(&tenant_id, &c.id, &query).await.map_err(rag_error)?;
    let next = (page.len() == limit).then(|| page.last().map(|d| d.latest.doc_id.clone())).flatten();
    Ok(Json(json!({"documents": page, "next_cursor": next})))
}

/// Ingests a document version: `202` with the pending version, or `200` with the existing one
/// when the same content and settings are already there.
pub(crate) async fn ingest(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name)): Path<(String, String)>,
    Json(body): Json<IngestRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let r = rag(&cp)?;
    let c = collection_of(&r, &tenant_id, &name).await?;
    let keyring = cp.keyring("documents")?;
    let dek = crate::keys::tenant_dek(&cp.store, keyring, &tenant_id, &p.actor).await?;
    let doc_id = body.doc_id.clone();
    let new = prepare(&dek, &c, body, &p.actor).map_err(unprocessable)?;
    let detail = json!({"collection": name, "doc_id": doc_id, "bytes": new.bytes, "content_type": new.content_type,
                        "trust": new.trust, "source": new.source});
    let a = event(&tenant_id, &p, "rag.document.ingest", &format!("{name}/{doc_id}"), detail);
    let (rec, created) = r.put_document(new, Some(a)).await.map_err(rag_error)?;
    drain(&cp, &r).await?;
    let status = if created { StatusCode::ACCEPTED } else { StatusCode::OK };
    let mut v = serde_json::to_value(&rec).unwrap_or_default();
    v["unchanged"] = json!(!created);
    Ok((status, Json(v)))
}

pub(crate) async fn get_document(
    AxState(cp): AxState<Cp>,
    Path((tenant_id, name, doc_id)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let r = rag(&cp)?;
    let c = collection_of(&r, &tenant_id, &name).await?;
    let versions = r.document(&tenant_id, &c.id, &doc_id).await.map_err(rag_error)?;
    if versions.is_empty() {
        return Err(not_found("document"));
    }
    let live = versions.iter().find(|d| d.status == DocStatus::Ready).map(|d| d.version);
    Ok(Json(json!({"doc_id": doc_id, "live_version": live, "versions": versions})))
}

pub(crate) async fn delete_document(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name, doc_id)): Path<(String, String, String)>,
) -> ApiResult<StatusCode> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let r = rag(&cp)?;
    let c = collection_of(&r, &tenant_id, &name).await?;
    let a = event(&tenant_id, &p, "rag.document.delete", &format!("{name}/{doc_id}"), json!({"collection": name}));
    if !r.delete_document(&tenant_id, &c.id, &doc_id, Utc::now(), Some(a)).await.map_err(rag_error)? {
        return Err(not_found("document"));
    }
    drain(&cp, &r).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Release {
    version: u32,
    /// Must be `true`: releasing is a decision about the findings it was quarantined for.
    #[serde(default)]
    acknowledge_findings: bool,
}

/// Releases a quarantined version: it is indexed again with its findings acknowledged, and served
/// once ready. Audited with the findings.
pub(crate) async fn release(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name, doc_id)): Path<(String, String, String)>,
    Json(body): Json<Release>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    if !body.acknowledge_findings {
        return Err(unprocessable("releasing a quarantined document needs acknowledge_findings: true"));
    }
    let r = rag(&cp)?;
    let c = collection_of(&r, &tenant_id, &name).await?;
    let versions = r.document(&tenant_id, &c.id, &doc_id).await.map_err(rag_error)?;
    let v = versions.iter().find(|d| d.version == body.version).ok_or_else(|| not_found("document version"))?;
    let detail = json!({"collection": name, "doc_id": doc_id, "version": body.version, "findings": v.findings,
                        "trust": v.trust});
    let a = event(&tenant_id, &p, "rag.document.release", &format!("{name}/{doc_id}"), detail);
    let key = DocRef { tenant_id: tenant_id.clone(), collection_id: c.id.clone(), doc_id, version: body.version };
    let rec = r.release(&key, &p.actor, Utc::now(), Some(a)).await.map_err(rag_error)?;
    drain(&cp, &r).await?;
    Ok(Json(serde_json::to_value(rec).unwrap_or_default()))
}

/// Publish-time check of a spec's retrieval scopes: each `rag.<name>:read` names a live collection
/// of the tenant (`rag.*:read` is always fine). Problems are returned, not raised.
pub(crate) async fn scope_problems(
    cp: &Cp,
    tenant: &str,
    spec: &caliban_nodes::NodeSpec,
) -> Vec<caliban_nodes::publish::Problem> {
    use caliban_nodes::publish::Problem;
    let wanted: Vec<(usize, String)> = spec
        .datasource_scopes()
        .into_iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let (target, _) = s.rsplit_once(':')?;
            let (ds, object) = target.split_once('.')?;
            (ds == caliban_nodes::RAG_SCOPE && object != "*").then(|| (i, object.to_owned()))
        })
        .collect();
    if wanted.is_empty() {
        return Vec::new();
    }
    let Some(r) = cp.rag() else {
        return vec![Problem::new("datasource_scope", "retrieval is not configured on this control plane", None)];
    };
    let live: Vec<String> = match r.collections(tenant).await {
        Ok(c) => c.into_iter().map(|c| c.name).collect(),
        Err(e) => return vec![Problem::new("datasource_scope", format!("the document registry: {e}"), None)],
    };
    wanted
        .into_iter()
        .filter(|(_, n)| !live.contains(n))
        .map(|(i, n)| {
            Problem::new(
                "datasource_scope",
                format!("datasource scope 'rag.{n}:read': the tenant has no document collection named '{n}'"),
                Some(format!("datasources.scopes[{i}]")),
            )
        })
        .collect()
}
