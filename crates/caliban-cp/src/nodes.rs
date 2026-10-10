//! Node versions on the admin API (P3 M1).
//!
//! A version is immutable and content-hashed. It is created as a `draft`, then **published**
//! (`NodesPublish`): validated against the tenant ([`caliban_nodes::publish`]), its spec sealed
//! under the tenant's DEK, and shipped to routers and workers in the signed snapshot. The
//! **promotion pointer** names the live version of each node (what a run without a version runs);
//! publishing promotes by default, and `promote` moves the pointer to another published version
//! (rollback). **Retiring** a version takes it off the data plane. Every transition is audited.

use crate::auth::Principal;
use crate::store::{Mutation, NodeRecord, NodeState, State, audit::now_micros, new_id};
use crate::{ApiError, ApiResult, Cp, bad, keys, not_found};
use axum::Json;
use axum::extract::{Extension, Path, Query, State as AxState};
use axum::http::StatusCode;
use caliban_nodes::NodeSpec;
use caliban_nodes::publish::Problem;
use serde::Deserialize;
use serde_json::{Value, json};

/// A version as the API shows it: the record plus whether it is the live one.
pub(crate) fn view(st: &State, n: &NodeRecord) -> Value {
    let mut v = serde_json::to_value(n).unwrap_or_default();
    v["live"] = json!(st.promotion(&n.tenant_id, &n.name).is_some_and(|p| p.version == n.version));
    v
}

fn invalid(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
}

/// The error of the routes that validate a version: a refusal (`422`) carries the list of problems
/// next to the message, `{"error": {"message", "type", "code": "validation_failed", "problems":
/// [{"kind", "message", "path"?}]}}`, so the console does not have to split the message.
pub(crate) enum NodeError {
    Api(ApiError),
    Problems(String, Vec<Problem>),
}

impl From<ApiError> for NodeError {
    fn from(e: ApiError) -> Self {
        Self::Api(e)
    }
}

impl From<crate::StoreError> for NodeError {
    fn from(e: crate::StoreError) -> Self {
        match e {
            crate::StoreError::Rejected(p) => Self::Problems(p.to_string(), p.problems),
            other => Self::Api(other.into()),
        }
    }
}

impl axum::response::IntoResponse for NodeError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Api(e) => e.into_response(),
            Self::Problems(message, problems) => {
                let body = json!({"error": {"message": message, "type": "invalid_request_error",
                                            "code": "validation_failed", "problems": problems}});
                (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
            }
        }
    }
}

type NodeResult<T> = Result<T, NodeError>;

/// Parses and statically validates a spec.
fn checked(spec: &Value) -> NodeResult<NodeSpec> {
    let parsed: NodeSpec = serde_json::from_value(spec.clone()).map_err(|e| {
        let m = format!("invalid node spec: {e}");
        NodeError::Problems(m.clone(), vec![Problem::new("spec", m, None)])
    })?;
    parsed
        .validate()
        .map_err(|e| NodeError::Problems(e.to_string(), vec![Problem::new("spec", e.to_string(), None)]))?;
    Ok(parsed)
}

/// Creates a draft version of node `name` (version = latest + 1).
async fn draft(cp: &Cp, p: &Principal, tenant_id: String, name: String, spec: Value) -> NodeResult<Value> {
    crate::ensure_tenant(cp, &tenant_id)?;
    if !caliban_nodes::valid_node_name(&name) {
        return Err(
            invalid(format!("'{name}' is not a node name (1 to 64 characters of a-z, 0-9, '-' and '_')")).into()
        );
    }
    checked(&spec)?;
    let id = new_id("node");
    let rec = NodeRecord {
        id: id.clone(),
        tenant_id,
        name,
        version: 0,
        hash: caliban_nodes::hash::content_hash(&spec),
        spec,
        state: NodeState::Draft,
        created_at: now_micros(),
        created_by: Some(p.actor.clone()),
        published_at: None,
        retired_at: None,
        sealed_spec: None,
        deleted_at: None,
    };
    let st = cp.store.apply(&p.actor, Mutation::CreateNode(rec)).await?;
    Ok(st.nodes.iter().find(|n| n.id == id).map(|n| view(&st, n)).ok_or_else(|| not_found("node"))?)
}

#[derive(Deserialize)]
pub(crate) struct NodeCreate {
    tenant_id: String,
    name: String,
    spec: Value,
}

/// `POST /nodes`: a new draft version (kept for compatibility; same as `POST .../versions`).
pub(crate) async fn create_node(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Json(body): Json<NodeCreate>,
) -> NodeResult<(StatusCode, Json<Value>)> {
    Ok((StatusCode::CREATED, Json(draft(&cp, &p, body.tenant_id, body.name, body.spec).await?)))
}

#[derive(Deserialize)]
pub(crate) struct VersionCreate {
    spec: Value,
}

pub(crate) async fn create_version(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name)): Path<(String, String)>,
    Json(body): Json<VersionCreate>,
) -> NodeResult<(StatusCode, Json<Value>)> {
    Ok((StatusCode::CREATED, Json(draft(&cp, &p, tenant_id, name, body.spec).await?)))
}

pub(crate) async fn list_versions(
    AxState(cp): AxState<Cp>,
    Path((tenant_id, name)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let st = cp.store.state();
    let versions: Vec<Value> = st.node_versions(&tenant_id, &name).map(|n| view(&st, n)).collect();
    if versions.is_empty() {
        return Err(not_found("node"));
    }
    let live = st.promotion(&tenant_id, &name);
    Ok(Json(json!({"name": name, "live": live.map(|p| p.version), "promotion": live, "versions": versions})))
}

fn version_of(st: &State, tenant: &str, name: &str, version: u32) -> ApiResult<NodeRecord> {
    st.node_version(tenant, name, version).cloned().ok_or_else(|| not_found("node version"))
}

pub(crate) async fn get_version(
    AxState(cp): AxState<Cp>,
    Path((tenant_id, name, version)): Path<(String, String, u32)>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let st = cp.store.state();
    Ok(Json(view(&st, &version_of(&st, &tenant_id, &name, version)?)))
}

#[derive(Deserialize, Default)]
pub(crate) struct PublishBody {
    /// Also make it the live version (default `true`).
    promote: Option<bool>,
}

/// Validates the draft against the tenant, seals its spec under the tenant's DEK and publishes it.
pub(crate) async fn publish(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name, version)): Path<(String, String, u32)>,
    body: axum::body::Bytes,
) -> NodeResult<Json<Value>> {
    // The body is optional (an empty POST publishes and promotes).
    let body: PublishBody = if body.iter().all(u8::is_ascii_whitespace) {
        PublishBody::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| bad(format!("invalid body: {e}")))?
    };
    crate::ensure_tenant(&cp, &tenant_id)?;
    let n = version_of(&cp.store.state(), &tenant_id, &name, version)?;
    if n.state != NodeState::Draft {
        return Err(
            ApiError(StatusCode::CONFLICT, format!("{name}@v{version} is {}, not a draft", n.state.as_str())).into()
        );
    }
    // Sealed like BYOK keys: routers and workers open it with their keyring.
    let keyring = cp.keyring("node versions").map_err(|_| bad("cannot publish nodes: CALIBAN_KEK is not set"))?;
    let dek = keys::tenant_dek(&cp.store, keyring, &tenant_id, &p.actor).await?;
    let m = Mutation::PublishNode {
        tenant_id: tenant_id.clone(),
        name: name.clone(),
        version,
        sealed_spec: dek.seal(&tenant_id, &n.spec.to_string()),
        promote: body.promote.unwrap_or(true),
        at: now_micros(),
        by: p.actor.clone(),
    };
    let st = cp.store.apply(&p.actor, m).await?;
    Ok(Json(view(&st, &version_of(&st, &tenant_id, &name, version)?)))
}

#[derive(Deserialize)]
pub(crate) struct PromoteBody {
    version: u32,
}

/// Moves the promotion pointer to a published version (rollback included).
pub(crate) async fn promote(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name)): Path<(String, String)>,
    Json(body): Json<PromoteBody>,
) -> NodeResult<Json<Value>> {
    let m = Mutation::PromoteNode {
        tenant_id: tenant_id.clone(),
        name: name.clone(),
        version: body.version,
        at: now_micros(),
        by: p.actor.clone(),
    };
    let st = cp.store.apply(&p.actor, m).await?;
    Ok(Json(view(&st, &version_of(&st, &tenant_id, &name, body.version)?)))
}

pub(crate) async fn retire(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, name, version)): Path<(String, String, u32)>,
) -> ApiResult<Json<Value>> {
    let m = Mutation::RetireNode { tenant_id: tenant_id.clone(), name: name.clone(), version, at: now_micros() };
    let st = cp.store.apply(&p.actor, m).await?;
    Ok(Json(view(&st, &version_of(&st, &tenant_id, &name, version)?)))
}

#[derive(Deserialize)]
pub(crate) struct DiffQuery {
    from: u32,
    to: u32,
}

/// What changed between two versions: their hashes and a structural JSON diff of their specs.
pub(crate) async fn diff(
    AxState(cp): AxState<Cp>,
    Path((tenant_id, name)): Path<(String, String)>,
    Query(q): Query<DiffQuery>,
) -> ApiResult<Json<Value>> {
    crate::ensure_tenant(&cp, &tenant_id)?;
    let st = cp.store.state();
    let (a, b) = (version_of(&st, &tenant_id, &name, q.from)?, version_of(&st, &tenant_id, &name, q.to)?);
    Ok(Json(json!({
        "name": name,
        "from": {"version": a.version, "hash": a.hash, "state": a.state},
        "to": {"version": b.version, "hash": b.hash, "state": b.state},
        "identical": a.hash == b.hash,
        "changes": caliban_nodes::diff::json_diff(&a.spec, &b.spec),
    })))
}

#[derive(Deserialize)]
pub(crate) struct TenantFilter {
    tenant_id: Option<String>,
}

/// Every version of every node (drafts, published and retired; not deleted), across the tenants
/// the caller may read.
pub(crate) async fn list_nodes(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Query(f): Query<TenantFilter>,
) -> Json<Vec<Value>> {
    let st = cp.store.state();
    let visible = p.visible(crate::auth::rbac::Perm::NodesRead);
    Json(
        st.nodes
            .iter()
            .filter(|n| n.is_live() && f.tenant_id.as_ref().is_none_or(|t| &n.tenant_id == t))
            .filter(|n| visible.contains(&n.tenant_id))
            .map(|n| view(&st, n))
            .collect(),
    )
}

/// Soft-deletes one node version (a draft or a retired one), scoped to the tenant. Its version
/// number is not reused.
pub(crate) async fn delete_node(
    AxState(cp): AxState<Cp>,
    Extension(p): Extension<Principal>,
    Path((tenant_id, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    cp.store.apply(&p.actor, Mutation::DeleteNode { tenant_id, id, at: now_micros() }).await?;
    Ok(StatusCode::NO_CONTENT)
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
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn ring() -> Keyring {
        Keyring::new([7; 32], [])
    }

    fn cp(keyring: Option<Keyring>) -> Arc<ControlPlane> {
        let cfg = Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
        let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
        Arc::new(
            ControlPlane::new(Store::new(cfg, handle, RecentUsage::default()), "admin-secret".into(), "standalone")
                .with_keyring(keyring.map(Arc::new)),
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

    fn spec(steps: u32) -> Value {
        json!({"kind": "agent", "prompt": {"system": "Triage the case."}, "model_policy": {}, "tools": [],
               "budgets": {"steps": steps, "tokens": 1000, "wall_clock_s": 30}})
    }

    const V: &str = "/api/v1/tenants/acme/nodes/triage";

    #[tokio::test]
    async fn versions_are_published_promoted_and_retired() {
        let c = cp(Some(ring()));
        let app = app(Arc::clone(&c), None);
        let (s, v1) = call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": spec(3)}))).await;
        assert_eq!(s, StatusCode::CREATED, "{v1}");
        assert_eq!(
            (v1["version"].as_u64(), v1["state"].as_str(), v1["live"].as_bool()),
            (Some(1), Some("draft"), Some(false))
        );
        assert_eq!(v1["hash"], caliban_nodes::hash::content_hash(&spec(3)));
        assert_eq!(v1["created_by"], "break_glass");
        // The same content in another key order hashes the same; a draft is not shipped.
        let reordered: Value = serde_json::from_str(
            r#"{"budgets": {"wall_clock_s": 30, "tokens": 1000, "steps": 3}, "tools": [], "model_policy": {},
                "prompt": {"system": "Triage the case."}, "kind": "agent"}"#,
        )
        .unwrap();
        let (_, v2) = call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": reordered}))).await;
        assert_eq!((v2["version"].as_u64(), &v2["hash"]), (Some(2), &v1["hash"]));
        let (_, d) = call(&app, "GET", &format!("{V}/diff?from=1&to=2"), None).await;
        assert_eq!((d["identical"].as_bool(), d["changes"].as_array().map(Vec::len)), (Some(true), Some(0)));
        assert!(c.store.config.load().tenant(&"acme".into()).unwrap().nodes.is_empty());

        let (s, p1) = call(&app, "POST", &format!("{V}/versions/1/publish"), None).await;
        assert_eq!(s, StatusCode::OK, "{p1}");
        assert_eq!((p1["state"].as_str(), p1["live"].as_bool()), (Some("published"), Some(true)));
        assert_eq!(call(&app, "POST", &format!("{V}/versions/1/publish"), None).await.0, StatusCode::CONFLICT);
        // The data plane gets it sealed under the tenant key; the keyring opens it, and its hash
        // is the version's hash.
        let snap = c.store.config.load();
        let t = snap.tenant(&"acme".into()).unwrap();
        let shipped = t.node("triage", None).unwrap();
        assert_eq!((shipped.version, shipped.live), (1, true));
        assert!(!serde_json::to_string(&snap.config).unwrap().contains("Triage the case"), "sealed in the snapshot");
        let opened: Value = serde_json::from_str(&shipped.open_spec(&ring()).unwrap()).unwrap();
        assert_eq!(caliban_nodes::hash::content_hash(&opened), shipped.hash);
        assert!(shipped.open_spec(&Keyring::new([8; 32], [])).is_err());
        assert!(t.data_key.is_some());

        // v3 changes the budget: published without promotion, then promoted, then rolled back.
        call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": spec(5)}))).await;
        let (_, d) = call(&app, "GET", &format!("{V}/diff?from=1&to=3"), None).await;
        assert_eq!(d["changes"], json!([{"path": "/budgets/steps", "op": "changed", "from": 3, "to": 5}]));
        let (s, p3) = call(&app, "POST", &format!("{V}/versions/3/publish"), Some(json!({"promote": false}))).await;
        assert_eq!((s, p3["live"].as_bool()), (StatusCode::OK, Some(false)));
        let (s, _) = call(&app, "POST", &format!("{V}/promote"), Some(json!({"version": 3}))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(c.store.config.load().tenant(&"acme".into()).unwrap().node("triage", None).unwrap().version, 3);
        assert_eq!(
            call(&app, "POST", &format!("{V}/promote"), Some(json!({"version": 2}))).await.0,
            StatusCode::CONFLICT
        );
        call(&app, "POST", &format!("{V}/promote"), Some(json!({"version": 1}))).await;
        let (_, list) = call(&app, "GET", &format!("{V}/versions"), None).await;
        assert_eq!(list["live"], 1);
        let states: Vec<(u64, &str)> = list["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| (v["version"].as_u64().unwrap(), v["state"].as_str().unwrap()))
            .collect();
        assert_eq!(states, [(1, "published"), (2, "draft"), (3, "published")]);

        // Retire the live version: it leaves the data plane and the pointer is cleared.
        let (s, r) = call(&app, "POST", &format!("{V}/versions/1/retire"), None).await;
        assert_eq!((s, r["state"].as_str(), r["live"].as_bool()), (StatusCode::OK, Some("retired"), Some(false)));
        let snap = c.store.config.load();
        let t = snap.tenant(&"acme".into()).unwrap();
        assert!(t.node("triage", None).is_none(), "nothing is live");
        assert_eq!(t.nodes.iter().map(|n| n.version).collect::<Vec<_>>(), [3], "only published versions ship");
        // Published versions are retired before they are deleted; drafts are deleted directly.
        let id_of = |v: &Value| v["id"].as_str().unwrap().to_owned();
        assert_eq!(
            call(&app, "DELETE", &format!("/api/v1/tenants/acme/nodes/{}", id_of(&p3)), None).await.0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(&app, "DELETE", &format!("/api/v1/tenants/acme/nodes/{}", id_of(&v2)), None).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(call(&app, "GET", &format!("{V}/versions/2"), None).await.0, StatusCode::NOT_FOUND);

        // Audited with hashes.
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=20", None).await;
        assert_eq!(a["chain_verified"], true);
        let actions: Vec<&str> =
            a["entries"].as_array().unwrap().iter().map(|e| e["action"].as_str().unwrap()).collect();
        for want in ["node.create", "tenant_key.create", "node.publish", "node.promote", "node.retire", "node.delete"] {
            assert!(actions.contains(&want), "{want} in {actions:?}");
        }
        let retire = a["entries"].as_array().unwrap().iter().find(|e| e["action"] == "node.retire").unwrap();
        assert_eq!(retire["detail"]["was_live"], true);
        assert_eq!(retire["detail"]["hash"], v1["hash"]);
    }

    #[tokio::test]
    async fn publishing_is_validated_against_the_tenant() {
        let c = cp(Some(ring()));
        let app = app(Arc::clone(&c), None);
        // Static checks at creation: code vertices are not supported yet.
        let code = json!({"kind": "workflow", "model_policy": {}, "budgets": {"steps": 3, "tokens": 10, "wall_clock_s": 5},
                          "graph": {"vertices": [{"id": "t", "type": "code"}], "edges": []}});
        let (s, e) = call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": code}))).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(e["error"]["message"].as_str().unwrap().contains("not yet supported"), "{e}");
        assert_eq!(
            (e["error"]["code"].as_str(), e["error"]["problems"][0]["kind"].as_str()),
            (Some("validation_failed"), Some("spec"))
        );
        let (s, _) =
            call(&app, "POST", "/api/v1/tenants/acme/nodes/BadName/versions", Some(json!({"spec": spec(3)}))).await;
        assert!(s.is_client_error());

        // Datasource scopes must exist for the tenant.
        let mut scoped = spec(3);
        scoped["datasources"] = json!({"scopes": ["erp.invoices:read"]});
        call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": scoped}))).await;
        let (s, e) = call(&app, "POST", &format!("{V}/versions/1/publish"), None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(e["error"]["message"].as_str().unwrap().contains("no datasource named 'erp'"), "{e}");
        // The problems, one by one, for the console.
        assert_eq!(
            e["error"]["problems"],
            json!([{"kind": "datasource_scope", "path": "datasources.scopes[0]",
                    "message": e["error"]["problems"][0]["message"]}])
        );
        assert!(e["error"]["problems"][0]["message"].as_str().unwrap().contains("no datasource named 'erp'"));
        let ds = json!({"tenant_id": "acme", "kind": "postgres", "name": "erp", "connection": {}});
        assert_eq!(call(&app, "POST", "/api/v1/datasources", Some(ds)).await.0, StatusCode::CREATED);
        let (s, e) = call(&app, "POST", &format!("{V}/versions/1/publish"), None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(e["error"]["message"].as_str().unwrap().contains("no approved ontology entity"), "{e}");
        let mut any = spec(3);
        any["datasources"] = json!({"scopes": ["erp.*:read"]});
        call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": any}))).await;
        assert_eq!(call(&app, "POST", &format!("{V}/versions/2/publish"), None).await.0, StatusCode::OK);

        // Budgets must fit the tenant's caps (PATCH like the other tenant settings).
        let (s, t) = call(
            &app,
            "PATCH",
            "/api/v1/tenants/acme",
            Some(json!({"node_caps": {"steps": 4, "tokens": 500, "wall_clock_s": 60, "depth": 3, "fanout": 8}})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{t}");
        assert_eq!(t["node_caps"]["steps"], 4);
        call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": spec(3)}))).await;
        let (s, e) = call(&app, "POST", &format!("{V}/versions/3/publish"), None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(
            e["error"]["message"]
                .as_str()
                .unwrap()
                .contains("budgets.tokens = 1000 exceeds the tenant's node cap of 500"),
            "{e}"
        );
        let (s, _) = call(
            &app,
            "PATCH",
            "/api/v1/tenants/acme",
            Some(json!({"node_caps": {"steps": 0, "tokens": 1, "wall_clock_s": 1, "depth": 1, "fanout": 1}})),
        )
        .await;
        assert!(s.is_client_error());
        let (s, t) = call(&app, "PATCH", "/api/v1/tenants/acme", Some(json!({"node_caps": null}))).await;
        assert_eq!((s, t["node_caps"].clone()), (StatusCode::OK, Value::Null));

        // node:// references resolve to a published version of the same tenant.
        let mut caller = spec(3);
        caller["tools"] = json!([{"ref": "node://triage@v1", "effect": "read"}]);
        call(&app, "POST", "/api/v1/tenants/acme/nodes/caller/versions", Some(json!({"spec": caller}))).await;
        let (s, e) = call(&app, "POST", "/api/v1/tenants/acme/nodes/caller/versions/1/publish", None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(e["error"]["message"].as_str().unwrap().contains("node://triage@v1 is a draft"), "{e}");
        caller["tools"] = json!([{"ref": "node://triage@v2", "effect": "read"}]);
        call(&app, "POST", "/api/v1/tenants/acme/nodes/caller/versions", Some(json!({"spec": caller}))).await;
        assert_eq!(
            call(&app, "POST", "/api/v1/tenants/acme/nodes/caller/versions/2/publish", None).await.0,
            StatusCode::OK
        );
        let (s, e) = call(&app, "POST", &format!("{V}/versions/2/retire"), None).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(e["error"]["message"].as_str().unwrap().contains("called by caller@v2"), "{e}");

        // Without a KEK nothing can be sealed, so nothing is published.
        let plain = app_without_kek();
        call(&plain, "POST", &format!("{V}/versions"), Some(json!({"spec": spec(3)}))).await;
        let (s, e) = call(&plain, "POST", &format!("{V}/versions/1/publish"), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(e["error"]["message"].as_str().unwrap().contains("CALIBAN_KEK"));
    }

    fn app_without_kek() -> Router {
        app(cp(None), None)
    }

    #[tokio::test]
    async fn api_keys_carry_node_allowlists() {
        let c = cp(Some(ring()));
        let app = app(Arc::clone(&c), None);
        let (s, k) = call(
            &app,
            "POST",
            "/api/v1/tenants/acme/api-keys",
            Some(json!({"name": "triage-only", "nodes": ["triage"]})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{k}");
        assert_eq!(k["nodes"], json!(["triage"]));
        let (_, all) = call(&app, "POST", "/api/v1/tenants/acme/api-keys", Some(json!({"name": "all"}))).await;
        assert!(all["nodes"].is_null(), "no allowlist: every published node");
        let (s, _) = call(&app, "POST", "/api/v1/tenants/acme/api-keys", Some(json!({"nodes": ["Not A Node"]}))).await;
        assert!(s.is_client_error());
        let snap = c.store.config.load();
        let t = snap.tenant(&"acme".into()).unwrap();
        let hash = |k: &Value| caliban_types::hash_api_key(k["key"].as_str().unwrap());
        assert!(t.key_may_run(&hash(&k), "triage") && !t.key_may_run(&hash(&k), "other"));
        assert!(t.key_may_run(&hash(&all), "other"));
        let (_, a) = call(&app, "GET", "/api/v1/audit?limit=5", None).await;
        let created = a["entries"].as_array().unwrap().iter().find(|e| e["detail"]["name"] == "triage-only").unwrap();
        assert_eq!(created["detail"]["nodes"], json!(["triage"]));
    }

    #[tokio::test]
    async fn the_datasource_tool_ships_sealed_datasources_and_the_approved_ontology() {
        let c = cp(Some(ring()));
        let app = app(Arc::clone(&c), None);
        let ds = json!({"tenant_id": "acme", "kind": "mongodb", "name": "shop",
                        "connection": {"uri": "mongodb://reader:s3cret@db:27017", "database": "shop"}});
        assert_eq!(call(&app, "POST", "/api/v1/datasources", Some(ds)).await.0, StatusCode::CREATED);
        let mut s = spec(3);
        s["tools"] = json!([{"ref": "builtin://datasource_query", "effect": "write"}]);
        let (st, e) = call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": s}))).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "read only: {e}");
        s["tools"] = json!([{"ref": "builtin://datasource_query", "effect": "read"}]);
        let (st, e) = call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": s.clone()}))).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "needs scopes: {e}");
        s["datasources"] = json!({"scopes": ["shop.*:read"]});
        call(&app, "POST", &format!("{V}/versions"), Some(json!({"spec": s}))).await;
        // Nothing ships before a published node uses the tool.
        assert!(c.store.config.load().tenant(&"acme".into()).unwrap().datasources.is_empty());
        assert_eq!(call(&app, "POST", &format!("{V}/versions/1/publish"), None).await.0, StatusCode::OK);
        let snap = c.store.config.load();
        let t = snap.tenant(&"acme".into()).unwrap();
        assert_eq!(t.datasources.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["shop"]);
        assert!(!serde_json::to_string(&snap.config).unwrap().contains("s3cret"), "credentials stay sealed");
        // A key can be narrowed to some scopes.
        let (st, k) = call(
            &app,
            "POST",
            "/api/v1/tenants/acme/api-keys",
            Some(json!({"name": "orders-only", "datasource_scopes": ["shop.orders:read"]})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "{k}");
        let hash = caliban_types::hash_api_key(k["key"].as_str().unwrap());
        let snap = c.store.config.load();
        assert_eq!(snap.tenant(&"acme".into()).unwrap().api_key_datasource_scopes[&hash], ["shop.orders:read"]);
    }
}
