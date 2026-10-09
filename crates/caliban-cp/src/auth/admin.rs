//! Users and roles admin API: `/api/v1/roles`, `/api/v1/users`, `/api/v1/role-bindings`.
//!
//! Only an owner (or the break-glass token) can grant or revoke the `owner` role; admins manage
//! every other binding. Every change is audited with the caller as actor.

use super::Principal;
use super::rbac::{Perm, Role};
use crate::store::audit::now_micros;
use crate::store::{Mutation, RoleBinding, SubjectKind, new_id};
use crate::{ApiResult, Cp, bad, not_found};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

pub(crate) async fn roles() -> Json<Value> {
    Json(Value::Array(
        Role::ALL
            .iter()
            .map(|r| {
                json!({
                    "role": r,
                    "scope": if r.is_tenant_role() { "tenant" } else { "deployment" },
                    "description": r.description(),
                    "permissions": r.permissions().iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                })
            })
            .collect(),
    ))
}

/// Users known to the control plane, with the bindings that name them and their active sessions.
pub(crate) async fn list_users(State(cp): State<Cp>) -> ApiResult<Json<Value>> {
    let st = cp.store.state();
    let now = now_micros();
    let idle = cp
        .oidc
        .as_ref()
        .and_then(|o| chrono::Duration::from_std(o.settings.session_idle).ok())
        .unwrap_or(chrono::Duration::MAX);
    let mut out = Vec::with_capacity(st.users.len());
    for u in &st.users {
        let bindings: Vec<&RoleBinding> =
            st.role_bindings.iter().filter(|b| b.subject_kind == SubjectKind::User && b.subject == u.id).collect();
        let sessions = cp.store.active_sessions(&u.id, now).await?;
        let sessions = sessions.iter().filter(|s| s.last_seen_at + idle > now).count();
        let mut v = serde_json::to_value(u).unwrap_or_default();
        v["role_bindings"] = json!(bindings);
        v["active_sessions"] = json!(sessions);
        out.push(v);
    }
    Ok(Json(Value::Array(out)))
}

/// Signs the user out everywhere (every active session is revoked).
pub(crate) async fn revoke_sessions(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    cp.store.apply(&p.actor, Mutation::RevokeUserSessions { user_id: id, at: now_micros() }).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Stored bindings, and the group mappings from the config file (read-only here).
pub(crate) async fn list_bindings(State(cp): State<Cp>) -> Json<Value> {
    let st = cp.store.state();
    let mappings: Vec<Value> = cp
        .oidc
        .as_ref()
        .map(|o| {
            o.settings
                .role_mappings
                .iter()
                .map(|(group, role, tenant)| json!({"group": group, "role": role, "tenant_id": tenant, "source": "config"}))
                .collect()
        })
        .unwrap_or_default();
    Json(json!({
        "bindings": st.role_bindings,
        "group_mappings": mappings,
        "groups_claim": cp.oidc.as_ref().map(|o| o.settings.groups_claim.clone()),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingCreate {
    subject_kind: SubjectKind,
    subject: String,
    role: String,
    tenant_id: Option<String>,
}

fn owner_guard(p: &Principal, role: Role) -> ApiResult<()> {
    if role == Role::Owner && !p.grants.has(Role::Owner) {
        return Err(super::forbidden("only an owner can grant or revoke the owner role"));
    }
    Ok(())
}

pub(crate) async fn create_binding(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Json(body): Json<BindingCreate>,
) -> ApiResult<(StatusCode, Json<RoleBinding>)> {
    let role = Role::parse(&body.role).ok_or_else(|| {
        bad(format!("unknown role '{}' (one of {})", body.role, Role::ALL.map(Role::as_str).join(", ")))
    })?;
    owner_guard(&p, role)?;
    debug_assert!(p.allows(Perm::RbacWrite, None));
    let b = RoleBinding {
        id: new_id("rb"),
        subject_kind: body.subject_kind,
        subject: body.subject.trim().to_owned(),
        role,
        tenant_id: body.tenant_id.filter(|t| !t.is_empty()),
        created_at: now_micros(),
        created_by: p.actor.clone(),
    };
    cp.store.apply(&p.actor, Mutation::CreateRoleBinding(b.clone())).await?;
    Ok((StatusCode::CREATED, Json(b)))
}

pub(crate) async fn delete_binding(
    State(cp): State<Cp>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let role = cp
        .store
        .state()
        .role_bindings
        .iter()
        .find(|b| b.id == id)
        .map(|b| b.role)
        .ok_or_else(|| not_found("role binding"))?;
    owner_guard(&p, role)?;
    cp.store.apply(&p.actor, Mutation::DeleteRoleBinding { id }).await?;
    Ok(StatusCode::NO_CONTENT)
}
