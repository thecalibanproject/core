//! Who is calling the admin API, and what they may do.
//!
//! Three ways in, checked in this order:
//! 1. `Authorization: Bearer <bootstrap token>` (`CALIBAN_ADMIN_TOKEN`): break-glass, owner rights.
//!    With SSO configured every use is logged and audited (`auth.break_glass`); mutations are
//!    always audited with the actor `break_glass`. `security.break_glass = false` turns it off.
//! 2. `Authorization: Bearer <JWT access token>` from the configured issuer, with the configured
//!    `api_audience` (CI, scripts). The user is created just in time on first sight.
//! 3. The console session cookie (set by `/auth/callback`). Server-side sessions with an absolute
//!    lifetime, an idle timeout and revocation. Requests that change something must carry the
//!    session's CSRF token in `X-CSRF-Token`, and a cross-origin `Origin` is refused.
//!
//! Roles come from the identity provider's groups (config `role_mappings` and group bindings) and
//! from bindings to the user; they are recomputed on every request, so a revoked binding takes
//! effect at once. [`authorize`] then checks the route's permission ([`rbac::ROUTES`]).

pub(crate) mod admin;
pub(crate) mod handlers;
#[cfg(test)]
pub(crate) mod mock_idp;
pub mod oidc;
pub mod rbac;
#[cfg(test)]
mod tests;

use crate::store::{Mutation, SessionRecord, State as StoreState, UserRecord, audit::AuditDraft, audit::now_micros};
use crate::{ApiError, Cp};
use axum::body::Body;
use axum::extract::{FromRequestParts, MatchedPath, OriginalUri, RawPathParams, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand::RngCore;
use rbac::{Grants, Perm, TenantFrom, Visible};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Audit actor of the bootstrap admin token.
pub const BREAK_GLASS_ACTOR: &str = "break_glass";

/// Session activity is written at most this often (idle timeout bookkeeping).
const TOUCH_EVERY: chrono::Duration = chrono::Duration::seconds(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    BreakGlass,
    Bearer,
    Session { session_id: String },
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::BreakGlass => "break_glass",
            AuthMethod::Bearer => "bearer",
            AuthMethod::Session { .. } => "session",
        }
    }
}

/// The authenticated caller of a request (a request extension for the handlers).
#[derive(Debug, Clone)]
pub struct Principal {
    pub method: AuthMethod,
    /// Recorded as the audit actor of everything this request changes.
    pub actor: String,
    pub user: Option<UserRecord>,
    pub groups: Vec<String>,
    pub grants: Grants,
    /// Sessions only: the token, needed to derive the CSRF token.
    session: Option<(SessionRecord, String)>,
}

impl Principal {
    fn break_glass() -> Self {
        Self {
            method: AuthMethod::BreakGlass,
            actor: BREAK_GLASS_ACTOR.into(),
            user: None,
            groups: vec![],
            grants: Grants::owner(),
            session: None,
        }
    }

    pub fn allows(&self, p: Perm, tenant: Option<&str>) -> bool {
        self.grants.allows(p, tenant)
    }

    pub fn visible(&self, p: Perm) -> Visible {
        self.grants.visible(p)
    }

    /// What `/auth/me` returns.
    pub fn describe(&self) -> Value {
        let (deployment, tenants) = self.grants.permissions();
        let mut roles: Vec<Value> = self.grants.deployment.iter().map(|r| json!({"role": r})).collect();
        for (t, rs) in &self.grants.tenants {
            roles.extend(rs.iter().map(|r| json!({"role": r, "tenant_id": t})));
        }
        let mut v = json!({
            "authenticated": true,
            "method": self.method.as_str(),
            "actor": self.actor,
            "user": self.user,
            "groups": self.groups,
            "roles": roles,
            "permissions": {"deployment": deployment, "tenants": tenants},
        });
        if let Some((s, token)) = &self.session {
            v["session"] = json!({"id": s.id, "created_at": s.created_at, "expires_at": s.expires_at});
            v["csrf_token"] = json!(csrf_token(token));
        }
        v
    }
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// 32 random bytes, base64url.
pub(crate) fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    B64URL.encode(b)
}

/// The CSRF token of a session, derived from its cookie token (which scripts cannot read).
pub(crate) fn csrf_token(session_token: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"caliban-csrf\0");
    h.update(session_token.as_bytes());
    B64URL.encode(h.finalize())
}

pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// Cookie names and attributes. An `https` console gets `Secure` cookies with the `__Host-`
/// prefix (no `Domain`, `Path=/`).
pub(crate) struct Cookies {
    secure: bool,
}

impl Cookies {
    pub(crate) fn of(cp: &crate::ControlPlane) -> Self {
        Self { secure: cp.oidc.as_ref().is_some_and(|o| o.settings.secure_cookies()) }
    }

    pub(crate) fn session_name(&self) -> &'static str {
        if self.secure { "__Host-caliban_session" } else { "caliban_session" }
    }

    pub(crate) fn login_name(&self) -> &'static str {
        if self.secure { "__Host-caliban_login" } else { "caliban_login" }
    }

    /// `SameSite=Strict` for the session; `Lax` for the login cookie, which must come back on the
    /// identity provider's redirect to `/auth/callback`.
    pub(crate) fn set(&self, name: &str, value: &str, max_age_secs: i64, same_site: &str) -> String {
        let secure = if self.secure { "; Secure" } else { "" };
        format!("{name}={value}; Path=/; HttpOnly; SameSite={same_site}; Max-Age={max_age_secs}{secure}")
    }

    pub(crate) fn clear(&self, name: &str, same_site: &str) -> String {
        self.set(name, "", 0, same_site)
    }
}

fn unauthorized(msg: &str) -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, msg.into())
}

pub(crate) fn forbidden(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::FORBIDDEN, msg.into())
}

/// The user record for a session's user id, refreshing the cached state once (another replica may
/// have created the user a moment ago).
async fn user_by_id(cp: &crate::ControlPlane, id: &str) -> Option<UserRecord> {
    if let Some(u) = cp.store.state().user(id) {
        return Some(u.clone());
    }
    let _ = cp.store.refresh().await;
    cp.store.state().user(id).cloned()
}

/// Roles of a user: config group mappings, group bindings and user bindings.
pub(crate) fn grants_for(cp: &crate::ControlPlane, st: &StoreState, user: &UserRecord, groups: &[String]) -> Grants {
    let mut g = Grants::default();
    if let Some(o) = &cp.oidc {
        for (group, role, tenant) in &o.settings.role_mappings {
            if groups.contains(group) {
                g.add(*role, tenant.as_deref());
            }
        }
    }
    for b in &st.role_bindings {
        let holds = match b.subject_kind {
            crate::store::SubjectKind::User => b.subject == user.id,
            crate::store::SubjectKind::Group => groups.contains(&b.subject),
        };
        if holds {
            g.add(b.role, b.tenant_id.as_deref());
        }
    }
    g
}

/// Authenticates a request (see the module docs). `method` decides whether the session's CSRF
/// token is required.
pub(crate) async fn authenticate(
    cp: &crate::ControlPlane,
    method: &Method,
    headers: &HeaderMap,
) -> Result<Principal, ApiError> {
    if let Some(token) = bearer(headers) {
        if let Some(admin) = cp.admin_token.as_deref()
            && constant_time_eq(token.as_bytes(), admin.as_bytes())
        {
            return Ok(Principal::break_glass());
        }
        if let Some(o) = cp.oidc.as_ref().filter(|o| o.accepts_bearer() && token.split('.').count() == 3) {
            let id = o.validate_access_token(token).await.map_err(|e| {
                tracing::warn!(reason = e.reason(), error = %e, "admin API access token rejected");
                unauthorized(&format!("invalid access token ({})", e.reason()))
            })?;
            return bearer_principal(cp, id).await;
        }
        return Err(unauthorized("invalid admin token"));
    }
    if cp.oidc.is_some()
        && let Some(token) = cookie(headers, Cookies::of(cp).session_name())
    {
        return session_principal(cp, method, headers, token).await;
    }
    Err(unauthorized("authentication required"))
}

async fn bearer_principal(cp: &crate::ControlPlane, id: oidc::Identity) -> Result<Principal, ApiError> {
    let known = cp.store.state().user_by_subject(&id.issuer, &id.subject).cloned();
    let user = match known {
        Some(u) => u,
        None => {
            let u = UserRecord {
                id: crate::store::new_id("usr"),
                issuer: id.issuer.clone(),
                subject: id.subject.clone(),
                email: id.email.clone(),
                name: id.name.clone(),
                created_at: now_micros(),
                last_login_at: None,
            };
            match cp.store.apply(&u.actor(), Mutation::CreateUser(u.clone())).await {
                Ok(st) => st.user_by_subject(&id.issuer, &id.subject).cloned().unwrap_or(u),
                Err(crate::store::StoreError::Conflict(_)) => {
                    let _ = cp.store.refresh().await;
                    cp.store.state().user_by_subject(&id.issuer, &id.subject).cloned().unwrap_or(u)
                }
                Err(e) => return Err(e.into()),
            }
        }
    };
    let grants = grants_for(cp, &cp.store.state(), &user, &id.groups);
    Ok(Principal {
        method: AuthMethod::Bearer,
        actor: user.actor(),
        user: Some(user),
        groups: id.groups,
        grants,
        session: None,
    })
}

async fn session_principal(
    cp: &crate::ControlPlane,
    method: &Method,
    headers: &HeaderMap,
    token: &str,
) -> Result<Principal, ApiError> {
    let o = cp.oidc.as_ref().ok_or_else(|| unauthorized("authentication required"))?;
    let s = cp.store.session(&sha256_hex(token)).await?.ok_or_else(|| unauthorized("session not found"))?;
    let now = now_micros();
    if s.revoked_at.is_some() {
        return Err(unauthorized("session revoked"));
    }
    let idle = chrono::Duration::from_std(o.settings.session_idle).unwrap_or(chrono::Duration::MAX);
    if s.expires_at <= now || s.last_seen_at + idle <= now {
        return Err(unauthorized("session expired"));
    }
    let unsafe_method = !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    if unsafe_method {
        check_csrf(o, headers, token)?;
    }
    let user = user_by_id(cp, &s.user_id).await.ok_or_else(|| unauthorized("session user not found"))?;
    if now - s.last_seen_at >= TOUCH_EVERY
        && let Err(e) = cp.store.touch_session(&s.id, now).await
    {
        tracing::warn!(error = %e, "recording session activity failed");
    }
    let grants = grants_for(cp, &cp.store.state(), &user, &s.groups);
    Ok(Principal {
        method: AuthMethod::Session { session_id: s.id.clone() },
        actor: user.actor(),
        groups: s.groups.clone(),
        user: Some(user),
        grants,
        session: Some((s, token.to_owned())),
    })
}

/// Cookie-authenticated writes: the `X-CSRF-Token` header must match the session, and an
/// `Origin` header, when the browser sends one, must be the console's.
fn check_csrf(o: &oidc::Oidc, headers: &HeaderMap, token: &str) -> Result<(), ApiError> {
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
        && origin != o.settings.console_origin()
    {
        return Err(forbidden("cross-origin request refused"));
    }
    let sent = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()).unwrap_or_default();
    if !constant_time_eq(sent.as_bytes(), csrf_token(token).as_bytes()) {
        return Err(forbidden("missing or invalid CSRF token (X-CSRF-Token)"));
    }
    Ok(())
}

/// Middleware on every admin API route: authenticates, records break-glass use, finds the route's
/// rule (no rule: denied) and the tenant it concerns, checks the permission, and hands the
/// [`Principal`] to the handler.
pub(crate) async fn authorize(State(cp): State<Cp>, req: Request, next: Next) -> Response {
    match authorize_inner(&cp, req).await {
        Ok(req) => next.run(req).await,
        Err(e) => e.into_response(),
    }
}

async fn authorize_inner(cp: &Cp, req: Request) -> Result<Request, ApiError> {
    let principal = authenticate(cp, req.method(), req.headers()).await?;
    let path = req.extensions().get::<MatchedPath>().map(|m| m.as_str().to_owned()).unwrap_or_default();
    if principal.method == AuthMethod::BreakGlass && cp.oidc.is_some() {
        let full =
            req.extensions().get::<OriginalUri>().map_or_else(|| req.uri().path().to_owned(), |u| u.path().to_owned());
        tracing::warn!(method = %req.method(), path = %full, "break-glass admin token used");
        let draft = AuditDraft {
            tenant_id: None,
            action: "auth.break_glass",
            target: None,
            detail: json!({"method": req.method().as_str(), "path": full}),
        };
        cp.store.apply(BREAK_GLASS_ACTOR, Mutation::Record(draft)).await?;
    }
    let Some(rule) = rbac::rule(req.method().as_str(), &path) else {
        return Err(forbidden("no permission is defined for this route"));
    };
    let (mut parts, body) = req.into_parts();
    let params = RawPathParams::from_request_parts(&mut parts, &()).await.ok();
    let param =
        |name: &str| params.as_ref().and_then(|p| p.iter().find(|(k, _)| *k == name).map(|(_, v)| v.to_owned()));
    let query_tenant = || {
        parts.uri.query().and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == "tenant_id").map(|(_, v)| v.into_owned())
        })
    };
    let p = &principal;
    let (allowed, body) = match rule.tenant {
        TenantFrom::None => (p.allows(rule.perm, None), body),
        TenantFrom::List => (p.grants.allows_somewhere(rule.perm), body),
        TenantFrom::Path => (param("tenant_id").is_some_and(|t| p.allows(rule.perm, Some(&t))), body),
        TenantFrom::QueryOrList => match query_tenant() {
            Some(t) => (p.allows(rule.perm, Some(&t)), body),
            None => (p.grants.allows_somewhere(rule.perm), body),
        },
        TenantFrom::Body => {
            let bytes = axum::body::to_bytes(body, 2 << 20)
                .await
                .map_err(|e| ApiError(StatusCode::PAYLOAD_TOO_LARGE, format!("request body: {e}")))?;
            let tenant = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v.get("tenant_id").and_then(Value::as_str).map(str::to_owned));
            let ok = match tenant {
                Some(t) => p.allows(rule.perm, Some(&t)),
                // Malformed bodies are the handler's to reject; it never acts without a tenant.
                None => p.grants.allows_somewhere(rule.perm),
            };
            (ok, Body::from(bytes))
        }
        TenantFrom::Datasource | TenantFrom::OntologyElement => {
            let id = param("id").unwrap_or_default();
            let st = cp.store.state();
            let tenant = if rule.tenant == TenantFrom::Datasource {
                st.datasources.iter().find(|d| d.id == id && d.is_live()).map(|d| d.tenant_id.clone())
            } else {
                st.ontologies
                    .values()
                    .find(|o| st.has_tenant(&o.tenant_id) && o.elements.iter().any(|e| e.id == id))
                    .map(|o| o.tenant_id.clone())
            };
            match tenant {
                Some(t) => (p.allows(rule.perm, Some(&t)), body),
                // Unknown id: the handler answers 404 to anyone who could act on some tenant.
                None => (p.grants.allows_somewhere(rule.perm), body),
            }
        }
    };
    if !allowed {
        return Err(forbidden(format!("permission '{}' is required", rule.perm.as_str())));
    }
    parts.extensions.insert(principal);
    Ok(Request::from_parts(parts, body))
}

/// Purges expired sessions and pending logins periodically.
pub fn spawn_purge(cp: Cp, every: std::time::Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match cp.store.purge_auth(now_micros()).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(removed = n, "purged expired sessions and logins"),
                Err(e) => tracing::warn!(error = %e, "purging expired sessions failed"),
            }
        }
    })
}
