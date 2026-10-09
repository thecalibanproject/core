//! `/auth/*`: the console's login, callback, logout and session endpoints. The control plane is
//! the backend for the console (BFF): tokens from the identity provider never reach the browser,
//! which only holds an opaque, HttpOnly session cookie.

use super::{AuthMethod, Cookies, authenticate, constant_time_eq, cookie, random_token, sha256_hex};
use crate::store::audit::{AuditDraft, now_micros};
use crate::store::{Mutation, PendingLogin, SessionRecord, UserRecord, new_id};
use crate::{ApiError, ApiResult, Cp};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::get, routing::post};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;

/// How long a login may take between `/auth/login` and `/auth/callback`.
const LOGIN_TTL: Duration = Duration::from_secs(600);

pub(crate) fn routes() -> Router<Cp> {
    Router::new()
        .route("/auth/config", get(config))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
}

fn sso_disabled() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "single sign-on is not configured".into())
}

/// Public: how the console should offer login.
async fn config(State(cp): State<Cp>) -> Json<Value> {
    Json(json!({
        "sso_enabled": cp.oidc.is_some(),
        "break_glass_enabled": cp.admin_token.is_some(),
        "login_url": cp.oidc.as_ref().map(|_| "/auth/login"),
    }))
}

async fn me(State(cp): State<Cp>, method: Method, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let p = authenticate(&cp, &method, &headers).await?;
    Ok(Json(p.describe()))
}

#[derive(Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
}

/// Only paths on this origin: `/...`, never `//host` or `/\host`.
fn safe_return_to(r: Option<&str>) -> String {
    match r {
        Some(r)
            if r.starts_with('/')
                && !r.starts_with("//")
                && !r.starts_with("/\\")
                && r.len() <= 512
                && !r.chars().any(char::is_control) =>
        {
            r.to_owned()
        }
        _ => "/".into(),
    }
}

/// Where the console shows a login error (hash routing).
fn to_console_error(code: &str) -> Response {
    redirect(&format!("/#/login?error={code}"), vec![])
}

fn redirect(location: &str, cookies: Vec<String>) -> Response {
    let mut r = (StatusCode::SEE_OTHER, [(header::LOCATION, location.to_owned())]).into_response();
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(&c) {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// Starts the authorization code flow: state, nonce and PKCE verifier are stored server-side,
/// bound to this browser by a short-lived login cookie, and the browser goes to the provider.
async fn login(State(cp): State<Cp>, Query(q): Query<LoginQuery>) -> ApiResult<Response> {
    let o = cp.oidc.as_ref().ok_or_else(sso_disabled)?;
    let (state, nonce, verifier, binding) = (random_token(), random_token(), random_token(), random_token());
    let url = match o.authorize_url(&state, &nonce, &verifier).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(error = %e, "cannot start SSO login");
            return Ok(to_console_error("idp_unavailable"));
        }
    };
    let now = now_micros();
    cp.store
        .put_login(&PendingLogin {
            state,
            binding_sha256: sha256_hex(&binding),
            nonce,
            pkce_verifier: verifier,
            return_to: safe_return_to(q.return_to.as_deref()),
            created_at: now,
            expires_at: now + chrono::Duration::from_std(LOGIN_TTL).unwrap_or_default(),
        })
        .await?;
    let c = Cookies::of(&cp);
    let set = c.set(c.login_name(), &binding, i64::try_from(LOGIN_TTL.as_secs()).unwrap_or(600), "Lax");
    Ok(redirect(&url, vec![set]))
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Records a failed login attempt (one that started at `/auth/login` in this browser).
async fn login_failed(cp: &Cp, reason: &str, detail: Value) -> Response {
    tracing::warn!(reason, %detail, "SSO login failed");
    let draft = AuditDraft {
        tenant_id: None,
        action: "auth.login_failed",
        target: None,
        detail: json!({"reason": reason, "detail": detail}),
    };
    if let Err(e) = cp.store.apply("anonymous", Mutation::Record(draft)).await {
        tracing::error!(error = %e, "auditing a failed login failed");
    }
    to_console_error("login_failed")
}

async fn callback(State(cp): State<Cp>, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> ApiResult<Response> {
    let o = cp.oidc.as_ref().ok_or_else(sso_disabled)?;
    let c = Cookies::of(&cp);
    let clear_login = c.clear(c.login_name(), "Lax");
    // Unknown or reused state: nothing ties this request to a login, so it is logged, not audited
    // (otherwise anyone could fill the audit log).
    let Some(pending) = (match q.state.as_deref() {
        Some(s) => cp.store.take_login(s).await?,
        None => None,
    }) else {
        tracing::warn!("SSO callback with an unknown, used or missing state");
        return Ok(redirect("/#/login?error=login_expired", vec![clear_login]));
    };
    let binding = cookie(&headers, c.login_name()).map(sha256_hex).unwrap_or_default();
    let fail = |reason: &'static str, detail: Value| {
        let cp = cp.clone();
        let clear = clear_login.clone();
        async move {
            let mut r = login_failed(&cp, reason, detail).await;
            if let Ok(v) = HeaderValue::from_str(&clear) {
                r.headers_mut().append(header::SET_COOKIE, v);
            }
            r
        }
    };
    if !constant_time_eq(binding.as_bytes(), pending.binding_sha256.as_bytes()) {
        return Ok(fail("browser_mismatch", json!("the login was started in another browser")).await);
    }
    if pending.expires_at <= now_micros() {
        return Ok(fail("expired", json!("the login took too long")).await);
    }
    if let Some(err) = q.error.as_deref() {
        // `error_description` is provider text; keep only the standard code.
        let err: String = err.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(64).collect();
        return Ok(fail("idp_error", json!(err)).await);
    }
    let Some(code) = q.code.as_deref().filter(|c| !c.is_empty()) else {
        return Ok(fail("no_code", Value::Null).await);
    };
    let id = match o.exchange_code(code, &pending.pkce_verifier).await {
        Ok(id_token) => match o.validate_id_token(&id_token, &pending.nonce).await {
            Ok(id) => id,
            Err(e) => return Ok(fail(e.reason(), json!(e.to_string())).await),
        },
        Err(e) => return Ok(fail(e.reason(), json!(e.to_string())).await),
    };

    let now = now_micros();
    let st = cp.store.state();
    let existing = st.user_by_subject(&id.issuer, &id.subject);
    let user = UserRecord {
        id: existing.map_or_else(|| new_id("usr"), |u| u.id.clone()),
        issuer: id.issuer.clone(),
        subject: id.subject.clone(),
        email: id.email.clone(),
        name: id.name.clone(),
        created_at: existing.map_or(now, |u| u.created_at),
        last_login_at: Some(now),
    };
    let token = random_token();
    let ttl = chrono::Duration::from_std(o.settings.session_ttl).unwrap_or_else(|_| chrono::Duration::hours(8));
    let session = SessionRecord {
        id: new_id("ses"),
        token_sha256: sha256_hex(&token),
        user_id: user.id.clone(),
        groups: id.groups.clone(),
        created_at: now,
        expires_at: now + ttl,
        last_seen_at: now,
        revoked_at: None,
    };
    // A session cookie already in this browser is replaced: end that session first.
    if let Some(old) = cookie(&headers, c.session_name())
        && let Ok(Some(s)) = cp.store.session(&sha256_hex(old)).await
        && s.revoked_at.is_none()
    {
        let actor = st.user(&s.user_id).map_or_else(|| s.user_id.clone(), UserRecord::actor);
        let m = Mutation::Logout { session_id: s.id, user_id: s.user_id, at: now };
        let _ = cp.store.apply(&actor, m).await;
    }
    let st = cp.store.apply(&user.actor(), Mutation::Login { user: user.clone(), session }).await?;
    let user = st.user_by_subject(&user.issuer, &user.subject).cloned().unwrap_or(user);
    tracing::info!(user = %user.actor(), "SSO login");
    let set = c.set(c.session_name(), &token, ttl.num_seconds(), "Strict");
    Ok(redirect(&pending.return_to, vec![set, clear_login]))
}

/// Ends the console session (CSRF-checked like any cookie write). Returns the provider's logout
/// URL, when it has one, for the console to navigate to.
async fn logout(State(cp): State<Cp>, method: Method, headers: HeaderMap) -> ApiResult<Response> {
    let o = cp.oidc.as_ref().ok_or_else(sso_disabled)?;
    let p = authenticate(&cp, &method, &headers).await?;
    let AuthMethod::Session { session_id } = &p.method else {
        return Err(crate::bad("only a console session can log out"));
    };
    let user_id = p.user.as_ref().map(|u| u.id.clone()).unwrap_or_default();
    let m = Mutation::Logout { session_id: session_id.clone(), user_id, at: now_micros() };
    cp.store.apply(&p.actor, m).await?;
    let c = Cookies::of(&cp);
    let mut r = Json(json!({"end_session_url": o.end_session_url().await})).into_response();
    if let Ok(v) = HeaderValue::from_str(&c.clear(c.session_name(), "Strict")) {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::safe_return_to;

    #[test]
    fn return_to_stays_on_this_origin() {
        assert_eq!(safe_return_to(Some("/#/tenants")), "/#/tenants");
        for bad in ["//evil.example", "/\\evil.example", "https://evil.example", "evil", "/\nx"] {
            assert_eq!(safe_return_to(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(safe_return_to(None), "/");
    }
}
