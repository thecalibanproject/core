//! SSO, sessions, CSRF, bearer tokens, break-glass and the role x route matrix, against the
//! in-process mock provider ([`super::mock_idp`]).

use super::mock_idp::{API_AUDIENCE, CLIENT_ID, CLIENT_SECRET, MockIdp, TestKey, now};
use super::oidc::{Oidc, OidcSettings};
use super::{csrf_token, random_token, sha256_hex};
use crate::store::audit::{now_micros, verify_chain};
use crate::store::{Mutation, SessionRecord, Store, UserRecord, new_id};
use crate::{ControlPlane, Cp, app};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use caliban_config::{Config, ConfigHandle, Keyring, OidcConfig, Snapshot};
use caliban_meter::RecentUsage;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tower::ServiceExt;

const BREAK_GLASS: &str = "break-glass-token-for-tests";
const CONSOLE: &str = "http://console.example.test";

fn base_config() -> Config {
    static CFG: OnceLock<Config> = OnceLock::new();
    CFG.get_or_init(|| Config::from_toml_str(include_str!("../../../../config/caliban.example.toml")).unwrap()).clone()
}

/// The client secret, as an operator would mount it (`{ file = ... }`).
fn secret_file() -> String {
    static PATH: OnceLock<String> = OnceLock::new();
    PATH.get_or_init(|| {
        let p = std::env::temp_dir().join(format!("caliban-sso-test-secret-{}", std::process::id()));
        std::fs::write(&p, format!("{CLIENT_SECRET}\n")).unwrap();
        p.to_string_lossy().into_owned()
    })
    .clone()
}

fn oidc_config(issuer: &str) -> OidcConfig {
    let mut groups = String::new();
    for (g, role, tenant) in [
        ("caliban-owners", "owner", None),
        ("caliban-admins", "admin", None),
        ("caliban-auditors", "auditor", None),
        ("acme-admins", "tenant_admin", Some("acme")),
        ("acme-devs", "developer", Some("acme")),
        ("acme-viewers", "viewer", Some("acme")),
        ("acme-billing", "billing", Some("acme")),
    ] {
        let t = tenant.map(|t| format!("tenant = \"{t}\"\n")).unwrap_or_default();
        groups.push_str(&format!("[[role_mappings]]\ngroup = \"{g}\"\nrole = \"{role}\"\n{t}"));
    }
    toml::from_str(&format!(
        "issuer = \"{issuer}\"\nclient_id = \"{CLIENT_ID}\"\nclient_secret = {{ file = \"{}\" }}\n\
         redirect_url = \"{CONSOLE}/auth/callback\"\napi_audience = \"{API_AUDIENCE}\"\n{groups}",
        secret_file().replace('\\', "\\\\")
    ))
    .unwrap()
}

fn settings(issuer: &str) -> OidcSettings {
    let mut s = OidcSettings::from_config(&oidc_config(issuer)).unwrap();
    s.jwks_min_refresh = Duration::ZERO;
    s
}

fn cp_with(oidc: Option<OidcSettings>) -> Cp {
    let cfg = base_config();
    let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
    Arc::new(
        ControlPlane::new(Store::new(cfg, handle, RecentUsage::default()), BREAK_GLASS.into(), "standalone")
            .with_keyring(Some(Arc::new(Keyring::new([7; 32], []))))
            .with_oidc(oidc.map(|s| Oidc::new(s).unwrap())),
    )
}

struct Harness {
    cp: Cp,
    app: Router,
    idp: MockIdp,
}

async fn harness_with(key: Arc<TestKey>, tweak: impl FnOnce(&mut OidcSettings)) -> Harness {
    let idp = MockIdp::start_with(key).await;
    let mut s = settings(&idp.issuer);
    tweak(&mut s);
    let cp = cp_with(Some(s));
    Harness { app: app(Arc::clone(&cp), None), cp, idp }
}

async fn harness() -> Harness {
    harness_with(TestKey::es256("k1"), |_| {}).await
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Resp {
    fn location(&self) -> &str {
        self.headers.get(header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or_default()
    }

    fn set_cookies(&self) -> Vec<String> {
        self.headers.get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap().to_owned()).collect()
    }
}

async fn send(app: &Router, method: &str, uri: &str, headers: &[(&str, &str)], body: Option<Value>) -> Resp {
    let mut req = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    Resp { status, headers, body: serde_json::from_slice(&bytes).unwrap_or(Value::Null) }
}

/// A cookie jar.
#[derive(Default, Clone)]
struct Browser {
    cookies: BTreeMap<String, String>,
}

impl Browser {
    fn absorb(&mut self, r: &Resp) {
        for c in r.set_cookies() {
            let (kv, attrs) = c.split_once(';').unwrap_or((&c, ""));
            let (k, v) = kv.split_once('=').unwrap();
            if attrs.contains("Max-Age=0") {
                self.cookies.remove(k);
            } else {
                self.cookies.insert(k.to_owned(), v.to_owned());
            }
        }
    }

    fn header(&self) -> String {
        self.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
    }

    async fn send(
        &mut self,
        app: &Router,
        method: &str,
        uri: &str,
        extra: &[(&str, &str)],
        body: Option<Value>,
    ) -> Resp {
        let jar = self.header();
        let mut headers = vec![("cookie", jar.as_str())];
        headers.extend_from_slice(extra);
        let r = send(app, method, uri, &headers, body).await;
        self.absorb(&r);
        r
    }

    /// The console's writes: cookie + CSRF token from `/auth/me`.
    async fn write(&mut self, app: &Router, method: &str, uri: &str, body: Option<Value>) -> Resp {
        let csrf = self.send(app, "GET", "/auth/me", &[], None).await.body["csrf_token"].as_str().unwrap().to_owned();
        self.send(app, method, uri, &[("x-csrf-token", &csrf), ("origin", CONSOLE)], body).await
    }
}

/// Runs the browser through `/auth/login` → provider → `/auth/callback`. Returns the callback.
async fn login(h: &Harness, b: &mut Browser, overrides: Value) -> Resp {
    let r = b.send(&h.app, "GET", "/auth/login?return_to=%2F%23%2Ftenants", &[], None).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER, "{:?}", r.body);
    let (code, state) = h.idp.approve(r.location(), &overrides);
    b.send(&h.app, "GET", &format!("/auth/callback?code={code}&state={state}"), &[], None).await
}

async fn last_audit(h: &Harness) -> crate::store::audit::AuditEntry {
    h.cp.store.audit(1).await.unwrap().remove(0)
}

fn bearer(t: &str) -> String {
    format!("Bearer {t}")
}

// ───────────────────────────── login ─────────────────────────────

#[tokio::test]
async fn login_round_trip_sets_a_strict_session_and_audits_the_user() {
    let h = harness().await;
    let r = send(&h.app, "GET", "/auth/config", &[], None).await;
    assert_eq!(r.body, json!({"sso_enabled": true, "break_glass_enabled": true, "login_url": "/auth/login"}));

    let mut b = Browser::default();
    let start = b.send(&h.app, "GET", "/auth/login?return_to=%2F%23%2Ftenants", &[], None).await;
    assert_eq!(start.status, StatusCode::SEE_OTHER);
    let login_cookie = &start.set_cookies()[0];
    assert!(login_cookie.starts_with("caliban_login=") && login_cookie.contains("HttpOnly"), "{login_cookie}");
    assert!(login_cookie.contains("SameSite=Lax") && !login_cookie.contains("Secure"), "http console: {login_cookie}");
    let (code, state) = h.idp.approve(start.location(), &json!({}));
    let cb = b.send(&h.app, "GET", &format!("/auth/callback?code={code}&state={state}"), &[], None).await;
    assert_eq!((cb.status, cb.location()), (StatusCode::SEE_OTHER, "/#/tenants"));
    let session_cookie = cb.set_cookies().into_iter().find(|c| c.starts_with("caliban_session=")).unwrap();
    for attr in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=28800"] {
        assert!(session_cookie.contains(attr), "{session_cookie}");
    }
    assert!(!b.cookies.contains_key("caliban_login"), "the login cookie is cleared");

    let me = b.send(&h.app, "GET", "/auth/me", &[], None).await;
    assert_eq!(me.status, StatusCode::OK, "{:?}", me.body);
    assert_eq!(me.body["method"], "session");
    assert_eq!(me.body["user"]["email"], "alice@example.test");
    assert_eq!(me.body["roles"], json!([{"role": "owner"}]));
    assert!(me.body["permissions"]["deployment"].as_array().unwrap().contains(&json!("rbac.write")));
    let actor = format!("alice@example.test <{}#alice>", h.idp.issuer);
    assert_eq!(me.body["actor"], actor.as_str());

    // The session works on the admin API; writes need the CSRF token.
    assert_eq!(b.send(&h.app, "GET", "/api/v1/tenants", &[], None).await.status, StatusCode::OK);
    let r = b.send(&h.app, "POST", "/api/v1/tenants", &[], Some(json!({"name": "Globex"}))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
    assert_eq!(r.body["error"]["type"], "permission_error");
    let r = b.write(&h.app, "POST", "/api/v1/tenants", Some(json!({"name": "Globex"}))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);

    // Audit: the user is the actor; the login is recorded; the chain holds.
    let log = h.cp.store.audit(10).await.unwrap();
    assert!(verify_chain(&log).is_ok());
    let created = log.iter().find(|e| e.action == "tenant.create").unwrap();
    assert_eq!(created.actor, actor);
    let row = log.iter().find(|e| e.action == "auth.login").unwrap();
    assert_eq!(row.actor, actor);
    assert_eq!(row.detail["groups"], json!(["caliban-owners"]));
    assert_eq!(row.detail["new_user"], json!(true));
    let user = h.cp.store.state().user_by_subject(&h.idp.issuer, "alice").cloned().unwrap();
    assert_eq!((user.name.as_deref(), user.email.as_deref()), (Some("Alice"), Some("alice@example.test")));
    assert!(!serde_json::to_string(&log).unwrap().contains(b.cookies["caliban_session"].as_str()), "no tokens");

    // The callback is single use.
    let replay = b.send(&h.app, "GET", &format!("/auth/callback?code={code}&state={state}"), &[], None).await;
    assert_eq!(replay.location(), "/#/login?error=login_expired");

    // Logout: CSRF-checked, revokes the session, clears the cookie, points at the provider.
    let r = b.send(&h.app, "POST", "/auth/logout", &[], None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let mut stolen = b.clone();
    let r = b.write(&h.app, "POST", "/auth/logout", None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let end = r.body["end_session_url"].as_str().unwrap();
    assert!(end.starts_with(&format!("{}/logout?client_id={CLIENT_ID}", h.idp.issuer)), "{end}");
    assert!(!b.cookies.contains_key("caliban_session"));
    assert_eq!(b.send(&h.app, "GET", "/auth/me", &[], None).await.status, StatusCode::UNAUTHORIZED);
    // A copy of the old cookie is dead too (server-side revocation).
    assert_eq!(stolen.send(&h.app, "GET", "/api/v1/tenants", &[], None).await.status, StatusCode::UNAUTHORIZED);
    let e = last_audit(&h).await;
    assert_eq!((e.action.as_str(), e.actor.as_str()), ("auth.logout", actor.as_str()));

    // A second login reuses the user.
    let mut b2 = Browser::default();
    login(&h, &mut b2, json!({"email": "alice@new.example.test"})).await;
    let st = h.cp.store.state();
    assert_eq!(st.users.len(), 1);
    assert_eq!(st.users[0].email.as_deref(), Some("alice@new.example.test"));
    assert_eq!(st.users[0].id, user.id);
}

#[tokio::test]
async fn rs256_keys_work_too() {
    let h = harness_with(TestKey::rs256("rsa-1"), |_| {}).await;
    let mut b = Browser::default();
    let cb = login(&h, &mut b, json!({})).await;
    assert_eq!(cb.location(), "/#/tenants");
    assert_eq!(b.send(&h.app, "GET", "/auth/me", &[], None).await.body["user"]["subject"], "alice");
}

#[tokio::test]
async fn bad_id_tokens_are_rejected_and_audited() {
    let h = harness().await;
    let impostor = h.idp.state.lock().signer.impostor();
    let cases: Vec<(&str, Value, Option<Arc<TestKey>>, &str)> = vec![
        ("wrong issuer", json!({"iss": "https://evil.example.test"}), None, "issuer"),
        ("wrong audience", json!({"aud": "someone-else"}), None, "audience"),
        ("azp of another client", json!({"aud": [CLIENT_ID, "other"], "azp": "other"}), None, "audience"),
        ("wrong nonce", json!({"nonce": "not-the-one"}), None, "nonce"),
        ("no nonce", json!({"nonce": null}), None, "nonce"),
        ("expired", json!({"exp": now() - 3600, "iat": now() - 7200}), None, "expired"),
        ("not yet valid", json!({"nbf": now() + 3600}), None, "not_yet_valid"),
        ("issued in the future", json!({"iat": now() + 3600}), None, "not_yet_valid"),
        ("no subject", json!({"sub": null}), None, "missing_claim"),
        ("bad signature", json!({}), Some(impostor), "signature"),
        ("unknown key", json!({}), Some(TestKey::es256("k-unknown")), "unknown_key"),
    ];
    for (what, overrides, signer, reason) in cases {
        let original = signer.map(|k| std::mem::replace(&mut h.idp.state.lock().signer, k));
        let mut b = Browser::default();
        let cb = login(&h, &mut b, overrides).await;
        if let Some(k) = original {
            h.idp.state.lock().signer = k;
        }
        assert_eq!(cb.location(), "/#/login?error=login_failed", "{what}");
        assert!(!b.cookies.contains_key("caliban_session"), "{what}: no session");
        let e = last_audit(&h).await;
        assert_eq!((e.action.as_str(), e.actor.as_str()), ("auth.login_failed", "anonymous"), "{what}");
        assert_eq!(e.detail["reason"], reason, "{what}: {}", e.detail);
    }
    assert!(h.cp.store.state().users.is_empty(), "no user was created");
    assert!(verify_chain(&h.cp.store.audit(100).await.unwrap()).is_ok());

    // `alg: none` never gets to a key.
    let none = format!(
        "{}.{}.",
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, r#"{"alg":"none"}"#),
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, r#"{"sub":"x"}"#)
    );
    let o = h.cp.oidc.as_ref().unwrap();
    assert!(o.validate_id_token(&none, "n").await.is_err());
    assert!(o.validate_access_token(&none).await.is_err());
}

#[tokio::test]
async fn state_browser_binding_and_provider_errors() {
    let h = harness().await;
    let head = h.cp.store.state().audit_head;
    // Unknown state: nothing ties it to a login, so it is not audited.
    let r = send(&h.app, "GET", "/auth/callback?code=x&state=forged", &[], None).await;
    assert_eq!(r.location(), "/#/login?error=login_expired");
    let r = send(&h.app, "GET", "/auth/callback?code=x", &[], None).await;
    assert_eq!(r.location(), "/#/login?error=login_expired");
    assert_eq!(h.cp.store.state().audit_head, head);

    // A real state completed in another browser (login CSRF): refused.
    let mut victim = Browser::default();
    let start = victim.send(&h.app, "GET", "/auth/login", &[], None).await;
    let (code, state) = h.idp.approve(start.location(), &json!({}));
    let mut attacker = Browser::default();
    let r = attacker.send(&h.app, "GET", &format!("/auth/callback?code={code}&state={state}"), &[], None).await;
    assert_eq!(r.location(), "/#/login?error=login_failed");
    assert_eq!(last_audit(&h).await.detail["reason"], "browser_mismatch");
    assert!(!attacker.cookies.contains_key("caliban_session"));

    // The provider reports an error (the user cancelled).
    let mut b = Browser::default();
    let start = b.send(&h.app, "GET", "/auth/login", &[], None).await;
    let (_, state) = h.idp.approve(start.location(), &json!({}));
    let r = b
        .send(
            &h.app,
            "GET",
            &format!("/auth/callback?error=access_denied&error_description=nope&state={state}"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.location(), "/#/login?error=login_failed");
    let e = last_audit(&h).await;
    assert_eq!((e.detail["reason"].as_str(), e.detail["detail"].as_str()), (Some("idp_error"), Some("access_denied")));

    // The token endpoint refuses the code.
    h.idp.state.lock().token_error = Some("invalid_grant");
    let mut b = Browser::default();
    login(&h, &mut b, json!({})).await;
    assert_eq!(last_audit(&h).await.detail["reason"], "token_exchange");
    h.idp.state.lock().token_error = None;

    // An open redirect through return_to is not possible.
    let mut b = Browser::default();
    let start = b.send(&h.app, "GET", "/auth/login?return_to=%2F%2Fevil.example", &[], None).await;
    let (code, state) = h.idp.approve(start.location(), &json!({}));
    let cb = b.send(&h.app, "GET", &format!("/auth/callback?code={code}&state={state}"), &[], None).await;
    assert_eq!(cb.location(), "/");
}

#[tokio::test]
async fn discovery_must_report_the_configured_issuer() {
    let h = harness().await;
    h.idp.state.lock().discovery_issuer = Some("https://other.example.test".into());
    let r = send(&h.app, "GET", "/auth/login", &[], None).await;
    assert_eq!(r.location(), "/#/login?error=idp_unavailable");
}

#[tokio::test]
async fn jwks_are_cached_and_rotation_is_picked_up() {
    let h = harness_with(TestKey::es256("k1"), |s| s.jwks_cache = Duration::from_millis(700)).await;
    let mut b = Browser::default();
    login(&h, &mut b, json!({})).await;
    login(&h, &mut Browser::default(), json!({})).await;
    assert_eq!(h.idp.jwks_fetches(), 1, "cached between logins");

    // The provider rotates: new kid, unknown to the cache, so the JWKS is fetched again.
    let old = h.idp.state.lock().signer.clone();
    h.idp.rotate("k2");
    let mut b2 = Browser::default();
    assert_eq!(login(&h, &mut b2, json!({})).await.location(), "/#/tenants");
    assert_eq!(h.idp.jwks_fetches(), 2);
    // The old key is retired: once the cached JWKS ages out, tokens it signs no longer verify.
    h.idp.state.lock().keys.retain(|k| k.kid != "k1");
    h.idp.state.lock().signer = old;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let mut b3 = Browser::default();
    assert_eq!(login(&h, &mut b3, json!({})).await.location(), "/#/login?error=login_failed");
    assert_eq!(last_audit(&h).await.detail["reason"], "unknown_key");

    // Made-up key ids do not turn into a request each (refetch is rate limited).
    let h = harness_with(TestKey::es256("k1"), |s| s.jwks_min_refresh = Duration::from_secs(3600)).await;
    let ok = h.idp.access_token(&json!({}));
    assert_eq!(
        send(&h.app, "GET", "/api/v1/tenants", &[("authorization", &bearer(&ok))], None).await.status,
        StatusCode::OK
    );
    let rogue =
        TestKey::es256("rogue").sign(&json!({"iss": h.idp.issuer, "sub": "x", "aud": API_AUDIENCE, "exp": now() + 60}));
    for _ in 0..5 {
        let r = send(&h.app, "GET", "/api/v1/tenants", &[("authorization", &bearer(&rogue))], None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(h.idp.jwks_fetches(), 1);
}

// ───────────────────────────── sessions ─────────────────────────────

#[tokio::test]
async fn sessions_expire_and_can_be_revoked() {
    // Absolute lifetime.
    let h = harness_with(TestKey::es256("k1"), |s| s.session_ttl = Duration::from_secs(1)).await;
    let mut b = Browser::default();
    login(&h, &mut b, json!({})).await;
    assert_eq!(b.send(&h.app, "GET", "/auth/me", &[], None).await.status, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = b.send(&h.app, "GET", "/auth/me", &[], None).await;
    assert_eq!((r.status, r.body["error"]["message"].as_str()), (StatusCode::UNAUTHORIZED, Some("session expired")));

    // Idle timeout.
    let h = harness().await;
    let mut b = Browser::default();
    login(&h, &mut b, json!({})).await;
    let s = h.cp.store.session(&sha256_hex(&b.cookies["caliban_session"])).await.unwrap().unwrap();
    h.cp.store.touch_session(&s.id, now_micros() - chrono::Duration::hours(2)).await.unwrap();
    assert_eq!(b.send(&h.app, "GET", "/auth/me", &[], None).await.status, StatusCode::UNAUTHORIZED);

    // An admin signs a user out everywhere.
    let mut b = Browser::default();
    login(&h, &mut b, json!({})).await;
    let mut b2 = Browser::default();
    login(&h, &mut b2, json!({})).await;
    let uid = h.cp.store.state().users[0].id.clone();
    let users = send(&h.app, "GET", "/api/v1/users", &[("authorization", &bearer(BREAK_GLASS))], None).await;
    assert_eq!(users.body[0]["active_sessions"], 2, "{:?}", users.body);
    let r = send(
        &h.app,
        "DELETE",
        &format!("/api/v1/users/{uid}/sessions"),
        &[("authorization", &bearer(BREAK_GLASS))],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    for mut br in [b, b2] {
        assert_eq!(br.send(&h.app, "GET", "/auth/me", &[], None).await.status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(last_audit(&h).await.action, "user.sessions_revoke");
    // Expired rows are purged.
    assert!(h.cp.store.purge_auth(now_micros() + chrono::Duration::days(1)).await.unwrap() >= 2);

    // A new login in a browser that still has a session replaces it.
    let mut b = Browser::default();
    login(&h, &mut b, json!({})).await;
    let first = b.cookies["caliban_session"].clone();
    login(&h, &mut b, json!({})).await;
    assert_ne!(b.cookies["caliban_session"], first);
    let old = h.cp.store.session(&sha256_hex(&first)).await.unwrap().unwrap();
    assert!(old.revoked_at.is_some());
}

#[tokio::test]
async fn csrf_and_origin_are_enforced_for_cookie_writes() {
    let h = harness().await;
    let mut b = Browser::default();
    login(&h, &mut b, json!({})).await;
    let csrf = csrf_token(&b.cookies["caliban_session"]);
    let body = || Some(json!({"name": "Initech"}));
    let r = b.send(&h.app, "POST", "/api/v1/tenants", &[("x-csrf-token", "wrong")], body()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = b
        .send(&h.app, "POST", "/api/v1/tenants", &[("x-csrf-token", &csrf), ("origin", "https://evil.example")], body())
        .await;
    assert_eq!(
        (r.status, r.body["error"]["message"].as_str()),
        (StatusCode::FORBIDDEN, Some("cross-origin request refused"))
    );
    let r = b.send(&h.app, "DELETE", "/api/v1/tenants/acme", &[], None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "deletes too");
    assert!(h.cp.store.state().has_tenant("acme"));
    // Same origin, or no Origin header (non-browser clients), with the token: accepted.
    let r = b.send(&h.app, "POST", "/api/v1/tenants", &[("x-csrf-token", &csrf), ("origin", CONSOLE)], body()).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = b
        .send(
            &h.app,
            "PATCH",
            "/api/v1/tenants/initech",
            &[("x-csrf-token", &csrf)],
            Some(json!({"semantic_cache": "on"})),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // Reads need no token.
    assert_eq!(b.send(&h.app, "GET", "/api/v1/audit", &[], None).await.status, StatusCode::OK);
    // Bearer callers are not subject to CSRF.
    let t = h.idp.access_token(&json!({}));
    let r = send(&h.app, "POST", "/api/v1/tenants", &[("authorization", &bearer(&t))], body()).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "authorized (the tenant already exists)");
}

// ───────────────────────────── bearer tokens ─────────────────────────────

#[tokio::test]
async fn access_tokens_work_for_automation() {
    let h = harness().await;
    let t = h.idp.access_token(&json!({}));
    let auth = bearer(&t);
    let r = send(&h.app, "POST", "/api/v1/tenants", &[("authorization", &auth)], Some(json!({"name": "Hooli"}))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let me = send(&h.app, "GET", "/auth/me", &[("authorization", &auth)], None).await;
    assert_eq!((me.body["method"].as_str(), me.body["roles"].clone()), (Some("bearer"), json!([{"role": "admin"}])));
    assert!(me.body.get("csrf_token").is_none());
    // The CI identity is a user, created once and audited.
    send(&h.app, "GET", "/api/v1/tenants", &[("authorization", &auth)], None).await;
    let log = h.cp.store.audit(20).await.unwrap();
    assert_eq!(log.iter().filter(|e| e.action == "user.create").count(), 1);
    let actor = format!("ci-bot <{}#ci-bot>", h.idp.issuer);
    assert_eq!(log.iter().find(|e| e.action == "tenant.create").unwrap().actor, actor);

    let rejected: Vec<(&str, Value)> = vec![
        ("ID token audience", json!({"aud": CLIENT_ID})),
        ("Keycloak ID token", json!({"typ": "ID"})),
        ("expired", json!({"exp": now() - 3600})),
        ("wrong issuer", json!({"iss": "https://evil.example.test"})),
        ("no audience", json!({"aud": null})),
    ];
    for (what, overrides) in rejected {
        let t = h.idp.access_token(&overrides);
        let r = send(&h.app, "GET", "/api/v1/tenants", &[("authorization", &bearer(&t))], None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{what}");
    }
    // A data-plane tenant key is not an admin credential.
    let r = send(&h.app, "GET", "/api/v1/tenants", &[("authorization", "Bearer cal_0123")], None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Groups from the token map to roles like a login's: a viewer of acme cannot create tenants.
    let viewer = h.idp.access_token(&json!({"sub": "viewer-bot", "groups": ["acme-viewers"]}));
    let r = send(&h.app, "POST", "/api/v1/tenants", &[("authorization", &bearer(&viewer))], Some(json!({"name": "X"})))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // API audience = client id (Entra ID v2): an ID token has that audience too, and is refused.
    let h = harness_with(TestKey::es256("k1"), |s| s.api_audience = Some(CLIENT_ID.into())).await;
    let id_like = h.idp.access_token(&json!({"aud": CLIENT_ID, "nonce": "n"}));
    let at = h.idp.access_token(&json!({"aud": CLIENT_ID}));
    assert_eq!(
        send(&h.app, "GET", "/api/v1/tenants", &[("authorization", &bearer(&id_like))], None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&h.app, "GET", "/api/v1/tenants", &[("authorization", &bearer(&at))], None).await.status,
        StatusCode::OK
    );

    // Without api_audience, access tokens are not accepted at all.
    let h = harness_with(TestKey::es256("k1"), |s| s.api_audience = None).await;
    let t = h.idp.access_token(&json!({}));
    assert_eq!(
        send(&h.app, "GET", "/api/v1/tenants", &[("authorization", &bearer(&t))], None).await.status,
        StatusCode::UNAUTHORIZED
    );
}

// ───────────────────────────── break-glass ─────────────────────────────

#[tokio::test]
async fn break_glass_is_audited_with_sso_and_can_be_disabled() {
    let h = harness().await;
    let auth = bearer(BREAK_GLASS);
    let r =
        send(&h.app, "POST", "/api/v1/tenants", &[("authorization", &auth)], Some(json!({"name": "Umbrella"}))).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let log = h.cp.store.audit(2).await.unwrap();
    assert_eq!((log[0].action.as_str(), log[0].actor.as_str()), ("auth.break_glass", "break_glass"));
    assert_eq!(log[0].detail, json!({"method": "POST", "path": "/api/v1/tenants"}));
    assert_eq!((log[1].action.as_str(), log[1].actor.as_str()), ("tenant.create", "break_glass"));
    // Reads with the token are recorded too.
    send(&h.app, "GET", "/api/v1/tenants", &[("authorization", &auth)], None).await;
    assert_eq!(last_audit(&h).await.detail["method"], "GET");
    let me = send(&h.app, "GET", "/auth/me", &[("authorization", &auth)], None).await;
    assert_eq!(
        (me.body["method"].as_str(), me.body["roles"].clone()),
        (Some("break_glass"), json!([{"role": "owner"}]))
    );

    // Token mode (no SSO): the token is the normal way in; mutations still name it.
    let cp = cp_with(None);
    let app = app(Arc::clone(&cp), None);
    let r = send(&app, "GET", "/auth/config", &[], None).await;
    assert_eq!(r.body, json!({"sso_enabled": false, "break_glass_enabled": true, "login_url": null}));
    send(&app, "POST", "/api/v1/tenants", &[("authorization", &auth)], Some(json!({"name": "Umbrella"}))).await;
    let e = cp.store.audit(1).await.unwrap().remove(0);
    assert_eq!((e.action.as_str(), e.actor.as_str()), ("tenant.create", "break_glass"));
    assert_eq!(send(&app, "GET", "/auth/login", &[], None).await.status, StatusCode::NOT_FOUND);
    // Cookies mean nothing without SSO.
    assert_eq!(
        send(&app, "GET", "/api/v1/tenants", &[("cookie", "caliban_session=x")], None).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Disabled: refused.
    let idp = MockIdp::start().await;
    let cfg = base_config();
    let cp = Arc::new(
        ControlPlane::new(
            Store::new(cfg.clone(), ConfigHandle::new(Snapshot::new(cfg, "b")), RecentUsage::default()),
            BREAK_GLASS.into(),
            "standalone",
        )
        .with_oidc(Some(Oidc::new(settings(&idp.issuer)).unwrap()))
        .with_break_glass(false),
    );
    let app = crate::app(cp, None);
    assert_eq!(
        send(&app, "GET", "/api/v1/tenants", &[("authorization", &auth)], None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(send(&app, "GET", "/auth/config", &[], None).await.body["break_glass_enabled"], false);
}

// ───────────────────────────── roles ─────────────────────────────

const PRINCIPALS: &[(&str, &[&str])] = &[
    ("owner", &["caliban-owners"]),
    ("admin", &["caliban-admins"]),
    ("auditor", &["caliban-auditors"]),
    ("tenant_admin", &["acme-admins"]),
    ("developer", &["acme-devs"]),
    ("viewer", &["acme-viewers"]),
    ("billing", &["acme-billing"]),
    ("none", &["unmapped-group"]),
];

/// A logged-in console user with `groups`; returns the cookie token.
async fn session_for(cp: &Cp, sub: &str, groups: &[&str]) -> String {
    let token = random_token();
    let now = now_micros();
    let user = UserRecord {
        id: new_id("usr"),
        issuer: cp.oidc.as_ref().unwrap().settings.issuer.clone(),
        subject: sub.into(),
        email: Some(format!("{sub}@example.test")),
        name: None,
        created_at: now,
        last_login_at: Some(now),
    };
    let session = SessionRecord {
        id: new_id("ses"),
        token_sha256: sha256_hex(&token),
        user_id: user.id.clone(),
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        last_seen_at: now,
        revoked_at: None,
    };
    cp.store.apply(&user.actor(), Mutation::Login { user, session }).await.unwrap();
    token
}

/// A control plane with tenants acme and globex, each with a datasource and an ontology element.
async fn matrix_cp() -> Cp {
    let cp = cp_with(Some(settings("http://127.0.0.1:9/never-contacted")));
    let s = &cp.store;
    let mut t = s.state().tenant("acme").cloned().unwrap();
    t.id = "globex".into();
    t.name = "Globex".into();
    s.apply("setup", Mutation::CreateTenant(t)).await.unwrap();
    for tenant in ["acme", "globex"] {
        let ds = crate::store::DatasourceRecord {
            id: format!("ds_{tenant}"),
            tenant_id: tenant.into(),
            kind: "postgres".into(),
            name: "erp".into(),
            status: "pending".into(),
            epoch: 0,
            connection: json!({}),
            deleted_at: None,
        };
        s.apply("setup", Mutation::CreateDatasource(ds)).await.unwrap();
        let el = serde_json::from_value(json!({
            "id": format!("el_{tenant}"), "name": "revenue", "description": null, "synonyms": [], "status": "proposed",
            "provenance": "llm", "confidence": 0.5, "kind": "glossary_term", "spec": {"phrase": "revenue", "maps_to": "orders.total"}
        }))
        .unwrap();
        s.apply("setup", Mutation::ProposeOntology { tenant_id: tenant.into(), elements: vec![el] }).await.unwrap();
    }
    cp
}

struct Case {
    method: &'static str,
    /// The `rbac::ROUTES` entry it exercises.
    route: &'static str,
    /// `{t}` is the tenant.
    url: &'static str,
    body: Option<Value>,
    /// Tenant-scoped: tenant roles pass only for their own tenant.
    scoped: bool,
    allowed: &'static str,
}

const READERS: &str = "owner admin auditor tenant_admin developer viewer";
const EVERYONE: &str = "owner admin auditor tenant_admin developer viewer billing";

fn cases() -> Vec<Case> {
    let c =
        |method, route, url, body: Option<Value>, scoped, allowed| Case { method, route, url, body, scoped, allowed };
    let node_spec = json!({"kind": "agent", "prompt": {"system": "x"}, "model_policy": {}, "tools": [],
                           "budgets": {"steps": 3, "tokens": 100, "wall_clock_s": 10}});
    vec![
        c("GET", "/tenants", "/api/v1/tenants", None, false, EVERYONE),
        c("POST", "/tenants", "/api/v1/tenants", Some(json!({"name": "Newco"})), false, "owner admin"),
        c("GET", "/tenants/{tenant_id}", "/api/v1/tenants/{t}", None, true, EVERYONE),
        c(
            "PATCH",
            "/tenants/{tenant_id}",
            "/api/v1/tenants/{t}",
            Some(json!({"semantic_cache": "on"})),
            true,
            "owner admin tenant_admin",
        ),
        c("DELETE", "/tenants/{tenant_id}", "/api/v1/tenants/{t}", None, true, "owner admin"),
        c("GET", "/tenants/{tenant_id}/api-keys", "/api/v1/tenants/{t}/api-keys", None, true, READERS),
        c(
            "POST",
            "/tenants/{tenant_id}/api-keys",
            "/api/v1/tenants/{t}/api-keys",
            Some(json!({})),
            true,
            "owner admin tenant_admin developer",
        ),
        c(
            "DELETE",
            "/tenants/{tenant_id}/api-keys/{key_id}",
            "/api/v1/tenants/{t}/api-keys/key_nope",
            None,
            true,
            "owner admin tenant_admin developer",
        ),
        c("GET", "/tenants/{tenant_id}/provider-keys", "/api/v1/tenants/{t}/provider-keys", None, true, READERS),
        c(
            "POST",
            "/tenants/{tenant_id}/provider-keys",
            "/api/v1/tenants/{t}/provider-keys",
            Some(json!({"kind": "openai", "label": "x", "api_key": "sk-test-0000", "trust_tier": "t2_contracted"})),
            true,
            "owner admin tenant_admin",
        ),
        c(
            "DELETE",
            "/tenants/{tenant_id}/provider-keys/{key_id}",
            "/api/v1/tenants/{t}/provider-keys/nope",
            None,
            true,
            "owner admin tenant_admin",
        ),
        c("GET", "/tenants/{tenant_id}/routes", "/api/v1/tenants/{t}/routes", None, true, READERS),
        c(
            "PUT",
            "/tenants/{tenant_id}/routes",
            "/api/v1/tenants/{t}/routes",
            Some(json!({"routes": []})),
            true,
            "owner admin tenant_admin developer",
        ),
        c(
            "DELETE",
            "/tenants/{tenant_id}/datasources/{id}",
            "/api/v1/tenants/{t}/datasources/nope",
            None,
            true,
            "owner admin tenant_admin",
        ),
        c(
            "DELETE",
            "/tenants/{tenant_id}/nodes/{id}",
            "/api/v1/tenants/{t}/nodes/nope",
            None,
            true,
            "owner admin tenant_admin developer",
        ),
        c(
            "GET",
            "/tenants/{tenant_id}/nodes/{id}/versions",
            "/api/v1/tenants/{t}/nodes/triage/versions",
            None,
            true,
            READERS,
        ),
        c(
            "POST",
            "/tenants/{tenant_id}/nodes/{id}/versions",
            "/api/v1/tenants/{t}/nodes/triage/versions",
            Some(json!({"spec": node_spec})),
            true,
            "owner admin tenant_admin developer",
        ),
        c(
            "GET",
            "/tenants/{tenant_id}/nodes/{id}/versions/{version}",
            "/api/v1/tenants/{t}/nodes/triage/versions/1",
            None,
            true,
            READERS,
        ),
        c(
            "POST",
            "/tenants/{tenant_id}/nodes/{id}/versions/{version}/publish",
            "/api/v1/tenants/{t}/nodes/triage/versions/1/publish",
            None,
            true,
            "owner admin tenant_admin",
        ),
        c(
            "POST",
            "/tenants/{tenant_id}/nodes/{id}/versions/{version}/retire",
            "/api/v1/tenants/{t}/nodes/triage/versions/1/retire",
            None,
            true,
            "owner admin tenant_admin",
        ),
        c(
            "POST",
            "/tenants/{tenant_id}/nodes/{id}/promote",
            "/api/v1/tenants/{t}/nodes/triage/promote",
            Some(json!({"version": 1})),
            true,
            "owner admin tenant_admin",
        ),
        c(
            "GET",
            "/tenants/{tenant_id}/nodes/{id}/diff",
            "/api/v1/tenants/{t}/nodes/triage/diff?from=1&to=2",
            None,
            true,
            READERS,
        ),
        c("GET", "/models", "/api/v1/models", None, false, EVERYONE),
        c("POST", "/models", "/api/v1/models", Some(json!({})), false, "owner admin"),
        c("DELETE", "/models/{*id}", "/api/v1/models/nope/none", None, false, "owner admin"),
        c("GET", "/providers", "/api/v1/providers", None, false, EVERYONE),
        c("POST", "/providers", "/api/v1/providers", Some(json!({})), false, "owner admin"),
        c("DELETE", "/providers/{id}", "/api/v1/providers/nope", None, false, "owner admin"),
        c("GET", "/providers/{id}/health", "/api/v1/providers/nope/health", None, false, "owner admin auditor"),
        c("POST", "/providers/{id}/discover", "/api/v1/providers/nope/discover", None, false, "owner admin"),
        c("GET", "/datasources", "/api/v1/datasources?tenant_id={t}", None, true, READERS),
        c("GET", "/datasources", "/api/v1/datasources", None, false, READERS),
        c(
            "POST",
            "/datasources",
            "/api/v1/datasources",
            Some(json!({"tenant_id": "{t}", "kind": "postgres", "name": "new", "connection": {}})),
            true,
            "owner admin tenant_admin",
        ),
        c(
            "POST",
            "/datasources/{id}/introspect",
            "/api/v1/datasources/ds_{t}/introspect",
            None,
            true,
            "owner admin tenant_admin",
        ),
        c("GET", "/ontology", "/api/v1/ontology?tenant_id={t}", None, true, READERS),
        c(
            "POST",
            "/ontology/elements/{id}/review",
            "/api/v1/ontology/elements/el_{t}/review",
            Some(json!({"decision": "approve"})),
            true,
            "owner admin tenant_admin developer",
        ),
        c("GET", "/nodes", "/api/v1/nodes?tenant_id={t}", None, true, READERS),
        c("GET", "/nodes", "/api/v1/nodes", None, false, READERS),
        c(
            "POST",
            "/nodes",
            "/api/v1/nodes",
            Some(json!({"tenant_id": "{t}", "name": "n", "spec": node_spec})),
            true,
            "owner admin tenant_admin developer",
        ),
        c("GET", "/usage", "/api/v1/usage?tenant_id={t}", None, true, EVERYONE),
        c("GET", "/usage", "/api/v1/usage", None, false, EVERYONE),
        c("GET", "/audit", "/api/v1/audit", None, false, "owner admin auditor"),
        c("GET", "/keys/status", "/api/v1/keys/status", None, false, "owner admin auditor"),
        c("GET", "/roles", "/api/v1/roles", None, false, "owner admin auditor"),
        c("GET", "/users", "/api/v1/users", None, false, "owner admin auditor"),
        c("DELETE", "/users/{id}/sessions", "/api/v1/users/usr_nope/sessions", None, false, "owner admin"),
        c("GET", "/role-bindings", "/api/v1/role-bindings", None, false, "owner admin auditor"),
        c(
            "POST",
            "/role-bindings",
            "/api/v1/role-bindings",
            Some(json!({"subject_kind": "group", "subject": "g", "role": "viewer", "tenant_id": "acme"})),
            false,
            "owner admin",
        ),
        c("DELETE", "/role-bindings/{id}", "/api/v1/role-bindings/nope", None, false, "owner admin"),
    ]
}

/// Every role against every admin route, on its own tenant and on another one. "Allowed" means
/// authorization let the request through (the handler may still answer 404, 409, 422, ...).
#[tokio::test]
async fn every_role_against_every_admin_route() {
    let cases = cases();
    for rule in super::rbac::ROUTES {
        assert!(
            cases.iter().any(|c| c.method == rule.method && c.route == rule.path),
            "no matrix case for {} {}",
            rule.method,
            rule.path
        );
    }
    let mut checked = 0;
    for case in &cases {
        let tenants: &[&str] = if case.scoped { &["acme", "globex"] } else { &["acme"] };
        for tenant in tenants {
            for (role, groups) in PRINCIPALS {
                let cp = matrix_cp().await;
                let app = app(Arc::clone(&cp), None);
                let token = session_for(&cp, role, groups).await;
                let url = case.url.replace("{t}", tenant);
                let body =
                    case.body.as_ref().map(|b| serde_json::from_str(&b.to_string().replace("{t}", tenant)).unwrap());
                let cookie = format!("caliban_session={token}");
                let csrf = csrf_token(&token);
                let r = send(&app, case.method, &url, &[("cookie", &cookie), ("x-csrf-token", &csrf)], body).await;
                let tenant_role = !["owner", "admin", "auditor", "none"].contains(role);
                let expected =
                    case.allowed.split(' ').any(|r| r == *role) && !(case.scoped && tenant_role && *tenant != "acme");
                let allowed = !matches!(r.status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED);
                assert_eq!(allowed, expected, "{role} {} {url}: {} {}", case.method, r.status, r.body);
                checked += 1;
            }
        }
    }
    assert!(checked > 450, "{checked}");
}

#[tokio::test]
async fn routes_without_a_rule_are_denied_to_everyone() {
    let cp = matrix_cp().await;
    let token = session_for(&cp, "owner", &["caliban-owners"]).await;
    let unlisted = Router::new()
        .route("/unlisted", axum::routing::get(|| async { "secret" }))
        .route_layer(axum::middleware::from_fn_with_state(Arc::clone(&cp), super::authorize));
    let app = Router::new().nest("/api/v1", unlisted).with_state(cp);
    let r = send(&app, "GET", "/api/v1/unlisted", &[("cookie", &format!("caliban_session={token}"))], None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = send(&app, "GET", "/api/v1/unlisted", &[("authorization", &bearer(BREAK_GLASS))], None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "not even break-glass");
}

#[tokio::test]
async fn tenant_roles_only_see_their_tenants() {
    let cp = matrix_cp().await;
    let app = app(Arc::clone(&cp), None);
    for tenant in ["acme", "globex"] {
        let spec = json!({"kind": "agent", "prompt": {"system": "x"}, "model_policy": {}, "tools": [],
                          "budgets": {"steps": 3, "tokens": 100, "wall_clock_s": 10}});
        let r = send(
            &app,
            "POST",
            "/api/v1/nodes",
            &[("authorization", &bearer(BREAK_GLASS))],
            Some(json!({"tenant_id": tenant, "name": "triage", "spec": spec})),
        )
        .await;
        assert_eq!(r.status, StatusCode::CREATED);
        let e: caliban_meter::UsageEvent = serde_json::from_value(json!({
            "request_id": format!("req_{tenant}"), "tenant_id": tenant, "model": "m", "intent": "chat",
            "prompt_tokens": 10, "completion_tokens": 5, "cached_prompt_tokens": 0, "tokens_saved": 0, "cache": "miss",
            "pii_entities": 0, "cost_usd": 0.5, "latency_ms": 1, "ts": "2026-10-09T12:00:00Z"
        }))
        .unwrap();
        caliban_meter::UsageSink::record(&cp.store.usage, e).await;
    }
    let token = session_for(&cp, "dev", &["acme-devs", "acme-billing"]).await;
    let cookie = format!("caliban_session={token}");
    let get = |uri: &'static str| {
        let app = app.clone();
        let cookie = cookie.clone();
        async move { send(&app, "GET", uri, &[("cookie", &cookie)], None).await }
    };
    let ids = |v: &Value, k: &str| {
        v.as_array().unwrap().iter().map(|x| x[k].as_str().unwrap().to_owned()).collect::<Vec<_>>()
    };
    assert_eq!(ids(&get("/api/v1/tenants").await.body, "id"), ["acme"]);
    assert_eq!(ids(&get("/api/v1/tenants?include_deleted=true").await.body, "id"), ["acme"]);
    assert_eq!(ids(&get("/api/v1/datasources").await.body, "tenant_id"), ["acme"]);
    assert_eq!(ids(&get("/api/v1/nodes").await.body, "tenant_id"), ["acme"]);
    let usage = get("/api/v1/usage").await.body;
    assert_eq!(ids(&usage["events"], "tenant_id"), ["acme"]);
    assert_eq!((usage["totals"]["requests"].clone(), usage["totals"]["cost_usd"].clone()), (json!(1), json!(0.5)));
    assert_eq!(get("/api/v1/datasources?tenant_id=globex").await.status, StatusCode::FORBIDDEN);
    assert_eq!(get("/api/v1/usage?tenant_id=globex").await.status, StatusCode::FORBIDDEN);
    assert_eq!(get("/api/v1/tenants/globex").await.status, StatusCode::FORBIDDEN);
    // A deployment role sees both.
    let admin = session_for(&cp, "adm", &["caliban-admins"]).await;
    let r = send(&app, "GET", "/api/v1/usage", &[("cookie", &format!("caliban_session={admin}"))], None).await;
    assert_eq!(r.body["totals"]["requests"], 2);
    // The /auth/me permissions say the same thing.
    let me = get("/auth/me").await.body;
    assert_eq!(me["permissions"]["deployment"], json!(["catalog.read"]));
    let acme: Vec<&str> =
        me["permissions"]["tenants"]["acme"].as_array().unwrap().iter().map(|p| p.as_str().unwrap()).collect();
    assert!(acme.contains(&"api_keys.write") && acme.contains(&"usage.read") && !acme.contains(&"provider_keys.write"));
    assert!(me["permissions"]["tenants"].get("globex").is_none());
}

#[tokio::test]
async fn role_bindings_take_effect_at_once_and_owner_is_guarded() {
    let cp = matrix_cp().await;
    let app = app(Arc::clone(&cp), None);
    let admin = session_for(&cp, "adm", &["caliban-admins"]).await;
    let bob = session_for(&cp, "bob", &[]).await;
    let bob_id = cp.store.state().user_by_subject("http://127.0.0.1:9/never-contacted", "bob").unwrap().id.clone();
    let as_admin = |m: &'static str, uri: String, body: Option<Value>| {
        let app = app.clone();
        let admin = admin.clone();
        async move {
            let csrf = csrf_token(&admin);
            send(&app, m, &uri, &[("cookie", &format!("caliban_session={admin}")), ("x-csrf-token", &csrf)], body).await
        }
    };
    let bob_get = |uri: &'static str| {
        let app = app.clone();
        let bob = bob.clone();
        async move { send(&app, "GET", uri, &[("cookie", &format!("caliban_session={bob}"))], None).await.status }
    };
    assert_eq!(bob_get("/api/v1/tenants/acme/api-keys").await, StatusCode::FORBIDDEN);
    let me = send(&app, "GET", "/auth/me", &[("cookie", &format!("caliban_session={bob}"))], None).await;
    assert_eq!((me.status, me.body["roles"].clone()), (StatusCode::OK, json!([])), "logged in, no roles");

    let r = as_admin(
        "POST",
        "/api/v1/role-bindings".into(),
        Some(json!({"subject_kind": "user", "subject": bob_id, "role": "viewer", "tenant_id": "acme"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.body["id"].as_str().unwrap().to_owned();
    assert_eq!(bob_get("/api/v1/tenants/acme/api-keys").await, StatusCode::OK);
    assert_eq!(bob_get("/api/v1/tenants/globex/api-keys").await, StatusCode::FORBIDDEN);
    let e = cp.store.audit(1).await.unwrap().remove(0);
    assert_eq!(
        (e.action.as_str(), e.actor.as_str()),
        ("role_binding.create", "adm@example.test <http://127.0.0.1:9/never-contacted#adm>")
    );
    assert_eq!(e.detail["email"], "bob@example.test");
    assert_eq!(r.body["created_by"], e.actor.as_str());

    // Group bindings work like config mappings.
    let r = as_admin(
        "POST",
        "/api/v1/role-bindings".into(),
        Some(json!({"subject_kind": "group", "subject": "ops", "role": "auditor"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let ops = session_for(&cp, "olga", &["ops"]).await;
    let r = send(&app, "GET", "/api/v1/audit", &[("cookie", &format!("caliban_session={ops}"))], None).await;
    assert_eq!(r.status, StatusCode::OK);

    // Validation and the owner guard.
    let bad = |body: Value| as_admin("POST", "/api/v1/role-bindings".into(), Some(body));
    assert_eq!(
        bad(json!({"subject_kind": "group", "subject": "g", "role": "root"})).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        bad(json!({"subject_kind": "group", "subject": "g", "role": "viewer"})).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        bad(json!({"subject_kind": "user", "subject": "usr_nope", "role": "admin"})).await.status,
        StatusCode::NOT_FOUND
    );
    let r = bad(json!({"subject_kind": "user", "subject": bob_id, "role": "owner"})).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "admins cannot make owners");
    let r = send(
        &app,
        "POST",
        "/api/v1/role-bindings",
        &[("authorization", &bearer(BREAK_GLASS))],
        Some(json!({"subject_kind": "user", "subject": bob_id, "role": "owner"})),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "owners (and break-glass) can");
    let owner_binding = r.body["id"].as_str().unwrap().to_owned();
    assert_eq!(
        as_admin("DELETE", format!("/api/v1/role-bindings/{owner_binding}"), None).await.status,
        StatusCode::FORBIDDEN
    );

    // Listing: stored bindings and the config's group mappings.
    let list = as_admin("GET", "/api/v1/role-bindings".into(), None).await.body;
    assert_eq!(list["bindings"].as_array().unwrap().len(), 3);
    assert_eq!(
        list["group_mappings"][0],
        json!({"group": "caliban-owners", "role": "owner", "tenant_id": null, "source": "config"})
    );
    assert_eq!(list["groups_claim"], "groups");
    let roles = as_admin("GET", "/api/v1/roles".into(), None).await.body;
    assert_eq!(roles.as_array().unwrap().len(), 7);
    assert_eq!(roles[6]["role"], "billing");
    assert_eq!(roles[6]["scope"], "tenant");

    // Revoking takes effect on the next request.
    let r = send(
        &app,
        "DELETE",
        &format!("/api/v1/role-bindings/{owner_binding}"),
        &[("authorization", &bearer(BREAK_GLASS))],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(bob_get("/api/v1/tenants/globex/api-keys").await, StatusCode::FORBIDDEN, "no longer an owner");
    assert_eq!(as_admin("DELETE", format!("/api/v1/role-bindings/{id}"), None).await.status, StatusCode::NO_CONTENT);
    assert_eq!(bob_get("/api/v1/tenants/acme/api-keys").await, StatusCode::FORBIDDEN);
    assert_eq!(as_admin("DELETE", format!("/api/v1/role-bindings/{id}"), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(cp.store.audit(1).await.unwrap()[0].action, "role_binding.delete");
    assert!(verify_chain(&cp.store.audit(1000).await.unwrap()).is_ok());
}

#[tokio::test]
async fn snapshots_never_carry_sso_settings() {
    let cp = matrix_cp().await;
    let mut cfg = cp.store.base().clone();
    cfg.security.oidc = Some(oidc_config("https://idp.example.test"));
    cfg.security.break_glass = false;
    let json = serde_json::to_value(&cfg.security).unwrap();
    assert!(json.get("oidc").is_some() && json["break_glass"] == false, "serialized when set");
    cfg.security.oidc = None;
    cfg.security.break_glass = true;
    let json = serde_json::to_value(&cfg.security).unwrap();
    assert!(json.get("oidc").is_none() && json.get("break_glass").is_none(), "old routers parse the default");
}

#[test]
fn environment_overrides() {
    use super::oidc::config_with_env;
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned())
    };
    assert_eq!(config_with_env(None, env(&[])).unwrap(), None);
    assert!(config_with_env(None, env(&[("CALIBAN_OIDC_ISSUER", "https://idp")])).unwrap_err().contains("CLIENT_ID"));
    let c = config_with_env(
        None,
        env(&[
            ("CALIBAN_OIDC_ISSUER", "https://idp.example.test/realms/c"),
            ("CALIBAN_OIDC_CLIENT_ID", "caliban"),
            ("CALIBAN_OIDC_CLIENT_SECRET", "x"),
            ("CALIBAN_OIDC_REDIRECT_URL", "https://console.example.test/auth/callback"),
            ("CALIBAN_OIDC_API_AUDIENCE", "caliban-api"),
            ("CALIBAN_OIDC_GROUPS_CLAIM", "realm_access.roles"),
            ("CALIBAN_OIDC_OWNER_GROUPS", "ops, platform"),
        ]),
    )
    .unwrap()
    .unwrap();
    assert_eq!(c.client_secret, Some(caliban_config::SecretRef::Env { env: "CALIBAN_OIDC_CLIENT_SECRET".into() }));
    assert_eq!((c.api_audience.as_deref(), c.groups_claim.as_str()), (Some("caliban-api"), "realm_access.roles"));
    assert_eq!(
        c.role_mappings.iter().map(|m| (m.group.as_str(), m.role.as_str())).collect::<Vec<_>>(),
        [("ops", "owner"), ("platform", "owner")]
    );
    assert!(OidcSettings::from_config(&c).is_ok());
    // A config section wins where the environment says nothing.
    let file = oidc_config("https://idp.example.test/realms/file");
    let c = config_with_env(Some(&file), env(&[("CALIBAN_OIDC_CLIENT_ID", "other")])).unwrap().unwrap();
    assert_eq!((c.issuer.as_str(), c.client_id.as_str()), ("https://idp.example.test/realms/file", "other"));
    assert_eq!(c.role_mappings.len(), 7);
}

/// Two control-plane replicas on one Postgres database: a session started on one works on the
/// other (the user is picked up on first sight), and a logout on either ends it everywhere.
#[tokio::test]
async fn postgres_sessions_work_across_replicas() {
    let Ok(url) = std::env::var("CALIBAN_TEST_DATABASE_URL") else {
        eprintln!("CALIBAN_TEST_DATABASE_URL not set; skipping");
        return;
    };
    use sqlx::postgres::PgConnectOptions;
    let schema = format!("t_{}", uuid::Uuid::now_v7().simple());
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}"))).execute(&admin).await.unwrap();
    let opts: PgConnectOptions = url.parse::<PgConnectOptions>().unwrap().options([("search_path", schema.as_str())]);
    let idp = MockIdp::start().await;
    let mut replicas = Vec::new();
    for _ in 0..2 {
        let pg = crate::store::postgres::PgBackend::connect_with(opts.clone()).await.unwrap();
        let cfg = base_config();
        let store = Store::open_postgres(
            pg,
            cfg.clone(),
            ConfigHandle::new(Snapshot::new(cfg, "boot")),
            RecentUsage::default(),
        )
        .await
        .unwrap();
        let cp = Arc::new(
            ControlPlane::new(store, BREAK_GLASS.into(), "control-plane")
                .with_oidc(Some(Oidc::new(settings(&idp.issuer)).unwrap())),
        );
        replicas.push(Harness {
            app: app(Arc::clone(&cp), None),
            cp,
            idp: MockIdp { issuer: idp.issuer.clone(), state: Arc::clone(&idp.state) },
        });
    }
    let (a, b) = (&replicas[0], &replicas[1]);
    let mut browser = Browser::default();
    assert_eq!(login(a, &mut browser, json!({})).await.location(), "/#/tenants");
    let me = browser.send(&b.app, "GET", "/auth/me", &[], None).await;
    assert_eq!((me.status, me.body["user"]["subject"].as_str()), (StatusCode::OK, Some("alice")), "{:?}", me.body);
    let r = browser.write(&b.app, "POST", "/api/v1/tenants", Some(json!({"name": "Replicated"}))).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    a.cp.store.refresh().await.unwrap();
    let log = a.cp.store.audit(5).await.unwrap();
    assert!(verify_chain(&log).is_ok());
    assert_eq!(log.last().unwrap().actor, format!("alice@example.test <{}#alice>", idp.issuer));
    // Session rows hold the token's hash only.
    let pool = sqlx::PgPool::connect_with(opts).await.unwrap();
    let token = browser.cookies["caliban_session"].clone();
    let stored: Vec<String> =
        sqlx::query_scalar("SELECT token_sha256 FROM auth_session").fetch_all(&pool).await.unwrap();
    assert_eq!(stored, [sha256_hex(&token)]);
    // Logout on B ends the session on A too.
    assert_eq!(browser.write(&b.app, "POST", "/auth/logout", None).await.status, StatusCode::OK);
    let mut copy = Browser::default();
    copy.cookies.insert("caliban_session".into(), token);
    assert_eq!(copy.send(&a.app, "GET", "/auth/me", &[], None).await.status, StatusCode::UNAUTHORIZED);
}
