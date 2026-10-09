//! An in-process OpenID provider for tests: discovery, JWKS and a token endpoint that checks the
//! client secret and PKCE, over real HTTP on 127.0.0.1. Signing keys are generated per test.

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

pub const CLIENT_ID: &str = "caliban-console";
pub const CLIENT_SECRET: &str = "test-client-secret-not-real";
pub const API_AUDIENCE: &str = "caliban-api";

pub struct TestKey {
    pub kid: String,
    pub alg: Algorithm,
    enc: EncodingKey,
    pub jwk: Value,
}

impl TestKey {
    pub fn es256(kid: &str) -> Arc<Self> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::EncodePrivateKey;
        let sk = p256::SecretKey::random(&mut rand_core::OsRng);
        let der = sk.to_pkcs8_der().unwrap();
        let pt = sk.public_key().to_encoded_point(false);
        let jwk = json!({"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
                         "x": B64URL.encode(pt.x().unwrap()), "y": B64URL.encode(pt.y().unwrap())});
        Arc::new(Self { kid: kid.into(), alg: Algorithm::ES256, enc: EncodingKey::from_ec_der(der.as_bytes()), jwk })
    }

    pub fn rs256(kid: &str) -> Arc<Self> {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        let sk = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let der = sk.to_pkcs1_der().unwrap();
        let jwk = json!({"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
                         "n": B64URL.encode(sk.n().to_bytes_be()), "e": B64URL.encode(sk.e().to_bytes_be())});
        Arc::new(Self { kid: kid.into(), alg: Algorithm::RS256, enc: EncodingKey::from_rsa_der(der.as_bytes()), jwk })
    }

    /// Same key id, different private key: its tokens name a published key but do not verify.
    pub fn impostor(&self) -> Arc<Self> {
        assert_eq!(self.alg, Algorithm::ES256);
        Self::es256(&self.kid)
    }

    pub fn sign(&self, claims: &Value) -> String {
        let mut h = Header::new(self.alg);
        h.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&h, claims, &self.enc).unwrap()
    }
}

struct Grant {
    challenge: String,
    redirect_uri: String,
    claims: Value,
}

pub struct IdpState {
    /// Published in the JWKS.
    pub keys: Vec<Arc<TestKey>>,
    /// Signs every token from now on.
    pub signer: Arc<TestKey>,
    pub jwks_fetches: usize,
    /// What discovery reports as `issuer` (default: the real one).
    pub discovery_issuer: Option<String>,
    /// The token endpoint answers this OAuth error instead of tokens.
    pub token_error: Option<&'static str>,
    codes: HashMap<String, Grant>,
}

pub struct MockIdp {
    pub issuer: String,
    pub state: Arc<Mutex<IdpState>>,
}

pub fn now() -> u64 {
    jsonwebtoken::get_current_timestamp()
}

/// `base` with `overrides` merged in; a `null` override removes the claim.
fn merged(mut base: Value, overrides: &Value) -> Value {
    if let (Some(b), Some(o)) = (base.as_object_mut(), overrides.as_object()) {
        for (k, v) in o {
            if v.is_null() {
                b.remove(k);
            } else {
                b.insert(k.clone(), v.clone());
            }
        }
    }
    base
}

impl MockIdp {
    pub async fn start() -> Self {
        Self::start_with(TestKey::es256("k1")).await
    }

    pub async fn start_with(key: Arc<TestKey>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}/realms/test", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(IdpState {
            keys: vec![Arc::clone(&key)],
            signer: key,
            jwks_fetches: 0,
            discovery_issuer: None,
            token_error: None,
            codes: HashMap::new(),
        }));
        let app = Router::new()
            .route("/realms/test/.well-known/openid-configuration", get(discovery))
            .route("/realms/test/jwks", get(jwks))
            .route("/realms/test/token", post(token))
            .with_state((issuer.clone(), Arc::clone(&state)));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { issuer, state }
    }

    /// The user approves the login the console started (`authorize_url` from `/auth/login`).
    /// Returns `(code, state)`; the ID token minted for the code gets `overrides` merged in.
    pub fn approve(&self, authorize_url: &str, overrides: &Value) -> (String, String) {
        let u = url::Url::parse(authorize_url).unwrap();
        assert!(authorize_url.starts_with(&format!("{}/auth?", self.issuer)), "{authorize_url}");
        let q: HashMap<String, String> = u.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], CLIENT_ID);
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(q["scope"].split(' ').any(|s| s == "openid"));
        let claims = json!({"iss": self.issuer, "sub": "alice", "aud": CLIENT_ID, "exp": now() + 300, "iat": now(),
                            "nonce": q["nonce"], "email": "alice@example.test", "name": "Alice",
                            "groups": ["caliban-owners"]});
        let code = super::random_token();
        let grant = Grant {
            challenge: q["code_challenge"].clone(),
            redirect_uri: q["redirect_uri"].clone(),
            claims: merged(claims, overrides),
        };
        self.state.lock().codes.insert(code.clone(), grant);
        (code, q["state"].clone())
    }

    /// An access token for the admin API (client credentials style), signed by the current key.
    pub fn access_token(&self, overrides: &Value) -> String {
        let claims = json!({"iss": self.issuer, "sub": "ci-bot", "aud": API_AUDIENCE, "exp": now() + 300,
                            "iat": now(), "azp": "ci", "scope": "caliban", "groups": ["caliban-admins"]});
        self.state.lock().signer.sign(&merged(claims, overrides))
    }

    /// Publishes a new key and signs with it from now on (the old key stays published).
    pub fn rotate(&self, kid: &str) -> Arc<TestKey> {
        let k = TestKey::es256(kid);
        let mut s = self.state.lock();
        s.keys.push(Arc::clone(&k));
        s.signer = Arc::clone(&k);
        k
    }

    pub fn jwks_fetches(&self) -> usize {
        self.state.lock().jwks_fetches
    }
}

type Shared = (String, Arc<Mutex<IdpState>>);

async fn discovery(State((issuer, st)): State<Shared>) -> Json<Value> {
    let reported = st.lock().discovery_issuer.clone().unwrap_or_else(|| issuer.clone());
    Json(json!({
        "issuer": reported,
        "authorization_endpoint": format!("{issuer}/auth"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "id_token_signing_alg_values_supported": ["ES256", "RS256"],
    }))
}

async fn jwks(State((_, st)): State<Shared>) -> Json<Value> {
    let mut s = st.lock();
    s.jwks_fetches += 1;
    Json(json!({"keys": s.keys.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>()}))
}

fn oauth_error(code: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": code}))).into_response()
}

/// Checks client authentication (Basic), the code, the redirect URI and the PKCE verifier.
async fn token(State((_, st)): State<Shared>, headers: HeaderMap, Form(f): Form<HashMap<String, String>>) -> Response {
    let expected = format!("Basic {}", B64.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}")));
    if headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_client"}))).into_response();
    }
    let mut s = st.lock();
    if let Some(e) = s.token_error {
        return oauth_error(e);
    }
    if f.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return oauth_error("unsupported_grant_type");
    }
    let Some(g) = f.get("code").and_then(|c| s.codes.remove(c)) else { return oauth_error("invalid_grant") };
    let verifier = f.get("code_verifier").cloned().unwrap_or_default();
    if super::oidc::pkce_challenge(&verifier) != g.challenge || f.get("redirect_uri") != Some(&g.redirect_uri) {
        return oauth_error("invalid_grant");
    }
    let id_token = s.signer.sign(&g.claims);
    Json(
        json!({"access_token": "opaque-access-token", "token_type": "Bearer", "expires_in": 300, "id_token": id_token}),
    )
    .into_response()
}
