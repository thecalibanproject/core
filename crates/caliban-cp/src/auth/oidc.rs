//! OpenID Connect relying party: discovery, signing keys (JWKS) with caching and rotation, the
//! authorization code flow with PKCE, and validation of ID tokens and access tokens.
//!
//! Only the configured issuer is contacted: discovery at `<issuer>/.well-known/openid-configuration`,
//! then the JWKS and token endpoints it names, which must be on the issuer's origin. Redirects are
//! not followed. JWT signatures are verified by the `jsonwebtoken` crate (asymmetric algorithms
//! only); this module picks the key and checks the OIDC-specific claims.

use super::rbac::Role;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use caliban_config::{OidcConfig, SecretRef};
use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

/// Signature algorithms accepted for ID and access tokens. Never `none` or a shared secret.
const ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Discovery is refetched this often (and retried sooner after a failure).
const METADATA_TTL: Duration = Duration::from_secs(24 * 3600);
const METADATA_RETRY: Duration = Duration::from_secs(10);

/// Why a login or a token was rejected. `reason()` is what the audit log and the logs record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OidcError {
    #[error("identity provider unavailable: {0}")]
    Unavailable(String),
    #[error("token endpoint refused the code: {0}")]
    TokenEndpoint(String),
    #[error("token rejected: {reason}")]
    Token { reason: &'static str, detail: String },
}

impl OidcError {
    pub fn reason(&self) -> &'static str {
        match self {
            OidcError::Unavailable(_) => "idp_unavailable",
            OidcError::TokenEndpoint(_) => "token_exchange",
            OidcError::Token { reason, .. } => reason,
        }
    }

    fn token(reason: &'static str, detail: impl Into<String>) -> Self {
        OidcError::Token { reason, detail: detail.into() }
    }
}

/// `[security.oidc]`, checked and resolved at startup.
#[derive(Debug, Clone)]
pub struct OidcSettings {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<SecretRef>,
    pub redirect_url: Url,
    pub scopes: Vec<String>,
    pub groups_claim: String,
    pub api_audience: Option<String>,
    pub session_ttl: Duration,
    pub session_idle: Duration,
    pub clock_skew_secs: u64,
    pub jwks_cache: Duration,
    /// An unknown key id refetches the JWKS at most this often (a flood of made-up key ids must
    /// not turn into a flood of requests to the provider).
    pub jwks_min_refresh: Duration,
    pub ca_file: Option<String>,
    pub post_logout_redirect_url: String,
    pub role_mappings: Vec<(String, Role, Option<String>)>,
}

impl OidcSettings {
    pub fn from_config(c: &OidcConfig) -> Result<Self, String> {
        let issuer = c.issuer.trim().to_owned();
        let issuer_url = Url::parse(&issuer).map_err(|e| format!("security.oidc.issuer: {e}"))?;
        if !matches!(issuer_url.scheme(), "https" | "http") {
            return Err("security.oidc.issuer must be an http(s) URL".into());
        }
        if c.client_id.trim().is_empty() {
            return Err("security.oidc.client_id is required".into());
        }
        let redirect_url = Url::parse(c.redirect_url.trim()).map_err(|e| format!("security.oidc.redirect_url: {e}"))?;
        if !matches!(redirect_url.scheme(), "https" | "http") || redirect_url.path() != "/auth/callback" {
            return Err("security.oidc.redirect_url must be the console's https://<host>/auth/callback".into());
        }
        if !c.scopes.iter().any(|s| s == "openid") {
            return Err("security.oidc.scopes must include \"openid\"".into());
        }
        if c.groups_claim.trim().is_empty() {
            return Err("security.oidc.groups_claim must not be empty".into());
        }
        if c.session_ttl_secs == 0 || c.session_idle_secs == 0 {
            return Err("security.oidc session lifetimes must be positive".into());
        }
        let mut role_mappings = Vec::new();
        for m in &c.role_mappings {
            let role = Role::parse(&m.role).ok_or_else(|| {
                format!(
                    "security.oidc.role_mappings: unknown role '{}' (one of {})",
                    m.role,
                    Role::ALL.map(Role::as_str).join(", ")
                )
            })?;
            match (role.is_tenant_role(), &m.tenant) {
                (true, None) => {
                    return Err(format!("security.oidc.role_mappings: role '{}' needs a tenant", m.role));
                }
                (false, Some(_)) => {
                    return Err(format!("security.oidc.role_mappings: role '{}' is deployment-wide", m.role));
                }
                _ => {}
            }
            if m.group.trim().is_empty() {
                return Err("security.oidc.role_mappings: group must not be empty".into());
            }
            role_mappings.push((m.group.clone(), role, m.tenant.clone()));
        }
        let post_logout_redirect_url = match &c.post_logout_redirect_url {
            Some(u) => u.clone(),
            None => format!("{}/", origin(&redirect_url)),
        };
        Ok(Self {
            issuer,
            client_id: c.client_id.trim().to_owned(),
            client_secret: c.client_secret.clone(),
            redirect_url,
            scopes: c.scopes.clone(),
            groups_claim: c.groups_claim.clone(),
            api_audience: c.api_audience.clone().filter(|a| !a.trim().is_empty()),
            session_ttl: Duration::from_secs(c.session_ttl_secs),
            session_idle: Duration::from_secs(c.session_idle_secs),
            clock_skew_secs: c.clock_skew_secs,
            jwks_cache: Duration::from_secs(c.jwks_cache_secs.max(1)),
            jwks_min_refresh: Duration::from_secs(30),
            ca_file: c.ca_file.clone(),
            post_logout_redirect_url,
            role_mappings,
        })
    }

    /// The console's origin (`scheme://host[:port]`), from the redirect URL.
    pub fn console_origin(&self) -> String {
        origin(&self.redirect_url)
    }

    /// `https` console: cookies are `Secure` and use the `__Host-` prefix.
    pub fn secure_cookies(&self) -> bool {
        self.redirect_url.scheme() == "https"
    }
}

/// `[security.oidc]` with `CALIBAN_OIDC_*` environment overrides (handy for Compose and Helm). With
/// no section, `CALIBAN_OIDC_ISSUER` alone turns SSO on (client id and redirect URL then come from
/// the environment too). Group lists (`CALIBAN_OIDC_OWNER_GROUPS`, `_ADMIN_GROUPS`,
/// `_AUDITOR_GROUPS`, comma-separated) add deployment-role mappings.
pub fn config_with_env(
    file: Option<&OidcConfig>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<OidcConfig>, String> {
    let var = |k: &str| env(k).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
    let mut c = match (file, var("CALIBAN_OIDC_ISSUER")) {
        (Some(c), _) => c.clone(),
        (None, Some(issuer)) => {
            let need = |k: &str| var(k).ok_or_else(|| format!("CALIBAN_OIDC_ISSUER is set, so {k} is required"));
            toml::from_str::<OidcConfig>(&format!(
                "issuer = {}\nclient_id = {}\nredirect_url = {}\n",
                toml_str(&issuer),
                toml_str(&need("CALIBAN_OIDC_CLIENT_ID")?),
                toml_str(&need("CALIBAN_OIDC_REDIRECT_URL")?)
            ))
            .map_err(|e| e.to_string())?
        }
        (None, None) => return Ok(None),
    };
    if let Some(v) = var("CALIBAN_OIDC_ISSUER") {
        c.issuer = v;
    }
    if let Some(v) = var("CALIBAN_OIDC_CLIENT_ID") {
        c.client_id = v;
    }
    if var("CALIBAN_OIDC_CLIENT_SECRET").is_some() && c.client_secret.is_none() {
        c.client_secret = Some(SecretRef::Env { env: "CALIBAN_OIDC_CLIENT_SECRET".into() });
    }
    if let Some(v) = var("CALIBAN_OIDC_REDIRECT_URL") {
        c.redirect_url = v;
    }
    if let Some(v) = var("CALIBAN_OIDC_SCOPES") {
        c.scopes = v.split([' ', ',']).filter(|s| !s.is_empty()).map(str::to_owned).collect();
    }
    if let Some(v) = var("CALIBAN_OIDC_GROUPS_CLAIM") {
        c.groups_claim = v;
    }
    if let Some(v) = var("CALIBAN_OIDC_API_AUDIENCE") {
        c.api_audience = Some(v);
    }
    if let Some(v) = var("CALIBAN_OIDC_CA_FILE") {
        c.ca_file = Some(v);
    }
    for (k, role) in [
        ("CALIBAN_OIDC_OWNER_GROUPS", "owner"),
        ("CALIBAN_OIDC_ADMIN_GROUPS", "admin"),
        ("CALIBAN_OIDC_AUDITOR_GROUPS", "auditor"),
    ] {
        for g in var(k).unwrap_or_default().split(',').map(str::trim).filter(|g| !g.is_empty()) {
            let m = caliban_config::RoleMapping { group: g.to_owned(), role: role.into(), tenant: None };
            if !c.role_mappings.contains(&m) {
                c.role_mappings.push(m);
            }
        }
    }
    Ok(Some(c))
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

fn origin(u: &Url) -> String {
    u.origin().ascii_serialization()
}

/// The provider metadata this client uses.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

/// Who a valid token says the caller is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Default)]
struct Keys {
    set: Option<JwkSet>,
    fetched_at: Option<Instant>,
}

pub struct Oidc {
    pub settings: OidcSettings,
    http: reqwest::Client,
    metadata: tokio::sync::Mutex<(Option<Arc<ProviderMetadata>>, Option<Instant>)>,
    keys: tokio::sync::Mutex<Keys>,
}

impl Oidc {
    pub fn new(settings: OidcSettings) -> Result<Self, String> {
        let mut b = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            // Only the issuer's own endpoints; a redirect elsewhere is an error.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("caliban-control-plane/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = &settings.ca_file {
            let pem = std::fs::read(path).map_err(|e| format!("security.oidc.ca_file {path}: {e}"))?;
            for cert in
                reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| format!("security.oidc.ca_file {path}: {e}"))?
            {
                b = b.add_root_certificate(cert);
            }
        }
        let http = b.build().map_err(|e| format!("building the OIDC HTTP client: {e}"))?;
        Ok(Self { settings, http, metadata: tokio::sync::Mutex::default(), keys: tokio::sync::Mutex::default() })
    }

    /// Bearer access tokens are accepted only with an `api_audience`.
    pub fn accepts_bearer(&self) -> bool {
        self.settings.api_audience.is_some()
    }

    /// Provider metadata from discovery, cached. A failed refresh keeps serving the cached copy.
    pub async fn metadata(&self) -> Result<Arc<ProviderMetadata>, OidcError> {
        let mut g = self.metadata.lock().await;
        let (cached, at) = &*g;
        let due = match (cached, at) {
            (Some(_), Some(t)) => t.elapsed() > METADATA_TTL,
            (None, Some(t)) => t.elapsed() > METADATA_RETRY,
            _ => true,
        };
        if !due {
            return cached.clone().ok_or_else(|| OidcError::Unavailable("discovery failed recently".into()));
        }
        match self.discover().await {
            Ok(m) => {
                let m = Arc::new(m);
                *g = (Some(Arc::clone(&m)), Some(Instant::now()));
                Ok(m)
            }
            Err(e) => {
                tracing::warn!(error = %e, issuer = %self.settings.issuer, "OIDC discovery failed");
                let keep = g.0.clone();
                *g = (keep.clone(), Some(Instant::now()));
                keep.ok_or(e)
            }
        }
    }

    async fn discover(&self) -> Result<ProviderMetadata, OidcError> {
        let url = format!("{}/.well-known/openid-configuration", self.settings.issuer.trim_end_matches('/'));
        let m: ProviderMetadata = self.get_json(&url).await?;
        // OIDC Discovery 1.0 section 4.3: the issuer must match exactly.
        if m.issuer != self.settings.issuer {
            return Err(OidcError::Unavailable(format!(
                "discovery reports issuer '{}', expected '{}'",
                m.issuer, self.settings.issuer
            )));
        }
        let issuer = Url::parse(&self.settings.issuer).map_err(|e| OidcError::Unavailable(e.to_string()))?;
        for (what, u) in [
            ("authorization_endpoint", &m.authorization_endpoint),
            ("token_endpoint", &m.token_endpoint),
            ("jwks_uri", &m.jwks_uri),
        ] {
            let parsed = Url::parse(u).map_err(|e| OidcError::Unavailable(format!("{what}: {e}")))?;
            if parsed.origin() != issuer.origin() {
                return Err(OidcError::Unavailable(format!(
                    "{what} {u} is not on the issuer's origin {}",
                    issuer.origin().ascii_serialization()
                )));
            }
        }
        Ok(m)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, OidcError> {
        let resp = self.http.get(url).send().await.map_err(|e| OidcError::Unavailable(format!("{url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(OidcError::Unavailable(format!("{url}: HTTP {}", resp.status())));
        }
        resp.json().await.map_err(|e| OidcError::Unavailable(format!("{url}: {e}")))
    }

    /// The signing key for a token header. Fetches the JWKS when the cache is stale, and again
    /// (rate limited) when the key id is unknown, which is how provider key rotation is picked up.
    async fn key(&self, kid: Option<&str>, alg: Algorithm) -> Result<Jwk, OidcError> {
        let mut keys = self.keys.lock().await;
        let stale = keys.fetched_at.is_none_or(|t| t.elapsed() > self.settings.jwks_cache);
        if stale {
            self.refresh_keys(&mut keys).await?;
        }
        if let Some(k) = keys.set.as_ref().and_then(|s| pick(s, kid, alg)) {
            return Ok(k);
        }
        if !stale && keys.fetched_at.is_some_and(|t| t.elapsed() >= self.settings.jwks_min_refresh) {
            self.refresh_keys(&mut keys).await?;
            if let Some(k) = keys.set.as_ref().and_then(|s| pick(s, kid, alg)) {
                return Ok(k);
            }
        }
        Err(OidcError::token("unknown_key", format!("no signing key for kid {kid:?} and {alg:?}")))
    }

    async fn refresh_keys(&self, keys: &mut Keys) -> Result<(), OidcError> {
        let meta = self.metadata().await?;
        match self.get_json::<JwkSet>(&meta.jwks_uri).await {
            Ok(set) => {
                keys.set = Some(set);
                keys.fetched_at = Some(Instant::now());
                Ok(())
            }
            Err(e) if keys.set.is_some() => {
                // Keep validating with the keys we have; try again after the minimum interval.
                tracing::warn!(error = %e, "JWKS refresh failed; keeping cached keys");
                keys.fetched_at = Some(Instant::now());
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Validates a JWT signed by the provider for `audience` and returns its claims.
    async fn validate(&self, token: &str, audience: &str) -> Result<Value, OidcError> {
        let header = jsonwebtoken::decode_header(token).map_err(|e| OidcError::token("malformed", e.to_string()))?;
        if !ALGORITHMS.contains(&header.alg) {
            return Err(OidcError::token("algorithm", format!("{:?} is not accepted", header.alg)));
        }
        let jwk = self.key(header.kid.as_deref(), header.alg).await?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| OidcError::token("unknown_key", e.to_string()))?;
        let mut v = Validation::new(header.alg);
        v.set_issuer(&[&self.settings.issuer]);
        v.set_audience(&[audience]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        v.leeway = self.settings.clock_skew_secs;
        v.validate_exp = true;
        v.validate_nbf = true;
        let data = jsonwebtoken::decode::<Value>(token, &key, &v).map_err(|e| {
            use jsonwebtoken::errors::ErrorKind as K;
            let reason = match e.kind() {
                K::InvalidSignature => "signature",
                K::ExpiredSignature => "expired",
                K::ImmatureSignature => "not_yet_valid",
                K::InvalidIssuer => "issuer",
                K::InvalidAudience => "audience",
                K::InvalidAlgorithm | K::InvalidAlgorithmName => "algorithm",
                K::MissingRequiredClaim(_) => "missing_claim",
                _ => "malformed",
            };
            OidcError::token(reason, e.to_string())
        })?;
        let claims = data.claims;
        // `iat` in the future (beyond the skew) means a wrong clock or a forged token.
        if let Some(iat) = claims.get("iat").and_then(Value::as_u64)
            && iat > jsonwebtoken::get_current_timestamp() + self.settings.clock_skew_secs
        {
            return Err(OidcError::token("not_yet_valid", "iat is in the future"));
        }
        Ok(claims)
    }

    /// ID token from the code flow (OIDC Core 3.1.3.7): signature, `iss`, `aud` = client id,
    /// `azp` when there are several audiences, `exp`, `iat`, and the `nonce` of this login.
    pub async fn validate_id_token(&self, token: &str, nonce: &str) -> Result<Identity, OidcError> {
        let claims = self.validate(token, &self.settings.client_id).await?;
        if claims.get("iat").and_then(Value::as_u64).is_none() {
            return Err(OidcError::token("missing_claim", "iat"));
        }
        let auds = match claims.get("aud") {
            Some(Value::Array(a)) => a.len(),
            _ => 1,
        };
        let azp = claims.get("azp").and_then(Value::as_str);
        if (auds > 1 || azp.is_some()) && azp != Some(self.settings.client_id.as_str()) {
            return Err(OidcError::token("audience", "azp is not this client"));
        }
        let sent = claims.get("nonce").and_then(Value::as_str).unwrap_or_default();
        if !super::constant_time_eq(sent.as_bytes(), nonce.as_bytes()) || nonce.is_empty() {
            return Err(OidcError::token("nonce", "nonce does not match this login"));
        }
        self.identity(&claims)
    }

    /// Access token sent as `Authorization: Bearer` (CI, scripts): signature, `iss`, `aud` =
    /// `api_audience`, `exp`, `nbf`. ID tokens are refused.
    pub async fn validate_access_token(&self, token: &str) -> Result<Identity, OidcError> {
        let audience = self
            .settings
            .api_audience
            .as_deref()
            .ok_or_else(|| OidcError::token("audience", "access tokens are not accepted (no api_audience)"))?;
        let header = jsonwebtoken::decode_header(token).map_err(|e| OidcError::token("malformed", e.to_string()))?;
        if let Some(typ) = header.typ.as_deref() {
            let t = typ.to_ascii_lowercase();
            if !matches!(t.as_str(), "jwt" | "at+jwt" | "application/at+jwt") {
                return Err(OidcError::token("token_type", format!("typ {typ} is not an access token")));
            }
        }
        let claims = self.validate(token, audience).await?;
        // Keycloak marks ID tokens with `typ: ID`; they are not credentials for an API.
        if claims.get("typ").and_then(Value::as_str).is_some_and(|t| t.eq_ignore_ascii_case("id")) {
            return Err(OidcError::token("token_type", "an ID token is not an access token"));
        }
        self.identity(&claims)
    }

    fn identity(&self, claims: &Value) -> Result<Identity, OidcError> {
        let s = |k: &str| claims.get(k).and_then(Value::as_str).map(str::to_owned).filter(|v| !v.is_empty());
        let subject = s("sub").ok_or_else(|| OidcError::token("missing_claim", "sub"))?;
        let groups = match claim_path(claims, &self.settings.groups_claim) {
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
            Some(Value::String(g)) => vec![g.clone()],
            _ => vec![],
        };
        Ok(Identity {
            issuer: self.settings.issuer.clone(),
            subject,
            email: s("email"),
            name: s("name").or_else(|| s("preferred_username")),
            groups,
        })
    }

    /// The URL the browser is sent to for login.
    pub async fn authorize_url(&self, state: &str, nonce: &str, verifier: &str) -> Result<String, OidcError> {
        let meta = self.metadata().await?;
        let mut u = Url::parse(&meta.authorization_endpoint).map_err(|e| OidcError::Unavailable(e.to_string()))?;
        u.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.settings.client_id)
            .append_pair("redirect_uri", self.settings.redirect_url.as_str())
            .append_pair("scope", &self.settings.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", &pkce_challenge(verifier))
            .append_pair("code_challenge_method", "S256");
        Ok(u.into())
    }

    /// Exchanges the authorization code (with the PKCE verifier) for the ID token.
    pub async fn exchange_code(&self, code: &str, verifier: &str) -> Result<String, OidcError> {
        let meta = self.metadata().await?;
        let mut form = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("redirect_uri", self.settings.redirect_url.to_string()),
            ("code_verifier", verifier.to_owned()),
        ];
        let mut req = self.http.post(&meta.token_endpoint);
        match &self.settings.client_secret {
            Some(r) => {
                let secret = r.resolve().map_err(|e| OidcError::TokenEndpoint(format!("client secret: {e}")))?;
                let basic = meta
                    .token_endpoint_auth_methods_supported
                    .as_ref()
                    .is_none_or(|m| m.iter().any(|x| x == "client_secret_basic"));
                if basic {
                    // RFC 6749 section 2.3.1: form-encode both parts before Basic.
                    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
                    req = req.basic_auth(enc(&self.settings.client_id), Some(enc(secret.expose())));
                } else {
                    form.push(("client_id", self.settings.client_id.clone()));
                    form.push(("client_secret", secret.expose().to_owned()));
                }
            }
            None => form.push(("client_id", self.settings.client_id.clone())),
        }
        let resp = req.form(&form).send().await.map_err(|e| OidcError::Unavailable(e.to_string()))?;
        let status = resp.status();
        let body: Value = resp.json().await.map_err(|e| OidcError::TokenEndpoint(format!("HTTP {status}: {e}")))?;
        if !status.is_success() {
            let err = body.get("error").and_then(Value::as_str).unwrap_or("unknown");
            return Err(OidcError::TokenEndpoint(format!("HTTP {status}: {err}")));
        }
        body.get("id_token")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| OidcError::TokenEndpoint("no id_token in the response".into()))
    }

    /// RP-initiated logout at the provider, if it supports it.
    pub async fn end_session_url(&self) -> Option<String> {
        let meta = self.metadata().await.ok()?;
        let mut u = Url::parse(meta.end_session_endpoint.as_deref()?).ok()?;
        u.query_pairs_mut()
            .append_pair("client_id", &self.settings.client_id)
            .append_pair("post_logout_redirect_uri", &self.settings.post_logout_redirect_url);
        Some(u.into())
    }
}

/// The key for `kid` (or the only usable key when the token names none), usable for `alg`.
fn pick(set: &JwkSet, kid: Option<&str>, alg: Algorithm) -> Option<Jwk> {
    let usable = |k: &&Jwk| {
        let alg_ok = k.common.key_algorithm.is_none_or(|ka| Algorithm::from_str(&ka.to_string()).ok() == Some(alg));
        let use_ok = k.common.public_key_use.as_ref().is_none_or(|u| *u == PublicKeyUse::Signature);
        let family_ok = DecodingKey::from_jwk(k).is_ok_and(|d| d.family() == alg.family());
        alg_ok && use_ok && family_ok
    };
    match kid {
        Some(kid) => set.keys.iter().filter(|k| k.common.key_id.as_deref() == Some(kid)).find(usable).cloned(),
        None => {
            let mut it = set.keys.iter().filter(usable);
            match (it.next(), it.next()) {
                (Some(k), None) => Some(k.clone()),
                _ => None,
            }
        }
    }
}

/// A claim by dotted path (`realm_access.roles`); a literal key containing dots wins.
fn claim_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(v) = claims.get(path) {
        return Some(v);
    }
    path.split('.').try_fold(claims, |v, k| v.get(k))
}

/// RFC 7636 S256: `base64url(sha256(verifier))`.
pub fn pkce_challenge(verifier: &str) -> String {
    B64URL.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_matches_rfc7636_appendix_b() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn groups_claim_paths() {
        let c = serde_json::json!({"groups": ["a"], "realm_access": {"roles": ["x", "y"]}, "a.b": "lit"});
        assert_eq!(claim_path(&c, "groups"), Some(&serde_json::json!(["a"])));
        assert_eq!(claim_path(&c, "realm_access.roles"), Some(&serde_json::json!(["x", "y"])));
        assert_eq!(claim_path(&c, "a.b"), Some(&serde_json::json!("lit")));
        assert_eq!(claim_path(&c, "nope.x"), None);
    }

    fn cfg(toml: &str) -> Result<OidcSettings, String> {
        OidcSettings::from_config(&toml::from_str::<OidcConfig>(toml).unwrap())
    }

    #[test]
    fn settings_are_checked() {
        let base = "issuer = \"https://idp.example.test/realms/c\"\nclient_id = \"caliban\"\nredirect_url = \"https://console.example.test/auth/callback\"\n";
        let s = cfg(base).unwrap();
        assert!(s.secure_cookies());
        assert_eq!(s.console_origin(), "https://console.example.test");
        assert_eq!(s.post_logout_redirect_url, "https://console.example.test/");
        assert_eq!(s.scopes, ["openid", "profile", "email"]);
        assert!(cfg(&base.replace("/auth/callback", "/cb")).is_err());
        assert!(cfg(&format!("{base}scopes = [\"profile\"]\n")).is_err());
        let mapping =
            |role: &str, tenant: &str| format!("{base}[[role_mappings]]\ngroup = \"g\"\nrole = \"{role}\"\n{tenant}");
        assert!(cfg(&mapping("owner", "")).is_ok());
        assert!(cfg(&mapping("owner", "tenant = \"acme\"\n")).is_err());
        assert!(cfg(&mapping("developer", "")).is_err());
        assert_eq!(cfg(&mapping("developer", "tenant = \"acme\"\n")).unwrap().role_mappings[0].1, Role::Developer);
        assert!(cfg(&mapping("superuser", "")).unwrap_err().contains("unknown role"));
        let http = cfg(&base.replace("https://console", "http://console")).unwrap();
        assert!(!http.secure_cookies());
    }
}
