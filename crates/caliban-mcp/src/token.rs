//! Tokens minted per tool call. Client tokens are never passed through to tool servers.
//!
//! For each call, the worker mints a JWT (JWS compact, `EdDSA` over Ed25519) for exactly that call:
//!
//! | Claim | Value |
//! |---|---|
//! | `iss` | `CALIBAN_TOOL_TOKEN_ISSUER` (default `caliban`) |
//! | `aud` | the server's registered audience (default: its URL's origin) |
//! | `sub` | `tenant:<tenant>/node:<name>@v<version>` |
//! | `scope` | `tool:<tool>`: the one tool being called (down-scoped) |
//! | `tenant`, `node`, `node_version`, `run_id`, `tool` | the same, as separate claims |
//! | `iat`, `nbf`, `exp` | now, now, now + 60 s |
//! | `jti` | unique per call (the step's idempotency key: a replayed step reuses it) |
//!
//! The signing key is `CALIBAN_TOOL_TOKEN_KEY` (a base64 Ed25519 seed, `caliban gen-tool-token-key`)
//! on the processes that run nodes (workers, standalone). Rotation: generate a new key, move the
//! old one's public key to `CALIBAN_TOOL_TOKEN_PREVIOUS_KEYS`, restart; tokens live 60 s, so the
//! previous key can be dropped a few minutes after every worker runs the new one. The JWKS lists
//! the current and previous public keys (`kid` = the first 16 hex characters of the SHA-256 of
//! the public key); the control plane serves it at `/.well-known/caliban-tool-jwks.json`, and a
//! server that cannot fetch it can be configured with the public keys directly.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64URL};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// How long a minted token is valid.
pub const TOKEN_TTL_SECS: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub scope: String,
    pub tenant: String,
    pub node: String,
    pub node_version: u32,
    pub run_id: String,
    pub tool: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub jti: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("tool token key: {0}")]
    Key(String),
    #[error("invalid token: {0}")]
    Invalid(String),
}

/// The key id of a public key.
pub fn key_id(vk: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(vk.as_bytes()))[..16].to_owned()
}

/// Signs tool tokens; lists the public keys servers verify them with.
pub struct ToolTokenSigner {
    key: SigningKey,
    kid: String,
    issuer: String,
    previous: Vec<VerifyingKey>,
}

impl std::fmt::Debug for ToolTokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolTokenSigner").field("kid", &self.kid).field("issuer", &self.issuer).finish_non_exhaustive()
    }
}

fn decode32(what: &str, b64: &str) -> Result<[u8; 32], TokenError> {
    let raw = STANDARD.decode(b64.trim()).map_err(|e| TokenError::Key(format!("{what} is not base64: {e}")))?;
    raw.try_into().map_err(|_| TokenError::Key(format!("{what} must be 32 bytes")))
}

impl ToolTokenSigner {
    pub fn new(seed: &[u8; 32], issuer: impl Into<String>, previous: Vec<VerifyingKey>) -> Self {
        let key = SigningKey::from_bytes(seed);
        let kid = key_id(&key.verifying_key());
        Self { key, kid, issuer: issuer.into(), previous }
    }

    /// `seed`: base64 Ed25519 seed; `previous`: base64 public keys, comma separated.
    pub fn from_b64(seed: &str, issuer: &str, previous: &str) -> Result<Self, TokenError> {
        let seed = decode32("CALIBAN_TOOL_TOKEN_KEY", seed)?;
        let previous = previous
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|p| {
                VerifyingKey::from_bytes(&decode32("CALIBAN_TOOL_TOKEN_PREVIOUS_KEYS", p)?)
                    .map_err(|e| TokenError::Key(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(&seed, if issuer.trim().is_empty() { "caliban" } else { issuer.trim() }, previous))
    }

    /// From `CALIBAN_TOOL_TOKEN_KEY`, `CALIBAN_TOOL_TOKEN_ISSUER`, `CALIBAN_TOOL_TOKEN_PREVIOUS_KEYS`.
    pub fn from_env() -> Result<Option<Self>, TokenError> {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        let Some(seed) = env("CALIBAN_TOOL_TOKEN_KEY") else { return Ok(None) };
        Self::from_b64(
            &seed,
            &env("CALIBAN_TOOL_TOKEN_ISSUER").unwrap_or_default(),
            &env("CALIBAN_TOOL_TOKEN_PREVIOUS_KEYS").unwrap_or_default(),
        )
        .map(Some)
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn key_id(&self) -> &str {
        &self.kid
    }

    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.key.verifying_key().as_bytes())
    }

    /// A token for one call. `now`: Unix seconds.
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        &self,
        audience: &str,
        tenant: &str,
        node: &str,
        node_version: u32,
        run_id: &str,
        tool: &str,
        jti: &str,
        now: i64,
    ) -> String {
        let claims = ToolClaims {
            iss: self.issuer.clone(),
            aud: audience.to_owned(),
            sub: format!("tenant:{tenant}/node:{node}@v{node_version}"),
            scope: format!("tool:{tool}"),
            tenant: tenant.to_owned(),
            node: node.to_owned(),
            node_version,
            run_id: run_id.to_owned(),
            tool: tool.to_owned(),
            iat: now,
            nbf: now,
            exp: now + TOKEN_TTL_SECS,
            jti: jti.to_owned(),
        };
        let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": self.kid});
        let signing_input = format!(
            "{}.{}",
            B64URL.encode(header.to_string()),
            B64URL.encode(serde_json::to_vec(&claims).unwrap_or_default())
        );
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64URL.encode(sig.to_bytes()))
    }

    /// The JWKS: the current key and the previous ones (RFC 8037 OKP keys).
    pub fn jwks(&self) -> Value {
        let jwk = |vk: &VerifyingKey| {
            json!({"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": key_id(vk),
                   "x": B64URL.encode(vk.as_bytes())})
        };
        let mut keys = vec![jwk(&self.key.verifying_key())];
        keys.extend(self.previous.iter().map(jwk));
        json!({"keys": keys})
    }
}

/// Verifies a tool token against a JWKS (what a tool server does): signature, issuer, audience,
/// validity window (with `leeway` seconds). Returns the claims.
pub fn verify(
    token: &str,
    jwks: &Value,
    issuer: &str,
    audience: &str,
    now: i64,
    leeway: i64,
) -> Result<ToolClaims, TokenError> {
    let bad = |m: &str| TokenError::Invalid(m.to_owned());
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(bad("not a compact JWS"));
    };
    let header: Value =
        serde_json::from_slice(&B64URL.decode(h).map_err(|_| bad("header encoding"))?).map_err(|_| bad("header"))?;
    if header["alg"] != "EdDSA" {
        return Err(bad("unexpected alg"));
    }
    let kid = header["kid"].as_str().ok_or_else(|| bad("no kid"))?;
    let jwk =
        jwks["keys"].as_array().into_iter().flatten().find(|k| k["kid"] == kid).ok_or_else(|| bad("unknown kid"))?;
    let x = B64URL.decode(jwk["x"].as_str().unwrap_or_default()).map_err(|_| bad("jwk x"))?;
    let vk = VerifyingKey::from_bytes(&x.try_into().map_err(|_| bad("jwk x length"))?).map_err(|_| bad("jwk key"))?;
    let sig = Signature::from_slice(&B64URL.decode(s).map_err(|_| bad("signature encoding"))?)
        .map_err(|_| bad("signature"))?;
    vk.verify(format!("{h}.{p}").as_bytes(), &sig).map_err(|_| bad("signature does not verify"))?;
    let c: ToolClaims =
        serde_json::from_slice(&B64URL.decode(p).map_err(|_| bad("payload encoding"))?).map_err(|_| bad("claims"))?;
    if c.iss != issuer {
        return Err(bad("wrong issuer"));
    }
    if c.aud != audience {
        return Err(bad("wrong audience"));
    }
    if now + leeway < c.nbf || now - leeway >= c.exp {
        return Err(bad("expired or not yet valid"));
    }
    if c.scope != format!("tool:{}", c.tool) {
        return Err(bad("scope does not match the tool"));
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_audience_bound_short_lived_and_rotate() {
        let old = ToolTokenSigner::new(&[1; 32], "caliban", vec![]);
        let s = ToolTokenSigner::new(
            &[2; 32],
            "caliban",
            vec![
                VerifyingKey::from_bytes(&STANDARD.decode(old.public_key_b64()).unwrap().try_into().unwrap()).unwrap(),
            ],
        );
        let t = s.mint("https://crm.internal", "acme", "triage", 3, "run_1", "lookup", "jti-1", 1_000);
        let c = verify(&t, &s.jwks(), "caliban", "https://crm.internal", 1_010, 0).unwrap();
        assert_eq!((c.sub.as_str(), c.scope.as_str(), c.exp), ("tenant:acme/node:triage@v3", "tool:lookup", 1_060));
        assert!(verify(&t, &s.jwks(), "caliban", "https://other.internal", 1_010, 0).is_err(), "audience");
        assert!(verify(&t, &s.jwks(), "caliban", "https://crm.internal", 1_061, 0).is_err(), "expired");
        assert!(verify(&t, &s.jwks(), "someone", "https://crm.internal", 1_010, 0).is_err(), "issuer");
        let mut forged = t.clone();
        forged.replace_range(forged.len() - 4.., "AAAA");
        assert!(verify(&forged, &s.jwks(), "caliban", "https://crm.internal", 1_010, 0).is_err(), "signature");
        // A token from the previous key still verifies during the rotation.
        let prev = old.mint("https://crm.internal", "acme", "triage", 3, "run_1", "lookup", "jti-2", 1_000);
        assert!(verify(&prev, &s.jwks(), "caliban", "https://crm.internal", 1_000, 0).is_ok());
        assert_eq!(s.jwks()["keys"].as_array().unwrap().len(), 2);
        assert!(ToolTokenSigner::from_b64("short", "", "").is_err());
    }
}
