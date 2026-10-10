//! Secret references and the key hierarchy for secrets stored by the control plane.
//!
//! ```text
//! KEK keyring  (CALIBAN_KEK = current, CALIBAN_KEK_PREVIOUS = retired keys still accepted)
//!   └─ per-tenant DEK, wrapped by one KEK     AES-256-GCM, AAD = tenant id + KEK id
//!        └─ the tenant's secrets              AES-256-GCM, AAD = tenant id
//!             (BYOK provider keys, datasource credentials)
//! ```
//!
//! A KEK is identified by a fingerprint of the key (`kek_` + 16 hex characters of a SHA-256 over
//! the key), so operators never name or number keys and two different keys cannot share an id.
//! Deployment-wide secrets (shared provider keys) are sealed directly under the current KEK.
//! All primitives come from the `aes-gcm` crate; key material is zeroized when dropped.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

/// Environment variable holding the current KEK (base64 of 32 bytes).
pub const KEK_ENV: &str = "CALIBAN_KEK";
/// Environment variable holding retired KEKs (base64, comma or whitespace separated). They are
/// only used to open values sealed before a rotation; nothing new is sealed under them.
pub const KEK_PREVIOUS_ENV: &str = "CALIBAN_KEK_PREVIOUS";

/// Reference to a secret. Secrets are never written inline in config files.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SecretRef {
    Env {
        env: String,
    },
    File {
        file: String,
    },
    /// AES-256-GCM ciphertext under a KEK of the process keyring (any key of the keyring opens
    /// it). Used for deployment-wide secrets such as shared provider keys.
    Sealed {
        sealed: String,
    },
    /// A tenant secret sealed under the tenant's DEK, with the DEK wrapped by a KEK. Rendered by
    /// the control plane into data-plane snapshots so a router can open it with its keyring alone.
    TenantSealed {
        tenant_sealed: TenantSealed,
    },
}

/// Self-contained tenant envelope (see [`SecretRef::TenantSealed`]).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantSealed {
    pub tenant: String,
    /// The KEK that wraps `wrapped_dek`.
    pub kek_id: String,
    /// base64(nonce ‖ wrapped DEK).
    pub wrapped_dek: String,
    /// base64(nonce ‖ ciphertext) under the DEK.
    pub sealed: String,
}

impl SecretRef {
    /// Resolves with the process keyring (`CALIBAN_KEK`, `CALIBAN_KEK_PREVIOUS`) for sealed values.
    pub fn resolve(&self) -> Result<Secret, crate::ConfigError> {
        match self {
            SecretRef::Env { env } => std::env::var(env)
                .map(Secret)
                .map_err(|_| crate::ConfigError::Secret(env.clone(), "environment variable not set".into())),
            SecretRef::File { file } => std::fs::read_to_string(file)
                .map(|s| Secret(s.trim_end().to_owned()))
                .map_err(|e| crate::ConfigError::Secret(file.clone(), e.to_string())),
            SecretRef::Sealed { .. } | SecretRef::TenantSealed { .. } => {
                let keyring = process_keyring()
                    .and_then(|k| k.ok_or_else(|| format!("{KEK_ENV} is not set")))
                    .map_err(|e| crate::ConfigError::Secret(KEK_ENV.into(), e))?;
                self.resolve_with(keyring)
            }
        }
    }

    /// Resolves sealed values with `keyring` (references are resolved as usual).
    pub fn resolve_with(&self, keyring: &Keyring) -> Result<Secret, crate::ConfigError> {
        match self {
            SecretRef::Sealed { sealed } => {
                keyring.open(sealed).map(Secret).map_err(|e| crate::ConfigError::Secret("sealed".into(), e))
            }
            SecretRef::TenantSealed { tenant_sealed: t } => {
                let fail = |e: String| crate::ConfigError::Secret(format!("tenant {} secret", t.tenant), e);
                let wrapped = WrappedDek { kek_id: t.kek_id.clone(), wrapped: t.wrapped_dek.clone() };
                let dek = keyring.unwrap_dek(&t.tenant, &wrapped).map_err(fail)?;
                dek.open(&t.tenant, &t.sealed).map(Secret).map_err(fail)
            }
            other => other.resolve(),
        }
    }
}

/// Ids of the KEKs that sealed the secrets in `config`, sorted and deduplicated: the `kek_id` of
/// every `tenant_sealed` envelope, and for values sealed directly under a KEK (`{ sealed }`) the
/// id of the key of `keyring` that opens them (`"unknown"` when none does or there is no
/// keyring). This is what a data plane needs in its keyring to open everything in `config`.
pub fn sealed_kek_ids(config: &crate::Config, keyring: Option<&Keyring>) -> Vec<String> {
    fn walk(v: &serde_json::Value, keyring: Option<&Keyring>, out: &mut std::collections::BTreeSet<String>) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(id) = m.get("tenant_sealed").and_then(|t| t.get("kek_id")).and_then(|i| i.as_str()) {
                    out.insert(id.to_owned());
                    return;
                }
                if m.len() == 1
                    && let Some(sealed) = m.get("sealed").and_then(|s| s.as_str())
                {
                    out.insert(keyring.and_then(|k| k.opener_id(sealed)).unwrap_or("unknown").to_owned());
                    return;
                }
                m.values().for_each(|x| walk(x, keyring, out));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, keyring, out)),
            _ => {}
        }
    }
    let mut out = std::collections::BTreeSet::new();
    if let Ok(v) = serde_json::to_value(config) {
        walk(&v, keyring, &mut out);
    }
    out.into_iter().collect()
}

/// A resolved secret. `Debug` never prints the value; the memory is zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn last4(&self) -> String {
        let n = self.0.chars().count();
        self.0.chars().skip(n.saturating_sub(4)).collect()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(****)")
    }
}

// ───────────────────────────── KEK keyring ─────────────────────────────

/// Key-encryption keys: the current one (seals and wraps) first, then retired ones (open only).
pub struct Keyring {
    keys: Vec<(String, Zeroizing<[u8; 32]>)>,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring").field("ids", &self.ids()).finish()
    }
}

/// `kek_` + the first 16 hex characters of SHA-256 over a domain label and the key.
pub fn kek_id(key: &[u8; 32]) -> String {
    let digest = Sha256::new().chain_update(b"caliban kek id v1\0").chain_update(key).finalize();
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("kek_{hex}")
}

fn decode_key(name: &str, b64: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let bytes = Zeroizing::new(B64.decode(b64.trim()).map_err(|e| format!("{name} is not base64: {e}"))?);
    if bytes.len() != 32 {
        return Err(format!("{name} must decode to exactly 32 bytes"));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

impl Keyring {
    /// `previous` keys equal to `current` (or to each other) are ignored.
    pub fn new(current: [u8; 32], previous: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let mut keys = vec![(kek_id(&current), Zeroizing::new(current))];
        for k in previous {
            let id = kek_id(&k);
            if !keys.iter().any(|(i, _)| *i == id) {
                keys.push((id, Zeroizing::new(k)));
            }
        }
        Self { keys }
    }

    /// From base64 values: `current`, and `previous` (comma or whitespace separated, may be empty).
    pub fn parse(current: &str, previous: &str) -> Result<Self, String> {
        let cur = decode_key(KEK_ENV, current)?;
        let mut prev = Vec::new();
        for (i, p) in previous.split([',', ' ', '\n', '\t']).filter(|p| !p.trim().is_empty()).enumerate() {
            prev.push(decode_key(&format!("{KEK_PREVIOUS_ENV} entry {}", i + 1), p)?);
        }
        Ok(Self::new(*cur, prev.iter().map(|k| **k)))
    }

    /// `CALIBAN_KEK` and `CALIBAN_KEK_PREVIOUS`. `Ok(None)` when no KEK is configured.
    pub fn from_env() -> Result<Option<Self>, String> {
        let current = std::env::var(KEK_ENV).ok().filter(|v| !v.trim().is_empty());
        let previous = std::env::var(KEK_PREVIOUS_ENV).ok().filter(|v| !v.trim().is_empty());
        match (current, previous) {
            (Some(c), p) => Self::parse(&c, p.as_deref().unwrap_or_default()).map(Some),
            (None, Some(_)) => Err(format!("{KEK_PREVIOUS_ENV} is set but {KEK_ENV} is not")),
            (None, None) => Ok(None),
        }
    }

    pub fn current_id(&self) -> &str {
        &self.keys[0].0
    }

    pub fn current_key(&self) -> &[u8; 32] {
        &self.keys[0].1
    }

    /// Every KEK id, current first.
    pub fn ids(&self) -> Vec<&str> {
        self.keys.iter().map(|(id, _)| id.as_str()).collect()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.keys.iter().any(|(i, _)| i == id)
    }

    fn key(&self, id: &str) -> Option<&[u8; 32]> {
        self.keys.iter().find(|(i, _)| i == id).map(|(_, k)| &**k)
    }

    /// Seals a deployment-wide secret under the current KEK.
    pub fn seal(&self, plaintext: &str) -> String {
        seal(self.current_key(), plaintext)
    }

    /// Opens a value sealed under any KEK of the keyring (current first).
    pub fn open(&self, sealed: &str) -> Result<String, String> {
        self.keys.iter().find_map(|(_, k)| open(k, sealed).ok()).ok_or_else(|| {
            format!("decryption failed: no key of the keyring ({KEK_ENV}, {KEK_PREVIOUS_ENV}) opens this value")
        })
    }

    /// True when `sealed` opens with the current KEK (nothing to re-seal on rotation).
    pub fn opens_with_current(&self, sealed: &str) -> bool {
        open(self.current_key(), sealed).is_ok()
    }

    /// The id of the KEK that opens `sealed`, if any key of the keyring does.
    pub fn opener_id(&self, sealed: &str) -> Option<&str> {
        self.keys.iter().find(|(_, k)| open(k, sealed).is_ok()).map(|(id, _)| id.as_str())
    }

    /// Wraps `dek` for `tenant` under the current KEK.
    pub fn wrap_dek(&self, tenant: &str, dek: &Dek) -> WrappedDek {
        let id = self.current_id();
        let wrapped = encrypt(self.current_key(), &dek_aad(tenant, id), &dek.0[..]);
        WrappedDek { kek_id: id.to_owned(), wrapped }
    }

    /// Unwraps a tenant DEK. Fails if its KEK is not in the keyring, or if the wrapped key was
    /// moved to another tenant or relabelled with another KEK id (both are associated data).
    pub fn unwrap_dek(&self, tenant: &str, w: &WrappedDek) -> Result<Dek, String> {
        let kek = self.key(&w.kek_id).ok_or_else(|| {
            format!(
                "the tenant key is wrapped by KEK {}, which is not in this process's keyring ({KEK_ENV}, {KEK_PREVIOUS_ENV})",
                w.kek_id
            )
        })?;
        let raw = decrypt(kek, &dek_aad(tenant, &w.kek_id), &w.wrapped)
            .map_err(|_| "unwrapping the tenant key failed".to_string())?;
        if raw.len() != 32 {
            return Err("unwrapped tenant key has the wrong length".into());
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&raw);
        Ok(Dek(key))
    }
}

/// The process keyring from the environment, loaded once.
pub fn process_keyring() -> Result<Option<&'static Keyring>, String> {
    static KEYRING: OnceLock<Result<Option<Keyring>, String>> = OnceLock::new();
    KEYRING.get_or_init(Keyring::from_env).as_ref().map(Option::as_ref).map_err(Clone::clone)
}

/// The current KEK of the process keyring (`CALIBAN_KEK`). Also the input of the per-tenant
/// `cache_salt` and PII surrogate key derivations on the data plane.
pub fn process_kek() -> Result<&'static [u8; 32], String> {
    process_keyring()?.map(Keyring::current_key).ok_or_else(|| format!("{KEK_ENV} is not set"))
}

// ───────────────────────────── tenant DEKs ─────────────────────────────

/// A tenant data-encryption key (plaintext, in memory only while in use).
pub struct Dek(Zeroizing<[u8; 32]>);

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek(****)")
    }
}

impl Dek {
    pub fn generate() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut key[..]);
        Self(key)
    }

    /// Seals a secret of `tenant`: base64(nonce ‖ ciphertext), the tenant id as associated data.
    pub fn seal(&self, tenant: &str, plaintext: &str) -> String {
        encrypt(&self.0, &secret_aad(tenant), plaintext.as_bytes())
    }

    pub fn open(&self, tenant: &str, sealed: &str) -> Result<String, String> {
        let pt = decrypt(&self.0, &secret_aad(tenant), sealed)
            .map_err(|_| "decryption failed (wrong tenant key?)".to_string())?;
        String::from_utf8(pt.to_vec()).map_err(|e| e.to_string())
    }
}

/// A DEK wrapped by the KEK `kek_id`: base64(nonce ‖ ciphertext), associated data = tenant id and
/// KEK id.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WrappedDek {
    pub kek_id: String,
    pub wrapped: String,
}

fn dek_aad(tenant: &str, kek_id: &str) -> Vec<u8> {
    [b"caliban/dek/v1\0".as_slice(), tenant.as_bytes(), b"\0", kek_id.as_bytes()].concat()
}

fn secret_aad(tenant: &str) -> Vec<u8> {
    [b"caliban/secret/v1\0".as_slice(), tenant.as_bytes()].concat()
}

fn encrypt(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> String {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg, aad }).expect("aes-gcm encrypt");
    let mut out = nonce.to_vec();
    out.extend(ct);
    B64.encode(out)
}

fn decrypt(key: &[u8; 32], aad: &[u8], sealed: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let raw = B64.decode(sealed).map_err(|e| e.to_string())?;
    if raw.len() < 13 {
        return Err("ciphertext too short".into());
    }
    let (nonce, ct) = raw.split_at(12);
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| "decryption failed".into())
}

/// Encrypts with AES-256-GCM (no associated data); output is base64(nonce ‖ ciphertext).
pub fn seal(kek: &[u8; 32], plaintext: &str) -> String {
    encrypt(kek, &[], plaintext.as_bytes())
}

pub fn open(kek: &[u8; 32], sealed: &str) -> Result<String, String> {
    let pt = decrypt(kek, &[], sealed)
        .map_err(|e| if e == "decryption failed" { "decryption failed (wrong KEK?)".to_string() } else { e })?;
    String::from_utf8(pt.to_vec()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip_and_wrong_key_fails() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let s = seal(&k1, "sk-test-123");
        assert_eq!(open(&k1, &s).unwrap(), "sk-test-123");
        assert!(open(&k2, &s).is_err());
    }

    #[test]
    fn keyring_parses_dedupes_and_opens_with_retired_keys() {
        let b = |k: u8| B64.encode([k; 32]);
        assert!(Keyring::parse("nope", "").is_err());
        assert!(Keyring::parse(&B64.encode([1u8; 16]), "").is_err());
        assert!(Keyring::parse(&b(1), "not-base64!").is_err());
        let old = Keyring::parse(&b(1), "").unwrap();
        let sealed = old.seal("sk-test-old");
        let ring = Keyring::parse(&b(2), &format!("{}, {}\n{}", b(1), b(2), b(1))).unwrap();
        assert_eq!(ring.ids(), [kek_id(&[2; 32]), kek_id(&[1; 32])]);
        assert_eq!(ring.current_id(), kek_id(&[2; 32]));
        assert!(ring.current_id().starts_with("kek_") && ring.current_id().len() == 20);
        assert_eq!(ring.open(&sealed).unwrap(), "sk-test-old");
        assert!(!ring.opens_with_current(&sealed));
        assert!(ring.opens_with_current(&ring.seal("x")));
        assert!(Keyring::parse(&b(3), "").unwrap().open(&sealed).is_err());
        assert!(!format!("{ring:?}").contains(&b(2)));
    }

    #[test]
    fn sealed_kek_ids_lists_what_a_router_needs() {
        let old = Keyring::new([1; 32], []);
        let ring = Keyring::new([2; 32], [[1; 32]]);
        let mut cfg = crate::Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
        assert!(sealed_kek_ids(&cfg, Some(&ring)).is_empty(), "the example has no sealed secret");
        // A tenant envelope still wrapped by the old KEK, and a shared value sealed under it.
        let dek = Dek::generate();
        let w = old.wrap_dek("acme", &dek);
        cfg.tenants[0].providers[0].api_key = Some(SecretRef::TenantSealed {
            tenant_sealed: TenantSealed {
                tenant: "acme".into(),
                kek_id: w.kek_id.clone(),
                wrapped_dek: w.wrapped,
                sealed: dek.seal("acme", "sk-test"),
            },
        });
        cfg.security.admin_token = Some(SecretRef::Sealed { sealed: old.seal("x") });
        assert_eq!(sealed_kek_ids(&cfg, Some(&ring)), [old.current_id()]);
        // After rotation both are under the new KEK.
        let w = ring.wrap_dek("acme", &dek);
        if let Some(SecretRef::TenantSealed { tenant_sealed }) = &mut cfg.tenants[0].providers[0].api_key {
            tenant_sealed.kek_id = w.kek_id;
        }
        cfg.security.admin_token = Some(SecretRef::Sealed { sealed: ring.seal("x") });
        assert_eq!(sealed_kek_ids(&cfg, Some(&ring)), [ring.current_id()]);
        // Without the keyring, a directly sealed value cannot be attributed.
        assert_eq!(sealed_kek_ids(&cfg, None), [ring.current_id().to_owned(), "unknown".into()]);
    }

    #[test]
    fn tenant_envelope_round_trip_and_binding() {
        let ring = Keyring::new([1; 32], []);
        let dek = Dek::generate();
        let w = ring.wrap_dek("acme", &dek);
        assert_eq!(w.kek_id, ring.current_id());
        let ct = dek.seal("acme", "sk-test-acme");
        let env = TenantSealed {
            tenant: "acme".into(),
            kek_id: w.kek_id.clone(),
            wrapped_dek: w.wrapped.clone(),
            sealed: ct.clone(),
        };
        let r = SecretRef::TenantSealed { tenant_sealed: env.clone() };
        assert_eq!(r.resolve_with(&ring).unwrap().expose(), "sk-test-acme");
        // The JSON shape round-trips through the untagged enum.
        let back: SecretRef = serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        // Moving the envelope to another tenant, or relabelling the KEK, fails.
        let moved = SecretRef::TenantSealed { tenant_sealed: TenantSealed { tenant: "globex".into(), ..env.clone() } };
        assert!(moved.resolve_with(&ring).is_err());
        let other = Keyring::new([2; 32], [[1; 32]]);
        let relabelled =
            SecretRef::TenantSealed { tenant_sealed: TenantSealed { kek_id: other.current_id().into(), ..env } };
        assert!(relabelled.resolve_with(&other).is_err());
        // A secret of one tenant does not open with another tenant's AAD, even with the same DEK.
        assert!(dek.open("globex", &ct).is_err());
        // After rotation the old wrap still opens while the old KEK is in the keyring, and the
        // re-wrapped DEK opens without it.
        let rotated = Keyring::new([2; 32], [[1; 32]]);
        let re = rotated.wrap_dek("acme", &rotated.unwrap_dek("acme", &w).unwrap());
        assert_ne!(re.kek_id, w.kek_id);
        let new_only = Keyring::new([2; 32], []);
        assert_eq!(new_only.unwrap_dek("acme", &re).unwrap().open("acme", &ct).unwrap(), "sk-test-acme");
        let err = new_only.unwrap_dek("acme", &w).unwrap_err();
        assert!(err.contains(&w.kek_id) && err.contains("not in this process's keyring"), "{err}");
    }
}
