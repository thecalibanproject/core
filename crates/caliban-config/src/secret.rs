use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::OnceLock;

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
    /// AES-256-GCM ciphertext under the process KEK (`CALIBAN_KEK`). Used for BYOK keys added
    /// through the control plane.
    Sealed {
        sealed: String,
    },
}

impl SecretRef {
    pub fn resolve(&self) -> Result<Secret, crate::ConfigError> {
        match self {
            SecretRef::Env { env } => std::env::var(env)
                .map(Secret)
                .map_err(|_| crate::ConfigError::Secret(env.clone(), "environment variable not set".into())),
            SecretRef::File { file } => std::fs::read_to_string(file)
                .map(|s| Secret(s.trim_end().to_owned()))
                .map_err(|e| crate::ConfigError::Secret(file.clone(), e.to_string())),
            SecretRef::Sealed { sealed } => {
                let kek = process_kek().map_err(|e| crate::ConfigError::Secret("CALIBAN_KEK".into(), e))?;
                open(kek, sealed).map(Secret).map_err(|e| crate::ConfigError::Secret("sealed".into(), e))
            }
        }
    }
}

/// A resolved secret. `Debug` never prints the value.
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

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(****)")
    }
}

/// Key-encryption key from `CALIBAN_KEK` (base64 of 32 bytes), loaded once.
/// TODO: PKCS#11 / KMS / Vault backends; per-tenant DEKs wrapped by the KEK.
pub fn process_kek() -> Result<&'static [u8; 32], String> {
    static KEK: OnceLock<Result<[u8; 32], String>> = OnceLock::new();
    KEK.get_or_init(|| {
        let raw = std::env::var("CALIBAN_KEK").map_err(|_| "CALIBAN_KEK is not set".to_string())?;
        let bytes = B64.decode(raw.trim()).map_err(|e| format!("CALIBAN_KEK is not base64: {e}"))?;
        bytes.try_into().map_err(|_| "CALIBAN_KEK must decode to exactly 32 bytes".to_string())
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// Encrypts with AES-256-GCM; output is base64(nonce ‖ ciphertext).
pub fn seal(kek: &[u8; 32], plaintext: &str) -> String {
    let cipher = Aes256Gcm::new(kek.into());
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes()).expect("aes-gcm encrypt");
    let mut out = nonce.to_vec();
    out.extend(ct);
    B64.encode(out)
}

pub fn open(kek: &[u8; 32], sealed: &str) -> Result<String, String> {
    let raw = B64.decode(sealed).map_err(|e| e.to_string())?;
    if raw.len() < 13 {
        return Err("ciphertext too short".into());
    }
    let (nonce, ct) = raw.split_at(12);
    let cipher = Aes256Gcm::new(kek.into());
    let pt = cipher.decrypt(Nonce::from_slice(nonce), ct).map_err(|_| "decryption failed (wrong KEK?)".to_string())?;
    String::from_utf8(pt).map_err(|e| e.to_string())
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
}
