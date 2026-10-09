//! Signed config snapshots for split deployments (control plane → routers).
//!
//! The control plane renders a [`Config`], serializes it once into a deterministic JSON payload
//! (`version`, `issued_at_ms`, `config`), and signs `DOMAIN ‖ payload` with Ed25519. The wire
//! envelope carries the payload as base64 of the exact signed bytes, so routers verify without any
//! re-canonicalization. Sealed BYOK secrets stay sealed inside the payload: routers need the same
//! `CALIBAN_KEK` to use them.
//!
//! Keys: the control plane signs with `CALIBAN_SNAPSHOT_SIGNING_KEY` (base64 of a 32-byte
//! Ed25519 seed); routers verify with `CALIBAN_SNAPSHOT_PUBLIC_KEY` (base64 of the 32-byte public
//! key; a comma-separated list is accepted for key rotation).

use crate::Config;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation: a signature over a snapshot can never be valid for anything else.
const DOMAIN: &[u8] = b"caliban-snapshot-v1\0";

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("invalid key: {0}")]
    Key(String),
    #[error("malformed snapshot: {0}")]
    Malformed(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("no trusted public key with id {0}")]
    UnknownKey(String),
    #[error("snapshot config is invalid: {0}")]
    Invalid(String),
}

/// The signed content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPayload {
    /// Control-plane version label (e.g. `cp-42`, the audit-log head when rendered).
    pub version: String,
    /// Unix milliseconds. Routers reject a snapshot older than the one they serve (anti-rollback).
    pub issued_at_ms: u64,
    pub config: Config,
}

/// Wire envelope served by `GET /api/v1/snapshot` and persisted by routers as their cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSnapshot {
    /// First 16 hex chars of sha256(public key).
    pub key_id: String,
    /// base64 of the exact payload bytes that were signed.
    pub payload: String,
    /// base64 Ed25519 signature over `DOMAIN ‖ payload bytes`.
    pub signature: String,
}

/// Content digest of a config (hex sha256 of its JSON serialization). Stable across control-plane
/// replicas rendering the same state; used as the snapshot ETag.
pub fn config_digest(config: &Config) -> String {
    let bytes = serde_json::to_vec(config).unwrap_or_default();
    hex_encode(&Sha256::digest(&bytes))
}

pub fn key_id(vk: &VerifyingKey) -> String {
    hex_encode(&Sha256::digest(vk.as_bytes()))[..16].to_owned()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decode32(what: &str, s: &str) -> Result<[u8; 32], SnapshotError> {
    let raw = B64.decode(s.trim()).map_err(|e| SnapshotError::Key(format!("{what} is not base64: {e}")))?;
    raw.try_into().map_err(|_| SnapshotError::Key(format!("{what} must decode to exactly 32 bytes")))
}

/// Control-plane side.
pub struct SnapshotSigner {
    key: SigningKey,
    key_id: String,
}

impl std::fmt::Debug for SnapshotSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotSigner").field("key_id", &self.key_id).finish_non_exhaustive()
    }
}

impl SnapshotSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(seed);
        let key_id = key_id(&key.verifying_key());
        Self { key, key_id }
    }

    /// From base64 of a 32-byte seed (`CALIBAN_SNAPSHOT_SIGNING_KEY`).
    pub fn from_b64(seed: &str) -> Result<Self, SnapshotError> {
        Ok(Self::from_seed(&decode32("CALIBAN_SNAPSHOT_SIGNING_KEY", seed)?))
    }

    /// `Ok(None)` when `CALIBAN_SNAPSHOT_SIGNING_KEY` is unset.
    pub fn from_env() -> Result<Option<Self>, SnapshotError> {
        match std::env::var("CALIBAN_SNAPSHOT_SIGNING_KEY") {
            Ok(s) if !s.trim().is_empty() => Self::from_b64(&s).map(Some),
            _ => Ok(None),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.key.verifying_key().as_bytes())
    }

    pub fn sign(&self, payload: &SnapshotPayload) -> Result<SignedSnapshot, SnapshotError> {
        let bytes = serde_json::to_vec(payload).map_err(|e| SnapshotError::Malformed(e.to_string()))?;
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&bytes);
        let sig = self.key.sign(&msg);
        Ok(SignedSnapshot { key_id: self.key_id.clone(), payload: B64.encode(&bytes), signature: B64.encode(sig.to_bytes()) })
    }
}

/// Router side: a set of trusted public keys.
#[derive(Debug, Clone)]
pub struct SnapshotVerifier {
    keys: Vec<(String, VerifyingKey)>,
}

impl SnapshotVerifier {
    pub fn new(keys: Vec<VerifyingKey>) -> Self {
        Self { keys: keys.into_iter().map(|k| (key_id(&k), k)).collect() }
    }

    /// Comma-separated base64 public keys (`CALIBAN_SNAPSHOT_PUBLIC_KEY`).
    pub fn from_b64_list(list: &str) -> Result<Self, SnapshotError> {
        let mut keys = Vec::new();
        for part in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let raw = decode32("CALIBAN_SNAPSHOT_PUBLIC_KEY", part)?;
            keys.push(VerifyingKey::from_bytes(&raw).map_err(|e| SnapshotError::Key(e.to_string()))?);
        }
        if keys.is_empty() {
            return Err(SnapshotError::Key("CALIBAN_SNAPSHOT_PUBLIC_KEY is empty".into()));
        }
        Ok(Self::new(keys))
    }

    /// Verifies the signature, then parses and validates the config. Nothing in the payload is
    /// trusted before the signature checks out.
    pub fn verify(&self, s: &SignedSnapshot) -> Result<SnapshotPayload, SnapshotError> {
        let (_, vk) = self.keys.iter().find(|(id, _)| *id == s.key_id).ok_or_else(|| SnapshotError::UnknownKey(s.key_id.clone()))?;
        let bytes = B64.decode(&s.payload).map_err(|e| SnapshotError::Malformed(format!("payload: {e}")))?;
        let sig = B64.decode(&s.signature).map_err(|e| SnapshotError::Malformed(format!("signature: {e}")))?;
        let sig = Signature::from_slice(&sig).map_err(|_| SnapshotError::BadSignature)?;
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&bytes);
        vk.verify_strict(&msg, &sig).map_err(|_| SnapshotError::BadSignature)?;
        let payload: SnapshotPayload = serde_json::from_slice(&bytes).map_err(|e| SnapshotError::Malformed(e.to_string()))?;
        payload.config.validate().map_err(|e| SnapshotError::Invalid(e.to_string()))?;
        Ok(payload)
    }
}

/// New random signing seed; returns (seed_b64 for the control plane, public_key_b64 for routers).
pub fn generate_signing_key() -> (String, String) {
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let s = SnapshotSigner::from_seed(&seed);
    (B64.encode(seed), s.public_key_b64())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> SnapshotPayload {
        let config = Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
        SnapshotPayload { version: "cp-7".into(), issued_at_ms: 1_700_000_000_000, config }
    }

    fn pair() -> (SnapshotSigner, SnapshotVerifier) {
        let (seed, public) = generate_signing_key();
        (SnapshotSigner::from_b64(&seed).unwrap(), SnapshotVerifier::from_b64_list(&public).unwrap())
    }

    #[test]
    fn round_trip() {
        let (signer, verifier) = pair();
        let signed = signer.sign(&payload()).unwrap();
        let out = verifier.verify(&signed).unwrap();
        assert_eq!(out.version, "cp-7");
        assert_eq!(config_digest(&out.config), config_digest(&payload().config));
        // Survives the JSON wire format (what the router receives and caches).
        let wire: SignedSnapshot = serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();
        assert!(verifier.verify(&wire).is_ok());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let (signer, verifier) = pair();
        let mut signed = signer.sign(&payload()).unwrap();
        let mut bytes = B64.decode(&signed.payload).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap().replace("t0_sovereign", "t3_public");
        bytes = text.into_bytes();
        signed.payload = B64.encode(&bytes);
        assert!(matches!(verifier.verify(&signed), Err(SnapshotError::BadSignature)));
    }

    #[test]
    fn tampered_signature_and_wrong_key_are_rejected() {
        let (signer, verifier) = pair();
        let good = signer.sign(&payload()).unwrap();
        let mut sig = B64.decode(&good.signature).unwrap();
        sig[0] ^= 1;
        let bad = SignedSnapshot { signature: B64.encode(sig), ..good.clone() };
        assert!(matches!(verifier.verify(&bad), Err(SnapshotError::BadSignature)));

        // A different signer whose key id is spoofed to match the trusted one.
        let (other, _) = pair();
        let forged = SignedSnapshot { key_id: good.key_id.clone(), ..other.sign(&payload()).unwrap() };
        assert!(matches!(verifier.verify(&forged), Err(SnapshotError::BadSignature)));
        // Unknown key id.
        assert!(matches!(verifier.verify(&other.sign(&payload()).unwrap()), Err(SnapshotError::UnknownKey(_))));
    }

    #[test]
    fn rotation_accepts_any_listed_key() {
        let (s1, _) = pair();
        let (s2, _) = pair();
        let v = SnapshotVerifier::from_b64_list(&format!("{}, {}", s1.public_key_b64(), s2.public_key_b64())).unwrap();
        assert!(v.verify(&s1.sign(&payload()).unwrap()).is_ok());
        assert!(v.verify(&s2.sign(&payload()).unwrap()).is_ok());
    }
}
