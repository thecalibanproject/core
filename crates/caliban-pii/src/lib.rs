//! PII protection for the request path.
//!
//! Pipeline (docs/research/05-anonymization-and-privacy.md §1–3):
//! - **L0** deterministic detection: regex + validators ([`patterns`]) and tenant dictionaries
//!   compiled from the ontology ([`dictionary`]).
//! - **L1** small token-classification NER model in-process via ONNX Runtime ([`ner`], cargo
//!   feature `ner`, off by default). Load a verified artifact with
//!   `NerDetector::load(dir, NerOptions::default())` and add it with
//!   `PiiEngine::default().with_detector(ner)`. Model choice, licences and how to fetch the
//!   artifact: `crates/caliban-pii/MODELS.md`.
//! - **L2** optional local LLM verifier for strict mode (TODO).
//!
//! Spans from all tiers are unioned by [`merge_spans`] (longest span wins, then higher risk).
//! A detector that fails (e.g. ONNX inference error) makes [`PiiEngine::protect`] return
//! [`PiiError::DetectorFailed`]: the request fails closed rather than going out half-scrubbed.
//!
//! Detected spans are replaced with realistic, type-consistent **surrogates** ([`surrogate`]),
//! consistent within a scope, and recorded in a [`Vault`]. Responses (including streams) are
//! restored with [`Rehydrator`] / [`StreamingRehydrator`].
//!
//! # Surrogate scopes and the exact cache
//!
//! Surrogates are a pure function of `(scope_key, entity type, normalized value)` (an HMAC, see
//! [`surrogate`]), so no shared state is needed to keep them consistent. The caller picks the
//! scope by choosing `scope_key` for [`PiiEngine::protect`]:
//!
//! - **request** (default today): 32 random bytes per request. Nothing links two requests.
//! - **tenant**: [`tenant_scope_key`]`(server_secret, tenant_id)` =
//!   `HMAC-SHA256(server_secret, "caliban-pii/scope/tenant/v1" ‖ 0 ‖ tenant_id)`. Identical
//!   requests from one tenant then produce byte-identical protected requests, so the exact
//!   cache (keyed on the *protected* request) can hit, and a cached response rehydrates with
//!   the new request's own vault because the surrogates are the same.
//! - **session**: [`session_scope_key`]`(server_secret, tenant_id, session_id)`, for agent
//!   memory / multi-turn consistency without cross-session linkability.
//!
//! `server_secret` is a per-deployment secret (≥ 32 random bytes, from the KMS / secret store,
//! never from config files in plain text), so surrogates cannot be precomputed by anyone who
//! does not hold it, and rotating it re-keys every scope. Trade-off: in a tenant scope the
//! upstream provider sees the same surrogate for the same person across requests (linkable, but
//! not identifiable). The collision guard can still bump a surrogate when it already occurs in
//! the request text, which is deterministic for identical requests but may differ between two
//! different requests that mention the same entity; that only costs a cache miss.

pub mod dictionary;
pub mod ner;
pub mod patterns;
pub mod rehydrate;
pub mod surrogate;

pub use dictionary::DictionaryDetector;
#[cfg(feature = "ner")]
pub use ner::{NerDetector, NerOptions};
pub use ner::NerError;
pub use patterns::PatternDetector;
pub use rehydrate::{Rehydrator, StreamingRehydrator};
pub use surrogate::Vault;

use caliban_ir::ChatRequest;
use caliban_types::PiiMode;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityType {
    Email,
    Phone,
    CreditCard,
    Iban,
    IpAddress,
    UsSsn,
    Person,
    Organization,
    /// Cities, street addresses and other places (L1 NER `LOC` / `CITY` / `STREET_ADDRESS` ...).
    Location,
    /// Credentials (API keys, tokens). Never forwarded: the request is blocked.
    Secret,
    /// Tenant-defined label from the ontology (e.g. "customer_id").
    Custom(String),
}

impl EntityType {
    pub fn label(&self) -> &str {
        match self {
            EntityType::Email => "EMAIL",
            EntityType::Phone => "PHONE",
            EntityType::CreditCard => "CARD",
            EntityType::Iban => "IBAN",
            EntityType::IpAddress => "IP",
            EntityType::UsSsn => "SSN",
            EntityType::Person => "PERSON",
            EntityType::Organization => "ORG",
            EntityType::Location => "LOCATION",
            EntityType::Secret => "SECRET",
            EntityType::Custom(s) => s.as_str(),
        }
    }

    /// Higher wins when overlapping spans have equal length.
    fn risk(&self) -> u8 {
        match self {
            EntityType::Secret => 9,
            EntityType::CreditCard | EntityType::UsSsn | EntityType::Iban => 8,
            EntityType::Email | EntityType::Phone => 6,
            EntityType::Person => 5,
            EntityType::Custom(_) => 4,
            EntityType::Organization | EntityType::Location | EntityType::IpAddress => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub entity: EntityType,
}

impl Span {
    fn len(&self) -> usize {
        self.end - self.start
    }
}

pub trait Detector: Send + Sync {
    fn detect(&self, text: &str) -> Vec<Span>;

    /// Fallible detection, used by [`PiiEngine::protect`]. Detectors that can fail at runtime
    /// (model inference) override this so a failure blocks the request instead of silently
    /// returning no spans. The default never fails.
    fn try_detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        Ok(self.detect(text))
    }
}

/// A detector could not run (e.g. ONNX Runtime error). The request must not be forwarded.
#[derive(Debug, thiserror::Error)]
#[error("{detector}: {message}")]
pub struct DetectError {
    pub detector: &'static str,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PiiError {
    #[error("request contains a credential ({0}); credentials are never forwarded to models")]
    SecretDetected(String),
    #[error("PII detection failed, request blocked (fail closed): {0}")]
    DetectorFailed(#[from] DetectError),
}

type HmacSha256 = Hmac<Sha256>;

fn derive_scope_key(server_secret: &[u8], label: &str, parts: &[&str]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(server_secret).expect("hmac accepts any key length");
    mac.update(label.as_bytes());
    for p in parts {
        mac.update(&[0]);
        // Length-prefix each part so ("ab","c") and ("a","bc") differ.
        mac.update(&(p.len() as u64).to_le_bytes());
        mac.update(p.as_bytes());
    }
    mac.finalize().into_bytes().into()
}

/// Scope key for **tenant-scoped** surrogates: the same value gets the same surrogate in every
/// request of `tenant_id`, so identical requests produce identical protected requests (exact
/// cache hits). `server_secret` is the deployment's secret; see the crate docs.
pub fn tenant_scope_key(server_secret: &[u8], tenant_id: &str) -> [u8; 32] {
    derive_scope_key(server_secret, "caliban-pii/scope/tenant/v1", &[tenant_id])
}

/// Scope key for **session-scoped** surrogates (consistent across the turns of one
/// conversation, unlinkable across sessions).
pub fn session_scope_key(server_secret: &[u8], tenant_id: &str, session_id: &str) -> [u8; 32] {
    derive_scope_key(server_secret, "caliban-pii/scope/session/v1", &[tenant_id, session_id])
}

/// Union of spans; overlaps resolved by preferring the longer span, then the higher-risk type.
/// Biased toward recall: a missed entity costs more than an extra one.
pub fn merge_spans(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.len().cmp(&a.len()))
            .then(b.entity.risk().cmp(&a.entity.risk()))
    });
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for s in spans {
        match out.last_mut() {
            Some(last) if s.start < last.end => {
                let better = s.len() > last.len() || (s.len() == last.len() && s.entity.risk() > last.entity.risk());
                if better {
                    *last = s;
                }
            }
            _ => out.push(s),
        }
    }
    out
}

/// Runs a set of detectors and rewrites a request in place.
pub struct PiiEngine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Default for PiiEngine {
    fn default() -> Self {
        Self { detectors: vec![Box::new(PatternDetector::new())] }
    }
}

/// Result of protecting one request.
#[derive(Debug, Default)]
pub struct Protected {
    pub vault: Vault,
    pub entities: usize,
}

impl PiiEngine {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    pub fn with_detector(mut self, d: impl Detector + 'static) -> Self {
        self.detectors.push(Box::new(d));
        self
    }

    /// Best-effort detection (a failing detector contributes no spans). Use [`Self::try_detect`]
    /// wherever a miss matters.
    pub fn detect(&self, text: &str) -> Vec<Span> {
        merge_spans(self.detectors.iter().flat_map(|d| d.detect(text)).collect())
    }

    /// Detection that fails if any detector fails.
    pub fn try_detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        let mut all = Vec::new();
        for d in &self.detectors {
            all.extend(d.try_detect(text)?);
        }
        Ok(merge_spans(all))
    }

    /// Protects every text segment of the request. `scope_key` makes surrogates consistent within
    /// a scope: random per request, or [`tenant_scope_key`] / [`session_scope_key`] (see the
    /// crate docs). The reverse map ([`Vault`]) is still per call; persisting it for session or
    /// tenant scopes (encrypted, TTL) is TODO.
    pub fn protect(&self, req: &mut ChatRequest, mode: PiiMode, scope_key: &[u8]) -> Result<Protected, PiiError> {
        let mut out = Protected { vault: Vault::new(scope_key), entities: 0 };
        if mode == PiiMode::Off {
            return Ok(out);
        }
        // Collect originals first so the collision guard can reject surrogates that already occur.
        let mut all_text = String::new();
        req.for_each_text_mut(|_, s| {
            all_text.push_str(s);
            all_text.push('\n');
        });
        out.vault.set_collision_corpus(&all_text);

        let mut err = None;
        req.for_each_text_mut(|_, s| {
            if err.is_some() {
                return;
            }
            let spans = match self.try_detect(s) {
                Ok(spans) => spans,
                Err(e) => {
                    err = Some(PiiError::DetectorFailed(e));
                    return;
                }
            };
            if let Some(sec) = spans.iter().find(|sp| sp.entity == EntityType::Secret) {
                err = Some(PiiError::SecretDetected(redact_preview(&s[sec.start..sec.end])));
                return;
            }
            out.entities += spans.len();
            *s = rewrite(s, &spans, mode, &mut out.vault);
        });
        match err {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }
}

fn rewrite(text: &str, spans: &[Span], mode: PiiMode, vault: &mut Vault) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for sp in spans {
        out.push_str(&text[cursor..sp.start]);
        let original = &text[sp.start..sp.end];
        match mode {
            PiiMode::Mask => {
                out.push('[');
                out.push_str(sp.entity.label());
                out.push(']');
            }
            PiiMode::Reversible => out.push_str(&vault.surrogate_for(&sp.entity, original)),
            PiiMode::Off => out.push_str(original),
        }
        cursor = sp.end;
    }
    out.push_str(&text[cursor..]);
    out
}

fn redact_preview(s: &str) -> String {
    let head: String = s.chars().take(4).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chat(text: &str) -> ChatRequest {
        let body = format!(r#"{{"model":"m","messages":[{{"role":"user","content":{}}}]}}"#, serde_json_string(text));
        ChatRequest::from_openai_json(body.as_bytes()).unwrap()
    }

    fn serde_json_string(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }

    #[test]
    fn round_trip_restores_originals() {
        let engine = PiiEngine::default();
        let original = "Email jane.doe@acme.com or call +1 415 555 2671 about card 4111 1111 1111 1111.";
        let mut req = chat(original);
        let p = engine.protect(&mut req, PiiMode::Reversible, b"scope").unwrap();
        assert_eq!(p.entities, 3);
        let sent = req.last_user_text().unwrap();
        assert!(!sent.contains("jane.doe@acme.com"));
        assert!(!sent.contains("4111 1111 1111 1111"));
        let restored = Rehydrator::new(&p.vault).rehydrate(&sent);
        assert_eq!(restored, original);
    }

    #[test]
    fn same_value_gets_same_surrogate_within_scope() {
        let engine = PiiEngine::default();
        let mut req = chat("a@x.io wrote to b@y.io, then a@x.io replied");
        engine.protect(&mut req, PiiMode::Reversible, b"s").unwrap();
        let sent = req.last_user_text().unwrap();
        let words: Vec<&str> = sent.split_whitespace().collect();
        assert_eq!(words[0], words[5].trim_end_matches(','));
        assert_ne!(words[0], words[3].trim_end_matches(','));
    }

    #[test]
    fn secrets_block_the_request() {
        let engine = PiiEngine::default();
        let mut req = chat("my key is sk-proj-abcdefghijklmnopqrstuvwxyz0123456789");
        assert!(matches!(engine.protect(&mut req, PiiMode::Reversible, b"s"), Err(PiiError::SecretDetected(_))));
    }

    #[test]
    fn mask_mode_is_not_reversible() {
        let engine = PiiEngine::default();
        let mut req = chat("ping 10.0.0.12 now");
        let p = engine.protect(&mut req, PiiMode::Mask, b"s").unwrap();
        assert_eq!(req.last_user_text().unwrap(), "ping [IP] now");
        assert!(p.vault.is_empty());
    }

    struct Failing;
    impl Detector for Failing {
        fn detect(&self, _: &str) -> Vec<Span> {
            Vec::new()
        }
        fn try_detect(&self, _: &str) -> Result<Vec<Span>, DetectError> {
            Err(DetectError { detector: "test", message: "boom".into() })
        }
    }

    #[test]
    fn failing_detector_fails_closed() {
        let engine = PiiEngine::default().with_detector(Failing);
        let mut req = chat("Email jane.doe@acme.com");
        let err = engine.protect(&mut req, PiiMode::Reversible, b"s").unwrap_err();
        assert!(matches!(err, PiiError::DetectorFailed(_)), "{err}");
        // Off mode never runs detectors.
        assert!(engine.protect(&mut chat("x"), PiiMode::Off, b"s").is_ok());
    }

    #[test]
    fn tenant_scope_keys_are_stable_and_separated() {
        let secret = b"0123456789abcdef0123456789abcdef";
        assert_eq!(tenant_scope_key(secret, "acme"), tenant_scope_key(secret, "acme"));
        assert_ne!(tenant_scope_key(secret, "acme"), tenant_scope_key(secret, "globex"));
        assert_ne!(tenant_scope_key(secret, "acme"), tenant_scope_key(b"another-secret", "acme"));
        assert_ne!(session_scope_key(secret, "acme", "s1"), session_scope_key(secret, "acme", "s2"));
        // Domain separation and length prefixes.
        assert_ne!(session_scope_key(secret, "ab", "c"), session_scope_key(secret, "a", "bc"));
        assert_ne!(tenant_scope_key(secret, "acme").to_vec(), session_scope_key(secret, "acme", "").to_vec());

        // Identical requests in one tenant scope → identical protected text; other tenants differ.
        let engine = PiiEngine::default();
        let text = "Mail jane.doe@acme.com, card 4111 1111 1111 1111";
        let protect = |key: &[u8]| {
            let mut r = chat(text);
            engine.protect(&mut r, PiiMode::Reversible, key).unwrap();
            r.last_user_text().unwrap()
        };
        let k = tenant_scope_key(secret, "acme");
        assert_eq!(protect(&k), protect(&k));
        assert_ne!(protect(&k), protect(&tenant_scope_key(secret, "globex")));
    }

    #[test]
    fn merge_prefers_longer_then_riskier() {
        let spans = vec![
            Span { start: 0, end: 5, entity: EntityType::IpAddress },
            Span { start: 0, end: 10, entity: EntityType::Phone },
            Span { start: 12, end: 15, entity: EntityType::Organization },
            Span { start: 12, end: 15, entity: EntityType::Person },
        ];
        let m = merge_spans(spans);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].entity, EntityType::Phone);
        assert_eq!(m[1].entity, EntityType::Person);
    }
}
