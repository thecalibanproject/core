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
//! consistent within a scope, and recorded in a per-request [`Vault`]. Responses (including
//! streams) are restored with [`Rehydrator`] / [`StreamingRehydrator`].
//!
//! # Surrogate scopes and the exact cache
//!
//! Surrogates are a pure function of `(scope key, entity type, normalised value)` (an HMAC, see
//! [`surrogate`]), so no shared state is needed to keep them consistent. The scope is a
//! per-tenant setting ([`PiiSurrogateScope`], `pii_surrogate_scope` in the tenant config) and
//! [`SurrogateKeys::scope_key`] turns it into the key for [`PiiEngine::protect`]:
//!
//! - **tenant** (default, docs/architecture §9): the tenant's surrogate key,
//!   `HKDF-SHA256(ikm = CALIBAN_KEK, salt = "caliban 2026 pii surrogate v1",
//!   info = "caliban/pii/surrogate/tenant/v1" ‖ 0 ‖ tenant_id)`. The same value in the same
//!   tenant always gets the same surrogate, so identical requests produce byte-identical
//!   protected requests and the exact cache (keyed on the *protected* request and the tenant)
//!   can hit. Every router of a deployment shares `CALIBAN_KEK`, so in split mode they all derive
//!   the same keys and the same surrogates. Different tenants get unrelated keys, so surrogates
//!   never cross tenants.
//! - **session** (per-tenant opt-in): 32 random bytes per request. Nothing links two requests,
//!   and requests carrying PII cannot hit the exact cache.
//!
//! Without `CALIBAN_KEK` the gateway derives from a random per-process secret instead
//! ([`SurrogateKeys::random`]): surrogates are then stable within one process only.
//!
//! Trade-off of tenant scope: the upstream provider sees the same surrogate for the same value
//! across sessions of the tenant (linkable, not identifiable). Nobody without the KEK can compute
//! or invert a surrogate, rotating the KEK re-keys every tenant, and no plaintext table is kept:
//! the reverse map of a request is built from the values seen in that request and dropped with
//! it. Collision handling and its probabilities are documented in [`surrogate`].

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
pub use caliban_types::PiiSurrogateScope;
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

    /// `true` for detectors whose cost (model inference, milliseconds of CPU) means they must not
    /// run on an async runtime's worker threads. The gateway runs engines with a heavy detector on
    /// its dedicated PII worker pool; regex and dictionary detectors are cheap and run inline.
    fn is_heavy(&self) -> bool {
        false
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

/// HKDF salt for surrogate keys (RFC 5869 extract step), next to the `cache_salt` key label in
/// the gateway. Changing it re-keys every tenant.
const SURROGATE_HKDF_SALT: &[u8] = b"caliban 2026 pii surrogate v1";
const TENANT_INFO: &[u8] = b"caliban/pii/surrogate/tenant/v1";

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 (RFC 5869) with a 32-byte output, i.e. one expand block:
/// `PRK = HMAC(salt, ikm)`, `OKM = HMAC(PRK, info ‖ 0x01)`.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = hmac_sha256(salt, &[ikm]);
    hmac_sha256(&prk, &[info, &[1]])
}

/// Derives the surrogate scope keys of a deployment from its key-encryption key.
///
/// Holds only the HKDF pseudo-random key (the extract step over `CALIBAN_KEK`); the per-tenant
/// key is one HMAC away. `Debug` never prints key material.
#[derive(Clone)]
pub struct SurrogateKeys {
    prk: [u8; 32],
}

impl std::fmt::Debug for SurrogateKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SurrogateKeys(..)")
    }
}

impl SurrogateKeys {
    /// From the process KEK (`CALIBAN_KEK`). Every router with the same KEK derives the same keys.
    pub fn from_kek(kek: &[u8; 32]) -> Self {
        Self { prk: hmac_sha256(SURROGATE_HKDF_SALT, &[kek]) }
    }

    /// Random per process, for deployments without a KEK: tenant-scope surrogates are then only
    /// stable within this process.
    pub fn random() -> Self {
        let mut ikm = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut ikm);
        Self::from_kek(&ikm)
    }

    /// The tenant's surrogate key: HKDF-Expand with `info = TENANT_INFO ‖ 0 ‖ tenant_id`.
    pub fn tenant_key(&self, tenant_id: &str) -> [u8; 32] {
        hmac_sha256(&self.prk, &[TENANT_INFO, &[0], tenant_id.as_bytes(), &[1]])
    }

    /// The scope key for one request of `tenant_id`: the tenant key, or fresh random bytes for
    /// session scope.
    pub fn scope_key(&self, scope: PiiSurrogateScope, tenant_id: &str) -> [u8; 32] {
        match scope {
            PiiSurrogateScope::Tenant => self.tenant_key(tenant_id),
            PiiSurrogateScope::Session => {
                let mut k = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rng(), &mut k);
                k
            }
        }
    }
}

/// Tenant surrogate key straight from a KEK: `SurrogateKeys::from_kek(kek).tenant_key(tenant_id)`.
pub fn tenant_scope_key(kek: &[u8; 32], tenant_id: &str) -> [u8; 32] {
    SurrogateKeys::from_kek(kek).tenant_key(tenant_id)
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

/// Which detectors a protect call runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tier {
    All,
    /// Non-heavy detectors only.
    Light,
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
        self.try_detect_tier(text, Tier::All)
    }

    fn try_detect_tier(&self, text: &str, tier: Tier) -> Result<Vec<Span>, DetectError> {
        let mut all = Vec::new();
        for d in self.detectors.iter().filter(|d| tier == Tier::All || !d.is_heavy()) {
            all.extend(d.try_detect(text)?);
        }
        Ok(merge_spans(all))
    }

    /// Whether any detector is heavy ([`Detector::is_heavy`]): such an engine should run off the
    /// async runtime.
    pub fn is_heavy(&self) -> bool {
        self.detectors.iter().any(|d| d.is_heavy())
    }

    /// Protects every text segment of the request. `scope_key` makes surrogates consistent within
    /// a scope: a tenant key or a random per-request key, see [`SurrogateKeys::scope_key`] and
    /// the crate docs. The returned [`Vault`] only knows the values of this request.
    ///
    /// Three passes: detect in every segment (a failing detector or a credential stops the
    /// request before anything is rewritten), assign surrogates to all values at once in
    /// canonical order (so collision handling does not depend on text order), then rewrite.
    pub fn protect(&self, req: &mut ChatRequest, mode: PiiMode, scope_key: &[u8]) -> Result<Protected, PiiError> {
        self.protect_tier(req, mode, scope_key, Tier::All)
    }

    /// [`Self::protect`] with the cheap detectors only (regex patterns, dictionaries), skipping
    /// heavy ones such as the NER model. Detects less (names, organisations and places are found
    /// by the model), so callers must only use it as an explicit, operator-chosen degradation.
    pub fn protect_light(&self, req: &mut ChatRequest, mode: PiiMode, scope_key: &[u8]) -> Result<Protected, PiiError> {
        self.protect_tier(req, mode, scope_key, Tier::Light)
    }

    fn protect_tier(&self, req: &mut ChatRequest, mode: PiiMode, scope_key: &[u8], tier: Tier) -> Result<Protected, PiiError> {
        let mut out = Protected { vault: Vault::new(scope_key), entities: 0 };
        if mode == PiiMode::Off {
            return Ok(out);
        }
        let mut all_text = String::new();
        let mut found: Vec<Vec<Span>> = Vec::new();
        let mut values: Vec<(EntityType, String)> = Vec::new();
        let mut err = None;
        req.for_each_text_mut(|_, s| {
            if err.is_some() {
                return;
            }
            let spans = match self.try_detect_tier(s, tier) {
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
            all_text.push_str(s);
            all_text.push('\n');
            values.extend(spans.iter().map(|sp| (sp.entity.clone(), s[sp.start..sp.end].to_owned())));
            found.push(spans);
        });
        if let Some(e) = err {
            return Err(e);
        }
        // The collision guard rejects surrogates that already occur in the original text.
        out.vault.set_collision_corpus(&all_text);
        if mode == PiiMode::Reversible {
            out.vault.assign(values.iter().map(|(e, o)| (e, o.as_str())));
        }
        let mut found = found.into_iter();
        req.for_each_text_mut(|_, s| {
            let spans = found.next().unwrap_or_default();
            out.entities += spans.len();
            *s = rewrite(s, &spans, mode, &mut out.vault);
        });
        Ok(out)
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

    /// A stand-in for the NER model: marks "Zed" as a person.
    struct Heavy;
    impl Detector for Heavy {
        fn detect(&self, text: &str) -> Vec<Span> {
            text.match_indices("Zed").map(|(i, m)| Span { start: i, end: i + m.len(), entity: EntityType::Person }).collect()
        }
        fn is_heavy(&self) -> bool {
            true
        }
    }

    #[test]
    fn protect_light_skips_heavy_detectors_only() {
        let engine = PiiEngine::default().with_detector(Heavy);
        assert!(engine.is_heavy());
        assert!(!PiiEngine::default().is_heavy());
        let mut full = chat("Zed: zed@acme.com");
        assert_eq!(engine.protect(&mut full, PiiMode::Mask, b"s").unwrap().entities, 2);
        assert_eq!(full.last_user_text().unwrap(), "[PERSON]: [EMAIL]");
        let mut light = chat("Zed: zed@acme.com");
        assert_eq!(engine.protect_light(&mut light, PiiMode::Mask, b"s").unwrap().entities, 1);
        assert_eq!(light.last_user_text().unwrap(), "Zed: [EMAIL]");
        let mut secret = chat("Zed sk-proj-abcdefghijklmnopqrstuvwxyz0123456789");
        assert!(matches!(engine.protect_light(&mut secret, PiiMode::Mask, b"s"), Err(PiiError::SecretDetected(_))), "credentials still block");
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

    const KEK: [u8; 32] = *b"0123456789abcdef0123456789abcdef";

    fn protect_with(key: &[u8], text: &str) -> (String, Protected) {
        let mut r = chat(text);
        let p = PiiEngine::default().protect(&mut r, PiiMode::Reversible, key).unwrap();
        (r.last_user_text().unwrap(), p)
    }

    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        assert_eq!(hex::encode(hkdf_sha256(&salt, &ikm, &info)), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
        // The tenant key is that construction with the documented salt and info.
        let mut info = TENANT_INFO.to_vec();
        info.push(0);
        info.extend_from_slice(b"acme");
        assert_eq!(hkdf_sha256(SURROGATE_HKDF_SALT, &KEK, &info), tenant_scope_key(&KEK, "acme"));
    }

    #[test]
    fn tenant_keys_are_stable_and_separated() {
        let keys = SurrogateKeys::from_kek(&KEK);
        assert_eq!(keys.tenant_key("acme"), tenant_scope_key(&KEK, "acme"));
        assert_ne!(keys.tenant_key("acme"), keys.tenant_key("globex"));
        assert_ne!(keys.tenant_key("acme"), keys.tenant_key("acme2"));
        assert_ne!(keys.tenant_key("acme"), SurrogateKeys::from_kek(&[9; 32]).tenant_key("acme"));
        assert_eq!(keys.scope_key(PiiSurrogateScope::Tenant, "acme"), keys.tenant_key("acme"));
        assert!(!format!("{keys:?}").contains(&hex::encode(keys.prk)));
    }

    /// Split mode: two routers that only share `CALIBAN_KEK` derive the same keys and therefore
    /// send byte-identical protected requests.
    #[test]
    fn routers_with_the_same_kek_derive_identical_surrogates() {
        let router_a = SurrogateKeys::from_kek(&KEK);
        let router_b = SurrogateKeys::from_kek(&KEK.clone());
        assert_eq!(router_a.tenant_key("acme"), router_b.tenant_key("acme"));
        let text = "Mail jane.doe@acme.com, card 4111 1111 1111 1111";
        let (a, _) = protect_with(&router_a.tenant_key("acme"), text);
        let (b, _) = protect_with(&router_b.tenant_key("acme"), text);
        assert_eq!(a, b);
    }

    #[test]
    fn tenant_scope_is_stable_across_requests_and_separated_between_tenants() {
        let keys = SurrogateKeys::from_kek(&KEK);
        let acme = keys.scope_key(PiiSurrogateScope::Tenant, "acme");
        // Same value, different requests and surrounding text: same surrogate.
        let (one, p1) = protect_with(&acme, "Mail jane.doe@acme.com today");
        let (two, p2) = protect_with(&acme, "Is jane.doe@acme.com still the contact? Card 4111 1111 1111 1111.");
        let s1 = &p1.vault.pairs()[0].0;
        assert!(one.contains(s1.as_str()) && two.contains(s1.as_str()), "{one} / {two}");
        assert_eq!(p2.vault.pairs().iter().find(|(_, o)| o == "jane.doe@acme.com").map(|(s, _)| s), Some(s1));
        // Identical requests: identical protected text.
        assert_eq!(protect_with(&acme, "Mail jane.doe@acme.com today").0, one);
        // Another tenant: another surrogate for the same value.
        let (globex, _) = protect_with(&keys.scope_key(PiiSurrogateScope::Tenant, "globex"), "Mail jane.doe@acme.com today");
        assert_ne!(globex, one);
        assert!(!globex.contains(s1.as_str()));
    }

    #[test]
    fn session_scope_differs_per_request() {
        let keys = SurrogateKeys::from_kek(&KEK);
        let text = "Mail jane.doe@acme.com today";
        let a = protect_with(&keys.scope_key(PiiSurrogateScope::Session, "acme"), text).0;
        let b = protect_with(&keys.scope_key(PiiSurrogateScope::Session, "acme"), text).0;
        assert_ne!(a, b);
        assert_ne!(a, protect_with(&keys.tenant_key("acme"), text).0);
    }

    /// A response may carry a surrogate this request never produced (e.g. a cached answer
    /// computed for another request, or another tenant's surrogate). Only values of the current
    /// request are restored; anything else is left as it is.
    #[test]
    fn only_surrogates_of_the_current_request_are_rehydrated() {
        let keys = SurrogateKeys::from_kek(&KEK);
        let acme = keys.tenant_key("acme");
        let (_, other) = protect_with(&acme, "Write to bob@corp.io");
        let foreign = other.vault.pairs()[0].0.clone();
        let (_, mine) = protect_with(&acme, "Write to jane.doe@acme.com");
        let mine_s = mine.vault.pairs()[0].0.clone();
        let answer = format!("Cc {foreign} and {mine_s}.");
        assert_eq!(Rehydrator::new(&mine.vault).rehydrate(&answer), format!("Cc {foreign} and jane.doe@acme.com."));
    }

    #[test]
    fn text_order_does_not_change_the_surrogates() {
        let key = SurrogateKeys::from_kek(&KEK).tenant_key("acme");
        let (_, p1) = protect_with(&key, "a@x.io then b@y.io");
        let (_, p2) = protect_with(&key, "b@y.io then a@x.io");
        let map = |p: &Protected| p.vault.pairs().iter().cloned().collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(map(&p1), map(&p2));
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
