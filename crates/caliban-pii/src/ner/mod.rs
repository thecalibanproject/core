//! L1 PII detection: a small token-classification (NER) model run in-process with ONNX Runtime.
//!
//! - [`artifact`]: loads a `pii_ner` artifact directory and verifies every file's SHA-256 before
//!   anything is loaded (refuses on mismatch).
//! - [`decode`]: model-free decoding (sliding windows, overlap stitching, BIO/IOB2/BIOES, byte
//!   offsets). Always compiled, so it is unit-tested without ONNX Runtime.
//! - `NerDetector` (cargo feature `ner`): tokenizer + ONNX session pool implementing
//!   [`crate::Detector`].
//!
//! Model labels are mapped to [`EntityType`] by [`default_label_map`] (overridable per label in
//! `NerOptions::label_map`). See `MODELS.md` for the model choice and licences.

pub mod artifact;
pub mod decode;
#[cfg(feature = "ner")]
mod detector;

#[cfg(feature = "ner")]
pub use detector::{NerDetector, NerOptions};

use crate::{EntityType, Span};
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum NerError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("invalid artifact manifest: {0}")]
    Manifest(String),
    #[error("artifact integrity check failed: {0}")]
    Integrity(String),
    #[error("tokenizer: {0}")]
    Tokenizer(String),
    #[error("onnx runtime: {0}")]
    Runtime(String),
    #[error("model does not match its manifest: {0}")]
    Model(String),
}

/// Default mapping from a model's entity base label (the part after `B-`/`I-`, matched
/// case-insensitively) to an [`EntityType`]. `None` means "ignore".
///
/// Covers CoNLL-style models (`PER`/`ORG`/`LOC`/`MISC`) and PII-specific label sets such as the
/// default nym model's 40 types. Choices that trade privacy against answer quality:
/// - `MISC`, generic `DATE`/`TIME`, `AGE`, `GENDER`, `COUNTRY`, `STATE`, `URL` are ignored
///   (quasi-identifiers; generalizing them belongs to the strict tier, not surrogates).
/// - Credentials found by the model (`API_KEY`, `PASSWORD`, `PIN`, `CVV`, ...) become
///   `Custom("CREDENTIAL")` and are replaced by a shape-preserving surrogate rather than mapped to
///   [`EntityType::Secret`], which would block the request on a model false positive. L0
///   patterns still block known key formats. Map them to `Some(EntityType::Secret)` to block.
pub fn default_label_map(base: &str) -> Option<EntityType> {
    let b = base.trim().to_ascii_uppercase();
    let b = b.strip_prefix("PRIVATE_").unwrap_or(&b);
    Some(match b {
        "PER" | "PERSON" | "NAME" | "GIVEN_NAME" | "FIRSTNAME" | "FIRST_NAME" | "MIDDLENAME" | "MIDDLE_NAME"
        | "SURNAME" | "LASTNAME" | "LAST_NAME" | "FULLNAME" | "FULL_NAME" | "USERNAME_PERSON" => EntityType::Person,
        "ORG" | "ORGANIZATION" | "ORGANISATION" | "COMPANY" | "COMPANY_NAME" | "COMPANYNAME" => {
            EntityType::Organization
        }
        "LOC" | "LOCATION" | "CITY" | "ADDRESS" | "STREET_ADDRESS" | "STREET_NAME" | "STREET" | "SECONDARY_ADDRESS"
        | "BUILDING_NUMBER" | "BUILDINGNUMBER" => EntityType::Location,
        "EMAIL" | "EMAIL_ADDRESS" => EntityType::Email,
        "PHONE" | "PHONE_NUMBER" | "PHONENUMBER" | "TELEPHONENUM" | "FAX_NUMBER" => EntityType::Phone,
        "CREDIT_DEBIT_CARD" | "CREDIT_CARD" | "CREDITCARDNUMBER" | "CREDIT_CARD_NUMBER" => EntityType::CreditCard,
        "IBAN" => EntityType::Iban,
        "SSN" | "US_SSN" => EntityType::UsSsn,
        "IP" | "IP_ADDRESS" | "IPV4" | "IPV6" => EntityType::IpAddress,
        "API_KEY" | "PASSWORD" | "PIN" | "CVV" | "SECRET" => EntityType::Custom("CREDENTIAL".into()),
        "ACCOUNT_NUMBER"
        | "ACCOUNTNUM"
        | "CUSTOMER_ID"
        | "EMPLOYEE_ID"
        | "GOVERNMENT_ID"
        | "IDCARDNUM"
        | "PASSPORT"
        | "PASSPORT_NUMBER"
        | "DRIVERS_LICENSE"
        | "DRIVERLICENSENUM"
        | "TAX_ID"
        | "TAXNUM"
        | "MEDICAL_RECORD_NUMBER"
        | "LICENSE_PLATE"
        | "ROUTING_NUMBER"
        | "SWIFT_BIC"
        | "MAC_ADDRESS"
        | "USERNAME"
        | "ZIP_CODE"
        | "ZIPCODE"
        | "POSTCODE"
        | "DATE_OF_BIRTH"
        | "DOB" => EntityType::Custom(b.to_owned()),
        // MISC, DATE, TIME, AGE, GENDER, COUNTRY, STATE, URL and anything unknown.
        _ => return None,
    })
}

/// Joins consecutive spans of the same name-like type separated only by whitespace (e.g. a
/// model's `GIVEN_NAME` + `SURNAME` → one `Person`, so the surrogate is a full name).
pub fn join_adjacent(text: &str, mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by_key(|s| (s.start, s.end));
    let mut out: Vec<Span> = Vec::with_capacity(spans.len());
    for s in spans {
        if let Some(last) = out.last_mut() {
            let joinable = matches!(s.entity, EntityType::Person | EntityType::Organization | EntityType::Location);
            if joinable
                && last.entity == s.entity
                && s.start >= last.end
                && text.get(last.end..s.start).is_some_and(|gap| gap.len() <= 3 && gap.chars().all(char::is_whitespace))
            {
                last.end = s.end;
                continue;
            }
        }
        out.push(s);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_conll_and_pii_labels() {
        assert_eq!(default_label_map("PER"), Some(EntityType::Person));
        assert_eq!(default_label_map("given_name"), Some(EntityType::Person));
        assert_eq!(default_label_map("private_person"), Some(EntityType::Person));
        assert_eq!(default_label_map("ORG"), Some(EntityType::Organization));
        assert_eq!(default_label_map("COMPANY_NAME"), Some(EntityType::Organization));
        assert_eq!(default_label_map("LOC"), Some(EntityType::Location));
        assert_eq!(default_label_map("CITY"), Some(EntityType::Location));
        assert_eq!(default_label_map("MISC"), None);
        assert_eq!(default_label_map("COUNTRY"), None);
        assert_eq!(default_label_map("DATE"), None);
        assert_eq!(default_label_map("API_KEY"), Some(EntityType::Custom("CREDENTIAL".into())));
        assert_eq!(default_label_map("PASSPORT"), Some(EntityType::Custom("PASSPORT".into())));
    }

    #[test]
    fn joins_given_name_and_surname_but_not_across_punctuation() {
        let text = "Gary Fisher, Paris, France and Acme  Corp";
        let sp = |s: &str, e: EntityType| {
            let start = text.find(s).unwrap();
            Span { start, end: start + s.len(), entity: e }
        };
        let spans = vec![
            sp("Gary", EntityType::Person),
            sp("Fisher", EntityType::Person),
            sp("Paris", EntityType::Location),
            sp("France", EntityType::Location),
            sp("Acme", EntityType::Organization),
            sp("Corp", EntityType::Organization),
        ];
        let got: Vec<&str> = join_adjacent(text, spans).iter().map(|s| &text[s.start..s.end]).collect();
        assert_eq!(got, vec!["Gary Fisher", "Paris", "France", "Acme  Corp"]);
    }
}
