//! A tenant's own L0 detectors (research note 05, section 1: tenant dictionaries and institutional
//! identifiers that generic detectors miss, arXiv 2608.17051):
//! - [`DictionaryDetector`]: exact terms (customer names, account ids, internal codes) matched with
//!   Aho-Corasick, whole words, case-insensitive;
//! - tenant patterns: regexes for identifier formats the built-in patterns do not know (a
//!   national ID format, a member number), each with a label.
//!
//! [`TenantDetectors`] holds both, compiled from the tenant's settings (`pii_patterns`,
//! `pii_dictionary`); the gateway rebuilds them when those change.

use crate::{Detector, EntityType, Span};
use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub struct DictionaryDetector {
    ac: AhoCorasick,
    labels: Vec<EntityType>,
}

impl DictionaryDetector {
    pub fn new(entries: impl IntoIterator<Item = (String, EntityType)>) -> Self {
        let (terms, labels): (Vec<String>, Vec<EntityType>) =
            entries.into_iter().filter(|(t, _)| t.trim().len() >= 2).unzip();
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(&terms)
            .expect("dictionary automaton");
        Self { ac, labels }
    }
}

impl Detector for DictionaryDetector {
    fn detect(&self, text: &str) -> Vec<Span> {
        let is_word = |c: Option<char>| c.is_some_and(char::is_alphanumeric);
        self.ac
            .find_iter(text)
            .filter(|m| !is_word(text[..m.start()].chars().next_back()) && !is_word(text[m.end()..].chars().next()))
            .map(|m| Span { start: m.start(), end: m.end(), entity: self.labels[m.pattern().as_usize()].clone() })
            .collect()
    }
}

/// One tenant pattern: a regex (the `regex` crate's syntax: linear time, no backreferences or
/// lookaround) and the label of what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPattern {
    /// `NATIONAL_ID`, `PHONE`, `EMAIL`, `PERSON`, ... map to the built-in types (and their
    /// surrogates); anything else is a custom label (shape-preserving surrogates).
    pub label: String,
    pub pattern: String,
}

/// Limits on a tenant's own detectors.
pub const MAX_TENANT_PATTERNS: usize = 50;
pub const MAX_PATTERN_LEN: usize = 500;
pub const MAX_DICTIONARY_TERMS: usize = 10_000;

/// The entity type a tenant label stands for.
pub fn entity_for_label(label: &str) -> EntityType {
    match label.trim().to_ascii_uppercase().as_str() {
        "NATIONAL_ID" | "NATIONALID" | "ID" => EntityType::NationalId,
        "PHONE" => EntityType::Phone,
        "EMAIL" => EntityType::Email,
        "PERSON" | "NAME" => EntityType::Person,
        "ORG" | "ORGANIZATION" => EntityType::Organization,
        "LOCATION" | "ADDRESS" => EntityType::Location,
        "IBAN" => EntityType::Iban,
        "CARD" => EntityType::CreditCard,
        other => EntityType::Custom(other.to_owned()),
    }
}

/// A label is 1 to 40 characters of `[A-Za-z0-9_]`.
fn valid_label(l: &str) -> bool {
    (1..=40).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A tenant's patterns and dictionary, compiled.
pub struct TenantDetectors {
    patterns: Vec<(EntityType, Regex)>,
    dictionary: Option<DictionaryDetector>,
}

impl TenantDetectors {
    /// Compiles `patterns` and `dictionary` (term, label). Errors name the offending entry.
    pub fn build(patterns: &[TenantPattern], dictionary: &[(String, String)]) -> Result<Self, String> {
        Self::check(patterns, dictionary)?;
        let patterns = patterns
            .iter()
            .map(|p| Ok((entity_for_label(&p.label), Regex::new(&p.pattern).map_err(|e| e.to_string())?)))
            .collect::<Result<Vec<_>, String>>()?;
        let dictionary = (!dictionary.is_empty())
            .then(|| DictionaryDetector::new(dictionary.iter().map(|(t, l)| (t.clone(), entity_for_label(l)))));
        Ok(Self { patterns, dictionary })
    }

    /// Validates a tenant's settings without keeping the result (the control plane, on write).
    pub fn check(patterns: &[TenantPattern], dictionary: &[(String, String)]) -> Result<(), String> {
        if patterns.len() > MAX_TENANT_PATTERNS {
            return Err(format!("pii_patterns: at most {MAX_TENANT_PATTERNS} patterns"));
        }
        for (i, p) in patterns.iter().enumerate() {
            if !valid_label(&p.label) {
                return Err(format!("pii_patterns[{i}]: label must be 1 to 40 characters of [A-Za-z0-9_]"));
            }
            if p.pattern.is_empty() || p.pattern.len() > MAX_PATTERN_LEN {
                return Err(format!("pii_patterns[{i}]: pattern must be 1 to {MAX_PATTERN_LEN} characters"));
            }
            let re = regex::RegexBuilder::new(&p.pattern)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| format!("pii_patterns[{i}]: {e}"))?;
            if re.is_match("") {
                return Err(format!("pii_patterns[{i}]: the pattern matches the empty string"));
            }
        }
        if dictionary.len() > MAX_DICTIONARY_TERMS {
            return Err(format!("pii_dictionary: at most {MAX_DICTIONARY_TERMS} terms"));
        }
        for (i, (t, l)) in dictionary.iter().enumerate() {
            if t.trim().chars().count() < 2 || t.len() > 200 {
                return Err(format!("pii_dictionary[{i}]: a term is 2 to 200 characters"));
            }
            if !valid_label(l) {
                return Err(format!("pii_dictionary[{i}]: label must be 1 to 40 characters of [A-Za-z0-9_]"));
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty() && self.dictionary.is_none()
    }
}

impl Detector for TenantDetectors {
    fn detect(&self, text: &str) -> Vec<Span> {
        let mut out: Vec<Span> = self
            .patterns
            .iter()
            .flat_map(|(e, re)| {
                re.find_iter(text).map(move |m| Span { start: m.start(), end: m.end(), entity: e.clone() })
            })
            .filter(|s| s.end > s.start)
            .collect();
        if let Some(d) = &self.dictionary {
            out.extend(d.detect(text));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_whole_words_case_insensitively() {
        let d = DictionaryDetector::new([
            ("Globex".to_string(), EntityType::Organization),
            ("ACC-2291".to_string(), EntityType::Custom("ACCOUNT".into())),
        ]);
        let spans = d.detect("globex owns acc-2291 but not Globexian");
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[1].entity, EntityType::Custom("ACCOUNT".into()));
    }

    #[test]
    fn tenant_patterns_and_dictionary() {
        let t = TenantDetectors::build(
            &[TenantPattern { label: "NATIONAL_ID".into(), pattern: r"\bLB-\d{4}-\d{4}-\d\b".into() }],
            &[("Cedar Valley Clinic".into(), "ORG".into())],
        )
        .unwrap();
        let spans = crate::merge_spans(t.detect("ID LB-4471-9902-3, seen at cedar valley clinic"));
        let kinds: Vec<_> = spans.iter().map(|s| s.entity.clone()).collect();
        assert_eq!(kinds, [EntityType::NationalId, EntityType::Organization]);
        // Bad settings are refused with the entry named.
        let bad = |p: &str| TenantDetectors::check(&[TenantPattern { label: "X".into(), pattern: p.into() }], &[]);
        assert!(bad("(").unwrap_err().contains("pii_patterns[0]"));
        assert!(bad("a*").unwrap_err().contains("empty string"));
        assert!(bad("(?P<x>a)\\k<x>").is_err(), "no backreferences");
        let label = TenantDetectors::check(&[TenantPattern { label: "has space".into(), pattern: "x".into() }], &[]);
        assert!(label.unwrap_err().contains("label"));
        assert!(TenantDetectors::check(&[], &[("a".into(), "ORG".into())]).is_err(), "one-character terms");
    }
}
