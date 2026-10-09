//! L0 deterministic detectors: regexes plus validators (Luhn, IBAN mod-97, SSN rules).

use crate::{Detector, EntityType, Span};
use regex::Regex;

type Rule = (EntityType, Regex, fn(&str) -> bool);

pub struct PatternDetector {
    rules: Vec<Rule>,
}

fn always(_: &str) -> bool {
    true
}

impl PatternDetector {
    pub fn new() -> Self {
        let r = |p: &str| Regex::new(p).expect("static regex");
        let rules: Vec<Rule> = vec![
            // Credentials first: these block the request.
            (EntityType::Secret, r(r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,}|cal_[A-Za-z0-9]{24,})\b"), always),
            (EntityType::Secret, r(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), always),
            (EntityType::Secret, r(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), always),
            (EntityType::Email, r(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"), always),
            (EntityType::Iban, r(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), iban_valid),
            (EntityType::CreditCard, r(r"\b\d(?:[ -]?\d){12,18}\b"), luhn_valid),
            (EntityType::UsSsn, r(r"\b\d{3}-\d{2}-\d{4}\b"), ssn_valid),
            (EntityType::Phone, r(r"\+\d{1,3}(?:[ .-]?\(?\d{2,4}\)?){2,4}\b"), phone_valid),
            (EntityType::Phone, r(r"(?:\(\d{3}\) ?|\b\d{3}-)\d{3}-\d{4}\b"), phone_valid),
            (EntityType::IpAddress, r(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), always),
        ];
        Self { rules }
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for PatternDetector {
    fn detect(&self, text: &str) -> Vec<Span> {
        let mut out = Vec::new();
        for (entity, re, valid) in &self.rules {
            for m in re.find_iter(text) {
                if valid(m.as_str()) {
                    out.push(Span { start: m.start(), end: m.end(), entity: entity.clone() });
                }
            }
        }
        out
    }
}

fn digits(s: &str) -> Vec<u8> {
    s.bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect()
}

pub fn luhn_valid(s: &str) -> bool {
    let d = digits(s);
    if !(13..=19).contains(&d.len()) {
        return false;
    }
    luhn_sum(&d).is_multiple_of(10)
}

pub(crate) fn luhn_sum(d: &[u8]) -> u32 {
    d.iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            let x = u32::from(x);
            if i % 2 == 1 {
                let y = x * 2;
                if y > 9 { y - 9 } else { y }
            } else {
                x
            }
        })
        .sum()
}

pub fn iban_valid(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    iban_mod97(&compact) == Some(1)
}

/// ISO 13616 mod-97 over the rearranged IBAN (`None` on invalid characters).
pub(crate) fn iban_mod97(compact: &str) -> Option<u32> {
    let (head, tail) = compact.split_at(4);
    let mut rem: u32 = 0;
    for c in tail.chars().chain(head.chars()) {
        let v = c.to_digit(36)?;
        rem = if v >= 10 { (rem * 100 + v) % 97 } else { (rem * 10 + v) % 97 };
    }
    Some(rem)
}

fn ssn_valid(s: &str) -> bool {
    let area = &s[0..3];
    let group = &s[4..6];
    let serial = &s[7..11];
    area != "000" && area != "666" && !area.starts_with('9') && group != "00" && serial != "0000"
}

fn phone_valid(s: &str) -> bool {
    (8..=15).contains(&digits(s).len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(t: &str) -> Vec<EntityType> {
        let mut v: Vec<_> = crate::merge_spans(PatternDetector::new().detect(t)).into_iter().map(|s| s.entity).collect();
        v.sort();
        v
    }

    #[test]
    fn detects_common_entities() {
        assert_eq!(kinds("mail bob@example.org"), vec![EntityType::Email]);
        assert_eq!(kinds("card 4111-1111-1111-1111"), vec![EntityType::CreditCard]);
        assert_eq!(kinds("iban DE89 3704 0044 0532 0130 00"), vec![EntityType::Iban]);
        assert_eq!(kinds("ssn 123-45-6789"), vec![EntityType::UsSsn]);
        assert_eq!(kinds("call (415) 555-2671"), vec![EntityType::Phone]);
        assert_eq!(kinds("host 192.168.1.20"), vec![EntityType::IpAddress]);
        assert_eq!(kinds("AKIAIOSFODNN7EXAMPLE"), vec![EntityType::Secret]);
    }

    #[test]
    fn validators_reject_lookalikes() {
        assert!(kinds("order 4111 1111 1111 1112").is_empty(), "bad Luhn");
        assert!(kinds("ssn 666-45-6789").is_empty());
        assert!(kinds("version 1.2.3").is_empty());
    }
}
