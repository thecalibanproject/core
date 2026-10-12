//! L0 deterministic detectors: regexes plus validators (Luhn, IBAN mod-97, SSN rules, the French
//! NIR key).
//!
//! Phone numbers: international (`+` and a country code, then 2 to 5 groups of 1 to 4 digits:
//! `+961 3 456 789`, `+33 6 12 34 56 78`), North American (`(415) 555-2671`) and French national
//! (`06 12 34 56 78`, ten digits starting with 0). National formats without a trunk prefix (a
//! Lebanese `71 234 567`) are not matched: they are indistinguishable from amounts
//! (`75 000 000` LBP) and codes, and a false positive rewrites a price. National IDs: US SSNs and
//! the French NIR (15 characters, validated by its key, or accepted without it right after words
//! that name it, since recall matters more than precision there: research note 05, section 1).
//! Other formats come from a tenant's own pattern list ([`crate::TenantDetectors`]).
//!
//! Number boundaries: a card, IBAN, SSN, phone or NIR candidate that is part of a longer number
//! is not one. A digit right next to it, or a decimal point joining it to digits (the fraction of
//! `0.4111111111111111`, a relevance score), or an exponent (`1.5e-4111111111111111`), rejects
//! it. Cards also need a major industry identifier of 2 to 6 (Mastercard 2 and 5, Amex, JCB and
//! Diners 3, Visa 4, Discover and UnionPay 6): runs starting with 0, 1 (Unix timestamps in
//! milliseconds or microseconds), 7, 8 or 9 are ids and amounts, not cards.

use crate::{Detector, EntityType, Span};
use regex::Regex;

type Rule = (EntityType, Regex, fn(&str) -> bool);

pub struct PatternDetector {
    rules: Vec<Rule>,
    /// The shape of a French NIR: sex, year, month, department (two digits, or 2A / 2B),
    /// commune, order, key; spaces or dots between the groups.
    nir: Regex,
    /// Words that name a social security number (French and English).
    nir_context: Regex,
}

fn always(_: &str) -> bool {
    true
}

impl PatternDetector {
    pub fn new() -> Self {
        let r = |p: &str| Regex::new(p).expect("static regex");
        let rules: Vec<Rule> = vec![
            // Credentials first: these block the request.
            (
                EntityType::Secret,
                r(
                    r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9-]{10,}|cal_[A-Za-z0-9]{24,})\b",
                ),
                always,
            ),
            (EntityType::Secret, r(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), always),
            (EntityType::Secret, r(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), always),
            (EntityType::Email, r(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b"), always),
            (EntityType::Iban, r(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), iban_valid),
            (EntityType::CreditCard, r(r"\b\d(?:[ -]?\d){12,18}\b"), card_valid),
            (EntityType::UsSsn, r(r"\b\d{3}-\d{2}-\d{4}\b"), ssn_valid),
            (EntityType::Phone, r(r"\+\d{1,3}(?:[ .-]?\(?\d{1,4}\)?){2,5}\b"), phone_valid),
            (EntityType::Phone, r(r"(?:\(\d{3}\) ?|\b\d{3}-)\d{3}-\d{4}\b"), phone_valid),
            // French national format: 0 and nine digits, in pairs (`06 12 34 56 78`, `01.23.45.67.89`).
            (EntityType::Phone, r(r"\b0[1-9](?:[ .-]?\d{2}){4}\b"), phone_valid),
            (
                EntityType::IpAddress,
                r(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
                always,
            ),
        ];
        Self {
            rules,
            nir: r(r"\b[1-478][ .]?\d{2}[ .]?\d{2}[ .]?(?:\d{2}|2[AaBb])[ .]?\d{3}[ .]?\d{3}[ .]?\d{2}\b"),
            nir_context: r(
                r"(?i)(?:s[ée]curit[ée] sociale|\bs[ée]cu\b|\bNIR\b|\bINSEE\b|social security|\bn°\s*ss\b|\bnum[ée]ro\s+ss\b)",
            ),
        }
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
                if valid(m.as_str()) && !(numeric(entity) && inside_number(text, m.start(), m.end())) {
                    out.push(Span { start: m.start(), end: m.end(), entity: entity.clone() });
                }
            }
        }
        for m in self.nir.find_iter(text) {
            // Its key, or words naming it just before (at most 60 bytes back).
            let mut from = m.start().saturating_sub(60);
            while !text.is_char_boundary(from) {
                from -= 1;
            }
            if inside_number(text, m.start(), m.end()) {
                continue;
            }
            if nir_valid(m.as_str()) || self.nir_context.is_match(&text[from..m.start()]) {
                out.push(Span { start: m.start(), end: m.end(), entity: EntityType::NationalId });
            }
        }
        out
    }
}

/// Entities written as digits, which a longer number can contain.
fn numeric(e: &EntityType) -> bool {
    matches!(e, EntityType::CreditCard | EntityType::Iban | EntityType::UsSsn | EntityType::Phone)
}

/// Whether `text[start..end]` is part of a longer number: a digit right before or after it, a
/// decimal point joining it to digits (`0.4111...`, `4111....5`), or an exponent (`1e-4111...`).
fn inside_number(text: &str, start: usize, end: usize) -> bool {
    let b = text.as_bytes();
    let before = |k: usize| start.checked_sub(k).map(|i| b[i]);
    let after = |k: usize| b.get(end + k - 1).copied();
    let digit = |c: Option<u8>| c.is_some_and(|c| c.is_ascii_digit());
    digit(before(1))
        || digit(after(1))
        || (before(1) == Some(b'.') && digit(before(2)))
        || (after(1) == Some(b'.') && digit(after(2)))
        || (matches!(before(1), Some(b'-' | b'+'))
            && matches!(before(2), Some(b'e' | b'E'))
            && (digit(before(3)) || before(3) == Some(b'.')))
}

/// A payment card: a major industry identifier of 2 to 6 and a valid Luhn check digit.
fn card_valid(s: &str) -> bool {
    s.bytes().next().is_some_and(|c| (b'2'..=b'6').contains(&c)) && luhn_valid(s)
}

/// The NIR (French social security number) key: `97 - (the first 13 characters mod 97)`, with
/// Corsica's departments 2A and 2B counted as 19 and 18 (INSEE).
pub fn nir_valid(s: &str) -> bool {
    let c: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_uppercase();
    if c.len() != 15 {
        return false;
    }
    let (body, key) = c.split_at(13);
    let body = match &body[5..7] {
        "2A" => format!("{}19{}", &body[..5], &body[7..]),
        "2B" => format!("{}18{}", &body[..5], &body[7..]),
        _ => body.to_owned(),
    };
    match (body.parse::<u64>(), key.parse::<u64>()) {
        (Ok(n), Ok(k)) => 97 - n % 97 == k,
        _ => false,
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
        let mut v: Vec<_> =
            crate::merge_spans(PatternDetector::new().detect(t)).into_iter().map(|s| s.entity).collect();
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
    fn phones_of_the_reference_market() {
        for t in [
            "tél. 06 12 34 56 78",
            "fixe 01.23.45.67.89",
            "portable 0612345678",
            "call +961 3 456 789",
            "call +961 71 234 567",
            "appelez le +33 6 12 34 56 78",
            "+33 1 23 45 67 89",
        ] {
            assert_eq!(kinds(t), vec![EntityType::Phone], "{t}");
        }
    }

    #[test]
    fn french_nir_by_key_or_by_name() {
        // A valid key: found anywhere.
        assert!(nir_valid("2 84 06 75 115 042 63"));
        assert_eq!(kinds("ref 2 84 06 75 115 042 63"), vec![EntityType::NationalId]);
        assert_eq!(kinds("1850578006048 22").len(), 0, "key 22 is wrong for this number");
        assert!(nir_valid("1 85 05 78 006 048 22") == (97 - 1_850_578_006_048u64 % 97 == 22));
        // Corsica.
        let corsica = 2_690_219_018_004u64; // 2 69 02 2A 018 004 (2A counted as 19)
        let key = 97 - corsica % 97;
        assert!(nir_valid(&format!("2 69 02 2A 018 004 {key:02}")));
        // A wrong key, but named as a social security number: still protected (recall first).
        assert_eq!(
            kinds("numéro de sécurité sociale 2 84 06 75 115 042 87"),
            vec![EntityType::NationalId],
            "the e2e's value has a wrong key"
        );
        assert_eq!(kinds("my social security number is 1 85 05 78 006 048 99"), vec![EntityType::NationalId]);
        // The same digits without a name and with a wrong key: not an ID.
        assert!(kinds("order 2 84 06 75 115 042 87").iter().all(|k| *k != EntityType::NationalId));
    }

    /// Values of the health-triage end-to-end data (deploy repo) that are not personal data:
    /// prices, dates, times, opening hours, ages, slot and catalogue codes, amounts.
    #[test]
    fn no_false_positives_on_prices_dates_and_codes() {
        for t in [
            "Echocardiography 150 USD, ECG 40 USD, consultation 60 USD",
            "price_usd: 110, 120, 140, 160, 25, 35, 55, 65, 95",
            "Lun-Sam 08:30-19:30, Mon-Fri 09:00-18:00, Mon-Sat 08:00-20:00, 24/7",
            "next slot 2026-10-14T09:30:00Z, then 14/10/2026 at 10:30, or 14.10.2026",
            "slot-0012, slot-0147, svc-card-echo, fac-bey-cedar-valley, LB-4471-9902-3",
            "children up to 16, my son is 4, fever for 2 days, wait 12 days",
            "11e arrondissement, 13e arrondissement",
            "75 000 000 LBP, 1 250,00 EUR, 3 500 000",
            "booking ref 2026101400123, order 0012-4471",
            "ontology medmarket@52, version 1.2.3, 10/12",
        ] {
            assert!(kinds(t).is_empty(), "{t}: {:?}", kinds(t));
        }
    }

    /// Digit runs inside a longer number are not cards, phones, IBANs, SSNs or NIRs: decimals
    /// (relevance scores, coordinates, amounts), timestamps and ids. The fractions here are
    /// Luhn-valid (or a valid NIR), so only the boundaries reject them.
    #[test]
    fn no_false_positives_inside_numbers() {
        assert!(luhn_valid("0322580645161292") && luhn_valid("4111111111111111"));
        for t in [
            "score 0.0322580645161292",
            "score 0.4111111111111111",
            r#"{"score":0.4111111111111111,"rank":1}"#,
            "12.4111111111111111",
            "4111111111111111.25",
            "4111111111111111.5 EUR",
            "1.5e-4111111111111111",
            "2.0E+4111111111111111",
            "x=-0.4111111111111111",
            "lat 33.0612345678, lng 35.4952471234",
            "ratio 1.123-45-6789",
            "0.2840675115042 63",
            "v 3.0612345678",
            "ts 1760000000000, 1760000000000000, 1760000000000000000",
            "epoch_ms 1728475200123, 1734567890123457",
            "ids 2026101400123, 98765432109876543, 7000000000000005, 9000000000000001",
            "amounts 1 250,00 EUR, 12 345 678.90, 0.000000000000001",
            "uuid 3f2b8c1e-4a5d-4e6f-9a7b-1c2d3e4f5a6b, ulid 01HZX4Y5R6T7Q8W9E0A1S2D3F4",
        ] {
            assert!(kinds(t).is_empty(), "{t}: {:?}", kinds(t));
        }
        assert!(luhn_valid("7000000000000005") && luhn_valid("1760000000000008"));
        assert!(kinds("ts 1760000000000008").is_empty(), "Unix microseconds are not cards");
    }

    /// Real cards in text are still caught: spaced, dashed, or a plain run bounded by non-digits
    /// (punctuation, quotes, letters).
    #[test]
    fn cards_in_prose_are_still_caught() {
        for t in [
            "card 4111 1111 1111 1111",
            "card 4111-1111-1111-1111",
            "card 4111111111111111.",
            "card: 4111111111111111, exp 12/27",
            "the number was 5500005555555559 thanks",
            "Amex 3782 822463 10005",
            "\"4111111111111111\"",
            "(4111111111111111)",
            "carte n°4111111111111111",
            "Mastercard 2221000000000009",
        ] {
            assert_eq!(kinds(t), vec![EntityType::CreditCard], "{t}");
        }
        // Other numeric entities next to ordinary punctuation are still found.
        assert_eq!(kinds("tél. 06 12 34 56 78."), vec![EntityType::Phone]);
        assert_eq!(kinds("ssn 123-45-6789."), vec![EntityType::UsSsn]);
        assert_eq!(kinds("iban DE89 3704 0044 0532 0130 00."), vec![EntityType::Iban]);
        assert_eq!(kinds("NIR: 2 84 06 75 115 042 63."), vec![EntityType::NationalId]);
    }

    #[test]
    fn validators_reject_lookalikes() {
        assert!(kinds("order 4111 1111 1111 1112").is_empty(), "bad Luhn");
        assert!(kinds("ssn 666-45-6789").is_empty());
        assert!(kinds("version 1.2.3").is_empty());
    }
}
