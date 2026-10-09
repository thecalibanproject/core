//! Realistic, type-consistent surrogates and the reverse map (vault).
//!
//! Surrogates are derived deterministically from `HMAC(scope_key, type ‖ normalized value)`, so the
//! same value maps to the same surrogate within a scope without a lookup. Placeholders such as
//! `[PERSON_1]` hurt answer quality; surrogates of the right shape keep the model reasoning
//! (docs/research/05-anonymization-and-privacy.md §2).
//!
//! TODO: FF1 format-preserving encryption (`fpe` crate) for structured IDs under a per-tenant
//! tweak; encrypted persistent vault for session/tenant scopes (envelope keys, TTL, crypto-shred).

use crate::EntityType;
use crate::patterns::{iban_mod97, luhn_sum};
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};

const FIRST: &[&str] = &[
    "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Avery", "Quinn", "Jamie", "Rowan",
    "Elena", "Mateo", "Priya", "Kenji", "Amara", "Lucas", "Noor", "Sofia", "Daniel", "Ines",
];
const LAST: &[&str] = &[
    "Rivera", "Okafor", "Lindqvist", "Moreau", "Haddad", "Novak", "Tanaka", "Silva", "Brennan", "Kowalski",
    "Mendes", "Varga", "Ahmed", "Fischer", "Costa", "Larsen", "Ibarra", "Petrov", "Nakamura", "Duarte",
];
const ORG_A: &[&str] = &["Northwind", "Bluepeak", "Harbor", "Silverline", "Crescent", "Ironwood", "Brightwater", "Summit"];
const ORG_B: &[&str] = &["Logistics", "Holdings", "Analytics", "Partners", "Industries", "Labs", "Group", "Systems"];
/// Invented, generic-sounding town names. Deliberately not common English words, so the
/// case-insensitive rehydrator does not rewrite ordinary words in model output.
const CITY: &[&str] = &[
    "Valemont", "Brenford", "Castlemere", "Dorrowby", "Elmsworth", "Farrowdale", "Glenhollow", "Kestonbury",
    "Larkmoor", "Merriton", "Norbridge", "Pellham Cross", "Quillmere", "Rosswick", "Selbury", "Thornwick",
    "Wexmoor", "Yarrowfield", "Ashcombe Vale", "Brightmere",
];
const STREET: &[&str] = &["Maple", "Cedar", "Juniper", "Linden", "Alder", "Hawthorn", "Rowan", "Sycamore", "Larch", "Birchwood"];
const STREET_SUFFIX: &[&str] = &["Street", "Road", "Avenue", "Lane", "Way", "Close"];

#[derive(Debug, Default)]
pub struct Vault {
    scope_key: Vec<u8>,
    forward: HashMap<(EntityType, String), String>,
    reverse: Vec<(String, String)>,
    used: HashSet<String>,
    corpus_lower: String,
}

impl Vault {
    pub fn new(scope_key: &[u8]) -> Self {
        Self { scope_key: scope_key.to_vec(), ..Default::default() }
    }

    /// Text that surrogates must never collide with (the original request text).
    pub fn set_collision_corpus(&mut self, text: &str) {
        self.corpus_lower = text.to_lowercase();
    }

    pub fn is_empty(&self) -> bool {
        self.reverse.is_empty()
    }

    pub fn len(&self) -> usize {
        self.reverse.len()
    }

    /// `(surrogate, original)` pairs, in insertion order.
    pub fn pairs(&self) -> &[(String, String)] {
        &self.reverse
    }

    pub fn surrogate_for(&mut self, entity: &EntityType, original: &str) -> String {
        let key = (entity.clone(), normalize(entity, original));
        if let Some(s) = self.forward.get(&key) {
            return s.clone();
        }
        let mut counter: u32 = 0;
        let surrogate = loop {
            let seed = self.seed(entity, &key.1, counter);
            let candidate = generate(entity, original, seed);
            let clash = candidate.is_empty()
                || self.used.contains(&candidate.to_lowercase())
                || self.corpus_lower.contains(&candidate.to_lowercase());
            if !clash || counter > 64 {
                break candidate;
            }
            counter += 1;
        };
        self.used.insert(surrogate.to_lowercase());
        self.forward.insert(key, surrogate.clone());
        self.reverse.push((surrogate.clone(), original.to_owned()));
        surrogate
    }

    fn seed(&self, entity: &EntityType, normalized: &str, counter: u32) -> u64 {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.scope_key).expect("hmac accepts any key length");
        mac.update(entity.label().as_bytes());
        mac.update(&[0]);
        mac.update(normalized.as_bytes());
        mac.update(&counter.to_le_bytes());
        let out = mac.finalize().into_bytes();
        u64::from_le_bytes(out[..8].try_into().expect("8 bytes"))
    }
}

fn normalize(entity: &EntityType, s: &str) -> String {
    match entity {
        EntityType::CreditCard | EntityType::Phone | EntityType::UsSsn => s.chars().filter(char::is_ascii_digit).collect(),
        EntityType::Iban => s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase(),
        _ => s.trim().to_lowercase(),
    }
}

fn pick<'a>(rng: &mut StdRng, pool: &[&'a str]) -> &'a str {
    pool[rng.random_range(0..pool.len())]
}

fn generate(entity: &EntityType, original: &str, seed: u64) -> String {
    let mut rng = StdRng::seed_from_u64(seed);
    match entity {
        EntityType::Email => {
            let tld = pick(&mut rng, &["com", "net", "org"]);
            format!(
                "{}.{}{}@example.{tld}",
                pick(&mut rng, FIRST).to_lowercase(),
                pick(&mut rng, LAST).to_lowercase(),
                rng.random_range(1..100)
            )
        }
        EntityType::Person => {
            let first = pick(&mut rng, FIRST);
            let last = pick(&mut rng, LAST);
            match original.split_whitespace().count() {
                1 => first.to_owned(),
                _ => format!("{first} {last}"),
            }
        }
        EntityType::Organization => format!("{} {}", pick(&mut rng, ORG_A), pick(&mut rng, ORG_B)),
        EntityType::Location => location(original, &mut rng),
        EntityType::IpAddress => format!("198.51.100.{}", rng.random_range(1..255)),
        EntityType::UsSsn => format!(
            "9{:02}-{:02}-{:04}",
            rng.random_range(0..100),
            rng.random_range(1..100),
            rng.random_range(1..10000)
        ),
        // Keep the first digit (country code / network) so the model can still reason about it.
        EntityType::Phone => shuffle_shape(original, &mut rng, 1),
        EntityType::CreditCard => card(original, &mut rng),
        EntityType::Iban => iban(original, &mut rng),
        EntityType::Custom(_) => shuffle_shape(original, &mut rng, 0),
        // Secrets never reach surrogate generation (the request is blocked).
        EntityType::Secret => String::new(),
    }
}

/// Street-like surrogate when the original carries a number (an address), a town name otherwise.
fn location(original: &str, rng: &mut StdRng) -> String {
    if original.chars().any(|c| c.is_ascii_digit()) {
        format!("{} {} {}", rng.random_range(2..400), pick(rng, STREET), pick(rng, STREET_SUFFIX))
    } else {
        pick(rng, CITY).to_owned()
    }
}

/// Replaces digits with digits and letters with letters, preserving separators and case.
fn shuffle_shape(original: &str, rng: &mut StdRng, keep_leading_digits: usize) -> String {
    let mut kept = 0;
    original
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                if kept < keep_leading_digits {
                    kept += 1;
                    return c;
                }
                char::from(b'0' + rng.random_range(0..10u8))
            } else if c.is_ascii_uppercase() {
                char::from(b'A' + rng.random_range(0..26u8))
            } else if c.is_ascii_lowercase() {
                char::from(b'a' + rng.random_range(0..26u8))
            } else {
                c
            }
        })
        .collect()
}

/// Card surrogate: same length and separators, first digit kept, valid Luhn check digit.
fn card(original: &str, rng: &mut StdRng) -> String {
    let n = original.chars().filter(char::is_ascii_digit).count();
    let mut d: Vec<u8> = Vec::with_capacity(n);
    for (i, c) in original.chars().filter(char::is_ascii_digit).enumerate() {
        d.push(if i == 0 { c as u8 - b'0' } else { rng.random_range(0..10u8) });
    }
    // Choose the last digit so the Luhn sum is a multiple of 10.
    if let Some(last) = d.last_mut() {
        *last = 0;
    }
    let check = (10 - luhn_sum(&d) % 10) % 10;
    if let Some(last) = d.last_mut() {
        *last = u8::try_from(check).unwrap_or(0);
    }
    let mut it = d.into_iter();
    original
        .chars()
        .map(|c| if c.is_ascii_digit() { char::from(b'0' + it.next().unwrap_or(0)) } else { c })
        .collect()
}

/// IBAN surrogate: same country and shape, random BBAN, valid check digits.
fn iban(original: &str, rng: &mut StdRng) -> String {
    let compact: String = original.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    if compact.len() < 5 {
        return shuffle_shape(original, rng, 0);
    }
    let country = &compact[..2];
    let bban: String = compact[4..]
        .chars()
        .map(|c| if c.is_ascii_digit() { char::from(b'0' + rng.random_range(0..10u8)) } else { char::from(b'A' + rng.random_range(0..26u8)) })
        .collect();
    let rem = iban_mod97(&format!("{country}00{bban}")).unwrap_or(0);
    let check = 98 - rem;
    let new_compact = format!("{country}{check:02}{bban}");
    // Re-apply the original spacing.
    let mut it = new_compact.chars();
    original
        .chars()
        .map(|c| if c.is_whitespace() { c } else { it.next().unwrap_or('0') })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::{iban_valid, luhn_valid};

    #[test]
    fn structured_surrogates_stay_valid() {
        let mut v = Vault::new(b"k");
        let c = v.surrogate_for(&EntityType::CreditCard, "4111 1111 1111 1111");
        assert!(luhn_valid(&c), "{c}");
        assert_eq!(c.len(), "4111 1111 1111 1111".len());
        let i = v.surrogate_for(&EntityType::Iban, "DE89 3704 0044 0532 0130 00");
        assert!(iban_valid(&i), "{i}");
        assert!(i.starts_with("DE"));
    }

    #[test]
    fn different_scopes_give_different_surrogates() {
        let a = Vault::new(b"scope-a").surrogate_for(&EntityType::Email, "x@y.com");
        let b = Vault::new(b"scope-b").surrogate_for(&EntityType::Email, "x@y.com");
        assert_ne!(a, b);
    }

    #[test]
    fn location_surrogates_are_towns_or_streets() {
        let mut v = Vault::new(b"k");
        let town = v.surrogate_for(&EntityType::Location, "Berlin");
        assert!(CITY.contains(&town.as_str()), "{town}");
        let street = v.surrogate_for(&EntityType::Location, "221B Baker Street");
        assert!(street.chars().next().is_some_and(|c| c.is_ascii_digit()), "{street}");
        assert!(STREET_SUFFIX.iter().any(|s| street.ends_with(s)), "{street}");
        // Stable within a scope.
        assert_eq!(v.surrogate_for(&EntityType::Location, "berlin "), town);
    }

    #[test]
    fn surrogate_never_collides_with_original_text() {
        let mut v = Vault::new(b"k");
        v.set_collision_corpus("198.51.100.7 is mentioned");
        for i in 0..50 {
            let s = v.surrogate_for(&EntityType::IpAddress, &format!("10.0.0.{i}"));
            assert_ne!(s, "198.51.100.7");
        }
    }
}
