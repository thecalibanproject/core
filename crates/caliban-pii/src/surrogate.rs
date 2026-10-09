//! Realistic, type-consistent surrogates and the per-request reverse map ([`Vault`]).
//!
//! Placeholders such as `[PERSON_1]` hurt answer quality; surrogates of the right shape keep the
//! model reasoning (docs/research/05-anonymization-and-privacy.md §2).
//!
//! # Derivation
//!
//! A surrogate is a pure function of `(scope key, entity type, normalised value)`. Every random
//! choice (pool index, digit, letter) is drawn from an HMAC-SHA256 stream:
//!
//! ```text
//! block_j = HMAC-SHA256(scope_key, "caliban/pii/surrogate/v2" ‖ 0 ‖ len(type) ‖ type
//!                                  ‖ len(value) ‖ normalised value ‖ attempt ‖ j)
//! ```
//!
//! with lengths as little-endian u64 and `attempt`, `j` as little-endian u32. Integers in
//! `[0, n)` are `(u64 × n) >> 64` over consecutive 8-byte words (bias below 2^-40 for every
//! range used here). No `rand` generator is involved, so the result is the same on every
//! platform, router and `rand` version. The scope key is either the tenant's key from
//! [`crate::SurrogateKeys`] (tenant scope) or 32 random bytes (session scope, a new key per
//! request).
//!
//! # Collisions
//!
//! Two different values must never share a surrogate **within a request**, or rehydration
//! cannot tell them apart. That is guaranteed, not probabilistic: [`Vault::assign`] gives
//! surrogates in a canonical order (sorted by entity type, then normalised value, independent of
//! where the values appear in the text), and a candidate that is already taken in the request, or
//! that occurs in the request's original text, is rejected and re-drawn with `attempt + 1`. After
//! [`MAX_REALISTIC_ATTEMPTS`] rejections the value gets a typed placeholder carrying 64 HMAC bits
//! (`⟦PERSON_1f2e…⟧`), still collision-checked, so the loop always ends with a distinct value.
//!
//! **Across requests of one tenant**, two different values can share a surrogate when the format
//! leaves few bits. For `n` distinct values of one type in a tenant and `N` possible surrogates,
//! the chance that any two collide is about `n² / 2N`:
//!
//! | Type | Format | N | p(collision), n = 1,000 |
//! |---|---|---|---|
//! | Card (16 digits) | first digit kept, Luhn-valid | 10^14 | 5 × 10^-9 |
//! | IBAN (DE) | country kept, 18-digit BBAN, valid check | 10^18 | 5 × 10^-13 |
//! | Phone (11 digits) | first digit kept | 10^10 | 5 × 10^-5 |
//! | Email | `first.last<1..99999>@example.<tld>` | 1.2 × 10^9 | 4 × 10^-4 |
//! | US SSN | `9xx-xx-xxxx` (never a real SSN) | 9.9 × 10^7 | 5 × 10^-3 |
//! | Street address | `<2..999> <street> <suffix>` | 1.6 × 10^5 | about 1 |
//! | Full name | 64 first × 64 last | 4,096 | 1 |
//! | Organisation | 32 × 16 | 512 | 1 |
//! | Town, single first name, IP | 40, 64, 762 (RFC 5737) | | 1 |
//!
//! Such a collision does not break rehydration, because the reverse map is built per request
//! from the values seen in that request and is never shared: response text is only mapped back
//! to originals of the current request. Its effects are bounded:
//! - the upstream sees two people of the tenant under one fake name (less linkable, not more);
//! - the exact cache may serve an answer computed for a byte-identical protected request about
//!   the other person. The model saw exactly the same input in both cases, so the answer is just
//!   as valid; the cache stores the pseudonymised answer and rehydrates it with the current
//!   request's map, so it never carries the other person's original;
//! - a request that mentions both values re-draws one of them, so that request's protected text
//!   differs from requests that mention only one (a cache miss, nothing worse).
//!
//! The same holds for the collision guard against the original text: identical requests always
//! produce identical protected requests, but a value can get a different surrogate in a request
//! whose own text happens to contain its first-choice surrogate.

use crate::EntityType;
use crate::patterns::{iban_mod97, luhn_sum};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap, HashSet};

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation prefix of the surrogate HMAC. Bump on any change to the derivation or the
/// formats, so a deployment never mixes two schemes under one name.
const DOMAIN: &[u8] = b"caliban/pii/surrogate/v2";

/// Realistic candidates tried before falling back to a typed placeholder.
pub const MAX_REALISTIC_ATTEMPTS: u32 = 32;

// Pools. Names and towns avoid common English words, because rehydration matches
// case-insensitively and must not rewrite ordinary words in model output.
const FIRST: &[&str] = &[
    "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Avery", "Quinn", "Jamie", "Rowan", "Elena", "Mateo", "Priya",
    "Kenji", "Amara", "Lucas", "Noor", "Sofia", "Daniel", "Ines", "Aiko", "Bastian", "Camila", "Dario", "Emeka", "Farah",
    "Giulia", "Hamid", "Ilse", "Jonas", "Kavya", "Leandro", "Mireille", "Nikolai", "Oona", "Pavel", "Rania", "Soren",
    "Talia", "Ugo", "Valeria", "Wendell", "Ximena", "Yusuf", "Zofia", "Anouk", "Bruno", "Chiara", "Dmitri", "Esme", "Femi",
    "Greta", "Hugo", "Ingrid", "Joaquin", "Keiko", "Leila", "Marek", "Nadia", "Oskar", "Paloma", "Rafael", "Saskia", "Tobias",
];
const LAST: &[&str] = &[
    "Rivera", "Okafor", "Lindqvist", "Moreau", "Haddad", "Novak", "Tanaka", "Silva", "Brennan", "Kowalski", "Mendes",
    "Varga", "Ahmed", "Fischer", "Costa", "Larsen", "Ibarra", "Petrov", "Nakamura", "Duarte", "Abara", "Bergstrom",
    "Castellano", "Dragomir", "Eriksen", "Ferreira", "Gallagher", "Horvath", "Iwasaki", "Jablonski", "Kapoor", "Lefebvre",
    "Marchetti", "Nyberg", "Oyelaran", "Pasternak", "Quintero", "Rasmussen", "Szabo", "Takahashi", "Uchenna", "Valdivia",
    "Wojcik", "Yamamoto", "Zielinski", "Achterberg", "Baptiste", "Cerny", "Delacroix", "Esposito", "Fontaine", "Grigoryan",
    "Halvorsen", "Ilunga", "Jovanovic", "Kristiansen", "Lombardi", "Mwangi", "Nakashima", "Osei", "Pellegrini", "Rautio",
    "Sandoval", "Thorsen",
];
const ORG_A: &[&str] = &[
    "Northwind", "Bluepeak", "Harbor", "Silverline", "Crescent", "Ironwood", "Brightwater", "Summit", "Ambergate",
    "Bellhaven", "Copperfield", "Driftwood", "Emberly", "Foxglove", "Granitebay", "Hollowbrook", "Juniperhill", "Kestrel",
    "Lanterna", "Meridale", "Oakhurst", "Pinecrest", "Quarrystone", "Redfern", "Stonebridge", "Tidewell", "Umberleigh",
    "Valecrest", "Westmarch", "Yellowpine", "Ashgrove", "Brackenridge",
];
const ORG_B: &[&str] = &[
    "Logistics", "Holdings", "Analytics", "Partners", "Industries", "Labs", "Group", "Systems", "Ventures", "Dynamics",
    "Solutions", "Capital", "Networks", "Consulting", "Technologies", "Trading",
];
/// Invented, generic-sounding town names.
const CITY: &[&str] = &[
    "Valemont", "Brenford", "Castlemere", "Dorrowby", "Elmsworth", "Farrowdale", "Glenhollow", "Kestonbury", "Larkmoor",
    "Merriton", "Norbridge", "Pellham Cross", "Quillmere", "Rosswick", "Selbury", "Thornwick", "Wexmoor", "Yarrowfield",
    "Ashcombe Vale", "Brightmere", "Ashwyke", "Brindlemoor", "Corrowdale", "Dunmarsh", "Eskerby", "Fenwold", "Gorsewick",
    "Haverleigh", "Islemont", "Jessamy Vale", "Kirkhallow", "Lindenmere", "Marrowby", "Netherwold", "Oakhallow",
    "Pennerick", "Ravelwick", "Sallowmere", "Tarrowby", "Umbersby",
];
const STREET: &[&str] = &[
    "Maple", "Cedar", "Juniper", "Linden", "Alder", "Hawthorn", "Rowan", "Sycamore", "Larch", "Birchwood", "Chestnut",
    "Elmwood", "Foxley", "Greenbank", "Holloway", "Ivywood", "Kingsmere", "Lavender", "Mulberry", "Orchard",
];
const STREET_SUFFIX: &[&str] = &["Street", "Road", "Avenue", "Lane", "Way", "Close", "Drive", "Court"];
/// RFC 5737 documentation networks: never routed, so a surrogate IP is never a real host.
const TEST_NETS: &[&str] = &["192.0.2", "198.51.100", "203.0.113"];
const EMAIL_TLDS: &[&str] = &["com", "net", "org"];

/// Deterministic draws from the HMAC stream of one `(scope, type, value, attempt)`.
struct Draw {
    mac: HmacSha256,
    block: u32,
    buf: [u8; 32],
    pos: usize,
}

impl Draw {
    fn new(scope_key: &[u8], entity: &EntityType, normalized: &str, attempt: u32) -> Self {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(scope_key).expect("hmac accepts any key length");
        mac.update(DOMAIN);
        mac.update(&[0]);
        for part in [entity.label().as_bytes(), normalized.as_bytes()] {
            mac.update(&(part.len() as u64).to_le_bytes());
            mac.update(part);
        }
        mac.update(&attempt.to_le_bytes());
        Self { mac, block: 0, buf: [0; 32], pos: 32 }
    }

    fn u64(&mut self) -> u64 {
        if self.pos + 8 > self.buf.len() {
            let mut m = self.mac.clone();
            m.update(&self.block.to_le_bytes());
            self.buf = m.finalize().into_bytes().into();
            self.block += 1;
            self.pos = 0;
        }
        let v = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().expect("8 bytes"));
        self.pos += 8;
        v
    }

    /// Integer in `[lo, hi)`.
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        let n = hi - lo;
        lo + u64::try_from((u128::from(self.u64()) * u128::from(n)) >> 64).expect("below n")
    }

    fn pick<'a>(&mut self, pool: &[&'a str]) -> &'a str {
        pool[usize::try_from(self.range(0, pool.len() as u64)).expect("pool index")]
    }

    fn digit(&mut self) -> u8 {
        u8::try_from(self.range(0, 10)).expect("digit")
    }

    fn letter(&mut self, base: u8) -> char {
        char::from(base + u8::try_from(self.range(0, 26)).expect("letter"))
    }

    /// 64 bits as hex, for the placeholder fallback.
    fn tag(&mut self) -> String {
        format!("{:016x}", self.u64())
    }
}

/// The reverse map for one request (or one protected body): `surrogate → original` for the
/// values seen in it, and nothing else. Surrogates of values that do not appear in the request
/// are unknown to it, so the rehydrator leaves them as they are.
#[derive(Default)]
pub struct Vault {
    scope_key: Vec<u8>,
    forward: HashMap<(EntityType, String), String>,
    reverse: Vec<(String, String)>,
    used: HashSet<String>,
    corpus_lower: String,
}

impl std::fmt::Debug for Vault {
    // Never print the scope key or the originals.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("entries", &self.reverse.len()).finish_non_exhaustive()
    }
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

    /// `(surrogate, original)` pairs, in assignment order.
    pub fn pairs(&self) -> &[(String, String)] {
        &self.reverse
    }

    /// Assigns surrogates to every value of a request at once, in canonical order (entity type,
    /// then normalised value), so the outcome of collision resolution does not depend on where the
    /// values appear in the text. When several spellings normalise to the same value, the
    /// smallest one (byte order) is the one restored.
    pub fn assign<'a>(&mut self, values: impl IntoIterator<Item = (&'a EntityType, &'a str)>) {
        let mut canonical: BTreeMap<(EntityType, String), &'a str> = BTreeMap::new();
        for (entity, original) in values {
            canonical
                .entry((entity.clone(), normalize(entity, original)))
                .and_modify(|o| *o = (*o).min(original))
                .or_insert(original);
        }
        for ((entity, _), original) in canonical {
            self.surrogate_for(&entity, original);
        }
    }

    /// The surrogate for `original`, assigning one if this vault has not seen the value yet.
    pub fn surrogate_for(&mut self, entity: &EntityType, original: &str) -> String {
        let key = (entity.clone(), normalize(entity, original));
        if let Some(s) = self.forward.get(&key) {
            return s.clone();
        }
        let surrogate = self.derive(entity, &key.1, original);
        self.used.insert(surrogate.to_lowercase());
        self.forward.insert(key, surrogate.clone());
        self.reverse.push((surrogate.clone(), original.to_owned()));
        surrogate
    }

    fn clashes(&self, candidate: &str) -> bool {
        let lower = candidate.to_lowercase();
        candidate.is_empty() || self.used.contains(&lower) || self.corpus_lower.contains(&lower)
    }

    /// First candidate that is free in this request: realistic ones first, then a typed
    /// placeholder. Ends because the placeholder carries 64 fresh bits per attempt.
    fn derive(&self, entity: &EntityType, normalized: &str, original: &str) -> String {
        let mut attempt = 0u32;
        loop {
            let mut d = Draw::new(&self.scope_key, entity, normalized, attempt);
            let candidate = if attempt < MAX_REALISTIC_ATTEMPTS {
                generate(entity, original, &mut d)
            } else {
                format!("⟦{}_{}⟧", entity.label().to_uppercase(), d.tag())
            };
            if !self.clashes(&candidate) {
                return candidate;
            }
            attempt = attempt.saturating_add(1);
        }
    }
}

fn normalize(entity: &EntityType, s: &str) -> String {
    match entity {
        EntityType::CreditCard | EntityType::Phone | EntityType::UsSsn => s.chars().filter(char::is_ascii_digit).collect(),
        EntityType::Iban => s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase(),
        _ => s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase(),
    }
}

fn generate(entity: &EntityType, original: &str, d: &mut Draw) -> String {
    match entity {
        EntityType::Email => {
            let first = d.pick(FIRST).to_lowercase();
            let last = d.pick(LAST).to_lowercase();
            let n = d.range(1, 100_000);
            let tld = d.pick(EMAIL_TLDS);
            format!("{first}.{last}{n}@example.{tld}")
        }
        EntityType::Person => {
            let first = d.pick(FIRST);
            let last = d.pick(LAST);
            match original.split_whitespace().count() {
                1 => first.to_owned(),
                _ => format!("{first} {last}"),
            }
        }
        EntityType::Organization => format!("{} {}", d.pick(ORG_A), d.pick(ORG_B)),
        EntityType::Location => location(original, d),
        EntityType::IpAddress => format!("{}.{}", d.pick(TEST_NETS), d.range(1, 255)),
        EntityType::UsSsn => format!("9{:02}-{:02}-{:04}", d.range(0, 100), d.range(1, 100), d.range(1, 10_000)),
        // Keep the first digit (country code / network) so the model can still reason about it.
        EntityType::Phone => shuffle_shape(original, d, 1),
        EntityType::CreditCard => card(original, d),
        EntityType::Iban => iban(original, d),
        EntityType::Custom(_) => shuffle_shape(original, d, 0),
        // Secrets never reach surrogate generation (the request is blocked).
        EntityType::Secret => String::new(),
    }
}

/// Street-like surrogate when the original carries a number (an address), a town name otherwise.
fn location(original: &str, d: &mut Draw) -> String {
    if original.chars().any(|c| c.is_ascii_digit()) {
        format!("{} {} {}", d.range(2, 1000), d.pick(STREET), d.pick(STREET_SUFFIX))
    } else {
        d.pick(CITY).to_owned()
    }
}

/// Replaces digits with digits and letters with letters, preserving separators and case.
fn shuffle_shape(original: &str, d: &mut Draw, keep_leading_digits: usize) -> String {
    let mut kept = 0;
    original
        .chars()
        .map(|c| {
            if c.is_ascii_digit() {
                if kept < keep_leading_digits {
                    kept += 1;
                    return c;
                }
                char::from(b'0' + d.digit())
            } else if c.is_ascii_uppercase() {
                d.letter(b'A')
            } else if c.is_ascii_lowercase() {
                d.letter(b'a')
            } else {
                c
            }
        })
        .collect()
}

/// Card surrogate: same length and separators, first digit kept, valid Luhn check digit.
fn card(original: &str, d: &mut Draw) -> String {
    let n = original.chars().filter(char::is_ascii_digit).count();
    let mut digits: Vec<u8> = Vec::with_capacity(n);
    for (i, c) in original.chars().filter(char::is_ascii_digit).enumerate() {
        digits.push(if i == 0 { c as u8 - b'0' } else { d.digit() });
    }
    // Choose the last digit so the Luhn sum is a multiple of 10.
    if let Some(last) = digits.last_mut() {
        *last = 0;
    }
    let check = (10 - luhn_sum(&digits) % 10) % 10;
    if let Some(last) = digits.last_mut() {
        *last = u8::try_from(check).unwrap_or(0);
    }
    let mut it = digits.into_iter();
    original.chars().map(|c| if c.is_ascii_digit() { char::from(b'0' + it.next().unwrap_or(0)) } else { c }).collect()
}

/// IBAN surrogate: same country and shape, random BBAN, valid check digits.
fn iban(original: &str, d: &mut Draw) -> String {
    let compact: String = original.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    if compact.len() < 5 || !compact.is_ascii() {
        return shuffle_shape(original, d, 0);
    }
    let country = &compact[..2];
    let bban: String =
        compact[4..].chars().map(|c| if c.is_ascii_digit() { char::from(b'0' + d.digit()) } else { d.letter(b'A') }).collect();
    let rem = iban_mod97(&format!("{country}00{bban}")).unwrap_or(0);
    let check = 98 - rem;
    let new_compact = format!("{country}{check:02}{bban}");
    // Re-apply the original spacing.
    let mut it = new_compact.chars();
    original.chars().map(|c| if c.is_whitespace() { c } else { it.next().unwrap_or('0') }).collect()
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
        assert!(c.starts_with('4'));
        let i = v.surrogate_for(&EntityType::Iban, "DE89 3704 0044 0532 0130 00");
        assert!(iban_valid(&i), "{i}");
        assert!(i.starts_with("DE"));
        let ssn = v.surrogate_for(&EntityType::UsSsn, "123-45-6789");
        assert!(ssn.starts_with('9') && ssn.len() == 11, "{ssn}");
        let ip = v.surrogate_for(&EntityType::IpAddress, "10.1.2.3");
        assert!(TEST_NETS.iter().any(|n| ip.starts_with(&format!("{n}."))), "{ip}");
        let e = v.surrogate_for(&EntityType::Email, "jane@acme.com");
        assert!(e.contains("@example."), "{e}");
    }

    #[test]
    fn pool_sizes_match_the_documented_table() {
        assert_eq!((FIRST.len(), LAST.len(), ORG_A.len(), ORG_B.len(), CITY.len()), (64, 64, 32, 16, 40));
        for pool in [FIRST, LAST, ORG_A, ORG_B, CITY, STREET] {
            assert_eq!(pool.iter().collect::<HashSet<_>>().len(), pool.len(), "duplicate in pool");
        }
    }

    #[test]
    fn different_scopes_give_different_surrogates() {
        let a = Vault::new(b"scope-a").surrogate_for(&EntityType::Email, "x@y.com");
        let b = Vault::new(b"scope-b").surrogate_for(&EntityType::Email, "x@y.com");
        assert_ne!(a, b);
    }

    #[test]
    fn same_scope_is_stable_across_vaults_and_spellings() {
        let a = Vault::new(b"k").surrogate_for(&EntityType::Person, "Jane  Doe");
        let b = Vault::new(b"k").surrogate_for(&EntityType::Person, "jane doe");
        assert_eq!(a, b);
    }

    /// Pinned output: the derivation is shared by every router of a deployment (split mode) and
    /// should only change on purpose. If this changes, bump `DOMAIN`.
    #[test]
    fn derivation_is_pinned() {
        let mut v = Vault::new(&[7u8; 32]);
        assert_eq!(v.surrogate_for(&EntityType::Email, "jane.doe@acme.com"), "taylor.mendes78440@example.org");
        assert_eq!(v.surrogate_for(&EntityType::CreditCard, "4111 1111 1111 1111"), "4882 4080 3603 1359");
        assert_eq!(v.surrogate_for(&EntityType::Person, "Jane Doe"), "Oskar Kapoor");
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

    /// Single first names have 64 realistic surrogates. 200 distinct values in one request must
    /// still get 200 distinct surrogates: re-draws first, then typed placeholders.
    #[test]
    fn collisions_within_a_request_are_resolved() {
        let names: Vec<String> = (0..200).map(|i| format!("Name{i}")).collect();
        let mut v = Vault::new(b"tenant-key");
        v.assign(names.iter().map(|n| (&EntityType::Person, n.as_str())));
        let surrogates: HashSet<String> = v.pairs().iter().map(|(s, _)| s.to_lowercase()).collect();
        assert_eq!(surrogates.len(), 200);
        assert!(v.pairs().iter().any(|(s, _)| FIRST.contains(&s.as_str())));
        assert!(v.pairs().iter().any(|(s, _)| s.starts_with("⟦PERSON_")), "pool exhausted, placeholders expected");
        // Every surrogate restores its own original.
        let r = crate::Rehydrator::new(&v);
        for (s, o) in v.pairs() {
            assert_eq!(&r.rehydrate(s), o);
        }
    }

    /// Two values whose first-choice surrogates clash: the outcome is the same whatever order they
    /// appear in, and the canonical first keeps its first choice.
    #[test]
    fn collision_resolution_is_order_independent() {
        let key = b"tenant-key";
        let first_choice = |name: &str| Vault::new(key).surrogate_for(&EntityType::Person, name);
        // Find two single names whose first choices clash (64-name pool: quick).
        let mut seen: HashMap<String, String> = HashMap::new();
        let (a, b) = (0..)
            .map(|i| format!("Person{i}"))
            .find_map(|n| seen.insert(first_choice(&n), n.clone()).map(|prev| (prev, n)))
            .expect("a clash in a 64-name pool");
        assert_eq!(first_choice(&a), first_choice(&b));

        let run = |order: [&str; 2]| {
            let mut v = Vault::new(key);
            v.assign(order.iter().map(|n| (&EntityType::Person, *n)));
            (v.surrogate_for(&EntityType::Person, &a), v.surrogate_for(&EntityType::Person, &b))
        };
        let ab = run([&a, &b]);
        assert_eq!(ab, run([&b, &a]), "same assignment whatever the text order");
        assert_ne!(ab.0, ab.1, "never one surrogate for two values in a request");
        let a_first = normalize(&EntityType::Person, &a) < normalize(&EntityType::Person, &b);
        let (kept, canonical_first) = if a_first { (&ab.0, &a) } else { (&ab.1, &b) };
        assert_eq!(kept, &first_choice(canonical_first));
    }

    #[test]
    fn debug_does_not_leak() {
        let mut v = Vault::new(b"secret-scope-key");
        v.surrogate_for(&EntityType::Email, "jane@acme.com");
        let s = format!("{v:?}");
        assert!(!s.contains("jane") && !s.contains("secret"), "{s}");
    }
}
