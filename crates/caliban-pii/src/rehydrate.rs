//! Restores originals in model output, including token streams.
//!
//! Streaming uses a hold-back buffer: text that could still be the start of a surrogate is held
//! until the next chunk proves otherwise, so a surrogate split across SSE chunks is still restored.
//! Matching is ASCII case-insensitive as a cheap fuzzy fallback.
//!
//! # Structured values whatever their separators
//!
//! A structured value (IBAN, card, phone, US SSN, national id such as the French NIR) gets one
//! surrogate per request, in the format of the spelling the vault restores. A model often writes
//! it back in another format: an IBAN without its spaces, a card number in groups of four, a
//! phone with dashes. Such a surrogate is still the request's own value, so it is restored too:
//! the match ignores separators (spaces, no-break and thin spaces, dashes, dots, slashes and
//! parentheses, at most [`MAX_SEPARATOR_RUN`] in a row) and compares the ASCII letters and digits, case-insensitively.
//!
//! - **Only issued surrogates.** A match is the exact separator-free key of a surrogate this
//!   request's vault gave, at least [`MIN_FUZZY_KEY`] characters long, with no letter or digit
//!   directly before or after it (a key inside a longer number is not one). The vault never gives
//!   a structured surrogate whose key occurs in the request's original text in any format, nor two
//!   surrogates with the same key, so a match cannot rewrite genuine text or restore the wrong
//!   value.
//! - **Restored in the format the model used.** The original's letters and digits are laid out
//!   in the model's separators (`FR76 1234 ...` written as `FR761234...` comes back as the real
//!   IBAN without spaces). The model chose that format for where the value goes (a tool argument
//!   whose schema wants it compact, a sentence), and either spelling of the value the caller sent
//!   is reproduced exactly. When the counts differ (they do not for the surrogates Caliban
//!   derives), the original is restored as the vault holds it.

use crate::{EntityType, Vault};
use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use std::sync::Arc;

/// Shortest separator-free key matched whatever its separators; shorter structured surrogates
/// are matched exactly only.
pub const MIN_FUZZY_KEY: usize = 6;
/// Most separators in a row inside a reformatted structured surrogate.
pub const MAX_SEPARATOR_RUN: usize = 3;

/// The entity types restored whatever their separators.
pub fn is_structured(e: &EntityType) -> bool {
    matches!(
        e,
        EntityType::Iban | EntityType::CreditCard | EntityType::Phone | EntityType::UsSsn | EntityType::NationalId
    )
}

/// A character that may separate the groups of a structured value.
pub fn is_separator(c: char) -> bool {
    matches!(c, ' ' | '-' | '.' | '/' | '(' | ')' | '\u{a0}' | '\u{202f}' | '\u{2009}' | '\u{2010}' | '\u{2011}')
}

/// The ASCII letters and digits of `s`, upper-cased.
pub fn structured_key(s: &str) -> String {
    s.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_uppercase()).collect()
}

/// The key a surrogate of `entity` is matched by whatever its separators (`None`: matched
/// exactly only).
pub fn fuzzy_key(entity: &EntityType, surrogate: &str) -> Option<String> {
    if !is_structured(entity) {
        return None;
    }
    let k = structured_key(surrogate);
    (k.len() >= MIN_FUZZY_KEY).then_some(k)
}

/// One replacement in a text.
#[derive(Debug, Clone, Copy)]
struct Hit {
    start: usize,
    end: usize,
    idx: usize,
    /// Matched by its separator-free key (restored in the matched text's layout).
    fuzzy: bool,
}

/// A letter or digit of the text, as structured keys see it.
struct Tok {
    start: usize,
    end: usize,
    /// Upper-cased; `None` for a non-ASCII alphanumeric (a word character that matches nothing).
    ch: Option<char>,
}

pub struct Rehydrator {
    ac: Option<AhoCorasick>,
    /// The entry of each automaton pattern.
    ac_idx: Vec<usize>,
    /// What each entry restores (JSON-escaped in [`Rehydrator::for_json`]).
    originals: Vec<String>,
    /// The ASCII letters and digits of each original, in order (structured entries).
    layouts: Vec<Vec<char>>,
    /// Exact patterns, lower-cased (the streaming hold-back).
    surrogates_lower: Vec<String>,
    /// `(key, entry)` of the structured surrogates matched whatever their separators.
    keys: Vec<(String, usize)>,
}

impl Rehydrator {
    pub fn new(vault: &Vault) -> Self {
        let mut originals = Vec::new();
        let mut layouts = Vec::new();
        let mut keys = Vec::new();
        let mut exact = Vec::new();
        let mut ac_idx = Vec::new();
        for (i, (entity, surrogate, original)) in vault.entries().enumerate() {
            originals.push(original.to_owned());
            layouts.push(original.chars().filter(char::is_ascii_alphanumeric).collect());
            match fuzzy_key(entity, surrogate) {
                Some(k) => keys.push((k, i)),
                None => {
                    exact.push(surrogate.to_owned());
                    ac_idx.push(i);
                }
            }
        }
        // One automaton per request over a handful of short patterns, searched over short texts:
        // a contiguous NFA builds an order of magnitude faster than the DFA the builder would
        // otherwise pick, and searches as fast at this size.
        let ac = (!exact.is_empty())
            .then(|| {
                AhoCorasick::builder()
                    .kind(Some(AhoCorasickKind::ContiguousNFA))
                    .match_kind(MatchKind::LeftmostLongest)
                    .ascii_case_insensitive(true)
                    .build(&exact)
                    .ok()
            })
            .flatten();
        let surrogates_lower = exact.iter().map(|s| s.to_ascii_lowercase()).collect();
        Self { ac, ac_idx, originals, layouts, surrogates_lower, keys }
    }

    /// Every replacement in `text`, leftmost-longest, without overlaps.
    fn hits(&self, text: &str) -> Vec<Hit> {
        let mut hits: Vec<Hit> = Vec::new();
        if let Some(ac) = &self.ac {
            hits.extend(ac.find_iter(text).map(|m| Hit {
                start: m.start(),
                end: m.end(),
                idx: self.ac_idx[m.pattern().as_usize()],
                fuzzy: false,
            }));
        }
        if !self.keys.is_empty() {
            hits.extend(self.fuzzy_hits(text));
        }
        hits.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        let mut out: Vec<Hit> = Vec::with_capacity(hits.len());
        for h in hits {
            if out.last().is_none_or(|last| h.start >= last.end) {
                out.push(h);
            }
        }
        out
    }

    /// The structured surrogates of `text` whatever their separators (see the module docs).
    fn fuzzy_hits(&self, text: &str) -> Vec<Hit> {
        let toks: Vec<Tok> = text
            .char_indices()
            .filter(|(_, c)| c.is_alphanumeric())
            .map(|(i, c)| Tok {
                start: i,
                end: i + c.len_utf8(),
                ch: c.is_ascii_alphanumeric().then(|| c.to_ascii_uppercase()),
            })
            .collect();
        // Whether tokens k and k + 1 touch, and whether what lies between them is a separator run.
        let adjacent = |k: usize| toks[k].end == toks[k + 1].start;
        let joined = |k: usize| {
            let gap = &text[toks[k].end..toks[k + 1].start];
            gap.chars().count() <= MAX_SEPARATOR_RUN && gap.chars().all(is_separator)
        };
        let mut out = Vec::new();
        for i in 0..toks.len() {
            if i > 0 && adjacent(i - 1) {
                continue;
            }
            for (key, idx) in &self.keys {
                let n = key.len();
                if i + n > toks.len() || (i + n < toks.len() && adjacent(i + n - 1)) {
                    continue;
                }
                let matched =
                    key.chars().enumerate().all(|(j, c)| toks[i + j].ch == Some(c) && (j + 1 == n || joined(i + j)));
                if matched {
                    out.push(Hit { start: toks[i].start, end: toks[i + n - 1].end, idx: *idx, fuzzy: true });
                }
            }
        }
        out
    }

    /// What a hit restores: the original, laid out in the matched text's separators for a
    /// structured value.
    fn restored(&self, text: &str, h: &Hit) -> String {
        let original = &self.originals[h.idx];
        let layout = &self.layouts[h.idx];
        let matched = &text[h.start..h.end];
        if !h.fuzzy || matched.chars().filter(char::is_ascii_alphanumeric).count() != layout.len() {
            return original.clone();
        }
        let mut it = layout.iter();
        matched.chars().map(|c| if c.is_ascii_alphanumeric() { *it.next().unwrap_or(&c) } else { c }).collect()
    }

    pub fn rehydrate(&self, text: &str) -> String {
        if self.is_noop() {
            return text.to_owned();
        }
        self.apply(text, &self.hits(text), text.len())
    }

    /// `text[..upto]` with the hits that end there replaced (hits found in the whole `text`, so
    /// `upto` never passes for the end of a value that goes on after it).
    fn apply(&self, text: &str, hits: &[Hit], upto: usize) -> String {
        let mut out = String::with_capacity(upto);
        let mut cursor = 0;
        for h in hits.iter().filter(|h| h.end <= upto) {
            out.push_str(&text[cursor..h.start]);
            out.push_str(&self.restored(text, h));
            cursor = h.end;
        }
        out.push_str(&text[cursor..upto]);
        out
    }

    /// The same matcher with each original JSON-escaped (no surrounding quotes), for text that is
    /// itself JSON, such as streamed tool-call arguments (`function.arguments`,
    /// `input_json_delta.partial_json`): an original with a quote, backslash or line break must
    /// not break the JSON it is restored into. (A structured value restored in the model's layout
    /// is letters, digits and the separators the JSON already held.)
    pub fn for_json(&self) -> Self {
        let originals = self
            .originals
            .iter()
            .map(|o| {
                let quoted = serde_json::to_string(o).unwrap_or_default();
                quoted.get(1..quoted.len().saturating_sub(1)).unwrap_or_default().to_owned()
            })
            .collect();
        Self {
            ac: self.ac.clone(),
            ac_idx: self.ac_idx.clone(),
            originals,
            layouts: self.layouts.clone(),
            surrogates_lower: self.surrogates_lower.clone(),
            keys: self.keys.clone(),
        }
    }

    pub fn is_noop(&self) -> bool {
        self.ac.is_none() && self.keys.is_empty()
    }

    pub fn streaming(self: &Arc<Self>) -> StreamingRehydrator {
        StreamingRehydrator { inner: Arc::clone(self), buf: String::new() }
    }

    /// Start index of the longest suffix of `buf` that could still become a surrogate: a proper
    /// prefix of an exact one, or the start of a structured one in any format (also a complete
    /// one that ends the buffer, until the next character shows it is not part of a longer
    /// number).
    fn hold_from(&self, buf: &str) -> usize {
        let lower = buf.to_ascii_lowercase();
        let mut from = buf.len();
        for (j, _) in lower.char_indices() {
            let suffix = &lower[j..];
            if self.surrogates_lower.iter().any(|s| s.len() > suffix.len() && s.starts_with(suffix)) {
                from = j;
                break;
            }
        }
        from.min(self.fuzzy_hold_from(buf))
    }

    fn fuzzy_hold_from(&self, buf: &str) -> usize {
        let Some(longest) = self.keys.iter().map(|(k, _)| k.len()).max() else { return buf.len() };
        let ends_alnum = buf.chars().next_back().is_some_and(char::is_alphanumeric);
        // Walk back over the trailing run of letters, digits and short separator runs, building
        // its key from the end; every start of a word inside it is a candidate.
        let mut best = buf.len();
        let mut key_rev = String::new();
        let mut seps = 0;
        let mut chars = buf.char_indices().rev().peekable();
        while let Some((i, c)) = chars.next() {
            if is_separator(c) {
                seps += 1;
                if seps > MAX_SEPARATOR_RUN {
                    break;
                }
                continue;
            }
            if !c.is_ascii_alphanumeric() {
                break;
            }
            seps = 0;
            key_rev.push(c.to_ascii_uppercase());
            if key_rev.len() > longest {
                break;
            }
            let word_start = chars.peek().is_none_or(|(_, p)| !p.is_alphanumeric());
            if !word_start {
                continue;
            }
            let key: String = key_rev.chars().rev().collect();
            let could = self.keys.iter().any(|(k, _)| k.starts_with(&key) && (k.len() > key.len() || ends_alnum));
            if could {
                best = i;
            }
        }
        best
    }
}

pub struct StreamingRehydrator {
    inner: Arc<Rehydrator>,
    buf: String,
}

impl StreamingRehydrator {
    /// Feed a decoded text delta; returns the text that is safe to emit now.
    pub fn push(&mut self, delta: &str) -> String {
        if self.inner.is_noop() {
            return delta.to_owned();
        }
        self.buf.push_str(delta);
        let mut emit_end = self.inner.hold_from(&self.buf);
        let hits = self.inner.hits(&self.buf);
        // A complete match that straddles the hold point is emitted whole.
        for m in &hits {
            if m.start < emit_end && m.end > emit_end {
                emit_end = m.end;
            }
        }
        let out = self.inner.apply(&self.buf, &hits, emit_end);
        self.buf.drain(..emit_end);
        out
    }

    /// Flush whatever is held back at end of stream.
    pub fn finish(&mut self) -> String {
        let rest = std::mem::take(&mut self.buf);
        self.inner.rehydrate(&rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityType;

    use crate::{PiiEngine, PiiMode};
    use caliban_ir::ChatRequest;

    const IBAN_SPACED: &str = "FR76 3000 6000 0112 3456 7890 189";
    const IBAN_COMPACT: &str = "FR7630006000011234567890189";

    /// A request carrying the IBAN in two formats, protected like the gateway does: the text the
    /// model received and the request's vault.
    fn fintech_request() -> (String, Vault) {
        let text = format!(
            "Refund to {IBAN_SPACED}. The form says {IBAN_COMPACT}. Card 4111 1111 1111 1111, phone +33 6 12 34 56 78."
        );
        let body = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": text}]}).to_string();
        let mut req = ChatRequest::from_openai_json(body.as_bytes()).unwrap();
        let p = PiiEngine::default().protect(&mut req, PiiMode::Reversible, b"tenant-key").unwrap();
        (req.last_user_text().unwrap(), p.vault)
    }

    fn surrogate_of(v: &Vault, e: &EntityType) -> String {
        v.entries().find(|(k, _, _)| *k == e).map(|(_, s, _)| s.to_owned()).unwrap()
    }

    /// Lays out `s`'s letters and digits in groups of `n` joined by `sep`.
    fn regroup(s: &str, n: usize, sep: &str) -> String {
        let k = structured_key(s);
        k.as_bytes().chunks(n).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(sep)
    }

    #[test]
    fn one_value_in_two_formats_gets_one_surrogate_restored_in_the_models_format() {
        let (sent, v) = fintech_request();
        let s = surrogate_of(&v, &EntityType::Iban);
        assert_eq!(sent.matches(&s).count(), 2, "one surrogate for both spellings: {sent}");
        assert!(!sent.contains("3000 6000") && !sent.contains("30006000"), "{sent}");
        let r = Rehydrator::new(&v);
        // As given (the spaced spelling, the smallest one), compact, regrouped, dashed, lowercase.
        assert_eq!(r.rehydrate(&format!("IBAN {s}.")), format!("IBAN {IBAN_SPACED}."));
        assert_eq!(r.rehydrate(&format!("IBAN {}.", structured_key(&s))), format!("IBAN {IBAN_COMPACT}."));
        assert_eq!(r.rehydrate(&regroup(&s, 2, " ")), regroup(IBAN_COMPACT, 2, " "));
        assert_eq!(r.rehydrate(&regroup(&s, 4, "-")), regroup(IBAN_COMPACT, 4, "-"));
        assert_eq!(r.rehydrate(&structured_key(&s).to_lowercase()), IBAN_COMPACT);
        // Card and phone too.
        let card = surrogate_of(&v, &EntityType::CreditCard);
        assert_eq!(r.rehydrate(&structured_key(&card)), "4111111111111111");
        assert_eq!(r.rehydrate(&format!("({})", regroup(&card, 4, "-"))), "(4111-1111-1111-1111)");
        let phone = surrogate_of(&v, &EntityType::Phone);
        let digits = structured_key(&phone);
        assert_eq!(r.rehydrate(&format!("call +{digits} now")), "call +33612345678 now");
        assert_eq!(
            r.rehydrate(&format!("call +{} {}", &digits[..2], regroup(&digits[2..], 3, "."))),
            format!("call +33 {}", regroup("612345678", 3, "."))
        );
    }

    #[test]
    fn a_reformatted_surrogate_in_tool_arguments_is_restored() {
        let (_, v) = fintech_request();
        let s = structured_key(&surrogate_of(&v, &EntityType::Iban));
        let r = Rehydrator::new(&v).for_json();
        let args = format!("{{\"iban\":\"{s}\",\"amount\":120}}");
        let v: serde_json::Value = serde_json::from_str(&r.rehydrate(&args)).unwrap();
        assert_eq!(v["iban"], IBAN_COMPACT);
    }

    #[test]
    fn only_exact_keys_of_issued_surrogates_are_restored() {
        let (sent, v) = fintech_request();
        let s = structured_key(&surrogate_of(&v, &EntityType::Iban));
        let r = Rehydrator::new(&v);
        // Inside a longer value: a letter or digit right before or after.
        for t in [format!("{s}1"), format!("X{s}"), format!("{s}A"), format!("0{s}")] {
            assert_eq!(r.rehydrate(&t), t);
        }
        // One character off, a missing character, too many separators in a row, a line break.
        let mut off = s.clone().into_bytes();
        off[10] = if off[10] == b'1' { b'2' } else { b'1' };
        let off = String::from_utf8(off).unwrap();
        let spread = format!("{} -  {}", &s[..8], &s[8..]);
        let broken = format!("{}\n{}", &s[..8], &s[8..]);
        for t in [off, s[..s.len() - 1].to_owned(), spread, broken] {
            assert_eq!(r.rehydrate(&t), t);
        }
        // The original text is never rewritten, in any format; another request's surrogate neither.
        assert_eq!(r.rehydrate(&sent).matches(IBAN_SPACED).count(), 2);
        assert_eq!(r.rehydrate(IBAN_COMPACT), IBAN_COMPACT);
        let mut other = Vault::new(b"other-tenant");
        let foreign = structured_key(&other.surrogate_for(&EntityType::Iban, IBAN_SPACED));
        assert_eq!(r.rehydrate(&foreign), foreign);
        // Short structured values are matched exactly only.
        let mut short = Vault::new(b"k");
        let ssn = short.surrogate_for(&EntityType::NationalId, "AB-12");
        let rs = Rehydrator::new(&short);
        assert_eq!(rs.rehydrate(&ssn), "AB-12");
        assert_eq!(rs.rehydrate(&structured_key(&ssn)), structured_key(&ssn));
    }

    #[test]
    fn a_nir_and_an_ssn_are_restored_without_their_separators() {
        let mut v = Vault::new(b"k");
        let nir = v.surrogate_for(&EntityType::NationalId, "2 84 06 75 115 042 63");
        let ssn = v.surrogate_for(&EntityType::UsSsn, "123-45-6789");
        let r = Rehydrator::new(&v);
        assert_eq!(r.rehydrate(&structured_key(&nir)), "284067511504263");
        assert_eq!(r.rehydrate(&format!("SSN {}", structured_key(&ssn))), "SSN 123456789");
        assert_eq!(r.rehydrate(&ssn), "123-45-6789");
    }

    #[test]
    fn reformatted_surrogates_are_restored_across_chunks() {
        let (_, v) = fintech_request();
        let s = structured_key(&surrogate_of(&v, &EntityType::Iban));
        let r = Arc::new(Rehydrator::new(&v));
        let text = format!("Pay {s}, then {} and {s}9.", regroup(&s, 4, " "));
        let want = format!("Pay {IBAN_COMPACT}, then {} and {s}9.", regroup(IBAN_COMPACT, 4, " "));
        assert_eq!(r.rehydrate(&text), want);
        for cut in 1..text.len() {
            let mut st = r.streaming();
            let mut out = st.push(&text[..cut]);
            out.push_str(&st.push(&text[cut..]));
            out.push_str(&st.finish());
            assert_eq!(out, want, "cut={cut}");
        }
        // Char by char.
        let mut st = r.streaming();
        let mut out: String = text.chars().map(|c| st.push(&c.to_string())).collect();
        out.push_str(&st.finish());
        assert_eq!(out, want);
    }

    #[test]
    fn a_surrogate_whose_key_occurs_in_the_original_text_is_redrawn() {
        let first = Vault::new(b"k").surrogate_for(&EntityType::Iban, IBAN_SPACED);
        let mut v = Vault::new(b"k");
        // The first choice occurs in the text in another format (dashed): it is not given.
        v.set_collision_corpus(&format!("ref {} and {IBAN_SPACED}", regroup(&first, 4, "-")));
        let s = v.surrogate_for(&EntityType::Iban, IBAN_SPACED);
        assert_ne!(structured_key(&s), structured_key(&first));
        assert!(crate::patterns::iban_valid(&s), "{s}");
    }

    fn vault() -> (Vault, String) {
        let mut v = Vault::new(b"k");
        let s = v.surrogate_for(&EntityType::Email, "jane@acme.com");
        (v, s)
    }

    #[test]
    fn restores_split_surrogates_across_chunks() {
        let (v, s) = vault();
        let r = Arc::new(Rehydrator::new(&v));
        let text = format!("Write to {s} today, {s}!");
        // Split at every possible position, including inside the surrogate.
        for cut in 1..text.len() {
            if !text.is_char_boundary(cut) {
                continue;
            }
            let mut st = r.streaming();
            let mut out = st.push(&text[..cut]);
            out.push_str(&st.push(&text[cut..]));
            out.push_str(&st.finish());
            assert_eq!(out, "Write to jane@acme.com today, jane@acme.com!", "cut={cut}");
        }
    }

    #[test]
    fn non_matching_text_is_not_delayed_much() {
        let (v, _) = vault();
        let r = Arc::new(Rehydrator::new(&v));
        let mut st = r.streaming();
        assert_eq!(st.push("hello world "), "hello world ");
    }

    #[test]
    fn json_variant_escapes_originals() {
        let mut v = Vault::new(b"k");
        let s = v.surrogate_for(&EntityType::Person, "Jane \"JJ\" O\\Neil");
        let r = Rehydrator::new(&v).for_json();
        let args = format!("{{\"name\": \"{s}\"}}");
        let restored = r.rehydrate(&args);
        let parsed: serde_json::Value = serde_json::from_str(&restored).unwrap();
        assert_eq!(parsed["name"], "Jane \"JJ\" O\\Neil");
    }

    #[test]
    fn case_mangled_surrogate_is_still_restored() {
        let (v, s) = vault();
        let r = Rehydrator::new(&v);
        assert_eq!(r.rehydrate(&s.to_uppercase()), "jane@acme.com");
    }
}
