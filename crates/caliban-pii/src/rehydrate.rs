//! Restores originals in model output, including token streams.
//!
//! Streaming uses a hold-back buffer: text that could still be the start of a surrogate is held
//! until the next chunk proves otherwise, so a surrogate split across SSE chunks is still restored.
//! Matching is ASCII case-insensitive as a cheap fuzzy fallback.

use crate::Vault;
use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use std::sync::Arc;

pub struct Rehydrator {
    ac: Option<AhoCorasick>,
    originals: Vec<String>,
    surrogates_lower: Vec<String>,
}

impl Rehydrator {
    pub fn new(vault: &Vault) -> Self {
        if vault.is_empty() {
            return Self { ac: None, originals: vec![], surrogates_lower: vec![] };
        }
        let (surrogates, originals): (Vec<String>, Vec<String>) = vault.pairs().iter().cloned().unzip();
        // One automaton per request over a handful of short patterns, searched over short texts:
        // a contiguous NFA builds an order of magnitude faster than the DFA the builder would
        // otherwise pick, and searches as fast at this size.
        let ac = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .match_kind(MatchKind::LeftmostLongest)
            .ascii_case_insensitive(true)
            .build(&surrogates)
            .ok();
        let surrogates_lower = surrogates.iter().map(|s| s.to_ascii_lowercase()).collect();
        Self { ac, originals, surrogates_lower }
    }

    pub fn rehydrate(&self, text: &str) -> String {
        match &self.ac {
            Some(ac) => ac.replace_all(text, &self.originals),
            None => text.to_owned(),
        }
    }

    pub fn is_noop(&self) -> bool {
        self.ac.is_none()
    }

    pub fn streaming(self: &Arc<Self>) -> StreamingRehydrator {
        StreamingRehydrator { inner: Arc::clone(self), buf: String::new() }
    }

    /// Start index of the longest suffix of `buf` that is a proper prefix of some surrogate.
    fn hold_from(&self, buf: &str) -> usize {
        let lower = buf.to_ascii_lowercase();
        for (j, _) in lower.char_indices() {
            let suffix = &lower[j..];
            if self.surrogates_lower.iter().any(|s| s.len() > suffix.len() && s.starts_with(suffix)) {
                return j;
            }
        }
        buf.len()
    }
}

pub struct StreamingRehydrator {
    inner: Arc<Rehydrator>,
    buf: String,
}

impl StreamingRehydrator {
    /// Feed a decoded text delta; returns the text that is safe to emit now.
    pub fn push(&mut self, delta: &str) -> String {
        let Some(ac) = &self.inner.ac else {
            return delta.to_owned();
        };
        self.buf.push_str(delta);
        let mut emit_end = self.inner.hold_from(&self.buf);
        // A complete match that straddles the hold point is emitted whole.
        for m in ac.find_iter(&self.buf) {
            if m.start() < emit_end && m.end() > emit_end {
                emit_end = m.end();
            }
        }
        let out = self.inner.rehydrate(&self.buf[..emit_end]);
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
    fn case_mangled_surrogate_is_still_restored() {
        let (v, s) = vault();
        let r = Rehydrator::new(&v);
        assert_eq!(r.rehydrate(&s.to_uppercase()), "jane@acme.com");
    }
}
