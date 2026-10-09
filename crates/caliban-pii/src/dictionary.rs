//! Tenant dictionaries: exact terms from the ontology (customer names, account ids, employee
//! lists) matched with Aho-Corasick. Rebuilt whenever the ontology version changes.

use crate::{Detector, EntityType, Span};
use aho_corasick::{AhoCorasick, MatchKind};

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
}
