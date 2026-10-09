//! Labelled exemplar prompts for Stage-1 kNN.
//!
//! The file format is ml's intent dataset (`ml/src/caliban_ml/router/dataset.py`, `IntentDataset`):
//! `{version, intents: {<id>: {description, utterances: [...]}}, oos: [...]}`. Core reads its JSON
//! encoding; JSON is valid YAML, so `caliban-ml router embed --dataset` reads the same files.
//! `oos` examples are never neighbours (ml uses them to pick the OOS gate); core ignores them.
//!
//! The built-in set (`data/exemplars.default.json`) was written for Caliban: synthetic prompts, no
//! third-party text. Tenants add their own through `[routing.tenants.<id>.exemplars]`.

use caliban_config::{RoutingConfig, valid_intent_id};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

pub const DEFAULT_EXEMPLARS_JSON: &str = include_str!("../data/exemplars.default.json");

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ExemplarError {
    #[error("exemplar file {0}: {1}")]
    File(String, String),
    #[error("invalid exemplar set: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentDataset {
    #[serde(default = "one")]
    pub version: u32,
    pub intents: BTreeMap<String, IntentSpec>,
    #[serde(default)]
    pub oos: Vec<String>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentSpec {
    #[serde(default)]
    pub description: String,
    pub utterances: Vec<String>,
}

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

impl IntentDataset {
    pub fn from_json(s: &str) -> Result<Self, String> {
        let d: IntentDataset = serde_json::from_str(s).map_err(|e| e.to_string())?;
        d.validate()?;
        Ok(d)
    }

    pub fn builtin() -> Self {
        Self::from_json(DEFAULT_EXEMPLARS_JSON).expect("built-in exemplar set is valid (tested)")
    }

    /// The same rules as ml's `IntentDataset._check`.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("unsupported version {}", self.version));
        }
        if self.intents.is_empty() {
            return Err("no intents".into());
        }
        let mut seen: HashMap<String, &str> = HashMap::new();
        for (intent, spec) in &self.intents {
            if !valid_intent_id(intent) {
                return Err(format!("invalid intent id {intent:?}"));
            }
            if spec.utterances.is_empty() {
                return Err(format!("intent {intent} has no utterances"));
            }
            for u in &spec.utterances {
                let k = norm(u);
                if k.is_empty() {
                    return Err(format!("empty utterance in intent {intent}"));
                }
                if let Some(other) = seen.insert(k, intent.as_str())
                    && other != intent
                {
                    return Err(format!("utterance {u:?} appears under both {other} and {intent}"));
                }
            }
        }
        if let Some(u) = self.oos.iter().find(|u| seen.contains_key(&norm(u))) {
            return Err(format!("OOS example {u:?} is also an in-scope utterance"));
        }
        Ok(())
    }
}

/// One exemplar: text, intent and owner (`None` = deployment-wide, else the tenant id).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Exemplar {
    pub owner: Option<String>,
    pub intent: String,
    pub text: String,
}

/// Everything Stage 1 indexes: the built-in set (unless disabled), exemplar files, inline
/// deployment exemplars, then each tenant's own. Duplicates (same owner, same normalised text)
/// keep the first label. The order is deterministic, so cached vectors line up.
pub fn assemble(cfg: &RoutingConfig) -> Result<Vec<Exemplar>, ExemplarError> {
    let mut out = Vec::new();
    let mut seen: HashMap<(Option<String>, String), String> = HashMap::new();
    let mut push = |owner: Option<&str>, intent: &str, text: &str, out: &mut Vec<Exemplar>| -> Result<(), ExemplarError> {
        let key = (owner.map(str::to_owned), norm(text));
        if key.1.is_empty() {
            return Ok(());
        }
        match seen.get(&key) {
            Some(prev) if prev != intent => Err(ExemplarError::Invalid(format!(
                "exemplar {text:?} is labelled both {prev} and {intent}{}",
                owner.map(|o| format!(" (tenant {o})")).unwrap_or_default()
            ))),
            Some(_) => Ok(()),
            None => {
                seen.insert(key, intent.to_owned());
                out.push(Exemplar { owner: owner.map(str::to_owned), intent: intent.to_owned(), text: text.trim().to_owned() });
                Ok(())
            }
        }
    };
    let mut datasets = Vec::new();
    if cfg.default_exemplars.unwrap_or(true) {
        datasets.push(IntentDataset::builtin());
    }
    for f in &cfg.exemplar_files {
        let raw = std::fs::read_to_string(f).map_err(|e| ExemplarError::File(f.clone(), e.to_string()))?;
        datasets.push(IntentDataset::from_json(&raw).map_err(|e| ExemplarError::File(f.clone(), e))?);
    }
    for d in &datasets {
        for (intent, spec) in &d.intents {
            for u in &spec.utterances {
                push(None, intent, u, &mut out)?;
            }
        }
    }
    for (intent, us) in &cfg.exemplars {
        for u in us {
            push(None, intent, u, &mut out)?;
        }
    }
    for (tenant, t) in &cfg.tenants {
        for (intent, us) in &t.exemplars {
            for u in us {
                push(Some(tenant.as_str()), intent, u, &mut out)?;
            }
        }
    }
    if out.is_empty() {
        return Err(ExemplarError::Invalid("no exemplars (default_exemplars = false and none configured)".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_set_is_valid_and_covers_the_core_intents() {
        let d = IntentDataset::builtin();
        for intent in ["chat", "code", "analytics", "summarize", "extraction", "translate", "reasoning"] {
            let n = d.intents.get(intent).map_or(0, |s| s.utterances.len());
            assert!(n >= 24, "{intent} has {n} exemplars");
        }
        assert!(!d.oos.is_empty());
    }

    #[test]
    fn conflicting_labels_are_rejected() {
        let bad = r#"{"version":1,"intents":{"a":{"utterances":["Hello  there"]},"b":{"utterances":["hello there"]}}}"#;
        assert!(IntentDataset::from_json(bad).unwrap_err().contains("both"));
        let bad_id = r#"{"version":1,"intents":{"Bad-Id":{"utterances":["x"]}}}"#;
        assert!(IntentDataset::from_json(bad_id).is_err());
        let unknown = r#"{"version":1,"intents":{"a":{"utterances":["x"]}},"extra":1}"#;
        assert!(IntentDataset::from_json(unknown).is_err());
    }

    #[test]
    fn tenant_exemplars_are_owned_and_may_reuse_global_text() {
        let mut cfg = RoutingConfig::default();
        cfg.exemplars.insert("legal.review".into(), vec!["review this nda clause".into()]);
        let mut t = caliban_config::TenantRouting::default();
        t.exemplars.insert("legal.review".into(), vec!["check this indemnity clause".into(), "hi there, how are you today".into()]);
        cfg.tenants.insert("acme".into(), t);
        let ex = assemble(&cfg).unwrap();
        let builtin = IntentDataset::builtin().intents.values().map(|s| s.utterances.len()).sum::<usize>();
        assert_eq!(ex.len(), builtin + 3);
        let owned: Vec<_> = ex.iter().filter(|e| e.owner.as_deref() == Some("acme")).collect();
        assert_eq!(owned.len(), 2);
        assert!(owned.iter().all(|e| e.intent == "legal.review"));
    }
}
