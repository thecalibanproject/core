//! Integration tests against a real `pii_ner` artifact. Skipped (pass trivially) unless
//! `CALIBAN_PII_NER_DIR` points at an artifact directory, e.g.
//!
//! ```sh
//! CALIBAN_PII_NER_DIR=../../../ml/artifacts/pii_ner/nym-pii-multilingual-small-int8/3.0.0 \
//!   cargo test -p caliban-pii --features ner --test ner_integration -- --nocapture
//! ```
#![cfg(feature = "ner")]

use caliban_ir::ChatRequest;
use caliban_pii::{Detector, EntityType, NerDetector, NerOptions, PiiEngine, Rehydrator, tenant_scope_key};
use caliban_types::PiiMode;
use std::path::PathBuf;
use std::sync::OnceLock;

fn artifact_dir() -> Option<PathBuf> {
    std::env::var_os("CALIBAN_PII_NER_DIR").map(PathBuf::from)
}

fn detector() -> Option<&'static NerDetector> {
    static D: OnceLock<Option<NerDetector>> = OnceLock::new();
    D.get_or_init(|| {
        let dir = artifact_dir()?;
        Some(NerDetector::load(&dir, NerOptions::default()).expect("load artifact"))
    })
    .as_ref()
}

macro_rules! need_model {
    () => {
        match detector() {
            Some(d) => d,
            None => {
                eprintln!("CALIBAN_PII_NER_DIR not set; skipping");
                return;
            }
        }
    };
}

fn found(d: &NerDetector, text: &str) -> Vec<(EntityType, String)> {
    let spans = d.try_detect(text).expect("inference");
    eprintln!("{text}");
    for (label, s, e, score) in d.entities(text).unwrap() {
        eprintln!("    raw {label:<16} {score:.2} {:?}", &text[s..e]);
    }
    for s in &spans {
        eprintln!("  → {:<14} {:?}", s.entity.label(), &text[s.start..s.end]);
    }
    spans.into_iter().map(|s| (s.entity, text[s.start..s.end].to_owned())).collect()
}

fn has(v: &[(EntityType, String)], ty: EntityType, s: &str) -> bool {
    v.iter().any(|(t, x)| *t == ty && x.contains(s))
}

/// The labelled mini-corpus: (text, expected (type, substring)) — used for a rough P/R print.
fn corpus() -> Vec<(&'static str, Vec<(EntityType, &'static str)>)> {
    use EntityType::*;
    vec![
        ("My name is Sarah Johnson and I live in Denver.", vec![(Person, "Sarah Johnson"), (Location, "Denver")]),
        (
            "Please forward the contract to Michael O'Brien at Globex Corporation.",
            vec![(Person, "Michael O'Brien"), (Organization, "Globex")],
        ),
        (
            "Dr. Priya Raman from Mercy General Hospital called about the MRI.",
            vec![(Person, "Priya Raman"), (Organization, "Mercy General")],
        ),
        ("Ship it to 42 Wallaby Way, Sydney by Friday.", vec![(Location, "Wallaby Way"), (Location, "Sydney")]),
        (
            "Tom met Angela Merkel in Berlin last year.",
            vec![(Person, "Tom"), (Person, "Angela Merkel"), (Location, "Berlin")],
        ),
        ("Can you summarize the Q3 report for Initech before the board meeting?", vec![(Organization, "Initech")]),
        ("The weather in Chicago was terrible, said Kevin Park.", vec![(Location, "Chicago"), (Person, "Kevin Park")]),
        ("Explain how photosynthesis works in simple terms.", vec![]),
        ("Write a Python function that reverses a linked list.", vec![]),
        (
            "Jean Dupont travaille chez Renault à Lyon depuis 2019.",
            vec![(Person, "Jean Dupont"), (Organization, "Renault"), (Location, "Lyon")],
        ),
        (
            "Frau Anna Schmidt aus München hat bei der Siemens AG angerufen.",
            vec![(Person, "Anna Schmidt"), (Location, "München"), (Organization, "Siemens")],
        ),
        (
            "María García vive en Sevilla y trabaja para Telefónica.",
            vec![(Person, "María García"), (Location, "Sevilla"), (Organization, "Telefónica")],
        ),
    ]
}

#[test]
fn detects_names_orgs_locations_and_reports_rough_pr() {
    let d = need_model!();
    eprintln!("artifact {}", d.artifact());
    let (mut tp, mut fn_, mut pred) = (0, 0, 0);
    for (text, gold) in corpus() {
        let got = found(d, text);
        pred += got.len();
        for (ty, s) in &gold {
            if has(&got, ty.clone(), s) {
                tp += 1;
            } else {
                fn_ += 1;
                eprintln!("  MISS {:?} {s:?}", ty);
            }
        }
    }
    let recall = tp as f32 / (tp + fn_) as f32;
    let precision = tp as f32 / pred.max(1) as f32;
    eprintln!("type-matched: tp={tp} fn={fn_} predicted={pred} recall≈{recall:.2} precision≈{precision:.2}");

    // Hard assertions only on clear-cut English cases.
    let a = found(d, "My name is Sarah Johnson and I live in Denver.");
    assert!(has(&a, EntityType::Person, "Sarah Johnson"), "{a:?}");
    assert!(has(&a, EntityType::Location, "Denver"), "{a:?}");
    let b = found(d, "Please forward the contract to Michael O'Brien at Globex Corporation.");
    assert!(has(&b, EntityType::Person, "Michael"), "{b:?}");
    assert!(b.iter().any(|(t, s)| *t == EntityType::Organization && s.contains("Globex")), "{b:?}");
    assert!(found(d, "Explain how photosynthesis works in simple terms.").is_empty());
}

#[test]
fn multilingual_and_multibyte_offsets() {
    let d = need_model!();
    if !d.languages().iter().any(|l| l == "de") {
        eprintln!("{} is not multilingual; skipping", d.artifact());
        return;
    }
    let text = "Ünal Çelik wohnt in Köln und arbeitet bei der Deutsche Bahn. 東京の田中太郎さん。";
    let spans = d.try_detect(text).unwrap();
    for s in &spans {
        assert!(text.is_char_boundary(s.start) && text.is_char_boundary(s.end));
        eprintln!("  {:<10} {:?}", s.entity.label(), &text[s.start..s.end]);
    }
    assert!(
        spans.iter().any(|s| s.entity == EntityType::Person && text[s.start..s.end].contains("Çelik")),
        "{spans:?}"
    );
}

#[test]
fn long_text_windows_find_entities_everywhere_once() {
    let d = need_model!();
    // ~3k tokens: names at the start, in the middle and at the end, filler in between.
    let filler = "The quarterly numbers were discussed at length and nothing else was decided. ".repeat(80);
    let text = format!(
        "Sarah Johnson opened the meeting. {filler} Then Kevin Park presented. {filler} Finally Angela Merkel closed it."
    );
    let spans = d.try_detect(&text).unwrap();
    let persons: Vec<&str> =
        spans.iter().filter(|s| s.entity == EntityType::Person).map(|s| &text[s.start..s.end]).collect();
    eprintln!("persons: {persons:?}");
    for name in ["Sarah Johnson", "Kevin Park", "Angela Merkel"] {
        assert_eq!(persons.iter().filter(|p| p.contains(name)).count(), 1, "{name} exactly once in {persons:?}");
    }
}

fn chat(text: &str) -> ChatRequest {
    let body = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": text}]});
    ChatRequest::from_openai_json(body.to_string().as_bytes()).unwrap()
}

#[test]
fn engine_round_trip_with_names() {
    let Some(dir) = artifact_dir() else {
        eprintln!("CALIBAN_PII_NER_DIR not set; skipping");
        return;
    };
    let ner = NerDetector::load(&dir, NerOptions::default()).unwrap();
    let engine = PiiEngine::default().with_detector(ner);
    let original = "Sarah Johnson (sarah.j@acme.com) asked Kevin Park to visit Denver with Sarah Johnson's team.";
    let mut req = chat(original);
    let p = engine.protect(&mut req, PiiMode::Reversible, b"scope").unwrap();
    let sent = req.last_user_text().unwrap();
    eprintln!("sent:     {sent}");
    for (s, o) in p.vault.pairs() {
        eprintln!("  {s:?} <- {o:?}");
    }
    for leaked in ["Sarah Johnson", "Kevin Park", "sarah.j@acme.com", "Denver"] {
        assert!(!sent.contains(leaked), "{leaked} leaked: {sent}");
    }
    // Same person → same surrogate within the scope.
    let first = p.vault.pairs().iter().find(|(_, o)| o == "Sarah Johnson").map(|(s, _)| s.clone()).unwrap();
    assert_eq!(sent.matches(first.as_str()).count(), 2, "{sent}");
    // Simulated model answer that reuses the surrogates.
    let answer = format!("Sure. {first} should brief the team first.");
    let restored = Rehydrator::new(&p.vault).rehydrate(&answer);
    assert_eq!(restored, "Sure. Sarah Johnson should brief the team first.");
    assert_eq!(Rehydrator::new(&p.vault).rehydrate(&sent), original);

    // Tenant scope: identical requests → identical protected text (exact-cache friendly).
    let key = tenant_scope_key(b"server-secret-for-tests-only-32b", "tenant-a");
    let (mut r1, mut r2) = (chat(original), chat(original));
    engine.protect(&mut r1, PiiMode::Reversible, &key).unwrap();
    engine.protect(&mut r2, PiiMode::Reversible, &key).unwrap();
    assert_eq!(r1.last_user_text(), r2.last_user_text());
}
