//! Retrieval quality on a small synthetic labelled set: recall@k and nDCG@10 for each stage of the
//! pipeline, navigation on long documents, and the conditional diversity penalty on redundant
//! pools. Run with `--nocapture` to see the table.
//!
//! The corpus is a fictional company's internal documents, written for this eval: paraphrased
//! questions (the dense leg's strength), error codes and product names (the lexical leg's),
//! questions whose answer depends on the heading above the passage (structure-aware chunks),
//! long manuals with near-identical sections of another product (hard negatives, for navigation),
//! and near-duplicate copies of a policy (redundant pools, for diversity). The embedder and
//! reranker are the deterministic stand-ins of `caliban_rag::eval`, not models: the numbers show
//! that each mechanism does what it is meant to on data built to exercise it, not how retrieval
//! performs on real documents with a real embedder.

use caliban_rag::CallScope;
use caliban_rag::eval::{Labels, TestServices, ndcg_at, recall_at};
use caliban_rag::index::{MemoryIndex, VectorIndex};
use caliban_rag::ingest::{Indexer, IngestRequest, prepare};
use caliban_rag::retrieve::{Diversity, Evidence, RetrieveOptions, Retriever, SearchArgs};
use caliban_rag::runner::{IndexOptions, IndexRunner};
use caliban_rag::store::{CollectionRecord, CollectionSettings, MemoryRagStore, RagStore, Trust};
use chrono::Utc;
use std::fmt::Write as _;
use std::sync::Arc;

/// Chunk size for the eval: small enough that a document spans several chunks.
const CHUNK_TOKENS: u32 = 64;

fn docs() -> Vec<(&'static str, String)> {
    let mut d: Vec<(&'static str, String)> = vec![
        ("handbook-leave", "# Leave policy\n\n## Annual leave\n\nEvery employee receives 25 days of paid annual leave per calendar year. Book it in the HR portal at least two weeks ahead.\n\n## Carry over\n\nUp to 5 unused days roll into the next year and expire on 31 March.\n\n## Parental leave\n\nBirth parents receive 20 weeks of paid parental leave; partners receive 8 weeks.\n\n## Sick leave\n\nReport sickness to your manager before 10:00 on the first day. A doctor's note is required after three consecutive days.".into()),
        ("it-handbook", "# IT handbook\n\n## Laptops\n\nA broken laptop is swapped by the service desk within two working days. Bring the charger.\n\n## Passwords\n\nPassphrases need at least 14 characters and change every 12 months.\n\n## VPN\n\nInstall the GlobalConnect client and sign in with your badge number.\n\n## Error codes\n\n### ERR-4471\n\nThe VPN certificate expired: renew it in the self-service portal.\n\n### ERR-5120\n\nThe disk is full: archive mail older than two years.\n\n### ERR-7781\n\nYour account is locked after five failed sign-ins; wait 30 minutes.".into()),
        ("router-guide", "# Router guide\n\n## Model X100\n\n### Reset\n\nHold the button for 10 seconds until the light blinks amber.\n\n### Firmware\n\nFirmware updates install automatically every Sunday at 03:00.\n\n## Model Z900\n\n### Reset\n\nHold the button for 30 seconds until the light turns blue.\n\n### Firmware\n\nFirmware updates must be started by hand from the admin page.".into()),
        ("expenses", "# Expense policy\n\n## Meals\n\nMeals on business trips are reimbursed up to 40 EUR per day.\n\n## Hotels\n\nHotels are covered up to 150 EUR per night, 220 EUR in capital cities.\n\n## Claims\n\nSubmit claims within 30 days with receipts in the expense tool.".into()),
        ("security", "# Security rules\n\n## Visitors\n\nVisitors sign in at reception and wear a red badge all day.\n\n## Clean desk\n\nLock your screen when you leave your desk; papers go in the locked cabinet.\n\n## Phishing\n\nForward suspicious email to the security team with the report button, then delete it.".into()),
        ("remote-work", "# Remote work\n\n## Eligibility\n\nStaff may work from home up to three days per week with manager approval.\n\n## Equipment\n\nThe company pays 300 EUR once for a home office chair and desk.".into()),
        ("travel-insurance", "# Travel insurance\n\nTravel insurance covers medical costs abroad up to 1 million EUR. Call the assistance line printed on your insurance card.".into()),
        ("badge-access", "# Lab access\n\nBadge access to the lab needs the safety course; the course is renewed every year.".into()),
    ];
    // Near-duplicates (not byte-identical: exact copies are dropped before ranking anyway).
    let travel = ["ahead", "in advance", "beforehand", "early"];
    for (v, word) in travel.iter().enumerate() {
        d.push((
            ["travel-v1", "travel-v2", "travel-v3", "travel-v4"][v],
            format!("# Travel booking (revision {})\n\nFlight booking rules for a business trip: book through the travel desk at least 14 days {word}. Economy class applies to flights under 6 hours.", v + 1),
        ));
    }
    let badge = ["the same day", "at once", "immediately", "without delay"];
    for (v, when) in badge.iter().enumerate() {
        d.push((
            ["badge-v1", "badge-v2", "badge-v3", "badge-v4"][v],
            format!("# Badges (copy {})\n\nBadge replacement rules: a lost badge is replaced at reception for 20 EUR; report the loss to security {when}.", v + 1),
        ));
    }
    d.push((
        "manual-fluxgen",
        manual(
            "FluxGen 3000",
            "every 90 days with the blue torque wrench",
            "type K7 fluid every 2000 operating hours",
            "press the green key, then wait for three beeps",
            "the maximum load is 450 kg",
            "the noise level stays below 62 dB",
        ),
    ));
    d.push((
        "manual-aquagen",
        manual(
            "AquaGen 200",
            "every 30 days with the red hex key",
            "type B2 fluid every 500 operating hours",
            "turn the dial to position 4, then press start",
            "the maximum load is 120 kg",
            "the noise level stays below 48 dB",
        ),
    ));
    d
}

/// A long manual: specific sections spread among generic ones.
fn manual(name: &str, calibration: &str, coolant: &str, startup: &str, load: &str, noise: &str) -> String {
    let mut m = format!("# {name} operating manual\n");
    let specific = [
        ("Calibration", format!("Calibrate the flux unit {calibration}.")),
        ("Coolant", format!("Replace the coolant with {coolant}.")),
        ("Start-up", format!("To start the machine, {startup}.")),
        ("Load limits", format!("For this model {load}.")),
        ("Noise", format!("During normal operation {noise}.")),
    ];
    for i in 0..30 {
        if i % 6 == 3 {
            let (h, t) = &specific[i / 6];
            let _ = write!(m, "\n## {h}\n\n{t}\n");
        }
        let _ = write!(
            m,
            "\n## Module {i}\n\nModule {i} needs a visual inspection of its casing and cables during the monthly check. Keep its vents free of dust.\n"
        );
    }
    m
}

struct Q {
    text: &'static str,
    labels: Vec<(&'static str, &'static str, u32)>,
}

fn q(text: &'static str, labels: &[(&'static str, &'static str, u32)]) -> Q {
    Q { text, labels: labels.to_vec() }
}

/// Set A: single-answer questions.
fn general() -> Vec<(&'static str, Q)> {
    vec![
        (
            "paraphrase",
            q("How many vacation days do I get each year?", &[("handbook-leave", "25 days of paid annual leave", 2)]),
        ),
        (
            "paraphrase",
            q("Can unused holiday roll over to next year?", &[("handbook-leave", "Up to 5 unused days", 2)]),
        ),
        ("paraphrase", q("How long is maternity leave?", &[("handbook-leave", "20 weeks of paid parental leave", 2)])),
        (
            "paraphrase",
            q("My notebook is damaged, how fast is it replaced?", &[("it-handbook", "broken laptop is swapped", 2)]),
        ),
        ("paraphrase", q("How long must a passphrase be?", &[("it-handbook", "at least 14 characters", 2)])),
        ("paraphrase", q("Can I telework?", &[("remote-work", "up to three days per week", 2)])),
        ("paraphrase", q("Is a home office chair paid for?", &[("remote-work", "300 EUR once", 2)])),
        (
            "paraphrase",
            q("What is the hotel limit in a capital city?", &[("expenses", "220 EUR in capital cities", 2)]),
        ),
        ("paraphrase", q("By when must I file an expense claim?", &[("expenses", "within 30 days with receipts", 2)])),
        ("paraphrase", q("Where do visitors sign in?", &[("security", "sign in at reception", 2)])),
        ("paraphrase", q("What do I do with a suspicious email?", &[("security", "Forward suspicious email", 2)])),
        ("identifier", q("ERR-4471", &[("it-handbook", "VPN certificate expired", 2)])),
        ("identifier", q("What does error ERR-5120 mean?", &[("it-handbook", "The disk is full", 2)])),
        ("identifier", q("ERR-7781 on sign in", &[("it-handbook", "locked after five failed sign-ins", 2)])),
        ("identifier", q("GlobalConnect", &[("it-handbook", "Install the GlobalConnect client", 2)])),
        ("identifier", q("K7 fluid", &[("manual-fluxgen", "type K7 fluid", 2)])),
        (
            "structure",
            q("How do I reset the Z900 router?", &[("router-guide", "30 seconds until the light turns blue", 2)]),
        ),
        ("structure", q("How do I reset the X100?", &[("router-guide", "10 seconds until the light blinks amber", 2)])),
        ("structure", q("Z900 firmware updates", &[("router-guide", "must be started by hand", 2)])),
        ("structure", q("X100 firmware schedule", &[("router-guide", "every Sunday at 03:00", 2)])),
        ("structure", q("FluxGen 3000 calibration interval", &[("manual-fluxgen", "every 90 days", 2)])),
        ("structure", q("AquaGen 200 maximum load", &[("manual-aquagen", "maximum load is 120 kg", 2)])),
    ]
}

/// Set B: two pieces of evidence inside one long manual, with the other manual's matching
/// sections as hard negatives.
fn long_doc() -> Vec<Q> {
    vec![
        q(
            "FluxGen 3000: how often is the flux unit calibrated and which coolant fluid does it take?",
            &[("manual-fluxgen", "every 90 days", 2), ("manual-fluxgen", "type K7 fluid", 2)],
        ),
        q(
            "FluxGen 3000 start-up steps and maximum load",
            &[("manual-fluxgen", "press the green key", 2), ("manual-fluxgen", "maximum load is 450 kg", 2)],
        ),
        q(
            "FluxGen 3000 noise level and coolant replacement interval",
            &[("manual-fluxgen", "below 62 dB", 2), ("manual-fluxgen", "every 2000 operating hours", 2)],
        ),
        q(
            "AquaGen 200 calibration and start-up",
            &[("manual-aquagen", "every 30 days", 2), ("manual-aquagen", "turn the dial to position 4", 2)],
        ),
    ]
}

/// Set C: questions that need two documents, over a pool with near-duplicate copies of one of
/// them. Each group is the set of documents that count as the same piece of evidence.
fn redundant() -> Vec<(&'static str, Vec<Vec<&'static str>>)> {
    vec![
        (
            "Business trip flight booking rules, and is there travel insurance?",
            vec![vec!["travel-v1", "travel-v2", "travel-v3", "travel-v4"], vec!["travel-insurance"]],
        ),
        (
            "Lost badge replacement rules, and lab access",
            vec![vec!["badge-v1", "badge-v2", "badge-v3", "badge-v4"], vec!["badge-access"]],
        ),
    ]
}

struct Built {
    retriever: Retriever,
    collection: CollectionRecord,
}

async fn build(plain: bool) -> Built {
    let store: Arc<dyn RagStore> = Arc::new(MemoryRagStore::new());
    let index: Arc<dyn VectorIndex> = Arc::new(MemoryIndex::new());
    let services = Arc::new(TestServices::new(256));
    let settings =
        CollectionSettings { chunk_tokens: CHUNK_TOKENS, nav_min_chunks: 12, ..CollectionSettings::default() };
    let c = CollectionRecord {
        id: "ragc_eval".into(),
        tenant_id: "acme".into(),
        name: "kb".into(),
        description: None,
        embedding_model: "emb".into(),
        rerank_model: Some("rr".into()),
        settings,
        created_at: Utc::now(),
        created_by: "eval".into(),
        deleted_at: None,
        purged_at: None,
    };
    let c = store.create_collection(c, None).await.unwrap();
    for (id, content) in docs() {
        let r = IngestRequest { doc_id: id.into(), content, trust: Some(Trust::Trusted), ..IngestRequest::default() };
        store.put_document(prepare(&services.dek("acme"), &c, r, "eval").unwrap(), None).await.unwrap();
    }
    let indexer = Arc::new(Indexer {
        store: Arc::clone(&store),
        index: Arc::clone(&index),
        services: Arc::clone(&services) as _,
        prefix: "eval".into(),
        plain_chunks: plain,
    });
    let runner = IndexRunner::new(indexer, "eval", IndexOptions::default());
    while runner.step().await {}
    let retriever =
        Retriever { store, index, services: services as _, prefix: "eval".into(), options: RetrieveOptions::default() };
    Built { retriever, collection: c }
}

async fn results(b: &Built, query: &str, k: usize, evidence: Evidence) -> Vec<(String, String)> {
    let scope = CallScope { tenant: "acme".into(), ..CallScope::default() };
    let args =
        SearchArgs { query: query.into(), k, max_tokens: 8000, doc_id: None, evidence, now: Utc::now().timestamp() };
    let out = b.retriever.search(&scope, std::slice::from_ref(&b.collection), &args).await.unwrap();
    // `[n] where (doc ..., chunk ...)\ntext` blocks, in the order the context gives them; the
    // citations give the rank order.
    let mut ranked: Vec<(f32, String, String)> = Vec::new();
    let blocks: Vec<&str> = out.context.split("\n\n[").skip(1).collect();
    for (r, block) in out.results.iter().zip(blocks) {
        let text = block.split_once(")\n").map_or("", |(_, t)| t);
        let shown = format!("{} :: {text}", r.heading_path.join(" > "));
        ranked.push((r.score, r.doc_id.clone(), shown));
    }
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0));
    ranked.into_iter().map(|(_, d, s)| (d, s)).collect()
}

fn labels(q: &Q) -> Labels {
    Labels { relevant: q.labels.iter().map(|(d, e, g)| ((*d).to_owned(), (*e).to_owned(), *g)).collect() }
}

#[derive(Default, Clone, Copy)]
struct Scores {
    r5: f64,
    r10: f64,
    ndcg: f64,
    n: usize,
}

impl Scores {
    fn add(&mut self, res: &[(String, String)], l: &Labels) {
        self.r5 += recall_at(res, l, 5);
        self.r10 += recall_at(res, l, 10);
        self.ndcg += ndcg_at(res, l, 10);
        self.n += 1;
    }

    fn mean(self) -> (f64, f64, f64) {
        #[allow(clippy::cast_precision_loss)]
        let n = self.n.max(1) as f64;
        (self.r5 / n, self.r10 / n, self.ndcg / n)
    }
}

async fn score_general(b: &Built, kinds: Option<&str>) -> (f64, f64, f64) {
    let mut s = Scores::default();
    for (kind, q) in general() {
        if kinds.is_some_and(|k| k != kind) {
            continue;
        }
        let res = results(b, q.text, 10, Evidence::Single).await;
        s.add(&res, &labels(&q));
    }
    s.mean()
}

/// Share of the evidence groups found in the first `k` results, averaged over the queries.
fn coverage(res: &[(String, String)], groups: &[Vec<&str>], k: usize) -> f64 {
    let top: Vec<&String> = res.iter().take(k).map(|(d, _)| d).collect();
    let found = groups.iter().filter(|g| g.iter().any(|d| top.iter().any(|t| t == d))).count();
    #[allow(clippy::cast_precision_loss)]
    let c = found as f64 / groups.len() as f64;
    c
}

#[tokio::test]
async fn retrieval_quality_on_the_synthetic_set() {
    let plain = build(true).await;
    let mut structured = build(false).await;
    let mut table =
        String::from("\n| Configuration (set A, 22 questions) | recall@5 | recall@10 | nDCG@10 |\n|---|---|---|---|\n");
    let mut row = |name: &str, (r5, r10, n): (f64, f64, f64)| {
        let _ = writeln!(table, "| {name} | {r5:.3} | {r10:.3} | {n:.3} |");
        (r5, r10, n)
    };

    let dense_only = RetrieveOptions { lexical: false, rerank: false, ..RetrieveOptions::default() };
    let mut plain = plain;
    plain.retriever.options = dense_only;
    let a1 = row("Dense, fixed windows without heading paths", score_general(&plain, None).await);
    structured.retriever.options = dense_only;
    let a2 = row("Dense, structure-aware chunks with heading paths", score_general(&structured, None).await);
    structured.retriever.options = RetrieveOptions { rerank: false, ..RetrieveOptions::default() };
    let a3 = row("Hybrid (dense + BM25, RRF)", score_general(&structured, None).await);
    structured.retriever.options = RetrieveOptions::default();
    let a4 = row("Hybrid + rerank (the default)", score_general(&structured, None).await);

    // Per question type.
    let mut by_kind = String::from(
        "\n| Question type | dense, fixed windows | dense, heading paths | hybrid | hybrid + rerank |\n|---|---|---|---|---|\n",
    );
    for kind in ["paraphrase", "identifier", "structure"] {
        let mut cells = Vec::new();
        for (use_plain, opts) in [
            (true, dense_only),
            (false, dense_only),
            (false, RetrieveOptions { rerank: false, ..RetrieveOptions::default() }),
            (false, RetrieveOptions::default()),
        ] {
            let b = if use_plain { &mut plain } else { &mut structured };
            b.retriever.options = opts;
            let (_, r10, n) = score_general(b, Some(kind)).await;
            cells.push(format!("{r10:.2} / {n:.2}"));
        }
        let _ = writeln!(by_kind, "| {kind} (recall@10 / nDCG@10) | {} |", cells.join(" | "));
    }

    // Set B: navigation on long documents. A shallow pool (2 candidates per leg) stands for a
    // corpus much larger than the candidate pool.
    let mut nav =
        String::from("\n| Set B (long manuals, 2 facts each, evidence multi) | recall@2 | recall@4 |\n|---|---|---|\n");
    let mut b_scores = Vec::new();
    for (name, navigate, rerank, depth) in [
        ("Flat hybrid", false, false, 40),
        ("Hybrid + navigation", true, false, 40),
        ("Flat hybrid + rerank", false, true, 40),
        ("Hybrid + navigation + rerank (the default)", true, true, 40),
        ("Flat hybrid + rerank, shallow pool", false, true, 2),
        ("Hybrid + navigation + rerank, shallow pool", true, true, 2),
    ] {
        structured.retriever.options = RetrieveOptions { navigate, rerank, depth, ..RetrieveOptions::default() };
        let (mut r2, mut r4) = (0.0, 0.0);
        for q in long_doc() {
            let res = results(&structured, q.text, 4, Evidence::Multi).await;
            r2 += recall_at(&res, &labels(&q), 2);
            r4 += recall_at(&res, &labels(&q), 4);
        }
        #[allow(clippy::cast_precision_loss)]
        let (r2, r4) = (r2 / long_doc().len() as f64, r4 / long_doc().len() as f64);
        let _ = writeln!(nav, "| {name} | {r2:.3} | {r4:.3} |");
        b_scores.push((r2, r4));
    }

    // Set C: diversity on redundant pools with room for two passages, and its cost on clean pools
    // (set A asked as multi-evidence questions, so the conditional rule is exercised).
    let mut div = String::from(
        "\n| Diversity | Set C evidence coverage@2 (redundant pools) | Set A nDCG@10 (clean pools) |\n|---|---|---|\n",
    );
    let mut c_scores = Vec::new();
    for (name, d) in
        [("Off", Diversity::Off), ("Conditional (the default)", Diversity::Conditional), ("Always", Diversity::Always)]
    {
        structured.retriever.options = RetrieveOptions { diversity: d, ..RetrieveOptions::default() };
        let mut cov = 0.0;
        for (text, groups) in redundant() {
            let res = results(&structured, text, 2, Evidence::Multi).await;
            cov += coverage(&res, &groups, 2);
        }
        #[allow(clippy::cast_precision_loss)]
        let cov = cov / redundant().len() as f64;
        // Clean pools, asked as multi-evidence questions so the conditional rule is exercised.
        let mut s = Scores::default();
        for (_, q) in general() {
            let res = results(&structured, q.text, 10, Evidence::Multi).await;
            s.add(&res, &labels(&q));
        }
        let (_, _, n) = s.mean();
        let _ = writeln!(div, "| {name} | {cov:.3} | {n:.3} |");
        c_scores.push((cov, n));
    }
    println!("{table}{by_kind}{nav}{div}");

    // Floors: the default pipeline finds what it should, and each stage holds its own.
    assert!(a4.1 >= 0.9, "hybrid + rerank recall@10 {}", a4.1);
    assert!(a3.1 >= a2.1, "BM25 next to dense must not lose recall: {} < {}", a3.1, a2.1);
    assert!(a2.2 >= a1.2, "heading paths must not lose nDCG: {} < {}", a2.2, a1.2);
    assert!(a4.2 >= a3.2, "rerank must not lose nDCG: {} < {}", a4.2, a3.2);
    for (flat, navigated) in [(b_scores[0], b_scores[1]), (b_scores[2], b_scores[3]), (b_scores[4], b_scores[5])] {
        assert!(navigated.1 >= flat.1, "navigation must not lose recall@4: {navigated:?} < {flat:?}");
    }
    let (off, cond, always) = (c_scores[0], c_scores[1], c_scores[2]);
    assert!(cond.0 >= off.0, "the penalty must help on redundant pools: {} < {}", cond.0, off.0);
    assert!(cond.1 >= always.1, "conditional must not cost more than always-on on clean pools");
}
