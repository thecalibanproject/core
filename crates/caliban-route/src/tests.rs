use super::*;
use crate::artifact::testutil::{tmp, write_artifact};
use async_trait::async_trait;
use caliban_config::Config;
use std::sync::atomic::{AtomicUsize, Ordering};

fn example() -> Snapshot {
    let cfg = Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
    Snapshot::new(cfg, "t")
}

fn req(model: &str, text: &str) -> ChatRequest {
    let body = serde_json::json!({"model": model, "messages": [{"role": "user", "content": text}]});
    ChatRequest::from_openai_json(body.to_string().as_bytes()).unwrap()
}

#[test]
fn auto_routes_by_intent_with_fallbacks() {
    let s = example();
    let t = s.tenant(&"acme".into()).unwrap();
    let d = Router::default().route(&s, t, &req(AUTO_MODEL, "hi there"), Constraints::default()).unwrap();
    assert_eq!(d.intent, "chat");
    assert_eq!(d.candidates[0].as_str(), "local/qwen3-8b");
    assert_eq!((d.stage, d.policy), ("keyword", "route_order"));
}

#[test]
fn sovereign_constraint_drops_external_models() {
    let s = example();
    let t = s.tenant(&"acme".into()).unwrap();
    let long = "please think carefully about the following long request that has many words in it ok";
    let d = Router::default()
        .route(&s, t, &req(AUTO_MODEL, long), Constraints { max_tier: TrustTier::T0Sovereign })
        .unwrap();
    assert_eq!(d.intent, "default");
    assert_eq!(d.candidates, vec![ModelId::from("local/gpt-oss-20b")]);
}

#[test]
fn pinned_unknown_model_is_rejected() {
    let s = example();
    let t = s.tenant(&"acme".into()).unwrap();
    let e = Router::default().route(&s, t, &req("nope/model", "x"), Constraints::default()).unwrap_err();
    assert_eq!(e, RouteError::UnknownModel("nope/model".into()));
}

/// A deployment with a shared embedding server, a free local model and two priced hosted ones.
fn staged(routing: &str) -> Snapshot {
    let toml = format!(
        r#"
[routing]
embedding_model = "emb/hash"
{routing}

[[providers]]
id = "embedder"
kind = "openai_compatible"
base_url = "http://embedder/v1"
trust_tier = "t0_sovereign"

[[models]]
id = "emb/hash"
provider = "embedder"
upstream_model = "hash"
kind = "embedding"
trust_tier = "t0_sovereign"

[[models]]
id = "local/small"
provider = "local"
upstream_model = "s"
trust_tier = "t0_sovereign"
price_in_per_mtok = 0.0
price_out_per_mtok = 0.0

[[models]]
id = "ext/mid"
provider = "hosted"
upstream_model = "m"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 4.0

[[models]]
id = "ext/big"
provider = "hosted"
upstream_model = "b"
trust_tier = "t2_contracted"
price_in_per_mtok = 5.0
price_out_per_mtok = 20.0

[[tenants]]
id = "acme"
name = "Acme"
  [[tenants.providers]]
  id = "local"
  kind = "openai_compatible"
  base_url = "http://local/v1"
  trust_tier = "t0_sovereign"
  [[tenants.providers]]
  id = "hosted"
  kind = "openai"
  base_url = "https://hosted/v1"
  trust_tier = "t2_contracted"
  api_key = {{ env = "X" }}
  [[tenants.routes]]
  intent = "default"
  models = ["local/small", "ext/big"]
  [[tenants.routes]]
  intent = "translate"
  models = ["ext/big", "ext/mid", "local/small"]
"#
    );
    Snapshot::new(Config::from_toml_str(&toml).unwrap(), "v1")
}

/// Counts calls; optionally fails or runs in another vector space.
struct Probe {
    inner: HashEmbedder,
    calls: AtomicUsize,
    fail: bool,
    space: Option<String>,
}

impl Probe {
    fn new() -> Self {
        Self { inner: HashEmbedder::default(), calls: AtomicUsize::new(0), fail: false, space: None }
    }
}

#[async_trait]
impl PromptEmbedder for Probe {
    fn space_id(&self) -> String {
        self.space.clone().unwrap_or_else(|| self.inner.space_id())
    }
    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(EmbedError::Upstream("boom".into()));
        }
        self.inner.embed(texts).await
    }
}

async fn ready(s: &Snapshot, e: &dyn PromptEmbedder) -> Router {
    let r = Router::default();
    assert!(r.needs_refresh(s));
    let rep = r.refresh(s, Some(e)).await;
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert!(r.knn_ready());
    r
}

const TRANSLATE: &str = "please translate this paragraph into french for me";

#[tokio::test]
async fn knn_decides_the_intent_and_the_header_says_so() {
    let s = staged("");
    let e = HashEmbedder::default();
    let r = ready(&s, &e).await;
    let t = s.tenant(&"acme".into()).unwrap();
    let d = r
        .route_auto(&s, t, &req(AUTO_MODEL, TRANSLATE), Constraints::default(), Some(&e), &AlwaysHealthy)
        .await
        .unwrap();
    assert_eq!((d.intent.as_str(), d.stage, d.knn_fallback), ("translate", "knn", None));
    assert!(d.confidence > 0.5);
    assert!(d.intent_header().starts_with("translate;confidence=0."));
    assert!(d.intent_header().ends_with(";stage=knn"));
    // No floor for translate: the tenant's route order.
    assert_eq!((d.policy, d.candidates[0].as_str()), ("route_order", "ext/big"));
    assert!(d.knn.as_ref().unwrap().elapsed_us < 25_000);
}

#[tokio::test]
async fn quality_floor_picks_the_cheapest_qualifying_model() {
    let s = staged(
        "[routing.floors]\ntranslate = 0.8\n[routing.quality.\"ext/mid\"]\ntranslate = 0.85\n[routing.quality.\"ext/big\"]\ntranslate = 0.95\n[routing.quality.\"local/small\"]\ntranslate = 0.5\n",
    );
    let e = HashEmbedder::default();
    let r = ready(&s, &e).await;
    let t = s.tenant(&"acme".into()).unwrap();
    let d = r
        .route_auto(&s, t, &req(AUTO_MODEL, TRANSLATE), Constraints::default(), Some(&e), &AlwaysHealthy)
        .await
        .unwrap();
    assert_eq!((d.policy, d.floor), ("quality_floor", Some(0.8)));
    assert_eq!(d.candidates, vec![ModelId::from("ext/mid"), ModelId::from("ext/big")]);
}

#[tokio::test]
async fn timeout_falls_back_to_the_rules_within_budget() {
    let s = staged("budget_ms = 5");
    let fast = HashEmbedder::default();
    let r = ready(&s, &fast).await;
    let slow = HashEmbedder::default().with_delay(Duration::from_millis(200));
    let t = s.tenant(&"acme".into()).unwrap();
    let started = Instant::now();
    let d = r
        .route_auto(
            &s,
            t,
            &req(AUTO_MODEL, "summarize this email thread for me"),
            Constraints::default(),
            Some(&slow),
            &AlwaysHealthy,
        )
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(150), "{:?}", started.elapsed());
    assert_eq!((d.stage, d.knn_fallback, d.intent.as_str()), ("keyword", Some("timeout"), "summarize"));
    assert!(d.intent_header().ends_with(";stage=keyword;knn=timeout"));
}

#[tokio::test]
async fn embedder_errors_and_foreign_spaces_fall_back() {
    let s = staged("");
    let r = ready(&s, &HashEmbedder::default()).await;
    let t = s.tenant(&"acme".into()).unwrap();
    let failing = Probe { fail: true, ..Probe::new() };
    let d = r
        .route_auto(&s, t, &req(AUTO_MODEL, TRANSLATE), Constraints::default(), Some(&failing), &AlwaysHealthy)
        .await
        .unwrap();
    assert_eq!((d.stage, d.knn_fallback), ("keyword", Some("embed_error")));
    let other = Probe { space: Some("other-model".into()), ..Probe::new() };
    let d = r
        .route_auto(&s, t, &req(AUTO_MODEL, TRANSLATE), Constraints::default(), Some(&other), &AlwaysHealthy)
        .await
        .unwrap();
    assert_eq!(d.knn_fallback, Some("unavailable"));
    assert_eq!(other.calls.load(Ordering::SeqCst), 0);
    let d =
        r.route_auto(&s, t, &req(AUTO_MODEL, TRANSLATE), Constraints::default(), None, &AlwaysHealthy).await.unwrap();
    assert_eq!(d.knn_fallback, Some("unavailable"));
}

#[tokio::test]
async fn abstain_uses_the_rules_choice() {
    // An OOS gate no prompt can pass.
    let s = staged("oos_threshold = 0.999");
    let e = HashEmbedder::default();
    let r = ready(&s, &e).await;
    let t = s.tenant(&"acme".into()).unwrap();
    let d =
        r.route_auto(&s, t, &req(AUTO_MODEL, "hi"), Constraints::default(), Some(&e), &AlwaysHealthy).await.unwrap();
    assert_eq!((d.stage, d.knn_fallback, d.intent.as_str()), ("keyword", Some("abstain_oos"), "chat"));
    let out = d.knn.unwrap().outcome.unwrap();
    assert!(out.top1_similarity < 0.999);
}

#[tokio::test]
async fn knn_can_be_turned_off_per_tenant() {
    let s = staged("[routing.tenants.acme]\nknn = false\n");
    let e = HashEmbedder::default();
    let r = ready(&s, &e).await;
    let t = s.tenant(&"acme".into()).unwrap();
    let d = r
        .route_auto(&s, t, &req(AUTO_MODEL, TRANSLATE), Constraints::default(), Some(&e), &AlwaysHealthy)
        .await
        .unwrap();
    assert_eq!((d.stage, d.knn_fallback), ("keyword", None));
}

#[tokio::test]
async fn tenant_exemplars_add_custom_intents() {
    let s = staged(
        "[routing.tenants.acme.exemplars]\n\"legal.review\" = [\"review this nda clause for risky indemnity terms\", \"check the liability cap in this msa\"]\n",
    );
    let e = HashEmbedder::default();
    let r = ready(&s, &e).await;
    let t = s.tenant(&"acme".into()).unwrap();
    let d = r
        .route_auto(
            &s,
            t,
            &req(AUTO_MODEL, "review this nda clause for indemnity terms"),
            Constraints::default(),
            Some(&e),
            &AlwaysHealthy,
        )
        .await
        .unwrap();
    assert_eq!(d.intent, "legal.review");
    // No route for the custom intent: the default route.
    assert_eq!(d.route, "default");
}

#[tokio::test]
async fn refresh_only_when_routing_assets_change() {
    let e = Probe::new();
    let s1 = staged("");
    let r = ready(&s1, &e).await;
    let calls = e.calls.load(Ordering::SeqCst);
    assert!(calls >= 1);
    assert!(!r.needs_refresh(&s1));
    // A new snapshot that only changes floors and thresholds: no rebuild.
    let s2 = Snapshot::new(staged("abstain_threshold = 0.9\n[routing.floors]\ncode = 0.7\n").config.clone(), "v2");
    assert!(!r.needs_refresh(&s2));
    // New exemplars: rebuild, and the unchanged built-in vectors are not reused (new set, new hash).
    let s3 = Snapshot::new(staged("[routing.exemplars]\nchat = [\"yo what is up\"]\n").config.clone(), "v3");
    assert!(r.needs_refresh(&s3));
    assert!(!r.needs_refresh(&s3), "a build is in flight");
    let rep = r.refresh(&s3, Some(&e)).await;
    assert!(rep.errors.is_empty() && !rep.from_cache);
    assert!(e.calls.load(Ordering::SeqCst) > calls);
    // Same set again under a new version: reused from memory.
    let s4 = Snapshot::new(s3.config.clone(), "v4");
    let before = e.calls.load(Ordering::SeqCst);
    let rep = r.refresh(&s4, Some(&e)).await;
    assert!(rep.from_cache);
    assert_eq!(e.calls.load(Ordering::SeqCst), before);
}

#[tokio::test]
async fn exemplar_vectors_are_cached_on_disk_by_space() {
    let dir = tmp("cache");
    let s = staged(&format!("exemplar_cache_dir = {:?}", dir.display().to_string()));
    let first = Probe::new();
    let r1 = ready(&s, &first).await;
    assert!(first.calls.load(Ordering::SeqCst) > 0);
    drop(r1);
    let second = Probe::new();
    let r2 = Router::default();
    let rep = r2.refresh(&s, Some(&second)).await;
    assert!(rep.from_cache && rep.errors.is_empty() && rep.warnings.is_empty(), "{rep:?}");
    assert_eq!(second.calls.load(Ordering::SeqCst), 0);
    // Another vector space does not reuse the file.
    let third = Probe { space: Some("other".into()), ..Probe::new() };
    let rep = Router::default().refresh(&s, Some(&third)).await;
    assert!(!rep.from_cache);
    assert!(third.calls.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn missing_embedder_is_retried_and_rules_serve_meanwhile() {
    let s = staged("");
    let r = Router::default();
    assert!(r.needs_refresh(&s));
    let rep = r.refresh(&s, None).await;
    assert_eq!(rep.errors.len(), 1);
    assert!(!r.knn_ready());
    let t = s.tenant(&"acme".into()).unwrap();
    let d =
        r.route_auto(&s, t, &req(AUTO_MODEL, TRANSLATE), Constraints::default(), None, &AlwaysHealthy).await.unwrap();
    assert_eq!((d.stage, d.knn_fallback), ("keyword", Some("unavailable")));
    // Not retried immediately.
    assert!(!r.needs_refresh(&s));
}

#[tokio::test]
async fn calibration_and_profile_artifacts_are_applied() {
    let cal = tmp("router-cal");
    write_artifact(
        &cal,
        "intent_head",
        &[(
            "config.json",
            r#"{"type":"knn","k":3,"smoothing":0.001,"aggregation":"softmax_over_neighbours_sum_by_class","similarity":"cosine"}"#,
        )],
        serde_json::json!({
            "labels": ["translate"],
            "calibration": {"method": "temperature", "temperature": 0.07, "default_threshold": 0.4, "oos_threshold": 0.05, "oos_score": "top1_similarity"},
            "requires": [{"kind": "embedder", "name": "hash", "version": "1.0.0"}]
        }),
    );
    let prof = tmp("router-profile");
    let profile = serde_json::json!({
        "profile_version": 1, "name": "p", "probe_set": "probes@1", "prior_weight": 2.0,
        "clusters": [{"id": "translate", "n_probes": 4}],
        "models": [
            {"model": "local/small", "prior": 0.9, "quality": [0.9], "raw_mean": [0.9], "counts": [4]},
            {"model": "ext/mid", "prior": 0.9, "quality": [0.92], "raw_mean": [0.92], "counts": [4]}
        ]
    });
    write_artifact(&prof, "router_profile", &[("profile.json", &profile.to_string())], serde_json::json!({}));
    let s = staged(&format!(
        "embedder_artifact = \"hash@1.0.0\"\ncalibration_dir = {:?}\nprofile_dir = {:?}\n[routing.floors]\ntranslate = 0.85\n",
        cal.display().to_string(),
        prof.display().to_string()
    ));
    let e = HashEmbedder::default();
    let r = Router::default();
    assert!(r.needs_refresh(&s));
    let rep = r.refresh(&s, Some(&e)).await;
    assert_eq!(
        (rep.calibration.as_deref(), rep.profile.as_deref()),
        (Some("test-artifact@1.0.0"), Some("test-artifact@1.0.0"))
    );
    assert!(rep.warnings.is_empty(), "{:?}", rep.warnings);
    let t = s.tenant(&"acme".into()).unwrap();
    let d = r
        .route_auto(&s, t, &req(AUTO_MODEL, TRANSLATE), Constraints::default(), Some(&e), &AlwaysHealthy)
        .await
        .unwrap();
    assert_eq!(d.knn.as_ref().unwrap().calibration.as_deref(), Some("test-artifact@1.0.0"));
    // Profile: local/small (0.9, free) meets the 0.85 floor and is cheapest.
    assert_eq!((d.policy, d.candidates[0].as_str()), ("quality_floor", "local/small"));

    // The same calibration under another embedder is not applied (defaults, with a warning).
    let s = staged(&format!("embedder_artifact = \"e5@2.0.0\"\ncalibration_dir = {:?}\n", cal.display().to_string()));
    let rep = Router::default().refresh(&s, Some(&e)).await;
    assert!(rep.calibration.is_none() && rep.warnings.len() == 1 && rep.errors.is_empty());
}

/// Added latency of the Stage-1 step with an in-process fake embedder. Run with
/// `cargo test --release -p caliban-route knn_latency -- --nocapture` for the numbers.
#[tokio::test]
async fn knn_latency_report() {
    let s = staged("");
    let e = HashEmbedder::default();
    let r = ready(&s, &e).await;
    let t = s.tenant(&"acme".into()).unwrap();
    let prompts = [
        "write a python function to parse dates",
        TRANSLATE,
        "top customers by revenue last quarter",
        "summarize the notes below",
        "hello",
    ];
    let n = 500;
    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        let rq = req(AUTO_MODEL, prompts[i % prompts.len()]);
        let started = Instant::now();
        let d = r.route_auto(&s, t, &rq, Constraints::default(), Some(&e), &AlwaysHealthy).await.unwrap();
        samples.push(started.elapsed());
        assert!(d.knn.is_some());
    }
    samples.sort();
    let p50 = samples[n / 2];
    let p99 = samples[n * 99 / 100];
    println!("route_auto with HashEmbedder, {} exemplars x 384 dims: p50 {p50:?}, p99 {p99:?}", knn_len(&r));

    // Brute force at a larger scale: 5,000 exemplars x 1,024 dims.
    let dim = 1024;
    let rows: Vec<Vec<f32>> =
        (0..5000).map(|i| hash_embed(&format!("exemplar number {i} about topic {}", i % 37), dim)).collect();
    let intents: Vec<String> = (0..5000).map(|i| format!("intent{}", i % 12)).collect();
    let idx = KnnIndex::build(rows, &intents, &vec![None; 5000]).unwrap();
    let q = hash_embed("exemplar about topic 5", dim);
    let started = Instant::now();
    for _ in 0..50 {
        let _ = idx.classify(&q, None, &KnnParams::default()).unwrap();
    }
    let per = started.elapsed() / 50;
    println!("brute-force kNN, 5000 x 1024: {per:?} per query");
    assert!(p99 < Duration::from_millis(25), "p99 {p99:?}");
}

fn knn_len(r: &Router) -> usize {
    r.knn.load().as_ref().map_or(0, |k| k.index.len())
}
