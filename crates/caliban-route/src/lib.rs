//! Routing (docs/research/02-intent-classification-and-routing.md).
//!
//! Staged pipeline for `caliban/auto`; each stage may exit early:
//! 0. rules/policy: a pinned model exits here (subject to trust tier and the tenant's catalogue).
//! 1. embedding kNN over labelled exemplars ([`knn`], [`exemplars`]) within a latency budget.
//!    Abstain (OOS, low confidence, low margin), timeout, embedder failure or a missing index all
//!    fall back to the keyword rules below, never to an error.
//! 2. ONNX multi-head classifier (intent, difficulty, OOS, jailbreak): TODO, artifacts from `ml/`.
//! 3. small-LLM fallback for ambiguous traffic: TODO.
//! 4. model selection within the route ([`policy`]): cheapest model at or above the intent's
//!    quality floor among what the tenant may use, else the tenant's default route.
//!
//! Calibration and quality profiles are ml artifacts ([`artifact`]); exemplar vectors are computed
//! once per vector space (optionally cached on disk) and held in memory behind an `ArcSwap`.

pub mod artifact;
pub mod embed;
pub mod exemplars;
pub mod knn;
pub mod policy;

pub use embed::{EmbedError, HashEmbedder, PromptEmbedder, hash_embed};
pub use policy::{AlwaysHealthy, CandidateTrace, DEFAULT_INTENT, ModelHealth};

use arc_swap::ArcSwapOption;
use artifact::RouterProfile;
use caliban_config::{ModelEntry, ModelKind, SharedProvider, Snapshot, TenantConfig};
use caliban_ir::ChatRequest;
use caliban_types::{ModelId, TrustTier};
use knn::{KnnIndex, KnnOutcome, KnnParams};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const AUTO_MODEL: &str = "caliban/auto";
/// Embed + kNN budget when `[routing] budget_ms` is unset.
pub const DEFAULT_BUDGET_MS: u64 = 25;
/// Only the start of the prompt is embedded: intent shows early, and embedders slow down with length.
pub const MAX_EMBED_CHARS: usize = 2000;
/// A failed index build (embedder down at startup) is retried this often.
const RETRY_AFTER: Duration = Duration::from_secs(30);
/// Exemplars per embedding request while building the index.
const EMBED_BATCH: usize = 64;
const BUILD_BATCH_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RouteError {
    #[error("model '{0}' is not available to this tenant")]
    UnknownModel(String),
    #[error("no route for intent '{0}' and no default route")]
    NoRoute(String),
    #[error("no candidate model satisfies policy (min trust tier {0:?})")]
    PolicyExcludesAll(TrustTier),
}

/// Classifies a request into an intent label.
pub trait IntentClassifier: Send + Sync {
    /// Returns (intent, confidence in 0..=1).
    fn classify(&self, text: &str) -> (String, f32);
}

/// Keyword rules: the fallback whenever Stage-1 kNN is off, abstains or misses its budget.
pub struct KeywordClassifier;

impl IntentClassifier for KeywordClassifier {
    fn classify(&self, text: &str) -> (String, f32) {
        let t = text.to_lowercase();
        let has = |ws: &[&str]| ws.iter().any(|w| t.contains(w));
        if has(&["```", "function", "compile", "stack trace", "refactor", "bug in"]) {
            ("code".into(), 0.6)
        } else if has(&["sql", "query", "revenue", "how many", "average", "per month", "dashboard"]) {
            ("analytics".into(), 0.55)
        } else if has(&["summarize", "summary", "tl;dr"]) {
            ("summarize".into(), 0.6)
        } else if has(&["extract", "parse", "fields from"]) {
            ("extraction".into(), 0.55)
        } else if t.split_whitespace().count() < 12 {
            ("chat".into(), 0.4)
        } else {
            (DEFAULT_INTENT.into(), 0.3)
        }
    }
}

/// Timing and result of the Stage-1 attempt (no prompt content).
#[derive(Debug, Clone, PartialEq)]
pub struct KnnTrace {
    pub outcome: Option<KnnOutcome>,
    /// Embed + classify wall time, microseconds (about the budget on timeout).
    pub elapsed_us: u64,
    /// Calibration artifact in use (`name@version`), if any.
    pub calibration: Option<String>,
}

/// Outcome of routing: an ordered list of models to try (first preferred, rest fallbacks).
#[derive(Debug, Clone, PartialEq)]
pub struct RouteDecision {
    /// Classified intent (`pinned` for a pinned model).
    pub intent: String,
    pub confidence: f32,
    pub candidates: Vec<ModelId>,
    /// Which stage decided the intent: `rules` (pinned), `knn` or `keyword`.
    pub stage: &'static str,
    /// Route table entry the candidates came from.
    pub route: String,
    /// How the model was picked: `pinned`, `route_order`, `quality_floor` or `default_fallback`.
    pub policy: &'static str,
    /// Why Stage 1 did not decide although it was on (`timeout`, `abstain_oos`, ...).
    pub knn_fallback: Option<&'static str>,
    /// The request asked for `caliban/auto`.
    pub auto: bool,
    pub floor: Option<f64>,
    pub knn: Option<KnnTrace>,
    pub trace: Vec<CandidateTrace>,
}

impl RouteDecision {
    /// `x-caliban-intent` value: `<intent>;confidence=<0..1>;stage=<stage>[;knn=<fallback>]`.
    pub fn intent_header(&self) -> String {
        let mut s = format!("{};confidence={:.3};stage={}", self.intent, self.confidence, self.stage);
        if let Some(f) = self.knn_fallback {
            s.push_str(";knn=");
            s.push_str(f);
        }
        s
    }
}

/// Request-level constraints from policy (e.g. sensitive data must stay on sovereign models).
#[derive(Debug, Clone, Copy)]
pub struct Constraints {
    /// Worst tier the request may be sent to. `T0Sovereign` = never leave the boundary.
    pub max_tier: TrustTier,
}

impl Default for Constraints {
    fn default() -> Self {
        Self { max_tier: TrustTier::T3Public }
    }
}

/// The routing embedder: `[routing] embedding_model` and the shared (deployment) provider that
/// serves it. Exemplars are embedded once for the whole deployment, so a tenant's BYOK provider
/// is never used for this.
pub fn routing_embedder(snap: &Snapshot) -> Option<(&ModelEntry, &SharedProvider)> {
    let m = snap.model(snap.config.routing.embedding_model.as_ref()?)?;
    if m.kind != ModelKind::Embedding {
        return None;
    }
    let p = snap.config.providers.iter().find(|p| p.provider.id == m.provider)?;
    Some((m, p))
}

/// Hash of everything that shapes the in-memory routing assets (exemplar set, vector space,
/// artifact paths). Floors, quality overrides, thresholds and prices apply per request and are
/// left out, so tuning them never re-embeds anything.
pub fn assets_fingerprint(snap: &Snapshot) -> String {
    let r = &snap.config.routing;
    let target = routing_embedder(snap).map(|(m, p)| (m, &p.provider.base_url, p.provider.kind));
    let tenants: Vec<_> = r.tenants.iter().map(|(t, x)| (t, &x.exemplars)).collect();
    let v = serde_json::json!({
        "embedder": target,
        "embedding_model": r.embedding_model,
        "embedder_artifact": r.embedder_artifact,
        "query_prefix": r.query_prefix,
        "default_exemplars": r.default_exemplars,
        "exemplar_files": r.exemplar_files,
        "exemplars": r.exemplars,
        "tenants": tenants,
        "calibration_dir": r.calibration_dir,
        "profile_dir": r.profile_dir,
        "exemplar_cache_dir": r.exemplar_cache_dir,
    });
    hex::encode(Sha256::digest(v.to_string().as_bytes()))
}

struct KnnState {
    index: Arc<KnnIndex>,
    /// Defaults overlaid with the calibration artifact; `[routing]` overrides apply per request.
    params: KnnParams,
    space: String,
    prefix: String,
    exemplars_fp: String,
    calibration: Option<String>,
}

#[derive(Default)]
struct RefreshState {
    version: Option<String>,
    fingerprint: Option<String>,
    building: bool,
    failed_at: Option<Instant>,
}

/// What a refresh loaded (logged at startup and on config changes).
#[derive(Debug, Clone, Default)]
pub struct RefreshReport {
    pub exemplars: usize,
    pub intents: usize,
    /// Vectors came from memory or the on-disk cache (nothing was embedded).
    pub from_cache: bool,
    pub embed_ms: u64,
    pub calibration: Option<String>,
    pub profile: Option<String>,
    /// Stage-1 index could not be built; retried later, requests use the keyword rules.
    pub errors: Vec<String>,
    /// Artifacts not applied (defaults or the previous profile stay in use), cache not written.
    pub warnings: Vec<String>,
}

/// On-disk exemplar vectors, keyed by vector space and exemplar set.
#[derive(Serialize, Deserialize)]
struct ExemplarCache {
    format: String,
    space: String,
    fingerprint: String,
    dim: usize,
    vectors: Vec<Vec<f32>>,
}

const CACHE_FORMAT: &str = "caliban-knn-exemplars/1";

pub struct Router {
    classifier: Box<dyn IntentClassifier>,
    knn: ArcSwapOption<KnnState>,
    profile: ArcSwapOption<RouterProfile>,
    refresh: Mutex<RefreshState>,
}

impl Default for Router {
    fn default() -> Self {
        Self::new(Box::new(KeywordClassifier))
    }
}

enum Stage1 {
    Off,
    Accepted(KnnOutcome, KnnTrace),
    Fallback(&'static str, Option<KnnTrace>),
}

fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// `[routing]` overrides on top of the calibrated parameters.
fn effective_params<'a>(base: &'a KnnParams, r: &caliban_config::RoutingConfig) -> Cow<'a, KnnParams> {
    if r.k.is_none() && r.temperature.is_none() && r.abstain_threshold.is_none() && r.margin_threshold.is_none() && r.oos_threshold.is_none() {
        return Cow::Borrowed(base);
    }
    let mut p = base.clone();
    if let Some(k) = r.k {
        p.k = k;
    }
    if let Some(t) = r.temperature {
        p.temperature = t;
    }
    if let Some(a) = r.abstain_threshold {
        p.default_threshold = a;
        p.thresholds.clear();
    }
    if r.margin_threshold.is_some() {
        p.margin_threshold = r.margin_threshold;
    }
    if r.oos_threshold.is_some() {
        p.oos_threshold = r.oos_threshold;
        p.oos_score = knn::OosScore::Top1Similarity;
    }
    Cow::Owned(p)
}

impl Router {
    pub fn new(classifier: Box<dyn IntentClassifier>) -> Self {
        Self { classifier, knn: ArcSwapOption::empty(), profile: ArcSwapOption::empty(), refresh: Mutex::new(RefreshState::default()) }
    }

    /// True when Stage-1 kNN has an index loaded.
    pub fn knn_ready(&self) -> bool {
        self.knn.load().is_some()
    }

    /// Cheap per-request check. Returns true (and marks a build as in flight) when the snapshot
    /// changed the routing assets, or a failed build is due for a retry. The caller then runs
    /// [`Router::refresh`], usually in a background task; requests keep using the previous assets
    /// (or the keyword rules) until it finishes.
    pub fn needs_refresh(&self, snap: &Snapshot) -> bool {
        let mut st = self.refresh.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.building {
            return false;
        }
        let retry = st.failed_at.is_some_and(|t| t.elapsed() >= RETRY_AFTER);
        if st.version.as_deref() == Some(snap.version.as_str()) && !retry {
            return false;
        }
        st.version = Some(snap.version.clone());
        let r = &snap.config.routing;
        if r.embedding_model.is_none() && r.profile_dir.is_none() {
            // Nothing to load: drop any previous assets without a background task.
            self.knn.store(None);
            self.profile.store(None);
            st.fingerprint = None;
            st.failed_at = None;
            return false;
        }
        let fp = assets_fingerprint(snap);
        if !retry && st.fingerprint.as_deref() == Some(fp.as_str()) {
            return false;
        }
        st.building = true;
        true
    }

    /// Loads the router profile and calibration, and builds the exemplar index (embedding the
    /// exemplars unless the same set is already in memory or in the on-disk cache). Failures keep
    /// the previous assets in place (fail-static); a failed index build is retried later.
    pub async fn refresh(&self, snap: &Snapshot, embedder: Option<&dyn PromptEmbedder>) -> RefreshReport {
        let r = &snap.config.routing;
        let mut report = RefreshReport::default();
        match &r.profile_dir {
            None => self.profile.store(None),
            Some(dir) => match artifact::load_router_profile(std::path::Path::new(dir)) {
                Ok(p) => {
                    report.profile = Some(p.id.clone());
                    self.profile.store(Some(Arc::new(p)));
                }
                Err(e) => report.warnings.push(format!("router profile {dir} not loaded: {e}")),
            },
        }
        if r.embedding_model.is_none() {
            self.knn.store(None);
        } else {
            match self.build_knn(snap, embedder, &mut report).await {
                Ok(state) => self.knn.store(Some(Arc::new(state))),
                Err(e) => report.errors.push(e),
            }
        }
        let mut st = self.refresh.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        st.building = false;
        st.fingerprint = Some(assets_fingerprint(snap));
        st.version = Some(snap.version.clone());
        st.failed_at = (!report.errors.is_empty()).then(Instant::now);
        report
    }

    async fn build_knn(&self, snap: &Snapshot, embedder: Option<&dyn PromptEmbedder>, report: &mut RefreshReport) -> Result<KnnState, String> {
        let r = &snap.config.routing;
        let embedder = embedder.ok_or_else(|| {
            format!(
                "routing embedding model {} is not an embedding model reachable through a shared provider",
                r.embedding_model.as_ref().map_or("", ModelId::as_str)
            )
        })?;
        let ex = exemplars::assemble(r).map_err(|e| e.to_string())?;
        let prefix = r.query_prefix.clone().unwrap_or_default();
        let space = embedder.space_id();
        let mut h = Sha256::new();
        h.update(space.as_bytes());
        h.update([0]);
        h.update(prefix.as_bytes());
        for e in &ex {
            h.update([0]);
            h.update(e.owner.as_deref().unwrap_or("").as_bytes());
            h.update([1]);
            h.update(e.intent.as_bytes());
            h.update([1]);
            h.update(e.text.as_bytes());
        }
        let exemplars_fp = hex::encode(h.finalize());
        report.exemplars = ex.len();

        let mut params = KnnParams::default();
        let mut calibration = None;
        if let Some(dir) = &r.calibration_dir {
            match artifact::load_knn_calibration(std::path::Path::new(dir), r.embedder_artifact.as_deref()) {
                Ok(c) => {
                    c.apply(&mut params);
                    calibration = Some(c.id.clone());
                }
                Err(e) => report.warnings.push(format!("kNN calibration {dir} not applied, using defaults: {e}")),
            }
        }
        report.calibration.clone_from(&calibration);

        let current = self.knn.load_full();
        let index = match current.as_ref().filter(|c| c.exemplars_fp == exemplars_fp) {
            Some(c) => {
                report.from_cache = true;
                Arc::clone(&c.index)
            }
            None => {
                let texts: Vec<String> = ex.iter().map(|e| format!("{prefix}{}", e.text)).collect();
                let cache_path = r.exemplar_cache_dir.as_ref().map(|d| std::path::Path::new(d).join(format!("knn-exemplars-{}.json", &exemplars_fp[..16])));
                let cached = cache_path.as_ref().and_then(|p| read_cache(p, &space, &exemplars_fp, texts.len()));
                let vectors = match cached {
                    Some(v) => {
                        report.from_cache = true;
                        v
                    }
                    None => {
                        let started = Instant::now();
                        let mut out = Vec::with_capacity(texts.len());
                        for batch in texts.chunks(EMBED_BATCH) {
                            let v = tokio::time::timeout(BUILD_BATCH_TIMEOUT, embedder.embed(batch))
                                .await
                                .map_err(|_| "embedding exemplars timed out".to_owned())?
                                .map_err(|e| format!("embedding exemplars: {e}"))?;
                            if v.len() != batch.len() {
                                return Err(EmbedError::Count { want: batch.len(), got: v.len() }.to_string());
                            }
                            out.extend(v);
                        }
                        report.embed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                        if let Some(p) = &cache_path {
                            write_cache(p, &space, &exemplars_fp, &out, report);
                        }
                        out
                    }
                };
                let intents: Vec<String> = ex.iter().map(|e| e.intent.clone()).collect();
                let owners: Vec<Option<String>> = ex.iter().map(|e| e.owner.clone()).collect();
                Arc::new(KnnIndex::build(vectors, &intents, &owners).map_err(|e| format!("building the kNN index: {e}"))?)
            }
        };
        report.intents = index.intents().len();
        Ok(KnnState { index, params, space, prefix, exemplars_fp, calibration })
    }

    /// Synchronous routing without Stage 1: pinned model, or keyword rules, then the policy.
    pub fn route(&self, snap: &Snapshot, tenant: &TenantConfig, req: &ChatRequest, constraints: Constraints) -> Result<RouteDecision, RouteError> {
        if let Some(d) = pinned(snap, tenant, req, constraints)? {
            return Ok(d);
        }
        let (intent, confidence) = self.classifier.classify(&req.last_user_text().unwrap_or_default());
        self.select(snap, tenant, req, constraints, Intent { intent, confidence, stage: "keyword", knn_fallback: None, knn: None }, &AlwaysHealthy)
    }

    /// Full staged routing: pinned model, then Stage-1 kNN within the budget (falling back to the
    /// keyword rules), then the quality-floor policy.
    pub async fn route_auto(
        &self,
        snap: &Snapshot,
        tenant: &TenantConfig,
        req: &ChatRequest,
        constraints: Constraints,
        embedder: Option<&dyn PromptEmbedder>,
        health: &dyn ModelHealth,
    ) -> Result<RouteDecision, RouteError> {
        if let Some(d) = pinned(snap, tenant, req, constraints)? {
            return Ok(d);
        }
        let text = req.last_user_text().unwrap_or_default();
        let intent = match self.stage1(snap, tenant, &text, embedder).await {
            Stage1::Accepted(out, trace) => Intent { intent: out.intent, confidence: out.confidence, stage: "knn", knn_fallback: None, knn: Some(trace) },
            Stage1::Fallback(reason, trace) => {
                let (intent, confidence) = self.classifier.classify(&text);
                Intent { intent, confidence, stage: "keyword", knn_fallback: Some(reason), knn: trace }
            }
            Stage1::Off => {
                let (intent, confidence) = self.classifier.classify(&text);
                Intent { intent, confidence, stage: "keyword", knn_fallback: None, knn: None }
            }
        };
        self.select(snap, tenant, req, constraints, intent, health)
    }

    async fn stage1(&self, snap: &Snapshot, tenant: &TenantConfig, text: &str, embedder: Option<&dyn PromptEmbedder>) -> Stage1 {
        let r = &snap.config.routing;
        if !r.knn_enabled_for(&tenant.id) {
            return Stage1::Off;
        }
        let Some(state) = self.knn.load_full() else { return Stage1::Fallback("unavailable", None) };
        let Some(emb) = embedder.filter(|e| e.space_id() == state.space) else { return Stage1::Fallback("unavailable", None) };
        let text = truncate(text.trim(), MAX_EMBED_CHARS);
        if text.is_empty() {
            return Stage1::Fallback("no_text", None);
        }
        let budget = Duration::from_millis(r.budget_ms.unwrap_or(DEFAULT_BUDGET_MS));
        let params = effective_params(&state.params, r);
        let input = [format!("{}{text}", state.prefix)];
        let started = Instant::now();
        let work = async {
            let v = emb.embed(&input).await.map_err(|_| "embed_error")?;
            let q = v.first().filter(|_| v.len() == 1).ok_or("embed_error")?;
            state.index.classify(q, Some(tenant.id.as_str()), &params).map_err(|_| "embed_error")
        };
        let res = tokio::time::timeout(budget, work).await;
        let trace = |outcome| KnnTrace {
            outcome,
            elapsed_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            calibration: state.calibration.clone(),
        };
        match res {
            Err(_) => Stage1::Fallback("timeout", Some(trace(None))),
            Ok(Err(reason)) => Stage1::Fallback(reason, Some(trace(None))),
            Ok(Ok(out)) => match out.abstain {
                Some(a) => Stage1::Fallback(a.as_str(), Some(trace(Some(out)))),
                None => Stage1::Accepted(out.clone(), trace(Some(out))),
            },
        }
    }

    fn select(&self, snap: &Snapshot, tenant: &TenantConfig, req: &ChatRequest, constraints: Constraints, i: Intent, health: &dyn ModelHealth) -> Result<RouteDecision, RouteError> {
        let profile = self.profile.load_full();
        let quality = policy::QualitySource { snap, profile: profile.as_deref() };
        let sel = policy::select(snap, tenant, req, constraints, &i.intent, &quality, health).map_err(|e| match e {
            policy::PolicyError::NoRoute => RouteError::NoRoute(i.intent.clone()),
            policy::PolicyError::NothingEligible => RouteError::PolicyExcludesAll(constraints.max_tier),
        })?;
        let d = RouteDecision {
            intent: i.intent,
            confidence: i.confidence,
            candidates: sel.candidates,
            stage: i.stage,
            route: sel.route,
            policy: sel.policy,
            knn_fallback: i.knn_fallback,
            auto: true,
            floor: sel.floor,
            knn: i.knn,
            trace: sel.trace,
        };
        log_decision(tenant, &d);
        Ok(d)
    }
}

/// The intent stages' result, before model selection.
struct Intent {
    intent: String,
    confidence: f32,
    stage: &'static str,
    knn_fallback: Option<&'static str>,
    knn: Option<KnnTrace>,
}

/// Stage 0: a named model (anything but `caliban/auto`) is used as is, if the tenant may use it.
fn pinned(snap: &Snapshot, tenant: &TenantConfig, req: &ChatRequest, constraints: Constraints) -> Result<Option<RouteDecision>, RouteError> {
    if req.model == AUTO_MODEL {
        return Ok(None);
    }
    let id = ModelId::from(req.model.as_str());
    let entry = snap.models_for(tenant).find(|m| m.id == id).ok_or_else(|| RouteError::UnknownModel(req.model.clone()))?;
    if entry.trust_tier > constraints.max_tier {
        return Err(RouteError::PolicyExcludesAll(constraints.max_tier));
    }
    Ok(Some(RouteDecision {
        intent: "pinned".into(),
        confidence: 1.0,
        candidates: vec![id],
        stage: "rules",
        route: "pinned".into(),
        policy: "pinned",
        knn_fallback: None,
        auto: false,
        floor: None,
        knn: None,
        trace: Vec::new(),
    }))
}

/// Debug-level decision trace. Never logs prompt text.
fn log_decision(tenant: &TenantConfig, d: &RouteDecision) {
    if !tracing::enabled!(target: "caliban_route", tracing::Level::DEBUG) {
        return;
    }
    let knn = d.knn.as_ref();
    let out = knn.and_then(|k| k.outcome.as_ref());
    let candidates: Vec<String> = d
        .trace
        .iter()
        .map(|c| {
            let q = c.quality.map_or_else(|| "-".into(), |q| format!("{q:.3}"));
            let cost = c.est_cost_usd.map_or_else(|| "-".into(), |x| format!("{x:.6}"));
            format!("{}:{}:q={q}:usd={cost}", c.model, c.verdict)
        })
        .collect();
    tracing::debug!(
        target: "caliban_route",
        tenant = %tenant.id,
        intent = %d.intent,
        confidence = d.confidence,
        stage = d.stage,
        route = %d.route,
        policy = d.policy,
        floor = ?d.floor,
        knn_fallback = ?d.knn_fallback,
        knn_us = ?knn.map(|k| k.elapsed_us),
        knn_intent = ?out.map(|o| o.intent.as_str()),
        knn_top1 = ?out.map(|o| o.top1_similarity),
        knn_margin = ?out.map(|o| o.margin),
        calibration = ?knn.and_then(|k| k.calibration.as_deref()),
        chosen = ?d.candidates.first().map(ModelId::as_str),
        candidates = ?candidates,
        "route decision"
    );
}

fn read_cache(path: &std::path::Path, space: &str, fp: &str, n: usize) -> Option<Vec<Vec<f32>>> {
    let raw = std::fs::read(path).ok()?;
    let c: ExemplarCache = serde_json::from_slice(&raw).ok()?;
    let ok = c.format == CACHE_FORMAT && c.space == space && c.fingerprint == fp && c.vectors.len() == n && c.vectors.iter().all(|v| v.len() == c.dim);
    ok.then_some(c.vectors)
}

fn write_cache(path: &std::path::Path, space: &str, fp: &str, vectors: &[Vec<f32>], report: &mut RefreshReport) {
    let c = ExemplarCache {
        format: CACHE_FORMAT.into(),
        space: space.into(),
        fingerprint: fp.into(),
        dim: vectors.first().map_or(0, Vec::len),
        vectors: vectors.to_vec(),
    };
    let res = (|| -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&c).map_err(std::io::Error::other)?)?;
        std::fs::rename(tmp, path)
    })();
    if let Err(e) = res {
        report.warnings.push(format!("exemplar cache {} not written: {e}", path.display()));
    }
}

#[cfg(test)]
mod tests;
