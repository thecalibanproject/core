//! Loading the routing artifacts `caliban-ml` produces.
//!
//! Contract: `ml/README.md` ("The artifact contract") and `ml/schemas/*.schema.json`.
//! - `intent_head` without ONNX = Stage-1 kNN calibration (`router knn-eval`): `manifest.json`
//!   with `labels`, `calibration` and a `requires` embedder, plus `config.json`
//!   (`type = "knn"`, `k`, `smoothing`, aggregation and similarity).
//! - `router_profile` (`router profile`): `profile.json`, UniRoute per-cluster quality per model.
//!   Core addresses clusters by id and treats the id as the intent.
//!
//! Loader duties from the contract: refuse an unknown `manifest_version`, check every listed file's
//! size and SHA-256 before use (and parse the verified bytes, not a second read), and only accept a
//! calibration whose `requires` embedder is the one in use. The detached `manifest.json.minisig`
//! signature check is not done here (same as the PII NER loader).

use crate::knn::{KnnParams, OosScore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path};

pub const SUPPORTED_MANIFEST_VERSION: u32 = 1;
pub const SUPPORTED_PROFILE_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ArtifactError {
    #[error("{0}: {1}")]
    Io(String, String),
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("{path}: {what} mismatch")]
    Integrity { path: String, what: &'static str },
    #[error("calibration requires embedder {required}, but routing uses {configured}")]
    EmbedderMismatch { required: String, configured: String },
    #[error("unsupported: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Deserialize)]
struct Manifest {
    manifest_version: u32,
    kind: String,
    name: String,
    version: String,
    files: Vec<FileEntry>,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    calibration: Option<Calibration>,
    #[serde(default)]
    requires: Vec<ArtifactRef>,
    #[serde(default)]
    onnx: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct FileEntry {
    path: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ArtifactRef {
    kind: String,
    name: String,
    version: String,
}

/// ml `Calibration`.
#[derive(Debug, Clone, Deserialize)]
struct Calibration {
    #[serde(default = "temperature_method")]
    method: String,
    #[serde(default = "one")]
    temperature: f64,
    #[serde(default)]
    thresholds: BTreeMap<String, f64>,
    default_threshold: Option<f64>,
    margin_threshold: Option<f64>,
    oos_threshold: Option<f64>,
    oos_score: Option<String>,
}

fn temperature_method() -> String {
    "temperature".into()
}
fn one() -> f64 {
    1.0
}

/// `config.json` written by ml's `write_knn_head_artifact`.
#[derive(Debug, Clone, Deserialize)]
struct KnnConfigJson {
    #[serde(rename = "type")]
    kind: String,
    k: usize,
    #[serde(default)]
    smoothing: Option<f64>,
    #[serde(default)]
    aggregation: Option<String>,
    #[serde(default)]
    similarity: Option<String>,
}

/// A verified `manifest.json` and the bytes of every file it lists.
struct Verified {
    manifest: Manifest,
    files: HashMap<String, Vec<u8>>,
}

fn io(path: &Path, e: impl std::fmt::Display) -> ArtifactError {
    ArtifactError::Io(path.display().to_string(), e.to_string())
}

fn safe_rel(p: &str) -> bool {
    !p.is_empty()
        && !p.contains('\\')
        && p != "manifest.json"
        && !p.starts_with("manifest.json.")
        && Path::new(p).components().all(|c| matches!(c, Component::Normal(_)))
        && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

fn verify(dir: &Path, kind: &str) -> Result<Verified, ArtifactError> {
    let mpath = dir.join("manifest.json");
    let raw = std::fs::read(&mpath).map_err(|e| io(&mpath, e))?;
    let manifest: Manifest =
        serde_json::from_slice(&raw).map_err(|e| ArtifactError::Manifest(format!("{}: {e}", mpath.display())))?;
    if manifest.manifest_version != SUPPORTED_MANIFEST_VERSION {
        return Err(ArtifactError::Manifest(format!(
            "unsupported manifest_version {} (this build understands {SUPPORTED_MANIFEST_VERSION})",
            manifest.manifest_version
        )));
    }
    if manifest.kind != kind {
        return Err(ArtifactError::Manifest(format!("artifact kind is {:?}, expected {kind:?}", manifest.kind)));
    }
    let real_dir = dir.canonicalize().map_err(|e| io(dir, e))?;
    let mut files = HashMap::new();
    for f in &manifest.files {
        if !safe_rel(&f.path) {
            return Err(ArtifactError::Manifest(format!("illegal file path {:?}", f.path)));
        }
        let path = dir.join(&f.path);
        let real = path.canonicalize().map_err(|e| io(&path, e))?;
        if !real.starts_with(&real_dir) {
            return Err(ArtifactError::Manifest(format!("{} escapes the artifact directory", f.path)));
        }
        let bytes = std::fs::read(&real).map_err(|e| io(&path, e))?;
        if bytes.len() as u64 != f.size_bytes {
            return Err(ArtifactError::Integrity { path: f.path.clone(), what: "size" });
        }
        if hex::encode(Sha256::digest(&bytes)) != f.sha256.to_ascii_lowercase() {
            return Err(ArtifactError::Integrity { path: f.path.clone(), what: "sha256" });
        }
        files.insert(f.path.clone(), bytes);
    }
    Ok(Verified { manifest, files })
}

/// A verified kNN calibration, ready to overlay on [`KnnParams`].
#[derive(Debug, Clone, PartialEq)]
pub struct KnnCalibration {
    /// `name@version` of this artifact (logged with every decision source).
    pub id: String,
    pub labels: Vec<String>,
    pub k: usize,
    pub smoothing: Option<f64>,
    pub temperature: f64,
    pub thresholds: BTreeMap<String, f64>,
    pub default_threshold: Option<f64>,
    pub margin_threshold: Option<f64>,
    pub oos_threshold: Option<f64>,
    pub oos_score: OosScore,
}

impl KnnCalibration {
    pub fn apply(&self, p: &mut KnnParams) {
        p.k = self.k;
        if let Some(s) = self.smoothing {
            p.smoothing = s;
        }
        p.temperature = self.temperature;
        p.thresholds.clone_from(&self.thresholds);
        if let Some(d) = self.default_threshold {
            p.default_threshold = d;
        }
        p.margin_threshold = self.margin_threshold;
        p.oos_threshold = self.oos_threshold;
        p.oos_score = self.oos_score;
    }
}

/// Loads an ml `intent_head` kNN calibration. `embedder` is the routing config's
/// `embedder_artifact` (`name@version`); a calibration that requires an embedder is refused unless
/// it matches, because thresholds are only meaningful in the vector space they were fitted in.
pub fn load_knn_calibration(dir: &Path, embedder: Option<&str>) -> Result<KnnCalibration, ArtifactError> {
    let v = verify(dir, "intent_head")?;
    let m = &v.manifest;
    if m.onnx.is_some() {
        return Err(ArtifactError::Unsupported(
            "intent_head with an ONNX graph is a Stage-2 classifier, not a kNN calibration".into(),
        ));
    }
    let cal = m.calibration.as_ref().ok_or_else(|| ArtifactError::Manifest("intent_head has no calibration".into()))?;
    if m.labels.is_empty() {
        return Err(ArtifactError::Manifest("intent_head has no labels".into()));
    }
    if let Some(req) = m.requires.iter().find(|r| r.kind == "embedder") {
        let required = format!("{}@{}", req.name, req.version);
        let configured = embedder.unwrap_or("<unset routing.embedder_artifact>");
        if configured != required {
            return Err(ArtifactError::EmbedderMismatch { required, configured: configured.to_owned() });
        }
    }
    let cfg_bytes = v
        .files
        .get("config.json")
        .ok_or_else(|| ArtifactError::Manifest("config.json is not listed in files".into()))?;
    let cfg: KnnConfigJson =
        serde_json::from_slice(cfg_bytes).map_err(|e| ArtifactError::Manifest(format!("config.json: {e}")))?;
    if cfg.kind != "knn" {
        return Err(ArtifactError::Unsupported(format!("config.json type {:?}", cfg.kind)));
    }
    if cfg.aggregation.as_deref().is_some_and(|a| a != "softmax_over_neighbours_sum_by_class") {
        return Err(ArtifactError::Unsupported(format!("aggregation {:?}", cfg.aggregation)));
    }
    if cfg.similarity.as_deref().is_some_and(|s| s != "cosine") {
        return Err(ArtifactError::Unsupported(format!("similarity {:?}", cfg.similarity)));
    }
    if cfg.k == 0 {
        return Err(ArtifactError::Manifest("config.json k must be >= 1".into()));
    }
    let oos_score = match cal.oos_score.as_deref() {
        None | Some("top1_similarity") => OosScore::Top1Similarity,
        Some("max_probability") => OosScore::MaxProbability,
        Some(other) => return Err(ArtifactError::Unsupported(format!("oos_score {other:?} for a kNN head"))),
    };
    let temperature = if cal.method == "none" { 1.0 } else { cal.temperature };
    if !(temperature.is_finite() && temperature > 0.0) {
        return Err(ArtifactError::Manifest("calibration temperature must be > 0".into()));
    }
    Ok(KnnCalibration {
        id: format!("{}@{}", m.name, m.version),
        labels: m.labels.clone(),
        k: cfg.k,
        smoothing: cfg.smoothing,
        temperature,
        thresholds: cal.thresholds.clone(),
        default_threshold: cal.default_threshold,
        margin_threshold: cal.margin_threshold,
        oos_threshold: cal.oos_threshold,
        oos_score,
    })
}

#[derive(Debug, Clone, Deserialize)]
struct ProfileJson {
    profile_version: u32,
    probe_set: String,
    clusters: Vec<ClusterJson>,
    models: Vec<ModelRowJson>,
}

#[derive(Debug, Clone, Deserialize)]
struct ClusterJson {
    id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ModelRowJson {
    model: String,
    quality: Vec<f64>,
    #[serde(default)]
    counts: Vec<u64>,
}

/// UniRoute-style quality table: `quality[model][intent]` in 0..=1.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RouterProfile {
    /// `name@version` of the artifact.
    pub id: String,
    pub probe_set: String,
    quality: HashMap<String, HashMap<String, f64>>,
}

impl RouterProfile {
    pub fn quality(&self, model: &str, intent: &str) -> Option<f64> {
        self.quality.get(model)?.get(intent).copied()
    }

    pub fn models(&self) -> usize {
        self.quality.len()
    }

    /// Builds a profile in memory (tests, or a control-plane-provided table later).
    pub fn from_rows(id: &str, rows: &[(&str, &str, f64)]) -> Self {
        let mut quality: HashMap<String, HashMap<String, f64>> = HashMap::new();
        for (m, c, q) in rows {
            quality.entry((*m).to_owned()).or_default().insert((*c).to_owned(), *q);
        }
        Self { id: id.to_owned(), probe_set: String::new(), quality }
    }
}

/// Loads an ml `router_profile` artifact.
pub fn load_router_profile(dir: &Path) -> Result<RouterProfile, ArtifactError> {
    let v = verify(dir, "router_profile")?;
    let bytes = v
        .files
        .get("profile.json")
        .ok_or_else(|| ArtifactError::Manifest("profile.json is not listed in files".into()))?;
    let p: ProfileJson =
        serde_json::from_slice(bytes).map_err(|e| ArtifactError::Manifest(format!("profile.json: {e}")))?;
    if p.profile_version != SUPPORTED_PROFILE_VERSION {
        return Err(ArtifactError::Unsupported(format!("profile_version {}", p.profile_version)));
    }
    let n = p.clusters.len();
    let mut quality: HashMap<String, HashMap<String, f64>> = HashMap::new();
    for row in &p.models {
        if row.quality.len() != n || (!row.counts.is_empty() && row.counts.len() != n) {
            return Err(ArtifactError::Manifest(format!(
                "profile.json: model {} vectors must have {n} entries",
                row.model
            )));
        }
        if row.quality.iter().any(|q| !q.is_finite() || !(0.0..=1.0).contains(q)) {
            return Err(ArtifactError::Manifest(format!(
                "profile.json: model {} has quality outside 0..=1",
                row.model
            )));
        }
        let per = quality.entry(row.model.clone()).or_default();
        for (c, q) in p.clusters.iter().zip(&row.quality) {
            per.insert(c.id.clone(), *q);
        }
    }
    Ok(RouterProfile { id: format!("{}@{}", v.manifest.name, v.manifest.version), probe_set: p.probe_set, quality })
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use serde_json::{Value, json};

    /// Writes an artifact directory the way ml's `build_manifest` does (every file hashed).
    pub fn write_artifact(dir: &Path, kind: &str, files: &[(&str, &str)], extra: Value) {
        std::fs::create_dir_all(dir).unwrap();
        let mut entries = Vec::new();
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
            entries.push(json!({"path": name, "sha256": hex::encode(Sha256::digest(body.as_bytes())), "size_bytes": body.len(), "role": "config"}));
        }
        let mut m =
            json!({"manifest_version": 1, "kind": kind, "name": "test-artifact", "version": "1.0.0", "files": entries});
        if let (Some(o), Some(e)) = (m.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&m).unwrap()).unwrap();
    }

    pub fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("caliban-route-{name}-{}-{}", std::process::id(), rand_suffix()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{tmp, write_artifact};
    use super::*;
    use serde_json::json;

    const KNN_CONFIG: &str = r#"{"type":"knn","k":7,"smoothing":0.001,"aggregation":"softmax_over_neighbours_sum_by_class","similarity":"cosine"}"#;

    fn calibration_extra() -> serde_json::Value {
        json!({
            "labels": ["chat", "code"],
            "calibration": {"method": "temperature", "temperature": 0.08, "thresholds": {"code": 0.7}, "default_threshold": 0.6,
                            "oos_threshold": 0.31, "oos_score": "top1_similarity"},
            "requires": [{"kind": "embedder", "name": "bge-small", "version": "1.0.0"}]
        })
    }

    #[test]
    fn loads_ml_knn_calibration_and_overlays_params() {
        let d = tmp("cal");
        write_artifact(
            &d,
            "intent_head",
            &[("config.json", KNN_CONFIG), ("labels.json", r#"["chat","code"]"#)],
            calibration_extra(),
        );
        let c = load_knn_calibration(&d, Some("bge-small@1.0.0")).unwrap();
        assert_eq!((c.id.as_str(), c.k, c.temperature), ("test-artifact@1.0.0", 7, 0.08));
        let mut p = KnnParams::default();
        c.apply(&mut p);
        assert_eq!((p.k, p.default_threshold, p.oos_threshold, p.thresholds["code"]), (7, 0.6, Some(0.31), 0.7));
    }

    #[test]
    fn calibration_for_another_embedder_is_refused() {
        let d = tmp("cal-mismatch");
        write_artifact(&d, "intent_head", &[("config.json", KNN_CONFIG)], calibration_extra());
        assert!(matches!(
            load_knn_calibration(&d, Some("e5-small@2.0.0")),
            Err(ArtifactError::EmbedderMismatch { .. })
        ));
        assert!(matches!(load_knn_calibration(&d, None), Err(ArtifactError::EmbedderMismatch { .. })));
    }

    #[test]
    fn tampered_files_and_unknown_versions_are_refused() {
        let d = tmp("cal-tamper");
        write_artifact(&d, "intent_head", &[("config.json", KNN_CONFIG)], calibration_extra());
        std::fs::write(d.join("config.json"), KNN_CONFIG.replace("\"k\":7", "\"k\":9")).unwrap();
        assert!(matches!(load_knn_calibration(&d, Some("bge-small@1.0.0")), Err(ArtifactError::Integrity { .. })));

        let d = tmp("cal-version");
        write_artifact(&d, "intent_head", &[("config.json", KNN_CONFIG)], json!({"manifest_version": 2}));
        assert!(load_knn_calibration(&d, None).unwrap_err().to_string().contains("manifest_version"));

        let d = tmp("cal-onnx");
        let mut extra = calibration_extra();
        extra["onnx"] = json!({"file": "model.onnx"});
        write_artifact(&d, "intent_head", &[("config.json", KNN_CONFIG)], extra);
        assert!(matches!(load_knn_calibration(&d, Some("bge-small@1.0.0")), Err(ArtifactError::Unsupported(_))));
    }

    #[test]
    fn loads_ml_router_profile() {
        let d = tmp("profile");
        let profile = json!({
            "profile_version": 1, "name": "p", "created_at": "2026-10-01T00:00:00Z", "probe_set": "probes@1", "prior_weight": 2.0,
            "embedder": null,
            "clusters": [{"id": "code", "description": "", "n_probes": 10, "centroid": null}, {"id": "chat", "description": "", "n_probes": 5, "centroid": null}],
            "models": [{"model": "local/qwen", "prior": 0.7, "quality": [0.6, 0.8], "raw_mean": [0.6, null], "counts": [10, 0], "n_errors": 0}]
        })
        .to_string();
        write_artifact(&d, "router_profile", &[("profile.json", &profile)], json!({}));
        let p = load_router_profile(&d).unwrap();
        assert_eq!(p.quality("local/qwen", "code"), Some(0.6));
        assert_eq!(p.quality("local/qwen", "chat"), Some(0.8));
        assert_eq!(p.quality("local/qwen", "translate"), None);
        assert_eq!(p.probe_set, "probes@1");

        let bad = profile.replace("[0.6,0.8]", "[0.6]");
        assert_ne!(bad, profile);
        let d = tmp("profile-bad");
        write_artifact(&d, "router_profile", &[("profile.json", &bad)], json!({}));
        assert!(load_router_profile(&d).is_err());
    }
}
