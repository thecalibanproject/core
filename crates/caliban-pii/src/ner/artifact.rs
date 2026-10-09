//! Loading a `pii_ner` artifact directory produced by `caliban-ml` (`ml/scripts/fetch_pii_ner.py`).
//!
//! Contract (`ml/src/caliban_ml/artifacts/manifest.py`, `ml/schemas/artifact-manifest.schema.json`):
//! `manifest.json` lists every payload file with its size and SHA-256. Before anything is handed
//! to ONNX Runtime or the tokenizer, every listed file is checked; any mismatch refuses the whole
//! artifact. The model and tokenizer are read into memory **once**, hashed, and loaded from those
//! same bytes, so a file swapped after the check cannot be loaded (no TOCTOU window).
//!
//! Not done here (yet): the detached `manifest.json.minisig` signature check, which deployments
//! that require signed artifacts must run before calling this.

use super::NerError;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

pub const MANIFEST_FILENAME: &str = "manifest.json";
pub const SUPPORTED_MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub kind: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub files: Vec<FileEntry>,
    pub onnx: Option<OnnxSpec>,
    pub tokenizer: Option<TokenizerSpec>,
    #[serde(default)]
    pub labels: Vec<String>,
    pub base_model: Option<BaseModelRef>,
    #[serde(default)]
    pub data_card: Option<DataCard>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DataCard {
    /// BCP-47 codes the model was trained for.
    #[serde(default)]
    pub languages: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnnxSpec {
    pub file: String,
    pub opset: u32,
    pub inputs: Vec<TensorSpec>,
    pub outputs: Vec<TensorSpec>,
    #[serde(default)]
    pub quantization: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TensorSpec {
    pub name: String,
    pub dtype: String,
    #[serde(default)]
    pub shape: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenizerSpec {
    pub file: String,
    pub max_length: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BaseModelRef {
    pub id: String,
    pub revision: String,
    pub licence: String,
}

/// A verified artifact: the parsed manifest plus the exact bytes that were hashed.
#[derive(Debug)]
pub struct VerifiedArtifact {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub model_bytes: Vec<u8>,
    pub tokenizer_bytes: Vec<u8>,
}

fn io_err(path: &Path, e: std::io::Error) -> NerError {
    NerError::Io { path: path.to_path_buf(), source: e }
}

fn check_rel_path(p: &str) -> Result<(), NerError> {
    let bad = p.is_empty()
        || p.contains('\\')
        || p == MANIFEST_FILENAME
        || p.starts_with(&format!("{MANIFEST_FILENAME}."))
        || Path::new(p).components().any(|c| !matches!(c, Component::Normal(_)))
        || p.split('/').any(|s| s.is_empty() || s == "." || s == "..");
    if bad {
        return Err(NerError::Manifest(format!("illegal file path in manifest: {p:?}")));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Reads and parses `manifest.json` (no file checks).
pub fn read_manifest(dir: &Path) -> Result<Manifest, NerError> {
    let path = dir.join(MANIFEST_FILENAME);
    let raw = std::fs::read(&path).map_err(|e| io_err(&path, e))?;
    let m: Manifest = serde_json::from_slice(&raw).map_err(|e| NerError::Manifest(format!("{}: {e}", path.display())))?;
    if m.manifest_version != SUPPORTED_MANIFEST_VERSION {
        return Err(NerError::Manifest(format!(
            "unsupported manifest_version {} (this build understands {SUPPORTED_MANIFEST_VERSION})",
            m.manifest_version
        )));
    }
    if m.kind != "pii_ner" {
        return Err(NerError::Manifest(format!("artifact kind is {:?}, expected \"pii_ner\"", m.kind)));
    }
    let onnx = m.onnx.as_ref().ok_or_else(|| NerError::Manifest("pii_ner manifest has no onnx section".into()))?;
    let tok = m.tokenizer.as_ref().ok_or_else(|| NerError::Manifest("pii_ner manifest has no tokenizer section".into()))?;
    if m.labels.is_empty() {
        return Err(NerError::Manifest("pii_ner manifest has no labels".into()));
    }
    for f in &m.files {
        check_rel_path(&f.path)?;
        if f.sha256.len() != 64 || !f.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(NerError::Manifest(format!("{}: sha256 must be 64 lower-case hex chars", f.path)));
        }
    }
    for (what, file) in [("onnx", &onnx.file), ("tokenizer", &tok.file)] {
        if !m.files.iter().any(|f| &f.path == file) {
            return Err(NerError::Manifest(format!("{what} file {file:?} is not listed in files")));
        }
    }
    Ok(m)
}

fn read_checked(dir: &Path, real_dir: &Path, entry: &FileEntry) -> Result<Vec<u8>, NerError> {
    let path = dir.join(&entry.path);
    let real = path.canonicalize().map_err(|e| io_err(&path, e))?;
    if !real.starts_with(real_dir) {
        return Err(NerError::Integrity(format!("{}: resolves outside the artifact directory", entry.path)));
    }
    let bytes = std::fs::read(&real).map_err(|e| io_err(&path, e))?;
    if bytes.len() as u64 != entry.size_bytes {
        return Err(NerError::Integrity(format!("{}: size {} != manifest {}", entry.path, bytes.len(), entry.size_bytes)));
    }
    let got = sha256_hex(&bytes);
    if got != entry.sha256 {
        return Err(NerError::Integrity(format!("{}: sha256 {got} != manifest {}", entry.path, entry.sha256)));
    }
    Ok(bytes)
}

/// Parses the manifest and checks size + SHA-256 of **every** listed file. Returns the model and
/// tokenizer bytes that were verified.
pub fn load_verified(dir: &Path) -> Result<VerifiedArtifact, NerError> {
    let manifest = read_manifest(dir)?;
    let real_dir = dir.canonicalize().map_err(|e| io_err(dir, e))?;
    let model_file = manifest.onnx.as_ref().map(|o| o.file.clone()).unwrap_or_default();
    let tok_file = manifest.tokenizer.as_ref().map(|t| t.file.clone()).unwrap_or_default();
    let (mut model_bytes, mut tokenizer_bytes) = (None, None);
    for entry in &manifest.files {
        let bytes = read_checked(dir, &real_dir, entry)?;
        if entry.path == model_file {
            model_bytes = Some(bytes);
        } else if entry.path == tok_file {
            tokenizer_bytes = Some(bytes);
        }
    }
    let (Some(model_bytes), Some(tokenizer_bytes)) = (model_bytes, tokenizer_bytes) else {
        return Err(NerError::Manifest("model or tokenizer file missing from files".into()));
    };
    Ok(VerifiedArtifact { dir: dir.to_path_buf(), manifest, model_bytes, tokenizer_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("caliban-pii-{tag}-{}-{}", std::process::id(), rand::random::<u64>()));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_artifact(dir: &Path, model: &[u8], tok: &[u8], tamper: Option<&str>) {
        std::fs::write(dir.join("model.onnx"), model).unwrap();
        std::fs::write(dir.join("tokenizer.json"), tok).unwrap();
        let entry = |p: &str, b: &[u8]| {
            serde_json::json!({"path": p, "sha256": sha256_hex(b), "size_bytes": b.len(), "role": "model"})
        };
        let m = serde_json::json!({
            "manifest_version": 1, "kind": "pii_ner", "name": "t", "version": "1.0.0",
            "files": [entry("model.onnx", model), entry("tokenizer.json", tok)],
            "onnx": {"file": "model.onnx", "opset": 17,
                     "inputs": [{"name": "input_ids", "dtype": "int64", "shape": ["b", "s"]}],
                     "outputs": [{"name": "logits", "dtype": "float32", "shape": ["b", "s", 3]}]},
            "tokenizer": {"file": "tokenizer.json", "format": "hf_tokenizers_json", "max_length": 512},
            "labels": ["O", "B-PER", "I-PER"],
            "data_card": {"intended_use": "test"},
            "base_model": {"id": "x/y", "revision": "abc", "licence": "mit"}
        });
        std::fs::write(dir.join(MANIFEST_FILENAME), serde_json::to_vec_pretty(&m).unwrap()).unwrap();
        if let Some(f) = tamper {
            let p = dir.join(f);
            let mut b = std::fs::read(&p).unwrap();
            b[0] ^= 1;
            std::fs::write(p, b).unwrap();
        }
    }

    #[test]
    fn loads_a_valid_artifact() {
        let d = TempDir::new("ok");
        write_artifact(&d.0, b"onnx-bytes", b"{\"tok\":1}", None);
        let a = load_verified(&d.0).unwrap();
        assert_eq!(a.model_bytes, b"onnx-bytes");
        assert_eq!(a.manifest.labels.len(), 3);
    }

    #[test]
    fn refuses_tampered_files() {
        for f in ["model.onnx", "tokenizer.json"] {
            let d = TempDir::new("tamper");
            write_artifact(&d.0, b"onnx-bytes", b"{\"tok\":1}", Some(f));
            let err = load_verified(&d.0).unwrap_err();
            assert!(matches!(err, NerError::Integrity(ref m) if m.contains(f) && m.contains("sha256")), "{err}");
        }
        let d = TempDir::new("size");
        write_artifact(&d.0, b"onnx-bytes", b"{}", None);
        std::fs::write(d.0.join("model.onnx"), b"onnx-bytes-longer").unwrap();
        assert!(matches!(load_verified(&d.0), Err(NerError::Integrity(m)) if m.contains("size")));
    }

    #[test]
    fn refuses_bad_manifests() {
        let d = TempDir::new("bad");
        write_artifact(&d.0, b"m", b"t", None);
        let p = d.0.join(MANIFEST_FILENAME);
        let orig: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        type Mutation = Box<dyn Fn(&mut serde_json::Value)>;
        let cases: Vec<(&str, Mutation)> = vec![
            ("manifest_version", Box::new(|m| m["manifest_version"] = 2.into())),
            ("kind", Box::new(|m| m["kind"] = "embedder".into())),
            ("illegal file path", Box::new(|m| m["files"][0]["path"] = "../model.onnx".into())),
            ("illegal file path", Box::new(|m| m["files"][0]["path"] = "/etc/passwd".into())),
            ("not listed", Box::new(|m| m["onnx"]["file"] = "other.onnx".into())),
            ("labels", Box::new(|m| m["labels"] = serde_json::json!([]))),
            ("sha256", Box::new(|m| m["files"][0]["sha256"] = "ABC".into())),
        ];
        for (needle, f) in cases {
            let mut m = orig.clone();
            f(&mut m);
            std::fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
            let err = load_verified(&d.0).unwrap_err().to_string();
            assert!(err.contains(needle), "expected {needle:?} in {err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_escape() {
        let outside = TempDir::new("outside");
        std::fs::write(outside.0.join("evil"), b"m").unwrap();
        let d = TempDir::new("link");
        write_artifact(&d.0, b"m", b"t", None);
        std::fs::remove_file(d.0.join("model.onnx")).unwrap();
        std::os::unix::fs::symlink(outside.0.join("evil"), d.0.join("model.onnx")).unwrap();
        assert!(matches!(load_verified(&d.0), Err(NerError::Integrity(m)) if m.contains("outside")));
    }
}
