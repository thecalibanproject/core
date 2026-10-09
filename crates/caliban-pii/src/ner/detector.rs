//! `NerDetector`: HF `tokenizers` + an ONNX Runtime session pool (CPU) behind [`Detector`].

use super::artifact::{self, Manifest};
use super::decode::{self, Aggregation, LabelSet, Stitcher};
use super::{NerError, default_label_map, join_adjacent};
use crate::{DetectError, Detector, EntityType, Span};
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;
use ort::value::Tensor;
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use tokenizers::Tokenizer;
use tokenizers::models::ModelWrapper;

/// Runtime options for [`NerDetector::load`].
#[derive(Debug, Clone)]
pub struct NerOptions {
    /// ONNX Runtime intra-op threads per session (default: [`NerOptions::default_intra_threads`]).
    pub intra_threads: usize,
    /// Let idle intra-op threads spin-wait for the next run (ONNX Runtime's default). Off by
    /// default: spinning shaves a little latency off back-to-back runs but burns whole cores that
    /// the gateway's async workers need.
    pub intra_spinning: bool,
    /// Independent sessions in the pool; concurrent requests run in parallel up to this many
    /// (default: [`NerOptions::default_sessions`]). Each session holds its own copy of the weights
    /// (about 100 MB for the int8 models).
    pub sessions: usize,
    /// Window length in tokens, special tokens included (default and maximum: the manifest's
    /// `tokenizer.max_length`, 512 for the shipped models).
    pub max_tokens: Option<usize>,
    /// Tokens shared by consecutive windows over long texts (default 128).
    pub overlap: usize,
    /// Windows per ONNX run (default 4).
    pub batch_size: usize,
    /// Minimum entity score (mean tag probability) for labels without an explicit threshold.
    pub default_threshold: f32,
    /// Per-label thresholds, keyed by the model's base label (`"PER"`, `"GIVEN_NAME"`), any case.
    pub thresholds: HashMap<String, f32>,
    /// Per-label mapping overrides on top of [`default_label_map`]; `None` ignores the label.
    pub label_map: HashMap<String, Option<EntityType>>,
    /// Sub-word grouping. `None` = auto: [`Aggregation::First`] for WordPiece tokenizers (BERT
    /// NER models label the first sub-word), [`Aggregation::Token`] otherwise.
    pub aggregation: Option<Aggregation>,
}

fn available_cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

impl NerOptions {
    /// Default session count for `cores` CPUs: `min(cores / 2, 4)`, at least 1. Half the cores at
    /// most, so inference never takes the whole machine from the async runtime; 4 at most,
    /// because each session holds its own copy of the weights.
    pub fn default_sessions(cores: usize) -> usize {
        (cores / 2).clamp(1, 4)
    }

    /// Default intra-op threads per session for `cores` CPUs and `sessions` sessions: the half of
    /// the cores given to inference, shared between the sessions, between 1 and 4. With every
    /// session busy, inference then uses at most about half of the cores.
    pub fn default_intra_threads(cores: usize, sessions: usize) -> usize {
        (cores / (2 * sessions.max(1))).clamp(1, 4)
    }
}

impl Default for NerOptions {
    fn default() -> Self {
        let cores = available_cores();
        let sessions = Self::default_sessions(cores);
        Self {
            intra_threads: Self::default_intra_threads(cores, sessions),
            intra_spinning: false,
            sessions,
            max_tokens: None,
            overlap: 128,
            batch_size: 4,
            default_threshold: 0.5,
            thresholds: HashMap::new(),
            label_map: HashMap::new(),
            aggregation: None,
        }
    }
}

/// L1 PII detector backed by a token-classification ONNX model. `Send + Sync`; inference runs
/// on a pool of sessions guarded by mutexes (ONNX Runtime's `run` needs `&mut Session` here).
pub struct NerDetector {
    name: String,
    version: String,
    languages: Vec<String>,
    tokenizer: Tokenizer,
    sessions: Vec<Mutex<Session>>,
    next: AtomicUsize,
    failures: AtomicU64,
    labels: LabelSet,
    /// Per entity base (index into `labels.bases()`): mapped type and threshold.
    targets: Vec<(Option<EntityType>, f32)>,
    input_ids: String,
    attention_mask: String,
    token_type_ids: Option<String>,
    logits: String,
    max_tokens: usize,
    overlap: usize,
    batch_size: usize,
    pad_id: i64,
    aggregation: Aggregation,
}

impl std::fmt::Debug for NerDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NerDetector")
            .field("artifact", &format!("{}@{}", self.name, self.version))
            .field("sessions", &self.sessions.len())
            .field("max_tokens", &self.max_tokens)
            .field("aggregation", &self.aggregation)
            .finish_non_exhaustive()
    }
}

fn rt(e: impl std::fmt::Display) -> NerError {
    NerError::Runtime(e.to_string())
}

impl NerDetector {
    /// Loads a `pii_ner` artifact directory (`manifest.json` + files). Every file listed in the
    /// manifest is size- and SHA-256-checked first; any mismatch refuses the artifact. ONNX
    /// inputs/outputs are bound by the names the manifest declares and cross-checked against the
    /// graph.
    pub fn load(dir: &Path, opts: NerOptions) -> Result<Self, NerError> {
        let art = artifact::load_verified(dir)?;
        let m = &art.manifest;
        let tok_spec = m.tokenizer.as_ref().expect("checked by read_manifest");

        let mut tokenizer =
            Tokenizer::from_bytes(&art.tokenizer_bytes).map_err(|e| NerError::Tokenizer(e.to_string()))?;
        tokenizer.with_truncation(None).map_err(|e| NerError::Tokenizer(e.to_string()))?;
        tokenizer.with_padding(None);
        let pad_id = tokenizer
            .get_padding()
            .map(|p| i64::from(p.pad_id))
            .or_else(|| ["<pad>", "[PAD]", "<PAD>"].iter().find_map(|t| tokenizer.token_to_id(t)).map(i64::from));
        let aggregation = opts.aggregation.unwrap_or(match tokenizer.get_model() {
            ModelWrapper::WordPiece(_) => Aggregation::First,
            _ => Aggregation::Token,
        });

        let (input_ids, attention_mask, token_type_ids, logits) = bind_tensors(m)?;

        let n_sessions = opts.sessions.max(1);
        let mut sessions = Vec::with_capacity(n_sessions);
        for _ in 0..n_sessions {
            let session = Session::builder()
                .map_err(rt)?
                .with_optimization_level(GraphOptimizationLevel::Level3)
                .map_err(rt)?
                .with_intra_threads(opts.intra_threads.max(1))
                .map_err(rt)?
                .with_inter_threads(1)
                .map_err(rt)?
                .with_intra_op_spinning(opts.intra_spinning)
                .map_err(rt)?
                .commit_from_memory(&art.model_bytes)
                .map_err(rt)?;
            check_graph(&session, m, &input_ids, &attention_mask, token_type_ids.as_deref(), &logits)?;
            sessions.push(Mutex::new(session));
        }

        let labels = LabelSet::parse(&m.labels);
        let label_map: HashMap<String, Option<EntityType>> =
            opts.label_map.iter().map(|(k, v)| (k.to_ascii_uppercase(), v.clone())).collect();
        let thresholds: HashMap<String, f32> =
            opts.thresholds.iter().map(|(k, v)| (k.to_ascii_uppercase(), *v)).collect();
        let targets = labels
            .bases()
            .iter()
            .map(|b| {
                let key = b.to_ascii_uppercase();
                let ty = label_map.get(&key).cloned().unwrap_or_else(|| default_label_map(b));
                (ty, thresholds.get(&key).copied().unwrap_or(opts.default_threshold))
            })
            .collect();

        let max_tokens = opts.max_tokens.unwrap_or(tok_spec.max_length).min(tok_spec.max_length).max(8);
        Ok(Self {
            name: m.name.clone(),
            version: m.version.clone(),
            languages: m.data_card.as_ref().map(|d| d.languages.clone()).unwrap_or_default(),
            tokenizer,
            sessions,
            next: AtomicUsize::new(0),
            failures: AtomicU64::new(0),
            labels,
            targets,
            input_ids,
            attention_mask,
            token_type_ids,
            logits,
            max_tokens,
            overlap: opts.overlap,
            batch_size: opts.batch_size.max(1),
            pad_id: pad_id.unwrap_or(0),
            aggregation,
        })
    }

    /// `name@version` of the loaded artifact.
    pub fn artifact(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }

    /// Languages the model was trained for (manifest `data_card.languages`, BCP-47).
    pub fn languages(&self) -> &[String] {
        &self.languages
    }

    /// Model label bases, in model order.
    pub fn label_bases(&self) -> &[String] {
        self.labels.bases()
    }

    /// Number of sessions in the pool (requests that can run inference at the same time).
    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Inference failures so far (each one also failed its request via `try_detect`).
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Detected entities with their model label and score, before label mapping. For eval and
    /// debugging; [`Detector::try_detect`] is the request-path API.
    pub fn entities(&self, text: &str) -> Result<Vec<(String, usize, usize, f32)>, NerError> {
        Ok(self
            .raw(text)?
            .into_iter()
            .map(|e| (self.labels.bases()[e.base].clone(), e.start, e.end, e.score))
            .collect())
    }

    fn raw(&self, text: &str) -> Result<Vec<decode::RawEntity>, NerError> {
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        let enc = self.tokenizer.encode(text, true).map_err(|e| NerError::Tokenizer(e.to_string()))?;
        let ids = enc.get_ids();
        let special = enc.get_special_tokens_mask();
        // The post-processor's leading/trailing special tokens ([CLS]…[SEP], <bos>…<eos>) are
        // re-attached to every window; everything between them is the body.
        let lead = special.iter().take_while(|&&s| s == 1).count();
        let trail = special[lead..].iter().rev().take_while(|&&s| s == 1).count();
        let body = lead..ids.len() - trail;
        if body.is_empty() {
            return Ok(Vec::new());
        }
        let prefix: Vec<i64> = ids[..lead].iter().map(|&x| i64::from(x)).collect();
        let suffix: Vec<i64> = ids[body.end..].iter().map(|&x| i64::from(x)).collect();
        let body_ids: Vec<i64> = ids[body.clone()].iter().map(|&x| i64::from(x)).collect();
        let offsets = &enc.get_offsets()[body.clone()];
        let word_ids = &enc.get_word_ids()[body];

        let n = body_ids.len();
        let classes = self.labels.num_classes();
        let window = self.max_tokens.saturating_sub(prefix.len() + suffix.len()).max(1);
        let windows = decode::plan_windows(n, window, self.overlap);
        let mut stitcher = Stitcher::new(n, classes);
        // Batch only equal-length windows: padding the short tail window to full length would
        // cost a full window of compute for nothing.
        let mut batches: Vec<&[std::ops::Range<usize>]> = Vec::new();
        let mut i = 0;
        while i < windows.len() {
            let mut j = i + 1;
            while j < windows.len() && j - i < self.batch_size && windows[j].len() == windows[i].len() {
                j += 1;
            }
            batches.push(&windows[i..j]);
            i = j;
        }
        for batch in batches {
            let seq = prefix.len() + suffix.len() + batch.iter().map(|w| w.len()).max().unwrap_or(0);
            let mut input = Vec::with_capacity(batch.len() * seq);
            let mut mask = Vec::with_capacity(batch.len() * seq);
            for w in batch {
                let real = prefix.len() + w.len() + suffix.len();
                input.extend_from_slice(&prefix);
                input.extend_from_slice(&body_ids[w.clone()]);
                input.extend_from_slice(&suffix);
                input.extend(std::iter::repeat_n(self.pad_id, seq - real));
                mask.extend(std::iter::repeat_n(1i64, real));
                mask.extend(std::iter::repeat_n(0i64, seq - real));
            }
            let logits = self.run(batch.len(), seq, input, mask)?;
            if logits.len() != batch.len() * seq * classes {
                return Err(NerError::Model(format!(
                    "logits has {} values, expected {}×{}×{classes}",
                    logits.len(),
                    batch.len(),
                    seq
                )));
            }
            for (b, w) in batch.iter().enumerate() {
                let start = (b * seq + prefix.len()) * classes;
                let mut probs = logits[start..start + w.len() * classes].to_vec();
                probs.chunks_mut(classes).for_each(decode::softmax);
                stitcher.add(w.clone(), &probs);
            }
        }
        let probs = stitcher.finish();
        let offsets: Vec<(usize, usize)> = offsets.to_vec();
        let units = decode::units(&probs, classes, &offsets, word_ids, self.aggregation);
        Ok(decode::finalize(text, decode::decode(&units, &self.labels)))
    }

    fn run(&self, batch: usize, seq: usize, input: Vec<i64>, mask: Vec<i64>) -> Result<Vec<f32>, NerError> {
        let shape = [batch, seq];
        let mut inputs: Vec<(Cow<'_, str>, ort::session::SessionInputValue<'_>)> = Vec::with_capacity(3);
        inputs.push((Cow::Borrowed(self.input_ids.as_str()), Tensor::from_array((shape, input)).map_err(rt)?.into()));
        inputs
            .push((Cow::Borrowed(self.attention_mask.as_str()), Tensor::from_array((shape, mask)).map_err(rt)?.into()));
        if let Some(tt) = &self.token_type_ids {
            inputs.push((
                Cow::Borrowed(tt.as_str()),
                Tensor::from_array((shape, vec![0i64; batch * seq])).map_err(rt)?.into(),
            ));
        }
        self.with_session(|s| {
            let out = s.run(inputs).map_err(rt)?;
            let value =
                out.get(&self.logits).ok_or_else(|| NerError::Model(format!("no output named {:?}", self.logits)))?;
            let (_, data) = value.try_extract_tensor::<f32>().map_err(rt)?;
            Ok(data.to_vec())
        })
    }

    /// Runs `f` on a free session, or waits for one (round-robin start, then blocking).
    fn with_session<R>(&self, f: impl FnOnce(&mut Session) -> R) -> R {
        let n = self.sessions.len();
        let first = self.next.fetch_add(1, Ordering::Relaxed) % n;
        for k in 0..n {
            if let Ok(mut s) = self.sessions[(first + k) % n].try_lock() {
                return f(&mut s);
            }
        }
        let mut s = self.sessions[first].lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut s)
    }

    fn spans(&self, text: &str) -> Result<Vec<Span>, NerError> {
        let spans = self
            .raw(text)?
            .into_iter()
            .filter_map(|e| {
                let (ty, threshold) = &self.targets[e.base];
                let ty = ty.as_ref()?;
                (e.score >= *threshold).then(|| Span { start: e.start, end: e.end, entity: ty.clone() })
            })
            .collect();
        Ok(join_adjacent(text, spans))
    }
}

impl Detector for NerDetector {
    /// Best effort: an inference failure yields no spans (counted in [`NerDetector::failures`]).
    /// [`crate::PiiEngine::protect`] uses [`Detector::try_detect`] and fails closed instead.
    fn detect(&self, text: &str) -> Vec<Span> {
        self.try_detect(text).unwrap_or_default()
    }

    fn try_detect(&self, text: &str) -> Result<Vec<Span>, DetectError> {
        self.spans(text).map_err(|e| {
            self.failures.fetch_add(1, Ordering::Relaxed);
            DetectError { detector: "ner", message: e.to_string() }
        })
    }

    fn is_heavy(&self) -> bool {
        true
    }
}

/// Picks the tensor names from the manifest (bound by name, never by position).
fn bind_tensors(m: &Manifest) -> Result<(String, String, Option<String>, String), NerError> {
    let onnx = m.onnx.as_ref().expect("checked");
    let find = |n: &str| onnx.inputs.iter().find(|t| t.name == n).map(|t| t.name.clone());
    let input_ids =
        find("input_ids").ok_or_else(|| NerError::Model("manifest declares no `input_ids` input".into()))?;
    let attention_mask =
        find("attention_mask").ok_or_else(|| NerError::Model("manifest declares no `attention_mask` input".into()))?;
    let token_type_ids = find("token_type_ids");
    if let Some(t) = onnx
        .inputs
        .iter()
        .find(|t| ![&input_ids, &attention_mask].contains(&&t.name) && Some(&t.name) != token_type_ids.as_ref())
    {
        return Err(NerError::Model(format!("unsupported model input {:?}", t.name)));
    }
    if let Some(t) = onnx.inputs.iter().find(|t| t.dtype != "int64") {
        return Err(NerError::Model(format!("input {:?} is {}, only int64 is supported", t.name, t.dtype)));
    }
    let n_labels = m.labels.len();
    let logits = onnx
        .outputs
        .iter()
        .find(|t| t.name == "logits")
        .or_else(|| {
            onnx.outputs.iter().find(|t| t.shape.last().and_then(serde_json::Value::as_u64) == Some(n_labels as u64))
        })
        .ok_or_else(|| NerError::Model("no `logits` output in the manifest".into()))?;
    if logits.dtype != "float32" {
        return Err(NerError::Model(format!("logits are {}, expected float32", logits.dtype)));
    }
    if let Some(d) = logits.shape.last().and_then(serde_json::Value::as_u64)
        && d != n_labels as u64
    {
        return Err(NerError::Model(format!("logits last dim {d} != {n_labels} labels")));
    }
    Ok((input_ids, attention_mask, token_type_ids, logits.name.clone()))
}

/// The graph must expose exactly the tensors the manifest declares.
fn check_graph(
    s: &Session,
    m: &Manifest,
    ids: &str,
    mask: &str,
    tt: Option<&str>,
    logits: &str,
) -> Result<(), NerError> {
    let graph_inputs: Vec<&str> = s.inputs().iter().map(|o| o.name()).collect();
    let declared: Vec<&str> = m.onnx.as_ref().expect("checked").inputs.iter().map(|t| t.name.as_str()).collect();
    for want in [Some(ids), Some(mask), tt].into_iter().flatten() {
        if !graph_inputs.contains(&want) {
            return Err(NerError::Model(format!("graph has no input {want:?} (graph inputs: {graph_inputs:?})")));
        }
    }
    if let Some(extra) = graph_inputs.iter().find(|g| !declared.contains(g)) {
        return Err(NerError::Model(format!("graph input {extra:?} is not declared in the manifest")));
    }
    if !s.outputs().iter().any(|o| o.name() == logits) {
        return Err(NerError::Model(format!("graph has no output {logits:?}")));
    }
    Ok(())
}
