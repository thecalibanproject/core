//! T2 semantic cache on the request path: the glue between the pipeline and
//! `caliban_cache::semantic` (key, store, threshold policy).
//!
//! Order: T1 exact → **T2 semantic** → upstream. T2 applies when all of these hold:
//! - `[cache.semantic] enabled` and the tenant's `semantic_cache = "on"`;
//! - the request does not say `caliban.cache = "off"` or `"exact"`, and is not `zdr`;
//! - the same PII rules as T1: no PII, or tenant-scoped (deterministic) surrogates or masking;
//!   and the destination sees the protected form or the request has no PII, so stored entries are
//!   always in surrogate form;
//! - no tools, no tool calls or tool results anywhere in the conversation, `n` unset or 1, and the
//!   last message is a text-only user message;
//! - `temperature <= [cache.semantic] max_temperature` (unset counts as sampling), unless the
//!   request opts in with `caliban.cache = "semantic"`.
//!
//! Streaming and non-streaming requests both qualify; a hit on a streaming request is replayed as
//! a stream (one content delta, then the finish chunk), through the same rehydration and dialect
//! encoders as a live stream.
//!
//! Failure policy: embedding plus vector search must finish within `lookup_budget_ms` (default
//! 50 ms) or the request goes on as a miss. The embedding keeps running in the background, and
//! when it lands it is reused to insert the fresh answer. Store or embedder errors are logged at
//! debug level and never fail a request.

use crate::pipeline::{Outcome, finish, json_response, render_cached};
use crate::{Gateway, quirks, stream, telemetry};
use axum::body::Bytes;
use axum::response::Response;
use caliban_cache::semantic::{
    KeyParts, Lookup, Match, NewEntry, ResponseShape, SemanticCache, SemanticKey, ThresholdPolicy, VerifyKind,
};
use caliban_config::{ModelEntry, SemanticCacheConfig, Snapshot, TenantConfig};
use caliban_ir::anthropic;
use caliban_ir::{ChatRequest, Usage};
use caliban_meter::quota::Settlement;
use caliban_pii::{Rehydrator, Vault};
use caliban_types::{CacheMode, EmbedError, Embedder, ModelId, PiiMode, TenantId, cosine};
use futures::StreamExt;
use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{Instrument, Span};

/// Request facts the pipeline already has.
pub(crate) struct Inputs<'a> {
    pub req: &'a ChatRequest,
    /// The body that goes upstream (protected when the destination is external).
    pub upstream_body: &'a Value,
    pub model: &'a ModelEntry,
    pub is_native: bool,
    pub pii_mode: PiiMode,
    /// The protected request's vault (its surrogates are part of the key).
    pub vault: &'a Vault,
    /// Surrogates are deterministic for this tenant (or there is no PII / masking), and what is
    /// stored will be in surrogate form.
    pub pii_ok: bool,
}

enum Emb {
    /// Not requested yet (the prompt): nothing is embedded for requests that T1 answers.
    Idle(String),
    Pending(JoinHandle<Result<Vec<Vec<f32>>, EmbedError>>),
    Ready(Arc<Vec<f32>>),
    Failed,
}

/// T2 state of one request: prepared before the upstream call, completed after it.
pub(crate) struct Semantic {
    cache: Arc<SemanticCache>,
    embedder: Arc<dyn Embedder>,
    policy: ThresholdPolicy,
    cfg: SemanticCacheConfig,
    tenant: TenantId,
    embed_model: ModelId,
    model_id: String,
    think: bool,
    key: SemanticKey,
    emb: Emb,
    /// Set when the lookup asked for verification against this entry.
    probe: Option<Match>,
}

pub(crate) fn policy(c: &SemanticCacheConfig) -> ThresholdPolicy {
    ThresholdPolicy {
        threshold: c.threshold,
        min_threshold: c.min_threshold,
        grey_band: c.grey_band,
        max_error_rate: c.max_error_rate,
        verify_rate: c.verify_rate,
    }
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Text of a message's content if it is text only (string, or only `text` parts/blocks).
fn text_only(content: &Value) -> Option<String> {
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(parts) => {
            let mut out = Vec::with_capacity(parts.len());
            for p in parts {
                if p.get("type").and_then(Value::as_str) != Some("text") {
                    return None;
                }
                out.push(p.get("text").and_then(Value::as_str)?);
            }
            Some(out.join("\n"))
        }
        _ => None,
    }
}

/// Tool use anywhere in an OpenAI-shaped or Anthropic conversation.
fn has_tool_traffic(body: &Value) -> bool {
    let tools = body.get("tools").and_then(Value::as_array).is_some_and(|a| !a.is_empty());
    let functions = body.get("functions").is_some();
    let in_messages = body.get("messages").and_then(Value::as_array).is_some_and(|ms| {
        ms.iter().any(|m| {
            m.get("role").and_then(Value::as_str) == Some("tool")
                || m.get("tool_calls").is_some_and(|t| !t.is_null())
                || m.get("content").and_then(Value::as_array).is_some_and(|parts| {
                    parts.iter().any(|p| {
                        matches!(
                            p.get("type").and_then(Value::as_str),
                            Some("tool_use" | "tool_result" | "server_tool_use")
                        )
                    })
                })
        })
    });
    tools || functions || in_messages
}

/// JSON bytes with every object's keys sorted. Hashes must not depend on key order: with
/// serde_json's `preserve_order` (enabled by some dependencies under feature unification) maps keep
/// insertion order, and `Map::remove` reorders the remaining keys.
pub(crate) fn canonical_json(v: &Value) -> Vec<u8> {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(o) => {
                let mut keys: Vec<&String> = o.keys().collect();
                keys.sort_unstable();
                Value::Object(keys.into_iter().map(|k| (k.clone(), sorted(&o[k]))).collect())
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sorted(v)).unwrap_or_default()
}

/// Hash of the upstream body with the last message's content removed and transport-only fields
/// dropped: everything that must match exactly for two requests to share an answer.
fn context_hash(body: &Value, model_id: &str) -> blake3::Hash {
    let mut b = body.clone();
    if let Some(o) = b.as_object_mut() {
        for k in ["stream", "stream_options", "user", "cache_salt", "metadata", "caliban"] {
            o.remove(k);
        }
        o.insert("model".into(), Value::String(model_id.to_owned()));
        if let Some(last) = o
            .get_mut("messages")
            .and_then(Value::as_array_mut)
            .and_then(|m| m.last_mut())
            .and_then(Value::as_object_mut)
        {
            last.insert("content".into(), Value::Null);
        }
    }
    blake3::hash(&canonical_json(&b))
}

/// Decides whether T2 applies to this request and computes its key.
pub(crate) fn prepare(gw: &Gateway, snap: &Snapshot, tenant: &TenantConfig, i: Inputs<'_>) -> Option<Semantic> {
    let cache = gw.semantic.as_ref()?;
    if !snap.semantic_cache_for(tenant) || !i.pii_ok {
        return None;
    }
    let cfg = &snap.config.cache.semantic;
    let embed_model = cfg.embedding_model.clone()?;
    let ext = i.req.ext();
    if matches!(ext.cache, Some(CacheMode::Off | CacheMode::Exact)) || ext.zdr {
        return None;
    }
    let temperature = i.req.extra.get("temperature").and_then(Value::as_f64);
    if ext.cache != Some(CacheMode::Semantic) && !temperature.is_some_and(|t| t <= cfg.max_temperature) {
        return None;
    }
    if i.req.has_tools()
        || has_tool_traffic(i.upstream_body)
        || i.req.extra.get("n").and_then(Value::as_u64).is_some_and(|n| n > 1)
    {
        return None;
    }
    let last = i.upstream_body.get("messages").and_then(Value::as_array).and_then(|m| m.last())?;
    if last.get("role").and_then(Value::as_str) != Some("user") {
        return None;
    }
    let prompt = text_only(last.get("content")?)?;
    if prompt.trim().is_empty() {
        return None;
    }
    let shape = if i.is_native { ResponseShape::Anthropic } else { ResponseShape::Openai };
    let surrogates: Vec<&str> = i.vault.pairs().iter().map(|(s, _)| s.as_str()).collect();
    let key = SemanticKey::new(&KeyParts {
        tenant: &tenant.id,
        model: i.model.id.as_str(),
        shape,
        context_hash: context_hash(i.upstream_body, i.model.id.as_str()),
        prompt: &prompt,
        surrogates: &surrogates,
        pii_mode: i.pii_mode,
        embed_prefix: cfg.query_prefix.as_deref().unwrap_or_default(),
    });
    // The text that is embedded: the prompt, after the optional instruction.
    let embed_text = match cfg.query_prefix.as_deref() {
        Some(p) if !p.is_empty() => format!("{p}{prompt}"),
        _ => prompt,
    };
    Some(Semantic {
        cache: Arc::clone(cache),
        embedder: Arc::clone(&gw.embedder),
        policy: policy(cfg),
        cfg: cfg.clone(),
        tenant: tenant.id.clone(),
        embed_model,
        model_id: i.model.id.to_string(),
        think: !i.is_native && i.model.capabilities.inline_think_tags,
        key,
        emb: Emb::Idle(embed_text),
        probe: None,
    })
}

impl Semantic {
    /// The prompt vector, waiting at most until `deadline` (`None`: wait for the embed timeout).
    /// The embedding runs as its own task, so a call that gives up early leaves it running and a
    /// later call picks up the result.
    async fn vector(&mut self, deadline: Option<tokio::time::Instant>) -> Result<Arc<Vec<f32>>, &'static str> {
        if let Emb::Idle(prompt) = &mut self.emb {
            let (embedder, t, m, prompt) =
                (Arc::clone(&self.embedder), self.tenant.clone(), self.embed_model.clone(), std::mem::take(prompt));
            self.emb =
                Emb::Pending(tokio::spawn(async move { embedder.embed(&t, &m, &[prompt]).await }.in_current_span()));
        }
        let res = match &mut self.emb {
            Emb::Idle(_) => return Err("embed_error"),
            Emb::Ready(v) => return Ok(Arc::clone(v)),
            Emb::Failed => return Err("embed_error"),
            Emb::Pending(h) => match deadline {
                Some(d) => match tokio::time::timeout_at(d, h).await {
                    Ok(r) => r,
                    Err(_) => return Err("timeout"),
                },
                None => match tokio::time::timeout(Duration::from_millis(self.cfg.embed_timeout_ms), h).await {
                    Ok(r) => r,
                    Err(_) => return Err("timeout"),
                },
            },
        };
        match res {
            Ok(Ok(mut vs)) if vs.len() == 1 && !vs[0].is_empty() => {
                let v = Arc::new(vs.swap_remove(0));
                self.emb = Emb::Ready(Arc::clone(&v));
                Ok(v)
            }
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "semantic cache: embedding failed");
                self.emb = Emb::Failed;
                Err("embed_error")
            }
            _ => {
                self.emb = Emb::Failed;
                Err("embed_error")
            }
        }
    }

    /// Embeds and searches within the lookup budget. Returns an entry to serve; a match that
    /// needs verification is remembered for [`Semantic::complete`].
    pub(crate) async fn lookup(&mut self) -> Option<Match> {
        let span = telemetry::child("semantic");
        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(self.cfg.lookup_budget_ms);
        let outcome: Result<Lookup, &'static str> = async {
            let v = self.vector(Some(deadline)).await?;
            let draw: f32 = rand::random();
            match tokio::time::timeout_at(
                deadline,
                self.cache.lookup(&self.key, self.embed_model.as_str(), &v, &self.policy, draw, now_secs()),
            )
            .await
            {
                Ok(Ok(l)) => Ok(l),
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "semantic cache: lookup failed");
                    Err("store_error")
                }
                Err(_) => Err("timeout"),
            }
        }
        .instrument(span.clone())
        .await;
        span.record("caliban.cache.lookup_ms", u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
        tracing::debug!(
            outcome = ?outcome.as_ref().map(|l| match l {
                Lookup::Hit(m) => ("hit", m.similarity),
                Lookup::Verify(m) => (if m.verify == Some(VerifyKind::Explore) { "verify_explore" } else { "verify_grey" }, m.similarity),
                Lookup::Miss => ("miss", 0.0),
            }),
            ms = started.elapsed().as_secs_f64() * 1000.0,
            "semantic cache lookup"
        );
        match outcome {
            Ok(Lookup::Hit(m)) => {
                span.record("caliban.cache", "hit");
                span.record("caliban.cache.similarity", f64::from(m.similarity));
                let (cache, policy, hit) = (Arc::clone(&self.cache), self.policy, m.clone());
                tokio::spawn(async move {
                    if let Err(e) = cache.record_hit(&hit, &policy).await {
                        tracing::debug!(error = %e, "semantic cache: hit count not recorded");
                    }
                });
                Some(m)
            }
            Ok(Lookup::Verify(m)) => {
                span.record(
                    "caliban.cache",
                    if m.verify == Some(VerifyKind::Explore) { "verify_explore" } else { "verify_grey" },
                );
                span.record("caliban.cache.similarity", f64::from(m.similarity));
                self.probe = Some(m);
                None
            }
            Ok(Lookup::Miss) => {
                span.record("caliban.cache", "miss");
                None
            }
            Err(reason) => {
                span.record("caliban.cache", reason);
                None
            }
        }
    }

    /// After a fresh answer: verify it against the probed entry (if any) and cache it. Runs in the
    /// background; never delays the response.
    pub(crate) fn complete(self, body: Bytes, usage: Usage) {
        tokio::spawn(self.complete_inner(body, usage).in_current_span());
    }

    async fn complete_inner(mut self, body: Bytes, usage: Usage) {
        let Some(answer) = answer_text(&body, self.key.shape) else { return };
        let vector = match self.vector(None).await {
            Ok(v) => v,
            Err(reason) => {
                tracing::debug!(reason, "semantic cache: no prompt embedding; not cached");
                return;
            }
        };
        if let Some(m) = self.probe.take() {
            let cached = answer_text(m.payload.response.as_bytes(), m.payload.shape);
            if let Some(correct) = self.judge(cached.as_deref(), &answer).await {
                match self.cache.record_verification(&m, correct, &self.policy).await {
                    Ok(stats) => tracing::debug!(
                        correct,
                        similarity = m.similarity,
                        threshold = stats.threshold(&self.policy),
                        "semantic cache: verified"
                    ),
                    Err(e) => tracing::debug!(error = %e, "semantic cache: verification not recorded"),
                }
            }
            if m.id == self.key.point_id {
                return; // same prompt: keep the entry and its learned threshold
            }
        }
        let entry = NewEntry {
            model: self.model_id.clone(),
            response: String::from_utf8_lossy(&body).into_owned(),
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            ttl_secs: self.cfg.ttl_secs,
        };
        if let Err(e) =
            self.cache.insert(&self.key, self.embed_model.as_str(), &vector, entry, &self.policy, now_secs()).await
        {
            tracing::debug!(error = %e, "semantic cache: insert failed");
        }
    }

    /// Whether two answers say the same thing: equal text, or answer embeddings with cosine of at
    /// least `verify_answer_similarity`. `None` when it cannot tell.
    async fn judge(&self, cached: Option<&str>, fresh: &str) -> Option<bool> {
        let cached = cached?;
        let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
        if norm(cached) == norm(fresh) {
            return Some(true);
        }
        let texts = [cached.to_owned(), fresh.to_owned()];
        let vs = tokio::time::timeout(
            Duration::from_millis(self.cfg.embed_timeout_ms),
            self.embedder.embed(&self.tenant, &self.embed_model, &texts),
        )
        .await
        .ok()?
        .ok()?;
        Some(cosine(vs.first()?, vs.get(1)?) >= self.cfg.verify_answer_similarity)
    }

    /// Wraps the request's T2 state for a live stream; the stream feeds it and completes it.
    pub(crate) fn into_capture(self) -> StreamCapture {
        StreamCapture {
            sem: self,
            valid: true,
            done: false,
            openai: OpenAiAcc::default(),
            anthropic: AnthropicAcc::default(),
        }
    }
}

/// The answer text of a cacheable response, or `None` if it must not be cached (tool calls,
/// several choices, empty, filtered).
fn answer_text(body: &[u8], shape: ResponseShape) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let text = match shape {
        ResponseShape::Openai => {
            let choices = v.get("choices")?.as_array()?;
            let [c] = choices.as_slice() else { return None };
            if matches!(
                c.get("finish_reason").and_then(Value::as_str),
                Some("tool_calls" | "function_call" | "content_filter")
            ) {
                return None;
            }
            let msg = c.get("message")?;
            if msg.get("tool_calls").is_some_and(|t| !t.is_null() && t.as_array().is_none_or(|a| !a.is_empty())) {
                return None;
            }
            msg.get("content")?.as_str()?.to_owned()
        }
        ResponseShape::Anthropic => {
            if matches!(v.get("stop_reason").and_then(Value::as_str), Some("tool_use" | "refusal" | "pause_turn")) {
                return None;
            }
            let mut out = String::new();
            for b in v.get("content")?.as_array()? {
                match b.get("type").and_then(Value::as_str) {
                    Some("text") => out.push_str(b.get("text")?.as_str()?),
                    Some("thinking" | "redacted_thinking") => {}
                    _ => return None,
                }
            }
            out
        }
    };
    (!text.trim().is_empty()).then_some(text)
}

// ───────────────────────────── stream capture (miss) ─────────────────────────────

#[derive(Default)]
struct OpenAiAcc {
    id: Value,
    content: String,
    reasoning: String,
    reasoning_key: Option<&'static str>,
    finish_reason: Option<Value>,
}

#[derive(Default)]
struct AnthropicAcc {
    message: Option<Value>,
    blocks: Vec<Value>,
    stop_reason: Value,
    stop_sequence: Value,
}

/// Rebuilds the upstream (pseudonymised) response of a live stream so it can be cached.
pub(crate) struct StreamCapture {
    sem: Semantic,
    valid: bool,
    done: bool,
    openai: OpenAiAcc,
    anthropic: AnthropicAcc,
}

impl StreamCapture {
    /// One OpenAI chunk as received (before rehydration).
    pub(crate) fn openai_chunk(&mut self, v: &Value) {
        if !self.valid {
            return;
        }
        let acc = &mut self.openai;
        if acc.id.is_null() {
            acc.id = v.get("id").cloned().unwrap_or(Value::Null);
        }
        for c in v.get("choices").and_then(Value::as_array).into_iter().flatten() {
            if c.get("index").and_then(Value::as_u64).unwrap_or(0) != 0 {
                self.valid = false;
                return;
            }
            if let Some(d) = c.get("delta") {
                if d.get("tool_calls").is_some_and(|t| !t.is_null())
                    || d.get("function_call").is_some_and(|t| !t.is_null())
                {
                    self.valid = false;
                    return;
                }
                if let Some(s) = d.get("content").and_then(Value::as_str) {
                    acc.content.push_str(s);
                }
                for k in ["reasoning_content", "reasoning"] {
                    if let Some(s) = d.get(k).and_then(Value::as_str) {
                        acc.reasoning.push_str(s);
                        acc.reasoning_key = Some(k);
                    }
                }
            }
            if let Some(f) = c.get("finish_reason").filter(|f| !f.is_null()) {
                acc.finish_reason = Some(f.clone());
                self.done = true;
            }
        }
    }

    /// One Anthropic event as received (before rehydration).
    pub(crate) fn anthropic_event(&mut self, ev: &Value) {
        if !self.valid {
            return;
        }
        let acc = &mut self.anthropic;
        let index = ev.get("index").and_then(Value::as_u64).and_then(|i| usize::try_from(i).ok()).unwrap_or(0);
        match ev.get("type").and_then(Value::as_str) {
            Some("message_start") => acc.message = ev.get("message").cloned(),
            Some("content_block_start") => {
                let block = ev.get("content_block").cloned().unwrap_or(Value::Null);
                if acc.blocks.len() <= index {
                    acc.blocks.resize(index + 1, Value::Null);
                }
                acc.blocks[index] = block;
            }
            Some("content_block_delta") => {
                let Some(block) = acc.blocks.get_mut(index).and_then(Value::as_object_mut) else {
                    self.valid = false;
                    return;
                };
                let d = ev.get("delta").cloned().unwrap_or(Value::Null);
                let (field, piece) = match d.get("type").and_then(Value::as_str) {
                    Some("text_delta") => ("text", d.get("text")),
                    Some("thinking_delta") => ("thinking", d.get("thinking")),
                    Some("signature_delta") => {
                        block.insert("signature".into(), d.get("signature").cloned().unwrap_or(Value::Null));
                        return;
                    }
                    _ => {
                        self.valid = false;
                        return;
                    }
                };
                let piece = piece.and_then(Value::as_str).unwrap_or_default();
                let cur = block.entry(field).or_insert_with(|| Value::String(String::new()));
                if let Value::String(s) = cur {
                    s.push_str(piece);
                }
            }
            Some("message_delta") => {
                acc.stop_reason = ev.pointer("/delta/stop_reason").cloned().unwrap_or(Value::Null);
                acc.stop_sequence = ev.pointer("/delta/stop_sequence").cloned().unwrap_or(Value::Null);
            }
            Some("message_stop") => self.done = true,
            Some("error") => self.valid = false,
            _ => {}
        }
    }

    /// The upstream failed or the client left: nothing is cached.
    pub(crate) fn abandon(&mut self) {
        self.valid = false;
    }

    /// End of a stream: caches the rebuilt response if the stream completed.
    pub(crate) fn finish(self, usage: Usage) {
        if !self.valid || !self.done {
            return;
        }
        let model = Value::String(self.sem.model_id.clone());
        let body = match self.sem.key.shape {
            ResponseShape::Openai => {
                let a = self.openai;
                let mut message = Map::new();
                message.insert("role".into(), json!("assistant"));
                message.insert("content".into(), Value::String(a.content));
                if let Some(k) = a.reasoning_key {
                    message.insert(k.into(), Value::String(a.reasoning));
                }
                let mut v = json!({
                    "id": a.id, "object": "chat.completion", "model": model,
                    "choices": [{"index": 0, "message": message, "finish_reason": a.finish_reason}],
                    "usage": anthropic::openai_usage(usage),
                });
                if self.sem.think {
                    quirks::normalize_message(&mut v);
                }
                v
            }
            ResponseShape::Anthropic => {
                let a = self.anthropic;
                let Some(mut m) = a.message else { return };
                if a.blocks.iter().any(Value::is_null) {
                    return;
                }
                m["content"] = Value::Array(a.blocks);
                m["stop_reason"] = a.stop_reason;
                m["stop_sequence"] = a.stop_sequence;
                m["model"] = model;
                m["usage"] = anthropic::anthropic_usage(usage);
                m
            }
        };
        self.sem.complete(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()), usage);
    }
}

// ───────────────────────────── serving a hit ─────────────────────────────

/// Serves a semantic hit: JSON (rehydrated, translated for the client) or a replayed stream.
pub(crate) async fn respond(
    gw: Arc<Gateway>,
    outcome: Outcome,
    m: &Match,
    rh: Option<Arc<Rehydrator>>,
    is_native: bool,
    stream: bool,
    settlement: Settlement,
) -> Response {
    let body = Bytes::from(m.payload.response.clone());
    if !stream {
        let body = render_cached(&body, rh.as_ref(), is_native, outcome.dialect);
        let cached = Usage {
            prompt_tokens: m.payload.prompt_tokens,
            completion_tokens: m.payload.completion_tokens,
            ..Usage::default()
        };
        finish(&gw, &outcome, crate::metering::Metered::hit(cached), 0, settlement).await;
        return json_response(&outcome, body, Some(0.0));
    }
    let v: Value = serde_json::from_slice(&body).unwrap_or_default();
    let sse = match m.payload.shape {
        ResponseShape::Openai => openai_replay(&v),
        ResponseShape::Anthropic => anthropic_replay(&v),
    };
    let upstream = futures::stream::iter([Ok(Bytes::from(sse))]).boxed();
    if is_native {
        stream::native_anthropic(gw, outcome, upstream, rh, settlement, Span::none(), None).await
    } else {
        stream::openai_shaped(gw, outcome, upstream, rh, false, settlement, Span::none(), None).await
    }
}

/// OpenAI chunks for a cached chat completion: one delta with the whole message, then the finish
/// chunk with usage, then `[DONE]`.
fn openai_replay(body: &Value) -> String {
    let choice = body.pointer("/choices/0").cloned().unwrap_or(Value::Null);
    let msg = choice.get("message").cloned().unwrap_or(Value::Null);
    let mut delta = Map::new();
    delta.insert("role".into(), json!("assistant"));
    for k in ["reasoning_content", "reasoning"] {
        if let Some(s) = msg.get(k).filter(|s| s.is_string()) {
            delta.insert(k.into(), s.clone());
        }
    }
    delta.insert("content".into(), msg.get("content").cloned().unwrap_or(json!("")));
    let (id, model) =
        (body.get("id").cloned().unwrap_or(Value::Null), body.get("model").cloned().unwrap_or(Value::Null));
    let first = json!({"id": id, "object": "chat.completion.chunk", "model": model, "choices": [{"index": 0, "delta": delta, "finish_reason": null}]});
    let last = json!({"id": id, "object": "chat.completion.chunk", "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": choice.get("finish_reason").cloned().unwrap_or(json!("stop"))}],
        "usage": body.get("usage").cloned().unwrap_or(Value::Null)});
    format!("data: {first}\n\ndata: {last}\n\ndata: [DONE]\n\n")
}

/// Anthropic events for a cached message.
fn anthropic_replay(body: &Value) -> String {
    let usage = body.get("usage").cloned().unwrap_or(json!({}));
    let mut start = body.clone();
    start["content"] = json!([]);
    start["stop_reason"] = Value::Null;
    start["stop_sequence"] = Value::Null;
    start["usage"] = json!({
        "input_tokens": usage.get("input_tokens").cloned().unwrap_or(json!(0)),
        "cache_read_input_tokens": usage.get("cache_read_input_tokens").cloned().unwrap_or(json!(0)),
        "cache_creation_input_tokens": 0,
        "output_tokens": 0,
    });
    let mut evs = vec![json!({"type": "message_start", "message": start})];
    for (i, b) in body.get("content").and_then(Value::as_array).into_iter().flatten().enumerate() {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => {
                evs.push(
                    json!({"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}}),
                );
                evs.push(json!({"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": b.get("text").cloned().unwrap_or(json!(""))}}));
            }
            Some("thinking") => {
                evs.push(json!({"type": "content_block_start", "index": i, "content_block": {"type": "thinking", "thinking": ""}}));
                evs.push(json!({"type": "content_block_delta", "index": i, "delta": {"type": "thinking_delta", "thinking": b.get("thinking").cloned().unwrap_or(json!(""))}}));
                if let Some(sig) = b.get("signature").filter(|s| s.is_string()) {
                    evs.push(json!({"type": "content_block_delta", "index": i, "delta": {"type": "signature_delta", "signature": sig}}));
                }
            }
            _ => evs.push(json!({"type": "content_block_start", "index": i, "content_block": b})),
        }
        evs.push(json!({"type": "content_block_stop", "index": i}));
    }
    evs.push(json!({"type": "message_delta", "delta": {"stop_reason": body.get("stop_reason").cloned().unwrap_or(json!("end_turn")), "stop_sequence": body.get("stop_sequence").cloned().unwrap_or(Value::Null)},
        "usage": {"output_tokens": usage.get("output_tokens").cloned().unwrap_or(json!(0))}}));
    evs.push(json!({"type": "message_stop"}));
    evs.iter().map(anthropic::sse_event).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_hash_ignores_only_the_last_message_and_transport_fields() {
        let a = json!({"model": "up", "temperature": 0, "stream": true, "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "q1"}]});
        let b = json!({"model": "up2", "temperature": 0, "cache_salt": "x", "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "q2 different"}]});
        assert_eq!(context_hash(&a, "m"), context_hash(&b, "m"));
        let c = json!({"model": "up", "temperature": 0.2, "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "q1"}]});
        assert_ne!(context_hash(&a, "m"), context_hash(&c, "m"), "temperature");
        let d = json!({"model": "up", "temperature": 0, "messages": [{"role": "system", "content": "other"}, {"role": "user", "content": "q1"}]});
        assert_ne!(context_hash(&a, "m"), context_hash(&d, "m"), "system prompt");
        assert_ne!(context_hash(&a, "m"), context_hash(&a, "m2"), "model");
    }

    #[test]
    fn canonical_json_ignores_key_order() {
        let mut a = Map::new();
        a.insert("b".into(), json!(1));
        a.insert("a".into(), json!({"y": 1, "x": [{"d": 1, "c": 2}]}));
        let mut b = Map::new();
        b.insert("a".into(), json!({"x": [{"c": 2, "d": 1}], "y": 1}));
        b.insert("b".into(), json!(1));
        assert_eq!(canonical_json(&Value::Object(a)), canonical_json(&Value::Object(b)));
        assert_eq!(canonical_json(&json!({"b": 1, "a": 2})), br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn tool_traffic_is_detected_in_both_shapes() {
        assert!(has_tool_traffic(&json!({"messages": [{"role": "tool", "content": "x"}]})));
        assert!(has_tool_traffic(&json!({"messages": [{"role": "assistant", "tool_calls": [{}]}]})));
        assert!(has_tool_traffic(
            &json!({"messages": [{"role": "user", "content": [{"type": "tool_result", "content": "x"}]}]})
        ));
        assert!(!has_tool_traffic(
            &json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "x"}]}]})
        ));
    }

    #[test]
    fn answers_with_tool_calls_or_several_choices_are_not_cached() {
        let ok = json!({"choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}]});
        assert_eq!(answer_text(ok.to_string().as_bytes(), ResponseShape::Openai).as_deref(), Some("hi"));
        let tools =
            json!({"choices": [{"message": {"content": null, "tool_calls": [{}]}, "finish_reason": "tool_calls"}]});
        assert!(answer_text(tools.to_string().as_bytes(), ResponseShape::Openai).is_none());
        let two = json!({"choices": [{"message": {"content": "a"}}, {"message": {"content": "b"}}]});
        assert!(answer_text(two.to_string().as_bytes(), ResponseShape::Openai).is_none());
        let anth = json!({"content": [{"type": "thinking", "thinking": "t"}, {"type": "text", "text": "x"}], "stop_reason": "end_turn"});
        assert_eq!(answer_text(anth.to_string().as_bytes(), ResponseShape::Anthropic).as_deref(), Some("x"));
        let tool_use = json!({"content": [{"type": "tool_use"}], "stop_reason": "tool_use"});
        assert!(answer_text(tool_use.to_string().as_bytes(), ResponseShape::Anthropic).is_none());
    }

    #[test]
    fn replays_parse_back_to_the_same_message() {
        let body = json!({"id": "c", "model": "m", "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello there"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}});
        let sse = openai_replay(&body);
        let chunks: Vec<Value> =
            sse.lines().filter_map(|l| l.strip_prefix("data: ")).filter_map(|d| serde_json::from_str(d).ok()).collect();
        assert_eq!(chunks[0]["choices"][0]["delta"]["content"], "Hello there");
        assert_eq!(chunks[1]["usage"]["completion_tokens"], 2);
        assert!(sse.ends_with("data: [DONE]\n\n"));
        let msg = json!({"id": "msg", "type": "message", "role": "assistant", "model": "m",
            "content": [{"type": "thinking", "thinking": "hmm", "signature": "sig"}, {"type": "text", "text": "Hi"}],
            "stop_reason": "end_turn", "stop_sequence": null, "usage": {"input_tokens": 4, "output_tokens": 2}});
        let sse = anthropic_replay(&msg);
        assert!(sse.starts_with("event: message_start\n"));
        assert!(sse.contains("signature_delta") && sse.contains("\"Hi\"") && sse.contains("message_stop"));
    }
}
