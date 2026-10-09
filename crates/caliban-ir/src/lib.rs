//! Canonical request representation (`CalibanIR`).
//!
//! Every inbound dialect (OpenAI Chat Completions and Anthropic Messages today; OpenAI Responses
//! next) is parsed once into [`ChatRequest`]. Unknown fields are preserved in `extra` so that
//! provider-specific options pass through untouched.

pub mod anthropic;
pub mod sse;

use caliban_types::{CacheMode, PiiMode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Caliban request extension: the optional `caliban` object in the request body.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CalibanExt {
    pub pii: Option<PiiMode>,
    pub cache: Option<CacheMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datasources: Vec<String>,
    pub node: Option<String>,
    pub max_cost_usd: Option<f64>,
    /// Reasoning preference, mapped per model family (Qwen3 `enable_thinking`, `reasoning_effort`, …).
    pub reasoning: Option<ReasoningPref>,
    #[serde(default)]
    pub zdr: bool,
    pub trace_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningPref {
    Off,
    Low,
    Medium,
    High,
}

impl ReasoningPref {
    /// Parses OpenAI's `reasoning_effort` values.
    pub fn from_effort(s: &str) -> Option<Self> {
        match s {
            "none" | "minimal" => Some(Self::Off),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }

    pub fn as_effort(self) -> &'static str {
        match self {
            Self::Off | Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Message {
    pub role: String,
    /// String, array of content parts, or null (assistant tool calls).
    #[serde(default)]
    pub content: Value,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stream: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caliban: Option<CalibanExt>,
    /// Everything else (temperature, tools, response_format, …) passes through unchanged.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ChatRequest {
    pub fn from_openai_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    pub fn ext(&self) -> CalibanExt {
        self.caliban.clone().unwrap_or_default()
    }

    /// Body to send to an OpenAI-compatible upstream: the `caliban` extension is stripped and the
    /// model is replaced with the upstream model name.
    pub fn to_openai_upstream(&self, upstream_model: &str) -> Value {
        let mut req = self.clone();
        req.caliban = None;
        req.model = upstream_model.to_owned();
        if req.stream {
            // Ask for usage in the final chunk so metering is exact.
            req.extra
                .entry("stream_options")
                .or_insert_with(|| serde_json::json!({ "include_usage": true }));
        }
        serde_json::to_value(req).unwrap_or(Value::Null)
    }

    /// Calls `f` on every user-visible text segment (string content and `{"type":"text"}` parts).
    pub fn for_each_text_mut(&mut self, mut f: impl FnMut(&str, &mut String)) {
        for m in &mut self.messages {
            let role = m.role.clone();
            match &mut m.content {
                Value::String(s) => f(&role, s),
                Value::Array(parts) => {
                    for p in parts {
                        if p.get("type").and_then(Value::as_str) == Some("text")
                            && let Some(Value::String(s)) = p.get_mut("text") {
                                f(&role, s);
                            }
                    }
                }
                _ => {}
            }
        }
    }

    /// Text of the last user message, used for intent classification.
    pub fn last_user_text(&self) -> Option<String> {
        let m = self.messages.iter().rev().find(|m| m.role == "user")?;
        match &m.content {
            Value::String(s) => Some(s.clone()),
            Value::Array(parts) => Some(
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            _ => None,
        }
    }

    /// Deterministic fingerprint of everything that affects the model's output.
    /// `serde_json::Map` is ordered (BTreeMap), so serialization is canonical.
    pub fn canonical_hash(&self, resolved_model: &str) -> blake3::Hash {
        let mut req = self.clone();
        req.caliban = None;
        req.stream = false;
        req.extra.remove("stream_options");
        req.extra.remove("user");
        req.model = resolved_model.to_owned();
        let bytes = serde_json::to_vec(&req).unwrap_or_default();
        blake3::hash(&bytes)
    }

    /// Temperature 0 (or unset with an explicit cache request) is required for exact caching.
    pub fn is_deterministic(&self) -> bool {
        matches!(self.extra.get("temperature").and_then(Value::as_f64), Some(t) if t == 0.0)
    }

    /// True if any message carries an image part.
    pub fn has_images(&self) -> bool {
        self.messages.iter().any(|m| {
            m.content.as_array().is_some_and(|parts| {
                parts.iter().any(|p| matches!(p.get("type").and_then(Value::as_str), Some("image_url" | "input_image")))
            })
        })
    }

    /// Requested reasoning level: the `caliban.reasoning` extension wins over `reasoning_effort`.
    pub fn reasoning_pref(&self) -> Option<ReasoningPref> {
        self.caliban.as_ref().and_then(|c| c.reasoning).or_else(|| {
            self.extra.get("reasoning_effort").and_then(Value::as_str).and_then(ReasoningPref::from_effort)
        })
    }

    pub fn has_tools(&self) -> bool {
        self.extra.get("tools").is_some_and(|t| t.as_array().is_some_and(|a| !a.is_empty()))
    }

    /// Requested output cap (`max_completion_tokens` wins over the legacy `max_tokens`).
    pub fn max_output_tokens(&self) -> Option<u64> {
        ["max_completion_tokens", "max_tokens"].iter().find_map(|k| self.extra.get(*k).and_then(Value::as_u64))
    }

    /// Cheap prompt-size estimate for quota reservation (no tokenizer): ~4 UTF-8 bytes per token
    /// for text, a flat cost per image, plus per-message and tool-schema overhead. Settlement
    /// corrects it with the usage the upstream reports.
    pub fn estimate_prompt_tokens(&self) -> u64 {
        const PER_MESSAGE: u64 = 4;
        const PER_IMAGE: u64 = 1_000;
        let bytes = |s: &str| (s.len() as u64).div_ceil(4);
        let mut n = 3;
        for m in &self.messages {
            n += PER_MESSAGE;
            match &m.content {
                Value::String(s) => n += bytes(s),
                Value::Array(parts) => {
                    for p in parts {
                        match p.get("type").and_then(Value::as_str) {
                            Some("text") => n += p.get("text").and_then(Value::as_str).map_or(0, bytes),
                            Some("image_url" | "input_image" | "image") => n += PER_IMAGE,
                            _ => n += bytes(&p.to_string()),
                        }
                    }
                }
                _ => {}
            }
            if let Some(calls) = m.extra.get("tool_calls") {
                n += bytes(&calls.to_string());
            }
        }
        if let Some(tools) = self.extra.get("tools") {
            n += bytes(&tools.to_string());
        }
        n
    }
}

/// Token usage as reported by the upstream (OpenAI shape).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Usage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub cached_prompt_tokens: u64,
}

impl Usage {
    /// Extracts usage from an OpenAI-style response or final stream chunk.
    pub fn from_openai(v: &Value) -> Option<Self> {
        let u = v.get("usage")?;
        if u.is_null() {
            return None;
        }
        Some(Usage {
            prompt_tokens: u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
            completion_tokens: u.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0),
            cached_prompt_tokens: u
                .pointer("/prompt_tokens_details/cached_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }

    /// Extracts usage from an Anthropic `usage` object. Anthropic's `input_tokens` excludes cache
    /// reads and writes, so they are added back to get the full prompt size.
    pub fn from_anthropic_usage(u: &Value) -> Self {
        let g = |k: &str| u.get(k).and_then(Value::as_u64).unwrap_or(0);
        let cached = g("cache_read_input_tokens");
        Usage {
            prompt_tokens: g("input_tokens") + cached + g("cache_creation_input_tokens"),
            completion_tokens: g("output_tokens"),
            cached_prompt_tokens: cached,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(json: &str) -> ChatRequest {
        ChatRequest::from_openai_json(json.as_bytes()).unwrap()
    }

    #[test]
    fn unknown_fields_pass_through_and_ext_is_stripped() {
        let r = req(r#"{"model":"caliban/auto","messages":[{"role":"user","content":"hi"}],
                     "temperature":0,"response_format":{"type":"json_object"},
                     "caliban":{"pii":"reversible","datasources":["dw"]}}"#);
        assert_eq!(r.ext().datasources, vec!["dw"]);
        let up = r.to_openai_upstream("gpt-x");
        assert_eq!(up["model"], "gpt-x");
        assert_eq!(up["response_format"]["type"], "json_object");
        assert!(up.get("caliban").is_none());
    }

    #[test]
    fn canonical_hash_ignores_stream_and_ext() {
        let a = req(r#"{"model":"m","messages":[{"role":"user","content":"x"}],"stream":true,"caliban":{"zdr":true}}"#);
        let b = req(r#"{"model":"m","messages":[{"role":"user","content":"x"}]}"#);
        assert_eq!(a.canonical_hash("m"), b.canonical_hash("m"));
        assert_ne!(a.canonical_hash("m"), a.canonical_hash("other"));
    }

    #[test]
    fn text_parts_are_visited() {
        let mut r = req(r#"{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"image_url","image_url":{"url":"x"}}]}]}"#);
        let mut seen = vec![];
        r.for_each_text_mut(|_, s| {
            seen.push(s.clone());
            s.push('!');
        });
        assert_eq!(seen, vec!["a"]);
        assert_eq!(r.last_user_text().unwrap(), "a!");
    }

    #[test]
    fn prompt_estimate_and_max_tokens() {
        let r = req(r#"{"model":"m","max_tokens":50,"messages":[{"role":"system","content":"abcdefgh"},
            {"role":"user","content":[{"type":"text","text":"abcd"},{"type":"image_url","image_url":{"url":"x"}}]}]}"#);
        assert_eq!(r.estimate_prompt_tokens(), 3 + 4 + 2 + 4 + 1 + 1000);
        assert_eq!(r.max_output_tokens(), Some(50));
    }

    #[test]
    fn anthropic_usage_adds_cache_tokens() {
        let u = Usage::from_anthropic_usage(&serde_json::json!({"input_tokens": 10, "cache_read_input_tokens": 100, "cache_creation_input_tokens": 5, "output_tokens": 7}));
        assert_eq!(u, Usage { prompt_tokens: 115, completion_tokens: 7, cached_prompt_tokens: 100 });
    }

    #[test]
    fn rejects_unknown_ext_fields() {
        let r = ChatRequest::from_openai_json(br#"{"model":"m","messages":[],"caliban":{"nope":1}}"#);
        assert!(r.is_err());
    }
}
