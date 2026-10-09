//! Per-model request shaping and response normalization, mostly for open-weight models served
//! on-prem (Qwen, gpt-oss, …) behind vLLM / SGLang / llama.cpp / Ollama.
//!
//! - Reasoning: maps the request's reasoning preference to what the family understands
//!   (`chat_template_kwargs.enable_thinking` for Qwen3 hybrid thinking, `reasoning_effort` for
//!   gpt-oss/OpenAI).
//! - Prefix-cache isolation: adds a per-tenant `cache_salt` for engines that support it, so one
//!   tenant cannot probe another's cached prefixes through timing.
//! - `<think>` tags: when a server returns reasoning inline in `content`, it is moved to
//!   `reasoning_content` so clients see the same shape as with a reasoning parser.
//! - Stream usage: every stream asks for `stream_options.include_usage` (metering needs the
//!   provider's usage even when the client did not ask for it). Models whose server rejects the
//!   field are marked `capabilities.rejects_stream_options`; the field is removed for them, and
//!   their streams are metered from an estimate (`usage_source: "estimated"`). The Anthropic
//!   adapter drops the field itself (Anthropic streams always carry usage).

use caliban_config::{ModelEntry, ProviderConfig, Reasoning, ReasoningControl};
use caliban_types::ProviderKind;
use caliban_ir::ReasoningPref;
use serde_json::{Map, Value, json};

const OPEN: &str = "<think>";
const CLOSE: &str = "</think>";

pub fn shape_request(body: &mut Value, model: &ModelEntry, provider: &ProviderConfig, pref: Option<ReasoningPref>, tenant_salt: &str) {
    let Some(obj) = body.as_object_mut() else { return };
    match model.capabilities.reasoning_control {
        ReasoningControl::EnableThinking => {
            obj.remove("reasoning_effort");
            if let Some(p) = pref {
                let kwargs = obj.entry("chat_template_kwargs").or_insert_with(|| json!({}));
                if let Some(k) = kwargs.as_object_mut() {
                    k.insert("enable_thinking".into(), Value::Bool(p != ReasoningPref::Off));
                }
            }
        }
        ReasoningControl::ReasoningEffort => {
            if let Some(p) = pref {
                obj.insert("reasoning_effort".into(), Value::String(p.as_effort().into()));
            }
        }
        ReasoningControl::None => {
            // Local servers may reject fields their model does not understand.
            if provider.kind == ProviderKind::OpenaiCompatible && model.capabilities.reasoning == Reasoning::None {
                obj.remove("reasoning_effort");
            }
        }
    }
    if provider.cache_salt {
        obj.insert("cache_salt".into(), Value::String(tenant_salt.to_owned()));
    }
    if model.capabilities.rejects_stream_options {
        obj.remove("stream_options");
    }
    // OpenAI's current models reject the legacy `max_tokens` (it arrives from Anthropic clients
    // and older SDKs); open-model servers keep it, since not all accept the new name.
    if provider.kind == ProviderKind::Openai
        && let Some(v) = obj.remove("max_tokens")
    {
        obj.entry("max_completion_tokens").or_insert(v);
    }
}

/// Splits inline reasoning from a complete message. Handles `<think>…</think>answer`, templates
/// that open the tag in the prompt (`…</think>answer`), and unterminated reasoning.
pub fn split_think(content: &str) -> Option<(String, String)> {
    if let Some(i) = content.find(CLOSE) {
        let reasoning = content[..i].trim_start();
        let reasoning = reasoning.strip_prefix(OPEN).unwrap_or(reasoning);
        return Some((reasoning.trim().to_owned(), content[i + CLOSE.len()..].trim_start().to_owned()));
    }
    let t = content.trim_start();
    t.strip_prefix(OPEN).map(|r| (r.trim().to_owned(), String::new()))
}

/// Applies `split_think` to every choice of a non-streaming response.
pub fn normalize_message(v: &mut Value) {
    let Some(choices) = v.get_mut("choices").and_then(Value::as_array_mut) else { return };
    for c in choices {
        let Some(msg) = c.get_mut("message").and_then(Value::as_object_mut) else { continue };
        let Some((reasoning, answer)) = msg.get("content").and_then(Value::as_str).and_then(split_think) else { continue };
        msg.insert("content".into(), Value::String(answer));
        if !reasoning.is_empty() {
            msg.insert("reasoning_content".into(), Value::String(reasoning));
        }
    }
}

/// Streaming `<think>` splitter for one choice. Detects an opening tag at the start of the output;
/// a response that starts with anything else passes through as content.
#[derive(Debug, Default)]
pub struct ThinkSplitter {
    state: State,
    buf: String,
    /// Drop whitespace between `</think>` and the first answer character.
    trim_answer_start: bool,
}

#[derive(Debug, Default, PartialEq)]
enum State {
    #[default]
    Detect,
    Thinking,
    Answer,
}

impl ThinkSplitter {
    /// Returns `(reasoning, content)` safe to emit now.
    pub fn push(&mut self, delta: &str) -> (String, String) {
        match self.state {
            State::Answer if self.trim_answer_start => {
                let t = delta.trim_start();
                if !t.is_empty() {
                    self.trim_answer_start = false;
                }
                (String::new(), t.to_owned())
            }
            State::Answer => (String::new(), delta.to_owned()),
            State::Detect => {
                self.buf.push_str(delta);
                let t = self.buf.trim_start();
                if t.is_empty() || (OPEN.starts_with(t) && t.len() < OPEN.len()) {
                    return (String::new(), String::new());
                }
                if let Some(rest) = t.strip_prefix(OPEN) {
                    let rest = rest.to_owned();
                    self.buf.clear();
                    self.state = State::Thinking;
                    return self.push(&rest);
                }
                self.state = State::Answer;
                (String::new(), std::mem::take(&mut self.buf))
            }
            State::Thinking => {
                self.buf.push_str(delta);
                if let Some(i) = self.buf.find(CLOSE) {
                    let reasoning = self.buf[..i].to_owned();
                    let answer = self.buf[i + CLOSE.len()..].trim_start().to_owned();
                    self.buf.clear();
                    self.state = State::Answer;
                    self.trim_answer_start = answer.is_empty();
                    return (reasoning, answer);
                }
                // Hold back a suffix that could be the start of `</think>`.
                let mut keep = 0;
                for n in (1..CLOSE.len()).rev() {
                    if self.buf.len() >= n && self.buf.is_char_boundary(self.buf.len() - n) && CLOSE.starts_with(&self.buf[self.buf.len() - n..]) {
                        keep = n;
                        break;
                    }
                }
                let emit = self.buf.len() - keep;
                let out: String = self.buf.drain(..emit).collect();
                (out, String::new())
            }
        }
    }

    pub fn finish(&mut self) -> (String, String) {
        let rest = std::mem::take(&mut self.buf);
        match self.state {
            State::Thinking => (rest, String::new()),
            _ => (String::new(), rest),
        }
    }
}

/// Hex salt for a tenant, stable for a given key.
pub fn tenant_salt(key: &[u8; 32], tenant: &str) -> String {
    blake3::keyed_hash(key, tenant.as_bytes()).to_hex()[..32].to_owned()
}

/// Field name the upstream used for reasoning deltas (vLLM: `reasoning_content`; newer: `reasoning`).
pub fn reasoning_key(delta: &Map<String, Value>) -> &'static str {
    if delta.contains_key("reasoning") { "reasoning" } else { "reasoning_content" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliban_config::Capabilities;

    fn model(control: ReasoningControl) -> ModelEntry {
        ModelEntry {
            id: "local/q".into(),
            provider: "p".into(),
            upstream_model: "Qwen/Qwen3-8B".into(),
            kind: Default::default(),
            family: Some("qwen3".into()),
            capabilities: Capabilities { reasoning: Reasoning::Hybrid, reasoning_control: control, ..Default::default() },
            trust_tier: caliban_types::TrustTier::T0Sovereign,
            licence: None,
            context_window: None,
            price_in_per_mtok: None,
            price_out_per_mtok: None,
            price_cache_read_per_mtok: None,
            price_cache_write_per_mtok: None,
            price_cache_write_1h_per_mtok: None,
        }
    }

    fn provider(salt: bool) -> ProviderConfig {
        ProviderConfig {
            id: "p".into(),
            kind: ProviderKind::OpenaiCompatible,
            base_url: "http://x".into(),
            trust_tier: caliban_types::TrustTier::T0Sovereign,
            api_key: None,
            cache_salt: salt,
        }
    }

    #[test]
    fn qwen_thinking_toggle_and_salt() {
        let mut body = json!({"model": "Qwen/Qwen3-8B", "reasoning_effort": "high"});
        shape_request(&mut body, &model(ReasoningControl::EnableThinking), &provider(true), Some(ReasoningPref::Off), "s1");
        assert_eq!(body["chat_template_kwargs"]["enable_thinking"], false);
        assert!(body.get("reasoning_effort").is_none());
        assert_eq!(body["cache_salt"], "s1");
    }

    #[test]
    fn effort_models_get_reasoning_effort() {
        let mut body = json!({});
        shape_request(&mut body, &model(ReasoningControl::ReasoningEffort), &provider(false), Some(ReasoningPref::High), "s");
        assert_eq!(body["reasoning_effort"], "high");
        assert!(body.get("cache_salt").is_none());
    }

    #[test]
    fn openai_gets_max_completion_tokens() {
        let mut body = json!({"max_tokens": 100});
        let mut p = provider(false);
        shape_request(&mut body, &model(ReasoningControl::None), &p, None, "s");
        assert_eq!(body["max_tokens"], 100, "open-model servers keep max_tokens");
        p.kind = ProviderKind::Openai;
        shape_request(&mut body, &model(ReasoningControl::None), &p, None, "s");
        assert_eq!(body, json!({"max_completion_tokens": 100}));
    }

    #[test]
    fn stream_options_are_removed_for_servers_that_reject_them() {
        let mut body = json!({"stream": true, "stream_options": {"include_usage": true}});
        let mut m = model(ReasoningControl::None);
        shape_request(&mut body, &m, &provider(false), None, "s");
        assert_eq!(body["stream_options"]["include_usage"], true, "kept by default");
        m.capabilities.rejects_stream_options = true;
        shape_request(&mut body, &m, &provider(false), None, "s");
        assert!(body.get("stream_options").is_none());
    }

    #[test]
    fn split_think_variants() {
        assert_eq!(split_think("<think>plan</think>\n\nHi"), Some(("plan".into(), "Hi".into())));
        assert_eq!(split_think("plan</think>Hi"), Some(("plan".into(), "Hi".into())));
        assert_eq!(split_think("  <think>cut off"), Some(("cut off".into(), String::new())));
        assert_eq!(split_think("plain answer"), None);
    }

    #[test]
    fn streaming_split_handles_tags_across_chunks() {
        let text = "<think>step 1, step 2</think>\n\nThe answer is 4.";
        for size in 1..10 {
            let mut s = ThinkSplitter::default();
            let (mut r, mut c) = (String::new(), String::new());
            let chars: Vec<char> = text.chars().collect();
            for chunk in chars.chunks(size) {
                let (a, b) = s.push(&chunk.iter().collect::<String>());
                r.push_str(&a);
                c.push_str(&b);
            }
            let (a, b) = s.finish();
            r.push_str(&a);
            c.push_str(&b);
            assert_eq!((r.as_str(), c.as_str()), ("step 1, step 2", "The answer is 4."), "chunk size {size}");
        }
    }

    #[test]
    fn non_thinking_output_streams_through() {
        let mut s = ThinkSplitter::default();
        assert_eq!(s.push("Hello"), (String::new(), "Hello".into()));
        assert_eq!(s.push(" <think> is a tag"), (String::new(), " <think> is a tag".into()));
    }
}
