//! Streaming translation: OpenAI `chat.completion.chunk`s ⇄ Anthropic stream events.

use super::response::{
    anthropic_usage, finish_reason_from_anthropic, message_id, now_secs, openai_usage, stop_reason_from_openai,
};
use crate::Usage;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Open {
    Text(u64),
    Thinking(u64),
    Tool { block: u64, openai: u64 },
}

impl Open {
    fn index(self) -> u64 {
        match self {
            Open::Text(i) | Open::Thinking(i) | Open::Tool { block: i, .. } => i,
        }
    }
}

/// OpenAI chunks → Anthropic events, for an Anthropic client served by an OpenAI-shaped
/// upstream. Emits `message_start` + `ping` on the first chunk, one content block per contiguous
/// run of reasoning (`thinking`), text (`text`) or tool call (`tool_use` with `input_json_delta`),
/// and `message_delta` (stop reason + usage) + `message_stop` on [`finish`](Self::finish).
/// Only choice 0 is translated (Anthropic has no `n`).
#[derive(Debug)]
pub struct OpenAiToAnthropicStream {
    model: String,
    started: bool,
    finished: bool,
    open: Option<Open>,
    next_index: u64,
    seen_tools: HashMap<u64, u64>,
    stop_reason: Option<&'static str>,
}

impl OpenAiToAnthropicStream {
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            started: false,
            finished: false,
            open: None,
            next_index: 0,
            seen_tools: HashMap::new(),
            stop_reason: None,
        }
    }

    fn start(&mut self, id: Option<&str>, out: &mut Vec<Value>) {
        if self.started {
            return;
        }
        self.started = true;
        out.push(json!({
            "type": "message_start",
            "message": {
                "id": message_id(id), "type": "message", "role": "assistant", "model": self.model,
                "content": [], "stop_reason": null, "stop_sequence": null,
                "usage": { "input_tokens": 0, "output_tokens": 0 },
            }
        }));
        out.push(json!({ "type": "ping" }));
    }

    fn close(&mut self, out: &mut Vec<Value>) {
        if let Some(o) = self.open.take() {
            out.push(json!({ "type": "content_block_stop", "index": o.index() }));
        }
    }

    fn open_block(&mut self, block: Value, out: &mut Vec<Value>) -> u64 {
        self.close(out);
        let index = self.next_index;
        self.next_index += 1;
        out.push(json!({ "type": "content_block_start", "index": index, "content_block": block }));
        index
    }

    /// Translates one upstream chunk (after Caliban's own rewriting) into zero or more events.
    pub fn push(&mut self, chunk: &Value) -> Vec<Value> {
        let mut out = Vec::new();
        if self.finished {
            return out;
        }
        self.start(chunk.get("id").and_then(Value::as_str), &mut out);
        let Some(choice) = chunk
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|cs| cs.iter().find(|c| c.get("index").and_then(Value::as_u64).unwrap_or(0) == 0))
        else {
            return out;
        };
        let delta = choice.get("delta").unwrap_or(&Value::Null);
        let reasoning = delta
            .get("reasoning_content")
            .or_else(|| delta.get("reasoning"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        if let Some(r) = reasoning {
            let index = match self.open {
                Some(Open::Thinking(i)) => i,
                _ => {
                    let i = self.open_block(json!({ "type": "thinking", "thinking": "", "signature": "" }), &mut out);
                    self.open = Some(Open::Thinking(i));
                    i
                }
            };
            out.push(json!({ "type": "content_block_delta", "index": index, "delta": { "type": "thinking_delta", "thinking": r } }));
        }
        if let Some(t) = delta.get("content").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            let index = match self.open {
                Some(Open::Text(i)) => i,
                _ => {
                    let i = self.open_block(json!({ "type": "text", "text": "" }), &mut out);
                    self.open = Some(Open::Text(i));
                    i
                }
            };
            out.push(
                json!({ "type": "content_block_delta", "index": index, "delta": { "type": "text_delta", "text": t } }),
            );
        }
        for tc in delta.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
            let openai = tc.get("index").and_then(Value::as_u64).unwrap_or(0);
            let index = match self.open {
                Some(Open::Tool { block, openai: o }) if o == openai => block,
                _ if self.seen_tools.contains_key(&openai) => continue, // late fragment of a closed block
                _ => {
                    let id =
                        tc.get("id").and_then(Value::as_str).map_or_else(|| format!("toolu_{openai}"), str::to_owned);
                    let name = tc.pointer("/function/name").and_then(Value::as_str).unwrap_or_default().to_owned();
                    let block =
                        self.open_block(json!({ "type": "tool_use", "id": id, "name": name, "input": {} }), &mut out);
                    self.open = Some(Open::Tool { block, openai });
                    self.seen_tools.insert(openai, block);
                    block
                }
            };
            if let Some(args) = tc.pointer("/function/arguments").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                out.push(json!({ "type": "content_block_delta", "index": index, "delta": { "type": "input_json_delta", "partial_json": args } }));
            }
        }
        if let Some(f) = choice.get("finish_reason").and_then(Value::as_str) {
            self.stop_reason = Some(stop_reason_from_openai(Some(f)));
        }
        out
    }

    /// Closes the open block and ends the message. Idempotent.
    pub fn finish(&mut self, usage: Usage) -> Vec<Value> {
        let mut out = Vec::new();
        if self.finished {
            return out;
        }
        self.start(None, &mut out);
        self.close(&mut out);
        self.finished = true;
        let mut u = anthropic_usage(usage);
        if let Some(o) = u.as_object_mut() {
            o.remove("cache_creation_input_tokens");
        }
        out.push(json!({
            "type": "message_delta",
            "delta": { "stop_reason": self.stop_reason.unwrap_or("end_turn"), "stop_sequence": null },
            "usage": u,
        }));
        out.push(json!({ "type": "message_stop" }));
        out
    }

    /// Error event (stream aborted upstream).
    pub fn error(&mut self, message: &str) -> Vec<Value> {
        self.finished = true;
        vec![super::error_body("api_error", message)]
    }
}

/// Accumulates usage across Anthropic stream events (`message_start` carries input and cache
/// tokens, `message_delta` the cumulative output tokens).
#[derive(Debug, Default, Clone)]
pub struct AnthropicUsage {
    fields: Map<String, Value>,
    started: bool,
    finished: bool,
}

impl AnthropicUsage {
    pub fn observe(&mut self, ev: &Value) {
        let u = match ev.get("type").and_then(Value::as_str) {
            Some("message_start") => ev.pointer("/message/usage"),
            Some("message_delta") => ev.get("usage"),
            _ => None,
        };
        if let Some(Value::Object(u)) = u {
            match ev.get("type").and_then(Value::as_str) {
                Some("message_start") => self.started = true,
                _ => self.finished = true,
            }
            for (k, v) in u {
                // Numbers, and the `cache_creation` per-TTL breakdown object.
                if v.is_number() || v.is_object() {
                    self.fields.insert(k.clone(), v.clone());
                }
            }
        }
    }

    pub fn usage(&self) -> Usage {
        Usage::from_anthropic_usage(&Value::Object(self.fields.clone()))
    }

    /// `message_start` usage was seen: input and cache tokens are the provider's.
    pub fn has_input(&self) -> bool {
        self.started
    }

    /// `message_delta` usage was seen: output tokens are final.
    pub fn is_complete(&self) -> bool {
        self.finished
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    Thinking,
    Tool(u64),
    Other,
}

/// Anthropic events → OpenAI chunk payloads (the `data:` strings, ending with `[DONE]`), for an
/// OpenAI client served by an Anthropic upstream.
#[derive(Debug)]
pub struct AnthropicToOpenAiStream {
    id: String,
    model: String,
    created: u64,
    blocks: HashMap<u64, Kind>,
    next_tool: u64,
    usage: AnthropicUsage,
    finish: Option<&'static str>,
    done: bool,
}

impl Default for AnthropicToOpenAiStream {
    fn default() -> Self {
        Self::new()
    }
}

impl AnthropicToOpenAiStream {
    pub fn new() -> Self {
        Self {
            id: String::new(),
            model: String::new(),
            created: now_secs(),
            blocks: HashMap::new(),
            next_tool: 0,
            usage: AnthropicUsage::default(),
            finish: None,
            done: false,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    fn chunk(&self, delta: Value, finish: Option<&str>) -> String {
        json!({
            "id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.model,
            "choices": [{ "index": 0, "delta": delta, "finish_reason": finish }],
        })
        .to_string()
    }

    pub fn push(&mut self, ev: &Value) -> Vec<String> {
        self.usage.observe(ev);
        let mut out = Vec::new();
        match ev.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                self.id = ev.pointer("/message/id").and_then(Value::as_str).unwrap_or_default().to_owned();
                self.model = ev.pointer("/message/model").and_then(Value::as_str).unwrap_or_default().to_owned();
                out.push(self.chunk(json!({ "role": "assistant", "content": "" }), None));
            }
            Some("content_block_start") => {
                let index = ev.get("index").and_then(Value::as_u64).unwrap_or(0);
                let cb = ev.get("content_block").unwrap_or(&Value::Null);
                let kind = match cb.get("type").and_then(Value::as_str) {
                    Some("text") => Kind::Text,
                    Some("thinking") => Kind::Thinking,
                    Some("tool_use") => {
                        let t = self.next_tool;
                        self.next_tool += 1;
                        out.push(self.chunk(
                            json!({ "tool_calls": [{ "index": t, "id": cb.get("id"), "type": "function", "function": { "name": cb.get("name"), "arguments": "" } }] }),
                            None,
                        ));
                        Kind::Tool(t)
                    }
                    _ => Kind::Other,
                };
                if kind == Kind::Text
                    && let Some(t) = cb.get("text").and_then(Value::as_str).filter(|s| !s.is_empty())
                {
                    out.push(self.chunk(json!({ "content": t }), None));
                }
                self.blocks.insert(index, kind);
            }
            Some("content_block_delta") => {
                let index = ev.get("index").and_then(Value::as_u64).unwrap_or(0);
                let d = ev.get("delta").unwrap_or(&Value::Null);
                let s = |k: &str| d.get(k).and_then(Value::as_str).unwrap_or_default().to_owned();
                match (d.get("type").and_then(Value::as_str), self.blocks.get(&index)) {
                    (Some("text_delta"), _) => out.push(self.chunk(json!({ "content": s("text") }), None)),
                    (Some("thinking_delta"), _) => {
                        out.push(self.chunk(json!({ "reasoning_content": s("thinking") }), None))
                    }
                    (Some("input_json_delta"), Some(Kind::Tool(t))) => {
                        out.push(self.chunk(
                            json!({ "tool_calls": [{ "index": t, "function": { "arguments": s("partial_json") } }] }),
                            None,
                        ));
                    }
                    _ => {}
                }
            }
            Some("message_delta") => {
                if let Some(r) = ev.pointer("/delta/stop_reason").and_then(Value::as_str) {
                    self.finish = Some(finish_reason_from_anthropic(Some(r)));
                }
            }
            Some("message_stop") => {
                out.push(self.chunk(json!({}), Some(self.finish.unwrap_or("stop"))));
                let usage = json!({ "id": self.id, "object": "chat.completion.chunk", "created": self.created, "model": self.model, "choices": [], "usage": openai_usage(self.usage.usage()) });
                out.push(usage.to_string());
                out.push("[DONE]".to_owned());
                self.done = true;
            }
            Some("error") => {
                out.push(json!({ "error": ev.get("error") }).to_string());
                self.done = true;
            }
            _ => {}
        }
        out
    }

    pub fn usage(&self) -> Usage {
        self.usage.usage()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(delta: Value, finish: Option<&str>) -> Value {
        json!({"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]})
    }

    fn types(evs: &[Value]) -> Vec<String> {
        evs.iter()
            .map(|e| {
                let t = e["type"].as_str().unwrap().to_owned();
                match e
                    .get("content_block")
                    .or_else(|| e.get("delta"))
                    .and_then(|d| d.get("type"))
                    .and_then(Value::as_str)
                {
                    Some(sub) if t.starts_with("content_block") => format!("{t}:{sub}"),
                    _ => t,
                }
            })
            .collect()
    }

    #[test]
    fn thinking_text_and_tool_use_stream() {
        let mut s = OpenAiToAnthropicStream::new("local/qwen");
        let mut evs = vec![];
        evs.extend(s.push(&chunk(json!({"role": "assistant"}), None)));
        evs.extend(s.push(&chunk(json!({"reasoning_content": "Think"}), None)));
        evs.extend(s.push(&chunk(json!({"reasoning_content": "ing."}), None)));
        evs.extend(s.push(&chunk(json!({"content": "Hello"}), None)));
        evs.extend(s.push(&chunk(json!({"tool_calls": [{"index": 0, "id": "call_a", "type": "function", "function": {"name": "f", "arguments": ""}}]}), None)));
        evs.extend(s.push(&chunk(json!({"tool_calls": [{"index": 0, "function": {"arguments": "{\"a\":"}}]}), None)));
        evs.extend(s.push(&chunk(json!({"tool_calls": [{"index": 0, "function": {"arguments": "1}"}}]}), None)));
        evs.extend(s.push(&chunk(json!({}), Some("tool_calls"))));
        evs.extend(s.push(&json!({"id": "c1", "choices": [], "usage": {"prompt_tokens": 9, "completion_tokens": 4}})));
        evs.extend(s.finish(Usage { prompt_tokens: 9, completion_tokens: 4, ..Usage::default() }));
        assert_eq!(
            types(&evs),
            [
                "message_start",
                "ping",
                "content_block_start:thinking",
                "content_block_delta:thinking_delta",
                "content_block_delta:thinking_delta",
                "content_block_stop",
                "content_block_start:text",
                "content_block_delta:text_delta",
                "content_block_stop",
                "content_block_start:tool_use",
                "content_block_delta:input_json_delta",
                "content_block_delta:input_json_delta",
                "content_block_stop",
                "message_delta",
                "message_stop"
            ]
        );
        assert_eq!(evs[0]["message"]["id"], "msg_c1");
        assert_eq!(evs[0]["message"]["model"], "local/qwen");
        assert_eq!(evs[9]["content_block"], json!({"type": "tool_use", "id": "call_a", "name": "f", "input": {}}));
        assert_eq!(evs[9]["index"], 2);
        let json: String =
            evs.iter().filter_map(|e| e.pointer("/delta/partial_json").and_then(Value::as_str)).collect();
        assert_eq!(json, r#"{"a":1}"#);
        let md = &evs[evs.len() - 2];
        assert_eq!(md["delta"]["stop_reason"], "tool_use");
        assert_eq!(md["usage"]["output_tokens"], 4);
        assert_eq!(md["usage"]["input_tokens"], 9);
        assert!(s.finish(Usage::default()).is_empty(), "finish is idempotent");
    }

    #[test]
    fn empty_stream_still_produces_a_valid_message() {
        let mut s = OpenAiToAnthropicStream::new("m");
        let t = types(&s.finish(Usage::default()));
        assert_eq!(t, ["message_start", "ping", "message_delta", "message_stop"]);
    }

    #[test]
    fn anthropic_events_to_openai_chunks() {
        let evs = [
            json!({"type": "message_start", "message": {"id": "msg_1", "model": "claude-x", "usage": {"input_tokens": 12, "cache_read_input_tokens": 3, "output_tokens": 1}}}),
            json!({"type": "ping"}),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "hm"}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "x"}}),
            json!({"type": "content_block_stop", "index": 0}),
            json!({"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
            json!({"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "Hi"}}),
            json!({"type": "content_block_start", "index": 2, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "f", "input": {}}}),
            json!({"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": "{\"a\":1}"}}),
            json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 20}}),
            json!({"type": "message_stop"}),
        ];
        let mut s = AnthropicToOpenAiStream::new();
        let out: Vec<String> = evs.iter().flat_map(|e| s.push(e)).collect();
        assert_eq!(out.last().unwrap(), "[DONE]");
        let chunks: Vec<Value> = out[..out.len() - 1].iter().map(|c| serde_json::from_str(c).unwrap()).collect();
        assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(chunks[1]["choices"][0]["delta"]["reasoning_content"], "hm");
        assert_eq!(chunks[2]["choices"][0]["delta"]["content"], "Hi");
        assert_eq!(chunks[3]["choices"][0]["delta"]["tool_calls"][0]["id"], "toolu_1");
        assert_eq!(chunks[4]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"], "{\"a\":1}");
        assert_eq!(chunks[5]["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(chunks[6]["usage"]["prompt_tokens"], 15);
        assert_eq!(chunks[6]["usage"]["completion_tokens"], 20);
        assert_eq!(chunks[0]["model"], "claude-x");
        assert!(s.is_done());
        assert_eq!(
            s.usage(),
            Usage { prompt_tokens: 15, completion_tokens: 20, cached_prompt_tokens: 3, ..Usage::default() }
        );
    }

    #[test]
    fn stream_usage_tracks_start_delta_and_cache_writes() {
        let mut u = AnthropicUsage::default();
        assert!(!u.has_input() && !u.is_complete());
        u.observe(&json!({"type": "message_start", "message": {"usage": {"input_tokens": 4, "cache_read_input_tokens": 10, "cache_creation_input_tokens": 30,
            "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 30}, "output_tokens": 1}}}));
        assert!(u.has_input() && !u.is_complete(), "input known, output not final");
        u.observe(&json!({"type": "message_delta", "usage": {"output_tokens": 9}}));
        assert!(u.is_complete());
        assert_eq!(
            u.usage(),
            Usage {
                prompt_tokens: 44,
                completion_tokens: 9,
                cached_prompt_tokens: 10,
                cache_write_tokens: 30,
                cache_write_1h_tokens: 30
            }
        );
        // Translated for an OpenAI client, the cache writes survive.
        assert_eq!(Usage::from_openai(&json!({"usage": openai_usage(u.usage())})), Some(u.usage()));
    }
}
