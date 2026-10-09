//! Non-streaming response translation: OpenAI chat completion ⇄ Anthropic message.

use crate::Usage;
use serde_json::{Value, json};

/// Anthropic `usage` from IR usage. Anthropic's `input_tokens` excludes cache reads and writes.
pub fn anthropic_usage(u: Usage) -> Value {
    json!({
        "input_tokens": u.uncached_prompt_tokens(),
        "output_tokens": u.completion_tokens,
        "cache_read_input_tokens": u.cached_prompt_tokens,
        "cache_creation_input_tokens": u.cache_write_tokens,
    })
}

/// OpenAI `usage` from IR usage. Cache writes (an Anthropic upstream translated for an OpenAI
/// client) are reported as `prompt_tokens_details.cache_write_tokens` (and
/// `cache_write_1h_tokens` for the 1-hour TTL), only when non-zero; OpenAI SDKs ignore the extra
/// keys, and the gateway meters cache writes from them.
pub fn openai_usage(u: Usage) -> Value {
    let mut details = json!({ "cached_tokens": u.cached_prompt_tokens });
    if u.cache_write_tokens > 0 {
        details["cache_write_tokens"] = json!(u.cache_write_tokens);
    }
    if u.cache_write_1h_tokens > 0 {
        details["cache_write_1h_tokens"] = json!(u.cache_write_1h_tokens);
    }
    json!({
        "prompt_tokens": u.prompt_tokens,
        "completion_tokens": u.completion_tokens,
        "total_tokens": u.prompt_tokens + u.completion_tokens,
        "prompt_tokens_details": details,
    })
}

pub(crate) fn stop_reason_from_openai(finish: Option<&str>) -> &'static str {
    match finish {
        Some("length") => "max_tokens",
        Some("tool_calls" | "function_call") => "tool_use",
        Some("content_filter") => "refusal",
        _ => "end_turn",
    }
}

pub(crate) fn finish_reason_from_anthropic(stop: Option<&str>) -> &'static str {
    match stop {
        Some("max_tokens" | "model_context_window_exceeded") => "length",
        Some("tool_use") => "tool_calls",
        Some("refusal") => "content_filter",
        _ => "stop",
    }
}

pub(crate) fn message_id(openai_id: Option<&str>) -> String {
    match openai_id {
        Some(id) if id.starts_with("msg_") => id.to_owned(),
        Some(id) if !id.is_empty() => format!("msg_{id}"),
        _ => "msg_caliban".to_owned(),
    }
}

/// Parses tool-call arguments into an object (`{}` when they are not valid JSON objects).
pub(crate) fn tool_input(args: Option<&str>) -> Value {
    args.and_then(|a| serde_json::from_str::<Value>(a).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}))
}

/// OpenAI chat completion (first choice) → Anthropic message. Reasoning (`reasoning_content` or
/// `reasoning`) becomes a leading `thinking` block (with an empty signature: it did not come from
/// Anthropic), then text, then `tool_use` blocks.
pub fn from_openai_response(v: &Value) -> Value {
    let choice = v.pointer("/choices/0");
    let msg = choice.and_then(|c| c.get("message"));
    let mut content = Vec::new();
    if let Some(r) = msg.and_then(|m| m.get("reasoning_content").or_else(|| m.get("reasoning"))).and_then(Value::as_str).filter(|s| !s.is_empty()) {
        content.push(json!({ "type": "thinking", "thinking": r, "signature": "" }));
    }
    if let Some(t) = msg.and_then(|m| m.get("content")).and_then(Value::as_str).filter(|s| !s.is_empty()) {
        content.push(json!({ "type": "text", "text": t }));
    }
    for call in msg.and_then(|m| m.get("tool_calls")).and_then(Value::as_array).into_iter().flatten() {
        content.push(json!({
            "type": "tool_use",
            "id": call.get("id").and_then(Value::as_str).unwrap_or_default(),
            "name": call.pointer("/function/name").and_then(Value::as_str).unwrap_or_default(),
            "input": tool_input(call.pointer("/function/arguments").and_then(Value::as_str)),
        }));
    }
    let finish = choice.and_then(|c| c.get("finish_reason")).and_then(Value::as_str);
    json!({
        "id": message_id(v.get("id").and_then(Value::as_str)),
        "type": "message",
        "role": "assistant",
        "model": v.get("model").cloned().unwrap_or(Value::Null),
        "content": content,
        "stop_reason": stop_reason_from_openai(finish),
        "stop_sequence": null,
        "usage": anthropic_usage(Usage::from_openai(v).unwrap_or_default()),
    })
}

/// Anthropic message → OpenAI chat completion. `thinking` blocks become `reasoning_content`.
pub fn to_openai_response(v: &Value) -> Value {
    let mut text = String::new();
    let mut thinking = String::new();
    let mut calls = Vec::new();
    for b in v.get("content").and_then(Value::as_array).into_iter().flatten() {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => text.push_str(b.get("text").and_then(Value::as_str).unwrap_or_default()),
            Some("thinking") => thinking.push_str(b.get("thinking").and_then(Value::as_str).unwrap_or_default()),
            Some("tool_use") => calls.push(json!({
                "id": b.get("id").cloned().unwrap_or(Value::Null),
                "type": "function",
                "function": { "name": b.get("name").cloned().unwrap_or(Value::Null), "arguments": b.get("input").map_or_else(|| "{}".to_owned(), Value::to_string) },
            })),
            _ => {}
        }
    }
    let mut message = json!({ "role": "assistant", "content": if text.is_empty() && !calls.is_empty() { Value::Null } else { Value::String(text) } });
    if !thinking.is_empty() {
        message["reasoning_content"] = Value::String(thinking);
    }
    if !calls.is_empty() {
        message["tool_calls"] = Value::Array(calls);
    }
    let usage = Usage::from_anthropic_usage(v.get("usage").unwrap_or(&Value::Null));
    json!({
        "id": v.get("id").cloned().unwrap_or(Value::Null),
        "object": "chat.completion",
        "created": now_secs(),
        "model": v.get("model").cloned().unwrap_or(Value::Null),
        "choices": [{ "index": 0, "message": message, "finish_reason": finish_reason_from_anthropic(v.get("stop_reason").and_then(Value::as_str)) }],
        "usage": openai_usage(usage),
    })
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_completion_with_reasoning_and_tools_to_anthropic() {
        let v = json!({
            "id": "chatcmpl-1", "model": "local/qwen",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": "Let me check.", "reasoning_content": "User wants weather.",
                "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]}}],
            "usage": {"prompt_tokens": 30, "completion_tokens": 12, "prompt_tokens_details": {"cached_tokens": 10}}
        });
        let a = from_openai_response(&v);
        assert_eq!(a["id"], "msg_chatcmpl-1");
        assert_eq!(a["type"], "message");
        assert_eq!(a["model"], "local/qwen");
        assert_eq!(a["stop_reason"], "tool_use");
        assert_eq!(a["content"][0], json!({"type": "thinking", "thinking": "User wants weather.", "signature": ""}));
        assert_eq!(a["content"][1], json!({"type": "text", "text": "Let me check."}));
        assert_eq!(a["content"][2], json!({"type": "tool_use", "id": "call_1", "name": "get_weather", "input": {"city": "Paris"}}));
        assert_eq!(a["usage"]["input_tokens"], 20);
        assert_eq!(a["usage"]["cache_read_input_tokens"], 10);
        assert_eq!(a["usage"]["output_tokens"], 12);
    }

    #[test]
    fn finish_reasons() {
        let mk = |f: &str| from_openai_response(&json!({"choices": [{"message": {"content": "x"}, "finish_reason": f}]}))["stop_reason"].clone();
        assert_eq!(mk("stop"), "end_turn");
        assert_eq!(mk("length"), "max_tokens");
    }

    #[test]
    fn anthropic_message_to_openai() {
        let v = json!({
            "id": "msg_1", "type": "message", "model": "claude-x", "stop_reason": "tool_use",
            "content": [{"type": "thinking", "thinking": "hmm", "signature": "s"}, {"type": "text", "text": "ok"},
                        {"type": "tool_use", "id": "toolu_1", "name": "f", "input": {"a": 1}}],
            "usage": {"input_tokens": 5, "cache_read_input_tokens": 100, "output_tokens": 9}
        });
        let o = to_openai_response(&v);
        let m = &o["choices"][0]["message"];
        assert_eq!(m["content"], "ok");
        assert_eq!(m["reasoning_content"], "hmm");
        assert_eq!(m["tool_calls"][0]["function"]["arguments"], r#"{"a":1}"#);
        assert_eq!(o["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(o["usage"]["prompt_tokens"], 105);
        assert_eq!(o["usage"]["prompt_tokens_details"]["cached_tokens"], 100);
    }
}
