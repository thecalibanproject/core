//! Request translation: Anthropic Messages ⇄ IR (OpenAI Chat Completions shape).

use crate::{CalibanExt, ChatRequest, Message, ReasoningPref};
use serde_json::{Map, Value, json};

/// Invalid Anthropic request (rendered as `invalid_request_error`).
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseError {}

fn err(s: impl Into<String>) -> ParseError {
    ParseError(s.into())
}

fn msg(role: &str, content: Value) -> Message {
    Message { role: role.to_owned(), content, extra: Map::new() }
}

fn str_of<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

// ───────────────────────────── Anthropic → IR ─────────────────────────────

/// Parses an Anthropic Messages request into the IR.
///
/// - `system` (string or text blocks) becomes a leading system message.
/// - Content blocks: `text` → text parts, `image` (base64/url) → `image_url`, `document`
///   (text/PDF) → text/`file` parts, `tool_use` → assistant `tool_calls`, `tool_result` → `tool`
///   messages (emitted before the rest of the user turn, as OpenAI requires).
/// - `thinking` maps to the `caliban.reasoning` preference (budget ≤2k low, ≤8k medium, else
///   high); prior `thinking` blocks are dropped (they only round-trip to Anthropic itself).
/// - `stop_sequences` → `stop`, `metadata.user_id` → `user`, `tool_choice` and
///   `disable_parallel_tool_use` → `tool_choice` / `parallel_tool_calls`.
/// - Blocks only Anthropic understands (server-tool results, search results, …) are skipped here;
///   they still reach Anthropic models through the native passthrough.
pub fn to_chat_request(body: &Value) -> Result<ChatRequest, ParseError> {
    let obj = body.as_object().ok_or_else(|| err("request body must be a JSON object"))?;
    let model = obj.get("model").and_then(Value::as_str).ok_or_else(|| err("model: Field required"))?.to_owned();
    let max_tokens = obj.get("max_tokens").and_then(Value::as_u64).ok_or_else(|| err("max_tokens: Field required"))?;
    let input = obj.get("messages").and_then(Value::as_array).ok_or_else(|| err("messages: Field required"))?;

    let mut messages = Vec::new();
    match obj.get("system") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => {
            if !s.is_empty() {
                messages.push(msg("system", Value::String(s.clone())));
            }
        }
        Some(Value::Array(blocks)) => {
            let text = blocks.iter().filter(|b| str_of(b, "type") == Some("text")).filter_map(|b| str_of(b, "text")).collect::<Vec<_>>().join("\n\n");
            if !text.is_empty() {
                messages.push(msg("system", Value::String(text)));
            }
        }
        Some(_) => return Err(err("system: must be a string or an array of text blocks")),
    }
    for (i, m) in input.iter().enumerate() {
        match m.get("role").and_then(Value::as_str) {
            Some("user") => user_message(m.get("content"), i, &mut messages)?,
            Some("assistant") => assistant_message(m.get("content"), i, &mut messages)?,
            Some(other) => return Err(err(format!("messages.{i}.role: unexpected role '{other}'"))),
            None => return Err(err(format!("messages.{i}.role: Field required"))),
        }
    }

    let mut extra = Map::new();
    extra.insert("max_tokens".into(), max_tokens.into());
    for k in ["temperature", "top_p"] {
        if let Some(v) = obj.get(k).filter(|v| !v.is_null()) {
            extra.insert(k.into(), v.clone());
        }
    }
    if let Some(stops) = obj.get("stop_sequences").and_then(Value::as_array).filter(|a| !a.is_empty()) {
        extra.insert("stop".into(), Value::Array(stops.clone()));
    }
    if let Some(user) = obj.get("metadata").and_then(|m| str_of(m, "user_id")) {
        extra.insert("user".into(), Value::String(user.to_owned()));
    }
    let tools: Vec<Value> = obj.get("tools").and_then(Value::as_array).map(|ts| ts.iter().filter_map(tool_to_openai).collect()).unwrap_or_default();
    if !tools.is_empty() {
        extra.insert("tools".into(), Value::Array(tools));
        if let Some(tc) = obj.get("tool_choice") {
            if let Some(c) = tool_choice_to_openai(tc) {
                extra.insert("tool_choice".into(), c);
            }
            if tc.get("disable_parallel_tool_use").and_then(Value::as_bool) == Some(true) {
                extra.insert("parallel_tool_calls".into(), Value::Bool(false));
            }
        }
    }

    let mut caliban = match obj.get("caliban") {
        None | Some(Value::Null) => None,
        Some(v) => Some(serde_json::from_value::<CalibanExt>(v.clone()).map_err(|e| err(format!("caliban: {e}")))?),
    };
    if let Some(pref) = obj.get("thinking").and_then(thinking_pref) {
        let ext = caliban.get_or_insert_with(CalibanExt::default);
        ext.reasoning.get_or_insert(pref);
    }
    let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
    Ok(ChatRequest { model, messages, stream, caliban, extra })
}

fn thinking_pref(t: &Value) -> Option<ReasoningPref> {
    match str_of(t, "type")? {
        "disabled" => Some(ReasoningPref::Off),
        "enabled" => Some(match t.get("budget_tokens").and_then(Value::as_u64).unwrap_or(0) {
            0..=2048 => ReasoningPref::Low,
            2049..=8192 => ReasoningPref::Medium,
            _ => ReasoningPref::High,
        }),
        _ => None,
    }
}

fn user_message(content: Option<&Value>, i: usize, out: &mut Vec<Message>) -> Result<(), ParseError> {
    match content {
        Some(Value::String(s)) => out.push(msg("user", Value::String(s.clone()))),
        Some(Value::Array(blocks)) => {
            let mut parts = Vec::new();
            for b in blocks {
                match str_of(b, "type") {
                    Some("text") => parts.push(json!({ "type": "text", "text": str_of(b, "text").unwrap_or_default() })),
                    Some("image") => parts.push(image_to_openai(b).ok_or_else(|| err(format!("messages.{i}: unsupported image source")))?),
                    Some("document") => parts.extend(document_to_openai(b)),
                    Some("tool_result") => out.push(tool_result_to_openai(b)),
                    _ => {}
                }
            }
            if parts.len() == 1 && str_of(&parts[0], "type") == Some("text") {
                out.push(msg("user", parts[0]["text"].clone()));
            } else if !parts.is_empty() {
                out.push(msg("user", Value::Array(parts)));
            }
        }
        _ => return Err(err(format!("messages.{i}.content: Field required"))),
    }
    Ok(())
}

fn assistant_message(content: Option<&Value>, i: usize, out: &mut Vec<Message>) -> Result<(), ParseError> {
    match content {
        Some(Value::String(s)) => out.push(msg("assistant", Value::String(s.clone()))),
        Some(Value::Array(blocks)) => {
            let mut texts = Vec::new();
            let mut calls = Vec::new();
            for b in blocks {
                match str_of(b, "type") {
                    Some("text") => texts.extend(str_of(b, "text").filter(|t| !t.is_empty())),
                    Some("tool_use") => calls.push(json!({
                        "id": str_of(b, "id").unwrap_or_default(),
                        "type": "function",
                        "function": {
                            "name": str_of(b, "name").unwrap_or_default(),
                            "arguments": b.get("input").map_or_else(|| "{}".to_owned(), Value::to_string),
                        }
                    })),
                    // thinking / redacted_thinking carry Anthropic signatures; other models ignore them.
                    _ => {}
                }
            }
            let text = texts.join("\n\n");
            let content = if text.is_empty() && !calls.is_empty() { Value::Null } else { Value::String(text) };
            let mut m = msg("assistant", content);
            if !calls.is_empty() {
                m.extra.insert("tool_calls".into(), Value::Array(calls));
            }
            out.push(m);
        }
        _ => return Err(err(format!("messages.{i}.content: Field required"))),
    }
    Ok(())
}

fn image_to_openai(b: &Value) -> Option<Value> {
    let src = b.get("source")?;
    let url = match str_of(src, "type")? {
        "base64" => format!("data:{};base64,{}", str_of(src, "media_type")?, str_of(src, "data")?),
        "url" => str_of(src, "url")?.to_owned(),
        _ => return None,
    };
    Some(json!({ "type": "image_url", "image_url": { "url": url } }))
}

fn document_to_openai(b: &Value) -> Option<Value> {
    let src = b.get("source")?;
    match str_of(src, "type")? {
        "text" => Some(json!({ "type": "text", "text": str_of(src, "data")? })),
        "content" => {
            let text = blocks_text(src.get("content")?);
            Some(json!({ "type": "text", "text": text }))
        }
        "base64" => {
            let media = str_of(src, "media_type").unwrap_or("application/pdf");
            Some(json!({ "type": "file", "file": {
                "filename": str_of(b, "title").unwrap_or("document.pdf"),
                "file_data": format!("data:{media};base64,{}", str_of(src, "data")?),
            }}))
        }
        _ => None,
    }
}

/// Text of a string or an array of blocks (non-text blocks become a placeholder).
fn blocks_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .map(|b| match str_of(b, "type") {
                Some("text") => str_of(b, "text").unwrap_or_default().to_owned(),
                Some(other) => format!("[{other}]"),
                None => String::new(),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn tool_result_to_openai(b: &Value) -> Message {
    let mut text = b.get("content").map(blocks_text).unwrap_or_default();
    if b.get("is_error").and_then(Value::as_bool) == Some(true) {
        text = format!("Error: {text}");
    }
    let mut m = msg("tool", Value::String(text));
    m.extra.insert("tool_call_id".into(), Value::String(str_of(b, "tool_use_id").unwrap_or_default().to_owned()));
    m
}

/// Client tools only; server tools (`web_search_…`, `bash_…`) have no schema to translate.
fn tool_to_openai(t: &Value) -> Option<Value> {
    let schema = t.get("input_schema")?;
    let mut f = Map::new();
    f.insert("name".into(), t.get("name")?.clone());
    if let Some(d) = t.get("description") {
        f.insert("description".into(), d.clone());
    }
    f.insert("parameters".into(), schema.clone());
    Some(json!({ "type": "function", "function": f }))
}

fn tool_choice_to_openai(tc: &Value) -> Option<Value> {
    Some(match str_of(tc, "type")? {
        "auto" => json!("auto"),
        "any" => json!("required"),
        "none" => json!("none"),
        "tool" => json!({ "type": "function", "function": { "name": str_of(tc, "name")? } }),
        _ => return None,
    })
}

/// Visits every text segment the client wrote: `system` (string or text blocks), message text
/// (string or `text` blocks), `tool_result` content and plain-text documents. Used to apply PII
/// protection to a native body without disturbing `cache_control` or other block fields.
/// (`tool_use.input` is not visited, matching tool-call arguments on the OpenAI path.)
pub fn for_each_text_mut(body: &mut Value, mut f: impl FnMut(&mut String)) {
    if let Some(sys) = body.get_mut("system") {
        visit(sys, &mut f);
    }
    if let Some(msgs) = body.get_mut("messages").and_then(Value::as_array_mut) {
        for m in msgs {
            if let Some(c) = m.get_mut("content") {
                visit(c, &mut f);
            }
        }
    }
}

fn visit(v: &mut Value, f: &mut dyn FnMut(&mut String)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(blocks) => {
            for b in blocks {
                match b.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(Value::String(s)) = b.get_mut("text") {
                            f(s);
                        }
                    }
                    Some("tool_result") => {
                        if let Some(c) = b.get_mut("content") {
                            visit(c, f);
                        }
                    }
                    Some("document") if b.pointer("/source/type").and_then(Value::as_str) == Some("text") => {
                        if let Some(Value::String(s)) = b.pointer_mut("/source/data") {
                            f(s);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

// ───────────────────────────── IR → Anthropic ─────────────────────────────

/// Translates an OpenAI-shaped upstream body (what [`ChatRequest::to_openai_upstream`] and the
/// quirks produce) into an Anthropic Messages request.
///
/// `reasoning_effort` becomes `thinking` (low 1024 / medium 4096 / high 16384 budget tokens,
/// with `max_tokens` raised above the budget and sampling params dropped, as Anthropic requires).
/// Engine-specific fields (`cache_salt`, `chat_template_kwargs`, `stream_options`, penalties…)
/// are dropped.
pub fn to_anthropic_request(body: &Value, default_max_tokens: u64) -> Value {
    let Some(obj) = body.as_object() else { return body.clone() };
    let mut system: Vec<String> = Vec::new();
    let mut turns: Vec<(&'static str, Vec<Value>)> = Vec::new();
    let mut push = |role: &'static str, blocks: Vec<Value>| {
        if blocks.is_empty() {
            return;
        }
        match turns.last_mut() {
            // Anthropic wants alternating turns; consecutive same-role messages are merged.
            Some((r, b)) if *r == role => b.extend(blocks),
            _ => turns.push((role, blocks)),
        }
    };
    for m in obj.get("messages").and_then(Value::as_array).into_iter().flatten() {
        let content = m.get("content").unwrap_or(&Value::Null);
        match str_of(m, "role") {
            Some("system" | "developer") => system.push(text_of(content)),
            Some("user") => push("user", user_blocks(content)),
            Some("assistant") => {
                let mut blocks = Vec::new();
                let text = text_of(content);
                if !text.is_empty() {
                    blocks.push(json!({ "type": "text", "text": text }));
                }
                for call in m.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
                    let args = call.pointer("/function/arguments").and_then(Value::as_str).unwrap_or("{}");
                    let input = serde_json::from_str::<Value>(args).ok().filter(Value::is_object).unwrap_or_else(|| json!({}));
                    blocks.push(json!({
                        "type": "tool_use",
                        "id": str_of(call, "id").unwrap_or_default(),
                        "name": call.pointer("/function/name").and_then(Value::as_str).unwrap_or_default(),
                        "input": input,
                    }));
                }
                push("assistant", blocks);
            }
            Some("tool") => push(
                "user",
                vec![json!({ "type": "tool_result", "tool_use_id": str_of(m, "tool_call_id").unwrap_or_default(), "content": text_of(content) })],
            ),
            _ => {}
        }
    }

    let mut out = Map::new();
    out.insert("model".into(), obj.get("model").cloned().unwrap_or(Value::Null));
    if !system.is_empty() {
        out.insert("system".into(), Value::String(system.join("\n\n")));
    }
    out.insert(
        "messages".into(),
        Value::Array(turns.into_iter().map(|(role, blocks)| json!({ "role": role, "content": blocks })).collect()),
    );
    let mut max_tokens = ["max_completion_tokens", "max_tokens"].iter().find_map(|k| obj.get(*k).and_then(Value::as_u64)).unwrap_or(default_max_tokens);
    let budget = match obj.get("reasoning_effort").and_then(Value::as_str) {
        Some("low") => Some(1024),
        Some("medium") => Some(4096),
        Some("high") => Some(16384),
        _ => None,
    };
    if let Some(b) = budget {
        if max_tokens <= b {
            max_tokens += b;
        }
        out.insert("thinking".into(), json!({ "type": "enabled", "budget_tokens": b }));
    } else {
        if let Some(t) = obj.get("temperature").and_then(Value::as_f64) {
            out.insert("temperature".into(), json!(t.clamp(0.0, 1.0)));
        }
        if let Some(p) = obj.get("top_p").filter(|v| v.is_number()) {
            out.insert("top_p".into(), p.clone());
        }
    }
    out.insert("max_tokens".into(), max_tokens.into());
    match obj.get("stop") {
        Some(Value::String(s)) => {
            out.insert("stop_sequences".into(), json!([s]));
        }
        Some(Value::Array(a)) if !a.is_empty() => {
            out.insert("stop_sequences".into(), Value::Array(a.clone()));
        }
        _ => {}
    }
    if obj.get("stream").and_then(Value::as_bool) == Some(true) {
        out.insert("stream".into(), Value::Bool(true));
    }
    let tools: Vec<Value> = obj
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|t| {
            let f = t.get("function")?;
            let mut a = Map::new();
            a.insert("name".into(), f.get("name")?.clone());
            if let Some(d) = f.get("description") {
                a.insert("description".into(), d.clone());
            }
            a.insert("input_schema".into(), f.get("parameters").cloned().unwrap_or_else(|| json!({ "type": "object", "properties": {} })));
            Some(Value::Object(a))
        })
        .collect();
    if !tools.is_empty() {
        let mut choice = match obj.get("tool_choice") {
            Some(Value::String(s)) if s == "required" => Some(json!({ "type": "any" })),
            Some(Value::String(s)) if s == "none" => Some(json!({ "type": "none" })),
            Some(Value::String(s)) if s == "auto" => Some(json!({ "type": "auto" })),
            Some(v @ Value::Object(_)) => v.pointer("/function/name").map(|n| json!({ "type": "tool", "name": n })),
            _ => None,
        };
        if obj.get("parallel_tool_calls").and_then(Value::as_bool) == Some(false) {
            let c = choice.get_or_insert_with(|| json!({ "type": "auto" }));
            c["disable_parallel_tool_use"] = Value::Bool(true);
        }
        out.insert("tools".into(), Value::Array(tools));
        if let Some(c) = choice {
            out.insert("tool_choice".into(), c);
        }
    }
    if let Some(user) = obj.get("user").and_then(Value::as_str) {
        out.insert("metadata".into(), json!({ "user_id": user }));
    }
    Value::Object(out)
}

fn text_of(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts.iter().filter_map(|p| str_of(p, "text")).collect::<Vec<_>>().join("\n"),
        _ => String::new(),
    }
}

fn user_blocks(content: &Value) -> Vec<Value> {
    match content {
        Value::String(s) if !s.is_empty() => vec![json!({ "type": "text", "text": s })],
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| match str_of(p, "type") {
                Some("text") => str_of(p, "text").filter(|t| !t.is_empty()).map(|t| json!({ "type": "text", "text": t })),
                Some("image_url") => {
                    let url = p.pointer("/image_url/url").and_then(Value::as_str)?;
                    Some(match parse_data_url(url) {
                        Some((media, data)) => json!({ "type": "image", "source": { "type": "base64", "media_type": media, "data": data } }),
                        None => json!({ "type": "image", "source": { "type": "url", "url": url } }),
                    })
                }
                Some("file") => {
                    let (media, data) = parse_data_url(p.pointer("/file/file_data").and_then(Value::as_str)?)?;
                    Some(json!({ "type": "document", "source": { "type": "base64", "media_type": media, "data": data } }))
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// `data:<media>;base64,<data>` → (media, data).
fn parse_data_url(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    Some((meta.strip_suffix(";base64")?, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_block_system_images_and_params() {
        let body = json!({
            "model": "claude-x", "max_tokens": 256, "temperature": 0.2, "stop_sequences": ["END"],
            "metadata": {"user_id": "u-1"}, "stream": true,
            "system": [{"type": "text", "text": "You are terse.", "cache_control": {"type": "ephemeral"}}, {"type": "text", "text": "Answer in French."}],
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "What is in this picture?"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBOR"}},
                {"type": "image", "source": {"type": "url", "url": "https://x/y.jpg"}}
            ]}]
        });
        let r = to_chat_request(&body).unwrap();
        assert_eq!(r.model, "claude-x");
        assert!(r.stream);
        assert_eq!(r.messages[0].role, "system");
        assert_eq!(r.messages[0].content, "You are terse.\n\nAnswer in French.");
        let parts = r.messages[1].content.as_array().unwrap();
        assert_eq!(parts[1]["image_url"]["url"], "data:image/png;base64,iVBOR");
        assert_eq!(parts[2]["image_url"]["url"], "https://x/y.jpg");
        assert_eq!(r.extra["max_tokens"], 256);
        assert_eq!(r.extra["stop"], json!(["END"]));
        assert_eq!(r.extra["user"], "u-1");
        assert!(r.has_images());
        let up = r.to_openai_upstream("m");
        assert!(up.get("system").is_none() && up.get("metadata").is_none());
    }

    #[test]
    fn tool_use_round_trip_into_ir() {
        let body = json!({
            "model": "m", "max_tokens": 100,
            "tools": [{"name": "get_weather", "description": "Weather", "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}},
                      {"type": "web_search_20250305", "name": "web_search"}],
            "tool_choice": {"type": "any", "disable_parallel_tool_use": true},
            "messages": [
                {"role": "user", "content": "Weather in Paris?"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "need tool", "signature": "sig"},
                    {"type": "text", "text": "Checking."},
                    {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Paris"}}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "18C"}]},
                    {"type": "text", "text": "Thanks"}]}
            ]
        });
        let r = to_chat_request(&body).unwrap();
        let tools = r.extra["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1, "server tools are not translatable");
        assert_eq!(tools[0]["function"]["parameters"]["properties"]["city"]["type"], "string");
        assert_eq!(r.extra["tool_choice"], "required");
        assert_eq!(r.extra["parallel_tool_calls"], false);
        let roles: Vec<&str> = r.messages.iter().map(|m| m.role.as_str()).collect();
        assert_eq!(roles, ["user", "assistant", "tool", "user"]);
        let a = &r.messages[1];
        assert_eq!(a.content, "Checking.");
        assert_eq!(a.extra["tool_calls"][0]["function"]["arguments"], r#"{"city":"Paris"}"#);
        assert_eq!(r.messages[2].extra["tool_call_id"], "toolu_1");
        assert_eq!(r.messages[2].content, "18C");
        assert_eq!(r.messages[3].content, "Thanks");
    }

    #[test]
    fn thinking_maps_to_reasoning_preference() {
        let mk = |t: Value| to_chat_request(&json!({"model": "m", "max_tokens": 1, "messages": [], "thinking": t})).unwrap().reasoning_pref();
        assert_eq!(mk(json!({"type": "enabled", "budget_tokens": 1024})), Some(ReasoningPref::Low));
        assert_eq!(mk(json!({"type": "enabled", "budget_tokens": 4000})), Some(ReasoningPref::Medium));
        assert_eq!(mk(json!({"type": "enabled", "budget_tokens": 32000})), Some(ReasoningPref::High));
        assert_eq!(mk(json!({"type": "disabled"})), Some(ReasoningPref::Off));
        // An explicit caliban.reasoning wins.
        let r = to_chat_request(&json!({"model": "m", "max_tokens": 1, "messages": [], "thinking": {"type": "disabled"}, "caliban": {"reasoning": "high"}})).unwrap();
        assert_eq!(r.reasoning_pref(), Some(ReasoningPref::High));
    }

    #[test]
    fn validation_errors() {
        assert!(to_chat_request(&json!({"model": "m", "messages": []})).unwrap_err().0.contains("max_tokens"));
        assert!(to_chat_request(&json!({"max_tokens": 1, "messages": []})).unwrap_err().0.contains("model"));
        assert!(to_chat_request(&json!({"model": "m", "max_tokens": 1, "messages": [{"role": "system", "content": "x"}]})).is_err());
        assert!(to_chat_request(&json!({"model": "m", "max_tokens": 1, "messages": [], "caliban": {"bogus": 1}})).is_err());
    }

    #[test]
    fn text_visitor_covers_system_text_and_tool_results_only() {
        let mut body = json!({
            "system": [{"type": "text", "text": "s", "cache_control": {"type": "ephemeral"}}],
            "messages": [
                {"role": "user", "content": "a"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "n", "input": {"q": "x"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": "r"},
                                             {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
                                             {"type": "text", "text": "b", "cache_control": {"type": "ephemeral"}}]}
            ]
        });
        let mut seen = vec![];
        for_each_text_mut(&mut body, |s| {
            seen.push(s.clone());
            s.push('!');
        });
        assert_eq!(seen, ["s", "a", "r", "b"]);
        assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(body["messages"][2]["content"][2]["text"], "b!");
    }

    #[test]
    fn openai_body_to_anthropic() {
        let body = json!({
            "model": "claude-sonnet", "stream": true, "stream_options": {"include_usage": true}, "cache_salt": "x",
            "temperature": 1.5, "stop": "###", "user": "u", "parallel_tool_calls": false,
            "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": [{"type": "text", "text": "hi"}, {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,/9j"}}]},
                {"role": "assistant", "content": null, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{\"a\":1}"}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "ok"},
                {"role": "tool", "tool_call_id": "c2", "content": "ok2"}
            ],
            "tools": [{"type": "function", "function": {"name": "f", "parameters": {"type": "object"}}}],
            "tool_choice": "required"
        });
        let a = to_anthropic_request(&body, 4096);
        assert_eq!(a["system"], "sys");
        assert_eq!(a["max_tokens"], 4096);
        assert_eq!(a["temperature"], 1.0);
        assert_eq!(a["stop_sequences"], json!(["###"]));
        assert_eq!(a["metadata"]["user_id"], "u");
        assert_eq!(a["tool_choice"], json!({"type": "any", "disable_parallel_tool_use": true}));
        assert_eq!(a["tools"][0]["input_schema"]["type"], "object");
        assert!(a.get("cache_salt").is_none() && a.get("stream_options").is_none());
        let msgs = a["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0]["content"][1]["source"], json!({"type": "base64", "media_type": "image/jpeg", "data": "/9j"}));
        assert_eq!(msgs[1]["content"][0], json!({"type": "tool_use", "id": "c1", "name": "f", "input": {"a": 1}}));
        // Both tool results merged into one user turn.
        assert_eq!(msgs[2]["content"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn reasoning_effort_becomes_thinking() {
        let a = to_anthropic_request(&json!({"model": "m", "max_tokens": 1000, "temperature": 0.3, "reasoning_effort": "medium", "messages": [{"role": "user", "content": "x"}]}), 4096);
        assert_eq!(a["thinking"], json!({"type": "enabled", "budget_tokens": 4096}));
        assert_eq!(a["max_tokens"], 5096);
        assert!(a.get("temperature").is_none());
    }
}
