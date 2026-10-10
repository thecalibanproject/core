//! How a chat request becomes a node's input (`model: "node/<name>"` on chat completions and
//! messages, and `caliban/auto` handing a request to a node), and how a node's output becomes the
//! assistant's answer.
//!
//! The input, from the conversation's messages:
//! - **The node declares `prompt.input_schema`:** the last user message, if it is JSON matching the
//!   schema, is the input as is (structured input over chat). Otherwise the text is placed where
//!   the schema expects text: the whole input for a `string` schema, or the one string property of
//!   an object schema that has exactly one (required, or the only property), e.g.
//!   `{"case": "<text>"}`. Any other schema refuses the request, saying what it expects.
//! - **No input schema:** `exposure.chat_input` in the spec chooses: `"text"` (the default) is the
//!   last user message's text; `"messages"` is `{"messages": [{"role", "content"}, ...]}` with every
//!   message's text, system messages included.
//!
//! The answer: a string output is the assistant's text as is; any other output is compact JSON.

use crate::NodeSpec;
use serde_json::{Value, json};

/// The text of a message's `content` (a string, or the text parts of an array).
pub fn message_text(m: &Value) -> String {
    match m.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => {
            parts.iter().filter_map(|p| p.get("text").and_then(Value::as_str)).collect::<Vec<_>>().join("\n")
        }
        _ => String::new(),
    }
}

/// The last user message's text.
pub fn last_user_text(messages: &[Value]) -> Option<String> {
    messages.iter().rev().find(|m| m.get("role").and_then(Value::as_str) == Some("user")).map(message_text)
}

/// The run input for a node from chat messages (OpenAI shape: `role`, `content`).
pub fn input_from_messages(spec: &NodeSpec, messages: &[Value]) -> Result<Value, String> {
    let text = last_user_text(messages).filter(|t| !t.trim().is_empty());
    match spec.input_schema() {
        Some(schema) => {
            let text = text.ok_or("the conversation has no user message to give the node")?;
            if let Ok(v) = serde_json::from_str::<Value>(text.trim())
                && v.is_object()
                && crate::schema::validate(schema, &v).is_ok()
            {
                return Ok(v);
            }
            if schema.get("type").and_then(Value::as_str) == Some("string") {
                return Ok(Value::String(text));
            }
            match text_property(schema) {
                Some(p) => Ok(json!({ p: text })),
                None => Err(format!(
                    "this node takes structured input: send it as one JSON object in the last user message, matching \
                     its input schema {schema}"
                )),
            }
        }
        None => match spec.rest.get("exposure").and_then(|e| e.get("chat_input")).and_then(Value::as_str) {
            Some("messages") => {
                let all: Vec<Value> = messages
                    .iter()
                    .map(|m| json!({"role": m.get("role").cloned().unwrap_or(Value::Null), "content": message_text(m)}))
                    .collect();
                if all.is_empty() {
                    return Err("the conversation has no messages".into());
                }
                Ok(json!({ "messages": all }))
            }
            _ => text.map(Value::String).ok_or_else(|| "the conversation has no user message to give the node".into()),
        },
    }
}

/// The one string property an object schema puts text in: its only required property, else its
/// only property, when that property is a string.
fn text_property(schema: &Value) -> Option<String> {
    let props = schema.get("properties")?.as_object()?;
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map_or(vec![], |r| r.iter().filter_map(Value::as_str).collect());
    let name = match (required.as_slice(), props.len()) {
        ([one], _) => (*one).to_owned(),
        ([], 1) => props.keys().next()?.clone(),
        _ => return None,
    };
    (props.get(&name)?.get("type").and_then(Value::as_str) == Some("string")).then_some(name)
}

/// The assistant's text for a node output.
pub fn output_text(output: &Value) -> String {
    match output {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// An answer to a human step from a chat message: JSON (an object, a boolean, a number) as
/// itself, anything else as text.
pub fn answer_from_text(text: &str) -> Value {
    match serde_json::from_str::<Value>(text.trim()) {
        Ok(v @ (Value::Object(_) | Value::Bool(_) | Value::Number(_))) => v,
        _ => Value::String(text.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(extra: Value) -> NodeSpec {
        let mut v = json!({"kind": "workflow", "budgets": {"steps": 1, "tokens": 10, "wall_clock_s": 1},
                           "graph": {"vertices": [{"id": "a", "type": "llm"}], "edges": []}});
        v.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        serde_json::from_value(v).unwrap()
    }

    fn msgs(texts: &[(&str, &str)]) -> Vec<Value> {
        texts.iter().map(|(r, t)| json!({"role": r, "content": t})).collect()
    }

    #[test]
    fn chat_messages_map_to_node_inputs() {
        let chat = msgs(&[("system", "be brief"), ("user", "first"), ("assistant", "ok"), ("user", "chest pain")]);
        // No schema: the last user text, or every message.
        assert_eq!(input_from_messages(&spec(json!({})), &chat).unwrap(), json!("chest pain"));
        let all = input_from_messages(&spec(json!({"exposure": {"chat_input": "messages"}})), &chat).unwrap();
        assert_eq!(all["messages"].as_array().unwrap().len(), 4);
        assert_eq!(all["messages"][0], json!({"role": "system", "content": "be brief"}));
        // A schema with one text property: the text goes there; JSON that matches is used as is.
        let triage = spec(json!({"prompt": {"input_schema": {"type": "object", "required": ["case"],
            "properties": {"case": {"type": "string"}}}}}));
        assert_eq!(input_from_messages(&triage, &chat).unwrap(), json!({"case": "chest pain"}));
        let structured = msgs(&[("user", r#"{"case": "given as JSON"}"#)]);
        assert_eq!(input_from_messages(&triage, &structured).unwrap(), json!({"case": "given as JSON"}));
        let parts = vec![json!({"role": "user", "content": [{"type": "text", "text": "in parts"}]})];
        assert_eq!(input_from_messages(&triage, &parts).unwrap(), json!({"case": "in parts"}));
        // A schema the text cannot fill is refused with what it expects.
        let two = spec(json!({"prompt": {"input_schema": {"type": "object", "required": ["a", "b"],
            "properties": {"a": {"type": "string"}, "b": {"type": "integer"}}}}}));
        assert!(input_from_messages(&two, &chat).unwrap_err().contains("structured input"));
        assert!(input_from_messages(&spec(json!({})), &msgs(&[("system", "x")])).is_err());
        // Answers and outputs.
        assert_eq!(answer_from_text("yes"), json!("yes"));
        assert_eq!(answer_from_text(r#"{"approve": true}"#), json!({"approve": true}));
        assert_eq!(output_text(&json!({"a": 1})), r#"{"a":1}"#);
        assert_eq!(output_text(&json!("plain")), "plain");
    }
}
