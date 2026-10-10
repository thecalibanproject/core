//! Prompt templates and JSON extraction.
//!
//! Templates use `{{ expr }}` placeholders. `expr` is `input` or `outputs.<vertex>`, optionally
//! followed by `.field` or `.<index>` segments (`{{input.patient.age}}`, `{{outputs.classify.route}}`).
//! A string value is inserted as is, anything else as compact JSON; a missing value becomes an
//! empty string. In a JSON template ([`render_value`]), a string that is exactly one placeholder is
//! replaced by the value itself (so `{"q": "{{input}}"}` passes an object through as an object).

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// What placeholders can name.
pub struct Scope<'a> {
    pub input: &'a Value,
    pub outputs: &'a BTreeMap<String, Value>,
}

fn lookup(expr: &str, s: &Scope<'_>) -> Option<Value> {
    let mut parts = expr.trim().split('.');
    let mut cur: Value = match parts.next()? {
        "input" => s.input.clone(),
        "outputs" => s.outputs.get(parts.next()?)?.clone(),
        _ => return None,
    };
    for p in parts {
        cur = match &cur {
            Value::Object(m) => m.get(p)?.clone(),
            Value::Array(a) => a.get(p.parse::<usize>().ok()?)?.clone(),
            _ => return None,
        };
    }
    Some(cur)
}

/// `v` as template text: strings raw, everything else compact JSON.
pub fn as_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

pub fn render_str(tpl: &str, s: &Scope<'_>) -> String {
    let mut out = String::with_capacity(tpl.len());
    let mut rest = tpl;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                out.push_str(&lookup(&after[..end], s).map(|v| as_text(&v)).unwrap_or_default());
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn render_value(v: &Value, s: &Scope<'_>) -> Value {
    match v {
        Value::String(t) => {
            let trimmed = t.trim();
            if let Some(inner) = trimmed.strip_prefix("{{").and_then(|x| x.strip_suffix("}}"))
                && !inner.contains("{{")
                && !inner.contains("}}")
            {
                return lookup(inner, s).unwrap_or(Value::Null);
            }
            Value::String(render_str(t, s))
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| render_value(x, s)).collect()),
        Value::Object(m) => {
            Value::Object(m.iter().map(|(k, x)| (k.clone(), render_value(x, s))).collect::<Map<_, _>>())
        }
        other => other.clone(),
    }
}

/// The JSON value in a model answer: the whole text, a fenced block, or the first balanced
/// object or array in it.
pub fn extract_json(text: &str) -> Option<Value> {
    let t = text.trim();
    if let Ok(v) = serde_json::from_str::<Value>(t) {
        return Some(v);
    }
    if let Some(start) = t.find("```") {
        let body = &t[start + 3..];
        let body = body.strip_prefix("json").unwrap_or(body);
        if let Some(end) = body.find("```")
            && let Ok(v) = serde_json::from_str::<Value>(body[..end].trim())
        {
            return Some(v);
        }
    }
    for (open, close) in [('{', '}'), ('[', ']')] {
        let Some(start) = t.find(open) else { continue };
        let (mut depth, mut in_str, mut esc) = (0i32, false, false);
        for (i, c) in t[start..].char_indices() {
            if in_str {
                match (esc, c) {
                    (true, _) => esc = false,
                    (false, '\\') => esc = true,
                    (false, '"') => in_str = false,
                    _ => {}
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                c if c == open => depth += 1,
                c if c == close => {
                    depth -= 1;
                    if depth == 0 {
                        if let Ok(v) = serde_json::from_str::<Value>(&t[start..start + i + c.len_utf8()]) {
                            return Some(v);
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn placeholders_resolve_paths() {
        let input = json!({"patient": {"age": 41, "name": "Ada"}, "tags": ["a", "b"]});
        let mut outputs = BTreeMap::new();
        outputs.insert("classify".to_owned(), json!({"route": "clinical"}));
        let s = Scope { input: &input, outputs: &outputs };
        assert_eq!(
            render_str(
                "{{input.patient.name}} ({{ input.patient.age }}), {{outputs.classify.route}}, {{input.tags.1}}, [{{nope}}]",
                &s
            ),
            "Ada (41), clinical, b, []"
        );
        assert_eq!(render_str("{{input.patient}}", &s), r#"{"age":41,"name":"Ada"}"#);
        assert_eq!(render_str("unclosed {{input", &s), "unclosed {{input");
        assert_eq!(
            render_value(&json!({"p": "{{input.patient}}", "n": "x{{input.patient.age}}"}), &s),
            json!({"p": {"age": 41, "name": "Ada"}, "n": "x41"})
        );
    }

    #[test]
    fn json_is_found_in_model_answers() {
        assert_eq!(extract_json(r#" {"a": 1} "#), Some(json!({"a": 1})));
        assert_eq!(extract_json("Sure:\n```json\n{\"a\": [1, 2]}\n```\nDone."), Some(json!({"a": [1, 2]})));
        assert_eq!(extract_json(r#"The answer is {"a": "}"} ok"#), Some(json!({"a": "}"})));
        assert_eq!(extract_json("no json here"), None);
    }
}
