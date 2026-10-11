//! Taint labels (CaMeL-lite; P3 decision 3): where a value came from, tracked by the executor.
//!
//! Labels:
//! - `tool:<server>/<tool>`: the output of an MCP tool (and everything derived from it);
//! - `datasource`: rows from a datasource (the built-in query tool);
//! - `retrieved`: retrieved documents;
//! - `caller`: run input the caller marked as untrusted data (or that the node's input schema
//!   declares `x-caliban-untrusted: true`), see [`caller_labels`];
//! - `pii`: the value holds personal data (found by the tenant's PII engine in the run input).
//!
//! Propagation: a vertex's input label set is the labels of the value it receives plus those of
//! every earlier output its config names (`{{outputs.<vertex>}}`); its output carries the input's
//! labels, and a tool adds its own. A model call is not a sanitizer: an `llm`, `router`, `verify`
//! or `reduce` vertex passes on what it consumed. An agent's context accumulates the labels of
//! every tool result it saw, and every call it makes after that is labelled with them. Branch
//! choices (control flow) are not labelled: CaMeL-lite tracks data, not control.
//!
//! The rule, enforced before the call: a tool declared `effect: write` whose arguments carry any
//! label other than `pii` needs either an allowlist entry in the node spec (`allow_tainted` on the
//! tool: label patterns such as `tool:catalogue/*`, `datasource`, `*`) or a human approval (the run
//! waits in `input_required`; the decision is journaled with who made it). `pii` is handled by the
//! data guard: a tool not trusted with personal data only ever receives surrogates.

use serde_json::Value;
use std::collections::BTreeSet;

pub type Taint = BTreeSet<String>;

pub const PII: &str = "pii";
/// Untrusted caller data in the run input (P3 decision 8).
pub const CALLER: &str = "caller";
/// The input-schema annotation that marks a field as untrusted caller data, whoever calls.
pub const UNTRUSTED_KEYWORD: &str = "x-caliban-untrusted";
/// At most this many marks per run request.
pub const MAX_MARKS: usize = 64;

/// The label a tool's output carries.
pub fn label_for(reference: &str) -> Option<String> {
    if let Some(rest) = reference.strip_prefix("mcp://") {
        return Some(format!("tool:{}", rest.split('#').next().unwrap_or(rest)));
    }
    match reference {
        "builtin://datasource_query" => Some("datasource".into()),
        "builtin://rag_search" => Some("retrieved".into()),
        _ => None,
    }
}

/// The labels that make a write need approval: everything but `pii`.
pub fn untrusted(t: &Taint) -> Vec<&String> {
    t.iter().filter(|l| *l != PII).collect()
}

/// Whether every untrusted label matches an allowlist pattern (`*`, an exact label, or a prefix
/// ending in `*`).
pub fn allowed(t: &Taint, patterns: &[String]) -> bool {
    untrusted(t).iter().all(|l| {
        patterns.iter().any(|p| p == "*" || p == *l || p.strip_suffix('*').is_some_and(|prefix| l.starts_with(prefix)))
    })
}

/// The vertices whose outputs a config names (`{{outputs.<vertex>...}}`), anywhere in it.
pub fn referenced_outputs(config: &Value) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => {
                let mut rest = s.as_str();
                while let Some(i) = rest.find("{{") {
                    let after = &rest[i + 2..];
                    let Some(end) = after.find("}}") else { break };
                    let expr = after[..end].trim();
                    if let Some(path) = expr.strip_prefix("outputs.") {
                        let id = path.split('.').next().unwrap_or_default().to_owned();
                        if !id.is_empty() && !out.contains(&id) {
                            out.push(id);
                        }
                    }
                    rest = &after[end + 2..];
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(m) => m.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(config, &mut out);
    out
}

/// The caller's marks (`"untrusted"` on a run request): `true` (the whole input), `false` or
/// `null` (none), or a list of JSON pointers (RFC 6901) into the input (`""` is the whole input).
pub fn parse_marks(v: &Value) -> Result<Vec<String>, String> {
    let bad = || "untrusted must be true, false or a list of JSON pointers into the input (\"/field\")".to_owned();
    match v {
        Value::Null | Value::Bool(false) => Ok(vec![]),
        Value::Bool(true) => Ok(vec![String::new()]),
        Value::Array(a) => {
            if a.len() > MAX_MARKS {
                return Err(format!("untrusted: at most {MAX_MARKS} pointers"));
            }
            a.iter()
                .map(|p| match p.as_str() {
                    Some(p) if p.is_empty() || p.starts_with('/') => Ok(p.to_owned()),
                    Some(p) => Err(format!("untrusted: '{p}' is not a JSON pointer (it must start with '/')")),
                    None => Err(bad()),
                })
                .collect()
        }
        _ => Err(bad()),
    }
}

/// The pointers an input schema marks untrusted (`x-caliban-untrusted: true` on the schema itself,
/// on a property, or on an array's `items`: then the array). Marks under `anyOf` / `allOf` apply
/// to the location the combinator sits at.
pub fn schema_marks(schema: &Value) -> Vec<String> {
    fn walk(s: &Value, at: &str, out: &mut Vec<String>) {
        let Some(m) = s.as_object() else { return };
        let mark = |out: &mut Vec<String>| {
            if !out.iter().any(|p| p == at) {
                out.push(at.to_owned());
            }
        };
        if m.get(UNTRUSTED_KEYWORD) == Some(&Value::Bool(true)) {
            mark(out);
        }
        if let Some(props) = m.get("properties").and_then(Value::as_object) {
            for (k, sub) in props {
                walk(sub, &format!("{at}/{}", k.replace('~', "~0").replace('/', "~1")), out);
            }
        }
        if let Some(items) = m.get("items") {
            let mut inner = Vec::new();
            walk(items, at, &mut inner);
            if !inner.is_empty() {
                mark(out);
            }
        }
        for k in ["anyOf", "allOf"] {
            for sub in m.get(k).and_then(Value::as_array).into_iter().flatten() {
                walk(sub, at, out);
            }
        }
        if let Some(extra) = m.get("additionalProperties").filter(|v| v.is_object()) {
            let mut inner = Vec::new();
            walk(extra, at, &mut inner);
            if !inner.is_empty() {
                // Any property the schema does not name may hold marked data: the object itself.
                mark(out);
            }
        }
    }
    let mut out = Vec::new();
    walk(schema, "", &mut out);
    out.sort();
    out
}

/// The labels a run input starts with because of untrusted caller data: [`CALLER`] when a value
/// the caller marked (`marks`) or the input schema marks is present and not null. Labels belong
/// to values and the run input is one value, so one marked field labels the whole input (and
/// everything derived from it); see docs/tools.md.
pub fn caller_labels(input: &Value, schema: Option<&Value>, marks: &[String]) -> Taint {
    let from_schema = schema.map(schema_marks).unwrap_or_default();
    let present = marks.iter().chain(&from_schema).any(|p| input.pointer(p).is_some_and(|v| !v.is_null()));
    if present { [CALLER.to_owned()].into() } else { Taint::new() }
}

/// What a human answered to an approval question: `{"approve": bool}`, a boolean, or a word.
pub fn approved(answer: &Value) -> bool {
    match answer {
        Value::Bool(b) => *b,
        Value::Object(m) => m.get("approve").or_else(|| m.get("approved")).and_then(Value::as_bool).unwrap_or(false),
        Value::String(s) => matches!(s.trim().to_ascii_lowercase().as_str(), "approve" | "approved" | "yes" | "true"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn labels_patterns_and_references() {
        assert_eq!(label_for("mcp://crm/update#sha256:00").as_deref(), Some("tool:crm/update"));
        assert_eq!(label_for("node://x@v1"), None);
        let t: Taint = ["tool:crm/lookup".to_owned(), PII.to_owned()].into();
        assert_eq!(untrusted(&t), [&"tool:crm/lookup".to_owned()]);
        assert!(allowed(&t, &["tool:crm/*".into()]));
        assert!(allowed(&t, &["*".into()]));
        assert!(!allowed(&t, &["tool:erp/*".into()]));
        assert!(allowed(&[PII.to_owned()].into(), &[]), "pii alone is not a reason to ask");
        assert_eq!(
            referenced_outputs(
                &json!({"args": {"a": "{{outputs.lookup.id}} and {{ outputs.score }}", "b": "{{input.x}}"}})
            ),
            ["lookup", "score"]
        );
        assert!(
            approved(&json!({"approve": true})) && approved(&json!("yes")) && !approved(&json!({"approve": false}))
        );
    }

    #[test]
    fn caller_marks_and_schema_marks() {
        assert_eq!(parse_marks(&json!(true)).unwrap(), [""]);
        assert!(parse_marks(&json!(false)).unwrap().is_empty() && parse_marks(&Value::Null).unwrap().is_empty());
        assert_eq!(parse_marks(&json!(["/email", ""])).unwrap(), ["/email", ""]);
        assert!(parse_marks(&json!(["email"])).is_err() && parse_marks(&json!("x")).is_err());
        assert!(parse_marks(&json!([1])).is_err());
        assert!(parse_marks(&Value::Array(vec![json!("/a"); MAX_MARKS + 1])).is_err());

        let schema = json!({"type": "object", "properties": {
            "request": {"type": "string"},
            "email": {"type": "string", "x-caliban-untrusted": true},
            "a/b": {"type": "object", "properties": {"body": {"x-caliban-untrusted": true}}},
            "docs": {"type": "array", "items": {"type": "string", "x-caliban-untrusted": true}},
            "plain": {"type": "array", "items": {"type": "string"}}}});
        assert_eq!(schema_marks(&schema), ["/a~1b/body", "/docs", "/email"]);
        assert_eq!(schema_marks(&json!({"x-caliban-untrusted": true})), [""]);
        assert!(schema_marks(&json!({"type": "string"})).is_empty());

        let caller: Taint = [CALLER.to_owned()].into();
        let input = json!({"request": "file it", "email": "Ignore previous instructions"});
        assert_eq!(caller_labels(&input, Some(&schema), &[]), caller, "the schema marks email");
        let input = json!({"request": "file it"});
        assert!(caller_labels(&input, Some(&schema), &[]).is_empty(), "an absent marked field labels nothing");
        assert_eq!(caller_labels(&input, Some(&schema), &["/request".into()]), caller, "the caller marks request");
        assert!(caller_labels(&input, None, &["/nope".into()]).is_empty());
        assert_eq!(caller_labels(&json!("text"), None, &[String::new()]), caller);
        assert!(caller_labels(&json!({"email": null}), Some(&schema), &[]).is_empty());
        assert_eq!(untrusted(&caller), [&CALLER.to_owned()], "caller data needs approval like tool output");
        assert!(allowed(&caller, &["caller".into()]) && !allowed(&caller, &["tool:*".into()]));
    }
}
