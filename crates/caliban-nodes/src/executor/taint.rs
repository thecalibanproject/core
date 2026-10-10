//! Taint labels (CaMeL-lite; P3 decision 3): where a value came from, tracked by the executor.
//!
//! Labels:
//! - `tool:<server>/<tool>`: the output of an MCP tool (and everything derived from it);
//! - `datasource`: rows from a datasource (the built-in query tool);
//! - `retrieved`: retrieved documents;
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
}
