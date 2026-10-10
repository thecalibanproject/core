//! A JSON Schema subset for the values that travel along a node's edges.
//!
//! Supported keywords: `type` (a name or a list of names), `enum`, `const`, `properties`,
//! `required`, `additionalProperties` (boolean or schema), `items` (one schema), `minItems`,
//! `maxItems`, `minLength`, `maxLength`, `pattern`, `minimum`, `maximum`, `anyOf`, `allOf`.
//! Annotations (`title`, `description`, `default`, `examples`, `$schema`, `$id`, `$comment`,
//! `format`) are accepted and not checked. Any other keyword (`$ref`, `oneOf`, `if`, ...) is
//! refused when the node version is published ([`check_supported`]), so a schema is never
//! silently weaker than it reads.

use serde_json::{Map, Value};

const CHECKED: &[&str] = &[
    "type",
    "enum",
    "const",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
    "pattern",
    "minimum",
    "maximum",
    "anyOf",
    "allOf",
];
const ANNOTATIONS: &[&str] = &["title", "description", "default", "examples", "$schema", "$id", "$comment", "format"];
const TYPES: &[&str] = &["string", "number", "integer", "boolean", "object", "array", "null"];

/// Refuses schemas that use keywords outside the supported subset, or malformed ones.
pub fn check_supported(schema: &Value) -> Result<(), String> {
    check_at(schema, "")
}

fn check_at(schema: &Value, at: &str) -> Result<(), String> {
    let here = || if at.is_empty() { "the schema".to_owned() } else { format!("'{at}'") };
    let m = match schema {
        Value::Bool(_) => return Ok(()),
        Value::Object(m) => m,
        _ => return Err(format!("{} must be an object", here())),
    };
    for (k, v) in m {
        if ANNOTATIONS.contains(&k.as_str()) {
            continue;
        }
        if !CHECKED.contains(&k.as_str()) {
            return Err(format!("keyword '{k}' at {} is not supported (supported: {})", here(), CHECKED.join(", ")));
        }
        let sub = |name: &str| if at.is_empty() { name.to_owned() } else { format!("{at}/{name}") };
        match k.as_str() {
            "type" => {
                let names: Vec<&Value> = match v {
                    Value::Array(a) => a.iter().collect(),
                    other => vec![other],
                };
                for n in names {
                    if !n.as_str().is_some_and(|n| TYPES.contains(&n)) {
                        return Err(format!("unknown type {n} at {}", here()));
                    }
                }
            }
            "enum" if !v.is_array() => return Err(format!("enum at {} must be an array", here())),
            "properties" => {
                let props = v.as_object().ok_or_else(|| format!("properties at {} must be an object", here()))?;
                for (p, s) in props {
                    check_at(s, &sub(&format!("properties/{p}")))?;
                }
            }
            "required" if !v.as_array().is_some_and(|a| a.iter().all(Value::is_string)) => {
                return Err(format!("required at {} must be a list of names", here()));
            }
            "additionalProperties" | "items" => check_at(v, &sub(k))?,
            "anyOf" | "allOf" => {
                let list = v
                    .as_array()
                    .filter(|a| !a.is_empty())
                    .ok_or_else(|| format!("{k} at {} must be a non-empty list", here()))?;
                for (i, s) in list.iter().enumerate() {
                    check_at(s, &sub(&format!("{k}/{i}")))?;
                }
            }
            "minItems" | "maxItems" | "minLength" | "maxLength" if !v.is_u64() => {
                return Err(format!("{k} at {} must be a non-negative integer", here()));
            }
            "minimum" | "maximum" if !v.is_number() => return Err(format!("{k} at {} must be a number", here())),
            "pattern" => {
                let p = v.as_str().ok_or_else(|| format!("pattern at {} must be a string", here()))?;
                regex::Regex::new(p).map_err(|e| format!("pattern at {}: {e}", here()))?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Validates `value` against `schema` (the supported subset). Returns the first violation, with a
/// JSON pointer to where it is.
pub fn validate(schema: &Value, value: &Value) -> Result<(), String> {
    at(schema, value, "")
}

fn type_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn is_type(v: &Value, t: &str) -> bool {
    match t {
        "number" => v.is_number(),
        "integer" => v.is_i64() || v.is_u64() || v.as_f64().is_some_and(|f| f.fract() == 0.0 && f.is_finite()),
        other => type_of(v) == other,
    }
}

fn at(schema: &Value, v: &Value, path: &str) -> Result<(), String> {
    let where_ = || if path.is_empty() { "/".to_owned() } else { path.to_owned() };
    let m: &Map<String, Value> = match schema {
        Value::Bool(true) => return Ok(()),
        Value::Bool(false) => return Err(format!("{}: no value is allowed here", where_())),
        Value::Object(m) => m,
        _ => return Ok(()),
    };
    if let Some(t) = m.get("type") {
        let ok = match t {
            Value::String(t) => is_type(v, t),
            Value::Array(ts) => ts.iter().filter_map(Value::as_str).any(|t| is_type(v, t)),
            _ => true,
        };
        if !ok {
            return Err(format!("{}: expected {t}, got {}", where_(), type_of(v)));
        }
    }
    if let Some(e) = m.get("enum").and_then(Value::as_array)
        && !e.contains(v)
    {
        return Err(format!("{}: {v} is not one of {}", where_(), Value::Array(e.clone())));
    }
    if let Some(c) = m.get("const")
        && c != v
    {
        return Err(format!("{}: expected {c}", where_()));
    }
    if let Value::Object(obj) = v {
        for r in m.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            if !obj.contains_key(r) {
                return Err(format!("{}: missing required property '{r}'", where_()));
            }
        }
        let props = m.get("properties").and_then(Value::as_object);
        for (k, x) in obj {
            let child = format!("{path}/{k}");
            match props.and_then(|p| p.get(k)) {
                Some(s) => at(s, x, &child)?,
                None => {
                    if let Some(extra) = m.get("additionalProperties") {
                        if extra == &Value::Bool(false) {
                            return Err(format!("{}: property '{k}' is not allowed", where_()));
                        }
                        at(extra, x, &child)?;
                    }
                }
            }
        }
    }
    if let Value::Array(items) = v {
        let n = items.len() as u64;
        if m.get("minItems").and_then(Value::as_u64).is_some_and(|min| n < min) {
            return Err(format!("{}: at least {} items required", where_(), m["minItems"]));
        }
        if m.get("maxItems").and_then(Value::as_u64).is_some_and(|max| n > max) {
            return Err(format!("{}: at most {} items allowed", where_(), m["maxItems"]));
        }
        if let Some(s) = m.get("items") {
            for (i, x) in items.iter().enumerate() {
                at(s, x, &format!("{path}/{i}"))?;
            }
        }
    }
    if let Value::String(s) = v {
        let n = s.chars().count() as u64;
        if m.get("minLength").and_then(Value::as_u64).is_some_and(|min| n < min) {
            return Err(format!("{}: shorter than {} characters", where_(), m["minLength"]));
        }
        if m.get("maxLength").and_then(Value::as_u64).is_some_and(|max| n > max) {
            return Err(format!("{}: longer than {} characters", where_(), m["maxLength"]));
        }
        if let Some(p) = m.get("pattern").and_then(Value::as_str) {
            let re = regex::Regex::new(p).map_err(|e| format!("{}: bad pattern: {e}", where_()))?;
            if !re.is_match(s) {
                return Err(format!("{}: does not match {p}", where_()));
            }
        }
    }
    if let Some(x) = v.as_f64() {
        if m.get("minimum").and_then(Value::as_f64).is_some_and(|min| x < min) {
            return Err(format!("{}: below the minimum {}", where_(), m["minimum"]));
        }
        if m.get("maximum").and_then(Value::as_f64).is_some_and(|max| x > max) {
            return Err(format!("{}: above the maximum {}", where_(), m["maximum"]));
        }
    }
    if let Some(all) = m.get("allOf").and_then(Value::as_array) {
        for s in all {
            at(s, v, path)?;
        }
    }
    if let Some(any) = m.get("anyOf").and_then(Value::as_array)
        && !any.iter().any(|s| at(s, v, path).is_ok())
    {
        return Err(format!("{}: matches none of the anyOf schemas", where_()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn recommendation() -> Value {
        json!({
            "type": "object",
            "required": ["category", "services"],
            "additionalProperties": false,
            "properties": {
                "category": {"enum": ["billing", "clinical", "other"]},
                "urgency": {"type": "integer", "minimum": 1, "maximum": 5},
                "services": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 2}},
                "note": {"type": ["string", "null"], "pattern": "^[^<>]*$"}
            }
        })
    }

    #[test]
    fn accepts_matching_values() {
        let v = json!({"category": "clinical", "urgency": 3, "services": ["gp", "lab"], "note": null});
        assert_eq!(validate(&recommendation(), &v), Ok(()));
        assert_eq!(check_supported(&recommendation()), Ok(()));
    }

    #[test]
    fn reports_where_values_go_wrong() {
        let s = recommendation();
        let cases = [
            (json!({"services": ["gp"]}), "missing required property 'category'"),
            (json!({"category": "x", "services": ["gp"]}), "is not one of"),
            (json!({"category": "other", "services": []}), "at least 1 items"),
            (json!({"category": "other", "services": ["g"]}), "/services/0: shorter"),
            (json!({"category": "other", "services": ["gp"], "urgency": 9}), "/urgency: above"),
            (json!({"category": "other", "services": ["gp"], "urgency": 2.5}), "/urgency: expected"),
            (json!({"category": "other", "services": ["gp"], "x": 1}), "'x' is not allowed"),
            (json!({"category": "other", "services": ["gp"], "note": "<b>"}), "/note: does not match"),
            (json!("text"), "expected \"object\""),
        ];
        for (v, want) in cases {
            let e = validate(&s, &v).unwrap_err();
            assert!(e.contains(want), "{v}: {e}");
        }
    }

    #[test]
    fn any_of_and_all_of() {
        let s = json!({"anyOf": [{"type": "string"}, {"type": "integer"}], "allOf": [{"not_checked_here": 1}]});
        assert!(check_supported(&s).is_err(), "unknown keyword inside allOf");
        let s = json!({"anyOf": [{"type": "string"}, {"type": "integer"}]});
        assert!(validate(&s, &json!("a")).is_ok() && validate(&s, &json!(3)).is_ok());
        assert!(validate(&s, &json!(true)).is_err());
    }

    #[test]
    fn unsupported_keywords_are_refused() {
        for s in [
            json!({"$ref": "#/defs/x"}),
            json!({"oneOf": [{"type": "string"}]}),
            json!({"properties": {"a": {"if": {}}}}),
            json!({"type": "strings"}),
            json!({"pattern": "("}),
            json!("string"),
        ] {
            assert!(check_supported(&s).is_err(), "{s}");
        }
        assert!(check_supported(&json!({"type": "string", "format": "email", "description": "d"})).is_ok());
    }
}
