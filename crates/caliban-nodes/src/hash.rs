//! Content hashes of node versions.
//!
//! A version's hash is `sha256:<hex>` over its spec in canonical JSON: object keys sorted by
//! their UTF-8 bytes at every level, no whitespace, numbers and strings as `serde_json` writes
//! them. Two specs that differ only in key order or formatting have the same hash; any change of
//! a value changes it. The hash is computed when a version is created and never changes (versions
//! are immutable).

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The canonical JSON text of `v`.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write(&m[k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// `sha256:<hex>` over the canonical JSON of `spec`.
pub fn content_hash(spec: &Value) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(canonical_json(spec).as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_and_formatting_do_not_matter() {
        let a: Value =
            serde_json::from_str(r#"{"b": 1, "a": {"y": [1, 2, {"q": "x", "p": null}], "x": true}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":true,"y":[1,2,{"p":null,"q":"x"}]},"b":1}"#).unwrap();
        assert_eq!(canonical_json(&a), r#"{"a":{"x":true,"y":[1,2,{"p":null,"q":"x"}]},"b":1}"#);
        assert_eq!(content_hash(&a), content_hash(&b));
        assert!(content_hash(&a).starts_with("sha256:") && content_hash(&a).len() == 71);
    }

    #[test]
    fn any_value_change_changes_the_hash() {
        let a = json!({"kind": "agent", "budgets": {"steps": 5}});
        let b = json!({"kind": "agent", "budgets": {"steps": 6}});
        let c = json!({"kind": "agent", "budgets": {"steps": 5}, "tools": []});
        assert_ne!(content_hash(&a), content_hash(&b));
        assert_ne!(content_hash(&a), content_hash(&c));
        // Array order is part of the value.
        assert_ne!(content_hash(&json!([1, 2])), content_hash(&json!([2, 1])));
        // Strings are escaped the same way every time.
        assert_eq!(canonical_json(&json!({"k": "a\"b\n"})), r#"{"k":"a\"b\n"}"#);
    }

    #[test]
    fn hash_is_stable_across_releases() {
        // Pinned: changing the canonical form would change every stored hash.
        let spec = json!({"kind": "agent", "prompt": {"system": "Be brief."}, "model_policy": {},
                          "budgets": {"steps": 3, "tokens": 100, "wall_clock_s": 10}});
        assert_eq!(
            canonical_json(&spec),
            r#"{"budgets":{"steps":3,"tokens":100,"wall_clock_s":10},"kind":"agent","model_policy":{},"prompt":{"system":"Be brief."}}"#
        );
        assert_eq!(content_hash(&spec), "sha256:47b9c886a65855d06f389ccb49baf6a5bf25fc33f632277b795e0ec9b229f57e");
    }
}
