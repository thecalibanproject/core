//! Structural JSON diff between two node specs (`GET .../diff`): every path whose value differs,
//! as JSON pointers. Objects are compared key by key; arrays index by index (a value inserted in
//! the middle of an array shows as changes up to the end and an addition).

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Change {
    /// JSON pointer (`/graph/vertices/1/config/prompt`).
    pub path: String,
    pub op: Op,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Value>,
}

/// The changes from `a` to `b`, in path order.
pub fn json_diff(a: &Value, b: &Value) -> Vec<Change> {
    let mut out = Vec::new();
    walk("", a, b, &mut out);
    out
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn walk(path: &str, a: &Value, b: &Value, out: &mut Vec<Change>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort_unstable();
            keys.dedup();
            for k in keys {
                let p = format!("{path}/{}", escape(k));
                match (x.get(k), y.get(k)) {
                    (Some(va), Some(vb)) => walk(&p, va, vb, out),
                    (Some(va), None) => out.push(Change { path: p, op: Op::Removed, from: Some(va.clone()), to: None }),
                    (None, Some(vb)) => out.push(Change { path: p, op: Op::Added, from: None, to: Some(vb.clone()) }),
                    (None, None) => {}
                }
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            for i in 0..x.len().max(y.len()) {
                let p = format!("{path}/{i}");
                match (x.get(i), y.get(i)) {
                    (Some(va), Some(vb)) => walk(&p, va, vb, out),
                    (Some(va), None) => out.push(Change { path: p, op: Op::Removed, from: Some(va.clone()), to: None }),
                    (None, Some(vb)) => out.push(Change { path: p, op: Op::Added, from: None, to: Some(vb.clone()) }),
                    (None, None) => {}
                }
            }
        }
        _ if a == b => {}
        _ => out.push(Change {
            path: if path.is_empty() { "/".into() } else { path.to_owned() },
            op: Op::Changed,
            from: Some(a.clone()),
            to: Some(b.clone()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn changes_are_listed_by_path() {
        let a = json!({"budgets": {"steps": 5}, "prompt": {"system": "a"}, "tools": [{"ref": "x"}], "old": 1});
        let b = json!({"budgets": {"steps": 6}, "prompt": {"system": "a"}, "tools": [{"ref": "x"}, {"ref": "y/z"}], "new": {"k~": 2}});
        let d = json_diff(&a, &b);
        let paths: Vec<(&str, &Op)> = d.iter().map(|c| (c.path.as_str(), &c.op)).collect();
        assert_eq!(
            paths,
            [("/budgets/steps", &Op::Changed), ("/new", &Op::Added), ("/old", &Op::Removed), ("/tools/1", &Op::Added)]
        );
        assert_eq!((d[0].from.clone(), d[0].to.clone()), (Some(json!(5)), Some(json!(6))));
        assert!(json_diff(&a, &a).is_empty());
        assert_eq!(json_diff(&json!(1), &json!("1"))[0].path, "/");
    }
}
