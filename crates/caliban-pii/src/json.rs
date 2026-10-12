//! JSON-aware rewriting: in a JSON document, only string values carry personal data that the
//! engine may rewrite. Keys, numbers, booleans and `null` are never altered, so a tool result such
//! as `{"score": 0.0322580645161290}` reaches the model as valid JSON with the same number.
//!
//! Structural fields of a CQIR query (an object with both `ir_version` and `ontology_version`) are
//! never rewritten either: its versions, element ids, attributes, operators, sort fields and
//! literal tags name the tenant's ontology, not a person, and a rewrite makes the query fail
//! (a tenant dictionary term that equals a word of the tenant id rewrote
//! `"ontology_version": "cabinet-Camila@5"`). Only its filter literals (`filters[i].value.v`) are
//! data and stay protectable.
//!
//! Two views of the same rule: [`protectable_strings_mut`] over a parsed [`Value`] (tool
//! arguments and results), and [`protectable_ranges`] over the raw text of a message segment that
//! holds a JSON object or array (tool messages, tool-call arguments).

use serde_json::{Map, Value};
use std::ops::Range;

/// A CQIR query object: it names both its IR and its ontology version.
fn is_cqir(has: impl Fn(&str) -> bool) -> bool {
    has("ir_version") && has("ontology_version")
}

/// The string values of `v` that the PII engine may rewrite, in document order: every string
/// value except the structural fields of a CQIR query. Keys are never included.
pub fn protectable_strings_mut(v: &mut Value) -> Vec<&mut String> {
    let mut out = Vec::new();
    walk_value(v, &mut out);
    out
}

fn walk_value<'a>(v: &'a mut Value, out: &mut Vec<&'a mut String>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter_mut().for_each(|x| walk_value(x, out)),
        Value::Object(m) => {
            if is_cqir(|k| m.contains_key(k)) {
                cqir_literals(m, out);
            } else {
                m.values_mut().for_each(|x| walk_value(x, out));
            }
        }
        _ => {}
    }
}

/// The filter literals of a CQIR query (`filters[i].value.v`), the only data it carries.
fn cqir_literals<'a>(m: &'a mut Map<String, Value>, out: &mut Vec<&'a mut String>) {
    if let Some(Value::Array(filters)) = m.get_mut("filters") {
        for f in filters {
            if let Some(lit) = f.get_mut("value").and_then(|l| l.get_mut("v")) {
                walk_value(lit, out);
            }
        }
    }
}

/// When `text` is a JSON object or array: the byte ranges (inside the quotes) of its protectable
/// string values, sorted, by the rule of [`protectable_strings_mut`]. `None` for any other text
/// (prose, a bare scalar, invalid JSON), which is scanned as a whole.
pub fn protectable_ranges(text: &str) -> Option<Vec<Range<usize>>> {
    let head = text.trim_start().as_bytes().first()?;
    if !matches!(head, b'{' | b'[') || serde_json::from_str::<serde::de::IgnoredAny>(text).is_err() {
        return None;
    }
    let mut p = Parser { src: text, i: 0 };
    let tree = p.value()?;
    let mut out = Vec::new();
    walk_node(&tree, &mut out);
    Some(out)
}

/// A JSON document reduced to what the rule needs: string values by position, keys decoded.
enum Node {
    Str(Range<usize>),
    Arr(Vec<Node>),
    Obj(Vec<(String, Node)>),
    Other,
}

impl Node {
    fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

fn walk_node(n: &Node, out: &mut Vec<Range<usize>>) {
    match n {
        Node::Str(r) => out.push(r.clone()),
        Node::Arr(a) => a.iter().for_each(|x| walk_node(x, out)),
        Node::Obj(fields) if is_cqir(|k| fields.iter().any(|(f, _)| f == k)) => {
            if let Some(Node::Arr(filters)) = n.get("filters") {
                for f in filters {
                    if let Some(lit) = f.get("value").and_then(|l| l.get("v")) {
                        walk_node(lit, out);
                    }
                }
            }
        }
        Node::Obj(fields) => fields.iter().for_each(|(_, v)| walk_node(v, out)),
        Node::Other => {}
    }
}

/// A recursive-descent reader over text serde_json has already accepted (so its depth is bounded
/// by serde_json's recursion limit). Any surprise returns `None`.
struct Parser<'a> {
    src: &'a str,
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.src.as_bytes().get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Option<()> {
        self.ws();
        (self.peek()? == c).then(|| self.i += 1)
    }

    /// A string at the cursor: the range of its contents (between the quotes).
    fn string(&mut self) -> Option<Range<usize>> {
        self.eat(b'"')?;
        let start = self.i;
        loop {
            match self.peek()? {
                b'\\' => self.i += 2,
                b'"' => {
                    let r = start..self.i;
                    self.i += 1;
                    return Some(r);
                }
                _ => self.i += 1,
            }
        }
    }

    fn value(&mut self) -> Option<Node> {
        self.ws();
        match self.peek()? {
            b'{' => {
                self.i += 1;
                let mut fields = Vec::new();
                self.ws();
                if self.peek()? == b'}' {
                    self.i += 1;
                    return Some(Node::Obj(fields));
                }
                loop {
                    let k = self.string()?;
                    let key: String = serde_json::from_str(&self.src[k.start - 1..=k.end]).ok()?;
                    self.eat(b':')?;
                    fields.push((key, self.value()?));
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b'}' => {
                            self.i += 1;
                            return Some(Node::Obj(fields));
                        }
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek()? == b']' {
                    self.i += 1;
                    return Some(Node::Arr(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(Node::Arr(items));
                        }
                        _ => return None,
                    }
                }
            }
            b'"' => self.string().map(Node::Str),
            _ => {
                // A number, true, false or null.
                let start = self.i;
                while !matches!(self.peek(), None | Some(b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n')) {
                    self.i += 1;
                }
                (self.i > start).then_some(Node::Other)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn values(text: &str) -> Vec<&str> {
        protectable_ranges(text).unwrap().into_iter().map(|r| &text[r]).collect()
    }

    #[test]
    fn only_string_values_of_objects_and_arrays() {
        let t = r#"{"name": "Jane", "score": 0.0322580645161290, "tags": ["a", 4111111111111111, true, null],
                    "4111 1111 1111 1111": {"k": "v\"w"}}"#;
        assert_eq!(values(t), vec!["Jane", "a", "v\\\"w"]);
        assert_eq!(values("[]"), Vec::<&str>::new());
        assert!(protectable_ranges("call 0612345678").is_none(), "prose");
        assert!(protectable_ranges("\"a string\"").is_none(), "a bare scalar is scanned as text");
        assert!(protectable_ranges("4111111111111111").is_none());
        assert!(protectable_ranges("{\"a\": ").is_none(), "invalid JSON is scanned as text");
    }

    fn cqir() -> Value {
        json!({"query": {
            "ir_version": "1", "ontology_version": "cabinet-Camila@5",
            "metrics": [{"id": "m_fees"}], "dimensions": [{"id": "d_client_name"}],
            "filters": [
                {"attr": "a_client_name", "op": "eq", "value": {"type": "string", "v": "Camila Duarte"}},
                {"attr": "a_city", "op": "in", "value": {"type": "string_list", "v": ["Paris", "Lyon"]}}
            ],
            "order_by": [{"metric": "m_fees", "dir": "desc"}], "limit": 10
        }, "note": "for Camila"})
    }

    #[test]
    fn cqir_structure_is_frozen_but_its_filter_literals_are_data() {
        let mut v = cqir();
        let got: Vec<String> = protectable_strings_mut(&mut v).into_iter().map(|s| s.clone()).collect();
        assert_eq!(got, vec!["for Camila", "Camila Duarte", "Paris", "Lyon"]);
        let text = cqir().to_string();
        let mut raw = values(&text);
        raw.sort_unstable();
        assert_eq!(raw, vec!["Camila Duarte", "Lyon", "Paris", "for Camila"]);
        // Without both version keys it is an ordinary object.
        let mut other = json!({"ontology_version": "x@1", "id": "Camila"});
        assert_eq!(protectable_strings_mut(&mut other).len(), 2);
    }
}
