//! Sampling-based schema inference for document collections (research 08, "Schema inference &
//! ontology bootstrap", steps 3–5). Pure functions over sampled BSON documents; the I/O lives in
//! [`crate::mongo`].
//!
//! For every dotted path (including paths inside arrays of documents, `lines.qty`) we record:
//! presence and null fractions relative to the containing object, a BSON type histogram, array
//! length percentiles and element types, a GEE distinct-count estimate, top values for
//! low-cardinality paths, polymorphism, dynamic-key objects (maps), and discriminator candidates.

use crate::mongo::bson::{Bson, Document};
use crate::{ArrayStats, DiscriminatorInfo, FieldInfo, ObjectInfo, Profile};
use serde_json::{Value as J, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone)]
pub struct InferOptions {
    pub max_depth: usize,
    pub max_paths: usize,
    /// Scalar values kept per path (distinct estimates, top values, reference probes).
    pub max_values_per_path: usize,
    pub top_k: usize,
    /// `FieldInfo::top_values` is only filled when the sampled distinct count is at most this.
    pub low_cardinality: usize,
}

impl Default for InferOptions {
    fn default() -> Self {
        Self { max_depth: 8, max_paths: 2_000, max_values_per_path: 5_000, top_k: 10, low_cardinality: 50 }
    }
}

/// `$type` alias of a BSON value.
pub fn bson_type_name(b: &Bson) -> &'static str {
    match b {
        Bson::Double(_) => "double",
        Bson::String(_) => "string",
        Bson::Array(_) => "array",
        Bson::Document(_) => "object",
        Bson::Boolean(_) => "bool",
        Bson::Null => "null",
        Bson::RegularExpression(_) => "regex",
        Bson::JavaScriptCode(_) => "javascript",
        Bson::JavaScriptCodeWithScope(_) => "javascriptWithScope",
        Bson::Int32(_) => "int",
        Bson::Int64(_) => "long",
        Bson::Timestamp(_) => "timestamp",
        Bson::Binary(_) => "binData",
        Bson::ObjectId(_) => "objectId",
        Bson::DateTime(_) => "date",
        Bson::Symbol(_) => "symbol",
        Bson::Decimal128(_) => "decimal",
        Bson::Undefined => "undefined",
        Bson::MaxKey => "maxKey",
        Bson::MinKey => "minKey",
        Bson::DbPointer(_) => "dbPointer",
    }
}

/// Type family used for polymorphism detection: numeric widening is not polymorphism.
fn family(t: &str) -> &str {
    match t {
        "int" | "long" | "double" | "decimal" => "number",
        other => other,
    }
}

/// Canonical, type-tagged key of a scalar value (numbers compare across int/long/double).
pub fn value_key(b: &Bson) -> String {
    match b {
        Bson::ObjectId(o) => format!("oid:{}", o.to_hex()),
        Bson::String(s) => format!("s:{s}"),
        Bson::Int32(i) => format!("n:{i}"),
        Bson::Int64(i) => format!("n:{i}"),
        Bson::Double(d) if d.fract() == 0.0 && d.abs() < 9.0e15 => format!("n:{}", *d as i64),
        Bson::Double(d) => format!("n:{d}"),
        Bson::Boolean(v) => format!("b:{v}"),
        Bson::DateTime(d) => format!("d:{}", d.timestamp_millis()),
        other => format!("x:{}", bson_to_json(other)),
    }
}

/// BSON → plain JSON for results and profiles: ObjectId → hex string, dates → RFC 3339 strings,
/// numbers → JSON numbers, Decimal128 → number when representable (else string).
pub fn bson_to_json(b: &Bson) -> J {
    match b {
        Bson::Double(d) => serde_json::Number::from_f64(*d).map(J::Number).unwrap_or(J::Null),
        Bson::String(s) | Bson::Symbol(s) => J::String(s.clone()),
        Bson::Array(a) => J::Array(a.iter().map(bson_to_json).collect()),
        Bson::Document(d) => doc_to_json(d),
        Bson::Boolean(v) => J::Bool(*v),
        Bson::Null | Bson::Undefined => J::Null,
        Bson::Int32(i) => json!(i),
        Bson::Int64(i) => json!(i),
        Bson::ObjectId(o) => J::String(o.to_hex()),
        Bson::DateTime(d) => d.try_to_rfc3339_string().map(J::String).unwrap_or_else(|_| json!(d.timestamp_millis())),
        Bson::Timestamp(t) => json!({ "t": t.time, "i": t.increment }),
        Bson::Decimal128(d) => {
            let s = d.to_string();
            s.parse::<f64>().ok().and_then(serde_json::Number::from_f64).map(J::Number).unwrap_or(J::String(s))
        }
        other => other.clone().into_relaxed_extjson(),
    }
}

pub fn doc_to_json(d: &Document) -> J {
    J::Object(d.iter().map(|(k, v)| (k.clone(), bson_to_json(v))).collect())
}

/// Numeric value of a BSON scalar, if it is a number.
pub fn bson_f64(b: &Bson) -> Option<f64> {
    match b {
        Bson::Double(d) => Some(*d),
        Bson::Int32(i) => Some(f64::from(*i)),
        Bson::Int64(i) => Some(*i as f64),
        Bson::Decimal128(d) => d.to_string().parse().ok(),
        _ => None,
    }
}

/// Resolve a dotted path inside a document without traversing arrays.
pub fn get_path<'a>(doc: &'a Document, path: &str) -> Option<&'a Bson> {
    let mut parts = path.split('.');
    let mut cur = doc.get(parts.next()?)?;
    for p in parts {
        cur = match cur {
            Bson::Document(d) => d.get(p)?,
            _ => return None,
        };
    }
    Some(cur)
}

#[derive(Debug, Default)]
struct PathAcc {
    container: String,
    parent_array: Option<String>,
    occurrences: u64,
    nulls: u64,
    types: BTreeMap<&'static str, u64>,
    lens: Vec<u32>,
    el_types: BTreeMap<&'static str, u64>,
    values: Vec<Bson>,
    /// Scalar values seen in total (`values` is capped).
    value_count: u64,
    /// Values sit inside arrays (array of scalars at this path).
    in_array_values: bool,
}

/// Result of inferring one collection's sample.
#[derive(Debug, Default)]
pub struct Inferred {
    pub sampled: u64,
    pub estimated_rows: Option<u64>,
    pub fields: Vec<FieldInfo>,
    pub discriminators: Vec<DiscriminatorInfo>,
    pub unstable: bool,
    values: HashMap<String, Vec<Bson>>,
    containers: HashMap<String, u64>,
    profiles: Vec<Profile>,
}

impl Inferred {
    /// Sampled scalar values of a path (capped). Arrays of scalars contribute their elements.
    pub fn values(&self, path: &str) -> &[Bson] {
        self.values.get(path).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn field(&self, path: &str) -> Option<&FieldInfo> {
        self.fields.iter().find(|f| f.path == path)
    }

    /// Per-path profiles (distinct estimate, null/missing fractions, top values), `object` filled in.
    pub fn profiles(&self, object: &str) -> Vec<Profile> {
        self.profiles
            .iter()
            .cloned()
            .map(|mut p| {
                p.object = object.to_owned();
                p
            })
            .collect()
    }

    pub fn into_object_info(self, name: &str, kind: &str) -> ObjectInfo {
        ObjectInfo {
            name: name.to_owned(),
            estimated_rows: self.estimated_rows,
            fields: self.fields,
            indexes: vec![],
            kind: kind.to_owned(),
            sampled: self.sampled,
            discriminators: self.discriminators,
            declared_schema: None,
            unstable: self.unstable,
        }
    }

    pub fn containers(&self, container: &str) -> u64 {
        self.containers.get(container).copied().unwrap_or(0)
    }
}

struct Walker<'o> {
    opts: &'o InferOptions,
    paths: BTreeMap<String, PathAcc>,
    containers: HashMap<String, u64>,
}

fn join(prefix: &str, k: &str) -> String {
    if prefix.is_empty() { k.to_owned() } else { format!("{prefix}.{k}") }
}

impl Walker<'_> {
    fn acc(&mut self, path: &str, container: &str, parent_array: Option<&str>) -> Option<&mut PathAcc> {
        if !self.paths.contains_key(path) {
            if self.paths.len() >= self.opts.max_paths {
                return None;
            }
            self.paths.insert(
                path.to_owned(),
                PathAcc {
                    container: container.to_owned(),
                    parent_array: parent_array.map(str::to_owned),
                    ..Default::default()
                },
            );
        }
        self.paths.get_mut(path)
    }

    fn push_value(&mut self, path: &str, v: &Bson, in_array: bool) {
        let cap = self.opts.max_values_per_path;
        if let Some(a) = self.paths.get_mut(path) {
            a.value_count += 1;
            a.in_array_values |= in_array;
            if a.values.len() < cap {
                a.values.push(v.clone());
            }
        }
    }

    fn walk(&mut self, doc: &Document, prefix: &str, parent_array: Option<&str>, depth: usize) {
        *self.containers.entry(prefix.to_owned()).or_default() += 1;
        if depth > self.opts.max_depth {
            return;
        }
        for (k, v) in doc {
            // Keys with dots or a `$` prefix cannot be addressed by dotted paths; skip them.
            if k.contains('.') || k.starts_with('$') {
                continue;
            }
            let path = join(prefix, k);
            let Some(a) = self.acc(&path, prefix, parent_array) else {
                continue;
            };
            a.occurrences += 1;
            *a.types.entry(bson_type_name(v)).or_default() += 1;
            match v {
                Bson::Null | Bson::Undefined => a.nulls += 1,
                Bson::Document(d) => self.walk(d, &path, parent_array, depth + 1),
                Bson::Array(items) => {
                    a.lens.push(items.len().min(u32::MAX as usize) as u32);
                    for el in items {
                        if let Some(a) = self.paths.get_mut(&path) {
                            *a.el_types.entry(bson_type_name(el)).or_default() += 1;
                        }
                        match el {
                            Bson::Document(d) => self.walk(d, &path, Some(&path), depth + 1),
                            Bson::Array(_) | Bson::Null | Bson::Undefined => {}
                            scalar => self.push_value(&path, scalar, true),
                        }
                    }
                }
                scalar => self.push_value(&path, scalar, false),
            }
        }
    }
}

fn percentile(sorted: &[u32], p: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Guaranteed-Error Estimator (Charikar et al., PODS 2000): `sqrt(N/n)·f1 + Σ_{j≥2} f_j`,
/// clamped to `[d, N]`. `n` = sampled values, `population` = estimated total values.
pub fn gee_distinct(counts: &HashMap<String, u64>, n: u64, population: u64) -> u64 {
    let d = counts.len() as u64;
    if n == 0 {
        return 0;
    }
    let population = population.max(n);
    let f1 = counts.values().filter(|c| **c == 1).count() as f64;
    let est = (population as f64 / n as f64).sqrt() * f1 + (d as f64 - f1);
    (est.round() as u64).clamp(d, population)
}

const DISCRIMINATOR_NAMES: &[&str] = &["kind", "_t", "__t", "_class", "_type", "type", "subtype"];

fn discriminator_name_hint(path: &str) -> bool {
    let l = path.to_ascii_lowercase();
    DISCRIMINATOR_NAMES.contains(&l.as_str()) || l.ends_with("type") || l.ends_with("_kind") || l.ends_with("kind")
}

/// Does an object's key set look like data (dates, numbers, ObjectIds) rather than a schema?
fn data_like_key(k: &str) -> bool {
    let b = k.as_bytes();
    let hex24 = k.len() == 24 && k.chars().all(|c| c.is_ascii_hexdigit());
    let numeric = !k.is_empty() && k.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '_');
    let date = b.len() >= 7 && b[..4].iter().all(u8::is_ascii_digit) && (b[4] == b'-' || b[4] == b'/');
    hex24 || numeric || date
}

/// Infers per-path statistics from a sample. `estimated_rows` scales distinct estimates.
pub fn infer(docs: &[Document], estimated_rows: Option<u64>, opts: &InferOptions) -> Inferred {
    let mut w = Walker { opts, paths: BTreeMap::new(), containers: HashMap::new() };
    for d in docs {
        w.walk(d, "", None, 0);
    }
    let sampled = docs.len() as u64;
    let scale = match estimated_rows {
        Some(n) if sampled > 0 && n > sampled => n as f64 / sampled as f64,
        _ => 1.0,
    };

    // Dynamic-key objects: many child keys that look like data, or very many sparse keys.
    let mut dynamic: BTreeSet<String> = BTreeSet::new();
    {
        let mut children: HashMap<&str, Vec<(&str, f64)>> = HashMap::new();
        for (p, a) in &w.paths {
            let parent_count = w.containers.get(&a.container).copied().unwrap_or(0).max(1);
            let key = p.rsplit('.').next().unwrap_or(p);
            children.entry(a.container.as_str()).or_default().push((key, a.occurrences as f64 / parent_count as f64));
        }
        for (container, kids) in &children {
            if container.is_empty() || w.paths.get(*container).is_some_and(|a| a.types.contains_key("array")) {
                continue;
            }
            let data_keys = kids.iter().filter(|(k, _)| data_like_key(k)).count();
            let avg_presence = kids.iter().map(|(_, p)| p).sum::<f64>() / kids.len() as f64;
            if (kids.len() >= 5 && data_keys * 10 >= kids.len() * 8) || (kids.len() > 50 && avg_presence < 0.2) {
                dynamic.insert((*container).to_owned());
            }
        }
    }
    let under_dynamic = |p: &str| {
        dynamic.iter().any(|d| p.len() > d.len() && p.starts_with(d.as_str()) && p.as_bytes()[d.len()] == b'.')
    };

    let mut fields = Vec::new();
    let mut values = HashMap::new();
    let mut profiles = Vec::new();
    let mut polymorphic_paths = 0usize;
    for (path, a) in w.paths {
        if under_dynamic(&path) {
            continue;
        }
        let containers = w.containers.get(&a.container).copied().unwrap_or(0).max(1);
        let mut types: Vec<(&str, u64)> = a.types.iter().map(|(t, n)| (*t, *n)).collect();
        types.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(y.0)));
        let families: BTreeSet<&str> =
            a.types.keys().filter(|t| **t != "null" && **t != "undefined").map(|t| family(t)).collect();
        let polymorphic = families.len() > 1;
        if polymorphic {
            polymorphic_paths += 1;
        }
        let arrays = a.types.get("array").copied().unwrap_or(0);
        let is_array = arrays > 0 && arrays * 2 >= a.occurrences - a.nulls;
        let array = (arrays > 0).then(|| {
            let mut lens = a.lens.clone();
            lens.sort_unstable();
            ArrayStats {
                len_p50: percentile(&lens, 0.5),
                len_p99: percentile(&lens, 0.99),
                len_max: lens.last().copied().unwrap_or(0),
                empty_fraction: lens.iter().filter(|l| **l == 0).count() as f32 / lens.len().max(1) as f32,
                element_types: a.el_types.iter().map(|(t, n)| ((*t).to_owned(), *n)).collect(),
            }
        });

        // Distinct estimate and top values over the canonical value keys.
        let mut counts: HashMap<String, u64> = HashMap::new();
        let mut repr: HashMap<String, &Bson> = HashMap::new();
        for v in &a.values {
            let k = value_key(v);
            *counts.entry(k.clone()).or_default() += 1;
            repr.entry(k).or_insert(v);
        }
        let n = a.values.len() as u64;
        let distinct = (n > 0).then(|| {
            let population = (a.value_count as f64 * scale).round() as u64;
            gee_distinct(&counts, n, population)
        });
        let mut top: Vec<(J, u64, String)> =
            counts.iter().map(|(k, c)| (bson_to_json(repr[k]), *c, k.clone())).collect();
        top.sort_by(|x, y| y.1.cmp(&x.1).then(x.2.cmp(&y.2)));
        top.truncate(opts.top_k);
        let top: Vec<(J, u64)> = top.into_iter().map(|(v, c, _)| (v, c)).collect();
        let low_card =
            !counts.is_empty() && counts.len() <= opts.low_cardinality && (counts.len() as u64) * 2 <= n.max(2);

        let presence = a.occurrences as f32 / containers as f32;
        let null_fraction = a.nulls as f32 / containers as f32;
        profiles.push(Profile {
            object: String::new(),
            path: path.clone(),
            distinct_estimate: distinct,
            null_fraction: (1.0 - presence + null_fraction).clamp(0.0, 1.0),
            top_values: top.clone(),
            missing_fraction: (1.0 - presence).clamp(0.0, 1.0),
        });
        fields.push(FieldInfo {
            path: path.clone(),
            types: types.iter().map(|(t, _)| (*t).to_owned()).collect(),
            presence,
            is_array,
            type_counts: a.types.iter().map(|(t, n)| ((*t).to_owned(), *n)).collect(),
            null_fraction,
            array,
            parent_array: a.parent_array.clone(),
            polymorphic,
            dynamic_keys: dynamic.contains(&path),
            distinct_estimate: distinct,
            top_values: if low_card { top } else { vec![] },
        });
        if !a.values.is_empty() {
            values.insert(path, a.values);
        }
    }

    let top_level_keys = fields.iter().filter(|f| !f.path.contains('.')).count();
    let unstable = polymorphic_paths > 5 || top_level_keys > 200;
    let containers = w.containers;
    let discriminators = detect_discriminators(docs, &fields, &values, sampled);
    Inferred { sampled, estimated_rows, fields, discriminators, unstable, values, containers, profiles }
}

/// A root-level, low-cardinality string field is a discriminator when its name says so
/// (`type`, `kind`, `_t`, …) or when its values predict which other top-level paths are present.
fn detect_discriminators(
    docs: &[Document],
    fields: &[FieldInfo],
    values: &HashMap<String, Vec<Bson>>,
    sampled: u64,
) -> Vec<DiscriminatorInfo> {
    let mut out = Vec::new();
    if sampled < 10 {
        return out;
    }
    let top_level: Vec<&str> =
        fields.iter().filter(|f| !f.path.contains('.') && f.path != "_id").map(|f| f.path.as_str()).collect();
    let min_group = (sampled as f64 * 0.02).ceil().max(2.0) as u64;
    for f in fields {
        if f.path.contains('.') || f.dominant_type() != Some("string") || f.presence < 0.95 || f.is_array {
            continue;
        }
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for v in values.get(&f.path).into_iter().flatten() {
            if let Bson::String(s) = v {
                *counts.entry(s.clone()).or_default() += 1;
            }
        }
        let groups: Vec<(&String, &u64)> = counts.iter().filter(|(_, c)| **c >= min_group).collect();
        if counts.len() < 2 || counts.len() > 20 || groups.len() < 2 {
            continue;
        }
        // presence(p | value) for each qualifying value group.
        let mut per_group: HashMap<&str, HashMap<&str, u64>> = HashMap::new();
        for d in docs {
            let Some(Bson::String(v)) = d.get(&f.path) else {
                continue;
            };
            if counts.get(v).copied().unwrap_or(0) < min_group {
                continue;
            }
            let g = per_group.entry(v.as_str()).or_default();
            for p in &top_level {
                if *p != f.path && d.contains_key(*p) {
                    *g.entry(p).or_default() += 1;
                }
            }
        }
        let mut predictive = Vec::new();
        for p in &top_level {
            if *p == f.path {
                continue;
            }
            let shares: Vec<f64> = groups
                .iter()
                .map(|(v, c)| {
                    per_group.get(v.as_str()).and_then(|g| g.get(p)).copied().unwrap_or(0) as f64 / **c as f64
                })
                .collect();
            let max = shares.iter().copied().fold(0.0, f64::max);
            let min = shares.iter().copied().fold(1.0, f64::min);
            if max - min >= 0.9 {
                predictive.push((*p).to_owned());
            }
        }
        let hint = discriminator_name_hint(&f.path);
        let confidence = match (hint && counts.len() <= 12, predictive.len()) {
            (true, 0) => 0.6,
            (true, _) => 0.9,
            (false, n) if n >= 2 => 0.7,
            _ => continue,
        };
        let mut vals: Vec<(String, u64)> = counts.into_iter().collect();
        vals.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out.push(DiscriminatorInfo { path: f.path.clone(), values: vals, predictive_paths: predictive, confidence });
    }
    out
}

/// A field whose sampled values may reference another collection's `_id`.
#[derive(Debug, Clone)]
pub struct RefCandidate {
    pub path: String,
    /// `objectId`, `string`, `int`, `long`, `double`.
    pub value_type: String,
    pub many_valued: bool,
    /// Distinct sampled values (capped), used for the `$in` containment probe.
    pub values: Vec<Bson>,
    pub distinct_ratio: f32,
    pub key_like_name: bool,
}

/// `customerId` / `customer_id` / `customerRef` → `customer`.
pub fn reference_stem(path: &str) -> Option<String> {
    let last = path.rsplit('.').next().unwrap_or(path);
    for suffix in ["_id", "Id", "ID", "_ref", "Ref", "_key", "Key"] {
        if let Some(stem) = last.strip_suffix(suffix)
            && !stem.is_empty()
        {
            return Some(stem.trim_end_matches('_').to_ascii_lowercase());
        }
    }
    if let Some(stem) = last.strip_suffix("Ids").or_else(|| last.strip_suffix("_ids"))
        && !stem.is_empty()
    {
        return Some(stem.trim_end_matches('_').to_ascii_lowercase());
    }
    None
}

/// Selects reference candidates: ObjectId-typed paths (other than `_id`s) and key-like names
/// (`*Id`, `*_id`, `*Ref`) holding strings or integers.
pub fn reference_candidates(inf: &Inferred, max_values: usize) -> Vec<RefCandidate> {
    let mut out = Vec::new();
    for f in &inf.fields {
        let last = f.path.rsplit('.').next().unwrap_or(&f.path);
        if last == "_id" {
            continue;
        }
        let vals = inf.values(&f.path);
        if vals.is_empty() {
            continue;
        }
        let mut by_type: BTreeMap<&str, u64> = BTreeMap::new();
        for v in vals {
            *by_type.entry(bson_type_name(v)).or_default() += 1;
        }
        let Some((ty, n)) = by_type.iter().max_by_key(|(_, n)| **n).map(|(t, n)| (*t, *n)) else {
            continue;
        };
        if (n as f64) < 0.9 * vals.len() as f64 {
            continue;
        }
        let key_like = reference_stem(&f.path).is_some();
        let hex24 = ty == "string"
            && vals
                .iter()
                .all(|v| matches!(v, Bson::String(s) if s.len() == 24 && s.chars().all(|c| c.is_ascii_hexdigit())));
        let ok = ty == "objectId" || hex24 || (key_like && matches!(ty, "string" | "int" | "long" | "double"));
        if !ok {
            continue;
        }
        let mut seen = BTreeSet::new();
        let mut distinct = Vec::new();
        for v in vals {
            if bson_type_name(v) == ty && seen.insert(value_key(v)) && distinct.len() < max_values {
                distinct.push(v.clone());
            }
        }
        out.push(RefCandidate {
            path: f.path.clone(),
            value_type: ty.to_owned(),
            many_valued: f.is_array,
            distinct_ratio: seen.len() as f32 / vals.len() as f32,
            values: distinct,
            key_like_name: key_like,
        });
    }
    out
}

/// Does the candidate's name point at `target` (`customerId` → `customers`)?
pub fn name_matches(candidate_path: &str, target: &str) -> bool {
    let Some(stem) = reference_stem(candidate_path) else {
        return false;
    };
    let t = target.to_ascii_lowercase().replace(['_', '-'], "");
    let stem = stem.replace(['_', '-'], "");
    !stem.is_empty() && (t == stem || crate::bootstrap::singular(&t) == stem || t.starts_with(&stem))
}

/// Are the candidate's values comparable with a target `_id` of type `target_id_type`?
pub fn type_compatible(value_type: &str, target_id_type: &str) -> bool {
    family(value_type) == family(target_id_type)
}

/// In-memory containment ratio of `values` in `target_keys` (canonical [`value_key`]s).
/// The connector uses an indexed `$in` probe instead; this backs tests and offline snapshots.
pub fn overlap(values: &[Bson], target_keys: &BTreeSet<String>) -> (u64, u64) {
    let mut probed = BTreeSet::new();
    let mut matched = 0;
    for v in values {
        let k = value_key(v);
        if probed.insert(k.clone()) && target_keys.contains(&k) {
            matched += 1;
        }
    }
    (matched, probed.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mongo::bson::{DateTime, doc, oid::ObjectId};

    fn orders() -> Vec<Document> {
        (0..100)
            .map(|i| {
                let mut d = doc! {
                    "_id": i,
                    "status": if i % 3 == 0 { "paid" } else { "shipped" },
                    "createdAt": DateTime::from_millis(1_780_000_000_000 + i as i64),
                    "total": if i % 2 == 0 { Bson::Int32(i) } else { Bson::Double(i as f64 + 0.5) },
                    "lines": (0..(i % 4)).map(|j| Bson::Document(doc! { "sku": format!("S{j}"), "qty": j })).collect::<Vec<_>>(),
                    "tags": ["a", "b"],
                };
                if i % 10 == 0 {
                    d.insert("note", Bson::Null);
                }
                if i % 5 != 0 {
                    d.insert("discount", 0.1);
                }
                d
            })
            .collect()
    }

    #[test]
    fn path_stats_and_type_histograms() {
        let inf = infer(&orders(), Some(10_000), &InferOptions::default());
        assert_eq!(inf.sampled, 100);
        let total = inf.field("total").unwrap();
        assert_eq!(total.type_counts.get("int"), Some(&50));
        assert_eq!(total.type_counts.get("double"), Some(&50));
        assert!(!total.polymorphic, "int/double is numeric widening, not polymorphism");
        assert_eq!(inf.field("createdAt").unwrap().dominant_type(), Some("date"));
        assert!((inf.field("discount").unwrap().presence - 0.8).abs() < 1e-6);
        let note = inf.field("note").unwrap();
        assert!((note.presence - 0.1).abs() < 1e-6);
        assert!((note.null_fraction - 0.1).abs() < 1e-6);

        let lines = inf.field("lines").unwrap();
        assert!(lines.is_array);
        let arr = lines.array.as_ref().unwrap();
        assert!(arr.of_documents());
        assert_eq!(arr.len_max, 3);
        assert_eq!(arr.len_p99, 3);
        assert!((arr.empty_fraction - 0.25).abs() < 1e-6);
        // Element paths are relative to the array's element documents.
        let qty = inf.field("lines.qty").unwrap();
        assert_eq!(qty.parent_array.as_deref(), Some("lines"));
        assert!((qty.presence - 1.0).abs() < 1e-6);
        let tags = inf.field("tags").unwrap();
        assert!(tags.is_array && !tags.array.as_ref().unwrap().of_documents());
        assert_eq!(inf.values("tags").len(), 200);

        let status = inf.field("status").unwrap();
        assert_eq!(status.top_values[0], (json!("shipped"), 66));
        assert_eq!(status.distinct_estimate, Some(2));
        let id = inf.field("_id").unwrap();
        assert!(id.top_values.is_empty(), "high-cardinality paths keep no top values");
        assert!(id.distinct_estimate.unwrap() >= 100);
    }

    #[test]
    fn polymorphic_and_dynamic_keys() {
        let docs: Vec<Document> = (0..20)
            .map(|i| {
                let mut daily = Document::new();
                daily.insert(format!("2026-07-{:02}", i % 28 + 1), i);
                daily.insert(format!("2026-08-{:02}", i % 28 + 1), i);
                daily.insert(format!("2026-09-{:02}", i % 28 + 1), i);
                daily.insert(format!("2026-10-{:02}", i % 28 + 1), i);
                daily.insert(format!("2026-11-{:02}", i % 28 + 1), i);
                doc! { "code": if i % 2 == 0 { Bson::String("x".into()) } else { Bson::Int32(i) }, "daily": daily }
            })
            .collect();
        let inf = infer(&docs, None, &InferOptions::default());
        assert!(inf.field("code").unwrap().polymorphic);
        assert!(inf.field("daily").unwrap().dynamic_keys);
        assert!(inf.fields.iter().all(|f| !f.path.starts_with("daily.")), "map keys are not columns");
    }

    #[test]
    fn discriminator_by_name_and_by_structure() {
        let docs: Vec<Document> = (0..60)
            .map(|i| match i % 3 {
                0 => doc! { "_id": i, "type": "invoice", "amount": 10, "dueAt": DateTime::now() },
                1 => doc! { "_id": i, "type": "receipt", "amount": 5, "paidBy": "card" },
                _ => doc! { "_id": i, "type": "quote", "validUntil": DateTime::now(), "amount": 1 },
            })
            .collect();
        let inf = infer(&docs, None, &InferOptions::default());
        assert_eq!(inf.discriminators.len(), 1);
        let d = &inf.discriminators[0];
        assert_eq!(d.path, "type");
        assert_eq!(d.values.len(), 3);
        assert!(d.predictive_paths.contains(&"dueAt".to_string()));
        assert!(d.confidence >= 0.9);

        // A status field that predicts nothing is not a discriminator.
        let docs: Vec<Document> =
            (0..60).map(|i| doc! { "_id": i, "status": if i % 2 == 0 { "a" } else { "b" }, "x": 1 }).collect();
        assert!(infer(&docs, None, &InferOptions::default()).discriminators.is_empty());
    }

    #[test]
    fn reference_candidates_and_overlap() {
        let customers: Vec<ObjectId> = (0..10).map(|_| ObjectId::new()).collect();
        let docs: Vec<Document> = (0..50)
            .map(|i| doc! { "_id": ObjectId::new(), "customerId": customers[i % 10], "sku": format!("S{i}"), "lines": [{ "_id": ObjectId::new(), "qty": 1 }] })
            .collect();
        let inf = infer(&docs, None, &InferOptions::default());
        let c = reference_candidates(&inf, 1000);
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!(c[0].path, "customerId");
        assert_eq!(c[0].value_type, "objectId");
        assert_eq!(c[0].values.len(), 10);
        assert!((c[0].distinct_ratio - 0.2).abs() < 1e-6);
        assert!(name_matches("customerId", "customers"));
        assert!(!name_matches("customerId", "orders"));
        assert!(type_compatible("int", "double") && !type_compatible("objectId", "string"));

        let mut target: BTreeSet<String> = customers[..9].iter().map(|o| value_key(&Bson::ObjectId(*o))).collect();
        assert_eq!(overlap(&c[0].values, &target), (9, 10));
        target.insert(value_key(&Bson::ObjectId(customers[9])));
        assert_eq!(overlap(&c[0].values, &target), (10, 10));
    }

    #[test]
    fn gee_scales_singletons_only() {
        let mut counts = HashMap::new();
        counts.insert("a".to_string(), 5);
        counts.insert("b".to_string(), 5);
        assert_eq!(gee_distinct(&counts, 10, 1_000_000), 2);
        let singles: HashMap<String, u64> = (0..100).map(|i| (i.to_string(), 1)).collect();
        assert_eq!(gee_distinct(&singles, 100, 10_000), 1_000);
    }

    #[test]
    fn bson_json_conversion() {
        let oid = ObjectId::parse_str("65a1f0c2e4b0a1b2c3d4e5f6").unwrap();
        let d = doc! { "o": oid, "t": DateTime::from_millis(0), "n": 3_i64, "f": 1.5, "a": [1, "x"], "z": Bson::Null };
        assert_eq!(
            doc_to_json(&d),
            json!({ "o": "65a1f0c2e4b0a1b2c3d4e5f6", "t": "1970-01-01T00:00:00Z", "n": 3, "f": 1.5, "a": [1, "x"], "z": null })
        );
        assert_eq!(get_path(&doc! { "a": { "b": 2 } }, "a.b"), Some(&Bson::Int32(2)));
        assert_eq!(get_path(&doc! { "a": [{ "b": 2 }] }, "a.b"), None);
    }
}
