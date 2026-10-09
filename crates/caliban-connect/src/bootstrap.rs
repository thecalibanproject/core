//! Ontology bootstrap: [`SchemaSnapshot`] → `proposed` CSM elements for human curation
//! (research 08, "Schema inference & ontology bootstrap", step 4–5).
//!
//! - One **root entity** per collection (`orders` → `Order`), keyed by `_id`.
//! - **Subtype entities** per value of a detected discriminator (`type`/`kind`/…, or a field whose
//!   values predict which paths are present), bound to the same collection with a discriminator
//!   and their own replica table.
//! - **Embedded entities** for arrays of documents (`orders.lines` → `OrderLine`).
//! - **Attributes** for scalar paths: id `<Entity>.<column>`, column = snake_case of the path
//!   relative to the entity (`createdAt` → `created_at`, `address.city` → `address_city`), data
//!   type from the dominant BSON type. Polymorphic paths get a lower confidence and a note.
//! - **Reference relations** for candidates whose sampled values are contained in the target's
//!   `_id` (overlap ≥ `min_overlap`); always `verified: false` until a human approves them.
//!
//! Names and ids are deterministic so re-running the bootstrap produces stable ids that can be
//! diffed against the published ontology.

use crate::{FieldInfo, ObjectInfo, ReferenceInfo, SchemaSnapshot};
use caliban_ontology::model::{
    AttributeDef, Cardinality, DataType, Discriminator, ElementSpec, EntityBinding, EntityDef, RelationDef,
};
use caliban_ontology::{Element, Provenance, Status};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct ProposeOptions {
    /// Minimum containment ratio for proposing a reference relation (research: 0.95).
    pub min_overlap: f32,
    /// Skip attributes present in fewer than this share of their containers.
    pub min_presence: f32,
}

impl Default for ProposeOptions {
    fn default() -> Self {
        Self { min_overlap: 0.95, min_presence: 0.01 }
    }
}

/// English singular of a collection-ish word (`orders` → `order`, `categories` → `category`).
pub fn singular(word: &str) -> String {
    let l = word.to_ascii_lowercase();
    let cut = |n: usize| word[..word.len() - n].to_owned();
    if l.ends_with("ies") && l.len() > 3 {
        format!("{}y", cut(3))
    } else if ["sses", "xes", "ches", "shes", "zes"].iter().any(|s| l.ends_with(s)) {
        cut(2)
    } else if l.ends_with("ss") || l.ends_with("us") || l.ends_with("is") || l.len() <= 3 {
        word.to_owned()
    } else if l.ends_with('s') {
        cut(1)
    } else {
        word.to_owned()
    }
}

/// Split identifiers into lowercase words: `createdAt` → [created, at], `order_items` → [order, items].
fn words(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = s.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' || c == '-' || c == '.' || c == ' ' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let boundary = c.is_ascii_uppercase()
            && !cur.is_empty()
            && (chars[i - 1].is_ascii_lowercase()
                || chars[i - 1].is_ascii_digit()
                || chars.get(i + 1).is_some_and(|n| n.is_ascii_lowercase()));
        if boundary {
            out.push(std::mem::take(&mut cur));
        }
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Column name for a document path: `createdAt` → `created_at`, `address.city` → `address_city`.
/// Leading underscores are kept (`_id` stays `_id`).
pub fn snake_case(path: &str) -> String {
    let lead: String = path.chars().take_while(|c| *c == '_').collect();
    let w = words(path);
    if w.is_empty() { path.to_owned() } else { format!("{lead}{}", w.join("_")) }
}

/// `order_items` → `OrderItem` (singularized), `lines` → `Line`.
pub fn entity_name(collection: &str) -> String {
    let mut w = words(collection);
    if let Some(last) = w.last_mut() {
        *last = singular(last);
    }
    w.iter()
        .map(|x| {
            let mut c = x.chars();
            c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
        })
        .collect()
}

fn human(s: &str) -> String {
    let w = words(s).join(" ");
    let mut c = w.chars();
    c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
}

/// Map a BSON type name to the ontology data type.
pub fn data_type_of(bson_type: &str) -> Option<DataType> {
    Some(match bson_type {
        "string" | "objectId" | "symbol" | "uuid" => DataType::String,
        "int" | "long" | "double" | "decimal" => DataType::Number,
        "date" | "timestamp" => DataType::Timestamp,
        "bool" => DataType::Bool,
        _ => return None,
    })
}

fn element(
    id: String,
    name: String,
    description: String,
    synonyms: Vec<String>,
    provenance: Provenance,
    confidence: f32,
    spec: ElementSpec,
) -> Element {
    Element {
        id,
        name,
        description: Some(description),
        synonyms,
        status: Status::Proposed,
        provenance,
        confidence: Some((confidence * 100.0).round() / 100.0),
        spec,
    }
}

fn pct(x: f32) -> String {
    format!("{:.0}%", x * 100.0)
}

/// Per-collection naming context: which entity owns which array path.
struct Owners {
    /// array path (from document root) → embedded entity id
    arrays: BTreeMap<String, String>,
    root: String,
}

impl Owners {
    /// Entity owning `path` and the path relative to that entity's document/element.
    fn owner<'a>(&'a self, f: &'a FieldInfo) -> (&'a str, &'a str) {
        match &f.parent_array {
            Some(a) => match self.arrays.get(a) {
                Some(e) => {
                    (e.as_str(), f.path.strip_prefix(a.as_str()).map(|p| p.trim_start_matches('.')).unwrap_or(&f.path))
                }
                None => (self.root.as_str(), f.path.as_str()),
            },
            None => (self.root.as_str(), f.path.as_str()),
        }
    }
}

/// Propose ontology elements for a snapshot. All elements are `Status::Proposed`.
pub fn propose(snapshot: &SchemaSnapshot) -> Vec<Element> {
    propose_with(snapshot, &ProposeOptions::default())
}

pub fn propose_with(snapshot: &SchemaSnapshot, opts: &ProposeOptions) -> Vec<Element> {
    let mut out = Vec::new();
    let mut owners_by_object: BTreeMap<&str, Owners> = BTreeMap::new();
    let mut used_ids: BTreeSet<String> = BTreeSet::new();

    for obj in &snapshot.objects {
        if obj.name.starts_with("system.") {
            continue;
        }
        let root = entity_name(&obj.name);
        let owners = propose_object(snapshot, obj, &root, opts, &mut out, &mut used_ids);
        owners_by_object.insert(obj.name.as_str(), owners);
    }
    for r in &snapshot.references {
        if let Some(e) = propose_relation(snapshot, r, &owners_by_object, opts) {
            out.push(e);
        }
    }
    out
}

fn propose_object(
    snapshot: &SchemaSnapshot,
    obj: &ObjectInfo,
    root: &str,
    opts: &ProposeOptions,
    out: &mut Vec<Element>,
    used_ids: &mut BTreeSet<String>,
) -> Owners {
    let unstable_note = if obj.unstable {
        " Collection flagged unstable (many polymorphic paths or keys): curate before use."
    } else {
        ""
    };
    let rows = obj.estimated_rows.map(|n| format!(" (~{n} documents)")).unwrap_or_default();
    let root_conf = if obj.unstable { 0.5 } else { 0.9 };
    out.push(element(
        root.to_owned(),
        human(root),
        format!(
            "Documents of the `{}` {}{rows}.{unstable_note}",
            obj.name,
            if obj.kind.is_empty() { "collection" } else { &obj.kind }
        ),
        vec![obj.name.clone()],
        Provenance::Introspect,
        root_conf,
        ElementSpec::Entity(EntityDef {
            binding: EntityBinding::Root {
                datasource: snapshot.datasource.clone(),
                collection: obj.name.clone(),
                table: None,
                discriminator: None,
            },
            keys: vec!["_id".into()],
        }),
    ));
    used_ids.insert(root.to_owned());

    // Subtypes from discriminators.
    for d in &obj.discriminators {
        let column = snake_case(&d.path);
        for (value, count) in &d.values {
            let id = format!("{}{root}", entity_name(value));
            if !used_ids.insert(id.clone()) {
                continue;
            }
            let share = *count as f32 / obj.sampled.max(1) as f32;
            out.push(element(
                id.clone(),
                human(&id),
                format!(
                    "Subtype of {root}: documents of `{}` where `{}` = \"{value}\" ({} of the sample). Discriminator evidence: {}.",
                    obj.name,
                    d.path,
                    pct(share),
                    if d.predictive_paths.is_empty() { "field name".to_owned() } else { format!("predicts presence of {}", d.predictive_paths.join(", ")) }
                ),
                vec![value.clone()],
                Provenance::Profile,
                d.confidence,
                ElementSpec::Entity(EntityDef {
                    binding: EntityBinding::Root {
                        datasource: snapshot.datasource.clone(),
                        collection: obj.name.clone(),
                        table: Some(format!("{}_{}", snake_case(value), obj.name)),
                        discriminator: Some(Discriminator { path: d.path.clone(), column: column.clone(), value: value.clone() }),
                    },
                    keys: vec!["_id".into()],
                }),
            ));
        }
    }

    // Embedded entities: arrays of documents, outermost first so parents exist before children.
    let mut owners = Owners { arrays: BTreeMap::new(), root: root.to_owned() };
    let mut arrays: Vec<&FieldInfo> =
        obj.fields.iter().filter(|f| f.is_array && f.array.as_ref().is_some_and(|a| a.of_documents())).collect();
    arrays.sort_by_key(|f| f.path.matches('.').count());
    for f in arrays {
        let (parent, rel) = owners.owner(f);
        let (parent, rel) = (parent.to_owned(), rel.to_owned());
        let last = rel.rsplit('.').next().unwrap_or(&rel);
        let mut id = format!("{parent}{}", entity_name(last));
        if !used_ids.insert(id.clone()) {
            id = format!("{parent}{}", entity_name(&rel));
            used_ids.insert(id.clone());
        }
        let a = f.array.clone().unwrap_or_default();
        out.push(element(
            id.clone(),
            human(&id),
            format!(
                "Elements of the `{rel}` array embedded in {parent} (1:N, owned). Present in {} of parents; length p50 {} / p99 {} / max {}; {} empty.",
                pct(f.presence),
                a.len_p50,
                a.len_p99,
                a.len_max,
                pct(a.empty_fraction)
            ),
            vec![rel.clone()],
            Provenance::Introspect,
            (0.85 * f.presence.max(0.5)).min(0.85),
            ElementSpec::Entity(EntityDef { binding: EntityBinding::Embedded { parent, array_path: rel, table: None }, keys: vec![] }),
        ));
        owners.arrays.insert(f.path.clone(), id);
    }

    // Attributes.
    let mut columns: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for f in &obj.fields {
        let (entity, rel) = owners.owner(f);
        if rel == "_id" && entity == root {
            continue; // the key; always projected
        }
        if f.presence < opts.min_presence || f.dynamic_keys {
            continue;
        }
        let Some(dominant) = f.dominant_type() else {
            continue;
        };
        if dominant == "object" || dominant == "array" {
            continue; // nested documents descend; arrays of documents are entities; scalar arrays: TODO multi-valued attributes
        }
        let Some(data_type) = data_type_of(dominant) else {
            continue;
        };
        let taken = columns.entry(entity.to_owned()).or_default();
        let mut column = snake_case(rel);
        if column.is_empty() {
            continue;
        }
        if taken.contains(&column) {
            let mut i = 2;
            while taken.contains(&format!("{column}_{i}")) {
                i += 1;
            }
            column = format!("{column}_{i}");
        }
        taken.insert(column.clone());
        let types: Vec<String> =
            f.types.iter().map(|t| format!("{t} {}", f.type_counts.get(t).copied().unwrap_or(0))).collect();
        let mut desc = format!(
            "`{}` in {}: present in {}, null in {}; types: {}.",
            rel,
            entity,
            pct(f.presence),
            pct(f.null_fraction),
            types.join(", ")
        );
        if let Some(d) = f.distinct_estimate {
            desc.push_str(&format!(" ~{d} distinct."));
        }
        if !f.top_values.is_empty() {
            let tv: Vec<String> = f.top_values.iter().take(5).map(|(v, n)| format!("{v} ({n})")).collect();
            desc.push_str(&format!(" Top values: {}.", tv.join(", ")));
        }
        if f.polymorphic {
            desc.push_str(" Polymorphic path: coercion needs a human decision.");
        }
        if dominant == "objectId" {
            desc.push_str(" ObjectId, projected as its hex string.");
        }
        let mut confidence = f.presence.min(1.0) * f.dominant_share();
        if f.polymorphic {
            confidence *= 0.5;
        }
        let synonyms = if rel != column { vec![rel.to_owned()] } else { vec![] };
        out.push(element(
            format!("{entity}.{column}"),
            human(rel),
            desc,
            synonyms,
            Provenance::Introspect,
            confidence,
            ElementSpec::Attribute(AttributeDef {
                entity: entity.to_owned(),
                path: rel.to_owned(),
                column,
                data_type,
                pii_class: None,
                unit: None,
            }),
        ));
    }
    owners
}

fn propose_relation(
    snapshot: &SchemaSnapshot,
    r: &ReferenceInfo,
    owners: &BTreeMap<&str, Owners>,
    opts: &ProposeOptions,
) -> Option<Element> {
    if r.overlap < opts.min_overlap {
        return None;
    }
    let from_obj = snapshot.object(&r.from_object)?;
    let to_obj = snapshot.object(&r.to_object)?;
    let field = from_obj.field(&r.from_path)?;
    let o = owners.get(r.from_object.as_str())?;
    let (from, local_path) = o.owner(field);
    let to = &owners.get(r.to_object.as_str())?.root;
    let cardinality = if r.many_valued {
        Cardinality::ManyToMany
    } else if r.local_distinct_ratio >= 0.99 && r.probed >= 20 {
        Cardinality::OneToOne
    } else {
        Cardinality::ManyToOne
    };
    let local_column = snake_case(local_path);
    let foreign_column = snake_case(&r.to_path);
    let confidence = r.overlap * if r.name_match { 1.0 } else { 0.85 };
    Some(element(
        format!("{from}.{local_column}->{to}"),
        format!("{from} → {to} ({local_path})"),
        format!(
            "Reference from `{}.{}` to `{}.{}`: {}/{} sampled {} values found ({} overlap){}. Unverified until approved.",
            r.from_object,
            r.from_path,
            r.to_object,
            r.to_path,
            r.matched,
            r.probed,
            r.value_type,
            pct(r.overlap),
            if r.name_match { "; field name matches the target" } else { "" }
        ),
        vec![local_path.to_owned()],
        Provenance::Profile,
        confidence,
        ElementSpec::Relation(RelationDef {
            from: from.to_owned(),
            to: to.clone(),
            cardinality,
            local_path: local_path.to_owned(),
            local_column,
            foreign_path: r.to_path.clone(),
            foreign_column,
            verified: false,
            foreign_indexed: to_obj.is_indexed(&r.to_path),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArrayStats, DiscriminatorInfo, IndexInfo};

    #[test]
    fn naming() {
        assert_eq!(snake_case("createdAt"), "created_at");
        assert_eq!(snake_case("unitPrice"), "unit_price");
        assert_eq!(snake_case("address.city"), "address_city");
        assert_eq!(snake_case("_id"), "_id");
        assert_eq!(snake_case("HTTPStatus"), "http_status");
        assert_eq!(entity_name("orders"), "Order");
        assert_eq!(entity_name("order_items"), "OrderItem");
        assert_eq!(entity_name("categories"), "Category");
        assert_eq!(entity_name("addresses"), "Address");
        assert_eq!(entity_name("lines"), "Line");
        assert_eq!(singular("status"), "status");
    }

    fn field(path: &str, ty: &str, presence: f32, parent_array: Option<&str>) -> FieldInfo {
        FieldInfo {
            path: path.into(),
            types: vec![ty.into()],
            presence,
            is_array: ty == "array",
            type_counts: [(ty.to_owned(), 100)].into_iter().collect(),
            null_fraction: 0.0,
            array: (ty == "array").then(|| ArrayStats {
                len_p50: 2,
                len_p99: 4,
                len_max: 4,
                empty_fraction: 0.0,
                element_types: [("object".to_owned(), 200)].into_iter().collect(),
            }),
            parent_array: parent_array.map(str::to_owned),
            polymorphic: false,
            dynamic_keys: false,
            distinct_estimate: None,
            top_values: vec![],
        }
    }

    fn snapshot() -> SchemaSnapshot {
        SchemaSnapshot {
            datasource: "dw".into(),
            objects: vec![
                ObjectInfo {
                    name: "orders".into(),
                    estimated_rows: Some(1000),
                    fields: vec![
                        field("_id", "objectId", 1.0, None),
                        field("status", "string", 1.0, None),
                        field("createdAt", "date", 1.0, None),
                        field("customerId", "objectId", 1.0, None),
                        field("lines", "array", 1.0, None),
                        field("lines.qty", "int", 1.0, Some("lines")),
                        field("lines.unitPrice", "double", 1.0, Some("lines")),
                        field("shipping", "object", 0.5, None),
                        field("shipping.city", "string", 0.5, None),
                    ],
                    indexes: vec![IndexInfo { name: "_id_".into(), keys: vec!["_id".into()], unique: true }],
                    kind: "collection".into(),
                    sampled: 1000,
                    discriminators: vec![],
                    declared_schema: None,
                    unstable: false,
                },
                ObjectInfo {
                    name: "customers".into(),
                    estimated_rows: Some(50),
                    fields: vec![
                        field("_id", "objectId", 1.0, None),
                        field("region", "string", 1.0, None),
                        field("kind", "string", 1.0, None),
                    ],
                    indexes: vec![],
                    kind: "collection".into(),
                    sampled: 50,
                    discriminators: vec![DiscriminatorInfo {
                        path: "kind".into(),
                        values: vec![("business".into(), 30), ("person".into(), 20)],
                        predictive_paths: vec![],
                        confidence: 0.6,
                    }],
                    declared_schema: None,
                    unstable: false,
                },
            ],
            references: vec![ReferenceInfo {
                from_object: "orders".into(),
                from_path: "customerId".into(),
                to_object: "customers".into(),
                to_path: "_id".into(),
                value_type: "objectId".into(),
                probed: 50,
                matched: 50,
                overlap: 1.0,
                many_valued: false,
                local_distinct_ratio: 0.05,
                name_match: true,
            }],
        }
    }

    #[test]
    fn proposes_entities_attributes_and_relations() {
        let els = propose(&snapshot());
        let ids: Vec<&str> = els.iter().map(|e| e.id.as_str()).collect();
        for want in [
            "Order",
            "OrderLine",
            "Customer",
            "BusinessCustomer",
            "PersonCustomer",
            "Order.status",
            "Order.created_at",
            "Order.customer_id",
            "Order.shipping_city",
            "OrderLine.qty",
            "OrderLine.unit_price",
            "Customer.region",
            "Order.customer_id->Customer",
        ] {
            assert!(ids.contains(&want), "missing {want} in {ids:?}");
        }
        assert!(!ids.contains(&"Order._id") && !ids.contains(&"Order.lines") && !ids.contains(&"Order.shipping"));
        assert!(els.iter().all(|e| e.status == Status::Proposed));

        let line = els.iter().find(|e| e.id == "OrderLine").unwrap();
        assert_eq!(
            line.spec,
            ElementSpec::Entity(EntityDef {
                binding: EntityBinding::Embedded { parent: "Order".into(), array_path: "lines".into(), table: None },
                keys: vec![]
            })
        );
        let price = els.iter().find(|e| e.id == "OrderLine.unit_price").unwrap();
        let ElementSpec::Attribute(a) = &price.spec else { panic!() };
        assert_eq!((a.path.as_str(), a.column.as_str(), a.data_type), ("unitPrice", "unit_price", DataType::Number));
        let created = els.iter().find(|e| e.id == "Order.created_at").unwrap();
        let ElementSpec::Attribute(a) = &created.spec else { panic!() };
        assert_eq!(a.data_type, DataType::Timestamp);

        let rel = els.iter().find(|e| e.id == "Order.customer_id->Customer").unwrap();
        assert_eq!(rel.provenance, Provenance::Profile);
        assert!(rel.requires_human_review());
        let ElementSpec::Relation(r) = &rel.spec else { panic!() };
        assert_eq!(r.cardinality, Cardinality::ManyToOne);
        assert!(!r.verified && r.foreign_indexed);
        assert_eq!((r.local_column.as_str(), r.foreign_column.as_str()), ("customer_id", "_id"));
        assert!(rel.description.as_ref().unwrap().contains("100% overlap"));

        let sub = els.iter().find(|e| e.id == "BusinessCustomer").unwrap();
        let ElementSpec::Entity(EntityDef {
            binding: EntityBinding::Root { discriminator: Some(d), table, .. }, ..
        }) = &sub.spec
        else {
            panic!()
        };
        assert_eq!((d.path.as_str(), d.value.as_str()), ("kind", "business"));
        assert_eq!(table.as_deref(), Some("business_customers"));
    }

    #[test]
    fn low_overlap_reference_is_not_proposed() {
        let mut s = snapshot();
        s.references[0].overlap = 0.6;
        assert!(!propose(&s).iter().any(|e| matches!(e.spec, ElementSpec::Relation(_))));
    }
}
