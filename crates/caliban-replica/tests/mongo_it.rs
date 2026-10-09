//! End-to-end test against a real MongoDB replica set (see `scripts/mongo-it.sh`).
//!
//! Gated by `CALIBAN_MONGO_TEST_URI` (a URI for a user that can seed data and create users,
//! e.g. `mongodb://admin:pw@127.0.0.1:27018/?directConnection=true&authSource=admin`). Skips with
//! a message when unset.
//!
//! (a) introspect + propose: Order / OrderLine (embedded) / Customer and the customerId →
//!     customers reference with high overlap;
//! (b) compile the reference CQIR with `plan` + `mongo::lower`, explain-gate it, run it natively;
//! (c) snapshot the replica and run `sql::lower` output through DataFusion;
//! (d) both lanes return the same rows (shadow comparison), for three query shapes;
//! (e) insert/update/delete through the change stream: the replica follows, the watermark advances.

use caliban_connect::bootstrap;
use caliban_connect::explain::GatePolicy;
use caliban_connect::mongo::bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use caliban_connect::mongo::mongodb::{Client, Collection, Database};
use caliban_connect::mongo::{MongoConfig, MongoConnector};
use caliban_connect::{ConnectError, Connector};
use caliban_ontology::compile::{mongo, plan, sql};
use caliban_ontology::cqir::{Filter, Query};
use caliban_ontology::model::{
    Aggregation, ElementSpec, EntityBinding, MetricDef, MetricExpr, Model,
};
use caliban_ontology::{Element, Ontology, Provenance, Status};
use caliban_replica::{Replica, ReplicaConfig, ReplicaStatus, batches_to_json};
use serde_json::{Value as J, json};
use std::time::{Duration, Instant};

const DB: &str = "caliban_it";
const RO_USER: &str = "caliban_it_ro";
const RO_PASS: &str = "caliban_it_ro_pw";

/// Rewrites the credentials of a `mongodb://` URI and pins `authSource=admin`.
fn with_credentials(uri: &str, user: &str, pass: &str) -> String {
    let (scheme, rest) = uri.split_once("://").expect("uri has a scheme");
    let host_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(host_end);
    let hosts = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let mut tail = tail.to_owned();
    if !tail.contains("authSource=") {
        if tail.contains('?') {
            tail.push_str("&authSource=admin");
        } else if tail.starts_with('/') {
            tail.push_str("?authSource=admin");
        } else {
            tail.push_str("/?authSource=admin");
        }
    }
    format!("{scheme}://{user}:{pass}@{hosts}{tail}")
}

/// Deterministic LCG so the seed is reproducible without a `rand` dependency.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const CATEGORIES: &[(&str, f64)] = &[
    ("books", 12.5),
    ("toys", 7.25),
    ("garden", 31.0),
    ("tools", 18.75),
    ("food", 3.4),
    ("music", 9.99),
];

async fn seed(db: &Database) -> Vec<ObjectId> {
    db.drop().await.unwrap();
    let mut rng = Lcg(42);
    let customers: Vec<Document> = (0..40)
        .map(|i| {
            doc! {
                "_id": ObjectId::new(),
                "name": format!("Customer {i}"),
                "email": format!("c{i}@example.com"),
                "region": if i % 3 == 0 { "US" } else { "EU" },
                "since": DateTime::from_millis(1_700_000_000_000 + i * 86_400_000),
            }
        })
        .collect();
    let ids: Vec<ObjectId> = customers
        .iter()
        .map(|c| c.get_object_id("_id").unwrap())
        .collect();
    db.collection::<Document>("customers")
        .insert_many(customers)
        .await
        .unwrap();

    let start = DateTime::parse_rfc3339_str("2026-05-01T00:00:00Z")
        .unwrap()
        .timestamp_millis();
    let statuses = ["paid", "shipped", "pending", "cancelled"];
    let orgs = ["EU-1", "EU-2", "US-1"];
    let orders: Vec<Document> = (0..300)
        .map(|i| {
            let mut d = doc! {
                "_id": ObjectId::new(),
                "status": statuses[rng.below(4) as usize],
                "salesOrg": orgs[rng.below(3) as usize],
                "customerId": ids[rng.below(ids.len() as u64) as usize],
                // May 1 + up to 210 days (through late November).
                "createdAt": DateTime::from_millis(start + rng.below(210) as i64 * 86_400_000 + rng.below(86_400_000) as i64),
            };
            if i % 20 != 0 {
                let lines: Vec<Bson> = (0..rng.below(4) + 1)
                    .map(|j| {
                        let (cat, price) = CATEGORIES[rng.below(CATEGORIES.len() as u64) as usize];
                        Bson::Document(doc! { "sku": format!("{}-{j}", &cat[..2].to_uppercase()), "category": cat, "qty": (rng.below(5) + 1) as i32, "unitPrice": price })
                    })
                    .collect();
                d.insert("lines", lines);
            }
            if i % 4 == 0 {
                d.insert("note", "gift wrap");
            }
            d
        })
        .collect();
    let coll: Collection<Document> = db.collection("orders");
    coll.insert_many(orders).await.unwrap();
    coll.create_index(
        caliban_connect::mongo::mongodb::IndexModel::builder()
            .keys(doc! { "createdAt": 1 })
            .build(),
    )
    .await
    .unwrap();
    ids
}

async fn create_ro_user(admin_client: &Client) {
    let admin = admin_client.database("admin");
    let _ = admin.run_command(doc! { "dropUser": RO_USER }).await;
    admin
        .run_command(
            doc! { "createUser": RO_USER, "pwd": RO_PASS, "roles": [{ "role": "read", "db": DB }] },
        )
        .await
        .expect("create read-only user");
}

fn metric_elements() -> Vec<Element> {
    let gross: Filter = serde_json::from_value(json!({ "attr": "Order.status", "op": "in", "value": { "type": "string_list", "v": ["paid", "shipped"] } })).unwrap();
    let el = |id: &str, def: MetricDef| Element {
        id: id.into(),
        name: id.into(),
        description: None,
        synonyms: vec![],
        status: Status::Approved,
        provenance: Provenance::Human,
        confidence: None,
        spec: ElementSpec::Metric(def),
    };
    vec![
        el(
            "metric.gross_revenue",
            MetricDef {
                grain: "OrderLine".into(),
                aggregation: Aggregation::Sum,
                expr: MetricExpr::Mul {
                    left: Box::new(MetricExpr::Attr {
                        id: "OrderLine.qty".into(),
                    }),
                    right: Box::new(MetricExpr::Attr {
                        id: "OrderLine.unit_price".into(),
                    }),
                },
                filters: vec![gross],
            },
        ),
        el(
            "metric.order_count",
            MetricDef {
                grain: "Order".into(),
                aggregation: Aggregation::Count,
                expr: MetricExpr::Rows,
                filters: vec![],
            },
        ),
    ]
}

fn reference_query() -> Query {
    serde_json::from_value(json!({
      "ir_version": "1",
      "ontology_version": "acme@42",
      "metrics":    [{ "id": "metric.gross_revenue" }],
      "dimensions": [{ "id": "OrderLine.category" }],
      "filters": [
        { "attr": "Customer.region",  "op": "eq", "value": { "type": "string", "v": "EU" } },
        { "attr": "Order.created_at", "op": "between", "half_open": true,
          "value": { "type": "timestamp_range", "v": ["2026-07-01T00:00:00Z", "2026-10-01T00:00:00Z"] } }
      ],
      "order_by": [{ "metric": "metric.gross_revenue", "dir": "desc" }],
      "limit": 5,
      "freshness": "PT15M"
    }))
    .unwrap()
}

fn eu_policy() -> Vec<Filter> {
    vec![serde_json::from_value(json!({ "attr": "Order.sales_org", "op": "in", "value": { "type": "string_list", "v": ["EU-1", "EU-2"] } })).unwrap()]
}

/// Numeric-tolerant row comparison (native sums are doubles; COUNT is int32 vs int64).
fn same_rows(a: &[J], b: &[J]) -> bool {
    fn eq(x: &J, y: &J) -> bool {
        match (x, y) {
            (J::Number(p), J::Number(q)) => {
                let (p, q) = (p.as_f64().unwrap(), q.as_f64().unwrap());
                (p - q).abs() <= 1e-9 * p.abs().max(q.abs()).max(1.0)
            }
            (J::Object(p), J::Object(q)) => {
                p.len() == q.len() && p.iter().all(|(k, v)| q.get(k).is_some_and(|w| eq(v, w)))
            }
            _ => x == y,
        }
    }
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| eq(x, y))
}

struct Lanes<'a> {
    model: &'a Model,
    conn: &'a MongoConnector,
    replica: &'a Replica,
}

impl Lanes<'_> {
    async fn native(&self, q: &Query, policy: &[Filter]) -> Vec<J> {
        let p = plan(self.model, q, policy).unwrap();
        let mq = mongo::lower(
            self.model,
            &p,
            &mongo::NativeOptions {
                max_time_ms: 15_000,
                audit_id: "it",
                read_tag: None,
            },
        )
        .unwrap();
        let r = self.conn.execute(&mq, 10_000).await.unwrap();
        assert!(!r.truncated);
        r.rows
    }

    async fn replica(&self, q: &Query, policy: &[Filter]) -> Vec<J> {
        let p = plan(self.model, q, policy).unwrap();
        let s = sql::lower(self.model, &p).unwrap();
        batches_to_json(
            &self
                .replica
                .query(&s)
                .await
                .unwrap_or_else(|e| panic!("{e}\n{s}")),
        )
        .unwrap()
    }

    async fn assert_same(&self, label: &str, q: &Query, policy: &[Filter]) -> Vec<J> {
        let n = self.native(q, policy).await;
        let r = self.replica(q, policy).await;
        assert!(
            same_rows(&n, &r),
            "{label}: lanes differ\nnative:  {n:?}\nreplica: {r:?}"
        );
        println!(
            "[{label}] native == replica ({} rows): {}",
            n.len(),
            serde_json::to_string(&n).unwrap()
        );
        n
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mongo_end_to_end() {
    let Ok(admin_uri) = std::env::var("CALIBAN_MONGO_TEST_URI") else {
        eprintln!(
            "skipping mongo_end_to_end: CALIBAN_MONGO_TEST_URI is not set (run scripts/mongo-it.sh)"
        );
        return;
    };
    let admin_client = Client::with_uri_str(&admin_uri)
        .await
        .expect("admin client");
    let admin_db = admin_client.database(DB);
    let customer_ids = seed(&admin_db).await;
    create_ro_user(&admin_client).await;

    // --- Read-only principal ---------------------------------------------------------------
    let ro_uri = with_credentials(&admin_uri, RO_USER, RO_PASS);
    let cfg = MongoConfig {
        datasource_id: Some("dw".into()),
        ..MongoConfig::new(ro_uri, DB)
    };
    let conn = MongoConnector::connect(cfg)
        .await
        .expect("connect read-only");
    let report = conn
        .verify_read_only()
        .await
        .expect("read-only user is accepted");
    println!(
        "privileges: users={:?} roles={:?} actions={:?} replica_set={}",
        report.users, report.roles, report.actions, report.replica_set
    );
    assert!(report.replica_set, "change streams need a replica set");
    assert!(conn.capabilities().change_feed);

    let admin_conn = MongoConnector::connect(MongoConfig::new(admin_uri.clone(), DB))
        .await
        .unwrap();
    match admin_conn.verify_read_only().await {
        Err(ConnectError::NotReadOnly(reason)) => println!(
            "admin refused as expected: {}",
            &reason[..reason.len().min(120)]
        ),
        other => panic!("admin user must be refused, got {other:?}"),
    }

    // --- (a) introspect + propose --------------------------------------------------------------
    let snapshot = conn.introspect().await.unwrap();
    let orders = snapshot.object("orders").unwrap();
    assert_eq!(orders.estimated_rows, Some(300));
    assert!(orders.sampled >= 290, "sampled {}", orders.sampled);
    assert!(orders.indexes.iter().any(|i| i.keys == ["createdAt"]));
    assert!(
        orders.discriminators.is_empty(),
        "no subtypes in orders: {:?}",
        orders.discriminators
    );
    let lines = orders.field("lines").unwrap();
    assert!(lines.is_array && lines.array.as_ref().unwrap().of_documents());
    assert!(
        (lines.presence - 0.95).abs() < 0.02,
        "lines presence {}",
        lines.presence
    );
    assert_eq!(
        orders.field("lines.qty").unwrap().dominant_type(),
        Some("int")
    );
    let r = snapshot
        .references
        .iter()
        .find(|r| {
            r.from_object == "orders" && r.from_path == "customerId" && r.to_object == "customers"
        })
        .expect("customerId reference discovered");
    assert!(
        r.overlap >= 0.99 && r.name_match && r.value_type == "objectId",
        "{r:?}"
    );
    println!(
        "reference: orders.customerId -> customers._id overlap {} ({}/{})",
        r.overlap, r.matched, r.probed
    );

    let proposed = bootstrap::propose(&snapshot);
    assert!(proposed.iter().all(|e| e.status == Status::Proposed));
    let find = |id: &str| {
        proposed.iter().find(|e| e.id == id).unwrap_or_else(|| {
            panic!(
                "missing {id}: {:?}",
                proposed.iter().map(|e| &e.id).collect::<Vec<_>>()
            )
        })
    };
    assert!(
        matches!(&find("Order").spec, ElementSpec::Entity(d) if matches!(&d.binding, EntityBinding::Root { collection, .. } if collection == "orders"))
    );
    assert!(
        matches!(&find("OrderLine").spec, ElementSpec::Entity(d) if matches!(&d.binding, EntityBinding::Embedded { parent, array_path, .. } if parent == "Order" && array_path == "lines"))
    );
    assert!(
        matches!(&find("Customer").spec, ElementSpec::Entity(d) if matches!(&d.binding, EntityBinding::Root { collection, .. } if collection == "customers"))
    );
    let rel = find("Order.customer_id->Customer");
    let ElementSpec::Relation(rd) = &rel.spec else {
        panic!()
    };
    assert!(!rd.verified && rd.foreign_indexed && rel.confidence.unwrap() >= 0.95);
    println!(
        "proposed {} elements: {:?}",
        proposed.len(),
        proposed.iter().map(|e| e.id.as_str()).collect::<Vec<_>>()
    );

    // Curation (simulated): approve everything, verify the reference, add the metrics.
    let mut elements: Vec<Element> = proposed
        .into_iter()
        .map(|mut e| {
            e.status = Status::Approved;
            if let ElementSpec::Relation(r) = &mut e.spec {
                r.verified = true;
            }
            e
        })
        .collect();
    elements.extend(metric_elements());
    let model = Model::from_ontology(&Ontology {
        tenant_id: "acme".into(),
        version: 42,
        elements,
    });
    // The bootstrap reproduces the hand-written fixture bindings of caliban-ontology.
    for (id, path, column) in [
        ("Order.status", "status", "status"),
        ("Order.created_at", "createdAt", "created_at"),
        ("Order.sales_org", "salesOrg", "sales_org"),
        ("OrderLine.category", "category", "category"),
        ("OrderLine.sku", "sku", "sku"),
        ("OrderLine.qty", "qty", "qty"),
        ("OrderLine.unit_price", "unitPrice", "unit_price"),
        ("Customer.region", "region", "region"),
    ] {
        let a = &model.attributes[id];
        assert_eq!((a.path.as_str(), a.column.as_str()), (path, column), "{id}");
    }

    // --- (b) native lane ----------------------------------------------------------------------
    let q = reference_query();
    let p = plan(&model, &q, &eu_policy()).unwrap();
    let mq = mongo::lower(
        &model,
        &p,
        &mongo::NativeOptions {
            max_time_ms: 15_000,
            audit_id: "it",
            read_tag: None,
        },
    )
    .unwrap();
    let gate = conn
        .explain_gate(&mq, &GatePolicy::default())
        .await
        .unwrap();
    println!(
        "explain: stages={:?} indexes={:?} lookups={:?} native_ok={}",
        gate.summary.plan_stages,
        gate.summary.index_names,
        gate.summary.lookup_strategies,
        gate.native_ok
    );
    assert!(gate.native_ok, "{gate:?}");
    assert!(
        gate.summary.index_names.iter().any(|i| i == "createdAt_1"),
        "createdAt range uses the index: {gate:?}"
    );

    // A child-element filter at order grain cannot use an index: COLLSCAN, rejected above 100 docs.
    let sku_q: Query = serde_json::from_value(json!({
      "ir_version": "1", "ontology_version": "acme@42",
      "metrics": [{ "id": "metric.order_count" }],
      "filters": [ { "attr": "OrderLine.category", "op": "eq", "value": { "type": "string", "v": "books" } },
                   { "attr": "OrderLine.qty", "op": "gte", "value": { "type": "number", "v": 3 } } ]
    }))
    .unwrap();
    let sku_plan = plan(&model, &sku_q, &[]).unwrap();
    let sku_mq = mongo::lower(
        &model,
        &sku_plan,
        &mongo::NativeOptions {
            max_time_ms: 15_000,
            audit_id: "it",
            read_tag: None,
        },
    )
    .unwrap();
    let strict = conn
        .explain_gate(
            &sku_mq,
            &GatePolicy {
                max_collscan_docs: 100,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(strict.summary.collscan && !strict.native_ok, "{strict:?}");
    println!("explain gate (strict): {:?}", strict.reasons);

    // Row cap.
    let capped = conn.execute(&mq, 2).await.unwrap();
    assert!(
        capped.truncated && capped.rows.len() == 2,
        "{capped:?} {}",
        serde_json::to_string(&mq.pipeline).unwrap()
    );

    // --- (c) replica snapshot -----------------------------------------------------------------
    let dir = tempfile::tempdir().unwrap();
    let replica = Replica::new(&model, Some("dw"), ReplicaConfig::new(dir.path())).unwrap();
    let stats = replica.snapshot(&conn).await.unwrap();
    println!("snapshot: {stats:?}");
    assert_eq!(stats.documents["orders"], 300);
    assert_eq!(stats.documents["customers"], 40);
    let w0 = replica.watermark();
    assert!(w0 > 0);

    // --- (d) shadow comparison ----------------------------------------------------------------
    let lanes = Lanes {
        model: &model,
        conn: &conn,
        replica: &replica,
    };
    let before = lanes
        .assert_same("gross_revenue by category (EU policy)", &q, &eu_policy())
        .await;
    assert!(!before.is_empty());
    lanes
        .assert_same("order_count with same-element child filter", &sku_q, &[])
        .await;
    let count_q: Query = serde_json::from_value(json!({
      "ir_version": "1", "ontology_version": "acme@42",
      "metrics": [{ "id": "metric.order_count" }],
      "dimensions": [{ "id": "Order.status" }],
      "filters": [ { "attr": "Customer.region", "op": "eq", "value": { "type": "string", "v": "EU" } } ],
      "order_by": [{ "dimension": "Order.status", "dir": "asc" }]
    }))
    .unwrap();
    lanes
        .assert_same("order_count by status (EU customers)", &count_q, &[])
        .await;

    // --- (e) change stream ----------------------------------------------------------------------
    let cdc = replica.start_cdc(&conn).await.unwrap();
    assert_eq!(replica.status(), ReplicaStatus::Live);
    let orders_coll: Collection<Document> = admin_db.collection("orders");
    let eu_customer = customer_ids[1]; // i % 3 != 0 → EU
    let new_id = ObjectId::new();
    orders_coll
        .insert_one(doc! {
            "_id": new_id, "status": "paid", "salesOrg": "EU-1", "customerId": eu_customer,
            "createdAt": DateTime::parse_rfc3339_str("2026-08-15T12:00:00Z").unwrap(),
            "lines": [ { "sku": "BO-9", "category": "books", "qty": 40, "unitPrice": 12.5 }, { "sku": "NE-1", "category": "newcat", "qty": 1, "unitPrice": 100000.0 } ],
        })
        .await
        .unwrap();
    // Update an existing contributing order: cancel it (drops out of gross revenue).
    let victim = orders_coll
        .find_one(doc! { "status": "paid", "salesOrg": "EU-2", "lines.0": { "$exists": true },
                         "createdAt": { "$gte": DateTime::parse_rfc3339_str("2026-07-01T00:00:00Z").unwrap(), "$lt": DateTime::parse_rfc3339_str("2026-10-01T00:00:00Z").unwrap() } })
        .await
        .unwrap();
    if let Some(v) = &victim {
        orders_coll
            .update_one(
                doc! { "_id": v.get_object_id("_id").unwrap() },
                doc! { "$set": { "status": "cancelled" } },
            )
            .await
            .unwrap();
    }
    // Rewrite the embedded array of the inserted order (parent update rewrites child rows).
    orders_coll
        .update_one(doc! { "_id": new_id }, doc! { "$push": { "lines": { "sku": "GA-2", "category": "garden", "qty": 2, "unitPrice": 31.0 } } })
        .await
        .unwrap();

    let after_native = lanes.native(&q, &eu_policy()).await;
    assert!(!same_rows(&before, &after_native), "the source changed");
    assert_eq!(after_native[0]["category"], "newcat");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let r = lanes.replica(&q, &eu_policy()).await;
        if same_rows(&after_native, &r) && replica.watermark() > w0 {
            println!(
                "replica caught up after inserts/updates: {}",
                serde_json::to_string(&r).unwrap()
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "replica did not converge: native {after_native:?} replica {r:?} status {:?}",
            replica.status()
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let w1 = replica.watermark();
    assert!(w1 > w0, "watermark advanced: {w0} -> {w1}");
    assert!(
        replica.events_applied() >= 2,
        "events applied: {}",
        replica.events_applied()
    );

    // Delete propagates too.
    orders_coll
        .delete_one(doc! { "_id": new_id })
        .await
        .unwrap();
    let after_delete = lanes.native(&q, &eu_policy()).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let r = lanes.replica(&q, &eu_policy()).await;
        if same_rows(&after_delete, &r) && replica.watermark() > w1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "delete did not propagate: native {after_delete:?} replica {r:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    lanes
        .assert_same("order_count by status after CDC", &count_q, &[])
        .await;
    let epoch = conn.epoch().await.unwrap();
    println!(
        "watermark {w0} -> {w1} -> {}; source epoch {epoch}; lag {}s",
        replica.watermark(),
        replica.lag_secs(epoch)
    );
    assert!(replica.lag_secs(epoch) <= 5);

    cdc.stop().await;
    let manifest: J =
        serde_json::from_slice(&std::fs::read(dir.path().join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["watermark"].as_u64(), Some(replica.watermark()));
    admin_db.drop().await.unwrap();
    // Close pools before the runtime goes away (avoids driver background-task noise at teardown).
    drop(replica);
    conn.client().clone().shutdown().await;
    admin_conn.client().clone().shutdown().await;
    admin_client.shutdown().await;
}
