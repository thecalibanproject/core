//! End to end: deleting a tenant on the control plane purges its T2 semantic-cache entries, in
//! both deployment shapes (in-memory vector store):
//! - standalone: the control plane publishes the post-delete snapshot into the shared
//!   `ConfigHandle`, and the gateway's `TenantPurger` sees the tenant disappear;
//! - split: the router swaps in the next signed snapshot (as `SnapshotSource::run` does), and its
//!   own purger does the same, against its own store.

use crate::split::SnapshotSource;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use caliban_cache::semantic::{KeyParts, MemoryStore, NewEntry, ResponseShape, SemanticKey, ThresholdPolicy};
use caliban_config::signing::{SnapshotSigner, SnapshotVerifier, generate_signing_key};
use caliban_config::{Config, ConfigHandle, Snapshot};
use caliban_cp::ControlPlane;
use caliban_cp::store::Store;
use caliban_gateway::Gateway;
use caliban_gateway::purge::TenantPurger;
use caliban_meter::RecentUsage;
use caliban_types::{PiiMode, TenantId};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "admin-secret";
const P: ThresholdPolicy =
    ThresholdPolicy { threshold: 0.95, min_threshold: 0.90, grey_band: 0.03, max_error_rate: 0.02, verify_rate: 0.0 };

fn config() -> Config {
    Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap()
}

async fn send(app: &axum::Router, method: &str, uri: &str, body: Option<Value>) -> StatusCode {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {ADMIN}"))
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

async fn create_tenant(cp: &axum::Router, name: &str) {
    assert_eq!(send(cp, "POST", "/api/v1/tenants", Some(json!({"name": name}))).await, StatusCode::CREATED);
}

fn gateway(handle: ConfigHandle, store: Arc<MemoryStore>) -> Arc<Gateway> {
    Arc::new(Gateway::new(handle, Arc::new(RecentUsage::default())).with_semantic_store(store))
}

/// One entry per tenant under two embedding models (as after an `embedding_model` change).
async fn seed(gw: &Gateway, tenants: &[&str]) {
    let cache = gw.semantic.as_ref().unwrap();
    for t in tenants {
        let tenant: TenantId = (*t).into();
        let key = SemanticKey::new(&KeyParts {
            tenant: &tenant,
            model: "ext/mock",
            shape: ResponseShape::Openai,
            context_hash: blake3::hash(b"ctx"),
            prompt: "what is our refund policy?",
            surrogates: &[],
            pii_mode: PiiMode::Reversible,
            embed_prefix: "",
        });
        for (model, v) in [("emb", vec![0.6f32, 0.8]), ("emb-old", vec![1.0, 0.0, 0.0])] {
            let e = NewEntry {
                model: "ext/mock".into(),
                response: "{}".into(),
                prompt_tokens: 3,
                completion_tokens: 4,
                ttl_secs: 3600,
            };
            cache.insert(&key, model, &v, e, &P, chrono::Utc::now().timestamp()).await.unwrap();
        }
    }
}

fn tenants_in(store: &MemoryStore) -> BTreeSet<String> {
    store.entries().into_iter().map(|(_, _, p)| p.tenant_id).collect()
}

#[tokio::test]
async fn standalone_tenant_delete_purges_its_semantic_entries() {
    let cfg = config();
    let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
    let store = Store::new(cfg, handle.clone(), RecentUsage::default());
    let cp = caliban_cp::app(Arc::new(ControlPlane::new(store, ADMIN.into(), "standalone")), None);
    create_tenant(&cp, "globex").await;
    create_tenant(&cp, "initech").await;

    let vectors = Arc::new(MemoryStore::default());
    let gw = gateway(handle, Arc::clone(&vectors));
    let mut purger = TenantPurger::new(Arc::clone(&gw));
    seed(&gw, &["globex", "initech"]).await;
    assert!(purger.tick().await.is_empty(), "nothing deleted yet");
    assert_eq!(vectors.len(), 4);

    assert_eq!(send(&cp, "DELETE", "/api/v1/tenants/globex", None).await, StatusCode::NO_CONTENT);
    assert_eq!(purger.tick().await, vec![TenantId::from("globex")]);
    assert_eq!(
        tenants_in(&vectors),
        BTreeSet::from(["initech".to_owned()]),
        "both of globex's collections purged, initech kept"
    );
    assert_eq!(vectors.len(), 2);
    assert!(purger.tick().await.is_empty() && purger.pending().is_empty(), "purged once");
}

#[tokio::test]
async fn split_router_purges_after_the_snapshot_that_drops_the_tenant() {
    let (seed_key, public) = generate_signing_key();
    let cfg = config();
    let cp_handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
    let store = Store::new(cfg, cp_handle, RecentUsage::default());
    let cp = Arc::new(
        ControlPlane::new(store, ADMIN.into(), "control-plane")
            .with_snapshots(Some(SnapshotSigner::from_b64(&seed_key).unwrap()), Some("router-secret".into())),
    );
    let cp_app = caliban_cp::app(cp, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(axum::serve(listener, cp_app.clone()).into_future());
    create_tenant(&cp_app, "globex").await;
    create_tenant(&cp_app, "initech").await;

    // The control plane holds no semantic cache; the router does (its own in-memory store).
    let mut source = SnapshotSource::new(
        &url,
        "router-secret".into(),
        SnapshotVerifier::from_b64_list(&public).unwrap(),
        None,
        "router-a".into(),
        vec![],
    )
    .unwrap();
    let first = source.fetch().await.unwrap().expect("first snapshot");
    let router_handle = ConfigHandle::new(Snapshot::new(first.config, first.version));
    let vectors = Arc::new(MemoryStore::default());
    let gw = gateway(router_handle.clone(), Arc::clone(&vectors));
    let mut purger = TenantPurger::new(Arc::clone(&gw));
    seed(&gw, &["globex", "initech"]).await;

    assert_eq!(send(&cp_app, "DELETE", "/api/v1/tenants/globex", None).await, StatusCode::NO_CONTENT);
    // Until the router polls, nothing changes on the data plane.
    assert!(purger.tick().await.is_empty());
    assert_eq!(vectors.len(), 4);
    let next = source.fetch().await.unwrap().expect("a delete publishes a new snapshot");
    router_handle.store(Snapshot::new(next.config, next.version));
    assert_eq!(purger.tick().await, vec![TenantId::from("globex")]);
    assert_eq!(tenants_in(&vectors), BTreeSet::from(["initech".to_owned()]));
    server.abort();
}
