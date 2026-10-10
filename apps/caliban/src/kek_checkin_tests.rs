//! KEK rotation in split mode, end to end: the signed snapshot names the KEKs that sealed its
//! secrets, the router reports the snapshot it serves on every poll (and exposes it on `/healthz`
//! and `/metrics`), and `GET /api/v1/keys/status` says when no router still needs the retired
//! KEK.

use crate::split::SnapshotSource;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use caliban_config::signing::{SnapshotSigner, SnapshotVerifier, generate_signing_key};
use caliban_config::{Config, ConfigHandle, Keyring, Snapshot};
use caliban_cp::ControlPlane;
use caliban_cp::store::Store;
use caliban_meter::RecentUsage;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "admin-secret";

async fn send(app: &axum::Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, String) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {ADMIN}"))
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn status(cp: &axum::Router) -> Value {
    let (s, body) = send(cp, "GET", "/api/v1/keys/status", None).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test]
async fn routers_report_the_kek_of_the_snapshot_they_serve() {
    let old = Keyring::new([1; 32], []);
    // Step 1 of the rotation: new current KEK, the old one kept as previous.
    let ring = Keyring::new([2; 32], [[1; 32]]);
    let (new_id, old_id) = (ring.current_id().to_owned(), old.current_id().to_owned());

    let cfg = Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
    let store = Store::new(cfg.clone(), ConfigHandle::new(Snapshot::new(cfg, "boot")), RecentUsage::default());
    // acme's data key was wrapped before the rotation.
    caliban_cp::keys::tenant_dek(&store, &old, "acme", "test").await.unwrap();
    let (seed, public) = generate_signing_key();
    let cp = Arc::new(
        ControlPlane::new(store, ADMIN.into(), "control-plane")
            .with_snapshots(Some(SnapshotSigner::from_b64(&seed).unwrap()), Some("router-secret".into()))
            .with_keyring(Some(Arc::new(Keyring::new([2; 32], [[1; 32]])))),
    );
    let cp_app = caliban_cp::app(Arc::clone(&cp), None);
    let byok =
        json!({"kind": "openai", "label": "acme-byok", "api_key": "sk-test-acme", "trust_tier": "t2_contracted"});
    let (s, body) = send(&cp_app, "POST", "/api/v1/tenants/acme/provider-keys", Some(byok)).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(axum::serve(listener, cp_app.clone()).into_future());

    let keyring_ids = ring.ids().into_iter().map(str::to_owned).collect();
    let verifier = SnapshotVerifier::from_b64_list(&public).unwrap();
    let mut source =
        SnapshotSource::new(&url, "router-secret".into(), verifier, None, "router-a".into(), keyring_ids).unwrap();
    let first = source.fetch().await.unwrap().expect("first snapshot");
    assert_eq!(first.kek_ids, std::slice::from_ref(&old_id), "the BYOK envelope is wrapped by the old KEK");
    let handle = ConfigHandle::new(Snapshot::new(first.config, first.version.clone()).with_kek_ids(first.kek_ids));
    let dp =
        caliban_gateway::app(Arc::new(caliban_gateway::Gateway::new(handle.clone(), Arc::new(RecentUsage::default()))));
    let (_, health) = send(&dp, "GET", "/healthz", None).await;
    let health: Value = serde_json::from_str(&health).unwrap();
    assert_eq!(health["snapshot"], json!({"version": first.version, "kek_ids": [old_id]}));
    let (s, metrics) = send(&dp, "GET", "/metrics", None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        metrics.contains(&format!("caliban_snapshot_info{{version=\"{}\",kek_ids=\"{old_id}\"}} 1", first.version))
    );

    // The next poll reports what the router serves.
    assert!(source.fetch().await.unwrap().is_none());
    let st = status(&cp_app).await;
    assert_eq!(st["routers"][0]["router_id"], "router-a");
    assert_eq!(st["routers"][0]["snapshot_kek_ids"], json!([old_id]));
    assert_eq!(st["routers"][0]["has_current_kek"], true);
    assert_eq!(st["routers_on_previous_keks"], json!(["router-a"]));
    assert_eq!(st["previous_keks_still_needed"], json!([old_id]));
    assert_eq!(st["rotation_complete"], false);

    // Step 2: `caliban keys rotate`. Stored data no longer needs the old KEK, but the router
    // still serves the old snapshot until it polls.
    cp.store.rekey(&ring, true, "cli").await.unwrap();
    let st = status(&cp_app).await;
    assert_eq!(st["previous_keks_still_needed"], json!([]));
    assert_eq!(
        (st["routers_on_previous_keks"].clone(), st["rotation_complete"].clone()),
        (json!(["router-a"]), json!(false))
    );

    // Step 3: the router polls the re-wrapped snapshot and checks in with it.
    let next = source.fetch().await.unwrap().expect("re-wrapped snapshot");
    assert_eq!(next.kek_ids, std::slice::from_ref(&new_id));
    handle.store(Snapshot::new(next.config, next.version).with_kek_ids(next.kek_ids));
    assert!(source.fetch().await.unwrap().is_none());
    let st = status(&cp_app).await;
    assert_eq!(st["routers"][0]["snapshot_kek_ids"], json!([new_id]));
    assert_eq!((st["routers_on_previous_keks"].clone(), st["rotation_complete"].clone()), (json!([]), json!(true)));
    let (_, health) = send(&dp, "GET", "/healthz", None).await;
    assert!(health.contains(&new_id), "{health}");

    // Only the router token may check in.
    let (s, _) = send(&cp_app, "GET", "/api/v1/snapshot", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    server.abort();
}
