//! End to end: a key revoked (or a tenant deleted) on the control plane is rejected by the data
//! plane, in both deployment shapes:
//! - standalone: the control plane and the gateway share one `ConfigHandle`, so the next request
//!   sees the new snapshot;
//! - split: the router's `SnapshotSource` fetches the signed snapshot over HTTP and swaps it in;
//!   the key is rejected from the next applied poll.

use crate::split::SnapshotSource;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use caliban_config::signing::{SnapshotSigner, SnapshotVerifier, generate_signing_key};
use caliban_config::{Config, ConfigHandle, Snapshot};
use caliban_cp::ControlPlane;
use caliban_cp::store::Store;
use caliban_meter::RecentUsage;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const ADMIN: &str = "admin-secret";

fn config() -> Config {
    Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap()
}

async fn send(app: &axum::Router, method: &str, uri: &str, bearer: &str, body: Option<Value>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Mints a key for a new tenant; returns `(key, key_id)`.
async fn mint(cp: &axum::Router, tenant: &str) -> (String, String) {
    let (s, _) = send(cp, "POST", "/api/v1/tenants", ADMIN, Some(json!({"name": tenant}))).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, k) =
        send(cp, "POST", &format!("/api/v1/tenants/{tenant}/api-keys"), ADMIN, Some(json!({"name": "e2e"}))).await;
    assert_eq!(s, StatusCode::CREATED);
    (k["key"].as_str().unwrap().to_owned(), k["id"].as_str().unwrap().to_owned())
}

fn gateway(handle: ConfigHandle) -> axum::Router {
    caliban_gateway::app(Arc::new(caliban_gateway::Gateway::new(handle, Arc::new(RecentUsage::default()))))
}

#[tokio::test]
async fn standalone_rejects_a_revoked_key_on_the_next_request() {
    let cfg = config();
    let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
    let store = Store::new(cfg, handle.clone(), RecentUsage::default());
    let cp = caliban_cp::app(Arc::new(ControlPlane::new(store, ADMIN.into(), "standalone")), None);
    let dp = gateway(handle);

    let (key, id) = mint(&cp, "globex").await;
    let (key2, _) = mint(&cp, "initech").await;
    assert_eq!(send(&dp, "GET", "/v1/models", &key, None).await.0, StatusCode::OK);
    assert_eq!(
        send(&cp, "DELETE", &format!("/api/v1/tenants/globex/api-keys/{id}"), ADMIN, None).await.0,
        StatusCode::NO_CONTENT
    );
    let (s, e) = send(&dp, "GET", "/v1/models", &key, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{e}");

    // Deleting a tenant revokes every key it had.
    assert_eq!(send(&dp, "GET", "/v1/models", &key2, None).await.0, StatusCode::OK);
    assert_eq!(send(&cp, "DELETE", "/api/v1/tenants/initech", ADMIN, None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(send(&dp, "GET", "/v1/models", &key2, None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn split_router_rejects_a_revoked_key_after_its_next_snapshot_poll() {
    // Control plane, served over real HTTP with snapshot signing on.
    let (seed, public) = generate_signing_key();
    let cfg = config();
    let cp_handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"));
    let store = Store::new(cfg, cp_handle, RecentUsage::default());
    let cp = Arc::new(
        ControlPlane::new(store, ADMIN.into(), "control-plane")
            .with_snapshots(Some(SnapshotSigner::from_b64(&seed).unwrap()), Some("router-secret".into())),
    );
    let cp_app = caliban_cp::app(cp, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(axum::serve(listener, cp_app.clone()).into_future());

    let (key, id) = mint(&cp_app, "globex").await;

    // Router: config only from verified snapshots (what `SnapshotSource::run` does on each poll).
    let mut source =
        SnapshotSource::new(&url, "router-secret".into(), SnapshotVerifier::from_b64_list(&public).unwrap(), None)
            .unwrap();
    let first = source.fetch().await.unwrap().expect("first snapshot");
    let router_handle = ConfigHandle::new(Snapshot::new(first.config, first.version));
    let dp = gateway(router_handle.clone());
    assert_eq!(send(&dp, "GET", "/v1/models", &key, None).await.0, StatusCode::OK);
    assert!(source.fetch().await.unwrap().is_none(), "unchanged → 304");

    assert_eq!(
        send(&cp_app, "DELETE", &format!("/api/v1/tenants/globex/api-keys/{id}"), ADMIN, None).await.0,
        StatusCode::NO_CONTENT
    );
    // Until the router polls, it still serves its last snapshot (fail-static by design).
    assert_eq!(send(&dp, "GET", "/v1/models", &key, None).await.0, StatusCode::OK);
    let next = source.fetch().await.unwrap().expect("a revoke publishes a new snapshot");
    router_handle.store(Snapshot::new(next.config, next.version));
    assert_eq!(send(&dp, "GET", "/v1/models", &key, None).await.0, StatusCode::UNAUTHORIZED);
    server.abort();
}
