//! Usage shipping in split mode, end to end over HTTP: routers (real gateways in front of a mock
//! model server) deliver their usage events to the control plane's ingest endpoint, and
//! `GET /api/v1/usage` totals include them, once each.
//!
//! The Postgres side of ingestion (dedupe by `request_id`, totals in SQL) is covered by the store
//! parity tests in `caliban-cp` (`store::tests::postgres_usage_*`).

use crate::split::HttpUsageTransport;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use caliban_bench::mock::{Mock, MockConfig};
use caliban_config::{Config, ConfigHandle, Snapshot};
use caliban_cp::ControlPlane;
use caliban_cp::store::Store;
use caliban_cp::store::usage::UsageTotals;
use caliban_meter::{RecentUsage, ShipOptions, ShipStats, Tee, UsageEvent, UsageShipper, UsageSink, UsageTransport};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tower::ServiceExt;

const ADMIN: &str = "admin-secret";
const ROUTER_TOKEN: &str = "router-secret";
const KEY: &str = "cal_ship_test_key_0000000000000000";

fn config(upstream: &str) -> Config {
    Config::from_toml_str(&format!(
        r#"
[routing]
auto_price_in_per_mtok = 3.0
auto_price_out_per_mtok = 12.0
auto_cache_hit_fraction = 0.2

[cache]
exact_enabled = true

[[models]]
id = "oa/m"
provider = "oa"
upstream_model = "mock-oa"
trust_tier = "t2_contracted"
price_in_per_mtok = 0.5
price_out_per_mtok = 1.5

[[tenants]]
id = "acme"
name = "Acme"
pii_mode = "off"
api_key_hashes = ["{hash}"]
  [[tenants.providers]]
  id = "oa"
  kind = "openai_compatible"
  base_url = "{upstream}"
  trust_tier = "t2_contracted"
  [[tenants.routes]]
  intent = "default"
  models = ["oa/m"]
"#,
        hash = caliban_types::hash_api_key(KEY),
    ))
    .unwrap()
}

/// The control plane (memory store seeded from `cfg`), served on `listener`.
fn control_plane(cfg: &Config, listener: tokio::net::TcpListener) -> (axum::Router, tokio::task::JoinHandle<()>) {
    let store = Store::new(cfg.clone(), ConfigHandle::new(Snapshot::new(cfg.clone(), "boot")), RecentUsage::default());
    let cp = Arc::new(
        ControlPlane::new(store, ADMIN.into(), "control-plane").with_snapshots(None, Some(ROUTER_TOKEN.into())),
    );
    let app = caliban_cp::app(cp, None);
    let serve = axum::serve(listener, app.clone());
    (app, tokio::spawn(async move { serve.await.unwrap() }))
}

fn options(spool_dir: Option<PathBuf>) -> ShipOptions {
    ShipOptions {
        batch_max: 2,
        interval: Duration::from_millis(20),
        spool_dir,
        retry_min: Duration::from_millis(20),
        retry_max: Duration::from_millis(50),
        ..ShipOptions::default()
    }
}

struct Router {
    app: axum::Router,
    ring: RecentUsage,
    shipper: Arc<UsageShipper>,
}

/// A router: a gateway on `cfg` whose usage goes to its ring and to the control plane at `cp`.
fn router(cfg: &Config, cp: &str, id: &str, spool_dir: Option<PathBuf>) -> Router {
    let transport = Arc::new(HttpUsageTransport::new(cp, ROUTER_TOKEN.into(), id.into()).unwrap());
    let shipper = Arc::new(UsageShipper::start(transport, options(spool_dir)).unwrap());
    let ring = RecentUsage::default();
    let sink: Arc<dyn UsageSink> =
        Arc::new(Tee(vec![Arc::new(ring.clone()), Arc::clone(&shipper) as Arc<dyn UsageSink>]));
    let gw = caliban_gateway::Gateway::new(ConfigHandle::new(Snapshot::new(cfg.clone(), "cp-1")), sink);
    Router { app: caliban_gateway::app(Arc::new(gw)), ring, shipper }
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

/// One chat request through a router; `caliban/auto` unless `model` is given.
async fn chat(r: &Router, prompt: &str, model: &str) {
    let body =
        json!({"model": model, "temperature": 0, "max_tokens": 16, "messages": [{"role": "user", "content": prompt}]});
    let (s, b) = send(&r.app, "POST", "/v1/chat/completions", KEY, Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{b}");
}

async fn totals(cp: &axum::Router) -> Value {
    let (s, u) = send(cp, "GET", "/api/v1/usage?tenant_id=acme&limit=1000", ADMIN, None).await;
    assert_eq!(s, StatusCode::OK, "{u}");
    u
}

async fn until(what: &str, mut f: impl AsyncFnMut() -> bool) {
    for _ in 0..400 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn close(t: &Value, k: &str, want: f64) {
    let got = t[k].as_f64().unwrap();
    assert!((got - want).abs() < 1e-12, "{k}: {got} vs {want}");
}

#[tokio::test]
async fn events_from_two_routers_land_in_the_control_plane_totals_once() {
    let mock = Mock::start("127.0.0.1:0", MockConfig::default()).await.unwrap();
    let cfg = config(&mock.base_url());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (cp, server) = control_plane(&cfg, listener);

    let (a, b) = (router(&cfg, &url, "router-a", None), router(&cfg, &url, "router-b", None));
    // Router A: a caliban/auto miss, then the same request again (an exact-cache hit, billed at
    // the cache-hit fraction). Router B: another auto miss and a pinned model.
    chat(&a, "Summarize the quarterly report in one line.", "caliban/auto").await;
    chat(&a, "Summarize the quarterly report in one line.", "caliban/auto").await;
    chat(&b, "Write a haiku about the sea.", "caliban/auto").await;
    chat(&b, "Write a haiku about the sea.", "oa/m").await;
    a.shipper.shutdown(Duration::from_secs(2)).await;
    b.shipper.shutdown(Duration::from_secs(2)).await;

    // The control plane's totals are exactly the routers' own events, billed as the routers
    // billed them (the same pipeline code as standalone).
    let mut local: Vec<UsageEvent> = a.ring.snapshot(None, 100);
    local.extend(b.ring.snapshot(None, 100));
    assert_eq!(local.len(), 4);
    let want = serde_json::to_value(UsageTotals::from_events(&local)).unwrap();
    let u = totals(&cp).await;
    let t = &u["totals"];
    assert_eq!(
        (t["requests"].as_u64(), t["auto_requests"].as_u64(), t["auto_cache_hits"].as_u64()),
        (Some(4), Some(3), Some(1))
    );
    for k in [
        "flat_price_usd",
        "billed_usd",
        "saved_usd",
        "auto_saved_usd",
        "routed_model_cost_usd",
        "margin_usd",
        "cost_usd",
    ] {
        close(t, k, want[k].as_f64().unwrap());
    }
    let hit = local.iter().find(|e| e.cache == caliban_types::CacheStatus::Hit).unwrap();
    let (flat, billed) = (hit.flat_price_usd.unwrap(), hit.billed_usd.unwrap());
    assert!(flat > 0.0 && (billed - flat * 0.2).abs() < 1e-12, "hit billed at 20%: {billed} of {flat}");
    let mut ids: Vec<String> =
        u["events"].as_array().unwrap().iter().map(|e| e["request_id"].as_str().unwrap().to_owned()).collect();
    let mut want_ids: Vec<String> = local.iter().map(|e| e.request_id.clone()).collect();
    ids.sort();
    want_ids.sort();
    assert_eq!(ids, want_ids);

    // A batch sent again (lost acknowledgement, router restart) is not counted twice.
    let transport = HttpUsageTransport::new(&url, ROUTER_TOKEN.into(), "router-a".into()).unwrap();
    let again = transport.send(&local).await.unwrap();
    assert_eq!((again.accepted, again.duplicates), (0, 4));
    assert_eq!(totals(&cp).await["totals"], *t);

    // Only the router token may deliver.
    let bad = HttpUsageTransport::new(&url, "wrong".into(), "router-x".into()).unwrap();
    assert!(bad.send(&local).await.is_err());
    server.abort();
}

#[tokio::test]
async fn an_unreachable_control_plane_loses_nothing_across_a_router_restart() {
    let mock = Mock::start("127.0.0.1:0", MockConfig::default()).await.unwrap();
    let cfg = config(&mock.base_url());
    // A port with nothing listening yet: the control plane is down.
    let addr = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    let url = format!("http://{addr}");
    let spool = std::env::temp_dir().join(format!("caliban-ship-it-{}-{}", std::process::id(), rand::random::<u64>()));

    // The router keeps serving (fail-static); its events wait in the spool.
    let r1 = router(&cfg, &url, "router-a", Some(spool.clone()));
    for i in 0..5 {
        chat(&r1, &format!("Question number {i} while the control plane is down"), "caliban/auto").await;
    }
    r1.shipper.flush().await;
    assert_eq!(r1.shipper.stats().backlog.load(Ordering::Relaxed), 5);
    let (_, health) = send(&r1.app, "GET", "/healthz", KEY, None).await;
    assert_eq!(health["usage_shipping"]["backlog"], 5, "{health}");
    assert!(health["usage_shipping"]["last_error"].is_string());
    // Restarted while the control plane is still down.
    r1.shipper.shutdown(Duration::from_millis(200)).await;
    let r2 = router(&cfg, &url, "router-a", Some(spool.clone()));
    assert_eq!(r2.shipper.stats().backlog.load(Ordering::Relaxed), 5, "the backlog survived the restart");
    for i in 5..8 {
        chat(&r2, &format!("Question number {i} while the control plane is down"), "caliban/auto").await;
    }

    // The control plane comes back: the whole backlog arrives, once.
    let (cp, server) = control_plane(&cfg, tokio::net::TcpListener::bind(addr).await.unwrap());
    until("the backlog to arrive", async || totals(&cp).await["totals"]["requests"] == 8).await;
    until("an empty backlog", async || r2.shipper.stats().backlog.load(Ordering::Relaxed) == 0).await;
    // The control plane stores a batch before its acknowledgement reaches the router, so wait
    // for the router's count too.
    let s: &ShipStats = r2.shipper.stats();
    until("every event acknowledged", async || s.delivered.load(Ordering::Relaxed) == 8).await;
    assert_eq!((s.duplicates.load(Ordering::Relaxed), s.dropped.load(Ordering::Relaxed)), (0, 0));
    assert_eq!(std::fs::read_dir(&spool).unwrap().count(), 0, "delivered segments are deleted");
    let mut events: Vec<UsageEvent> = r1.ring.snapshot(None, 100);
    events.extend(r2.ring.snapshot(None, 100));
    let want = serde_json::to_value(UsageTotals::from_events(&events)).unwrap();
    let t = totals(&cp).await["totals"].clone();
    close(&t, "billed_usd", want["billed_usd"].as_f64().unwrap());
    r2.shipper.shutdown(Duration::from_millis(200)).await;
    server.abort();
    let _ = std::fs::remove_dir_all(spool);
}
