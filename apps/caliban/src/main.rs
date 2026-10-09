//! `caliban` — one binary for every deployment shape (SaaS, VPC, air-gapped).

#[cfg(test)]
mod purge_tests;
#[cfg(test)]
mod revocation_tests;
mod split;

use anyhow::{Context, Result};
use base64::Engine;
use caliban_config::signing::{SnapshotSigner, SnapshotVerifier, generate_signing_key};
use caliban_config::{Config, ConfigHandle, Snapshot};
use caliban_meter::{FsyncPolicy, JsonlSink, RecentUsage, Tee, UsageSink, WalOptions};
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "caliban", version, about = "Caliban AI gateway")]
struct Cli {
    /// Path to the TOML config.
    #[arg(long, env = "CALIBAN_CONFIG", default_value = "/etc/caliban/caliban.toml", global = true)]
    config: String,
    /// Append usage events to this JSONL file (write-ahead log for billing).
    #[arg(long, env = "CALIBAN_USAGE_WAL", global = true)]
    usage_wal: Option<String>,
    /// When the usage WAL calls fdatasync: `off` (default; the OS writes back, graceful shutdown
    /// syncs) or `batch` (after every written batch).
    #[arg(long, env = "CALIBAN_USAGE_WAL_FSYNC", default_value = "off", global = true)]
    usage_wal_fsync: FsyncPolicy,
    /// Usage events the WAL queue holds before requests wait (up to 20 ms) or the event is dropped
    /// and counted in /healthz.
    #[arg(long, env = "CALIBAN_USAGE_WAL_QUEUE", default_value_t = 16_384, global = true)]
    usage_wal_queue: usize,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Data plane only (OpenAI-compatible API). Config from the file, or, with
    /// `--control-plane-url`, from signed control-plane snapshots (split mode).
    Router(RouterArgs),
    /// Control plane only (admin API + web console).
    ControlPlane,
    /// Data plane + control plane in one process (on-prem default).
    Standalone,
    /// Validate the config file and exit.
    CheckConfig,
    /// Generate a tenant API key and print it with its hash (put the hash in the config).
    Keygen,
    /// Generate a base64 32-byte key-encryption key for CALIBAN_KEK.
    GenKek,
    /// Generate an Ed25519 snapshot signing key (control plane) and its public key (routers).
    GenSigningKey,
    /// Probe a local health endpoint and exit 0/1 (for container healthchecks; the image has no shell).
    Healthcheck {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
        #[arg(long, default_value = "/healthz")]
        path: String,
    },
}

#[derive(clap::Args)]
struct RouterArgs {
    /// Control-plane base URL, e.g. http://cp:8081. Requires CALIBAN_ROUTER_TOKEN and
    /// CALIBAN_SNAPSHOT_PUBLIC_KEY; the config file is not read.
    #[arg(long, env = "CALIBAN_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,
    /// Seconds between snapshot polls (with ±20% jitter).
    #[arg(long, env = "CALIBAN_SNAPSHOT_POLL_SECS", default_value_t = 10)]
    poll_interval_secs: u64,
    /// Listen address in split mode.
    #[arg(long, env = "CALIBAN_ROUTER_ADDR", default_value = "0.0.0.0:8080")]
    listen: String,
    /// Persist the last good signed snapshot here, so the router can restart while the control
    /// plane is down.
    #[arg(long, env = "CALIBAN_SNAPSHOT_CACHE")]
    snapshot_cache: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs (CALIBAN_LOG) + OTLP traces only when OTEL_EXPORTER_OTLP_ENDPOINT is set. Keep the
    // guard alive until exit so buffered spans are flushed.
    let _telemetry = caliban_gateway::telemetry::init();
    let cli = Cli::parse();

    match &cli.cmd {
        Cmd::Healthcheck { addr, path } => {
            let ok = healthcheck(addr, path).await;
            std::process::exit(i32::from(!ok));
        }
        Cmd::Keygen => {
            let key = caliban_cp::generate_api_key();
            println!("key:  {key}\nhash: {}", caliban_types::hash_api_key(&key));
            return Ok(());
        }
        Cmd::GenKek => {
            let mut k = [0u8; 32];
            rand::rng().fill_bytes(&mut k);
            println!("{}", base64::engine::general_purpose::STANDARD.encode(k));
            return Ok(());
        }
        Cmd::GenSigningKey => {
            let (seed, public) = generate_signing_key();
            println!("CALIBAN_SNAPSHOT_SIGNING_KEY={seed}   # control plane only; keep secret");
            println!("CALIBAN_SNAPSHOT_PUBLIC_KEY={public}   # routers");
            return Ok(());
        }
        _ => {}
    }

    // The usage WAL: written by a background task, flushed on graceful shutdown.
    let wal: Option<Arc<JsonlSink>> = cli.usage_wal.as_ref().map(|path| {
        let opts = WalOptions { queue: cli.usage_wal_queue.max(1), fsync: cli.usage_wal_fsync, ..WalOptions::default() };
        tracing::info!(path = %path, fsync = opts.fsync.as_str(), queue = opts.queue, "usage WAL enabled");
        Arc::new(JsonlSink::with_options(path, opts))
    });
    let usage_sinks = |recent: &RecentUsage| -> Arc<dyn UsageSink> {
        let mut sinks: Vec<Arc<dyn UsageSink>> = vec![Arc::new(recent.clone())];
        if let Some(w) = &wal {
            sinks.push(Arc::clone(w) as Arc<dyn UsageSink>);
        }
        Arc::new(Tee(sinks))
    };

    // Split mode: the router's config comes only from signed control-plane snapshots.
    if let Cmd::Router(RouterArgs { control_plane_url: Some(url), poll_interval_secs, listen, snapshot_cache }) = &cli.cmd {
        let token = std::env::var("CALIBAN_ROUTER_TOKEN").context("CALIBAN_ROUTER_TOKEN is required with --control-plane-url")?;
        let keys = std::env::var("CALIBAN_SNAPSHOT_PUBLIC_KEY").context("CALIBAN_SNAPSHOT_PUBLIC_KEY is required with --control-plane-url")?;
        let verifier = SnapshotVerifier::from_b64_list(&keys).context("CALIBAN_SNAPSHOT_PUBLIC_KEY")?;
        let every = Duration::from_secs((*poll_interval_secs).max(1));
        let mut source = split::SnapshotSource::new(url, token, verifier, snapshot_cache.clone())?;
        tracing::info!(control_plane = %url, poll_secs = every.as_secs(), cache = ?snapshot_cache, "router in split mode");
        let first = source.initial(every).await;
        tracing::info!(version = %first.version, tenants = first.config.tenants.len(), "serving config snapshot");
        let handle = ConfigHandle::new(Snapshot::new(first.config, first.version));
        tokio::spawn(source.run(handle.clone(), every));
        let gw = Arc::new(new_gateway(handle, usage_sinks(&RecentUsage::default()))?);
        spawn_router_warmup(&gw);
        gw.spawn_tenant_purge(PURGE_EVERY);
        let res = serve("router", listen.clone(), caliban_gateway::app(gw)).await;
        flush_wal(wal.as_deref()).await;
        return res;
    }

    let cfg = Config::from_file(&cli.config).with_context(|| format!("loading {}", cli.config))?;
    if matches!(cli.cmd, Cmd::CheckConfig) {
        println!("config OK: {} models, {} tenants", cfg.models.len(), cfg.tenants.len());
        return Ok(());
    }
    let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "file-0"));
    let recent = RecentUsage::default();
    let usage = usage_sinks(&recent);

    let gw = Arc::new(new_gateway(handle.clone(), Arc::clone(&usage))?);
    spawn_router_warmup(&gw);
    let purge_gw = Arc::clone(&gw);
    let router_addr = cfg.server.router_addr.clone();
    let router_task = move || serve("router", router_addr.clone(), caliban_gateway::app(Arc::clone(&gw)));

    let res = match cli.cmd {
        Cmd::Router(_) => {
            purge_gw.spawn_tenant_purge(PURGE_EVERY);
            router_task().await
        }
        Cmd::ControlPlane => {
            let cp = control_plane(&cfg, &handle, &recent, "control-plane").await?;
            cp.await
        }
        Cmd::Standalone => {
            // The control plane publishes the store's state (Postgres wins over the file) into
            // `handle` before the data plane starts serving. Tenant purges start from that state.
            let cp = control_plane(&cfg, &handle, &recent, "standalone").await?;
            purge_gw.spawn_tenant_purge(PURGE_EVERY);
            tokio::try_join!(router_task(), cp).map(|_| ())
        }
        Cmd::CheckConfig | Cmd::Keygen | Cmd::GenKek | Cmd::GenSigningKey | Cmd::Healthcheck { .. } => unreachable!(),
    };
    flush_wal(wal.as_deref()).await;
    res
}

/// Graceful shutdown of the usage WAL: everything recorded so far is written and synced, and
/// streams that finish shortly after the server stopped accepting are still recorded.
async fn flush_wal(wal: Option<&JsonlSink>) {
    if let Some(w) = wal {
        w.shutdown(Duration::from_secs(2)).await;
    }
}

/// Builds the control plane (store, snapshot signing) and returns its server future.
async fn control_plane(
    cfg: &Config,
    handle: &ConfigHandle,
    recent: &RecentUsage,
    mode: &'static str,
) -> Result<impl std::future::Future<Output = Result<()>>> {
    let admin_token = match &cfg.security.admin_token {
        Some(r) => r.resolve().context("resolving admin token")?.expose().to_owned(),
        None => std::env::var("CALIBAN_ADMIN_TOKEN").context("CALIBAN_ADMIN_TOKEN is required for the control plane")?,
    };
    let store = match std::env::var("CALIBAN_DATABASE_URL").ok().filter(|u| !u.trim().is_empty()) {
        Some(url) => {
            let s = caliban_cp::store::Store::postgres(&url, cfg.clone(), handle.clone(), recent.clone())
                .await
                .context("opening the Postgres control-plane store (CALIBAN_DATABASE_URL)")?;
            tracing::info!(version = %handle.load().version, "control-plane store: postgres (source of truth; config file seeds an empty database only)");
            s
        }
        None => {
            tracing::warn!("control-plane store: in-memory (seeded from the config file; changes are lost on restart; set CALIBAN_DATABASE_URL to persist)");
            caliban_cp::store::Store::new(cfg.clone(), handle.clone(), recent.clone())
        }
    };
    let postgres = store.backend_name() == "postgres";
    let signer = SnapshotSigner::from_env().context("CALIBAN_SNAPSHOT_SIGNING_KEY")?;
    let router_token = std::env::var("CALIBAN_ROUTER_TOKEN").ok().filter(|t| !t.is_empty());
    match (&signer, &router_token) {
        (Some(s), Some(_)) => tracing::info!(key_id = s.key_id(), "split mode: serving signed snapshots at /api/v1/snapshot"),
        (None, None) => {}
        _ => tracing::warn!("split mode needs both CALIBAN_SNAPSHOT_SIGNING_KEY and CALIBAN_ROUTER_TOKEN; /api/v1/snapshot is disabled"),
    }
    let cp = Arc::new(caliban_cp::ControlPlane::new(store, admin_token, mode).with_snapshots(signer, router_token));
    if postgres {
        // Picks up writes made through other control-plane replicas.
        caliban_cp::spawn_refresh(Arc::clone(&cp), Duration::from_secs(5));
    }
    let web_dir = std::env::var("CALIBAN_WEB_DIR").ok().or_else(|| cfg.server.web_dir.clone());
    let web_dir = web_dir.filter(|d| std::path::Path::new(d).join("index.html").exists());
    if web_dir.is_none() {
        tracing::warn!("web console not found (set CALIBAN_WEB_DIR); serving API only");
    }
    Ok(serve("control-plane", cfg.server.control_plane_addr.clone(), caliban_cp::app(cp, web_dir.as_deref())))
}

/// Minimal HTTP/1.1 GET; true on a 2xx status line within 3 seconds.
async fn healthcheck(addr: &str, path: &str) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let probe = async {
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf).await.ok()?;
        let line = String::from_utf8_lossy(&buf[..n]).to_string();
        Some(line.starts_with("HTTP/1.1 2"))
    };
    matches!(tokio::time::timeout(std::time::Duration::from_secs(3), probe).await, Ok(Some(true)))
}

/// How often a data plane checks its snapshot for deleted tenants whose semantic-cache entries
/// must be purged (see `caliban_gateway::purge`).
const PURGE_EVERY: Duration = caliban_gateway::purge::PURGE_EVERY;

/// Builds the `caliban/auto` routing assets (exemplar embeddings, kNN calibration, router profile)
/// in the background; until they are ready, `caliban/auto` routes by the keyword rules.
fn spawn_router_warmup(gw: &Arc<caliban_gateway::Gateway>) {
    let gw = Arc::clone(gw);
    tokio::spawn(async move { gw.warm_router().await });
}

/// Builds the data plane. With `CALIBAN_PII_NER_DIR` set, the L1 NER detector is loaded (and its
/// artifact hashes verified); a failure refuses to start rather than silently running without it.
/// The quota store follows `[limits] store` (`valkey` needs `CALIBAN_VALKEY_URL`).
fn new_gateway(handle: ConfigHandle, usage: Arc<dyn UsageSink>) -> Result<caliban_gateway::Gateway> {
    let quota = caliban_gateway::quota_store(&handle.load().config.limits).map_err(anyhow::Error::msg)?;
    let mut gw = caliban_gateway::Gateway::new(handle, usage).with_quota(quota);
    if let Some(dir) = std::env::var("CALIBAN_PII_NER_DIR").ok().filter(|d| !d.trim().is_empty()) {
        gw.pii = load_ner(&dir)?;
    }
    Ok(gw)
}

#[cfg(feature = "ner")]
fn load_ner(dir: &str) -> Result<caliban_pii::PiiEngine> {
    let mut opts = caliban_pii::ner::NerOptions::default();
    if let Some(n) = std::env::var("CALIBAN_PII_NER_SESSIONS").ok().and_then(|v| v.parse().ok()) {
        opts.sessions = n;
    }
    let started = std::time::Instant::now();
    let ner = caliban_pii::ner::NerDetector::load(std::path::Path::new(dir), opts)
        .with_context(|| format!("loading PII NER model from {dir}"))?;
    tracing::info!(dir, ms = started.elapsed().as_millis() as u64, "PII NER model loaded (L1)");
    Ok(caliban_pii::PiiEngine::default().with_detector(ner))
}

#[cfg(not(feature = "ner"))]
fn load_ner(_dir: &str) -> Result<caliban_pii::PiiEngine> {
    anyhow::bail!("CALIBAN_PII_NER_DIR is set but this binary was built without the `ner` feature (cargo build -p caliban --features ner)")
}

async fn serve(name: &'static str, addr: String, app: axum::Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&addr).await.with_context(|| format!("{name}: binding {addr}"))?;
    tracing::info!(%addr, "{name} listening");
    axum::serve(listener, app).with_graceful_shutdown(shutdown()).await.with_context(|| format!("{name} server"))
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
    tracing::info!("shutting down");
}
