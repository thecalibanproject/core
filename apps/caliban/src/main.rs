//! `caliban` — one binary for every deployment shape (SaaS, VPC, air-gapped).

#[cfg(test)]
mod kek_checkin_tests;
#[cfg(test)]
mod purge_tests;
#[cfg(test)]
mod revocation_tests;
#[cfg(test)]
mod ship_tests;
mod split;

use anyhow::{Context, Result};
use base64::Engine;
use caliban_config::signing::{SnapshotSigner, SnapshotVerifier, generate_signing_key};
use caliban_config::{Config, ConfigHandle, Keyring, Snapshot};
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
    #[command(flatten)]
    ship: ShipArgs,
    #[command(subcommand)]
    cmd: Cmd,
}

/// Usage shipping: split-mode routers deliver their usage events to the control plane (and a
/// standalone process with a Postgres store to its own store), at least once, deduplicated there.
#[derive(clap::Args)]
struct ShipArgs {
    /// Ship usage events to the control plane (split mode; standalone with Postgres). `false`
    /// keeps them on the router only (WAL and ring), as before.
    #[arg(long, env = "CALIBAN_USAGE_SHIP", default_value_t = true, action = clap::ArgAction::Set, global = true)]
    usage_ship: bool,
    /// Events per delivery at most (1 to 5000).
    #[arg(long, env = "CALIBAN_USAGE_SHIP_BATCH", default_value_t = 500, global = true)]
    usage_ship_batch: usize,
    /// How long an event waits for its batch to fill before it is sent anyway.
    #[arg(long, env = "CALIBAN_USAGE_SHIP_INTERVAL_MS", default_value_t = 1000, global = true)]
    usage_ship_interval_ms: u64,
    /// Events queued in memory for the sender; beyond it events are dropped and counted.
    #[arg(long, env = "CALIBAN_USAGE_SHIP_QUEUE", default_value_t = 10_000, global = true)]
    usage_ship_queue: usize,
    /// Directory for undelivered events (control plane unreachable). Default: `usage-spool` next
    /// to `CALIBAN_SNAPSHOT_CACHE` when that is set, otherwise memory (lost on restart).
    #[arg(long, env = "CALIBAN_USAGE_SPOOL_DIR", global = true)]
    usage_spool_dir: Option<PathBuf>,
    /// Undelivered events kept at most; beyond it events are dropped, counted and logged.
    #[arg(long, env = "CALIBAN_USAGE_SPOOL_MAX", default_value_t = 100_000, global = true)]
    usage_spool_max: usize,
}

impl ShipArgs {
    fn options(&self, snapshot_cache: Option<&std::path::Path>) -> Result<caliban_meter::ShipOptions> {
        anyhow::ensure!(
            (1..=5000).contains(&self.usage_ship_batch),
            "CALIBAN_USAGE_SHIP_BATCH must be between 1 and 5000"
        );
        let spool_dir = self.usage_spool_dir.clone().or_else(|| {
            snapshot_cache.map(|p| p.parent().unwrap_or_else(|| std::path::Path::new(".")).join("usage-spool"))
        });
        Ok(caliban_meter::ShipOptions {
            batch_max: self.usage_ship_batch,
            interval: Duration::from_millis(self.usage_ship_interval_ms.max(1)),
            queue: self.usage_ship_queue.max(1),
            spool_dir,
            spool_max_events: self.usage_spool_max,
            ..caliban_meter::ShipOptions::default()
        })
    }

    fn start(
        &self,
        transport: Arc<dyn caliban_meter::UsageTransport>,
        snapshot_cache: Option<&std::path::Path>,
    ) -> Result<Arc<caliban_meter::UsageShipper>> {
        let opts = self.options(snapshot_cache)?;
        let spool = opts.spool_dir.as_ref().map_or_else(|| "memory".to_owned(), |d| d.display().to_string());
        if opts.spool_dir.is_none() {
            tracing::warn!(
                "usage shipping without a spool directory: events not yet delivered when the process stops are lost (set CALIBAN_USAGE_SPOOL_DIR)"
            );
        }
        let shipper = caliban_meter::UsageShipper::start(transport, opts.clone())
            .with_context(|| format!("opening the usage spool {spool}"))?;
        tracing::info!(
            batch = opts.batch_max,
            interval_ms = opts.interval.as_millis() as u64,
            spool,
            spool_max = opts.spool_max_events,
            "usage shipping enabled"
        );
        Ok(Arc::new(shipper))
    }
}

/// Standalone with a Postgres store: the data plane's events go to the store through the same
/// shipper as a router's (batched, deduplicated), once the control plane is built.
#[derive(Default)]
struct LocalUsageTransport {
    cp: std::sync::OnceLock<Arc<caliban_cp::ControlPlane>>,
}

#[async_trait::async_trait]
impl caliban_meter::UsageTransport for LocalUsageTransport {
    async fn send(
        &self,
        events: &[caliban_meter::UsageEvent],
    ) -> Result<caliban_meter::Delivered, caliban_meter::ShipError> {
        let cp = self.cp.get().ok_or_else(|| caliban_meter::ShipError::Retry("control plane starting".into()))?;
        let r =
            cp.store.ingest_usage(events.to_vec()).await.map_err(|e| caliban_meter::ShipError::Retry(e.to_string()))?;
        Ok(caliban_meter::Delivered { accepted: r.accepted, duplicates: r.duplicates, rejected: r.rejected })
    }
}

fn database_url() -> Option<String> {
    std::env::var("CALIBAN_DATABASE_URL").ok().filter(|u| !u.trim().is_empty())
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
    /// Tenant data keys and KEK rotation (Postgres store; uses CALIBAN_DATABASE_URL, CALIBAN_KEK,
    /// CALIBAN_KEK_PREVIOUS and the config file, like the control plane).
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
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

#[derive(Subcommand)]
enum KeysCmd {
    /// Show which KEK wraps each tenant data key, what still waits for migration, and whether the
    /// retired keys in CALIBAN_KEK_PREVIOUS are still needed. Read-only.
    Status,
    /// Re-wrap every tenant data key and re-seal shared provider keys under the current
    /// CALIBAN_KEK (and migrate anything still sealed the old way). All or nothing; idempotent;
    /// audited as `keys.rotate`.
    Rotate,
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
    // A malformed keyring must stop every mode: routers would otherwise derive cache salts and PII
    // surrogate keys from a random secret, and fail to open BYOK keys.
    let keyring = caliban_config::process_keyring().map_err(anyhow::Error::msg).context("KEK keyring")?;
    if let Some(k) = keyring {
        tracing::info!(current = k.current_id(), previous = ?&k.ids()[1..], "KEK keyring loaded");
    }

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
        Cmd::Keys { cmd } => {
            let cfg = Config::from_file(&cli.config).with_context(|| format!("loading {}", cli.config))?;
            return keys_command(cmd, &cfg).await;
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
        let opts =
            WalOptions { queue: cli.usage_wal_queue.max(1), fsync: cli.usage_wal_fsync, ..WalOptions::default() };
        tracing::info!(path = %path, fsync = opts.fsync.as_str(), queue = opts.queue, "usage WAL enabled");
        Arc::new(JsonlSink::with_options(path, opts))
    });
    let usage_sinks = |recent: &RecentUsage, ship: Option<&Arc<caliban_meter::UsageShipper>>| -> Arc<dyn UsageSink> {
        let mut sinks: Vec<Arc<dyn UsageSink>> = vec![Arc::new(recent.clone())];
        if let Some(w) = &wal {
            sinks.push(Arc::clone(w) as Arc<dyn UsageSink>);
        }
        if let Some(s) = ship {
            sinks.push(Arc::clone(s) as Arc<dyn UsageSink>);
        }
        Arc::new(Tee(sinks))
    };

    // Split mode: the router's config comes only from signed control-plane snapshots.
    if let Cmd::Router(RouterArgs { control_plane_url: Some(url), poll_interval_secs, listen, snapshot_cache }) =
        &cli.cmd
    {
        let token = std::env::var("CALIBAN_ROUTER_TOKEN")
            .context("CALIBAN_ROUTER_TOKEN is required with --control-plane-url")?;
        let keys = std::env::var("CALIBAN_SNAPSHOT_PUBLIC_KEY")
            .context("CALIBAN_SNAPSHOT_PUBLIC_KEY is required with --control-plane-url")?;
        let verifier = SnapshotVerifier::from_b64_list(&keys).context("CALIBAN_SNAPSHOT_PUBLIC_KEY")?;
        let every = Duration::from_secs((*poll_interval_secs).max(1));
        let router_id = split::router_id();
        let keyring_ids =
            keyring.as_ref().map(|k| k.ids().into_iter().map(str::to_owned).collect()).unwrap_or_default();
        let mut source = split::SnapshotSource::new(
            url,
            token.clone(),
            verifier,
            snapshot_cache.clone(),
            router_id.clone(),
            keyring_ids,
        )?;
        tracing::info!(control_plane = %url, router_id, poll_secs = every.as_secs(), cache = ?snapshot_cache, "router in split mode");
        let first = source.initial(every).await;
        tracing::info!(version = %first.version, tenants = first.config.tenants.len(), kek_ids = ?first.kek_ids, "serving config snapshot");
        let handle = ConfigHandle::new(Snapshot::new(first.config, first.version).with_kek_ids(first.kek_ids));
        tokio::spawn(source.run(handle.clone(), every));
        // Usage events go to the control plane (fail-static: the router keeps serving while it is
        // down; undelivered events wait in the spool).
        let shipper = if cli.ship.usage_ship {
            let transport = Arc::new(split::HttpUsageTransport::new(url, token.clone(), router_id)?);
            Some(cli.ship.start(transport, snapshot_cache.as_deref())?)
        } else {
            tracing::warn!(
                "CALIBAN_USAGE_SHIP=false: usage events stay on this router (the control plane does not bill them)"
            );
            None
        };
        let gw = Arc::new(new_gateway(handle, usage_sinks(&RecentUsage::default(), shipper.as_ref()))?);
        spawn_router_warmup(&gw);
        gw.spawn_tenant_purge(PURGE_EVERY);
        let res = serve("router", listen.clone(), caliban_gateway::app(gw)).await;
        flush_wal(wal.as_deref()).await;
        flush_shipper(shipper.as_deref()).await;
        return res;
    }

    let cfg = Config::from_file(&cli.config).with_context(|| format!("loading {}", cli.config))?;
    if matches!(cli.cmd, Cmd::CheckConfig) {
        println!("config OK: {} models, {} tenants", cfg.models.len(), cfg.tenants.len());
        return Ok(());
    }
    let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "file-0"));
    let recent = RecentUsage::default();
    // Standalone with Postgres: usage is read from the store, so the data plane ships its events
    // there (the memory store reads this process's ring directly).
    let local_ship = (matches!(cli.cmd, Cmd::Standalone) && database_url().is_some() && cli.ship.usage_ship)
        .then(|| Arc::new(LocalUsageTransport::default()));
    let shipper = match &local_ship {
        Some(t) => Some(cli.ship.start(Arc::clone(t) as Arc<dyn caliban_meter::UsageTransport>, None)?),
        None => None,
    };
    let usage = usage_sinks(&recent, shipper.as_ref());

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
            let cp = control_plane(&cfg, &handle, &recent, "control-plane", None).await?;
            cp.await
        }
        Cmd::Standalone => {
            // The control plane publishes the store's state (Postgres wins over the file) into
            // `handle` before the data plane starts serving. Tenant purges start from that state.
            let cp = control_plane(&cfg, &handle, &recent, "standalone", local_ship.as_deref()).await?;
            purge_gw.spawn_tenant_purge(PURGE_EVERY);
            tokio::try_join!(router_task(), cp).map(|_| ())
        }
        Cmd::CheckConfig
        | Cmd::Keygen
        | Cmd::GenKek
        | Cmd::Keys { .. }
        | Cmd::GenSigningKey
        | Cmd::Healthcheck { .. } => unreachable!(),
    };
    flush_wal(wal.as_deref()).await;
    flush_shipper(shipper.as_deref()).await;
    res
}

/// Graceful shutdown of usage shipping: what is queued is delivered, or kept in the spool for the
/// next start.
async fn flush_shipper(shipper: Option<&caliban_meter::UsageShipper>) {
    if let Some(s) = shipper {
        s.shutdown(Duration::from_secs(5)).await;
    }
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
    local_ship: Option<&LocalUsageTransport>,
) -> Result<impl std::future::Future<Output = Result<()>>> {
    let oidc = control_plane_sso(cfg)?;
    let break_glass = match std::env::var("CALIBAN_BREAK_GLASS").ok().filter(|v| !v.trim().is_empty()) {
        Some(v) => v.trim().parse::<bool>().context("CALIBAN_BREAK_GLASS must be true or false")?,
        None => cfg.security.break_glass,
    };
    if !break_glass && oidc.is_none() {
        anyhow::bail!("security.break_glass = false needs single sign-on ([security.oidc]): nobody could log in");
    }
    let token = match &cfg.security.admin_token {
        Some(r) => r.resolve().context("resolving admin token").map(|s| s.expose().to_owned()),
        None => std::env::var("CALIBAN_ADMIN_TOKEN").context("CALIBAN_ADMIN_TOKEN is required for the control plane"),
    };
    let admin_token = match (break_glass, token, oidc.is_some()) {
        (false, _, _) => {
            tracing::info!("break-glass admin token disabled (security.break_glass = false)");
            String::new()
        }
        (true, Ok(t), true) => {
            tracing::info!("admin token accepted as break-glass: every use is logged and audited");
            t
        }
        (true, Ok(t), false) => t,
        (true, Err(e), true) => {
            tracing::warn!(error = %e, "no admin token: break-glass access is off, SSO is the only way in");
            String::new()
        }
        (true, Err(e), false) => return Err(e),
    };
    let store = match database_url() {
        Some(url) => {
            let s = caliban_cp::store::Store::postgres(&url, cfg.clone(), handle.clone(), recent.clone())
                .await
                .context("opening the Postgres control-plane store (CALIBAN_DATABASE_URL)")?;
            tracing::info!(version = %handle.load().version, "control-plane store: postgres (source of truth; config file seeds an empty database only)");
            s
        }
        None => {
            tracing::warn!(
                "control-plane store: in-memory (seeded from the config file; changes are lost on restart; set CALIBAN_DATABASE_URL to persist)"
            );
            caliban_cp::store::Store::new(cfg.clone(), handle.clone(), recent.clone())
        }
    };
    let postgres = store.backend_name() == "postgres";
    let keyring = Keyring::from_env().map_err(anyhow::Error::msg)?.map(Arc::new);
    match &keyring {
        // Startup migration: BYOK keys sealed directly under the KEK (before migration 0008) and
        // datasource credentials in clear are sealed under tenant data keys. Idempotent.
        Some(k) => match store.rekey(k, false, "system").await {
            Ok((plan, problems)) => {
                if !plan.is_empty() {
                    tracing::info!(detail = %plan.summary(), "migrated tenant secrets to tenant data keys");
                }
                for p in problems {
                    tracing::warn!(problem = %p, "tenant secret not migrated (see `caliban keys status`)");
                }
            }
            Err(e) => tracing::warn!(error = %e, "tenant secret migration failed; will retry at the next start"),
        },
        None => tracing::warn!("CALIBAN_KEK is not set: BYOK keys and datasource credentials cannot be stored"),
    }
    let signer = SnapshotSigner::from_env().context("CALIBAN_SNAPSHOT_SIGNING_KEY")?;
    let router_token = std::env::var("CALIBAN_ROUTER_TOKEN").ok().filter(|t| !t.is_empty());
    match (&signer, &router_token) {
        (Some(s), Some(_)) => {
            tracing::info!(key_id = s.key_id(), "split mode: serving signed snapshots at /api/v1/snapshot")
        }
        (None, None) => {}
        _ => tracing::warn!(
            "split mode needs both CALIBAN_SNAPSHOT_SIGNING_KEY and CALIBAN_ROUTER_TOKEN; /api/v1/snapshot is disabled"
        ),
    }
    let sso = oidc.is_some();
    let cp = Arc::new(
        caliban_cp::ControlPlane::new(store, admin_token, mode)
            .with_snapshots(signer, router_token)
            .with_keyring(keyring)
            .with_oidc(oidc),
    );
    if postgres {
        // Picks up writes made through other control-plane replicas.
        caliban_cp::spawn_refresh(Arc::clone(&cp), Duration::from_secs(5));
    }
    if let Some(t) = local_ship {
        let _ = t.cp.set(Arc::clone(&cp));
    }
    if sso {
        caliban_cp::auth::spawn_purge(Arc::clone(&cp), Duration::from_secs(600));
    }
    let web_dir = std::env::var("CALIBAN_WEB_DIR").ok().or_else(|| cfg.server.web_dir.clone());
    let web_dir = web_dir.filter(|d| std::path::Path::new(d).join("index.html").exists());
    if web_dir.is_none() {
        tracing::warn!("web console not found (set CALIBAN_WEB_DIR); serving API only");
    }
    Ok(serve("control-plane", cfg.server.control_plane_addr.clone(), caliban_cp::app(cp, web_dir.as_deref())))
}

/// Single sign-on from `[security.oidc]` and the `CALIBAN_OIDC_*` environment overrides.
fn control_plane_sso(cfg: &Config) -> Result<Option<caliban_cp::auth::oidc::Oidc>> {
    use caliban_cp::auth::oidc::{Oidc, OidcSettings, config_with_env};
    let Some(c) = config_with_env(cfg.security.oidc.as_ref(), |k| std::env::var(k).ok()).map_err(anyhow::Error::msg)?
    else {
        tracing::info!("single sign-on not configured: the admin token is the only way in (token mode)");
        return Ok(None);
    };
    if let Some(r) = &c.client_secret {
        r.resolve().context("resolving security.oidc.client_secret")?;
    }
    let settings = OidcSettings::from_config(&c).map_err(anyhow::Error::msg)?;
    if !c.issuer.starts_with("https://") {
        tracing::warn!(issuer = %c.issuer, "OIDC issuer is not https: tokens and keys travel in clear");
    }
    if !settings.secure_cookies() {
        tracing::warn!("security.oidc.redirect_url is not https: session cookies are not Secure (development only)");
    }
    tracing::info!(
        issuer = %settings.issuer,
        client_id = %settings.client_id,
        bearer_tokens = settings.api_audience.is_some(),
        group_mappings = settings.role_mappings.len(),
        "single sign-on enabled"
    );
    Ok(Some(Oidc::new(settings).map_err(anyhow::Error::msg)?))
}

/// `caliban keys status|rotate` against the Postgres store (the in-memory store is rebuilt from the
/// config file at every start, so there is nothing to rotate).
async fn keys_command(cmd: &KeysCmd, cfg: &Config) -> Result<()> {
    let url = std::env::var("CALIBAN_DATABASE_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .context("`caliban keys` needs CALIBAN_DATABASE_URL (the in-memory store keeps no keys across restarts)")?;
    let keyring = Keyring::from_env().map_err(anyhow::Error::msg)?;
    let handle = ConfigHandle::new(Snapshot::new(cfg.clone(), "keys"));
    let store = caliban_cp::store::Store::postgres(&url, cfg.clone(), handle, RecentUsage::default())
        .await
        .context("opening the Postgres control-plane store (CALIBAN_DATABASE_URL)")?;
    match cmd {
        KeysCmd::Status => {
            let mut status = caliban_cp::keys::status(&store.state(), keyring.as_ref());
            let routers = store.routers().await.context("reading router check-ins")?;
            caliban_cp::keys::add_routers(&mut status, &routers, keyring.as_ref(), chrono::Utc::now());
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        KeysCmd::Rotate => {
            let k = keyring.context("CALIBAN_KEK is not set")?;
            let (plan, _) = store.rekey(&k, true, "cli").await.context("rotating tenant keys")?;
            if plan.is_empty() {
                println!("nothing to do: every key is already under {}", k.current_id());
            } else {
                println!("{}", serde_json::to_string_pretty(&plan.summary())?);
            }
            let status = caliban_cp::keys::status(&store.state(), Some(&k));
            if status["previous_keks_still_needed"].as_array().is_some_and(Vec::is_empty) {
                println!(
                    "No stored key depends on CALIBAN_KEK_PREVIOUS any more. Run `caliban keys status` until \
                     routers_on_previous_keks is empty (every router serves the re-wrapped snapshot), then remove the \
                     retired keys from CALIBAN_KEK_PREVIOUS and destroy them when your backup retention allows (see \
                     README, KEK rotation)."
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&status)?);
            }
        }
    }
    Ok(())
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
/// artifact hashes verified) and run on a dedicated worker pool; a failure refuses to start rather
/// than silently running without it. The quota and `Idempotency-Key` stores follow `[limits] store`
/// (`valkey` needs `CALIBAN_VALKEY_URL`).
fn new_gateway(handle: ConfigHandle, usage: Arc<dyn UsageSink>) -> Result<caliban_gateway::Gateway> {
    let quota = caliban_gateway::quota_store(&handle.load().config.limits).map_err(anyhow::Error::msg)?;
    let idempotency = caliban_gateway::idempotency_store(&handle.load().config.limits).map_err(anyhow::Error::msg)?;
    let mut gw = caliban_gateway::Gateway::new(handle, usage).with_quota(quota).with_idempotency(idempotency);
    if let Some(dir) = std::env::var("CALIBAN_PII_NER_DIR").ok().filter(|d| !d.trim().is_empty()) {
        let (engine, pool) = load_ner(&dir)?;
        gw = gw.with_pii(engine, pool);
    }
    Ok(gw)
}

/// A positive integer from the environment; unset or empty is `None`, anything else an error.
#[cfg(feature = "ner")]
fn env_count(name: &str) -> Result<Option<usize>> {
    match std::env::var(name).ok().filter(|v| !v.trim().is_empty()) {
        None => Ok(None),
        Some(v) => match v.trim().parse::<usize>() {
            Ok(n) if n > 0 => Ok(Some(n)),
            _ => anyhow::bail!("{name} must be a positive integer, got {v:?}"),
        },
    }
}

/// Loads the NER model with `CALIBAN_PII_NER_SESSIONS` sessions (default `min(cores / 2, 4)`) of
/// `CALIBAN_PII_NER_THREADS` intra-op threads each (default 2, see
/// [`caliban_pii::ner::default_intra_threads`]), and the pool's queue and overflow policy
/// (`CALIBAN_PII_NER_QUEUE`, `CALIBAN_PII_NER_QUEUE_WAIT_MS`, `CALIBAN_PII_NER_OVERFLOW`).
#[cfg(feature = "ner")]
fn load_ner(dir: &str) -> Result<(caliban_pii::PiiEngine, caliban_gateway::pii_pool::PiiPoolOptions)> {
    use caliban_pii::ner::NerOptions;
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let mut opts = NerOptions::default();
    if let Some(n) = env_count("CALIBAN_PII_NER_SESSIONS")? {
        opts.sessions = n;
    }
    opts.intra_threads = ner_threads(env_count("CALIBAN_PII_NER_THREADS")?, cores);
    let started = std::time::Instant::now();
    let ner = caliban_pii::ner::NerDetector::load(std::path::Path::new(dir), opts.clone())
        .with_context(|| format!("loading PII NER model from {dir}"))?;
    let pool = caliban_gateway::pii_pool::PiiPoolOptions::new(ner.sessions())
        .with_env(|k| std::env::var(k).ok())
        .map_err(anyhow::Error::msg)?;
    tracing::info!(
        dir,
        ms = started.elapsed().as_millis() as u64,
        sessions = opts.sessions,
        intra_threads = opts.intra_threads,
        queue = pool.queue,
        queue_wait_ms = pool.queue_wait.as_millis() as u64,
        overflow = ?pool.overflow,
        "PII NER model loaded (L1)"
    );
    Ok((caliban_pii::PiiEngine::default().with_detector(ner), pool))
}

/// Intra-op threads per NER session: `CALIBAN_PII_NER_THREADS` when set, otherwise 2 (fewer on a
/// machine with fewer cores).
#[cfg_attr(not(feature = "ner"), allow(dead_code))]
fn ner_threads(env: Option<usize>, cores: usize) -> usize {
    env.unwrap_or_else(|| caliban_pii::ner::default_intra_threads(cores))
}

#[cfg(not(feature = "ner"))]
fn load_ner(_dir: &str) -> Result<(caliban_pii::PiiEngine, caliban_gateway::pii_pool::PiiPoolOptions)> {
    anyhow::bail!(
        "CALIBAN_PII_NER_DIR is set but this binary was built without the `ner` feature (cargo build -p caliban --features ner)"
    )
}

/// `TCP_NODELAY` on accepted connections: on unless `CALIBAN_TCP_NODELAY` is `0`, `false` or
/// `off`. With Nagle on, Linux holds a stream's first SSE frame until the client's delayed ACK
/// of the headers (24 ms per stream at real model pacing, up to 50 ms; see
/// `bench/RESULTS-aws-2026-10.md`). On macOS loopback Nagle coalesced small frames instead and
/// `TCP_NODELAY` cost about 5 ms p50 at concurrency 64 in the stress bench, but production
/// runs on Linux.
fn tcp_nodelay() -> bool {
    nodelay_from(std::env::var("CALIBAN_TCP_NODELAY").ok().as_deref())
}

fn nodelay_from(v: Option<&str>) -> bool {
    !v.is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"))
}

async fn serve(name: &'static str, addr: String, app: axum::Router) -> Result<()> {
    use axum::serve::ListenerExt;
    let listener = tokio::net::TcpListener::bind(&addr).await.with_context(|| format!("{name}: binding {addr}"))?;
    let nodelay = tcp_nodelay();
    tracing::info!(%addr, nodelay, "{name} listening");
    let listener = listener.tap_io(move |tcp| {
        if nodelay && let Err(e) = tcp.set_nodelay(true) {
            tracing::debug!(error = %e, "TCP_NODELAY not set");
        }
    });
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

#[cfg(test)]
mod ner_threads_tests {
    #[test]
    fn two_threads_unless_overridden() {
        assert_eq!(super::ner_threads(None, 8), 2);
        assert_eq!(super::ner_threads(None, 1), 1);
        assert_eq!(super::ner_threads(Some(4), 8), 4);
        assert_eq!(super::ner_threads(Some(1), 64), 1);
    }
}

#[cfg(test)]
mod nodelay_tests {
    #[test]
    fn tcp_nodelay_is_on_unless_turned_off() {
        for v in [None, Some("1"), Some("true"), Some(""), Some("yes")] {
            assert!(super::nodelay_from(v), "{v:?}");
        }
        for v in ["0", "false", "OFF", " no "] {
            assert!(!super::nodelay_from(Some(v)), "{v}");
        }
    }
}
