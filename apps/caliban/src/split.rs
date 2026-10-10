//! Split mode, router side: poll the control plane's signed snapshot, verify, swap.
//!
//! Fail-static: any error (control plane down, bad signature, invalid config, older snapshot)
//! is logged and the router keeps serving its last good snapshot. With `CALIBAN_SNAPSHOT_CACHE`
//! the last good signed snapshot is persisted (re-verified on load), so a router can restart
//! while the control plane is down.

use anyhow::{Context, Result, anyhow, bail};
use caliban_config::signing::{SignedSnapshot, SnapshotPayload, SnapshotVerifier, config_digest};
use caliban_config::{ConfigHandle, Snapshot};
use caliban_meter::ShipError;
use rand::Rng;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, ETAG, IF_NONE_MATCH};
use std::path::PathBuf;
use std::time::Duration;

pub struct SnapshotSource {
    client: reqwest::Client,
    url: String,
    token: String,
    verifier: SnapshotVerifier,
    cache: Option<PathBuf>,
    etag: Option<String>,
    /// Anti-rollback: never accept a snapshot issued before the one being served.
    issued_at_ms: u64,
    version: String,
    /// KEKs that sealed the secrets of the snapshot being served (reported on every poll).
    kek_ids: Vec<String>,
    /// Reported on every poll: this router's id and keyring ids (current first).
    router_id: String,
    keyring_ids: Vec<String>,
}

/// This router's id for check-ins: `CALIBAN_ROUTER_ID`, else `HOSTNAME`, else `/etc/hostname`,
/// else a random id for this process. Characters outside `[A-Za-z0-9._:-]` become `-`.
pub fn router_id() -> String {
    let from_env = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
    let raw = from_env("CALIBAN_ROUTER_ID")
        .or_else(|| from_env("HOSTNAME"))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname").ok().map(|h| h.trim().to_owned()).filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| format!("router-{:08x}", rand::rng().random::<u32>()));
    raw.chars()
        .take(128)
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-') { c } else { '-' })
        .collect()
}

impl SnapshotSource {
    pub fn new(
        control_plane_url: &str,
        token: String,
        verifier: SnapshotVerifier,
        cache: Option<PathBuf>,
        router_id: String,
        keyring_ids: Vec<String>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            client,
            url: format!("{}/api/v1/snapshot", control_plane_url.trim_end_matches('/')),
            token,
            verifier,
            cache,
            etag: None,
            issued_at_ms: 0,
            version: String::new(),
            kek_ids: Vec::new(),
            router_id,
            keyring_ids,
        })
    }

    fn accept(&mut self, p: &SnapshotPayload, etag: Option<String>) -> Result<()> {
        if p.issued_at_ms < self.issued_at_ms {
            bail!(
                "snapshot {} was issued before the one being served ({} < {}); refusing rollback",
                p.version,
                p.issued_at_ms,
                self.issued_at_ms
            );
        }
        self.issued_at_ms = p.issued_at_ms;
        self.version.clone_from(&p.version);
        self.kek_ids.clone_from(&p.kek_ids);
        // The CP's ETag is the config digest; recompute it if the header is missing (cache load).
        self.etag = etag.or_else(|| Some(format!("\"{}\"", &config_digest(&p.config)[..32])));
        Ok(())
    }

    /// Last good snapshot from disk, verified like a fresh one.
    pub fn load_cache(&mut self) -> Option<SnapshotPayload> {
        let path = self.cache.clone()?;
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read snapshot cache");
                return None;
            }
        };
        let verified = serde_json::from_str::<SignedSnapshot>(&raw)
            .map_err(anyhow::Error::from)
            .and_then(|s| self.verifier.verify(&s).map_err(anyhow::Error::from));
        match verified {
            Ok(p) => {
                self.accept(&p, None).ok()?;
                tracing::info!(path = %path.display(), version = %p.version, "loaded cached snapshot");
                Some(p)
            }
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "ignoring snapshot cache that fails verification");
                None
            }
        }
    }

    /// `Ok(None)` when unchanged (304).
    pub async fn fetch(&mut self) -> Result<Option<SnapshotPayload>> {
        use caliban_config::signing::checkin;
        // Check-in: what this router serves, so `caliban keys status` can tell when no router
        // needs a retired KEK any more.
        let mut req = self
            .client
            .get(&self.url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(checkin::ROUTER_ID, &self.router_id)
            .header(checkin::SNAPSHOT_VERSION, &self.version)
            .header(checkin::SNAPSHOT_KEK_IDS, self.kek_ids.join(","))
            .header(checkin::KEYRING, self.keyring_ids.join(","));
        if let Some(e) = &self.etag {
            req = req.header(IF_NONE_MATCH, e);
        }
        let resp = req.send().await.with_context(|| format!("GET {}", self.url))?;
        match resp.status() {
            StatusCode::NOT_MODIFIED => return Ok(None),
            s if !s.is_success() => {
                let body = resp.text().await.unwrap_or_default();
                return Err(anyhow!("control plane returned {s}: {}", body.chars().take(300).collect::<String>()));
            }
            _ => {}
        }
        let etag = resp.headers().get(ETAG).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let body = resp.text().await.context("reading snapshot body")?;
        let signed: SignedSnapshot = serde_json::from_str(&body).context("decoding snapshot envelope")?;
        let payload = self.verifier.verify(&signed)?;
        self.accept(&payload, etag)?;
        if let Some(path) = &self.cache
            && let Err(e) = write_atomic(path, body.as_bytes())
        {
            tracing::warn!(path = %path.display(), error = %e, "cannot persist snapshot cache");
        }
        Ok(Some(payload))
    }

    /// Cache first (fast start while the CP is down), then the CP; blocks until one of them
    /// yields a valid snapshot.
    pub async fn initial(&mut self, retry: Duration) -> SnapshotPayload {
        let cached = self.load_cache();
        match self.fetch().await {
            Ok(Some(p)) => return p,
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "control plane snapshot unavailable at startup"),
        }
        if let Some(p) = cached {
            return p;
        }
        let mut wait = Duration::from_millis(500);
        loop {
            tracing::warn!(url = %self.url, "no snapshot yet (no usable cache); retrying in {wait:?}");
            tokio::time::sleep(wait).await;
            match self.fetch().await {
                Ok(Some(p)) => return p,
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "snapshot fetch failed"),
            }
            wait = (wait * 2).min(retry);
        }
    }

    /// Polls forever, swapping `handle` on every new verified snapshot.
    pub async fn run(mut self, handle: ConfigHandle, every: Duration) {
        loop {
            // ±20% jitter so a fleet of routers does not poll in lockstep.
            let jitter = rand::rng().random_range(0.8..1.2);
            tokio::time::sleep(every.mul_f64(jitter)).await;
            match self.fetch().await {
                Ok(Some(p)) => {
                    tracing::info!(version = %p.version, tenants = p.config.tenants.len(), kek_ids = ?p.kek_ids, "applied new config snapshot");
                    handle.store(Snapshot::new(p.config, p.version).with_kek_ids(p.kek_ids));
                    // Report the new snapshot right away (a 304), not one poll interval later.
                    if let Err(e) = self.fetch().await {
                        tracing::debug!(error = %format!("{e:#}"), "check-in after applying a snapshot failed");
                    }
                }
                Ok(None) => tracing::debug!(version = %self.version, "snapshot unchanged"),
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), serving = %self.version, "snapshot poll failed; keeping last good snapshot")
                }
            }
        }
    }
}

/// Delivers usage events to the control plane (`POST /api/v1/usage/ingest`, router token), for
/// [`caliban_meter::UsageShipper`]. The control plane stores each `request_id` once, so a batch
/// sent again after a lost acknowledgement or a restart is not counted twice.
pub struct HttpUsageTransport {
    client: reqwest::Client,
    url: String,
    token: String,
    router_id: String,
}

impl HttpUsageTransport {
    pub fn new(control_plane_url: &str, token: String, router_id: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            client,
            url: format!("{}/api/v1/usage/ingest", control_plane_url.trim_end_matches('/')),
            token,
            router_id,
        })
    }
}

#[async_trait::async_trait]
impl caliban_meter::UsageTransport for HttpUsageTransport {
    async fn send(&self, events: &[caliban_meter::UsageEvent]) -> Result<caliban_meter::Delivered, ShipError> {
        let body = serde_json::json!({ "router_id": self.router_id, "events": events });
        let resp = self
            .client
            .post(&self.url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| ShipError::Retry(format!("POST {}: {e}", self.url)))?;
        let status = resp.status();
        if status.is_success() {
            let v: serde_json::Value =
                resp.json().await.map_err(|e| ShipError::Retry(format!("reading the ingest answer: {e}")))?;
            let n = |k: &str| v[k].as_u64().unwrap_or(0);
            return Ok(caliban_meter::Delivered {
                accepted: n("accepted"),
                duplicates: n("duplicates"),
                rejected: n("rejected"),
            });
        }
        let text: String = resp.text().await.unwrap_or_default().chars().take(300).collect();
        let msg = match status {
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => {
                format!("the control plane does not accept usage events ({status}); upgrade it")
            }
            StatusCode::UNAUTHORIZED => format!("the control plane refused the router token ({status})"),
            _ => format!("control plane returned {status}: {text}"),
        };
        // A malformed or oversized batch fails the same way every time: drop it (counted) rather
        // than block the backlog. Everything else (down, overloaded, misconfigured token, older
        // control plane) is retried.
        if matches!(status, StatusCode::BAD_REQUEST | StatusCode::PAYLOAD_TOO_LARGE | StatusCode::UNPROCESSABLE_ENTITY)
        {
            Err(ShipError::Fatal(msg))
        } else {
            Err(ShipError::Retry(msg))
        }
    }
}

/// Write-then-rename so a crash never leaves a torn cache file. Owner-only permissions: the
/// snapshot holds key hashes and sealed (encrypted) BYOK credentials.
fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliban_config::Config;
    use caliban_config::signing::{SnapshotSigner, generate_signing_key};

    fn payload(at: u64) -> SnapshotPayload {
        let config = Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
        SnapshotPayload { version: format!("cp-{at}"), issued_at_ms: at, config, kek_ids: vec![format!("kek_{at}")] }
    }

    fn source(public: &str, cache: Option<PathBuf>) -> SnapshotSource {
        SnapshotSource::new(
            "http://127.0.0.1:9",
            "t".into(),
            SnapshotVerifier::from_b64_list(public).unwrap(),
            cache,
            "r1".into(),
            vec![],
        )
        .unwrap()
    }

    #[test]
    fn rollback_is_refused() {
        let (_, public) = generate_signing_key();
        let mut s = source(&public, None);
        s.accept(&payload(200), None).unwrap();
        assert!(s.accept(&payload(100), None).is_err());
        assert_eq!((s.version.as_str(), s.kek_ids.as_slice()), ("cp-200", ["kek_200".to_owned()].as_slice()));
        assert!(s.accept(&payload(300), None).is_ok());
    }

    #[test]
    fn cache_is_verified_on_load() {
        let (seed, public) = generate_signing_key();
        let dir = std::env::temp_dir().join(format!("caliban-split-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snapshot.json");
        let signed = SnapshotSigner::from_b64(&seed).unwrap().sign(&payload(5)).unwrap();
        write_atomic(&path, serde_json::to_string(&signed).unwrap().as_bytes()).unwrap();
        let mut s = source(&public, Some(path.clone()));
        assert_eq!(s.load_cache().unwrap().version, "cp-5");
        assert!(s.etag.is_some());

        // A cache signed by someone else (or edited on disk) is ignored.
        let (other, _) = generate_signing_key();
        let forged = SnapshotSigner::from_b64(&other).unwrap().sign(&payload(6)).unwrap();
        write_atomic(&path, serde_json::to_string(&forged).unwrap().as_bytes()).unwrap();
        assert!(source(&public, Some(path)).load_cache().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn unreachable_control_plane_is_an_error_not_a_panic() {
        let (_, public) = generate_signing_key();
        assert!(source(&public, None).fetch().await.is_err());
    }
}
