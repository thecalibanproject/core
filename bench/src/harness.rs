//! Runs the real `caliban` binary in `standalone` mode against a generated config, for the
//! benchmark and the black-box isolation and usage-accuracy tests.

use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::RngCore;
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use serde_json::Value;
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const ADMIN_TOKEN: &str = "bench-admin-token";

/// A fresh tenant API key (`cal_…`) and the SHA-256 hex hash the config stores.
pub fn new_key(tag: &str) -> (String, String) {
    let mut b = [0u8; 16];
    rand::rng().fill_bytes(&mut b);
    let key = format!("cal_{tag}_{}", hex::encode(b));
    let hash = hex::encode(sha2::Sha256::digest(key.as_bytes()));
    (key, hash)
}

/// A base64 32-byte key-encryption key for `CALIBAN_KEK`.
pub fn new_kek() -> String {
    let mut k = [0u8; 32];
    rand::rng().fill_bytes(&mut k);
    base64::engine::general_purpose::STANDARD.encode(k)
}

/// A port that was free a moment ago.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

/// Options for one gateway process.
#[derive(Debug, Clone, Default)]
pub struct Launch {
    /// Config body without `[server]` (added here with the chosen ports).
    pub config: String,
    /// Extra environment (BYOK key variables, `CALIBAN_PII_NER_DIR`, …).
    pub env: Vec<(String, String)>,
    /// `CALIBAN_KEK`; a fresh one when `None`.
    pub kek: Option<String>,
    /// Write usage events to this JSONL file (`CALIBAN_USAGE_WAL`).
    pub usage_wal: bool,
    /// `CALIBAN_LOG` (default: `warn`).
    pub log: Option<String>,
    /// Startup timeout (NER model loading can take a while).
    pub startup_timeout: Option<Duration>,
}

/// A running `caliban standalone` process; killed on drop.
pub struct Caliban {
    child: Child,
    pub dp: String,
    pub cp: String,
    pub work: PathBuf,
    pub wal: Option<PathBuf>,
    pub kek: String,
    http: reqwest::Client,
}

impl Drop for Caliban {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(256)
        .build()
        .expect("http client")
}

impl Caliban {
    /// Starts `bin standalone` with `launch`, retrying with new ports if the process dies at
    /// startup (a port taken in between).
    pub async fn start(bin: &Path, launch: &Launch) -> Result<Self> {
        let mut last = None;
        for _ in 0..3 {
            match Self::try_start(bin, launch).await {
                Ok(c) => return Ok(c),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("caliban did not start")))
    }

    async fn try_start(bin: &Path, launch: &Launch) -> Result<Self> {
        let (dp_port, cp_port) = (free_port(), free_port());
        let mut b = [0u8; 8];
        rand::rng().fill_bytes(&mut b);
        let work = std::env::temp_dir().join(format!("caliban-bench-{}", hex::encode(b)));
        std::fs::create_dir_all(&work)?;
        let config = format!(
            "[server]\nrouter_addr = \"127.0.0.1:{dp_port}\"\ncontrol_plane_addr = \"127.0.0.1:{cp_port}\"\n\n{}",
            launch.config
        );
        let cfg_path = work.join("caliban.toml");
        std::fs::write(&cfg_path, config)?;
        let wal = launch.usage_wal.then(|| work.join("usage.jsonl"));
        let kek = launch.kek.clone().unwrap_or_else(new_kek);
        let log = std::fs::File::create(work.join("caliban.log"))?;
        let mut cmd = Command::new(bin);
        cmd.arg("standalone")
            .env("CALIBAN_CONFIG", &cfg_path)
            .env("CALIBAN_ADMIN_TOKEN", ADMIN_TOKEN)
            .env("CALIBAN_KEK", &kek)
            .env("CALIBAN_LOG", launch.log.as_deref().unwrap_or("warn"))
            .env_remove("CALIBAN_DATABASE_URL")
            .env_remove("CALIBAN_USAGE_WAL")
            .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        if !launch.env.iter().any(|(k, _)| k == "CALIBAN_PII_NER_DIR") {
            cmd.env_remove("CALIBAN_PII_NER_DIR");
        }
        if let Some(w) = &wal {
            cmd.env("CALIBAN_USAGE_WAL", w);
        }
        for (k, v) in &launch.env {
            cmd.env(k, v);
        }
        let child = cmd
            .spawn()
            .with_context(|| format!("spawning {}", bin.display()))?;
        let mut me = Self {
            child,
            dp: format!("http://127.0.0.1:{dp_port}"),
            cp: format!("http://127.0.0.1:{cp_port}"),
            work,
            wal,
            kek,
            http: client(),
        };
        let deadline = Instant::now() + launch.startup_timeout.unwrap_or(Duration::from_secs(30));
        loop {
            if let Some(status) = me.child.try_wait()? {
                let log = std::fs::read_to_string(me.work.join("caliban.log")).unwrap_or_default();
                bail!("caliban exited at startup ({status}):\n{log}");
            }
            let dp_ok = me
                .http
                .get(format!("{}/healthz", me.dp))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            let cp_ok = me
                .http
                .get(format!("{}/api/v1/health", me.cp))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            if dp_ok && cp_ok {
                return Ok(me);
            }
            if Instant::now() > deadline {
                let log = std::fs::read_to_string(me.work.join("caliban.log")).unwrap_or_default();
                bail!("caliban did not become healthy:\n{log}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The process log so far.
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.work.join("caliban.log")).unwrap_or_default()
    }

    /// Usage events from the JSONL write-ahead log.
    pub fn wal_events(&self) -> Vec<Value> {
        let Some(p) = &self.wal else {
            return Vec::new();
        };
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// Admin API call with the admin token.
    pub async fn admin(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.cp_call(method, path, Some(ADMIN_TOKEN), body).await
    }

    /// Control-plane call with an arbitrary bearer token (or none).
    pub async fn cp_call(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let url = format!("{}/api/v1{path}", self.cp);
        let mut req = self.http.request(method.parse().expect("method"), url);
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.expect("control plane reachable");
        let status = resp.status();
        let v = resp.json().await.unwrap_or(Value::Null);
        (status, v)
    }

    /// Data-plane call: OpenAI-style bearer key.
    pub async fn chat(&self, key: &str, body: &Value) -> Reply {
        self.dp_post(
            "/v1/chat/completions",
            &[("authorization", format!("Bearer {key}"))],
            body,
        )
        .await
    }

    /// Data-plane call: Anthropic-style `x-api-key`.
    pub async fn messages(&self, key: &str, body: &Value) -> Reply {
        self.dp_post(
            "/v1/messages",
            &[
                ("x-api-key", key.to_owned()),
                ("anthropic-version", "2023-06-01".to_owned()),
            ],
            body,
        )
        .await
    }

    pub async fn dp_post(&self, path: &str, headers: &[(&str, String)], body: &Value) -> Reply {
        let mut req = self.http.post(format!("{}{path}", self.dp)).json(body);
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        let resp = req.send().await.expect("data plane reachable");
        Reply::read(resp).await
    }

    pub async fn dp_get(&self, path: &str, key: &str) -> Reply {
        let resp = self
            .http
            .get(format!("{}{path}", self.dp))
            .bearer_auth(key)
            .send()
            .await
            .expect("data plane reachable");
        Reply::read(resp).await
    }
}

/// A complete data-plane response.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub text: String,
}

impl Reply {
    async fn read(resp: reqwest::Response) -> Self {
        let status = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().await.unwrap_or_default();
        Self {
            status,
            headers,
            text,
        }
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    pub fn request_id(&self) -> String {
        self.header("x-caliban-request-id").unwrap_or_default()
    }

    /// Text of a non-streaming response in either dialect.
    pub fn content(&self) -> String {
        let v = self.json();
        if let Some(s) = v
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
        {
            return s.to_owned();
        }
        v.get("content")
            .and_then(Value::as_array)
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|b| b.get("text").and_then(Value::as_str))
                    .collect::<String>()
            })
            .unwrap_or_default()
    }

    /// `data:` payloads of an SSE response, parsed as JSON where possible.
    pub fn sse_events(&self) -> Vec<Value> {
        self.text
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|d| serde_json::from_str(d).ok())
            .collect()
    }

    /// Concatenated text of a streaming response in either dialect.
    pub fn stream_text(&self) -> String {
        let mut out = String::new();
        for ev in self.sse_events() {
            if let Some(choices) = ev.get("choices").and_then(Value::as_array) {
                for c in choices {
                    if let Some(s) = c.pointer("/delta/content").and_then(Value::as_str) {
                        out.push_str(s);
                    }
                }
            } else if ev.get("type").and_then(Value::as_str) == Some("content_block_delta")
                && let Some(s) = ev.pointer("/delta/text").and_then(Value::as_str)
            {
                out.push_str(s);
            }
        }
        out
    }
}
