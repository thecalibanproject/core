//! Shared quota store on Valkey (or any RESP server with Lua scripting), so every router of a
//! deployment enforces the same rate limits and budgets.
//!
//! Every check is one Lua script run atomically on the server (EVALSHA, falling back to EVAL
//! when the script cache is cold), so concurrent routers cannot double-spend:
//!
//! | Script | Keys | Does |
//! |---|---|---|
//! | `lua/rate.lua` | `rpm` (+ `key:<hash>:rpm`) | GCRA for the tenant and API-key rates, all or nothing |
//! | `lua/reserve.lua` | `tpm`, `day` | checks tokens/day, USD/day and the minute bucket, then reserves |
//! | `lua/settle.lua` | `tpm`, `day` | swaps a reservation for the actual usage (refund or debt) |
//!
//! Keys are `<prefix>:{<tenant>}:<limit>`. The braces are a cluster hash tag, so one tenant's
//! keys share a slot and the multi-key scripts stay valid on a Valkey cluster. Tenant ids are
//! percent-encoded outside `[A-Za-z0-9_.-]`. Every key has a TTL: rate keys expire when their
//! theoretical arrival time passes, minute buckets once refilled, day counters after the UTC day.
//!
//! Errors and timeouts surface as [`QuotaError::Backend`]; [`super::FallbackQuota`] turns them
//! into local limiting. This type never falls back on its own.

use super::{Amount, LimitScope, QuotaError, QuotaPolicy, QuotaStatus, QuotaStore, Reservation};
use async_trait::async_trait;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{Client, ErrorKind, FromRedisValue, IntoConnectionInfo, ServerErrorKind};
use std::fmt::Write as _;
use std::time::Duration;

/// Default per-operation timeout. Same-host or same-zone round trips are well under 1 ms; past
/// this the router stops waiting and limits locally.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(30);
pub const DEFAULT_PREFIX: &str = "caliban";

/// Connection settings for [`ValkeyQuota`].
#[derive(Clone)]
pub struct ValkeyOptions {
    /// `redis://[user:password@]host:port[/db]`, or `rediss://` for TLS (verified against the
    /// platform trust store; `SSL_CERT_FILE` adds a private CA).
    pub url: String,
    /// Overrides the URL's password (e.g. from a separate secret).
    pub password: Option<String>,
    /// Key namespace; lets several deployments share one Valkey.
    pub key_prefix: String,
    /// Upper bound on each quota operation, connection waits included.
    pub timeout: Duration,
}

impl std::fmt::Debug for ValkeyOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValkeyOptions")
            .field("url", &redact(&self.url))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("key_prefix", &self.key_prefix)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl ValkeyOptions {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), password: None, key_prefix: DEFAULT_PREFIX.to_owned(), timeout: DEFAULT_TIMEOUT }
    }
}

/// `redis://user:secret@host` -> `redis://user:***@host`, for logs and health output.
pub fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else { return url.to_owned() };
    match rest.rsplit_once('@') {
        Some((cred, host)) => match cred.split_once(':') {
            Some((user, _)) => format!("{scheme}://{user}:***@{host}"),
            None => format!("{scheme}://***@{host}"),
        },
        None => url.to_owned(),
    }
}

struct Lua {
    src: &'static str,
    sha: String,
}

impl Lua {
    fn new(src: &'static str) -> Self {
        Self { src, sha: redis::Script::new(src).get_hash().to_owned() }
    }
}

pub struct ValkeyQuota {
    conn: ConnectionManager,
    prefix: String,
    timeout: Duration,
    endpoint: String,
    rate: Lua,
    reserve: Lua,
    settle: Lua,
}

impl ValkeyQuota {
    /// Builds the store without connecting: the connection is opened on first use and
    /// re-opened after errors, so a router starts even while Valkey is down. Must be called
    /// inside a Tokio runtime. Fails only on an invalid URL.
    pub fn new(opts: &ValkeyOptions) -> Result<Self, QuotaError> {
        let bad = |e: redis::RedisError| QuotaError::Backend(format!("invalid valkey url {}: {e}", redact(&opts.url)));
        let mut info = opts.url.as_str().into_connection_info().map_err(bad)?;
        if let Some(pw) = opts.password.as_deref().filter(|p| !p.is_empty()) {
            let settings = info.redis_settings().clone().set_password(pw);
            info = info.set_redis_settings(settings);
        }
        let client = Client::open(info).map_err(bad)?;
        let cfg = ConnectionManagerConfig::new()
            // One quick retry per (re)connect; the fallback layer decides how often to probe.
            .set_number_of_retries(1)
            .set_min_delay(Duration::from_millis(50))
            .set_max_delay(Duration::from_millis(500))
            .set_connection_timeout(Some(Duration::from_secs(1)))
            // Bounds how long an abandoned request (see `timeout`) stays queued on the socket.
            .set_response_timeout(Some(Duration::from_secs(1)));
        let conn = ConnectionManager::new_lazy_with_config(client, cfg).map_err(bad)?;
        Ok(Self {
            conn,
            prefix: opts.key_prefix.clone(),
            timeout: opts.timeout,
            endpoint: redact(&opts.url),
            rate: Lua::new(include_str!("lua/rate.lua")),
            reserve: Lua::new(include_str!("lua/reserve.lua")),
            settle: Lua::new(include_str!("lua/settle.lua")),
        })
    }

    /// The Valkey URL with its password redacted.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Round trip to the server within the operation timeout.
    pub async fn ping(&self) -> Result<(), QuotaError> {
        self.ping_within(self.timeout).await
    }

    /// Round trip with a custom bound (start-up, where the first connect and TLS handshake may
    /// take longer than one quota call is allowed to).
    pub async fn ping_within(&self, limit: Duration) -> Result<(), QuotaError> {
        let mut conn = self.conn.clone();
        self.bounded_by(limit, async move { redis::cmd("PING").query_async::<String>(&mut conn).await })
            .await
            .map(|_| ())
    }

    async fn bounded<T>(&self, fut: impl Future<Output = redis::RedisResult<T>>) -> Result<T, QuotaError> {
        self.bounded_by(self.timeout, fut).await
    }

    async fn bounded_by<T>(
        &self,
        limit: Duration,
        fut: impl Future<Output = redis::RedisResult<T>>,
    ) -> Result<T, QuotaError> {
        match tokio::time::timeout(limit, fut).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(QuotaError::Backend(format!("valkey {}: {e}", self.endpoint))),
            Err(_) => {
                Err(QuotaError::Backend(format!("valkey {}: no reply within {} ms", self.endpoint, limit.as_millis())))
            }
        }
    }

    pub fn key_prefix(&self) -> &str {
        &self.prefix
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// EVALSHA, then EVAL if the server does not have the script cached (restart, failover,
    /// SCRIPT FLUSH). EVAL also caches it, so the next EVALSHA hits.
    async fn eval<T: FromRedisValue>(&self, script: &Lua, keys: &[String], args: &[String]) -> Result<T, QuotaError> {
        let mut conn = self.conn.clone();
        let fut = async move {
            let mut cmd = redis::cmd("EVALSHA");
            cmd.arg(&script.sha).arg(keys.len()).arg(keys).arg(args);
            match cmd.query_async::<T>(&mut conn).await {
                Err(e) if e.kind() == ErrorKind::Server(ServerErrorKind::NoScript) => {
                    let mut cmd = redis::cmd("EVAL");
                    cmd.arg(script.src).arg(keys.len()).arg(keys).arg(args);
                    cmd.query_async::<T>(&mut conn).await
                }
                other => other,
            }
        };
        self.bounded(fut).await
    }

    fn key(&self, tenant: &str, limit: &str) -> String {
        format!("{}:{{{}}}:{limit}", self.prefix, encode(tenant))
    }

    /// Keys of a tenant's minute bucket and day counters.
    fn budget_keys(&self, tenant: &str) -> [String; 2] {
        [self.key(tenant, "tpm"), self.key(tenant, "day")]
    }

    /// Settlement that reports failures (the trait's `settle` only logs them).
    pub async fn try_settle(&self, r: &Reservation, actual: Amount) -> Result<(), QuotaError> {
        if !r.tracked {
            return Ok(());
        }
        let args = [
            r.amount.tokens.to_string(),
            num(r.amount.usd),
            actual.tokens.to_string(),
            num(actual.usd),
            r.day.to_string(),
        ];
        self.eval::<i64>(&self.settle, &self.budget_keys(&r.tenant), &args).await.map(|_| ())
    }
}

/// Keeps `[A-Za-z0-9_.-]`, percent-encodes the rest (so `{`, `}` and `:` never reach a key).
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// A float as a Lua-readable number (`tonumber`), exact round trip.
fn num(x: f64) -> String {
    if x.is_finite() { format!("{x:?}") } else { "0".to_owned() }
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|v| v.to_string()).unwrap_or_default()
}

fn scope_named(name: &str) -> Option<LimitScope> {
    Some(match name {
        "tokens_per_minute" => LimitScope::TokensPerMinute,
        "tokens_per_day" => LimitScope::TokensPerDay,
        "usd_per_day" => LimitScope::UsdPerDay,
        _ => return None,
    })
}

#[async_trait]
impl QuotaStore for ValkeyQuota {
    async fn check_rate(&self, tenant: &str, key: Option<&str>, policy: &QuotaPolicy) -> Result<(), QuotaError> {
        let mut keys = Vec::with_capacity(2);
        let mut args = Vec::with_capacity(2);
        let mut scopes = Vec::with_capacity(2);
        if let Some(rpm) = policy.requests_per_minute {
            keys.push(self.key(tenant, "rpm"));
            args.push(rpm.max(1).to_string());
            scopes.push(LimitScope::Requests);
        }
        if let (Some(rpm), Some(k)) = (policy.key_requests_per_minute, key) {
            keys.push(self.key(tenant, &format!("key:{}:rpm", encode(k))));
            args.push(rpm.max(1).to_string());
            scopes.push(LimitScope::KeyRequests);
        }
        if keys.is_empty() {
            return Ok(());
        }
        let reply: Vec<i64> = self.eval(&self.rate, &keys, &args).await?;
        match reply.as_slice() {
            [0] => Ok(()),
            [i, wait_us] => {
                let scope = usize::try_from(*i - 1).ok().and_then(|i| scopes.get(i).copied());
                let scope = scope.ok_or_else(|| QuotaError::Backend(format!("rate script: bad limit index {i}")))?;
                Err(QuotaError::Exceeded {
                    scope,
                    retry_after: Duration::from_micros(u64::try_from(*wait_us).unwrap_or(1).max(1)),
                })
            }
            other => Err(QuotaError::Backend(format!("rate script: unexpected reply {other:?}"))),
        }
    }

    async fn reserve(&self, tenant: &str, policy: &QuotaPolicy, amount: Amount) -> Result<Reservation, QuotaError> {
        if !policy.has_budgets() {
            let (day, _) = super::utc_day_and_secs_left();
            return Ok(Reservation { tenant: tenant.to_owned(), amount, day, tracked: false, local: false });
        }
        let args = [
            amount.tokens.to_string(),
            num(amount.usd),
            opt(policy.tokens_per_minute),
            opt(policy.tokens_per_day),
            policy.usd_per_day.map(num).unwrap_or_default(),
        ];
        let (status, n): (String, i64) = self.eval(&self.reserve, &self.budget_keys(tenant), &args).await?;
        if status == "ok" {
            return Ok(Reservation { tenant: tenant.to_owned(), amount, day: n, tracked: true, local: false });
        }
        let scope = scope_named(&status)
            .ok_or_else(|| QuotaError::Backend(format!("reserve script: unexpected reply {status}")))?;
        Err(QuotaError::Exceeded { scope, retry_after: Duration::from_millis(u64::try_from(n).unwrap_or(1).max(1)) })
    }

    async fn settle(&self, reservation: &Reservation, actual: Amount) {
        if let Err(e) = self.try_settle(reservation, actual).await {
            tracing::warn!(error = %e, tenant = %reservation.tenant, "quota settlement lost; the reservation stays charged");
        }
    }

    fn status(&self) -> QuotaStatus {
        QuotaStatus { store: "valkey", state: "ok", endpoint: Some(self.endpoint.clone()), ..QuotaStatus::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_prefixed_hash_tagged_and_escaped() {
        assert_eq!(encode("acme-corp_1.x"), "acme-corp_1.x");
        assert_eq!(encode("a{b}:c d"), "a%7Bb%7D%3Ac%20d");
        assert_eq!(num(0.1), "0.1");
        assert_eq!(num(f64::NAN), "0");
        assert_eq!(num(3.0), "3.0");
    }

    #[test]
    fn urls_are_redacted() {
        assert_eq!(redact("redis://:s3cret@valkey:6379/0"), "redis://:***@valkey:6379/0");
        assert_eq!(redact("rediss://user:pw@h:6380"), "rediss://user:***@h:6380");
        assert_eq!(redact("redis://valkey:6379"), "redis://valkey:6379");
        let o = ValkeyOptions { password: Some("pw".into()), ..ValkeyOptions::new("redis://:x@h") };
        assert!(!format!("{o:?}").contains("pw\"") && !format!("{o:?}").contains(":x@"));
    }

    #[tokio::test]
    async fn key_layout() {
        let v =
            ValkeyQuota::new(&ValkeyOptions { key_prefix: "p".into(), ..ValkeyOptions::new("redis://127.0.0.1:1") })
                .unwrap();
        assert_eq!(v.key("acme", "rpm"), "p:{acme}:rpm");
        assert_eq!(v.budget_keys("a:b"), ["p:{a%3Ab}:tpm".to_owned(), "p:{a%3Ab}:day".to_owned()]);
        assert!(ValkeyQuota::new(&ValkeyOptions::new("http://nope")).is_err());
    }
}
