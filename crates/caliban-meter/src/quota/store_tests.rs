//! One behavioural suite for every [`QuotaStore`]: always against [`InMemoryQuota`], and against
//! Valkey when `CALIBAN_TEST_VALKEY_URL` is set (e.g. `redis://127.0.0.1:6379`), plus
//! Valkey-only tests: concurrency across two store instances, reserve and settle against the
//! server's counters, TTLs, the fallback when Valkey goes away, and a latency measurement.
//!
//! Without the variable the Valkey tests print a skip message and pass. Each test uses its own
//! random key prefix, so runs never collide and leftovers expire on their own.

use super::*;
use std::time::Instant;

// ─────────────────────────────── shared suite ───────────────────────────────

fn p() -> QuotaPolicy {
    QuotaPolicy::default()
}

fn amt(tokens: u64, usd: f64) -> Amount {
    Amount { tokens, usd }
}

fn exceeded(r: Result<impl std::fmt::Debug, QuotaError>) -> (LimitScope, Duration) {
    match r {
        Err(QuotaError::Exceeded { scope, retry_after }) => (scope, retry_after),
        other => panic!("expected a 429, got {other:?}"),
    }
}

fn close(d: Duration, secs: f64, tol: f64) -> bool {
    (d.as_secs_f64() - secs).abs() <= tol
}

async fn suite(s: &Arc<dyn QuotaStore>) {
    // GCRA: burst of `rpm`, then a wait of one emission interval (60 s / rpm).
    let two = QuotaPolicy { requests_per_minute: Some(2), ..p() };
    s.check_rate("t1", None, &two).await.unwrap();
    s.check_rate("t1", None, &two).await.unwrap();
    let (scope, ra) = exceeded(s.check_rate("t1", None, &two).await);
    assert_eq!(scope, LimitScope::Requests);
    assert!(ra > Duration::from_secs(29) && ra <= Duration::from_secs(30), "{ra:?}");
    s.check_rate("t1-other", None, &two).await.unwrap();

    // A changed rate takes effect at once (hot reload).
    let more = QuotaPolicy { requests_per_minute: Some(100), ..p() };
    s.check_rate("t1", None, &more).await.unwrap();

    // Per-key rates are separate from each other and from the tenant rate.
    let key1 = QuotaPolicy { key_requests_per_minute: Some(1), ..p() };
    s.check_rate("t2", Some("k1"), &key1).await.unwrap();
    s.check_rate("t2", Some("k2"), &key1).await.unwrap();
    assert_eq!(exceeded(s.check_rate("t2", Some("k1"), &key1).await).0, LimitScope::KeyRequests);
    // No key: only the tenant rate applies.
    s.check_rate("t2", None, &key1).await.unwrap();

    // Minute bucket: reserve, refuse with the refill wait, refund on settle.
    let tpm = QuotaPolicy { tokens_per_minute: Some(600), ..p() };
    let r = s.reserve("t3", &tpm, amt(500, 0.0)).await.unwrap();
    assert!(r.tracked);
    let (scope, ra) = exceeded(s.reserve("t3", &tpm, amt(200, 0.0)).await);
    assert_eq!(scope, LimitScope::TokensPerMinute);
    assert!(close(ra, 10.0, 0.5), "100 tokens missing at 10/s: {ra:?}");
    s.settle(&r, amt(50, 0.0)).await;
    s.reserve("t3", &tpm, amt(200, 0.0)).await.unwrap();

    // Under-estimate: the bucket goes into debt.
    let tpm60 = QuotaPolicy { tokens_per_minute: Some(60), ..p() };
    let r = s.reserve("t4", &tpm60, amt(10, 0.0)).await.unwrap();
    s.settle(&r, amt(110, 0.0)).await;
    let (_, ra) = exceeded(s.reserve("t4", &tpm60, amt(1, 0.0)).await);
    assert!(close(ra, 51.0, 0.5), "level -50, 1 token at 1/s: {ra:?}");

    // A request larger than the bucket gets in only when the bucket is full.
    let tpm100 = QuotaPolicy { tokens_per_minute: Some(100), ..p() };
    s.reserve("t5", &tpm100, amt(1000, 0.0)).await.unwrap();
    assert_eq!(exceeded(s.reserve("t5", &tpm100, amt(1000, 0.0)).await).0, LimitScope::TokensPerMinute);

    // Day budgets: tokens and USD, reserved then reconciled.
    let day = QuotaPolicy { tokens_per_day: Some(1000), usd_per_day: Some(1.0), ..p() };
    let r = s.reserve("t6", &day, amt(800, 0.5)).await.unwrap();
    let (scope, ra) = exceeded(s.reserve("t6", &day, amt(300, 0.0)).await);
    assert_eq!(scope, LimitScope::TokensPerDay);
    assert!(ra > Duration::ZERO && ra <= Duration::from_secs(86_400), "{ra:?}");
    s.settle(&r, amt(100, 0.9)).await; // now 100 tokens, 0.9 USD
    assert_eq!(exceeded(s.reserve("t6", &day, amt(300, 0.2)).await).0, LimitScope::UsdPerDay);
    s.reserve("t6", &day, amt(300, 0.05)).await.unwrap(); // 400 tokens, 0.95 USD
    assert_eq!(exceeded(s.reserve("t6", &day, amt(601, 0.0)).await).0, LimitScope::TokensPerDay);
    s.reserve("t6", &day, amt(600, 0.0)).await.unwrap();

    // No budgets: nothing tracked, settle is a no-op.
    let r = s.reserve("t7", &p(), amt(10, 0.0)).await.unwrap();
    assert!(!r.tracked);
    s.settle(&r, amt(99, 0.0)).await;

    // The settlement guard refunds on drop unless an upstream call is in flight.
    let tpd = QuotaPolicy { tokens_per_day: Some(1000), ..p() };
    let r = s.reserve("t8", &tpd, amt(600, 0.0)).await.unwrap();
    drop(Settlement::new(Arc::clone(s), r));
    eventually(|| async {
        s.reserve("t8", &QuotaPolicy { tokens_per_day: Some(600), ..p() }, amt(600, 0.0)).await.is_ok()
    })
    .await;
}

/// Polls `f` for up to 2 s (background settlement runs on a spawned task).
async fn eventually<F, Fut>(f: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..200 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not met within 2 s");
}

#[tokio::test]
async fn memory_store_passes_the_suite() {
    suite(&(Arc::new(InMemoryQuota::new()) as Arc<dyn QuotaStore>)).await;
    assert_eq!(InMemoryQuota::new().status(), QuotaStatus::default());
}

// ─────────────────────────────── fallback (no Valkey needed) ───────────────────────────────

/// The in-memory limiter's clock (`quanta`) calibrates on first use, once per process; do it
/// before timing anything.
async fn warm_local_clock() {
    let q = InMemoryQuota::new();
    q.check_rate("warm", None, &QuotaPolicy { requests_per_minute: Some(1), ..p() }).await.unwrap();
}

/// A port nothing listens on.
async fn closed_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test]
async fn unreachable_valkey_falls_back_to_local_limits() {
    warm_local_clock().await;
    let url = format!("redis://:pw@127.0.0.1:{}", closed_port().await);
    let store = Arc::new(FallbackQuota::new(ValkeyQuota::new(&ValkeyOptions::new(url)).unwrap()));
    assert!(!store.probe(Duration::from_secs(2)).await);
    let status = store.status();
    assert_eq!((status.store, status.state), ("valkey", "degraded"));
    assert!(status.detail.as_deref().is_some_and(|d| d.contains("limiting locally")), "{status:?}");
    assert!(status.endpoint.as_deref().is_some_and(|e| !e.contains("pw")), "password must be redacted: {status:?}");

    // Still limited, by the local store, and without waiting on Valkey while the circuit is open.
    let s: Arc<dyn QuotaStore> = store.clone();
    let two = QuotaPolicy { requests_per_minute: Some(2), tokens_per_day: Some(100), ..p() };
    let started = Instant::now();
    s.check_rate("t", None, &two).await.unwrap();
    s.check_rate("t", None, &two).await.unwrap();
    assert_eq!(exceeded(s.check_rate("t", None, &two).await).0, LimitScope::Requests);
    let r = s.reserve("t", &two, amt(80, 0.0)).await.unwrap();
    assert!(r.local, "reserved in the local store");
    assert_eq!(exceeded(s.reserve("t", &two, amt(30, 0.0)).await).0, LimitScope::TokensPerDay);
    s.settle(&r, amt(10, 0.0)).await;
    assert_eq!(store.local().day_usage("t").0, 10, "settled where it was reserved");
    assert!(
        started.elapsed() < Duration::from_millis(20),
        "circuit open: no Valkey round trips ({:?})",
        started.elapsed()
    );
    assert_eq!(store.fallbacks(), 5, "3 rate checks + 2 reservations served locally");
}

// ─────────────────────────────── Valkey ───────────────────────────────

fn valkey_url() -> Option<String> {
    let url = std::env::var("CALIBAN_TEST_VALKEY_URL").ok().filter(|u| !u.trim().is_empty());
    if url.is_none() {
        eprintln!("CALIBAN_TEST_VALKEY_URL not set; skipping Valkey quota tests");
    }
    url
}

fn opts(url: &str, prefix: &str) -> ValkeyOptions {
    // Generous timeout: CI runners are noisy; the latency test measures the real cost.
    ValkeyOptions { key_prefix: prefix.to_owned(), timeout: Duration::from_millis(500), ..ValkeyOptions::new(url) }
}

fn prefix() -> String {
    format!("caliban-test-{}", uuid::Uuid::new_v4().simple())
}

async fn raw(url: &str) -> redis::aio::MultiplexedConnection {
    redis::Client::open(url)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .expect("CALIBAN_TEST_VALKEY_URL must be reachable")
}

#[tokio::test]
async fn valkey_store_passes_the_suite() {
    let Some(url) = valkey_url() else { return };
    let v = ValkeyQuota::new(&opts(&url, &prefix())).unwrap();
    v.ping().await.expect("CALIBAN_TEST_VALKEY_URL must be reachable");
    suite(&(Arc::new(v) as Arc<dyn QuotaStore>)).await;
}

#[tokio::test]
async fn valkey_script_cache_miss_falls_back_to_eval() {
    let Some(url) = valkey_url() else { return };
    let v = ValkeyQuota::new(&opts(&url, &prefix())).unwrap();
    let one = QuotaPolicy { requests_per_minute: Some(1), ..p() };
    let _: () = redis::cmd("SCRIPT").arg("FLUSH").query_async(&mut raw(&url).await).await.unwrap();
    v.check_rate("t", None, &one).await.unwrap();
    assert!(v.check_rate("t", None, &one).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valkey_two_routers_never_exceed_the_limits() {
    let Some(url) = valkey_url() else { return };
    let prefix = prefix();
    let a = Arc::new(ValkeyQuota::new(&opts(&url, &prefix)).unwrap());
    let b = Arc::new(ValkeyQuota::new(&opts(&url, &prefix)).unwrap());
    let stores: [Arc<dyn QuotaStore>; 2] = [a, b];

    // Request rate: 20/min = one per 3 s after the burst of 20.
    let rpm = QuotaPolicy { requests_per_minute: Some(20), key_requests_per_minute: Some(15), ..p() };
    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..400 {
        let s = Arc::clone(&stores[i % 2]);
        let rpm = rpm.clone();
        // Half the calls carry API key "k": at most 15 of those.
        tasks.spawn(async move { (i % 4 < 2, s.check_rate("t", (i % 4 < 2).then_some("k"), &rpm).await) });
    }
    let (mut ok, mut ok_key) = (0u64, 0u64);
    while let Some(r) = tasks.join_next().await {
        let (keyed, r) = r.unwrap();
        match r {
            Ok(()) => {
                ok += 1;
                ok_key += u64::from(keyed);
            }
            Err(QuotaError::Exceeded { .. }) => {}
            Err(e) => panic!("{e}"),
        }
    }
    let refills = started.elapsed().as_secs() / 3;
    assert!(ok >= 20 && ok <= 20 + refills, "admitted {ok} of 400 with rpm 20 in {:?}", started.elapsed());
    assert!(ok_key <= 15 + refills / 4 + 1, "key admitted {ok_key} with key rpm 15");

    // Day budget: 1000 tokens, 7 per request: exactly 142 reservations fit.
    let tpd = QuotaPolicy { tokens_per_day: Some(1000), ..p() };
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..400 {
        let s = Arc::clone(&stores[i % 2]);
        let tpd = tpd.clone();
        tasks.spawn(async move { s.reserve("budget", &tpd, amt(7, 0.0)).await.is_ok() });
    }
    let fit = tasks.join_all().await.into_iter().filter(|ok| *ok).count();
    assert_eq!(fit, 142);

    // Reserve and settle concurrently from both routers: counters end exactly at actual usage.
    let big = QuotaPolicy { tokens_per_day: Some(10_000_000), usd_per_day: Some(1000.0), ..p() };
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..300 {
        let s = Arc::clone(&stores[i % 2]);
        let big = big.clone();
        tasks.spawn(async move {
            let r = s.reserve("recon", &big, amt(1000, 0.5)).await.unwrap();
            s.settle(&r, amt(3, 0.25)).await;
        });
    }
    tasks.join_all().await;
    let (tokens, usd): (f64, f64) = redis::cmd("HMGET")
        .arg(format!("{prefix}:{{recon}}:day"))
        .arg("tokens")
        .arg("usd")
        .query_async(&mut raw(&url).await)
        .await
        .unwrap();
    assert!((tokens - 900.0).abs() < 1e-9, "tokens {tokens}");
    assert!((usd - 75.0).abs() < 1e-6, "usd {usd}");
}

#[tokio::test]
async fn valkey_reserve_and_reconcile_update_shared_counters() {
    let Some(url) = valkey_url() else { return };
    let prefix = prefix();
    let a = ValkeyQuota::new(&opts(&url, &prefix)).unwrap();
    let b = ValkeyQuota::new(&opts(&url, &prefix)).unwrap();
    let conn = raw(&url).await;
    let day_key = format!("{prefix}:{{acme}}:day");
    let tpm_key = format!("{prefix}:{{acme}}:tpm");
    let read = |key: String, field: &'static str| {
        let mut c = conn.clone();
        async move {
            redis::cmd("HGET").arg(key).arg(field).query_async::<Option<f64>>(&mut c).await.unwrap().unwrap_or(0.0)
        }
    };

    let pol = QuotaPolicy { tokens_per_minute: Some(6000), tokens_per_day: Some(5000), usd_per_day: Some(2.0), ..p() };
    // Router A reserves; router B sees the reservation.
    let r = a.reserve("acme", &pol, amt(4000, 1.5)).await.unwrap();
    assert_eq!(read(day_key.clone(), "tokens").await, 4000.0);
    assert!(read(tpm_key.clone(), "level").await <= 2000.0 + 1.0);
    assert_eq!(exceeded(b.reserve("acme", &pol, amt(1500, 0.0)).await).0, LimitScope::TokensPerDay);
    // A settles the actual (smaller) usage: B now fits.
    a.settle(&r, amt(1200, 0.4)).await;
    assert_eq!(read(day_key.clone(), "tokens").await, 1200.0);
    assert!((read(day_key.clone(), "usd").await - 0.4).abs() < 1e-9);
    let r2 = b.reserve("acme", &pol, amt(1500, 0.5)).await.unwrap();
    // An under-estimate is charged in full and puts the minute bucket in debt.
    b.settle(&r2, amt(9000, 0.5)).await;
    assert_eq!(read(day_key.clone(), "tokens").await, 10_200.0);
    assert!(read(tpm_key.clone(), "level").await < 0.0);
    assert_eq!(
        exceeded(a.reserve("acme", &QuotaPolicy { tokens_per_day: None, ..pol.clone() }, amt(1, 0.0)).await).0,
        LimitScope::TokensPerMinute
    );
    // Settling a reservation from an earlier UTC day charges today without refunding.
    let stale = Reservation { day: r.day - 1, ..r.clone() };
    a.settle(&stale, amt(5, 0.0)).await;
    assert_eq!(read(day_key, "tokens").await, 10_205.0);
}

#[tokio::test]
async fn valkey_keys_are_namespaced_and_expire() {
    let Some(url) = valkey_url() else { return };
    let prefix = prefix();
    let v = ValkeyQuota::new(&opts(&url, &prefix)).unwrap();
    let mut conn = raw(&url).await;

    // 600 rpm: TAT 100 ms ahead; 6000 tpm (100 tokens/s): 50 tokens refill in 500 ms.
    let pol = QuotaPolicy {
        requests_per_minute: Some(600),
        key_requests_per_minute: Some(600),
        tokens_per_minute: Some(6000),
        tokens_per_day: Some(1_000_000),
        ..p()
    };
    v.check_rate("idle", Some("abc"), &pol).await.unwrap();
    v.reserve("idle", &pol, amt(50, 0.0)).await.unwrap();

    let mut keys: Vec<String> = redis::cmd("KEYS").arg(format!("{prefix}:*")).query_async(&mut conn).await.unwrap();
    keys.sort();
    let want = ["day", "key:abc:rpm", "rpm", "tpm"].map(|k| format!("{prefix}:{{idle}}:{k}"));
    assert_eq!(keys, want);

    let pttl = |k: &str| {
        let mut c = conn.clone();
        let k = format!("{prefix}:{{idle}}:{k}");
        async move { redis::cmd("PTTL").arg(k).query_async::<i64>(&mut c).await.unwrap() }
    };
    let (rpm, tpm, day) = (pttl("rpm").await, pttl("tpm").await, pttl("day").await);
    assert!(rpm > 0 && rpm <= 100, "rpm ttl {rpm}");
    assert!(tpm > 300 && tpm <= 500, "tpm ttl {tpm}");
    assert!(day > 60_000 && day <= 86_460_000, "day ttl {day}");

    tokio::time::sleep(Duration::from_millis(650)).await;
    let left: Vec<String> = redis::cmd("KEYS").arg(format!("{prefix}:*")).query_async(&mut conn).await.unwrap();
    assert_eq!(left, vec![format!("{prefix}:{{idle}}:day")], "rate and minute keys expire once idle");
}

/// TCP proxy in front of Valkey that can be cut and restored, to simulate an outage.
struct Proxy {
    addr: std::net::SocketAddr,
    upstream: String,
    tasks: Arc<parking_lot::Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl Proxy {
    async fn start(upstream: String, addr: &str) -> Self {
        let l = tokio::net::TcpListener::bind(addr).await.unwrap();
        let p = Self { addr: l.local_addr().unwrap(), upstream, tasks: Arc::default() };
        p.serve(l);
        p
    }

    fn serve(&self, l: tokio::net::TcpListener) {
        let (up, tasks) = (self.upstream.clone(), Arc::clone(&self.tasks));
        let t2 = Arc::clone(&tasks);
        let h = tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let up = up.clone();
                let h = tokio::spawn(async move {
                    if let Ok(mut s) = tokio::net::TcpStream::connect(&up).await {
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
                    }
                });
                t2.lock().push(h.abort_handle());
            }
        });
        tasks.lock().push(h.abort_handle());
    }

    fn cut(&self) {
        for h in self.tasks.lock().drain(..) {
            h.abort();
        }
    }

    async fn restore(&self) {
        let l = tokio::net::TcpListener::bind(self.addr).await.unwrap();
        self.serve(l);
    }
}

fn host_port(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
    rest.split('/').next().unwrap_or(rest).to_owned()
}

#[tokio::test]
async fn valkey_outage_falls_back_locally_and_recovers() {
    let Some(url) = valkey_url() else { return };
    warm_local_clock().await;
    let proxy = Proxy::start(host_port(&url), "127.0.0.1:0").await;
    let via_proxy = url.replacen(&host_port(&url), &proxy.addr.to_string(), 1);
    let o = ValkeyOptions { key_prefix: prefix(), timeout: Duration::from_millis(30), ..ValkeyOptions::new(via_proxy) };
    let store = Arc::new(FallbackQuota::with_retry_after(ValkeyQuota::new(&o).unwrap(), Duration::from_millis(200)));
    assert!(store.probe(Duration::from_secs(2)).await);
    let s: Arc<dyn QuotaStore> = store.clone();

    let pol = QuotaPolicy { requests_per_minute: Some(3), tokens_per_day: Some(1000), ..p() };
    s.check_rate("t", None, &pol).await.unwrap();
    s.check_rate("t", None, &pol).await.unwrap();
    let shared = s.reserve("t", &pol, amt(400, 0.0)).await.unwrap();
    assert!(!shared.local);
    assert_eq!(store.status().state, "ok");

    // Outage: calls are served locally, each bounded by the timeout, then without any wait.
    proxy.cut();
    let started = Instant::now();
    s.check_rate("t", None, &pol).await.unwrap(); // the local limiter starts from zero
    let first = started.elapsed();
    assert!(first < Duration::from_millis(250), "first call after the cut took {first:?}");
    assert_eq!(store.status().state, "degraded");
    let started = Instant::now();
    s.check_rate("t", None, &pol).await.unwrap();
    s.check_rate("t", None, &pol).await.unwrap();
    assert_eq!(exceeded(s.check_rate("t", None, &pol).await).0, LimitScope::Requests, "still limited locally");
    let local = s.reserve("t", &pol, amt(900, 0.0)).await.unwrap();
    assert!(local.local);
    assert!(started.elapsed() < Duration::from_millis(20), "circuit open: {:?}", started.elapsed());
    // A shared reservation cannot be settled now: it stays charged (conservative).
    s.settle(&shared, amt(0, 0.0)).await;
    s.settle(&local, amt(100, 0.0)).await;
    assert_eq!(store.local().day_usage("t").0, 100);
    assert!(store.status().settlements_lost >= 1);

    // Recovery: after the retry window one probe reaches Valkey and shared limits resume,
    // with the state from before the outage (2 requests, 400 tokens).
    proxy.restore().await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let mut recovered = false;
    for _ in 0..50 {
        let _ = s.check_rate("probe", None, &p()).await;
        let _ = s.reserve("probe", &QuotaPolicy { tokens_per_day: Some(1), ..p() }, amt(0, 0.0)).await;
        if store.status().state == "ok" {
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(recovered, "{:?}", store.status());
    s.check_rate("t", None, &pol).await.unwrap();
    assert_eq!(
        exceeded(s.check_rate("t", None, &pol).await).0,
        LimitScope::Requests,
        "shared count survived the outage"
    );
    assert_eq!(
        exceeded(s.reserve("t", &pol, amt(601, 0.0)).await).0,
        LimitScope::TokensPerDay,
        "400 still reserved in Valkey"
    );
}

/// Added latency per request (check_rate + reserve + settle). Prints a table; run with
/// `--nocapture`. Asserts only a loose ceiling (p50 under 50 ms, no fallback within a 500 ms
/// bound) so it does not flake on busy machines.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valkey_added_latency() {
    let Some(url) = valkey_url() else { return };
    // Generous bound so a loaded machine measures slow calls instead of falling back (the 30 ms
    // production bound is exercised by the outage test).
    let o = opts(&url, &prefix());
    let fallback = FallbackQuota::new(ValkeyQuota::new(&o).unwrap());
    // As at router start-up: connect (and TLS handshake) outside the 30 ms per-call bound.
    assert!(fallback.probe(Duration::from_secs(2)).await);
    let valkey: Arc<dyn QuotaStore> = Arc::new(fallback);
    let memory: Arc<dyn QuotaStore> = Arc::new(InMemoryQuota::new());
    let pol = QuotaPolicy {
        requests_per_minute: Some(1_000_000),
        key_requests_per_minute: Some(1_000_000),
        tokens_per_minute: Some(u64::MAX / 4),
        tokens_per_day: Some(u64::MAX / 4),
        usd_per_day: Some(1e12),
    };
    let one = |s: Arc<dyn QuotaStore>, pol: QuotaPolicy, i: usize| async move {
        let t = format!("tenant{}", i % 16);
        let started = Instant::now();
        s.check_rate(&t, Some("key"), &pol).await.unwrap();
        let r = s.reserve(&t, &pol, amt(1500, 0.01)).await.unwrap();
        s.settle(&r, amt(700, 0.004)).await;
        started.elapsed()
    };
    let pct = |mut v: Vec<Duration>| {
        v.sort();
        let at = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)].as_secs_f64() * 1e3;
        (at(0.5), at(0.99), at(0.999))
    };
    // Warm up (connect, load scripts).
    for i in 0..200 {
        one(Arc::clone(&valkey), pol.clone(), i).await;
    }
    let mut out = String::from(
        "\nquota latency per request (check_rate + reserve + settle), ms\nstore   concurrency      p50      p99    p99.9\n",
    );
    let mut p50_seq = 0.0;
    for (name, s) in [("memory", &memory), ("valkey", &valkey)] {
        for conc in [1usize, 32] {
            let mut samples = Vec::new();
            for round in 0..(4000 / conc) {
                let mut set = tokio::task::JoinSet::new();
                for j in 0..conc {
                    set.spawn(one(Arc::clone(s), pol.clone(), round * conc + j));
                }
                samples.extend(set.join_all().await);
            }
            let (p50, p99, p999) = pct(samples);
            if name == "valkey" && conc == 1 {
                p50_seq = p50;
            }
            out.push_str(&format!("{name:<7} {conc:>11} {p50:>8.3} {p99:>8.3} {p999:>8.3}\n"));
        }
    }
    // Network floor: three bare PINGs (the same three round trips, no script work).
    let conn = raw(&url).await;
    let mut floor = Vec::new();
    for _ in 0..4000 {
        let mut c = conn.clone();
        let started = Instant::now();
        for _ in 0..3 {
            let _: String = redis::cmd("PING").query_async(&mut c).await.unwrap();
        }
        floor.push(started.elapsed());
    }
    let (p50, p99, p999) = pct(floor);
    out.push_str(&format!("{:<7} {:>11} {p50:>8.3} {p99:>8.3} {p999:>8.3}\n", "3xPING", 1));
    eprintln!("{out}");
    let status = valkey.status();
    assert_eq!(status.local_fallbacks, 0, "latency run must not fall back: {status:?}");
    assert!(p50_seq < 50.0, "p50 {p50_seq} ms");
}
