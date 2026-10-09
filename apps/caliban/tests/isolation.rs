//! Tenant-isolation audit, black box: the real `caliban standalone` binary in front of the mock
//! upstream (`caliban-bench`), two tenants (`alpha`, `beta`) and a shared on-prem pool.
//!
//! Each test states the property it proves. `cargo test -p caliban --test isolation`.

use caliban_bench::harness::{ADMIN_TOKEN, Caliban, Launch, Reply, new_key};
use caliban_bench::mock::{Mock, MockConfig};
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

const ALPHA_OPENAI: &str = "sk-alpha-openai-1111";
const BETA_OPENAI: &str = "sk-beta-openai-2222";
const ALPHA_PRIVATE: &str = "sk-alpha-private-3333";
const BETA_PRIVATE: &str = "sk-beta-private-4444";
const ALPHA_ANTHROPIC: &str = "sk-ant-alpha-5555";
const BETA_ANTHROPIC: &str = "sk-ant-beta-6666";

fn bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_caliban"))
}

struct Env {
    mock: Mock,
    gw: Caliban,
    a: String,
    b: String,
}

fn tenant(id: &str, hash: &str, base: &str, openai: &str, private: &str, anth: &str) -> String {
    format!(
        r#"
[[tenants]]
id = "{id}"
name = "{id}"
pii_mode = "reversible"
api_key_hashes = ["{hash}"]
  [[tenants.providers]]
  id = "openai"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  api_key = {{ env = "{openai}" }}
  [[tenants.providers]]
  id = "{id}-only"
  kind = "openai_compatible"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  api_key = {{ env = "{private}" }}
  [[tenants.providers]]
  id = "anthropic"
  kind = "anthropic"
  base_url = "{base}"
  trust_tier = "t2_contracted"
  api_key = {{ env = "{anth}" }}
  [[tenants.routes]]
  intent = "default"
  models = ["{id}/private"]
  [[tenants.routes]]
  intent = "chat"
  models = ["{id}/private"]
"#
    )
}

fn config(base: &str, a_hash: &str, b_hash: &str) -> String {
    format!(
        r#"
[cache]
exact_enabled = true

# Shared on-prem pool (all tenants), with per-tenant cache_salt.
[[providers]]
id = "pool"
kind = "openai_compatible"
base_url = "{base}"
trust_tier = "t0_sovereign"
cache_salt = true

# Shared pool restricted to alpha.
[[providers]]
id = "gpu-alpha"
kind = "openai_compatible"
base_url = "{base}"
trust_tier = "t0_sovereign"
tenants = ["alpha"]

[[models]]
id = "local/pool"
provider = "pool"
upstream_model = "pool-model"
trust_tier = "t0_sovereign"

[[models]]
id = "local/gpu-alpha"
provider = "gpu-alpha"
upstream_model = "gpu-alpha-model"
trust_tier = "t0_sovereign"

[[models]]
id = "local/embed"
provider = "pool"
upstream_model = "embed-model"
kind = "embedding"
trust_tier = "t0_sovereign"

# One catalogue model, provider id "openai": each tenant reaches it with its own BYOK key.
[[models]]
id = "byok/gpt"
provider = "openai"
upstream_model = "gpt-byok"
trust_tier = "t2_contracted"
price_in_per_mtok = 1.0
price_out_per_mtok = 2.0

[[models]]
id = "byok/claude"
provider = "anthropic"
upstream_model = "claude-byok"
trust_tier = "t2_contracted"

[[models]]
id = "alpha/private"
provider = "alpha-only"
upstream_model = "alpha-private-model"
trust_tier = "t2_contracted"

[[models]]
id = "beta/private"
provider = "beta-only"
upstream_model = "beta-private-model"
trust_tier = "t2_contracted"
{}
{}
"#,
        tenant("alpha", a_hash, base, "ALPHA_OPENAI", "ALPHA_PRIVATE", "ALPHA_ANTHROPIC"),
        tenant("beta", b_hash, base, "BETA_OPENAI", "BETA_PRIVATE", "BETA_ANTHROPIC"),
    )
}

fn env_vars() -> Vec<(String, String)> {
    [
        ("ALPHA_OPENAI", ALPHA_OPENAI),
        ("BETA_OPENAI", BETA_OPENAI),
        ("ALPHA_PRIVATE", ALPHA_PRIVATE),
        ("BETA_PRIVATE", BETA_PRIVATE),
        ("ALPHA_ANTHROPIC", ALPHA_ANTHROPIC),
        ("BETA_ANTHROPIC", BETA_ANTHROPIC),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect()
}

async fn setup_with(usage_wal: bool, kek: Option<String>) -> Env {
    let mock = Mock::start("127.0.0.1:0", MockConfig::default()).await.unwrap();
    let (a, a_hash) = new_key("alpha");
    let (b, b_hash) = new_key("beta");
    let launch = Launch { config: config(&mock.base_url(), &a_hash, &b_hash), env: env_vars(), usage_wal, kek, ..Default::default() };
    let gw = Caliban::start(bin(), &launch).await.unwrap();
    Env { mock, gw, a, b }
}

async fn setup() -> Env {
    setup_with(false, None).await
}

fn chat(model: &str, text: &str) -> Value {
    json!({"model": model, "messages": [{"role": "user", "content": text}]})
}

fn ok(r: &Reply) {
    assert!(r.status.is_success(), "{} {}", r.status, r.text);
}

fn model_ids(r: &Reply) -> Vec<String> {
    r.json()["data"].as_array().unwrap().iter().map(|m| m["id"].as_str().unwrap().to_owned()).collect()
}

/// Routes and models: a tenant sees and reaches only the models its own providers (or shared
/// pools open to it) serve; `caliban/auto` follows the caller's own route table; pinning another
/// tenant's model is rejected before anything is sent upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_and_models_are_tenant_scoped() {
    let e = setup().await;
    let a_models = model_ids(&e.gw.dp_get("/v1/models", &e.a).await);
    let b_models = model_ids(&e.gw.dp_get("/v1/models", &e.b).await);
    assert!(a_models.contains(&"alpha/private".into()) && a_models.contains(&"local/gpu-alpha".into()), "{a_models:?}");
    assert!(!a_models.contains(&"beta/private".into()), "alpha lists beta's model: {a_models:?}");
    assert!(b_models.contains(&"beta/private".into()), "{b_models:?}");
    assert!(!b_models.contains(&"alpha/private".into()) && !b_models.contains(&"local/gpu-alpha".into()), "beta lists alpha's models: {b_models:?}");

    // Pinning the other tenant's models (BYOK-only and restricted shared pool): 400, no upstream call.
    let before = e.mock.len();
    for (key, model) in [(&e.a, "beta/private"), (&e.b, "alpha/private"), (&e.b, "local/gpu-alpha")] {
        let r = e.gw.chat(key, &chat(model, "hello")).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{model}: {}", r.text);
        let r = e.gw.messages(key, &json!({"model": model, "max_tokens": 16, "messages": [{"role": "user", "content": "hello"}]})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{model} (messages): {}", r.text);
        assert_eq!(r.json()["type"], "error");
    }
    assert_eq!(e.mock.len(), before, "a rejected cross-tenant request reached the upstream");

    // caliban/auto: each tenant's own route, with its own credential, for every intent.
    for text in ["hello there", "please write a long and detailed explanation of how our quarterly planning process works for the team"] {
        for (key, upstream, cred) in [(&e.a, "alpha-private-model", ALPHA_PRIVATE), (&e.b, "beta-private-model", BETA_PRIVATE)] {
            ok(&e.gw.chat(key, &chat("caliban/auto", text)).await);
            let last = e.mock.last().unwrap();
            assert_eq!(last.body["model"], upstream);
            assert_eq!(last.credential(), Some(cred));
        }
    }
    // A shared pool restricted to alpha works for alpha.
    ok(&e.gw.chat(&e.a, &chat("local/gpu-alpha", "hello")).await);
}

/// BYOK credentials: the same catalogue model (provider id `openai` / `anthropic`) is reached
/// with the caller's own key, for JSON, streams, the translated and the native Anthropic paths,
/// including under interleaved concurrent load.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn byok_credentials_never_cross_tenants() {
    let e = setup().await;
    for (key, openai, anth) in [(&e.a, ALPHA_OPENAI, ALPHA_ANTHROPIC), (&e.b, BETA_OPENAI, BETA_ANTHROPIC)] {
        ok(&e.gw.chat(key, &chat("byok/gpt", "hi")).await);
        assert_eq!(e.mock.last().unwrap().credential(), Some(openai));
        let mut s = chat("byok/gpt", "hi");
        s["stream"] = json!(true);
        ok(&e.gw.chat(key, &s).await);
        assert_eq!(e.mock.last().unwrap().credential(), Some(openai));
        ok(&e.gw.chat(key, &chat("byok/claude", "hi")).await);
        let last = e.mock.last().unwrap();
        assert_eq!((last.path.as_str(), last.x_api_key.as_deref(), last.auth.as_deref()), ("/v1/messages", Some(anth), None));
        let r = e.gw.messages(key, &json!({"model": "byok/claude", "max_tokens": 16, "stream": true, "messages": [{"role": "user", "content": "hi"}]})).await;
        ok(&r);
        assert_eq!(e.mock.last().unwrap().x_api_key.as_deref(), Some(anth));
    }

    // Interleaved concurrent load: every upstream request carries the credential of the tenant
    // whose prompt it carries.
    e.mock.clear_log();
    let mut tasks = Vec::new();
    for i in 0..60 {
        let (gw_key, tag) = if i % 2 == 0 { (e.a.clone(), "alpha") } else { (e.b.clone(), "beta") };
        let dp = e.gw.dp.clone();
        tasks.push(tokio::spawn(async move {
            let model = if i % 3 == 0 { "byok/claude" } else { "byok/gpt" };
            let body = json!({"model": model, "stream": i % 4 == 0, "messages": [{"role": "user", "content": format!("marker {tag} {i}")}]});
            let r = reqwest::Client::new().post(format!("{dp}/v1/chat/completions")).bearer_auth(gw_key).json(&body).send().await.unwrap();
            assert!(r.status().is_success());
            r.text().await.unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let log = e.mock.log();
    assert_eq!(log.len(), 60);
    for entry in log {
        let text = entry.last_user_text();
        let expected = if text.contains("alpha") {
            [ALPHA_OPENAI, ALPHA_ANTHROPIC]
        } else {
            [BETA_OPENAI, BETA_ANTHROPIC]
        };
        assert!(expected.contains(&entry.credential().unwrap()), "{text:?} sent with {:?}", entry.credential());
    }
}

/// Exact cache: an entry seeded by alpha is a miss for beta on an identical request to the same
/// shared model (and the same BYOK-routed catalogue model); beta's request goes upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_cache_entries_are_tenant_scoped() {
    let e = setup().await;
    for model in ["local/pool", "byok/gpt"] {
        let body = json!({"model": model, "temperature": 0, "messages": [{"role": "user", "content": "what is two plus two"}]});
        let n = e.mock.len();
        let r1 = e.gw.chat(&e.a, &body).await;
        let r2 = e.gw.chat(&e.a, &body).await;
        assert_eq!((r1.header("x-caliban-cache").as_deref(), r2.header("x-caliban-cache").as_deref()), (Some("miss"), Some("hit")), "{model}");
        assert_eq!(e.mock.len(), n + 1, "{model}: alpha's repeat must be served from cache");
        let rb = e.gw.chat(&e.b, &body).await;
        assert_eq!(rb.header("x-caliban-cache").as_deref(), Some("miss"), "{model}: beta hit alpha's cache entry");
        assert_eq!(e.mock.len(), n + 2, "{model}: beta's request must go upstream");
        assert_eq!(e.gw.chat(&e.b, &body).await.header("x-caliban-cache").as_deref(), Some("hit"), "{model}: beta's own entry");
        // Anthropic-dialect clients share the canonical cache only within the tenant.
        let m = json!({"model": model, "max_tokens": 64, "temperature": 0, "messages": [{"role": "user", "content": "anthropic dialect probe"}]});
        assert_eq!(e.gw.messages(&e.a, &m).await.header("x-caliban-cache").as_deref(), Some("miss"));
        assert_eq!(e.gw.messages(&e.a, &m).await.header("x-caliban-cache").as_deref(), Some("hit"));
        assert_eq!(e.gw.messages(&e.b, &m).await.header("x-caliban-cache").as_deref(), Some("miss"), "{model}: beta hit alpha's entry (messages)");
    }
}

/// Provider-side prompt cache: requests to the shared, salted pool carry a per-tenant
/// `cache_salt` (stable per tenant, different across tenants, not the tenant id). The mock
/// emulates a vLLM prefix cache keyed by salt: alpha's repeat reports cached tokens, beta's
/// identical first request reports none (no cross-tenant `cached_tokens` signal). Salts are
/// derived from CALIBAN_KEK, so they are stable across restarts and differ between deployments.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_salt_differs_per_tenant() {
    let e = setup().await;
    let body = chat("local/pool", "a shared system prompt and question about the weather");
    let cached = |r: &Reply| r.json()["usage"]["prompt_tokens_details"]["cached_tokens"].as_u64().unwrap_or(0);
    let r = e.gw.chat(&e.a, &body).await;
    let salt_a1 = e.mock.last().unwrap().body["cache_salt"].as_str().unwrap().to_owned();
    assert_eq!(cached(&r), 0);
    let r = e.gw.chat(&e.a, &body).await;
    let salt_a2 = e.mock.last().unwrap().body["cache_salt"].as_str().unwrap().to_owned();
    assert!(cached(&r) > 0, "alpha's repeat should hit its own prefix cache: {}", r.text);
    let r = e.gw.chat(&e.b, &body).await;
    let salt_b = e.mock.last().unwrap().body["cache_salt"].as_str().unwrap().to_owned();
    assert_eq!(cached(&r), 0, "beta observed cached tokens from alpha's prefix: {}", r.text);
    assert_eq!(salt_a1, salt_a2, "salt must be stable per tenant");
    assert_ne!(salt_a1, salt_b, "salt must differ across tenants");
    for s in [&salt_a1, &salt_b] {
        assert!(s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()), "{s}");
        assert!(!s.contains("alpha") && !s.contains("beta"));
    }
    // Streams carry it too.
    let mut st = body.clone();
    st["stream"] = json!(true);
    ok(&e.gw.chat(&e.b, &st).await);
    assert_eq!(e.mock.last().unwrap().body["cache_salt"], salt_b.as_str());

    // Same KEK after a restart: same salts. Another deployment's KEK: different salts.
    let same = setup_with(false, Some(e.gw.kek.clone())).await;
    ok(&same.gw.chat(&same.a, &body).await);
    assert_eq!(same.mock.last().unwrap().body["cache_salt"], salt_a1.as_str());
    let other = setup().await;
    ok(&other.gw.chat(&other.a, &body).await);
    assert_ne!(other.mock.last().unwrap().body["cache_salt"], salt_a1.as_str());
}

/// Usage and metering: every usage event (WAL and `/api/v1/usage`) belongs to the tenant that
/// made the request, including cache hits, streams and the Anthropic dialect, under concurrency.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_is_attributed_to_the_calling_tenant() {
    let e = setup_with(true, None).await;
    let mut who: HashMap<String, &str> = HashMap::new();
    // Seed the temperature-0 entry for both tenants and both dialects, so repeats below hit.
    let cached = json!({"model": "local/pool", "temperature": 0, "max_tokens": 32, "messages": [{"role": "user", "content": "cached question"}]});
    for (key, tag) in [(&e.a, "alpha"), (&e.b, "beta")] {
        for r in [e.gw.chat(key, &cached).await, e.gw.messages(key, &cached).await] {
            ok(&r);
            who.insert(r.request_id(), tag);
        }
    }
    let mut tasks = Vec::new();
    for i in 0..48 {
        let (key, tag) = if i % 3 == 0 { (e.b.clone(), "beta") } else { (e.a.clone(), "alpha") };
        let dp = e.gw.dp.clone();
        tasks.push(tokio::spawn(async move {
            let http = reqwest::Client::new();
            let model = ["byok/gpt", "local/pool", "byok/claude"][i % 3];
            let stream = i % 4 == 1;
            // Every 5th request repeats a temperature-0 prompt (cache hits for both tenants).
            let body = if i % 5 == 0 {
                json!({"model": "local/pool", "temperature": 0, "max_tokens": 32, "messages": [{"role": "user", "content": "cached question"}]})
            } else {
                json!({"model": model, "stream": stream, "max_tokens": 32, "messages": [{"role": "user", "content": format!("{tag} request {i}")}]})
            };
            let req = if i % 7 == 0 {
                http.post(format!("{dp}/v1/messages")).header("x-api-key", &key).header("anthropic-version", "2023-06-01")
            } else {
                http.post(format!("{dp}/v1/chat/completions")).bearer_auth(&key)
            };
            let r = req.json(&body).send().await.unwrap();
            assert!(r.status().is_success(), "{}", r.status());
            let id = r.headers()["x-caliban-request-id"].to_str().unwrap().to_owned();
            r.text().await.unwrap();
            (id, tag)
        }));
    }
    for t in tasks {
        let (id, tag) = t.await.unwrap();
        who.insert(id, tag);
    }
    // Stream events are written when the stream task finishes.
    let mut events = Vec::new();
    for _ in 0..100 {
        events = e.gw.wal_events();
        if events.len() >= who.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(events.len(), who.len(), "one usage event per request");
    let mut hits = HashMap::new();
    for ev in &events {
        let id = ev["request_id"].as_str().unwrap();
        let tenant = ev["tenant_id"].as_str().unwrap();
        assert_eq!(Some(&tenant), who.get(id), "event {id} attributed to {tenant}");
        if ev["cache"] == "hit" {
            *hits.entry(tenant.to_owned()).or_insert(0) += 1;
        }
    }
    assert!(hits.get("alpha").is_some_and(|n| *n > 0) && hits.get("beta").is_some_and(|n| *n > 0), "cache hits: {hits:?}");

    for tenant in ["alpha", "beta"] {
        let (s, u) = e.gw.admin("GET", &format!("/usage?tenant_id={tenant}&limit=1000"), None).await;
        assert_eq!(s, StatusCode::OK);
        let evs = u["events"].as_array().unwrap();
        assert!(evs.iter().all(|ev| ev["tenant_id"] == tenant), "{tenant}: foreign events in /usage");
        assert_eq!(evs.len(), who.values().filter(|t| **t == tenant).count(), "{tenant}: /usage count");
        assert_eq!(u["totals"]["requests"].as_u64().unwrap() as usize, evs.len());
    }
}

fn find_email(text: &str) -> Option<String> {
    text.split(|c: char| c.is_whitespace() || c == '"' || c == ',').find(|w| w.contains('@')).map(|w| w.trim_end_matches('.').to_owned())
}

/// PII: the same value gets different surrogates for different tenants; a surrogate issued for
/// alpha, sent by beta, is never rehydrated to alpha's original in beta's response; and under
/// interleaved concurrent load (JSON and streams) every response carries only its own
/// originals, while the upstream never sees any.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pii_surrogates_never_cross_tenants() {
    let e = setup().await;
    const ORIGINAL: &str = "jane.doe@acme.com";
    let prompt = format!("Please contact {ORIGINAL} today");
    let ra = e.gw.chat(&e.a, &chat("byok/gpt", &prompt)).await;
    let seen_a = e.mock.last().unwrap().last_user_text();
    let s_a = find_email(&seen_a).unwrap();
    assert_ne!(s_a, ORIGINAL, "external model saw the original");
    assert!(ra.content().contains(ORIGINAL), "alpha's response is rehydrated: {}", ra.text);

    ok(&e.gw.chat(&e.b, &chat("byok/gpt", &prompt)).await);
    let s_b = find_email(&e.mock.last().unwrap().last_user_text()).unwrap();
    assert_ne!(s_a, s_b, "alpha and beta got the same surrogate for the same value");

    // Beta sends alpha's surrogate: never rehydrated to alpha's original.
    for stream in [false, true] {
        let mut body = chat("byok/gpt", &format!("What do you know about {s_a}?"));
        body["stream"] = json!(stream);
        let r = e.gw.chat(&e.b, &body).await;
        ok(&r);
        let text = if stream { r.stream_text() } else { r.content() };
        assert!(!text.contains(ORIGINAL), "beta's response leaked alpha's original: {text}");
        assert!(text.contains(&s_a), "beta gets back exactly what it sent: {text}");
    }

    // Interleaved load.
    e.mock.clear_log();
    let mut tasks = Vec::new();
    for i in 0..40 {
        let (key, tag) = if i % 2 == 0 { (e.a.clone(), "alpha") } else { (e.b.clone(), "beta") };
        let dp = e.gw.dp.clone();
        tasks.push(tokio::spawn(async move {
            let email = format!("{tag}.user{i}@{tag}-corp.example");
            let card = if tag == "alpha" { "4111 1111 1111 1111" } else { "5555 5555 5555 4444" };
            let stream = i % 4 < 2;
            let body = json!({"model": "byok/gpt", "stream": stream, "messages": [{"role": "user", "content": format!("Email {email} about card {card}")}]});
            let r = reqwest::Client::new().post(format!("{dp}/v1/chat/completions")).bearer_auth(&key).json(&body).send().await.unwrap();
            assert!(r.status().is_success());
            let text = r.text().await.unwrap();
            (tag, email, card, text, stream)
        }));
    }
    let mut results = Vec::new();
    for t in tasks {
        results.push(t.await.unwrap());
    }
    let all_emails: Vec<String> = results.iter().map(|r| r.1.clone()).collect();
    for (tag, email, card, raw, stream) in &results {
        let reply = Reply { status: StatusCode::OK, headers: Default::default(), text: raw.clone() };
        let text = if *stream { reply.stream_text() } else { reply.content() };
        assert!(text.contains(email.as_str()) && text.contains(card), "{tag}: own originals restored: {text}");
        for other in all_emails.iter().filter(|o| *o != email) {
            assert!(!text.contains(other.as_str()), "{tag}: response contains another request's original {other}");
        }
        let other_card = if *tag == "alpha" { "5555 5555 5555 4444" } else { "4111 1111 1111 1111" };
        assert!(!text.contains(other_card), "{tag}: other tenant's card in response");
    }
    for entry in e.mock.log() {
        let t = entry.last_user_text();
        assert!(!all_emails.iter().any(|m| t.contains(m.as_str())) && !t.contains("4111 1111 1111 1111"), "upstream saw an original: {t}");
    }
}

/// Revocation: a revoked key and every key of a deleted tenant get 401 on every data-plane
/// endpoint, while other keys keep working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_and_deleted_tenant_keys_get_401() {
    let e = setup().await;
    let (s, _) = e.gw.admin("POST", "/tenants", Some(json!({"name": "Gamma"}))).await;
    assert_eq!(s, StatusCode::CREATED);
    let mut keys = Vec::new();
    for n in ["k1", "k2"] {
        let (s, k) = e.gw.admin("POST", "/tenants/gamma/api-keys", Some(json!({"name": n}))).await;
        assert_eq!(s, StatusCode::CREATED);
        keys.push((k["key"].as_str().unwrap().to_owned(), k["id"].as_str().unwrap().to_owned()));
    }
    let byok = json!({"kind": "openai_compatible", "label": "gamma-llm", "base_url": e.mock.base_url(), "api_key": "sk-gamma-7777", "trust_tier": "t2_contracted"});
    assert_eq!(e.gw.admin("POST", "/tenants/gamma/provider-keys", Some(byok)).await.0, StatusCode::CREATED);

    let probes = |gw: &Caliban, key: String| {
        let dp = gw.dp.clone();
        async move {
            let http = reqwest::Client::new();
            let mut codes = Vec::new();
            let chat = json!({"model": "caliban/auto", "messages": [{"role": "user", "content": "hello there"}]});
            let msg = json!({"model": "caliban/auto", "max_tokens": 16, "messages": [{"role": "user", "content": "hello there"}]});
            codes.push(http.post(format!("{dp}/v1/chat/completions")).bearer_auth(&key).json(&chat).send().await.unwrap().status());
            codes.push(http.post(format!("{dp}/v1/messages")).header("x-api-key", &key).json(&msg).send().await.unwrap().status());
            codes.push(http.post(format!("{dp}/v1/messages/count_tokens")).header("x-api-key", &key).json(&msg).send().await.unwrap().status());
            codes.push(http.get(format!("{dp}/v1/models")).bearer_auth(&key).send().await.unwrap().status());
            codes.push(http.post(format!("{dp}/v1/embeddings")).bearer_auth(&key).json(&json!({"model": "local/embed", "input": "x"})).send().await.unwrap().status());
            codes
        }
    };
    let before = probes(&e.gw, keys[0].0.clone()).await;
    assert!(before.iter().all(|c| c.is_success()), "gamma's key works before revocation: {before:?}");

    assert_eq!(e.gw.admin("DELETE", &format!("/tenants/gamma/api-keys/{}", keys[0].1), None).await.0, StatusCode::NO_CONTENT);
    let revoked = probes(&e.gw, keys[0].0.clone()).await;
    assert!(revoked.iter().all(|c| *c == StatusCode::UNAUTHORIZED), "revoked key: {revoked:?}");
    assert!(probes(&e.gw, keys[1].0.clone()).await.iter().all(|c| c.is_success()), "the tenant's other key still works");

    assert_eq!(e.gw.admin("DELETE", "/tenants/gamma", None).await.0, StatusCode::NO_CONTENT);
    let deleted = probes(&e.gw, keys[1].0.clone()).await;
    assert!(deleted.iter().all(|c| *c == StatusCode::UNAUTHORIZED), "deleted tenant's key: {deleted:?}");
    // Other tenants are unaffected.
    ok(&e.gw.chat(&e.a, &chat("caliban/auto", "hello there")).await);
}

/// Admin API: tenant keys (bearer or `x-api-key`) are rejected on every control-plane route, the
/// data plane does not serve the admin API, and the admin token is not a tenant key. A request
/// body cannot name another tenant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_endpoints_reject_tenant_keys() {
    let e = setup().await;
    let (s, ds) = e.gw.admin("POST", "/datasources", Some(json!({"tenant_id": "beta", "kind": "mongodb", "name": "crm", "connection": {"uri": "mongodb://u:p@h"}}))).await;
    assert_eq!(s, StatusCode::CREATED);
    let ds_id = ds["id"].as_str().unwrap().to_owned();
    let routes: Vec<(&str, String, Option<Value>)> = vec![
        ("GET", "/tenants".into(), None),
        ("POST", "/tenants".into(), Some(json!({"name": "evil"}))),
        ("GET", "/tenants/beta".into(), None),
        ("DELETE", "/tenants/beta".into(), None),
        ("GET", "/tenants/beta/api-keys".into(), None),
        ("POST", "/tenants/beta/api-keys".into(), Some(json!({"name": "x"}))),
        ("GET", "/tenants/beta/provider-keys".into(), None),
        ("POST", "/tenants/alpha/provider-keys".into(), Some(json!({"kind": "openai_compatible", "label": "x", "base_url": "http://x", "trust_tier": "t2_contracted"}))),
        ("GET", "/tenants/beta/routes".into(), None),
        ("PUT", "/tenants/alpha/routes".into(), Some(json!({"routes": []}))),
        ("GET", "/models".into(), None),
        ("POST", "/models".into(), Some(json!({}))),
        ("GET", "/providers".into(), None),
        ("GET", "/datasources?tenant_id=beta".into(), None),
        ("POST", format!("/datasources/{ds_id}/introspect"), None),
        ("DELETE", format!("/tenants/beta/datasources/{ds_id}"), None),
        ("GET", "/ontology".into(), None),
        ("GET", "/nodes".into(), None),
        ("GET", "/usage".into(), None),
        ("GET", "/usage?tenant_id=beta".into(), None),
        ("GET", "/audit".into(), None),
    ];
    let http = reqwest::Client::new();
    for (method, path, body) in &routes {
        for key in [&e.a, &e.b] {
            let (s, _) = e.gw.cp_call(method, path, Some(key), body.clone()).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{method} {path} with a tenant bearer key");
            let mut req = http.request(method.parse().unwrap(), format!("{}/api/v1{path}", e.gw.cp)).header("x-api-key", key.as_str());
            if let Some(b) = body {
                req = req.json(b);
            }
            assert_eq!(req.send().await.unwrap().status(), StatusCode::UNAUTHORIZED, "{method} {path} with x-api-key");
        }
        assert_eq!(e.gw.cp_call(method, path, None, body.clone()).await.0, StatusCode::UNAUTHORIZED, "{method} {path} without auth");
    }
    // The datasource survived every attempt.
    let (_, list) = e.gw.admin("GET", "/datasources?tenant_id=beta", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    // The snapshot endpoint (router token only) never hands a tenant the config.
    let (s, _) = e.gw.cp_call("GET", "/snapshot", Some(&e.a), None).await;
    assert_ne!(s, StatusCode::OK);
    // The data plane does not serve the admin API; the admin token is not a tenant key.
    let r = http.get(format!("{}/api/v1/tenants", e.gw.dp)).bearer_auth(ADMIN_TOKEN).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(e.gw.dp_get("/v1/models", ADMIN_TOKEN).await.status, StatusCode::UNAUTHORIZED);
    // A request cannot select another tenant through the `caliban` extension.
    let mut body = chat("caliban/auto", "hello there");
    body["caliban"] = json!({"tenant": "beta"});
    assert_eq!(e.gw.chat(&e.a, &body).await.status, StatusCode::BAD_REQUEST);
}

/// Datasources on the data plane: `caliban.datasources` is accepted but not consumed yet (no
/// grounding in P0), so naming another tenant's datasource changes nothing upstream. This test
/// pins today's behaviour; when grounding lands it must become a 403 (see bench/RESULTS.md).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datasource_ids_from_another_tenant_are_inert_today() {
    let e = setup().await;
    let (_, ds) = e.gw.admin("POST", "/datasources", Some(json!({"tenant_id": "beta", "kind": "postgres", "name": "erp", "connection": {}}))).await;
    let ds_id = ds["id"].as_str().unwrap();
    let mut body = chat("byok/gpt", "summarise the erp data");
    body["caliban"] = json!({"datasources": [ds_id]});
    let r = e.gw.chat(&e.a, &body).await;
    ok(&r);
    let up = e.mock.last().unwrap();
    assert_eq!(up.credential(), Some(ALPHA_OPENAI));
    assert!(up.body.get("caliban").is_none() && !up.body.to_string().contains(ds_id), "datasource reference forwarded upstream");
}
