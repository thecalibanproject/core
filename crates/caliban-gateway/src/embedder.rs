//! Provider-backed [`Embedder`]: the single path by which Caliban embeds text for its own
//! consumers (T2 semantic cache, embedding-kNN intent routing).
//!
//! - **Routes:** [`Embedder::embed`] uses the tenant's route to the model, the same as
//!   `/v1/embeddings` (the tenant's own provider first, then shared pools). [`Embedder::embed_shared`]
//!   only uses the deployment provider named by the model (a shared `[[providers]]` entry), never a
//!   tenant's BYOK key; routing uses it so exemplars and prompts live in one deployment-wide space.
//! - **Batching:** one `embed` call sends every text that is not cached in one upstream request,
//!   split into requests of at most `max_batch` inputs that run concurrently.
//! - **Timeout:** request-path calls are bounded (`[cache.semantic] embed_timeout_ms`, default
//!   2 s; callers add their own, shorter budget on top). Deployment text (exemplars, embedded in the
//!   background) gets [`BULK_TIMEOUT`].
//! - **LRU:** recent vectors are kept in-process (moka, TinyLFU), keyed by BLAKE3(scope, model,
//!   upstream model, endpoint, text), where the scope is the tenant (or the deployment, for
//!   exemplars). Keys never cross tenants. The key names the endpoint rather than the credentials
//!   (a vector depends on the model and the text, not on whose key asked), so when routing and T2
//!   embed the same text with the same model through the same endpoint in one request, the second
//!   call is an LRU hit and only one upstream call is made.
//!
//! Inputs are sent as given (see the [`Embedder`] contract): the semantic cache passes surrogate
//! text, routing masks PII before an external embedder. Internal embedding calls are not metered as
//! usage events.

use crate::pipeline::resolve;
use caliban_config::{ConfigHandle, ModelEntry, ModelKind, ProviderConfig};
use caliban_providers::Providers;
use caliban_types::{EmbedError, Embedder, ModelId, TenantId};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// Upper bound on inputs per upstream request (TEI's default `max_client_batch_size` is 32).
pub const DEFAULT_MAX_BATCH: usize = 32;
/// Vectors kept in the LRU.
pub const DEFAULT_LRU_ENTRIES: u64 = 20_000;
/// Timeout for deployment text (routing exemplars), embedded in the background at startup or after
/// a config change; a CPU embedding server can take seconds per batch.
pub const BULK_TIMEOUT: Duration = Duration::from_secs(60);

pub struct ProviderEmbedder {
    config: ConfigHandle,
    providers: Arc<Providers>,
    lru: moka::future::Cache<[u8; 32], Arc<Vec<f32>>>,
    timeout: Duration,
    max_batch: usize,
}

impl ProviderEmbedder {
    pub fn new(
        config: ConfigHandle,
        providers: Arc<Providers>,
        lru_entries: u64,
        timeout: Duration,
        max_batch: usize,
    ) -> Self {
        Self {
            config,
            providers,
            lru: moka::future::Cache::builder().max_capacity(lru_entries).build(),
            timeout,
            max_batch: max_batch.max(1),
        }
    }

    /// Embeds `texts` with `entry` through `provider`: LRU first, then batched upstream calls.
    async fn run(
        &self,
        scope: Option<&TenantId>,
        entry: &ModelEntry,
        provider: &ProviderConfig,
        texts: &[String],
        timeout: Duration,
    ) -> Result<Vec<Vec<f32>>, EmbedError> {
        if entry.kind != ModelKind::Embedding {
            return Err(EmbedError::Unavailable(format!("model '{}' is not an embedding model", entry.id)));
        }
        let keys: Vec<[u8; 32]> = texts.iter().map(|x| lru_key(scope, entry, provider, x)).collect();
        let mut out: Vec<Option<Arc<Vec<f32>>>> = Vec::with_capacity(texts.len());
        for k in &keys {
            out.push(self.lru.get(k).await);
        }
        let missing: Vec<usize> = (0..texts.len()).filter(|&i| out[i].is_none()).collect();
        if !missing.is_empty() {
            let adapter = self.providers.adapter(provider.kind).map_err(|e| EmbedError::Unavailable(e.to_string()))?;
            let calls = missing.chunks(self.max_batch).map(|chunk| {
                let body = json!({ "model": entry.upstream_model, "input": chunk.iter().map(|&i| &texts[i]).collect::<Vec<_>>() });
                async move {
                    let v = adapter.embeddings(provider, body).await.map_err(|e| EmbedError::Upstream(e.to_string()))?;
                    parse_vectors(&v, chunk.len())
                }
            });
            let batches = tokio::time::timeout(timeout, futures::future::try_join_all(calls))
                .await
                .map_err(|_| EmbedError::Timeout)??;
            for (chunk, vectors) in missing.chunks(self.max_batch).zip(batches) {
                for (&i, v) in chunk.iter().zip(vectors) {
                    let v = Arc::new(v);
                    self.lru.insert(keys[i], Arc::clone(&v)).await;
                    out[i] = Some(v);
                }
            }
        }
        let out: Vec<Vec<f32>> = out.into_iter().map(|v| v.map(|v| v.as_ref().clone()).unwrap_or_default()).collect();
        if out.iter().any(|v| v.len() != out[0].len()) {
            // A cached vector from before a model swap behind the same id.
            return Err(EmbedError::Invalid("mixed-dimension vectors".into()));
        }
        Ok(out)
    }
}

/// LRU key: the scope (tenant, or the deployment), the vector space (model, upstream model,
/// endpoint) and the text.
fn lru_key(scope: Option<&TenantId>, entry: &ModelEntry, provider: &ProviderConfig, text: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"caliban/embed/v2\0");
    match scope {
        Some(t) => {
            h.update(b"t");
            h.update(t.as_str().as_bytes());
        }
        None => {
            h.update(b"d");
        }
    }
    h.update(&[0]);
    for part in [entry.id.as_str(), entry.upstream_model.as_str(), provider.base_url.as_str()] {
        h.update(part.as_bytes());
        h.update(&[0]);
    }
    h.update(text.as_bytes());
    *h.finalize().as_bytes()
}

/// `data[].embedding` ordered by `data[].index`; exactly `n` vectors of one dimension.
fn parse_vectors(v: &Value, n: usize) -> Result<Vec<Vec<f32>>, EmbedError> {
    let data = v.get("data").and_then(Value::as_array).ok_or_else(|| EmbedError::Invalid("no data array".into()))?;
    if data.len() != n {
        return Err(EmbedError::Invalid(format!("expected {n} vectors, got {}", data.len())));
    }
    let mut out: Vec<Option<Vec<f32>>> = vec![None; n];
    for (pos, item) in data.iter().enumerate() {
        let idx = item.get("index").and_then(Value::as_u64).map_or(pos, |i| usize::try_from(i).unwrap_or(usize::MAX));
        #[allow(clippy::cast_possible_truncation)]
        let vec: Vec<f32> = item
            .get("embedding")
            .and_then(Value::as_array)
            .ok_or_else(|| EmbedError::Invalid("embedding is not a float array (encoding_format?)".into()))?
            .iter()
            .map(|x| x.as_f64().map(|f| f as f32))
            .collect::<Option<_>>()
            .ok_or_else(|| EmbedError::Invalid("non-numeric embedding".into()))?;
        let slot = out.get_mut(idx).ok_or_else(|| EmbedError::Invalid(format!("index {idx} out of range")))?;
        *slot = Some(vec);
    }
    let out: Vec<Vec<f32>> =
        out.into_iter().collect::<Option<_>>().ok_or_else(|| EmbedError::Invalid(format!("expected {n} vectors")))?;
    if out.iter().any(|v| v.is_empty() || v.len() != out[0].len()) {
        return Err(EmbedError::Invalid("empty or mixed-dimension vectors".into()));
    }
    Ok(out)
}

#[async_trait::async_trait]
impl Embedder for ProviderEmbedder {
    async fn embed(&self, tenant: &TenantId, model: &ModelId, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        if texts.is_empty() {
            return Ok(vec![]);
        }
        let snap = self.config.load();
        let t = snap.tenant(tenant).ok_or_else(|| EmbedError::Unavailable(format!("unknown tenant '{tenant}'")))?;
        let (entry, provider) = resolve(&snap, t, model)
            .ok_or_else(|| EmbedError::Unavailable(format!("model '{model}' is not available to tenant '{tenant}'")))?;
        self.run(Some(tenant), &entry, &provider, texts, self.timeout).await
    }

    async fn embed_shared(
        &self,
        tenant: Option<&TenantId>,
        model: &ModelId,
        texts: &[String],
    ) -> Result<Vec<Vec<f32>>, EmbedError> {
        if texts.is_empty() {
            return Ok(vec![]);
        }
        let snap = self.config.load();
        let entry = snap.model(model).ok_or_else(|| EmbedError::Unavailable(format!("unknown model '{model}'")))?;
        let shared =
            snap.config.providers.iter().find(|p| p.provider.id == entry.provider).ok_or_else(|| {
                EmbedError::Unavailable(format!("model '{model}' is not served by a shared provider"))
            })?;
        if let Some(t) = tenant {
            if snap.tenant(t).is_none() {
                return Err(EmbedError::Unavailable(format!("unknown tenant '{t}'")));
            }
            if !shared.allows(t) {
                return Err(EmbedError::Unavailable(format!(
                    "shared provider '{}' does not serve tenant '{t}'",
                    shared.provider.id
                )));
            }
        }
        let timeout = if tenant.is_some() { self.timeout } else { BULK_TIMEOUT.max(self.timeout) };
        self.run(tenant, entry, &shared.provider, texts, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Json, Router};
    use caliban_config::{Config, Snapshot};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Embedding server: vector = [len(text), index-in-batch, 1]; counts calls and inputs.
    async fn server(delay: Duration) -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let inputs = Arc::new(AtomicUsize::new(0));
        let (c, n) = (Arc::clone(&calls), Arc::clone(&inputs));
        let app = Router::new().route(
            "/v1/embeddings",
            post(move |Json(b): Json<Value>| {
                let (c, n) = (Arc::clone(&c), Arc::clone(&n));
                async move {
                    tokio::time::sleep(delay).await;
                    c.fetch_add(1, Ordering::SeqCst);
                    let input = b["input"].as_array().cloned().unwrap_or_default();
                    n.fetch_add(input.len(), Ordering::SeqCst);
                    // Reverse order on purpose: the index field decides.
                    let data: Vec<Value> = input
                        .iter()
                        .enumerate()
                        .rev()
                        .map(|(i, t)| json!({"object": "embedding", "index": i, "embedding": [t.as_str().unwrap().len() as f64, i as f64, 1.0]}))
                        .collect();
                    Json(json!({"object": "list", "data": data, "model": b["model"]}))
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}/v1"), calls, inputs)
    }

    fn handle(base: &str) -> ConfigHandle {
        let toml = format!(
            r#"
[[models]]
id = "local/embed"
provider = "tei"
upstream_model = "Qwen/Qwen3-Embedding-0.6B"
kind = "embedding"
trust_tier = "t0_sovereign"

[[models]]
id = "local/chat"
provider = "tei"
upstream_model = "chat"
trust_tier = "t0_sovereign"

[[providers]]
id = "tei"
kind = "openai_compatible"
base_url = "{base}"
trust_tier = "t0_sovereign"
tenants = ["acme"]

[[tenants]]
id = "acme"
name = "Acme"

[[tenants]]
id = "other"
name = "Other"
"#
        );
        ConfigHandle::new(Snapshot::new(Config::from_toml_str(&toml).unwrap(), "t"))
    }

    fn texts(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[tokio::test]
    async fn batches_caches_and_keeps_order() {
        let (base, calls, inputs) = server(Duration::ZERO).await;
        let e = ProviderEmbedder::new(handle(&base), Arc::default(), 100, Duration::from_secs(2), 2);
        let (acme, m): (TenantId, ModelId) = ("acme".into(), "local/embed".into());
        let out = e.embed(&acme, &m, &texts(&["a", "bb", "ccc"])).await.unwrap();
        assert_eq!(out.iter().map(|v| v[0]).collect::<Vec<_>>(), [1.0, 2.0, 3.0], "input order");
        assert_eq!(calls.load(Ordering::SeqCst), 2, "3 inputs, batches of 2");
        // Cached texts are not sent again; only the new one is.
        let out = e.embed(&acme, &m, &texts(&["bb", "dddd", "a"])).await.unwrap();
        assert_eq!(out.iter().map(|v| v[0]).collect::<Vec<_>>(), [2.0, 4.0, 1.0]);
        assert_eq!(inputs.load(Ordering::SeqCst), 4);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(e.embed(&acme, &m, &[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn unavailable_models_and_timeouts_fail_fast() {
        let (base, _, _) = server(Duration::from_millis(300)).await;
        let e = ProviderEmbedder::new(handle(&base), Arc::default(), 100, Duration::from_millis(50), 8);
        let m: ModelId = "local/embed".into();
        let t0 = std::time::Instant::now();
        assert_eq!(e.embed(&"acme".into(), &m, &texts(&["x"])).await, Err(EmbedError::Timeout));
        assert!(t0.elapsed() < Duration::from_millis(250));
        assert!(
            matches!(e.embed(&"other".into(), &m, &texts(&["x"])).await, Err(EmbedError::Unavailable(_))),
            "shared pool restricted to acme"
        );
        assert!(matches!(
            e.embed(&"acme".into(), &"local/chat".into(), &texts(&["x"])).await,
            Err(EmbedError::Unavailable(_))
        ));
        assert!(matches!(e.embed(&"nobody".into(), &m, &texts(&["x"])).await, Err(EmbedError::Unavailable(_))));
    }

    #[tokio::test]
    async fn shared_path_ignores_byok_and_shares_the_lru_with_the_tenant_path() {
        let (base, calls, inputs) = server(Duration::ZERO).await;
        // `own` has a BYOK provider with the shared provider's id, pointing nowhere.
        let toml = format!(
            r#"
[[models]]
id = "local/embed"
provider = "tei"
upstream_model = "Qwen/Qwen3-Embedding-0.6B"
kind = "embedding"
trust_tier = "t0_sovereign"

[[providers]]
id = "tei"
kind = "openai_compatible"
base_url = "{base}"
trust_tier = "t0_sovereign"
tenants = ["acme", "own"]

[[tenants]]
id = "acme"
name = "Acme"

[[tenants]]
id = "own"
name = "Own"
  [[tenants.providers]]
  id = "tei"
  kind = "openai_compatible"
  base_url = "http://127.0.0.1:9/v1"
  trust_tier = "t0_sovereign"

[[tenants]]
id = "other"
name = "Other"
"#
        );
        let h = ConfigHandle::new(Snapshot::new(Config::from_toml_str(&toml).unwrap(), "t"));
        let e = ProviderEmbedder::new(h, Arc::default(), 100, Duration::from_secs(2), 8);
        let m: ModelId = "local/embed".into();
        let (acme, own, other): (TenantId, TenantId, TenantId) = ("acme".into(), "own".into(), "other".into());

        // Routing's call for a tenant prompt, then T2's call for the same text: one upstream call.
        e.embed_shared(Some(&acme), &m, &texts(&["route me"])).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        e.embed(&acme, &m, &texts(&["route me"])).await.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "T2 reuses the routing vector (same tenant, model, endpoint, text)"
        );

        // The shared path never uses a tenant's own provider with the same id.
        assert!(e.embed(&own, &m, &texts(&["x"])).await.is_err(), "tenant path goes to the (dead) BYOK endpoint");
        assert_eq!(e.embed_shared(Some(&own), &m, &texts(&["x"])).await.unwrap().len(), 1);

        // Tenants the shared provider does not serve are refused; deployment text needs no tenant.
        assert!(matches!(e.embed_shared(Some(&other), &m, &texts(&["x"])).await, Err(EmbedError::Unavailable(_))));
        assert!(matches!(
            e.embed_shared(Some(&"nobody".into()), &m, &texts(&["x"])).await,
            Err(EmbedError::Unavailable(_))
        ));
        let before = inputs.load(Ordering::SeqCst);
        e.embed_shared(None, &m, &texts(&["route me"])).await.unwrap();
        assert_eq!(inputs.load(Ordering::SeqCst), before + 1, "deployment scope does not read tenant vectors");
    }

    /// Latency of single-prompt embeddings (LRU cold) against a real OpenAI-compatible embedding
    /// server, e.g. TEI: `CALIBAN_TEST_EMBED_URL=http://127.0.0.1:8080/v1`. Skipped when unset.
    #[tokio::test]
    async fn real_embedding_server_latency() {
        let Some(base) = std::env::var("CALIBAN_TEST_EMBED_URL").ok().filter(|u| !u.is_empty()) else {
            eprintln!("CALIBAN_TEST_EMBED_URL not set; skipping");
            return;
        };
        let e =
            ProviderEmbedder::new(handle(&base), Arc::default(), 10_000, Duration::from_secs(10), DEFAULT_MAX_BATCH);
        let (acme, m): (TenantId, ModelId) = ("acme".into(), "local/embed".into());
        let questions = [
            "What is our refund policy for enterprise customers",
            "How do I rotate the API key for the billing service",
            "Summarise last quarter's churn by region",
        ];
        for i in 0..5 {
            e.embed(&acme, &m, &texts(&[&format!("warm up {i}")])).await.unwrap();
        }
        let mut ms = Vec::new();
        let mut dim = 0;
        for i in 0..60 {
            let t = format!("{} (variant {i})", questions[i % questions.len()]);
            let t0 = std::time::Instant::now();
            let v = e.embed(&acme, &m, &[t]).await.unwrap();
            ms.push(t0.elapsed().as_secs_f64() * 1000.0);
            dim = v[0].len();
        }
        ms.sort_by(f64::total_cmp);
        let p = |q: f64| ms[((ms.len() as f64 - 1.0) * q) as usize];
        eprintln!(
            "embedding one prompt (dim {dim}, LRU cold): p50 {:.1} ms, p90 {:.1} ms, p99 {:.1} ms",
            p(0.5),
            p(0.9),
            p(0.99)
        );
        e.embed(&acme, &m, &[questions[0].to_owned()]).await.unwrap();
        let t0 = std::time::Instant::now();
        e.embed(&acme, &m, &[questions[0].to_owned()]).await.unwrap();
        eprintln!("LRU hit: {:.3} ms", t0.elapsed().as_secs_f64() * 1000.0);
    }

    #[test]
    fn parse_rejects_bad_shapes() {
        assert!(parse_vectors(&json!({"data": [{"index": 0, "embedding": [1.0]}]}), 2).is_err());
        assert!(parse_vectors(&json!({"data": [{"index": 0, "embedding": "base64"}]}), 1).is_err());
        assert!(
            parse_vectors(
                &json!({"data": [{"index": 0, "embedding": [1.0]}, {"index": 1, "embedding": [1.0, 2.0]}]}),
                2
            )
            .is_err()
        );
        assert_eq!(
            parse_vectors(&json!({"data": [{"embedding": [1.0]}, {"embedding": [2.0]}]}), 2).unwrap(),
            vec![vec![1.0], vec![2.0]]
        );
    }
}
