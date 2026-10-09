//! Model catalogue and shared model servers (on-prem pools), editable at runtime.
//!
//! On-prem, an operator serves open-weight models (Qwen, gpt-oss, Mistral, …) with vLLM, SGLang,
//! llama.cpp or Ollama, registers the server once as a shared provider, then uses **discovery**
//! (`GET <base_url>/models`) to add what it serves to the catalogue. Every change republishes the
//! data-plane snapshot.

use crate::store::Mutation;
use crate::{ADMIN_ACTOR, ApiError, ApiResult, Cp, bad, not_found, still_referenced};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use caliban_config::{
    Capabilities, ModelEntry, ModelKind, ProviderConfig, Reasoning, ReasoningControl, SharedProvider,
};
use caliban_types::{ModelId, TrustTier};
use serde::Serialize;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

fn model_json(cp: &Cp, m: &ModelEntry) -> Value {
    json!({
        "id": m.id, "provider_id": m.provider, "provider_kind": provider_kind(cp, m.provider.as_str()),
        "upstream_model": m.upstream_model, "kind": m.kind, "family": m.family, "capabilities": m.capabilities,
        "trust_tier": m.trust_tier, "licence": m.licence, "context_window": m.context_window,
        "price_in_per_mtok": m.price_in_per_mtok, "price_out_per_mtok": m.price_out_per_mtok,
        "price_cache_read_per_mtok": m.price_cache_read_per_mtok, "price_cache_write_per_mtok": m.price_cache_write_per_mtok,
        "price_cache_write_1h_per_mtok": m.price_cache_write_1h_per_mtok,
    })
}

fn provider_kind(cp: &Cp, id: &str) -> Value {
    let st = cp.store.state();
    let kind = st
        .shared_providers
        .iter()
        .find(|p| p.provider.id.as_str() == id)
        .map(|p| p.provider.kind)
        .or_else(|| st.provider_keys.iter().find(|p| p.id == id).map(|p| p.kind));
    kind.map_or(Value::Null, |k| serde_json::to_value(k).unwrap_or(Value::Null))
}

pub(crate) async fn list_models(State(cp): State<Cp>) -> Json<Value> {
    let st = cp.store.state();
    Json(Value::Array(st.models.iter().map(|m| model_json(&cp, m)).collect()))
}

pub(crate) async fn create_model(
    State(cp): State<Cp>,
    Json(m): Json<ModelEntry>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    cp.store.apply(ADMIN_ACTOR, Mutation::CreateModel(m.clone())).await?;
    Ok((StatusCode::CREATED, Json(model_json(&cp, &m))))
}

pub(crate) async fn delete_model(State(cp): State<Cp>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    cp.store.apply(ADMIN_ACTOR, Mutation::DeleteModel(id)).await.map_err(|e| still_referenced(e, "model"))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct ProviderView {
    id: String,
    kind: caliban_types::ProviderKind,
    base_url: String,
    trust_tier: TrustTier,
    cache_salt: bool,
    has_api_key: bool,
    tenants: Vec<String>,
}

fn view(p: &SharedProvider) -> ProviderView {
    ProviderView {
        id: p.provider.id.to_string(),
        kind: p.provider.kind,
        base_url: p.provider.base_url.clone(),
        trust_tier: p.provider.trust_tier,
        cache_salt: p.provider.cache_salt,
        has_api_key: p.provider.api_key.is_some(),
        tenants: p.tenants.iter().map(ToString::to_string).collect(),
    }
}

pub(crate) async fn list_providers(State(cp): State<Cp>) -> Json<Value> {
    let st = cp.store.state();
    Json(serde_json::to_value(st.shared_providers.iter().map(view).collect::<Vec<_>>()).unwrap_or_default())
}

#[derive(serde::Deserialize)]
pub(crate) struct SharedProviderCreate {
    id: String,
    kind: caliban_types::ProviderKind,
    base_url: String,
    trust_tier: TrustTier,
    #[serde(default)]
    cache_salt: bool,
    api_key: Option<String>,
    #[serde(default)]
    tenants: Vec<String>,
}

pub(crate) async fn create_provider(
    State(cp): State<Cp>,
    Json(b): Json<SharedProviderCreate>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if b.id.trim().is_empty() || b.base_url.trim().is_empty() {
        return Err(bad("id and base_url are required"));
    }
    let api_key = match b.api_key.as_deref().filter(|k| !k.is_empty()) {
        Some(k) => {
            let kek = caliban_config::process_kek().map_err(|e| bad(format!("cannot store provider keys: {e}")))?;
            Some(caliban_config::SecretRef::Sealed { sealed: caliban_config::seal(kek, k) })
        }
        None => None,
    };
    let sp = SharedProvider {
        provider: ProviderConfig {
            id: b.id.as_str().into(),
            kind: b.kind,
            base_url: b.base_url,
            trust_tier: b.trust_tier,
            api_key,
            cache_salt: b.cache_salt,
        },
        tenants: b.tenants.into_iter().map(Into::into).collect(),
    };
    cp.store.apply(ADMIN_ACTOR, Mutation::CreateSharedProvider(sp.clone())).await?;
    Ok((StatusCode::CREATED, Json(serde_json::to_value(view(&sp)).unwrap_or_default())))
}

pub(crate) async fn delete_provider(State(cp): State<Cp>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    cp.store
        .apply(ADMIN_ACTOR, Mutation::DeleteSharedProvider(id))
        .await
        .map_err(|e| still_referenced(e, "provider"))?;
    Ok(StatusCode::NO_CONTENT)
}

fn find_provider(cp: &Cp, id: &str) -> ApiResult<ProviderConfig> {
    cp.store
        .state()
        .shared_providers
        .iter()
        .find(|p| p.provider.id.as_str() == id)
        .map(|p| p.provider.clone())
        .ok_or_else(|| not_found("provider"))
}

/// Calls `GET <base_url>/models` on the server.
async fn fetch_models(p: &ProviderConfig) -> Result<(Vec<Value>, u128), String> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().map_err(|e| e.to_string())?;
    let mut req = client.get(format!("{}/models", p.base_url.trim_end_matches('/')));
    if let Some(r) = &p.api_key {
        req = req.bearer_auth(r.resolve().map_err(|e| e.to_string())?.expose());
    }
    let t = Instant::now();
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let latency = t.elapsed().as_millis();
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status()));
    }
    let v: Value = resp.json().await.map_err(|e| e.to_string())?;
    // OpenAI shape `{data: [...]}`; Ollama's native `/api/tags` is not used here.
    Ok((v.get("data").and_then(Value::as_array).cloned().unwrap_or_default(), latency))
}

pub(crate) async fn provider_health(State(cp): State<Cp>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let p = find_provider(&cp, &id)?;
    Ok(Json(match fetch_models(&p).await {
        Ok((models, ms)) => json!({ "status": "ok", "latency_ms": ms, "models": models.len() }),
        Err(e) => json!({ "status": "unreachable", "error": e }),
    }))
}

/// Lists what the server serves and suggests catalogue entries for models not yet registered.
/// Suggestions are heuristics from the model name and must be reviewed (capabilities, licence).
pub(crate) async fn discover(State(cp): State<Cp>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let p = find_provider(&cp, &id)?;
    let (served, _) =
        fetch_models(&p).await.map_err(|e| ApiError(StatusCode::BAD_GATEWAY, format!("discovery failed: {e}")))?;
    let known: Vec<(String, String)> =
        cp.store.state().models.iter().map(|m| (m.provider.to_string(), m.upstream_model.clone())).collect();
    let mut available = Vec::new();
    let mut suggested = Vec::new();
    for m in &served {
        let Some(upstream) = m.get("id").and_then(Value::as_str) else { continue };
        available.push(upstream.to_owned());
        if known.iter().any(|(pid, u)| pid == p.id.as_str() && u == upstream) {
            continue;
        }
        let context = m.get("max_model_len").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok());
        suggested.push(suggest(&p, upstream, context));
    }
    Ok(Json(json!({ "provider": id, "available": available, "suggested": suggested })))
}

/// Heuristic catalogue entry from a served model id (e.g. `Qwen/Qwen3-30B-A3B-Instruct-2507`).
pub(crate) fn suggest(p: &ProviderConfig, upstream: &str, context_window: Option<u32>) -> ModelEntry {
    let lower = upstream.to_ascii_lowercase();
    let short = upstream.rsplit('/').next().unwrap_or(upstream).to_ascii_lowercase();
    let kind = if lower.contains("embed") || lower.contains("bge-m3") || lower.contains("e5-") {
        ModelKind::Embedding
    } else if lower.contains("rerank") {
        ModelKind::Rerank
    } else {
        ModelKind::Chat
    };
    let family = [
        "qwen3", "qwen2.5", "gpt-oss", "deepseek", "mistral", "mixtral", "gemma", "glm", "granite", "phi", "llama",
        "kimi",
    ]
    .into_iter()
    .find(|f| lower.contains(f))
    .map(str::to_owned);
    let mut caps =
        Capabilities { vision: lower.contains("-vl") || lower.contains("vision"), ..Capabilities::default() };
    if kind == ModelKind::Chat {
        caps.tools = true;
        match family.as_deref() {
            Some("qwen3") if lower.contains("thinking") => caps.reasoning = Reasoning::Always,
            Some("qwen3") if lower.contains("instruct") || lower.contains("coder") => {}
            Some("qwen3") => {
                caps.reasoning = Reasoning::Hybrid;
                caps.reasoning_control = ReasoningControl::EnableThinking;
            }
            Some("gpt-oss") => {
                caps.reasoning = Reasoning::Always;
                caps.reasoning_control = ReasoningControl::ReasoningEffort;
            }
            Some("deepseek") if lower.contains("r1") => caps.reasoning = Reasoning::Always,
            _ => {}
        }
    }
    ModelEntry {
        id: ModelId::from(format!("local/{short}")),
        provider: p.id.clone(),
        upstream_model: upstream.to_owned(),
        kind,
        family,
        capabilities: caps,
        trust_tier: p.trust_tier,
        licence: None,
        context_window,
        price_in_per_mtok: Some(0.0),
        price_out_per_mtok: Some(0.0),
        price_cache_read_per_mtok: None,
        price_cache_write_per_mtok: None,
        price_cache_write_1h_per_mtok: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> ProviderConfig {
        ProviderConfig {
            id: "vllm".into(),
            kind: caliban_types::ProviderKind::OpenaiCompatible,
            base_url: "http://x/v1".into(),
            trust_tier: TrustTier::T0Sovereign,
            api_key: None,
            cache_salt: true,
        }
    }

    #[test]
    fn suggestions_classify_common_open_models() {
        let q = suggest(&p(), "Qwen/Qwen3-8B", Some(32768));
        assert_eq!((q.id.as_str(), q.kind, q.family.as_deref()), ("local/qwen3-8b", ModelKind::Chat, Some("qwen3")));
        assert_eq!(q.capabilities.reasoning_control, ReasoningControl::EnableThinking);
        let i = suggest(&p(), "Qwen/Qwen3-30B-A3B-Instruct-2507", None);
        assert_eq!(i.capabilities.reasoning, Reasoning::None);
        let g = suggest(&p(), "openai/gpt-oss-20b", None);
        assert_eq!(g.capabilities.reasoning_control, ReasoningControl::ReasoningEffort);
        assert_eq!(suggest(&p(), "Qwen/Qwen3-Embedding-0.6B", None).kind, ModelKind::Embedding);
        assert_eq!(suggest(&p(), "Qwen/Qwen3-Reranker-0.6B", None).kind, ModelKind::Rerank);
        assert!(suggest(&p(), "Qwen/Qwen2.5-VL-7B-Instruct", None).capabilities.vision);
    }
}
