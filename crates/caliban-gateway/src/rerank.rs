//! `/v1/rerank`: Cohere/Jina-style reranking against rerank models (e.g. Qwen3-Reranker on vLLM,
//! bge-reranker on TEI). Request: `{model, query, documents: [string], top_n?, return_documents?}`.
//! Response: `{model, results: [{index, relevance_score, document?}]}` sorted by score.
//!
//! The upstream body carries both `documents` (vLLM/Cohere) and `texts` (TEI); both servers
//! ignore the field they do not use. TEI's bare-array response is normalized. Text sent outside
//! the trust boundary is PII-masked, as for embeddings.

use crate::embeddings::mask_texts;
use crate::error::Dialect;
use crate::pipeline::{Outcome, caliban_headers, finish, resolve};
use crate::{ApiError, Gateway, auth, limits, telemetry};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use caliban_config::ModelKind;
use caliban_ir::Usage;
use caliban_meter::quota::Amount;
use caliban_types::{CacheStatus, CalibanError, ModelId, PiiMode, RequestId};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Instant;
use tracing::{Instrument, Span};

#[derive(Deserialize)]
struct RerankRequest {
    model: String,
    query: String,
    documents: Vec<String>,
    top_n: Option<usize>,
    #[serde(default)]
    return_documents: bool,
}

pub async fn rerank(State(gw): State<Arc<Gateway>>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    let request_id = RequestId::new();
    let span = telemetry::request_span("rerank", Dialect::OpenAi, &request_id);
    telemetry::link_parent(&span, &headers);
    run(gw, headers, body, request_id, span.clone()).instrument(span.clone()).await.inspect_err(|e| telemetry::record_error(&span, e.error.kind()))
}

async fn run(gw: Arc<Gateway>, headers: HeaderMap, body: Bytes, request_id: RequestId, span: Span) -> Result<Response, ApiError> {
    let started = Instant::now();
    let snap = gw.config.load();
    let caller = auth::caller(&snap, &headers)?;
    let tenant = caller.tenant.clone();
    span.record("caliban.tenant", tenant.id.as_str());
    let policy = limits::policy(&snap.limits_for(&tenant));
    limits::check_rate(&gw, tenant.id.as_str(), Some(&caller.key_hash), &policy).await?;

    let req: RerankRequest = serde_json::from_slice(&body).map_err(|e| CalibanError::InvalidRequest(e.to_string()))?;
    if req.documents.is_empty() {
        return Err(CalibanError::InvalidRequest("documents must not be empty".into()).into());
    }
    span.record("otel.name", format!("rerank {}", req.model));
    span.record("gen_ai.request.model", req.model.as_str());
    let (model, provider) = resolve(&snap, &tenant, &ModelId::from(req.model.as_str()))
        .ok_or_else(|| CalibanError::InvalidRequest(format!("model '{}' is not available to this tenant", req.model)))?;
    if model.kind != ModelKind::Rerank {
        return Err(CalibanError::InvalidRequest(format!("model '{}' is not a rerank model", req.model)).into());
    }
    span.record("gen_ai.provider.name", telemetry::provider_name(provider.kind));

    let est = (req.query.len() + req.documents.iter().map(String::len).sum::<usize>()) as u64 / 4 + 1;
    let usd = caliban_meter::cost_usd(est, 0, model.price_in_per_mtok, Some(0.0)).unwrap_or(0.0);
    let mut settlement = limits::reserve(&gw, tenant.id.as_str(), &policy, Amount { tokens: est, usd }).await?;

    let (mut query, mut docs, mut entities) = (req.query.clone(), req.documents.clone(), 0);
    let external = model.trust_tier.is_external() || provider.trust_tier.is_external();
    if external && snap.pii_mode_for(&tenant) != PiiMode::Off {
        let mut all = vec![query];
        all.extend(docs);
        let (masked, n) = mask_texts(&gw, all)?;
        entities = n;
        let mut it = masked.into_iter();
        query = it.next().unwrap_or_default();
        docs = it.collect();
    }
    let upstream_body = json!({
        "model": model.upstream_model, "query": query, "documents": docs, "texts": docs,
        "top_n": req.top_n.unwrap_or(req.documents.len()),
    });

    let adapter = gw.providers.adapter(provider.kind).map_err(|e| CalibanError::Upstream(e.to_string()))?;
    let us = telemetry::upstream_span("rerank", &model, &provider, 0, false);
    settlement.set_in_flight(true);
    let raw = match adapter.rerank(&provider, upstream_body).instrument(us.clone()).await {
        Ok(v) => v,
        Err(e) => {
            settlement.set_in_flight(false);
            telemetry::record_error(&us, e.kind());
            return Err(CalibanError::Upstream(e.to_string()).into());
        }
    };
    let mut results = normalize(&raw);
    results.sort_by(|a, b| b.1.total_cmp(&a.1));
    results.truncate(req.top_n.unwrap_or(usize::MAX));
    let results: Vec<Value> = results
        .into_iter()
        .filter(|(i, _)| *i < req.documents.len())
        .map(|(i, score)| {
            let mut r = json!({ "index": i, "relevance_score": score });
            if req.return_documents {
                // Always the caller's original text, never the masked copy.
                r["document"] = json!({ "text": req.documents[i] });
            }
            r
        })
        .collect();
    let prompt_tokens = raw.pointer("/usage/total_tokens").or_else(|| raw.pointer("/usage/prompt_tokens")).and_then(Value::as_u64).unwrap_or(est);
    let usage = Usage { prompt_tokens, ..Usage::default() };
    telemetry::record_usage(&us, usage);
    let outcome = Outcome {
        request_id,
        tenant_id: tenant.id.to_string(),
        model,
        intent: "rerank".into(),
        cache: CacheStatus::Bypass,
        cache_tier: None,
        pii_entities: entities,
        started,
        dialect: Dialect::OpenAi,
        span,
        est_prompt_tokens: est,
        route: None,
    };
    let model_id = outcome.model.id.to_string();
    finish(&gw, &outcome, usage, 0, settlement, 0).await;
    let mut resp = axum::Json(json!({ "model": model_id, "results": results, "usage": { "total_tokens": prompt_tokens } })).into_response();
    caliban_headers(resp.headers_mut(), &outcome);
    Ok(resp)
}

/// `(index, score)` pairs from either `{results:[{index, relevance_score}]}` (vLLM/Cohere/Jina)
/// or TEI's `[{index, score}]`.
fn normalize(v: &Value) -> Vec<(usize, f64)> {
    let items = v.get("results").and_then(Value::as_array).or_else(|| v.as_array());
    items
        .into_iter()
        .flatten()
        .filter_map(|r| {
            let i = usize::try_from(r.get("index")?.as_u64()?).ok()?;
            let s = r.get("relevance_score").or_else(|| r.get("score"))?.as_f64()?;
            Some((i, s))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_vllm_and_tei_shapes() {
        let vllm = json!({"results": [{"index": 1, "relevance_score": 0.9}, {"index": 0, "relevance_score": 0.1}]});
        let tei = json!([{"index": 0, "score": 0.2}, {"index": 1, "score": 0.7}]);
        assert_eq!(normalize(&vllm), vec![(1, 0.9), (0, 0.1)]);
        assert_eq!(normalize(&tei), vec![(0, 0.2), (1, 0.7)]);
    }
}
