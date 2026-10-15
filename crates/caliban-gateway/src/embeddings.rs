//! `/v1/embeddings`: routes to embedding models (e.g. open models on vLLM/TEI on-prem).
//!
//! Inputs sent to providers outside the trust boundary are **masked** (`[EMAIL]`, `[PERSON]`…),
//! not pseudonymized: vectors cannot be rehydrated, and request-scoped surrogates would make
//! identical texts embed differently.

use crate::error::Dialect;
use crate::metering::Metered;
use crate::pipeline::{Outcome, caliban_headers, finish, resolve};
use crate::timing::Timings;
use crate::{ApiError, Gateway, auth, limits, telemetry};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use caliban_config::ModelKind;
use caliban_ir::{ChatRequest, Message, Usage};
use caliban_meter::quota::Amount;
use caliban_types::{CacheStatus, CalibanError, ModelId, PiiMode, RequestId};
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;
use tracing::{Instrument, Span};

pub async fn embeddings(
    State(gw): State<Arc<Gateway>>,
    internal: Option<axum::Extension<auth::InternalCaller>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let request_id = RequestId::new();
    let span = telemetry::request_span("embeddings", Dialect::OpenAi, &request_id);
    telemetry::link_parent(&span, &headers);
    run(gw, headers, body, request_id, span.clone(), internal.map(|e| e.0))
        .instrument(span.clone())
        .await
        .inspect_err(|e| telemetry::record_error(&span, e.error.kind()))
}

async fn run(
    gw: Arc<Gateway>,
    headers: HeaderMap,
    body: Bytes,
    request_id: RequestId,
    span: Span,
    internal: Option<auth::InternalCaller>,
) -> Result<Response, ApiError> {
    let started = Instant::now();
    let snap = gw.config.load();
    let caller = auth::resolve(&snap, &headers, internal.as_ref())?;
    let tenant = caller.tenant.clone();
    span.record("caliban.tenant", tenant.id.as_str());
    let policy = limits::policy(&snap.limits_for(&tenant));
    limits::check_rate(&gw, tenant.id.as_str(), caller.key(), &policy).await?;
    let mut timings = Timings::new(snap.config.telemetry.server_timing);
    timings.auth = Some(started.elapsed());

    let mut v: Value = serde_json::from_slice(&body).map_err(|e| CalibanError::InvalidRequest(e.to_string()))?;
    let model_id = v
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| CalibanError::InvalidRequest("model is required".into()))?
        .to_owned();
    span.record("otel.name", format!("embeddings {model_id}"));
    span.record("gen_ai.request.model", model_id.as_str());
    let (model, provider) = resolve(&snap, &tenant, &ModelId::from(model_id.as_str()))
        .ok_or_else(|| CalibanError::InvalidRequest(format!("model '{model_id}' is not available to this tenant")))?;
    if model.kind != ModelKind::Embedding {
        return Err(CalibanError::InvalidRequest(format!("model '{model_id}' is not an embedding model")).into());
    }
    span.record("gen_ai.provider.name", telemetry::provider_name(provider.kind));

    let est = v.get("input").map_or(0, |i| (i.to_string().len() as u64).div_ceil(4));
    let usd = caliban_meter::cost_usd(est, 0, model.price_in_per_mtok, Some(0.0)).unwrap_or(0.0);
    let mut settlement = limits::reserve(&gw, tenant.id.as_str(), &policy, Amount { tokens: est, usd }).await?;

    let mut entities = 0;
    let external = model.trust_tier.is_external() || provider.trust_tier.is_external();
    // Masked (embeddings cannot be rehydrated); inside the trust boundary only when the tenant or a
    // `caliban.pii_floor` asks for it (`Snapshot::pii_protection`).
    let floor = v.pointer("/caliban/pii_floor").and_then(|f| serde_json::from_value::<PiiMode>(f.clone()).ok());
    if snap.pii_protection(&tenant, None, floor, external).is_some() {
        let s = telemetry::child("pii");
        s.record("caliban.pii.mode", "mask");
        let pii_started = Instant::now();
        entities = mask_inputs(&gw, tenant.id.as_str(), &mut v).instrument(s.clone()).await?;
        timings.add_pii(pii_started.elapsed());
        s.record("caliban.pii.entities", entities);
    }
    v["model"] = Value::String(model.upstream_model.clone());
    if let Some(o) = v.as_object_mut() {
        o.remove("caliban");
    }

    let adapter = gw.providers.adapter(provider.kind).map_err(|e| CalibanError::Upstream(e.to_string()))?;
    let us = telemetry::upstream_span("embeddings", &model, &provider, 0, false);
    settlement.set_in_flight(true);
    let upstream_started = Instant::now();
    let (out, headers_at) =
        caliban_providers::time_to_headers(adapter.embeddings(&provider, v).instrument(us.clone())).await;
    timings.upstream_call(upstream_started, headers_at);
    timings.upstream_done();
    let mut out = match out {
        Ok(out) => out,
        Err(e) => {
            settlement.set_in_flight(false);
            telemetry::record_error(&us, e.kind());
            return Err(CalibanError::Upstream(e.to_string()).into());
        }
    };
    out["model"] = Value::String(model.id.to_string());
    // The provider's count; the request estimate when the upstream reports none.
    let usage = match out.pointer("/usage/prompt_tokens").and_then(Value::as_u64) {
        Some(n) => Metered::provider(Usage { prompt_tokens: n, ..Usage::default() }),
        None => Metered::estimated(Usage { prompt_tokens: est, ..Usage::default() }),
    };
    telemetry::record_usage(&us, usage.usage);
    let outcome = Outcome {
        request_id,
        tenant_id: tenant.id.to_string(),
        model,
        // Retrieval's own embedding calls are labelled by what they do, not as client embeddings.
        intent: internal.as_ref().and_then(|i| i.purpose).unwrap_or("embedding").into(),
        cache: CacheStatus::Bypass,
        cache_tier: None,
        pii_entities: entities,
        started,
        dialect: Dialect::OpenAi,
        span,
        est_prompt_tokens: est,
        route: None,
        client_usage: true,
        purpose: internal.as_ref().and_then(|i| i.purpose),
        node: internal.and_then(|i| i.node),
        auto_fallback: None,
        timings,
        pii_ignored: None,
    };
    finish(&gw, &outcome, usage, 0, settlement).await;
    let mut resp = axum::Json(out).into_response();
    caliban_headers(resp.headers_mut(), &outcome);
    Ok(resp)
}

/// Masks PII in `input` (string or array of strings) in place; returns the entity count.
async fn mask_inputs(gw: &Gateway, tenant: &str, v: &mut Value) -> Result<usize, ApiError> {
    let texts: Vec<String> = match v.get("input") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) if a.iter().all(Value::is_string) => {
            a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()
        }
        // Token-id inputs carry no text to scan.
        _ => return Ok(0),
    };
    let (masked, entities) = mask_texts(gw, Some(tenant), texts).await?;
    let masked: Vec<Value> = masked.into_iter().map(Value::String).collect();
    v["input"] = if v.get("input").is_some_and(Value::is_string) {
        masked.into_iter().next().unwrap_or(Value::Null)
    } else {
        Value::Array(masked)
    };
    Ok(entities)
}

/// Masks PII in each text (`[EMAIL]`, `[PERSON]`, …); credentials still block the request.
pub(crate) async fn mask_texts(
    gw: &Gateway,
    tenant: Option<&str>,
    texts: Vec<String>,
) -> Result<(Vec<String>, usize), ApiError> {
    let req = ChatRequest {
        model: String::new(),
        messages: texts
            .into_iter()
            .map(|t| Message { role: "user".into(), content: Value::String(t), extra: Default::default() })
            .collect(),
        stream: false,
        caliban: None,
        extra: Default::default(),
    };
    let (req, p) = gw.protect(tenant, req, PiiMode::Mask, b"embeddings").await?;
    let masked = req.messages.into_iter().map(|m| m.content.as_str().unwrap_or_default().to_owned()).collect();
    Ok((masked, p.entities))
}
