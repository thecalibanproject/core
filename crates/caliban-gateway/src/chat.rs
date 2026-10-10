//! `/v1/chat/completions` and `/v1/models` (OpenAI dialect).

use crate::error::Dialect;
use crate::{ApiError, Gateway, auth, pipeline};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use std::sync::Arc;

pub async fn chat_completions(
    State(gw): State<Arc<Gateway>>,
    internal: Option<axum::Extension<auth::InternalCaller>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    if let Some(r) = crate::node_chat::maybe_handle(&gw, &headers, &body, Dialect::OpenAi, internal.is_some()).await {
        return Ok(r);
    }
    pipeline::handle(gw, headers, body, Dialect::OpenAi, internal.map(|e| e.0)).await
}

pub async fn list_models(State(gw): State<Arc<Gateway>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let snap = gw.config.load();
    let tenant = auth::tenant(&snap, &headers)?;
    let mut data: Vec<Value> = snap
        .models_for(tenant)
        .map(|m| serde_json::json!({ "id": m.id, "object": "model", "owned_by": m.provider, "caliban": { "kind": m.kind, "family": m.family, "capabilities": m.capabilities, "trust_tier": m.trust_tier } }))
        .collect();
    data.push(serde_json::json!({ "id": caliban_route::AUTO_MODEL, "object": "model", "owned_by": "caliban" }));
    Ok(axum::Json(serde_json::json!({ "object": "list", "data": data })).into_response())
}
