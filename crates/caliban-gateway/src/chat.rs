//! `/v1/chat/completions` and `/v1/models` (OpenAI dialect).

use crate::error::Dialect;
use crate::{ApiError, Gateway, auth, pipeline};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use std::sync::Arc;

pub async fn chat_completions(State(gw): State<Arc<Gateway>>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    pipeline::handle(gw, headers, body, Dialect::OpenAi).await
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
