//! Anthropic Messages API: `/v1/messages` and `/v1/messages/count_tokens`.
//!
//! Runs through the same pipeline as `/v1/chat/completions` (see [`crate::pipeline`]); responses,
//! stream events and errors are Anthropic-shaped. Anthropic SDKs authenticate with
//! `x-api-key: cal_…` (a `Bearer` header works too).

use crate::error::Dialect;
use crate::{ApiError, Gateway, auth, pipeline};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use caliban_types::CalibanError;
use serde_json::Value;
use std::sync::Arc;

pub async fn messages(State(gw): State<Arc<Gateway>>, headers: HeaderMap, body: Bytes) -> Response {
    match pipeline::handle(gw, headers, body, Dialect::Anthropic).await {
        Ok(r) => r,
        Err(e) => e.with_dialect(Dialect::Anthropic).into_response(),
    }
}

/// Approximate token count (no tokenizer: ~4 bytes per token plus per-message, image and tool
/// overhead), matching what the quota reservation uses.
pub async fn count_tokens(State(gw): State<Arc<Gateway>>, headers: HeaderMap, body: Bytes) -> Response {
    let run = || -> Result<Response, CalibanError> {
        let snap = gw.config.load();
        auth::tenant(&snap, &headers)?;
        let mut v: Value = serde_json::from_slice(&body).map_err(|e| CalibanError::InvalidRequest(e.to_string()))?;
        // count_tokens takes no max_tokens.
        if let Some(o) = v.as_object_mut() {
            o.entry("max_tokens").or_insert(Value::from(1));
        }
        let req =
            caliban_ir::anthropic::to_chat_request(&v).map_err(|e| CalibanError::InvalidRequest(e.to_string()))?;
        Ok(axum::Json(serde_json::json!({ "input_tokens": req.estimate_prompt_tokens() })).into_response())
    };
    run().unwrap_or_else(|e| ApiError::from(e).with_dialect(Dialect::Anthropic).into_response())
}
