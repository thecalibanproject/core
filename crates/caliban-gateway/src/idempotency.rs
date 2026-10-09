//! `Idempotency-Key` on the inference endpoints (`/v1/chat/completions`, `/v1/messages`,
//! `/v1/embeddings`, `/v1/rerank`), so a client may retry a POST without paying twice.
//!
//! Per tenant and key (records in `caliban_meter::idempotency`; Valkey when `[limits] store =
//! "valkey"`, otherwise this router's memory):
//!
//! - **First request**: runs. It keeps running when the client disconnects (a stream is read to
//!   its end), so the retry the client is about to send can be answered from the record.
//! - **Duplicate while the first runs**: `409` with `Retry-After: 1` and code
//!   `idempotency_key_in_use`. It does not wait: a stream can take minutes.
//! - **Duplicate after a 2xx**: the stored response is replayed for 24 h: status, headers and body,
//!   plus `Idempotent-Replayed: true`. A stream is stored as it was sent (every SSE event, after
//!   rehydration) and replayed as one SSE body. Nothing runs, so no usage event is recorded and no
//!   quota is used: a request is charged once. A response over 4 MiB is not kept; its duplicates
//!   get `409` with code `idempotency_response_not_stored`.
//! - **Same key, different request** (method, path or body): `422`, code
//!   `idempotency_key_reused`.
//! - **First request failed** (non-2xx, or a stream that ended with an error or without its final
//!   event): the key is freed, so the retry runs again.
//!
//! Keys are 1 to 255 visible ASCII characters (else `400`). Requests without a valid API key are
//! passed to the handler untouched (it answers `401`). If the record store fails, the request runs
//! without deduplication (fail open, like quotas).

use crate::error::Dialect;
use crate::{Gateway, MAX_BODY, auth};
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use caliban_meter::idempotency::{Begin, IdempotencyStore, Lease, MAX_STORED_BYTES, StoredResponse};
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc;

pub(crate) const HEADER: &str = "idempotency-key";
pub(crate) const REPLAYED: &str = "idempotent-replayed";

/// Response headers never stored (hop-by-hop, or set again by the server).
fn stored_header(name: &HeaderName) -> bool {
    !matches!(name.as_str(), "content-length" | "transfer-encoding" | "connection" | "date" | "keep-alive")
}

fn error(dialect: Dialect, status: StatusCode, code: &'static str, message: &str, retry: bool) -> Response {
    let body = match dialect {
        Dialect::OpenAi => {
            serde_json::json!({"error": {"message": message, "type": "invalid_request_error", "code": code}})
        }
        Dialect::Anthropic => caliban_ir::anthropic::error_body("invalid_request_error", message),
    };
    let mut resp = (status, axum::Json(body)).into_response();
    if retry {
        resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    resp
}

fn valid_key(k: &str) -> bool {
    (1..=255).contains(&k.len()) && k.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

/// The middleware on the inference routes.
pub(crate) async fn middleware(State(gw): State<Arc<Gateway>>, req: Request, next: Next) -> Response {
    let Some(raw) = req.headers().get(HEADER) else { return next.run(req).await };
    let dialect = if req.uri().path() == "/v1/messages" { Dialect::Anthropic } else { Dialect::OpenAi };
    let Some(key) = raw.to_str().ok().map(str::trim).filter(|k| valid_key(k)).map(str::to_owned) else {
        return error(
            dialect,
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "Idempotency-Key must be 1 to 255 visible ASCII characters",
            false,
        );
    };
    let tenant = {
        let snap = gw.config.load();
        match auth::caller(&snap, req.headers()) {
            Ok(c) => c.tenant.id.to_string(),
            Err(_) => return next.run(req).await,
        }
    };
    let (parts, body) = req.into_parts();
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY).await else {
        return error(dialect, StatusCode::PAYLOAD_TOO_LARGE, "request_too_large", "request body too large", false);
    };
    let fingerprint = fingerprint(parts.method.as_str(), parts.uri.path(), &body);
    let store = Arc::clone(&gw.idempotency);
    let lease = match store.begin(&tenant, &key, &fingerprint).await {
        Ok(Begin::Started(lease)) => lease,
        Ok(Begin::InProgress) => {
            return error(
                dialect,
                StatusCode::CONFLICT,
                "idempotency_key_in_use",
                "a request with this Idempotency-Key is still being processed; retry later",
                true,
            );
        }
        Ok(Begin::Mismatch) => {
            return error(
                dialect,
                StatusCode::UNPROCESSABLE_ENTITY,
                "idempotency_key_reused",
                "this Idempotency-Key was used for a different request (method, path or body)",
                false,
            );
        }
        Ok(Begin::Replay(Some(stored))) => return replay(stored),
        Ok(Begin::Replay(None)) => {
            return error(
                dialect,
                StatusCode::CONFLICT,
                "idempotency_response_not_stored",
                "a request with this Idempotency-Key completed, but its response was too large to keep for replay",
                false,
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "idempotency store failed; running the request without deduplication");
            return next.run(Request::from_parts(parts, Body::from(body))).await;
        }
    };
    let guard = LeaseGuard { store, lease: Some(lease) };
    let req = Request::from_parts(parts, Body::from(body));
    // Spawned: the request completes (and its record with it) even if this client goes away.
    let task = tokio::spawn(async move {
        let resp = next.run(req).await;
        finish(guard, resp).await
    });
    match task.await {
        Ok(resp) => resp,
        Err(_) => crate::ApiError::from(caliban_types::CalibanError::Internal("request task failed".into()))
            .with_dialect(dialect)
            .into_response(),
    }
}

/// Identifies the request a key was used for: method, path and body.
pub(crate) fn fingerprint(method: &str, path: &str, body: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(method.as_bytes());
    h.update(&[0]);
    h.update(path.as_bytes());
    h.update(&[0]);
    h.update(body);
    h.finalize().to_hex().to_string()
}

fn replay(stored: StoredResponse) -> Response {
    let mut resp = Response::new(Body::from(stored.body));
    *resp.status_mut() = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
    let h = resp.headers_mut();
    for (k, v) in stored.headers {
        if let (Ok(k), Ok(v)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) {
            h.append(k, v);
        }
    }
    h.insert(REPLAYED, HeaderValue::from_static("true"));
    resp
}

/// Releases the key if the request ends without completing it (failure, panic).
struct LeaseGuard {
    store: Arc<dyn IdempotencyStore>,
    lease: Option<Lease>,
}

impl LeaseGuard {
    async fn complete(mut self, response: Option<StoredResponse>) {
        if let Some(l) = self.lease.take() {
            self.store.complete(&l, response).await;
        }
    }

    async fn release(mut self) {
        if let Some(l) = self.lease.take() {
            self.store.release(&l).await;
        }
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if let Some(l) = self.lease.take() {
            let store = Arc::clone(&self.store);
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move { store.release(&l).await });
            }
        }
    }
}

fn headers_of(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .filter(|(k, _)| stored_header(k))
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_owned(), v.to_owned())))
        .collect()
}

/// Stores a 2xx response for replay (or frees the key) and hands the response to the client.
async fn finish(guard: LeaseGuard, resp: Response) -> Response {
    if !resp.status().is_success() {
        guard.release().await;
        return resp;
    }
    let sse = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    let (parts, body) = resp.into_parts();
    let headers = headers_of(&parts.headers);
    let status = parts.status.as_u16();
    if !sse {
        let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
            guard.release().await;
            return Response::from_parts(parts, Body::empty());
        };
        let stored = std::str::from_utf8(&bytes).ok().map(|b| StoredResponse { status, headers, body: b.to_owned() });
        match stored {
            Some(s) => guard.complete(Some(s)).await,
            None => guard.release().await,
        }
        return Response::from_parts(parts, Body::from(bytes));
    }
    // A stream: forwarded as it comes, copied for the record, and read to its end even when the
    // client is gone.
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        let mut inner = body.into_data_stream();
        let mut copy: Vec<u8> = Vec::new();
        let (mut over, mut client) = (false, Some(tx));
        while let Some(frame) = inner.next().await {
            let Ok(b) = frame else {
                guard.release().await;
                return;
            };
            if !over {
                if copy.len() + b.len() > MAX_STORED_BYTES {
                    over = true;
                    copy = Vec::new();
                } else {
                    copy.extend_from_slice(&b);
                }
            }
            if let Some(c) = &client
                && c.send(Ok(b)).await.is_err()
            {
                client = None;
            }
        }
        drop(client);
        let text = String::from_utf8(copy).ok();
        let complete = over || text.as_deref().is_some_and(stream_completed);
        if !complete {
            guard.release().await;
        } else {
            guard.complete(text.filter(|_| !over).map(|body| StoredResponse { status, headers, body })).await;
        }
    });
    Response::from_parts(parts, crate::stream::body_after_first_frame(rx).await)
}

/// The stream ended normally: OpenAI's `[DONE]` or Anthropic's `message_stop`, no error event.
fn stream_completed(sse: &str) -> bool {
    let t = sse.trim_end();
    let ended =
        t.ends_with("data: [DONE]") || t.rsplit("\n\n").next().is_some_and(|ev| ev.starts_with("event: message_stop"));
    ended && !sse.contains("event: error\n") && !sse.contains("data: {\"error\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_completion_is_detected_in_both_dialects() {
        assert!(stream_completed("data: {\"x\":1}\n\ndata: [DONE]\n\n"));
        assert!(stream_completed(
            "event: message_start\ndata: {}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
        ));
        assert!(!stream_completed("data: {\"x\":1}\n\n"), "cut short");
        assert!(!stream_completed("data: {\"error\":{\"message\":\"boom\"}}\n\n"));
        assert!(!stream_completed("event: error\ndata: {}\n\n"));
    }

    #[test]
    fn keys_are_validated() {
        assert!(valid_key("a") && valid_key(&"k".repeat(255)) && valid_key("order 42/retry-1"));
        assert!(!valid_key("") && !valid_key(&"k".repeat(256)) && !valid_key("é") && !valid_key("a\tb"));
    }
}
