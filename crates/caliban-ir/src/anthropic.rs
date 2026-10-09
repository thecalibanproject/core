//! Anthropic Messages API codec (`/v1/messages`).
//!
//! Two directions:
//! - **Client speaks Anthropic** (`POST /v1/messages`): [`to_chat_request`] parses the body into
//!   the IR so it runs through the same pipeline as Chat Completions (auth, PII, routing, cache,
//!   fallbacks, metering); [`from_openai_response`] and [`OpenAiToAnthropicStream`] translate
//!   OpenAI-shaped upstream output back into Anthropic messages and stream events.
//! - **Upstream is Anthropic** but the request is OpenAI-shaped (OpenAI client, or an Anthropic
//!   client routed to a non-Anthropic-native path): [`to_anthropic_request`],
//!   [`to_openai_response`] and [`AnthropicToOpenAiStream`].
//!
//! When both sides speak Anthropic the gateway passes the native body through untouched (so
//! `cache_control` breakpoints, server tools, thinking signatures survive), only rewriting text
//! for PII via [`for_each_text_mut`].

mod request;
mod response;
mod stream;

pub use request::{ParseError, for_each_text_mut, to_anthropic_request, to_chat_request};
pub use response::{anthropic_usage, from_openai_response, openai_usage, to_openai_response};
pub use stream::{AnthropicToOpenAiStream, AnthropicUsage, OpenAiToAnthropicStream};

use serde_json::{Value, json};

/// The codec is implemented (kept for callers that feature-detected the old placeholder).
pub const SUPPORTED: bool = true;

/// `anthropic-version` sent upstream when the client did not send one.
pub const API_VERSION: &str = "2023-06-01";

/// `max_tokens` is required by Anthropic; used when an OpenAI-shaped request has none.
pub const DEFAULT_MAX_TOKENS: u64 = 4096;

/// Anthropic error body: `{"type":"error","error":{"type":…,"message":…}}`.
pub fn error_body(error_type: &str, message: &str) -> Value {
    json!({ "type": "error", "error": { "type": error_type, "message": message } })
}

/// Formats one event as SSE, using its `type` as the `event:` name (as Anthropic does).
pub fn sse_event(ev: &Value) -> String {
    let name = ev.get("type").and_then(Value::as_str).unwrap_or("message");
    format!("event: {name}\ndata: {ev}\n\n")
}
