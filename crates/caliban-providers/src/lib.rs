//! Provider adapters.
//!
//! Every call uses the **tenant's own** credential (BYOK) and the tenant's own provider base URL.
//! Caliban never pools upstream keys, which also keeps provider-side prompt caches isolated per
//! tenant (KeyPooling, arXiv 2608.17485).
//!
//! Implemented:
//! - OpenAI and any OpenAI-compatible server (vLLM, SGLang, llama.cpp, Ollama, …).
//! - Anthropic Messages (`kind = "anthropic"`, `x-api-key` + `anthropic-version`): OpenAI-shaped
//!   requests are translated both ways ([`Provider::chat`]); Anthropic-shaped requests from
//!   `/v1/messages` clients pass through natively ([`Provider::messages`]), preserving
//!   `cache_control` breakpoints.
//!
//! TODO: Azure OpenAI, Bedrock, Vertex.

use async_trait::async_trait;
use bytes::Bytes;
use caliban_config::ProviderConfig;
use caliban_ir::anthropic::{self as anth, AnthropicToOpenAiStream};
use caliban_ir::sse::SseParser;
use caliban_types::ProviderKind;
use futures::StreamExt;
use futures::stream::BoxStream;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("provider kind {0:?} is not supported yet")]
    Unsupported(ProviderKind),
    #[error("credential: {0}")]
    Credential(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("upstream returned {status}: {body}")]
    Status { status: u16, body: String },
}

impl ProviderError {
    /// Whether trying the next candidate model makes sense.
    pub fn is_retryable(&self) -> bool {
        match self {
            ProviderError::Transport(_) => true,
            ProviderError::Status { status, .. } => *status == 429 || *status >= 500,
            _ => false,
        }
    }

    /// Short, content-free classification (for spans and metrics; never includes bodies).
    pub fn kind(&self) -> &'static str {
        match self {
            ProviderError::Unsupported(_) => "unsupported",
            ProviderError::Credential(_) => "credential",
            ProviderError::Transport(_) => "transport",
            ProviderError::Status { status: 429, .. } => "upstream_429",
            ProviderError::Status { status, .. } if *status >= 500 => "upstream_5xx",
            ProviderError::Status { .. } => "upstream_4xx",
        }
    }
}

pub enum ProviderResponse {
    Json(serde_json::Value),
    /// Raw SSE byte stream from the upstream.
    Stream(BoxStream<'static, Result<Bytes, ProviderError>>),
}

/// Client headers forwarded on the native Anthropic path.
#[derive(Debug, Clone, Default)]
pub struct NativeOptions {
    pub anthropic_version: Option<String>,
    pub anthropic_beta: Option<String>,
}

#[async_trait]
pub trait Provider: Send + Sync {
    /// `body` is an OpenAI-format request for the upstream model. Responses (and streams) are
    /// OpenAI-shaped whatever the upstream speaks.
    async fn chat(&self, provider: &ProviderConfig, body: serde_json::Value, stream: bool) -> Result<ProviderResponse, ProviderError>;

    /// OpenAI `/embeddings` (also served by vLLM, TEI, Infinity, llama.cpp, Ollama).
    async fn embeddings(&self, provider: &ProviderConfig, body: serde_json::Value) -> Result<serde_json::Value, ProviderError>;

    /// `{base_url}/rerank` (vLLM `/v1/rerank`, TEI `/rerank`). The raw upstream JSON is returned;
    /// the gateway normalizes the shapes.
    async fn rerank(&self, provider: &ProviderConfig, _body: serde_json::Value) -> Result<serde_json::Value, ProviderError> {
        Err(ProviderError::Unsupported(provider.kind))
    }

    /// Native Anthropic Messages call: `body` is an Anthropic request; the response is an
    /// Anthropic message (JSON) or the raw Anthropic SSE stream.
    async fn messages(&self, provider: &ProviderConfig, _body: serde_json::Value, _stream: bool, _opts: &NativeOptions) -> Result<ProviderResponse, ProviderError> {
        Err(ProviderError::Unsupported(provider.kind))
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .expect("reqwest client")
}

/// Sends a request; non-2xx becomes `ProviderError::Status` with a short body prefix.
async fn send(req: reqwest::RequestBuilder) -> Result<reqwest::Response, ProviderError> {
    let resp = req.send().await.map_err(|e| ProviderError::Transport(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        // Upstream bodies can echo prompts; keep only a short prefix.
        let body: String = body.chars().take(500).collect();
        return Err(ProviderError::Status { status: status.as_u16(), body });
    }
    Ok(resp)
}

fn byte_stream(resp: reqwest::Response) -> BoxStream<'static, Result<Bytes, ProviderError>> {
    resp.bytes_stream().map(|r| r.map_err(|e| ProviderError::Transport(e.to_string()))).boxed()
}

// ───────────────────────────── OpenAI-compatible ─────────────────────────────

/// OpenAI Chat Completions over HTTP. Also used for every on-prem OpenAI-compatible server.
pub struct OpenAiCompatible {
    http: reqwest::Client,
}

impl OpenAiCompatible {
    pub fn new() -> Self {
        Self { http: http_client() }
    }
}

impl Default for OpenAiCompatible {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenAiCompatible {
    async fn post(&self, provider: &ProviderConfig, path: &str, body: &serde_json::Value) -> Result<reqwest::Response, ProviderError> {
        let url = format!("{}/{path}", provider.base_url.trim_end_matches('/'));
        let mut req = self.http.post(&url).json(body);
        if let Some(secret_ref) = &provider.api_key {
            let key = secret_ref.resolve().map_err(|e| ProviderError::Credential(e.to_string()))?;
            req = req.bearer_auth(key.expose());
        }
        send(req).await
    }
}

#[async_trait]
impl Provider for OpenAiCompatible {
    async fn rerank(&self, provider: &ProviderConfig, body: serde_json::Value) -> Result<serde_json::Value, ProviderError> {
        let resp = self.post(provider, "rerank", &body).await?;
        resp.json().await.map_err(|e| ProviderError::Transport(e.to_string()))
    }

    async fn embeddings(&self, provider: &ProviderConfig, body: serde_json::Value) -> Result<serde_json::Value, ProviderError> {
        let resp = self.post(provider, "embeddings", &body).await?;
        resp.json().await.map_err(|e| ProviderError::Transport(e.to_string()))
    }

    async fn chat(&self, provider: &ProviderConfig, body: serde_json::Value, stream: bool) -> Result<ProviderResponse, ProviderError> {
        let resp = self.post(provider, "chat/completions", &body).await?;
        if stream {
            Ok(ProviderResponse::Stream(byte_stream(resp)))
        } else {
            let v = resp.json().await.map_err(|e| ProviderError::Transport(e.to_string()))?;
            Ok(ProviderResponse::Json(v))
        }
    }
}

// ───────────────────────────── Anthropic ─────────────────────────────

/// Anthropic Messages API (`{base_url}/messages`, e.g. `https://api.anthropic.com/v1`).
pub struct Anthropic {
    http: reqwest::Client,
}

impl Anthropic {
    pub fn new() -> Self {
        Self { http: http_client() }
    }

    async fn post(&self, provider: &ProviderConfig, body: &serde_json::Value, opts: &NativeOptions) -> Result<reqwest::Response, ProviderError> {
        let url = format!("{}/messages", provider.base_url.trim_end_matches('/'));
        let mut req = self
            .http
            .post(&url)
            .header("anthropic-version", opts.anthropic_version.as_deref().unwrap_or(anth::API_VERSION))
            .json(body);
        if let Some(beta) = &opts.anthropic_beta {
            req = req.header("anthropic-beta", beta);
        }
        if let Some(secret_ref) = &provider.api_key {
            let key = secret_ref.resolve().map_err(|e| ProviderError::Credential(e.to_string()))?;
            req = req.header("x-api-key", key.expose());
        }
        send(req).await
    }
}

impl Default for Anthropic {
    fn default() -> Self {
        Self::new()
    }
}

/// Re-frames an Anthropic SSE stream as OpenAI `chat.completion.chunk` SSE.
fn anthropic_stream_as_openai(upstream: BoxStream<'static, Result<Bytes, ProviderError>>) -> BoxStream<'static, Result<Bytes, ProviderError>> {
    let mut parser = SseParser::default();
    let mut tr = AnthropicToOpenAiStream::new();
    upstream
        .map(move |item| {
            item.map(|bytes| {
                let mut out = String::new();
                for data in parser.push(&bytes) {
                    let Ok(ev) = serde_json::from_str::<serde_json::Value>(&data) else { continue };
                    for payload in tr.push(&ev) {
                        out.push_str("data: ");
                        out.push_str(&payload);
                        out.push_str("\n\n");
                    }
                }
                Bytes::from(out)
            })
        })
        .boxed()
}

#[async_trait]
impl Provider for Anthropic {
    async fn chat(&self, provider: &ProviderConfig, body: serde_json::Value, stream: bool) -> Result<ProviderResponse, ProviderError> {
        let req = anth::to_anthropic_request(&body, anth::DEFAULT_MAX_TOKENS);
        let resp = self.post(provider, &req, &NativeOptions::default()).await?;
        if stream {
            Ok(ProviderResponse::Stream(anthropic_stream_as_openai(byte_stream(resp))))
        } else {
            let v: serde_json::Value = resp.json().await.map_err(|e| ProviderError::Transport(e.to_string()))?;
            Ok(ProviderResponse::Json(anth::to_openai_response(&v)))
        }
    }

    async fn embeddings(&self, provider: &ProviderConfig, _body: serde_json::Value) -> Result<serde_json::Value, ProviderError> {
        Err(ProviderError::Unsupported(provider.kind))
    }

    async fn messages(&self, provider: &ProviderConfig, body: serde_json::Value, stream: bool, opts: &NativeOptions) -> Result<ProviderResponse, ProviderError> {
        let resp = self.post(provider, &body, opts).await?;
        if stream {
            Ok(ProviderResponse::Stream(byte_stream(resp)))
        } else {
            let v = resp.json().await.map_err(|e| ProviderError::Transport(e.to_string()))?;
            Ok(ProviderResponse::Json(v))
        }
    }
}

/// Picks the adapter for a provider kind.
#[derive(Default)]
pub struct Providers {
    openai: OpenAiCompatible,
    anthropic: Anthropic,
}

impl Providers {
    pub fn adapter(&self, kind: ProviderKind) -> Result<&dyn Provider, ProviderError> {
        match kind {
            ProviderKind::Openai | ProviderKind::OpenaiCompatible => Ok(&self.openai),
            ProviderKind::Anthropic => Ok(&self.anthropic),
            other => Err(ProviderError::Unsupported(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};

    type Seen = Arc<Mutex<Vec<(HeaderMap, Value)>>>;

    async fn mock() -> (String, Seen) {
        let seen: Seen = Arc::default();
        let s = Arc::clone(&seen);
        let app = axum::Router::new().route(
            "/v1/messages",
            post(move |h: HeaderMap, Json(b): Json<Value>| {
                let s = Arc::clone(&s);
                async move {
                    let stream = b["stream"].as_bool().unwrap_or(false);
                    s.lock().unwrap().push((h, b));
                    if stream {
                        let evs = [
                            json!({"type": "message_start", "message": {"id": "msg_9", "model": "claude-up", "usage": {"input_tokens": 7, "output_tokens": 1}}}),
                            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
                            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi there"}}),
                            json!({"type": "content_block_stop", "index": 0}),
                            json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 3}}),
                            json!({"type": "message_stop"}),
                        ];
                        let body: String = evs.iter().map(anth::sse_event).collect();
                        axum::response::Response::builder().header("content-type", "text/event-stream").body(axum::body::Body::from(body)).unwrap()
                    } else {
                        let v = json!({"id": "msg_9", "type": "message", "model": "claude-up", "stop_reason": "end_turn",
                            "content": [{"type": "text", "text": "Hi there"}], "usage": {"input_tokens": 7, "output_tokens": 3}});
                        axum::response::IntoResponse::into_response(Json(v))
                    }
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (format!("http://{addr}/v1"), seen)
    }

    fn provider(base: String) -> ProviderConfig {
        let path = std::env::temp_dir().join(format!("caliban-test-anthropic-key-{}", std::process::id()));
        std::fs::write(&path, "sk-ant-test").unwrap();
        let api_key = caliban_config::SecretRef::File { file: path.display().to_string() };
        ProviderConfig { id: "anth".into(), kind: ProviderKind::Anthropic, base_url: base, trust_tier: caliban_types::TrustTier::T2Contracted, api_key: Some(api_key), cache_salt: false }
    }

    #[tokio::test]
    async fn openai_shaped_call_is_translated_both_ways() {
        let (base, seen) = mock().await;
        let p = provider(base);
        let a = Providers::default();
        let body = json!({"model": "claude-up", "messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hello"}], "stream_options": {"include_usage": true}});
        let ProviderResponse::Json(v) = a.adapter(ProviderKind::Anthropic).unwrap().chat(&p, body, false).await.unwrap() else { panic!() };
        assert_eq!(v["choices"][0]["message"]["content"], "Hi there");
        assert_eq!(v["usage"]["completion_tokens"], 3);
        let (h, sent) = seen.lock().unwrap()[0].clone();
        assert_eq!(h["x-api-key"], "sk-ant-test");
        assert_eq!(h["anthropic-version"], anth::API_VERSION);
        assert!(h.get("authorization").is_none());
        assert_eq!(sent["system"], "be brief");
        assert_eq!(sent["max_tokens"], anth::DEFAULT_MAX_TOKENS);
        assert!(sent.get("stream_options").is_none());

        let body = json!({"model": "claude-up", "stream": true, "messages": [{"role": "user", "content": "hello"}]});
        let ProviderResponse::Stream(mut s) = a.adapter(ProviderKind::Anthropic).unwrap().chat(&p, body, true).await.unwrap() else { panic!() };
        let mut text = String::new();
        while let Some(b) = s.next().await {
            text.push_str(std::str::from_utf8(&b.unwrap()).unwrap());
        }
        assert!(text.contains(r#""content":"Hi there""#), "{text}");
        assert!(text.contains(r#""completion_tokens":3"#), "{text}");
        assert!(text.trim_end().ends_with("data: [DONE]"));
    }

    #[tokio::test]
    async fn native_passthrough_keeps_body_and_forwards_beta() {
        let (base, seen) = mock().await;
        let p = provider(base);
        let body = json!({"model": "claude-up", "max_tokens": 10, "system": [{"type": "text", "text": "s", "cache_control": {"type": "ephemeral"}}], "messages": [{"role": "user", "content": "x"}]});
        let opts = NativeOptions { anthropic_version: None, anthropic_beta: Some("some-beta-2025".into()) };
        let ProviderResponse::Json(v) = Anthropic::new().messages(&p, body.clone(), false, &opts).await.unwrap() else { panic!() };
        assert_eq!(v["type"], "message");
        let (h, sent) = seen.lock().unwrap()[0].clone();
        assert_eq!(sent, body);
        assert_eq!(h["anthropic-beta"], "some-beta-2025");
        assert!(OpenAiCompatible::new().messages(&p, body, false, &opts).await.is_err());
    }
}
