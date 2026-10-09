//! Logging and OpenTelemetry GenAI tracing (request lifecycle stage 14).
//!
//! - Logs: `fmt` to stdout, filtered by `CALIBAN_LOG` (default `info,tower_http=info`).
//! - Traces: **off by default** (on-prem rule). Exported over OTLP HTTP/protobuf only when
//!   `OTEL_EXPORTER_OTLP_ENDPOINT` (or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) is set; the standard
//!   `OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_HEADERS` and `OTEL_SDK_DISABLED` are honoured.
//!
//! Span tree per request (OTel GenAI semantic conventions):
//! ```text
//! chat {model}            gen_ai.operation.name, gen_ai.provider.name, gen_ai.request.model,
//!  │                      gen_ai.response.model, gen_ai.usage.input_tokens/output_tokens,
//!  │                      caliban.tenant, caliban.cache, caliban.pii.entities,
//!  │                      caliban.route.intent, caliban.route.stage, error.type
//!  ├─ route
//!  ├─ pii
//!  ├─ cache
//!  └─ chat {upstream_model}   (client span, one per attempt incl. fallbacks)
//! ```
//! **Prompt and response content are never recorded**: only spans and events with the
//! [`TARGET`] target are exported, and those carry ids, counts and labels only. (Ordinary log
//! events, which may include truncated upstream error bodies, never reach the exporter.)

use crate::error::Dialect;
use caliban_config::{ModelEntry, ProviderConfig};
use caliban_ir::Usage;
use caliban_types::{ProviderKind, RequestId};
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::Span;
use tracing::field::Empty;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Target of every span/event that may be exported. Nothing else reaches the OTLP exporter.
pub const TARGET: &str = "caliban::genai";

/// Flushes and shuts down the exporter when dropped (keep it alive for the life of `main`).
pub struct TelemetryGuard {
    provider: SdkTracerProvider,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Err(e) = self.provider.shutdown() {
            eprintln!("caliban: OTLP shutdown: {e}");
        }
    }
}

/// Installs the global tracing subscriber (logs + optional OTLP traces). Returns a guard only
/// when trace export is enabled. Safe to call more than once (later calls keep the first
/// subscriber).
pub fn init() -> Option<TelemetryGuard> {
    let fmt_filter = EnvFilter::try_from_env("CALIBAN_LOG").unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));
    let fmt = tracing_subscriber::fmt::layer().with_filter(fmt_filter);
    let provider = otlp_provider();
    let otel = provider
        .as_ref()
        .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer("caliban")).with_filter(export_filter()));
    if tracing_subscriber::registry().with(fmt).with(otel).try_init().is_err() {
        return None;
    }
    if provider.is_some() {
        tracing::info!("OpenTelemetry trace export enabled (OTLP http/protobuf)");
    }
    provider.map(|provider| TelemetryGuard { provider })
}

/// The filter applied to the OTLP layer: Caliban GenAI spans only.
pub fn export_filter() -> Targets {
    Targets::new().with_target(TARGET, LevelFilter::INFO)
}

fn env_set(k: &str) -> bool {
    std::env::var(k).is_ok_and(|v| !v.trim().is_empty())
}

fn otlp_provider() -> Option<SdkTracerProvider> {
    if !(env_set("OTEL_EXPORTER_OTLP_ENDPOINT") || env_set("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")) {
        return None;
    }
    if std::env::var("OTEL_SDK_DISABLED").is_ok_and(|v| v.eq_ignore_ascii_case("true")) {
        return None;
    }
    if let Ok(p) = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL")
        && p.starts_with("grpc")
    {
        eprintln!("caliban: OTEL_EXPORTER_OTLP_PROTOCOL={p} is not supported; exporting with http/protobuf");
    }
    // Endpoint, headers and timeout come from the standard OTEL_EXPORTER_OTLP_* variables.
    let exporter = match opentelemetry_otlp::SpanExporter::builder().with_http().build() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("caliban: OTLP exporter disabled: {e}");
            return None;
        }
    };
    let service = std::env::var("OTEL_SERVICE_NAME").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "caliban".into());
    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service)
        .with_attribute(opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build();
    Some(SdkTracerProvider::builder().with_batch_exporter(exporter).with_resource(resource).build())
}

/// `gen_ai.provider.name` (well-known values where they exist).
pub(crate) fn provider_name(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::Openai => "openai",
        ProviderKind::Anthropic => "anthropic",
        ProviderKind::OpenaiCompatible => "openai_compatible",
        ProviderKind::AzureOpenai => "azure.ai.openai",
        ProviderKind::Bedrock => "aws.bedrock",
        ProviderKind::Vertex => "gcp.vertex_ai",
    }
}

/// Root span for one data-plane request. Named `{op}` until the body is parsed, then
/// `{op} {model}` (callers record `otel.name` and `gen_ai.request.model`).
pub(crate) fn request_span(op: &'static str, dialect: Dialect, request_id: &RequestId) -> Span {
    tracing::info_span!(
        target: TARGET,
        "gen_ai.request",
        otel.name = op,
        otel.kind = "server",
        otel.status_code = Empty,
        gen_ai.operation.name = op,
        gen_ai.provider.name = Empty,
        gen_ai.request.model = Empty,
        gen_ai.response.model = Empty,
        gen_ai.usage.input_tokens = Empty,
        gen_ai.usage.output_tokens = Empty,
        error.type = Empty,
        caliban.request_id = %request_id,
        caliban.dialect = dialect.as_str(),
        caliban.tenant = Empty,
        caliban.cache = Empty,
        caliban.pii.entities = Empty,
        caliban.route.intent = Empty,
        caliban.route.stage = Empty,
        caliban.fallbacks = Empty,
    )
}

/// Client span for one upstream attempt.
pub(crate) fn upstream_span(op: &'static str, model: &ModelEntry, provider: &ProviderConfig, attempt: usize, native: bool) -> Span {
    tracing::info_span!(
        target: TARGET,
        "upstream",
        otel.name = %format!("{op} {}", model.upstream_model),
        otel.kind = "client",
        otel.status_code = Empty,
        gen_ai.operation.name = op,
        gen_ai.provider.name = provider_name(provider.kind),
        gen_ai.request.model = %model.upstream_model,
        gen_ai.response.model = Empty,
        gen_ai.usage.input_tokens = Empty,
        gen_ai.usage.output_tokens = Empty,
        server.address = %host_of(&provider.base_url),
        error.type = Empty,
        caliban.provider.id = %provider.id,
        caliban.attempt = attempt,
        caliban.native = native,
    )
}

pub(crate) fn child(name: &'static str) -> Span {
    match name {
        "route" => tracing::info_span!(target: TARGET, "route", caliban.route.intent = Empty, caliban.route.stage = Empty, caliban.route.candidates = Empty),
        "pii" => tracing::info_span!(target: TARGET, "pii", caliban.pii.mode = Empty, caliban.pii.surrogate_scope = Empty, caliban.pii.entities = Empty),
        _ => tracing::info_span!(target: TARGET, "cache", caliban.cache = Empty),
    }
}

/// Usage + response model on a span (request or upstream).
pub(crate) fn record_usage(span: &Span, usage: Usage) {
    span.record("gen_ai.usage.input_tokens", usage.prompt_tokens);
    span.record("gen_ai.usage.output_tokens", usage.completion_tokens);
}

pub(crate) fn record_error(span: &Span, kind: &str) {
    span.record("error.type", kind);
    span.record("otel.status_code", "ERROR");
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?']).next().unwrap_or(rest)
}

struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(axum::http::HeaderName::as_str).collect()
    }
}

/// Continues a caller's W3C trace (`traceparent`) when present.
pub(crate) fn link_parent(span: &Span, headers: &axum::http::HeaderMap) {
    if headers.contains_key("traceparent") {
        let cx = TraceContextPropagator::new().extract(&HeaderExtractor(headers));
        let _ = span.set_parent(cx);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_extraction() {
        assert_eq!(super::host_of("http://llm:8000/v1"), "llm:8000");
        assert_eq!(super::host_of("https://api.anthropic.com/v1"), "api.anthropic.com");
    }

    #[test]
    fn export_is_off_without_endpoint() {
        if !super::env_set("OTEL_EXPORTER_OTLP_ENDPOINT") && !super::env_set("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") {
            assert!(super::otlp_provider().is_none());
        }
    }
}
