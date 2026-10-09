//! The request pipeline shared by `/v1/chat/completions` (OpenAI dialect) and `/v1/messages`
//! (Anthropic dialect):
//!
//! auth → rate limit (GCRA) → parse to IR → route → PII protect → token reservation →
//! per candidate: [exact cache] → provider call (BYOK, fallbacks) → rehydrate → translate to the
//! client's dialect → meter + settle reservation + record span.
//!
//! The IR drives every decision. The upstream body is the IR rendered as OpenAI Chat Completions,
//! except when the client speaks Anthropic **and** the routed provider is Anthropic: then the
//! client's native body is passed through (PII applied to its text blocks only), so
//! `cache_control` breakpoints, server tools and thinking signatures survive.

use crate::error::Dialect;
use crate::{ApiError, Gateway, auth, limits, quirks, stream, telemetry};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use caliban_cache::{CacheKeyParts, CachedResponse, cache_key};
use caliban_config::{ModelEntry, ModelKind, ProviderConfig, Snapshot, TenantConfig};
use caliban_ir::anthropic;
use caliban_ir::{ChatRequest, Message, Usage};
use caliban_meter::quota::{Amount, Settlement};
use caliban_meter::{UsageEvent, cost_usd};
use caliban_pii::Rehydrator;
use caliban_providers::{NativeOptions, ProviderResponse};
use caliban_route::RouteError;
use caliban_types::{CacheMode, CacheStatus, CalibanError, PiiMode, ProviderKind, RequestId};
use rand::RngCore;
use serde_json::{Map, Value};
use std::sync::Arc;
use std::time::Instant;
use tracing::{Instrument, Span};

/// Everything the response path needs to know about how the request was handled.
pub(crate) struct Outcome {
    pub request_id: RequestId,
    pub tenant_id: String,
    pub model: ModelEntry,
    pub intent: String,
    pub cache: CacheStatus,
    pub pii_entities: usize,
    pub started: Instant,
    pub dialect: Dialect,
    /// Root `chat {model}` span; kept alive until the response (or stream) is finished.
    pub span: Span,
    /// Prompt estimate used for the reservation (settles streams that end without usage).
    pub est_prompt_tokens: u64,
}

/// Entry point for both chat dialects.
pub(crate) async fn handle(gw: Arc<Gateway>, headers: HeaderMap, body: Bytes, dialect: Dialect) -> Result<Response, ApiError> {
    let request_id = RequestId::new();
    let span = telemetry::request_span("chat", dialect, &request_id);
    telemetry::link_parent(&span, &headers);
    let res = run(gw, &headers, &body, dialect, request_id, span.clone()).instrument(span.clone()).await;
    res.map_err(|e| {
        telemetry::record_error(&span, e.error.kind());
        e.with_dialect(dialect)
    })
}

fn parse(body: &[u8], dialect: Dialect) -> Result<(ChatRequest, Option<Value>), CalibanError> {
    match dialect {
        Dialect::OpenAi => Ok((ChatRequest::from_openai_json(body).map_err(|e| CalibanError::InvalidRequest(e.to_string()))?, None)),
        Dialect::Anthropic => {
            let v: Value = serde_json::from_slice(body).map_err(|e| CalibanError::InvalidRequest(e.to_string()))?;
            let req = anthropic::to_chat_request(&v).map_err(|e| CalibanError::InvalidRequest(e.to_string()))?;
            Ok((req, Some(v)))
        }
    }
}

fn header_str(h: &HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
}

async fn run(gw: Arc<Gateway>, headers: &HeaderMap, body: &[u8], dialect: Dialect, request_id: RequestId, span: Span) -> Result<Response, ApiError> {
    let started = Instant::now();
    let snap = gw.config.load();
    let caller = auth::caller(&snap, headers)?;
    let tenant = caller.tenant.clone();
    span.record("caliban.tenant", tenant.id.as_str());

    let policy = limits::policy(&snap.limits_for(&tenant));
    limits::check_rate(&gw, tenant.id.as_str(), Some(&caller.key_hash), &policy).await?;

    let (req, native) = parse(body, dialect)?;
    span.record("otel.name", format!("chat {}", req.model));
    span.record("gen_ai.request.model", req.model.as_str());
    if req.messages.is_empty() {
        return Err(CalibanError::InvalidRequest("messages must not be empty".into()).into());
    }
    let native_opts = NativeOptions { anthropic_version: header_str(headers, "anthropic-version"), anthropic_beta: header_str(headers, "anthropic-beta") };
    let ext = req.ext();
    let pii_mode = ext.pii.unwrap_or_else(|| snap.pii_mode_for(&tenant));

    let decision = {
        let s = telemetry::child("route");
        let _g = s.enter();
        let d = gw.router.route(&snap, &tenant, &req, caliban_route::Constraints::default()).map_err(|e| match e {
            RouteError::UnknownModel(_) => CalibanError::InvalidRequest(e.to_string()),
            _ => CalibanError::PolicyViolation(e.to_string()),
        })?;
        s.record("caliban.route.intent", d.intent.as_str());
        s.record("caliban.route.stage", d.stage);
        s.record("caliban.route.candidates", d.candidates.len());
        d
    };
    span.record("caliban.route.intent", decision.intent.as_str());
    span.record("caliban.route.stage", decision.stage);

    // Pseudonymize once with a fresh per-request scope; the protected copy is only sent to
    // destinations outside the trust boundary. Credentials block the request regardless.
    let (protected_req, protected) = {
        let s = telemetry::child("pii");
        let _g = s.enter();
        s.record("caliban.pii.mode", pii_mode_str(pii_mode));
        let mut scope_key = [0u8; 32];
        rand::rng().fill_bytes(&mut scope_key);
        let mut pr = req.clone();
        let p = gw.pii.protect(&mut pr, pii_mode, &scope_key).map_err(|e| CalibanError::PolicyViolation(e.to_string()))?;
        s.record("caliban.pii.entities", p.entities);
        (pr, p)
    };
    let rehydrator = Arc::new(Rehydrator::new(&protected.vault));

    // Token/USD reservation: prompt estimate + requested output, priced at the first candidate.
    let est_prompt = req.estimate_prompt_tokens();
    let est_out = req.max_output_tokens().unwrap_or(limits::DEFAULT_OUTPUT_RESERVE);
    let usd = decision
        .candidates
        .iter()
        .find_map(|id| snap.model(id))
        .and_then(|m| cost_usd(est_prompt, est_out, m.price_in_per_mtok, m.price_out_per_mtok))
        .unwrap_or(0.0);
    let mut settlement = limits::reserve(&gw, tenant.id.as_str(), &policy, Amount { tokens: est_prompt + est_out, usd }).await?;

    let salt = quirks::tenant_salt(&gw.salt_key, tenant.id.as_str());
    let mut native_protected: Option<NativeProtected> = None;
    let mut last_err = None;
    for (attempt, model_id) in decision.candidates.iter().enumerate() {
        let Some((model, provider)) = resolve(&snap, &tenant, model_id) else {
            continue;
        };
        if model.kind != ModelKind::Chat {
            continue;
        }
        let external = model.trust_tier.is_external() || provider.trust_tier.is_external();
        let use_protected = external && pii_mode != PiiMode::Off;
        let native_body = native.as_ref().filter(|_| provider.kind == ProviderKind::Anthropic);
        let is_native = native_body.is_some();

        let (upstream_body, pii_entities, rh) = match native_body {
            Some(nb) => {
                let (mut b, entities, rh) = if use_protected {
                    if native_protected.is_none() {
                        native_protected = Some(protect_native(&gw, nb, pii_mode)?);
                    }
                    let np = native_protected.as_ref().expect("initialized above");
                    (np.body.clone(), np.entities, Some(Arc::clone(&np.rehydrator)))
                } else {
                    (nb.clone(), 0, None)
                };
                if let Some(o) = b.as_object_mut() {
                    o.insert("model".into(), Value::String(model.upstream_model.clone()));
                    o.remove("caliban");
                }
                (b, entities, rh)
            }
            None => {
                let outgoing = if use_protected { &protected_req } else { &req };
                let mut b = outgoing.to_openai_upstream(&model.upstream_model);
                quirks::shape_request(&mut b, &model, &provider, req.reasoning_pref(), &salt);
                (b, if use_protected { protected.entities } else { 0 }, use_protected.then(|| Arc::clone(&rehydrator)))
            }
        };
        span.record("caliban.pii.entities", pii_entities);
        span.record("gen_ai.provider.name", telemetry::provider_name(provider.kind));

        // T1 exact cache, keyed on the exact upstream body (so native Anthropic and OpenAI-shaped
        // entries never mix). Requests whose surrogates are request-scoped cannot hit (their
        // text differs every time), so they bypass the cache until tenant-scoped surrogates land.
        let native_tools = native_body.is_some_and(|b| b.get("tools").and_then(Value::as_array).is_some_and(|a| !a.is_empty()));
        let cacheable = attempt == 0
            && ext.cache.unwrap_or_default() != CacheMode::Off
            && snap.config.cache.exact_enabled
            && !req.stream
            && !ext.zdr
            && req.is_deterministic()
            && !req.has_tools()
            && !native_tools
            && pii_entities == 0;
        let key = cacheable.then(|| {
            cache_key(&CacheKeyParts {
                tenant: &tenant.id,
                request_hash: body_hash(&upstream_body, model.id.as_str()),
                acl_fingerprint: &[],
                datasource_epochs: &[],
                pii_mode,
            })
        });

        let outcome = Outcome {
            request_id: request_id.clone(),
            tenant_id: tenant.id.to_string(),
            model: model.clone(),
            intent: decision.intent.clone(),
            cache: if cacheable { CacheStatus::Miss } else { CacheStatus::Bypass },
            pii_entities,
            started,
            dialect,
            span: span.clone(),
            est_prompt_tokens: est_prompt,
        };

        if let Some(k) = &key {
            let cs = telemetry::child("cache");
            let hit = gw.cache.get(k).instrument(cs.clone()).await;
            cs.record("caliban.cache", if hit.is_some() { "hit" } else { "miss" });
            if let Some(hit) = hit {
                let outcome = Outcome { cache: CacheStatus::Hit, ..outcome };
                // Cached bodies are upstream-shaped; OpenAI-shaped ones are translated for
                // Anthropic clients.
                let body = if dialect == Dialect::Anthropic && !is_native {
                    let v: Value = serde_json::from_slice(&hit.body).unwrap_or_default();
                    Bytes::from(serde_json::to_vec(&anthropic::from_openai_response(&v)).unwrap_or_default())
                } else {
                    hit.body.clone()
                };
                finish(&gw, &outcome, Usage::default(), hit.prompt_tokens + hit.completion_tokens, settlement, 0).await;
                return Ok(json_response(&outcome, body, Some(0.0)));
            }
        }

        let adapter = gw.providers.adapter(provider.kind).map_err(|e| CalibanError::Upstream(e.to_string()))?;
        let us = telemetry::upstream_span("chat", &model, &provider, attempt, is_native);
        settlement.set_in_flight(true);
        let result = if is_native {
            adapter.messages(&provider, upstream_body, req.stream, &native_opts).instrument(us.clone()).await
        } else {
            adapter.chat(&provider, upstream_body, req.stream).instrument(us.clone()).await
        };
        match result {
            Ok(ProviderResponse::Json(mut v)) => {
                if let Some(m) = v.get("model").and_then(Value::as_str) {
                    us.record("gen_ai.response.model", m);
                }
                let (client_body, cache_body, usage) = if is_native {
                    if let Some(r) = &rh {
                        rehydrate_anthropic(&mut v, r);
                    }
                    set_model(&mut v, &model);
                    let usage = Usage::from_anthropic_usage(v.get("usage").unwrap_or(&Value::Null));
                    let bytes = Bytes::from(serde_json::to_vec(&v).unwrap_or_default());
                    (bytes.clone(), bytes, usage)
                } else {
                    if model.capabilities.inline_think_tags {
                        quirks::normalize_message(&mut v);
                    }
                    if let Some(r) = &rh {
                        rehydrate_message(&mut v, r);
                    }
                    set_model(&mut v, &model);
                    let usage = Usage::from_openai(&v).unwrap_or_default();
                    let bytes = Bytes::from(serde_json::to_vec(&v).unwrap_or_default());
                    let client = match dialect {
                        Dialect::OpenAi => bytes.clone(),
                        Dialect::Anthropic => Bytes::from(serde_json::to_vec(&anthropic::from_openai_response(&v)).unwrap_or_default()),
                    };
                    (client, bytes, usage)
                };
                if let Some(k) = key {
                    gw.cache
                        .put(k, CachedResponse {
                            body: cache_body,
                            model: model.id.to_string(),
                            prompt_tokens: usage.prompt_tokens,
                            completion_tokens: usage.completion_tokens,
                        })
                        .await;
                }
                telemetry::record_usage(&us, usage);
                drop(us);
                let cost = cost_usd(usage.prompt_tokens, usage.completion_tokens, model.price_in_per_mtok, model.price_out_per_mtok);
                finish(&gw, &outcome, usage, 0, settlement, 0).await;
                return Ok(json_response(&outcome, client_body, cost));
            }
            Ok(ProviderResponse::Stream(upstream)) => {
                return Ok(if is_native {
                    stream::native_anthropic(gw, outcome, upstream, rh, settlement, us)
                } else {
                    let think = model.capabilities.inline_think_tags;
                    stream::openai_shaped(gw, outcome, upstream, rh, think, settlement, us)
                });
            }
            Err(e) => {
                settlement.set_in_flight(false);
                telemetry::record_error(&us, e.kind());
                if e.is_retryable() && attempt + 1 < decision.candidates.len() {
                    tracing::warn!(request_id = %request_id, model = %model.id, error = %e, "upstream failed, trying fallback");
                    span.record("caliban.fallbacks", attempt + 1);
                    last_err = Some(e);
                } else {
                    return Err(CalibanError::Upstream(e.to_string()).into());
                }
            }
        }
    }
    Err(CalibanError::Upstream(last_err.map_or_else(|| "no usable candidate model".into(), |e| e.to_string())).into())
}

fn pii_mode_str(m: PiiMode) -> &'static str {
    match m {
        PiiMode::Off => "off",
        PiiMode::Mask => "mask",
        PiiMode::Reversible => "reversible",
    }
}

fn set_model(v: &mut Value, model: &ModelEntry) {
    if let Some(o) = v.as_object_mut() {
        o.insert("model".into(), Value::String(model.id.to_string()));
    }
}

/// A native Anthropic body with PII applied to its text, and the matching rehydrator.
struct NativeProtected {
    body: Value,
    entities: usize,
    rehydrator: Arc<Rehydrator>,
}

/// Applies the PII engine to every client-written text segment of a native Anthropic body
/// (system, text blocks, tool results) in one scope, leaving all other fields untouched.
fn protect_native(gw: &Gateway, native: &Value, mode: PiiMode) -> Result<NativeProtected, CalibanError> {
    let mut body = native.clone();
    let mut texts = Vec::new();
    anthropic::for_each_text_mut(&mut body, |s| texts.push(std::mem::take(s)));
    let mut tmp = ChatRequest {
        model: String::new(),
        messages: texts.into_iter().map(|t| Message { role: "user".into(), content: Value::String(t), extra: Map::new() }).collect(),
        stream: false,
        caliban: None,
        extra: Map::new(),
    };
    let mut scope_key = [0u8; 32];
    rand::rng().fill_bytes(&mut scope_key);
    let p = gw.pii.protect(&mut tmp, mode, &scope_key).map_err(|e| CalibanError::PolicyViolation(e.to_string()))?;
    let mut rewritten = tmp.messages.into_iter().map(|m| match m.content {
        Value::String(s) => s,
        _ => String::new(),
    });
    anthropic::for_each_text_mut(&mut body, |s| {
        if let Some(t) = rewritten.next() {
            *s = t;
        }
    });
    Ok(NativeProtected { body, entities: p.entities, rehydrator: Arc::new(Rehydrator::new(&p.vault)) })
}

/// Model + the provider the tenant reaches it through (own BYOK provider first, then shared pools).
pub(crate) fn resolve(snap: &Snapshot, tenant: &TenantConfig, id: &caliban_types::ModelId) -> Option<(ModelEntry, ProviderConfig)> {
    let model = snap.model(id)?.clone();
    let provider = snap.provider_for(tenant, &model.provider)?.clone();
    Some((model, provider))
}

/// Cache key input: the exact body sent upstream, minus transport-only fields.
fn body_hash(body: &Value, model: &str) -> blake3::Hash {
    let mut b = body.clone();
    if let Some(o) = b.as_object_mut() {
        for k in ["stream", "stream_options", "user", "cache_salt", "metadata"] {
            o.remove(k);
        }
        o.insert("model".into(), Value::String(model.to_owned()));
    }
    blake3::hash(&serde_json::to_vec(&b).unwrap_or_default())
}

/// Restores originals in `content`, `reasoning_content` and tool-call arguments.
fn rehydrate_message(v: &mut Value, rh: &Rehydrator) {
    let Some(choices) = v.get_mut("choices").and_then(Value::as_array_mut) else { return };
    for c in choices {
        for ptr in ["/message/content", "/message/reasoning_content", "/message/reasoning"] {
            if let Some(Value::String(s)) = c.pointer_mut(ptr) {
                *s = rh.rehydrate(s);
            }
        }
        if let Some(calls) = c.pointer_mut("/message/tool_calls").and_then(Value::as_array_mut) {
            for call in calls {
                if let Some(Value::String(a)) = call.pointer_mut("/function/arguments") {
                    *a = rh.rehydrate(a);
                }
            }
        }
    }
}

/// Restores originals in an Anthropic message: text, thinking and every string in tool inputs.
fn rehydrate_anthropic(v: &mut Value, rh: &Rehydrator) {
    fn strings(v: &mut Value, rh: &Rehydrator) {
        match v {
            Value::String(s) => *s = rh.rehydrate(s),
            Value::Array(a) => a.iter_mut().for_each(|x| strings(x, rh)),
            Value::Object(o) => o.values_mut().for_each(|x| strings(x, rh)),
            _ => {}
        }
    }
    let Some(blocks) = v.get_mut("content").and_then(Value::as_array_mut) else { return };
    for b in blocks {
        let field = match b.get("type").and_then(Value::as_str) {
            Some("text") => "text",
            Some("thinking") => "thinking",
            Some("tool_use") => "input",
            _ => continue,
        };
        if let Some(x) = b.get_mut(field) {
            strings(x, rh);
        }
    }
}

pub(crate) fn caliban_headers(h: &mut HeaderMap, o: &Outcome) {
    let mut set = |name: &'static str, val: String| {
        if let Ok(v) = HeaderValue::from_str(&val) {
            h.insert(name, v);
        }
    };
    set("x-caliban-request-id", o.request_id.to_string());
    set("x-caliban-routed-model", o.model.id.to_string());
    set("x-caliban-cache", o.cache.as_str().to_owned());
    set("x-caliban-pii-entities", o.pii_entities.to_string());
    if o.dialect == Dialect::Anthropic {
        // Anthropic SDKs surface this as `_request_id`.
        set("request-id", o.request_id.to_string());
    }
}

/// Non-streaming responses also carry `x-caliban-cost-usd` when the model has prices (streams
/// report cost only in usage events, since it is known after the last chunk).
pub(crate) fn json_response(o: &Outcome, body: Bytes, cost: Option<f64>) -> Response {
    let mut resp = (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], body).into_response();
    caliban_headers(resp.headers_mut(), o);
    if let Some(c) = cost.and_then(|c| HeaderValue::from_str(&format!("{c:.8}")).ok()) {
        resp.headers_mut().insert("x-caliban-cost-usd", c);
    }
    resp
}

/// Completes a request: usage event, quota settlement, span attributes. `streamed_bytes`
/// estimates output when a stream ended without usage (e.g. the client disconnected).
pub(crate) async fn finish(gw: &Gateway, o: &Outcome, usage: Usage, tokens_saved: u64, settlement: Settlement, streamed_bytes: u64) {
    record(gw, o, usage, tokens_saved).await;
    let (tokens, usd) = if o.cache == CacheStatus::Hit {
        (0, 0.0)
    } else {
        let reported = usage.prompt_tokens + usage.completion_tokens;
        let tokens = if reported > 0 { reported } else { o.est_prompt_tokens + streamed_bytes.div_ceil(4) };
        (tokens, cost_usd(usage.prompt_tokens, usage.completion_tokens, o.model.price_in_per_mtok, o.model.price_out_per_mtok).unwrap_or(0.0))
    };
    settlement.settle(Amount { tokens, usd }).await;
    let s = &o.span;
    s.record("caliban.cache", o.cache.as_str());
    s.record("caliban.pii.entities", o.pii_entities);
    s.record("gen_ai.response.model", o.model.id.as_str());
    telemetry::record_usage(s, usage);
}

pub(crate) async fn record(gw: &Gateway, o: &Outcome, usage: Usage, tokens_saved: u64) {
    let event = UsageEvent {
        request_id: o.request_id.to_string(),
        tenant_id: o.tenant_id.clone(),
        model: o.model.id.to_string(),
        intent: o.intent.clone(),
        prompt_tokens: usage.prompt_tokens,
        completion_tokens: usage.completion_tokens,
        cached_prompt_tokens: usage.cached_prompt_tokens,
        tokens_saved,
        cache: o.cache,
        pii_entities: o.pii_entities,
        cost_usd: cost_usd(usage.prompt_tokens, usage.completion_tokens, o.model.price_in_per_mtok, o.model.price_out_per_mtok),
        latency_ms: u64::try_from(o.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        ts: chrono::Utc::now(),
    };
    gw.usage.record(event).await;
}
