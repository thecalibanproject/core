//! Metering helpers shared by every response path:
//!
//! - **Cost.** One function prices a request ([`model_cost`]): uncached input, prompt-cache reads
//!   and writes (the Anthropic 1-hour TTL at its own price) and output, each at the model's price.
//!   The usage event's `cost_usd`, the `x-caliban-cost-usd` header, quota settlement, and the
//!   `caliban/auto` `routed_model_cost_usd` and `flat_price_usd` all use it.
//! - **Usage source.** Every non-hit event says whether its tokens are the provider's report or a
//!   gateway estimate ([`Metered`], [`stream_end`]).
//! - **Usage the client did not ask for.** Usage is always requested upstream on streams; for an
//!   OpenAI client that did not set `stream_options.include_usage: true`, [`strip_usage`] removes
//!   it from what the client receives.

use crate::Gateway;
use caliban_config::{ModelEntry, ModelKind, Snapshot};
use caliban_ir::Usage;
use caliban_meter::{Prices, Tokens, UsageSource, cost};
use caliban_types::ProviderKind;
use serde_json::Value;

/// A model's prices for [`caliban_meter::cost`].
pub(crate) fn prices(m: &ModelEntry) -> Prices {
    Prices {
        input: m.price_in_per_mtok,
        output: m.price_out_per_mtok,
        cache_read: m.price_cache_read_per_mtok,
        cache_write: m.price_cache_write_per_mtok,
        cache_write_1h: m.price_cache_write_1h_per_mtok,
    }
}

pub(crate) fn tokens(u: Usage) -> Tokens {
    Tokens {
        prompt: u.prompt_tokens,
        completion: u.completion_tokens,
        cache_read: u.cached_prompt_tokens,
        cache_write: u.cache_write_tokens,
        cache_write_1h: u.cache_write_1h_tokens,
    }
}

/// What the request cost at the model's prices (`None` without input and output prices).
pub(crate) fn model_cost(m: &ModelEntry, u: Usage) -> Option<f64> {
    cost(tokens(u), prices(m))
}

/// The flat `caliban/auto` price for the same tokens, through the same cost function. The flat
/// price has no cache prices of its own, so cache reads and writes are charged at its input price.
pub(crate) fn flat_cost(flat: (Option<f64>, Option<f64>), u: Usage) -> Option<f64> {
    cost(tokens(u), Prices::flat(flat.0, flat.1))
}

/// Usage to meter, and where it came from (`None` on gateway cache hits: nothing was consumed).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Metered {
    pub usage: Usage,
    pub source: Option<UsageSource>,
}

impl Metered {
    pub(crate) fn provider(usage: Usage) -> Self {
        Self { usage, source: Some(UsageSource::Provider) }
    }

    pub(crate) fn estimated(usage: Usage) -> Self {
        Self { usage, source: Some(UsageSource::Estimated) }
    }

    /// A gateway cache hit (the cached usage only feeds `tokens_saved`).
    pub(crate) fn hit(usage: Usage) -> Self {
        Self { usage, source: None }
    }
}

/// Usage for a stream that has ended, normally or not.
///
/// - `reported`: the provider's usage, if any arrived; `complete`: it covers the whole response
///   (OpenAI's final usage chunk; Anthropic's `message_delta`).
/// - Otherwise (client disconnect, upstream error, no usage sent) the numbers are estimated:
///   prompt tokens from the provider when it already reported them (Anthropic `message_start`),
///   else the request's prompt estimate; completion tokens from the output bytes streamed so far
///   (about 4 bytes per token), never below what the provider already reported. After a client
///   disconnect the provider may still bill more than this: it keeps generating until it notices
///   the cancelled connection.
pub(crate) fn stream_end(reported: Option<Usage>, complete: bool, est_prompt_tokens: u64, streamed_bytes: u64) -> Metered {
    let est_completion = streamed_bytes.div_ceil(4);
    match reported {
        Some(u) if complete => Metered::provider(u),
        Some(u) => Metered::estimated(Usage { completion_tokens: u.completion_tokens.max(est_completion), ..u }),
        None => Metered::estimated(Usage { prompt_tokens: est_prompt_tokens, completion_tokens: est_completion, ..Usage::default() }),
    }
}

/// A non-streaming response without a usage object: prompt estimate plus output bytes / 4.
pub(crate) fn json_estimate(est_prompt_tokens: u64, body: &Value) -> Metered {
    let completion = output_bytes(body).div_ceil(4);
    Metered::estimated(Usage { prompt_tokens: est_prompt_tokens, completion_tokens: completion, ..Usage::default() })
}

/// Output text bytes of a complete response, OpenAI (`choices[].message`) or Anthropic (`content`).
fn output_bytes(v: &Value) -> u64 {
    let s = |x: Option<&Value>| x.and_then(Value::as_str).map_or(0, str::len) as u64;
    let mut n = 0;
    for c in v.get("choices").and_then(Value::as_array).into_iter().flatten() {
        let m = c.get("message");
        for k in ["content", "reasoning_content", "reasoning"] {
            n += s(m.and_then(|m| m.get(k)));
        }
        for tc in m.and_then(|m| m.get("tool_calls")).and_then(Value::as_array).into_iter().flatten() {
            n += s(tc.pointer("/function/arguments"));
        }
    }
    for b in v.get("content").and_then(Value::as_array).into_iter().flatten() {
        n += s(b.get("text")) + s(b.get("thinking"));
        if let Some(input) = b.get("input") {
            n += input.to_string().len() as u64;
        }
    }
    n
}

/// Did an OpenAI-dialect client ask for stream usage (`stream_options.include_usage: true`)?
pub(crate) fn client_wants_stream_usage(extra: &serde_json::Map<String, Value>) -> bool {
    extra.get("stream_options").and_then(|o| o.get("include_usage")).and_then(Value::as_bool) == Some(true)
}

/// Removes usage from an OpenAI chunk for a client that did not ask for it. Returns `true` when
/// the chunk carried nothing else (the final usage-only chunk) and must not be sent at all.
pub(crate) fn strip_usage(v: &mut Value) -> bool {
    let Some(o) = v.as_object_mut() else { return false };
    let had_usage = o.remove("usage").is_some_and(|u| !u.is_null());
    had_usage && o.get("choices").and_then(Value::as_array).is_none_or(Vec::is_empty)
}

/// Startup check: chat models on providers that report prompt-cache tokens (Anthropic, OpenAI)
/// whose cost would be computed without cache prices. Returns the model ids.
pub(crate) fn models_missing_cache_prices(snap: &Snapshot) -> Vec<String> {
    let cfg = &snap.config;
    let kind_of = |id: &caliban_types::ProviderId| {
        cfg.providers
            .iter()
            .map(|p| &p.provider)
            .chain(cfg.tenants.iter().flat_map(|t| t.providers.iter()))
            .find(|p| &p.id == id)
            .map(|p| p.kind)
    };
    cfg.models
        .iter()
        .filter(|m| m.kind == ModelKind::Chat && !m.has_cache_prices() && m.price_in_per_mtok.is_some_and(|p| p > 0.0))
        .filter(|m| matches!(kind_of(&m.provider), Some(ProviderKind::Anthropic | ProviderKind::Openai)))
        .map(|m| m.id.to_string())
        .collect()
}

/// Logs the startup warning for [`models_missing_cache_prices`].
pub(crate) fn warn_missing_cache_prices_at_startup(snap: &Snapshot) {
    let missing = models_missing_cache_prices(snap);
    if !missing.is_empty() {
        tracing::warn!(
            models = %missing.join(", "),
            "these models' providers report prompt-cache tokens, but no cache prices are configured \
             (price_cache_read_per_mtok, price_cache_write_per_mtok): cache reads and writes are \
             metered at the input price, which overstates cost against the provider's bill"
        );
    }
}

/// Runtime check, once per model per process: the provider reported cache reads or writes for a
/// priced model without cache prices.
pub(crate) fn warn_once_if_unpriced_cache(gw: &Gateway, m: &ModelEntry, u: Usage) {
    if (u.cached_prompt_tokens == 0 && u.cache_write_tokens == 0) || m.has_cache_prices() || !m.price_in_per_mtok.is_some_and(|p| p > 0.0) {
        return;
    }
    let first = gw.cache_price_warned.lock().map(|mut s| s.insert(m.id.to_string())).unwrap_or(false);
    if first {
        tracing::warn!(
            model = %m.id,
            cached = u.cached_prompt_tokens,
            cache_writes = u.cache_write_tokens,
            "the provider reported prompt-cache tokens but the model has no cache prices; they are metered at the input price"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn complete_provider_usage_is_kept() {
        let u = Usage { prompt_tokens: 10, completion_tokens: 3, ..Usage::default() };
        let m = stream_end(Some(u), true, 99, 400);
        assert_eq!((m.usage, m.source), (u, Some(UsageSource::Provider)));
    }

    #[test]
    fn missing_usage_is_estimated_from_the_prompt_and_streamed_bytes() {
        let m = stream_end(None, false, 42, 401);
        assert_eq!((m.usage.prompt_tokens, m.usage.completion_tokens, m.source), (42, 101, Some(UsageSource::Estimated)));
    }

    #[test]
    fn partial_provider_usage_keeps_the_provider_prompt() {
        // Anthropic `message_start` seen (exact input and cache tokens), no `message_delta`.
        let u = Usage { prompt_tokens: 500, completion_tokens: 1, cached_prompt_tokens: 400, ..Usage::default() };
        let m = stream_end(Some(u), false, 7, 80);
        assert_eq!((m.usage.prompt_tokens, m.usage.cached_prompt_tokens, m.usage.completion_tokens), (500, 400, 20));
        assert_eq!(m.source, Some(UsageSource::Estimated));
    }

    #[test]
    fn usage_is_stripped_for_clients_that_did_not_ask() {
        let mut only = json!({"id": "c", "choices": [], "usage": {"prompt_tokens": 1}});
        assert!(strip_usage(&mut only), "usage-only chunk is dropped");
        let mut with_choice = json!({"id": "c", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1}});
        assert!(!strip_usage(&mut with_choice));
        assert!(with_choice.get("usage").is_none(), "usage removed, chunk kept");
        // OpenAI sends `"usage": null` on every chunk once usage is requested.
        let mut null = json!({"id": "c", "choices": [{"index": 0, "delta": {"content": "x"}}], "usage": null});
        assert!(!strip_usage(&mut null));
        assert!(null.get("usage").is_none());
        let mut plain = json!({"id": "c", "choices": []});
        assert!(!strip_usage(&mut plain), "an empty chunk without usage is passed through as before");
    }

    #[test]
    fn client_usage_opt_in() {
        let m = |v: Value| v.as_object().cloned().unwrap();
        assert!(client_wants_stream_usage(&m(json!({"stream_options": {"include_usage": true}}))));
        assert!(!client_wants_stream_usage(&m(json!({"stream_options": {"include_usage": false}}))));
        assert!(!client_wants_stream_usage(&m(json!({}))));
    }
}
