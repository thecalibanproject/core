//! Glue between the router (`caliban-route`) and the gateway: a thin [`PromptEmbedder`] over the
//! provider embeddings path, the routing call used by the chat pipeline, and the background
//! refresh of the routing assets (exemplar index, kNN calibration, router profile).
//!
//! The routing embedder is `[routing] embedding_model`, served by a shared (deployment) provider
//! such as an on-prem TEI or vLLM embedding server: exemplars are embedded once for the whole
//! deployment, so no tenant's BYOK key is used for them. When that provider is outside the trust
//! boundary, prompts are PII-masked before they are embedded (as on `/v1/embeddings`); a T0
//! embedder avoids both the egress and the masking latency.

use crate::Gateway;
use crate::embeddings::mask_texts;
use async_trait::async_trait;
use caliban_config::{ModelEntry, ProviderConfig, Snapshot, TenantConfig};
use caliban_ir::ChatRequest;
use caliban_route::{AlwaysHealthy, Constraints, EmbedError, PromptEmbedder, RouteDecision, RouteError};
use caliban_types::PiiMode;
use serde_json::{Value, json};
use std::sync::Arc;

pub(crate) struct RouteEmbedder<'a> {
    gw: &'a Gateway,
    model: &'a ModelEntry,
    provider: &'a ProviderConfig,
    /// Mask PII before prompt text leaves the trust boundary.
    mask: bool,
}

impl<'a> RouteEmbedder<'a> {
    /// The embedder for one tenant's prompts, if the shared provider serves that tenant.
    pub(crate) fn for_tenant(gw: &'a Gateway, snap: &'a Snapshot, tenant: &TenantConfig) -> Option<Self> {
        let (model, shared) = caliban_route::routing_embedder(snap)?;
        if !shared.allows(&tenant.id) {
            return None;
        }
        let external = model.trust_tier.is_external() || shared.provider.trust_tier.is_external();
        Some(Self { gw, model, provider: &shared.provider, mask: external && snap.pii_mode_for(tenant) != PiiMode::Off })
    }

    /// The embedder for the deployment's exemplar set (Caliban-authored or operator-supplied text).
    pub(crate) fn for_exemplars(gw: &'a Gateway, snap: &'a Snapshot) -> Option<Self> {
        let (model, shared) = caliban_route::routing_embedder(snap)?;
        Some(Self { gw, model, provider: &shared.provider, mask: false })
    }
}

#[async_trait]
impl PromptEmbedder for RouteEmbedder<'_> {
    fn space_id(&self) -> String {
        format!("{}|{}|{}", self.model.id, self.model.upstream_model, self.provider.base_url)
    }

    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        let input = if self.mask { mask_texts(self.gw, texts.to_vec()).map_err(|e| EmbedError::Unavailable(e.to_string()))?.0 } else { texts.to_vec() };
        let adapter = self.gw.providers.adapter(self.provider.kind).map_err(|e| EmbedError::Unavailable(e.to_string()))?;
        let out = adapter
            .embeddings(self.provider, json!({"model": self.model.upstream_model, "input": input}))
            .await
            .map_err(|e| EmbedError::Upstream(e.to_string()))?;
        parse_embeddings(&out, texts.len())
    }
}

/// OpenAI `/embeddings` response → vectors in input order.
fn parse_embeddings(v: &Value, want: usize) -> Result<Vec<Vec<f32>>, EmbedError> {
    let data = v.get("data").and_then(Value::as_array).ok_or_else(|| EmbedError::Upstream("response has no data array".into()))?;
    let mut out: Vec<Option<Vec<f32>>> = vec![None; want];
    for (pos, d) in data.iter().enumerate() {
        let i = d.get("index").and_then(Value::as_u64).and_then(|i| usize::try_from(i).ok()).unwrap_or(pos);
        #[allow(clippy::cast_possible_truncation)]
        let vec: Option<Vec<f32>> = d.get("embedding").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_f64).map(|x| x as f32).collect());
        match (out.get_mut(i), vec) {
            (Some(slot), Some(e)) if !e.is_empty() => *slot = Some(e),
            _ => return Err(EmbedError::Upstream(format!("bad embedding at index {i}"))),
        }
    }
    let got = out.iter().filter(|x| x.is_some()).count();
    if got != want || data.len() != want {
        return Err(EmbedError::Count { want, got: data.len() });
    }
    Ok(out.into_iter().flatten().collect())
}

/// What the response headers and the usage event need from the routing decision.
#[derive(Debug, Clone)]
pub(crate) struct RouteMeta {
    /// `x-caliban-intent` value.
    pub header: String,
    pub confidence: f32,
    pub stage: &'static str,
    /// The client asked for `caliban/auto`: meter the routed cost next to the flat price.
    pub auto: bool,
    pub requested_model: String,
    /// Flat `caliban/auto` price per million tokens (in, out) for this tenant.
    pub flat_price: (Option<f64>, Option<f64>),
}

impl RouteMeta {
    pub(crate) fn new(d: &RouteDecision, snap: &Snapshot, tenant: &TenantConfig, req: &ChatRequest) -> Self {
        Self {
            header: d.intent_header(),
            confidence: d.confidence,
            stage: d.stage,
            auto: d.auto,
            requested_model: req.model.clone(),
            flat_price: snap.config.routing.auto_price_for(&tenant.id),
        }
    }
}

/// Routes a chat request: Stage 0 rules, Stage-1 kNN within `[routing] budget_ms`, then the
/// quality-floor policy. Also kicks off a background asset refresh when the snapshot changed.
pub(crate) async fn route(gw: &Arc<Gateway>, snap: &Arc<Snapshot>, tenant: &TenantConfig, req: &ChatRequest) -> Result<RouteDecision, RouteError> {
    spawn_refresh_if_needed(gw, snap);
    let embedder = RouteEmbedder::for_tenant(gw, snap, tenant);
    gw.router
        .route_auto(snap, tenant, req, Constraints::default(), embedder.as_ref().map(|e| e as &dyn PromptEmbedder), &AlwaysHealthy)
        .await
}

/// Starts a background refresh of the routing assets when the snapshot changed them.
pub(crate) fn spawn_refresh_if_needed(gw: &Arc<Gateway>, snap: &Arc<Snapshot>) {
    if !gw.router.needs_refresh(snap) {
        return;
    }
    let (gw, snap) = (Arc::clone(gw), Arc::clone(snap));
    tokio::spawn(async move { refresh(&gw, &snap).await });
}

/// Rebuilds the routing assets now and logs what was loaded.
pub(crate) async fn refresh(gw: &Gateway, snap: &Snapshot) {
    let embedder = RouteEmbedder::for_exemplars(gw, snap);
    let rep = gw.router.refresh(snap, embedder.as_ref().map(|e| e as &dyn PromptEmbedder)).await;
    for w in &rep.warnings {
        tracing::warn!(target: "caliban_route", "{w}");
    }
    for e in &rep.errors {
        tracing::error!(target: "caliban_route", "Stage-1 kNN unavailable, routing by rules until the next retry: {e}");
    }
    if rep.errors.is_empty() && snap.config.routing.embedding_model.is_some() {
        tracing::info!(
            target: "caliban_route",
            exemplars = rep.exemplars,
            intents = rep.intents,
            from_cache = rep.from_cache,
            embed_ms = rep.embed_ms,
            calibration = ?rep.calibration,
            profile = ?rep.profile,
            "Stage-1 kNN ready"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeddings_are_reordered_by_index_and_counted() {
        let v = json!({"data": [{"index": 1, "embedding": [0.0, 1.0]}, {"index": 0, "embedding": [1.0, 0.0]}]});
        assert_eq!(parse_embeddings(&v, 2).unwrap(), vec![vec![1.0, 0.0], vec![0.0, 1.0]]);
        assert!(parse_embeddings(&v, 3).is_err());
        assert!(parse_embeddings(&json!({"data": [{"index": 5, "embedding": [1.0]}]}), 1).is_err());
        assert!(parse_embeddings(&json!({"error": "x"}), 1).is_err());
    }
}
