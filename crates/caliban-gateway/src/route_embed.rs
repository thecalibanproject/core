//! Glue between the router (`caliban-route`) and the gateway: the adapter from the gateway's
//! single [`Embedder`](caliban_types::Embedder) (`ProviderEmbedder`) to the router's [`PromptEmbedder`], the routing call
//! used by the chat pipeline, and the background refresh of the routing assets (exemplar index,
//! kNN calibration, router profile).
//!
//! The routing embedder is `[routing] embedding_model`, served by a shared (deployment) provider
//! such as an on-prem TEI or vLLM embedding server: exemplars are embedded once for the whole
//! deployment, so no tenant's BYOK key is used for them, and prompts must land in the same space.
//! Every call therefore goes through [`Embedder::embed_shared`](caliban_types::Embedder::embed_shared), which never resolves a tenant's
//! own provider. When that provider is outside the trust boundary, prompts are PII-masked before
//! they are embedded (as on `/v1/embeddings`); a T0 embedder avoids both the egress and the
//! masking latency.
//!
//! The same `ProviderEmbedder` serves the T2 semantic cache. Its LRU is keyed by tenant, model,
//! endpoint and text, so when T2 embeds the same prompt with the same model through the same
//! endpoint later in the request (no `query_prefix`, no masked PII, prompt under
//! `MAX_EMBED_CHARS`), it reuses the routing vector instead of calling the embedder again.

use crate::Gateway;
use crate::embeddings::mask_texts;
use async_trait::async_trait;
use caliban_config::{Snapshot, TenantConfig};
use caliban_ir::ChatRequest;
use caliban_route::{AlwaysHealthy, Constraints, EmbedError, PromptEmbedder, RouteDecision, RouteError};
use caliban_types::{ModelId, PiiMode, TenantId};
use std::sync::Arc;

/// [`PromptEmbedder`] over the gateway's [`Embedder`](caliban_types::Embedder), pinned to the routing model's shared provider.
pub(crate) struct RouteEmbedder<'a> {
    gw: &'a Gateway,
    model: ModelId,
    /// Whose prompts these are (`None`: the deployment's exemplars).
    tenant: Option<TenantId>,
    /// Vector space id: model id, upstream model and the shared provider's endpoint.
    space: String,
    /// Mask PII before prompt text leaves the trust boundary.
    mask: bool,
}

impl<'a> RouteEmbedder<'a> {
    fn new(gw: &'a Gateway, snap: &Snapshot, tenant: Option<&TenantConfig>) -> Option<Self> {
        let (model, shared) = caliban_route::routing_embedder(snap)?;
        if let Some(t) = tenant
            && !shared.allows(&t.id)
        {
            return None;
        }
        let external = model.trust_tier.is_external() || shared.provider.trust_tier.is_external();
        Some(Self {
            gw,
            model: model.id.clone(),
            tenant: tenant.map(|t| t.id.clone()),
            space: space_id(&model.id, &model.upstream_model, &shared.provider.base_url),
            mask: tenant.is_some_and(|t| external && snap.pii_mode_for(t) != PiiMode::Off),
        })
    }

    /// The embedder for one tenant's prompts, if the shared provider serves that tenant.
    pub(crate) fn for_tenant(gw: &'a Gateway, snap: &Snapshot, tenant: &TenantConfig) -> Option<Self> {
        Self::new(gw, snap, Some(tenant))
    }

    /// The embedder for the deployment's exemplar set (Caliban-authored or operator-supplied text).
    pub(crate) fn for_exemplars(gw: &'a Gateway, snap: &Snapshot) -> Option<Self> {
        Self::new(gw, snap, None)
    }
}

/// Exemplar vectors are only comparable with prompt vectors from the same space; the router's
/// exemplar cache (memory and disk) is keyed by this.
fn space_id(model: &ModelId, upstream_model: &str, base_url: &str) -> String {
    format!("{model}|{upstream_model}|{base_url}")
}

fn route_error(e: caliban_types::EmbedError) -> EmbedError {
    use caliban_types::EmbedError as E;
    match e {
        E::Unavailable(m) => EmbedError::Unavailable(m),
        E::Timeout => EmbedError::Upstream("embedding timed out".into()),
        E::Upstream(m) | E::Invalid(m) => EmbedError::Upstream(m),
    }
}

#[async_trait]
impl PromptEmbedder for RouteEmbedder<'_> {
    fn space_id(&self) -> String {
        self.space.clone()
    }

    async fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbedError> {
        let input = if self.mask { mask_texts(self.gw, texts.to_vec()).await.map_err(|e| EmbedError::Unavailable(e.error.to_string()))?.0 } else { texts.to_vec() };
        let out = self.gw.embedder.embed_shared(self.tenant.as_ref(), &self.model, &input).await.map_err(route_error)?;
        if out.len() != texts.len() {
            return Err(EmbedError::Count { want: texts.len(), got: out.len() });
        }
        Ok(out)
    }
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
