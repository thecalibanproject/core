//! Stage 4: pick concrete models for an intent.
//!
//! 1. **Candidates**: the tenant's route for the intent, else its `default` route, else (a tenant
//!    without any route table) every chat model it can reach, in catalogue order. The route table
//!    is the tenant's allow-list: nothing outside it is ever chosen.
//! 2. **Eligibility**: chat model in the catalogue, reachable through the tenant's own (BYOK) or a
//!    shared provider, with a credential (or a keyless OpenAI-compatible endpoint), within the
//!    request's trust-tier constraint, and healthy. Capability (tools, images) and context-window
//!    fit narrow the set further when at least one candidate fits.
//! 3. **Quality floor** (only when a floor is configured for the intent): keep models whose quality
//!    for the intent is at or above the floor and order them by estimated request cost (cheapest
//!    first; unpriced models last), then higher quality, then route position, then model id. The
//!    first is chosen; the rest are fallbacks for retryable upstream errors.
//! 4. **Tenant default**: if no eligible model meets the floor, use the tenant's `default` route in
//!    its own order. Without a floor for the intent, the route order is kept as is.

use crate::Constraints;
use crate::artifact::RouterProfile;
use caliban_config::{ModelEntry, ModelKind, ProviderConfig, Snapshot, TenantConfig};
use caliban_ir::ChatRequest;
use caliban_types::{ModelId, ProviderKind};

pub const DEFAULT_INTENT: &str = "default";
/// Output estimate when the request sets no `max_tokens` (same as the gateway's reservation).
pub const DEFAULT_OUTPUT_ESTIMATE: u64 = 1024;
/// Floors compare with a small tolerance so 0.8 written in config equals 0.8 from a profile.
const EPS: f64 = 1e-9;

/// Model health as seen by the data plane. Unhealthy models are skipped unless nothing else is left.
pub trait ModelHealth: Send + Sync {
    fn is_healthy(&self, model: &ModelId) -> bool;
}

/// The data plane does not track model health yet; every model counts as healthy.
pub struct AlwaysHealthy;

impl ModelHealth for AlwaysHealthy {
    fn is_healthy(&self, _: &ModelId) -> bool {
        true
    }
}

/// Quality per (model, intent): `[routing.quality]` first, then the router profile.
pub struct QualitySource<'a> {
    pub snap: &'a Snapshot,
    pub profile: Option<&'a RouterProfile>,
}

impl QualitySource<'_> {
    pub fn quality(&self, model: &ModelId, intent: &str) -> Option<f64> {
        self.snap
            .config
            .routing
            .quality
            .get(model)
            .and_then(|m| m.get(intent).copied())
            .or_else(|| self.profile.and_then(|p| p.quality(model.as_str(), intent)))
    }
}

/// Why a candidate was or was not picked (logged at debug; never contains prompt text).
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateTrace {
    pub model: ModelId,
    pub quality: Option<f64>,
    pub est_cost_usd: Option<f64>,
    pub verdict: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    /// Route table entry the candidates came from (`default` when the intent has none).
    pub route: String,
    pub candidates: Vec<ModelId>,
    /// `route_order`, `quality_floor` or `default_fallback`.
    pub policy: &'static str,
    pub floor: Option<f64>,
    pub trace: Vec<CandidateTrace>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyError {
    NoRoute,
    NothingEligible,
}

/// A credential is configured, or the endpoint is an OpenAI-compatible server (local servers
/// usually run without a key). Hosted providers without a key cannot be called.
pub fn has_credentials(p: &ProviderConfig) -> bool {
    p.api_key.is_some() || p.kind == ProviderKind::OpenaiCompatible
}

/// Estimated USD cost of serving `req` on `m`; `None` when the model has no price.
pub fn estimate_cost(m: &ModelEntry, req: &ChatRequest) -> Option<f64> {
    let (pi, po) = (m.price_in_per_mtok?, m.price_out_per_mtok?);
    let est_in = req.estimate_prompt_tokens();
    let est_out = req.max_output_tokens().unwrap_or(DEFAULT_OUTPUT_ESTIMATE);
    #[allow(clippy::cast_precision_loss)]
    Some((est_in as f64 * pi + est_out as f64 * po) / 1_000_000.0)
}

struct Eligible {
    id: ModelId,
    pos: usize,
}

/// Steps 1 and 2: the tenant's candidates for a route, filtered to those it can actually use.
fn eligible(snap: &Snapshot, tenant: &TenantConfig, req: &ChatRequest, constraints: Constraints, health: &dyn ModelHealth, ids: &[ModelId], trace: &mut Vec<CandidateTrace>) -> Vec<Eligible> {
    let mut out = Vec::new();
    let mut unhealthy = Vec::new();
    for (pos, id) in ids.iter().enumerate() {
        let verdict = match snap.model(id) {
            None => Some("unknown_model"),
            Some(m) if m.kind != ModelKind::Chat => Some("not_chat"),
            Some(m) => match snap.provider_for(tenant, &m.provider) {
                None => Some("unreachable"),
                Some(p) if !has_credentials(p) => Some("no_credentials"),
                Some(p) if m.trust_tier > constraints.max_tier || p.trust_tier > constraints.max_tier => Some("trust_tier"),
                Some(_) if !health.is_healthy(id) => {
                    unhealthy.push(Eligible { id: id.clone(), pos });
                    Some("unhealthy")
                }
                Some(_) => None,
            },
        };
        match verdict {
            Some(v) => trace.push(CandidateTrace { model: id.clone(), quality: None, est_cost_usd: None, verdict: v }),
            None => out.push(Eligible { id: id.clone(), pos }),
        }
    }
    // Fail open on health: a stale health signal must not take the tenant offline.
    if out.is_empty() && !unhealthy.is_empty() {
        trace.retain(|t| t.verdict != "unhealthy");
        out = unhealthy;
    }
    // Prefer candidates that declare what the request needs; keep all when none do.
    type Fits = Box<dyn Fn(&ModelEntry) -> bool>;
    let est = req.estimate_prompt_tokens() + req.max_output_tokens().unwrap_or(0);
    let needs: [(bool, &'static str, Fits); 3] = [
        (req.has_tools(), "no_tools", Box::new(|m: &ModelEntry| m.capabilities.tools)),
        (req.has_images(), "no_vision", Box::new(|m: &ModelEntry| m.capabilities.vision)),
        (true, "context_window", Box::new(move |m: &ModelEntry| m.context_window.is_none_or(|w| u64::from(w) >= est))),
    ];
    for (needed, verdict, fits) in needs {
        let ok = |e: &Eligible| snap.model(&e.id).is_some_and(&fits);
        if needed && out.iter().any(ok) {
            for e in out.iter().filter(|e| !ok(e)) {
                trace.push(CandidateTrace { model: e.id.clone(), quality: None, est_cost_usd: None, verdict });
            }
            out.retain(ok);
        }
    }
    out
}

fn route_models(snap: &Snapshot, tenant: &TenantConfig, intent: &str) -> Option<(String, Vec<ModelId>)> {
    if let Some(r) = tenant.routes.iter().find(|r| r.intent == intent) {
        return Some((r.intent.clone(), r.models.clone()));
    }
    if let Some(r) = tenant.routes.iter().find(|r| r.intent == DEFAULT_INTENT) {
        return Some((r.intent.clone(), r.models.clone()));
    }
    tenant.routes.is_empty().then(|| (DEFAULT_INTENT.to_owned(), snap.models_for(tenant).filter(|m| m.kind == ModelKind::Chat).map(|m| m.id.clone()).collect()))
}

/// Steps 1 to 4 for `intent`.
pub fn select(
    snap: &Snapshot,
    tenant: &TenantConfig,
    req: &ChatRequest,
    constraints: Constraints,
    intent: &str,
    quality: &QualitySource<'_>,
    health: &dyn ModelHealth,
) -> Result<Selection, PolicyError> {
    let (route, ids) = route_models(snap, tenant, intent).ok_or(PolicyError::NoRoute)?;
    let mut trace = Vec::new();
    let mut el = eligible(snap, tenant, req, constraints, health, &ids, &mut trace);
    let floor = snap.config.routing.floor_for(&tenant.id, intent);

    let default_fallback = |trace: &mut Vec<CandidateTrace>| -> Result<Selection, PolicyError> {
        let (droute, dids) = match tenant.routes.iter().find(|r| r.intent == DEFAULT_INTENT) {
            Some(r) => (r.intent.clone(), r.models.clone()),
            None => (route.clone(), ids.clone()),
        };
        let del = if droute == route && dids == ids { eligible(snap, tenant, req, constraints, health, &dids, &mut Vec::new()) } else { eligible(snap, tenant, req, constraints, health, &dids, trace) };
        if del.is_empty() {
            return Err(PolicyError::NothingEligible);
        }
        let candidates: Vec<ModelId> = del.into_iter().map(|e| e.id).collect();
        trace.push(CandidateTrace { model: candidates[0].clone(), quality: None, est_cost_usd: None, verdict: "default_chosen" });
        Ok(Selection { route: droute, candidates, policy: "default_fallback", floor, trace: std::mem::take(trace) })
    };

    if el.is_empty() {
        // Step 4 also covers an intent route that is entirely unusable for this tenant.
        return if route == DEFAULT_INTENT { Err(PolicyError::NothingEligible) } else { default_fallback(&mut trace) };
    }
    let Some(floor) = floor else {
        let candidates: Vec<ModelId> = el.into_iter().map(|e| e.id).collect();
        for (i, id) in candidates.iter().enumerate() {
            let verdict = if i == 0 { "chosen" } else { "fallback" };
            trace.push(CandidateTrace { model: id.clone(), quality: quality.quality(id, intent), est_cost_usd: None, verdict });
        }
        return Ok(Selection { route, candidates, policy: "route_order", floor: None, trace });
    };

    struct Scored {
        id: ModelId,
        pos: usize,
        q: f64,
        cost: Option<f64>,
    }
    let mut ok = Vec::new();
    for e in el.drain(..) {
        let q = quality.quality(&e.id, intent);
        let cost = snap.model(&e.id).and_then(|m| estimate_cost(m, req));
        match q {
            Some(q) if q + EPS >= floor => ok.push(Scored { id: e.id, pos: e.pos, q, cost }),
            Some(q) => trace.push(CandidateTrace { model: e.id, quality: Some(q), est_cost_usd: cost, verdict: "below_floor" }),
            None => trace.push(CandidateTrace { model: e.id, quality: None, est_cost_usd: cost, verdict: "no_quality" }),
        }
    }
    if ok.is_empty() {
        return default_fallback(&mut trace);
    }
    ok.sort_by(|a, b| {
        let cost = match (a.cost, b.cost) {
            (Some(x), Some(y)) => x.total_cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        };
        cost.then_with(|| b.q.total_cmp(&a.q)).then_with(|| a.pos.cmp(&b.pos)).then_with(|| a.id.as_str().cmp(b.id.as_str()))
    });
    for (i, s) in ok.iter().enumerate() {
        trace.push(CandidateTrace { model: s.id.clone(), quality: Some(s.q), est_cost_usd: s.cost, verdict: if i == 0 { "chosen" } else { "fallback" } });
    }
    Ok(Selection { route, candidates: ok.into_iter().map(|s| s.id).collect(), policy: "quality_floor", floor: Some(floor), trace })
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliban_config::Config;

    /// Four chat models with distinct prices; tenant `acme` reaches all of them, `nokey` lacks the
    /// hosted credential.
    const CFG: &str = r#"
        [routing.floors]
        code = 0.8
        chat = 0.5

        [routing.quality."local/small"]
        code = 0.6
        chat = 0.7
        [routing.quality."ext/mid"]
        code = 0.82
        chat = 0.8
        [routing.quality."ext/big"]
        code = 0.95
        chat = 0.9
        [routing.quality."ext/twin"]
        code = 0.82

        [[models]]
        id = "local/small"
        provider = "local"
        upstream_model = "s"
        trust_tier = "t0_sovereign"
        price_in_per_mtok = 0.0
        price_out_per_mtok = 0.0

        [[models]]
        id = "ext/mid"
        provider = "hosted"
        upstream_model = "m"
        trust_tier = "t2_contracted"
        price_in_per_mtok = 1.0
        price_out_per_mtok = 4.0

        [[models]]
        id = "ext/twin"
        provider = "hosted"
        upstream_model = "t"
        trust_tier = "t2_contracted"
        price_in_per_mtok = 1.0
        price_out_per_mtok = 4.0

        [[models]]
        id = "ext/big"
        provider = "hosted"
        upstream_model = "b"
        trust_tier = "t2_contracted"
        price_in_per_mtok = 5.0
        price_out_per_mtok = 20.0

        [[tenants]]
        id = "acme"
        name = "Acme"
          [[tenants.providers]]
          id = "local"
          kind = "openai_compatible"
          base_url = "http://local/v1"
          trust_tier = "t0_sovereign"
          [[tenants.providers]]
          id = "hosted"
          kind = "openai"
          base_url = "https://hosted/v1"
          trust_tier = "t2_contracted"
          api_key = { env = "X" }
          [[tenants.routes]]
          intent = "default"
          models = ["local/small", "ext/big"]
          [[tenants.routes]]
          intent = "code"
          models = ["ext/big", "ext/twin", "ext/mid", "local/small"]
          [[tenants.routes]]
          intent = "chat"
          models = ["ext/big", "local/small"]
          [[tenants.routes]]
          intent = "analytics"
          models = ["ext/big", "ext/mid"]

        [[tenants]]
        id = "nokey"
        name = "No key"
          [[tenants.providers]]
          id = "local"
          kind = "openai_compatible"
          base_url = "http://local/v1"
          trust_tier = "t0_sovereign"
          [[tenants.providers]]
          id = "hosted"
          kind = "openai"
          base_url = "https://hosted/v1"
          trust_tier = "t2_contracted"
          [[tenants.routes]]
          intent = "default"
          models = ["local/small"]
          [[tenants.routes]]
          intent = "code"
          models = ["ext/big", "ext/mid", "local/small"]
    "#;

    fn snap(extra: &str) -> Snapshot {
        Snapshot::new(Config::from_toml_str(&format!("{extra}\n{CFG}")).unwrap(), "t")
    }

    fn req() -> ChatRequest {
        ChatRequest::from_openai_json(br#"{"model":"caliban/auto","messages":[{"role":"user","content":"x"}]}"#).unwrap()
    }

    fn pick(s: &Snapshot, tenant: &str, intent: &str, health: &dyn ModelHealth) -> Result<Selection, PolicyError> {
        let t = s.tenant(&tenant.into()).unwrap();
        select(s, t, &req(), Constraints::default(), intent, &QualitySource { snap: s, profile: None }, health)
    }

    fn ids(sel: &Selection) -> Vec<&str> {
        sel.candidates.iter().map(ModelId::as_str).collect()
    }

    #[test]
    fn cheapest_model_at_or_above_the_floor_wins() {
        let s = snap("");
        let sel = pick(&s, "acme", "code", &AlwaysHealthy).unwrap();
        assert_eq!(sel.policy, "quality_floor");
        // local/small (0.6) is below 0.8; mid and twin tie on price and quality, big is dearer.
        assert_eq!(ids(&sel), ["ext/twin", "ext/mid", "ext/big"]);
        assert!(sel.trace.iter().any(|t| t.model.as_str() == "local/small" && t.verdict == "below_floor"));
        // chat floor 0.5: the free local model qualifies and wins.
        assert_eq!(ids(&pick(&s, "acme", "chat", &AlwaysHealthy).unwrap())[0], "local/small");
    }

    #[test]
    fn ties_break_by_route_position_then_id() {
        let s = snap("");
        // ext/twin precedes ext/mid in the code route; same price, same quality.
        let sel = pick(&s, "acme", "code", &AlwaysHealthy).unwrap();
        assert_eq!(&ids(&sel)[..2], ["ext/twin", "ext/mid"]);
        // Deterministic across calls.
        assert_eq!(sel, pick(&s, "acme", "code", &AlwaysHealthy).unwrap());
    }

    #[test]
    fn allow_list_is_the_route_table() {
        let s = snap("[routing.tenants.acme.floors]\nanalytics = 0.5\n");
        let t = s.tenant(&"acme".into()).unwrap();
        // ext/twin is cheaper and scores higher for analytics, but the analytics route does not list it.
        let profile = RouterProfile::from_rows("p@1", &[("ext/twin", "analytics", 0.99), ("ext/big", "analytics", 0.9)]);
        let q = QualitySource { snap: &s, profile: Some(&profile) };
        let sel = select(&s, t, &req(), Constraints::default(), "analytics", &q, &AlwaysHealthy).unwrap();
        assert_eq!((sel.policy, ids(&sel)), ("quality_floor", vec!["ext/big"]));
        assert!(sel.trace.iter().all(|c| c.model.as_str() != "ext/twin"));
        assert!(sel.trace.iter().any(|c| c.model.as_str() == "ext/mid" && c.verdict == "no_quality"));
    }

    #[test]
    fn missing_credentials_exclude_hosted_models() {
        let s = snap("");
        let sel = pick(&s, "nokey", "code", &AlwaysHealthy).unwrap();
        assert!(sel.trace.iter().filter(|t| t.verdict == "no_credentials").count() == 2);
        // Only local/small is usable and it is below the code floor: tenant default.
        assert_eq!(sel.policy, "default_fallback");
        assert_eq!(ids(&sel), ["local/small"]);
    }

    #[test]
    fn no_model_meets_the_floor_falls_back_to_the_default_route() {
        let s = snap("[routing.tenants.acme.floors]\ncode = 0.99\n");
        let sel = pick(&s, "acme", "code", &AlwaysHealthy).unwrap();
        assert_eq!((sel.policy, sel.route.as_str(), sel.floor), ("default_fallback", "default", Some(0.99)));
        assert_eq!(ids(&sel), ["local/small", "ext/big"]);
    }

    #[test]
    fn without_a_floor_the_route_order_is_kept() {
        let s = snap("");
        let sel = pick(&s, "acme", "analytics", &AlwaysHealthy).unwrap();
        assert_eq!((sel.policy, ids(&sel)), ("route_order", vec!["ext/big", "ext/mid"]));
    }

    #[test]
    fn unknown_intent_uses_the_default_route_with_its_floor() {
        let s = snap("[routing.tenants.acme.floors]\n\"*\" = 0.65\n");
        let sel = pick(&s, "acme", "translate", &AlwaysHealthy).unwrap();
        // No quality scores for translate: nothing qualifies, default route order.
        assert_eq!(sel.policy, "default_fallback");
        assert_eq!(sel.route, "default");
    }

    struct Down(&'static str);
    impl ModelHealth for Down {
        fn is_healthy(&self, m: &ModelId) -> bool {
            m.as_str() != self.0
        }
    }

    #[test]
    fn unhealthy_models_are_skipped_but_fail_open() {
        let s = snap("");
        let sel = pick(&s, "acme", "code", &Down("ext/twin")).unwrap();
        assert_eq!(ids(&sel)[0], "ext/mid");
        struct AllDown;
        impl ModelHealth for AllDown {
            fn is_healthy(&self, _: &ModelId) -> bool {
                false
            }
        }
        assert_eq!(ids(&pick(&s, "acme", "code", &AllDown).unwrap())[0], "ext/twin");
    }

    #[test]
    fn trust_tier_constraint_applies_before_the_floor() {
        let s = snap("");
        let t = s.tenant(&"acme".into()).unwrap();
        let sel = select(&s, t, &req(), Constraints { max_tier: caliban_types::TrustTier::T0Sovereign }, "code", &QualitySource { snap: &s, profile: None }, &AlwaysHealthy).unwrap();
        assert_eq!((sel.policy, ids(&sel)), ("default_fallback", vec!["local/small"]));
    }

    #[test]
    fn profile_supplies_quality_and_config_overrides_it() {
        let s = snap("");
        let profile = RouterProfile::from_rows("p@1", &[("local/small", "summarize", 0.9), ("ext/mid", "summarize", 0.95), ("local/small", "code", 0.99)]);
        let q = QualitySource { snap: &s, profile: Some(&profile) };
        assert_eq!(q.quality(&"local/small".into(), "summarize"), Some(0.9));
        // Config wins over the profile.
        assert_eq!(q.quality(&"local/small".into(), "code"), Some(0.6));
    }
}
