//! Routing (docs/research/02-intent-classification-and-routing.md).
//!
//! Staged pipeline; each stage may exit early:
//! 0. rules/policy (pinned model, trust tier, licence) — implemented
//! 1. embedding kNN over tenant exemplars — TODO (shares the request embedding with the cache)
//! 2. ONNX multi-head classifier (intent, difficulty, OOS, jailbreak) — TODO, artifacts from `ml/`
//! 3. small-LLM fallback for ambiguous traffic — TODO
//! 4. pick a model within the route: ordered candidates now; cost/latency scoring + bandit later
//!
//! The keyword classifier below is a placeholder so routing works end to end before the
//! ONNX head ships.

use caliban_config::{ModelEntry, ModelKind, Snapshot, TenantConfig};
use caliban_ir::ChatRequest;
use caliban_types::{ModelId, TrustTier};

pub const AUTO_MODEL: &str = "caliban/auto";
pub const DEFAULT_INTENT: &str = "default";

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RouteError {
    #[error("model '{0}' is not available to this tenant")]
    UnknownModel(String),
    #[error("no route for intent '{0}' and no default route")]
    NoRoute(String),
    #[error("no candidate model satisfies policy (min trust tier {0:?})")]
    PolicyExcludesAll(TrustTier),
}

/// Classifies a request into an intent label.
pub trait IntentClassifier: Send + Sync {
    /// Returns (intent, confidence in 0..=1).
    fn classify(&self, text: &str) -> (String, f32);
}

/// Placeholder stage-2 classifier. Replace with the ONNX head (`ort`) from the `ml` repo.
pub struct KeywordClassifier;

impl IntentClassifier for KeywordClassifier {
    fn classify(&self, text: &str) -> (String, f32) {
        let t = text.to_lowercase();
        let has = |ws: &[&str]| ws.iter().any(|w| t.contains(w));
        if has(&["```", "function", "compile", "stack trace", "refactor", "bug in"]) {
            ("code".into(), 0.6)
        } else if has(&["sql", "query", "revenue", "how many", "average", "per month", "dashboard"]) {
            ("analytics".into(), 0.55)
        } else if has(&["summarize", "summary", "tl;dr"]) {
            ("summarize".into(), 0.6)
        } else if has(&["extract", "parse", "fields from"]) {
            ("extraction".into(), 0.55)
        } else if t.split_whitespace().count() < 12 {
            ("chat".into(), 0.4)
        } else {
            (DEFAULT_INTENT.into(), 0.3)
        }
    }
}

/// Outcome of routing: an ordered list of models to try (first preferred, rest fallbacks).
#[derive(Debug, Clone, PartialEq)]
pub struct RouteDecision {
    pub intent: String,
    pub confidence: f32,
    pub candidates: Vec<ModelId>,
    /// Which stage decided; logged for offline router evaluation.
    pub stage: &'static str,
}

pub struct Router {
    classifier: Box<dyn IntentClassifier>,
}

impl Default for Router {
    fn default() -> Self {
        Self { classifier: Box::new(KeywordClassifier) }
    }
}

/// Request-level constraints from policy (e.g. sensitive data must stay on sovereign models).
#[derive(Debug, Clone, Copy)]
pub struct Constraints {
    /// Worst tier the request may be sent to. `T0Sovereign` = never leave the boundary.
    pub max_tier: TrustTier,
}

impl Default for Constraints {
    fn default() -> Self {
        Self { max_tier: TrustTier::T3Public }
    }
}

impl Router {
    pub fn new(classifier: Box<dyn IntentClassifier>) -> Self {
        Self { classifier }
    }

    pub fn route(
        &self,
        snap: &Snapshot,
        tenant: &TenantConfig,
        req: &ChatRequest,
        constraints: Constraints,
    ) -> Result<RouteDecision, RouteError> {
        let allowed = |m: &ModelEntry| m.trust_tier <= constraints.max_tier;

        // Stage 0: pinned model.
        if req.model != AUTO_MODEL {
            let id = ModelId::from(req.model.as_str());
            let entry = snap
                .models_for(tenant)
                .find(|m| m.id == id)
                .ok_or_else(|| RouteError::UnknownModel(req.model.clone()))?;
            if !allowed(entry) {
                return Err(RouteError::PolicyExcludesAll(constraints.max_tier));
            }
            return Ok(RouteDecision { intent: "pinned".into(), confidence: 1.0, candidates: vec![id], stage: "rules" });
        }

        // Stages 1–3 (placeholder): classify, then map intent → route table.
        let text = req.last_user_text().unwrap_or_default();
        let (intent, confidence) = self.classifier.classify(&text);
        let route = tenant
            .routes
            .iter()
            .find(|r| r.intent == intent)
            .or_else(|| tenant.routes.iter().find(|r| r.intent == DEFAULT_INTENT));

        // Stage 4: keep route order, drop candidates that policy forbids. A tenant without any
        // route table falls back to every model it can reach (catalogue order).
        let (route_intent, ids): (String, Vec<ModelId>) = match route {
            Some(r) => (r.intent.clone(), r.models.clone()),
            None if tenant.routes.is_empty() => (DEFAULT_INTENT.into(), snap.models_for(tenant).map(|m| m.id.clone()).collect()),
            None => return Err(RouteError::NoRoute(intent)),
        };
        let mut candidates: Vec<ModelId> = ids
            .into_iter()
            .filter(|id| snap.model(id).is_some_and(|m| allowed(m) && m.kind == ModelKind::Chat))
            .collect();
        if candidates.is_empty() {
            return Err(RouteError::PolicyExcludesAll(constraints.max_tier));
        }
        // Capability filter: prefer candidates that declare what the request needs (tools,
        // images). Models without declared capabilities are kept when nothing declares support.
        type Supports = fn(&ModelEntry) -> bool;
        let needs: [(bool, Supports); 2] =
            [(req.has_tools(), |m| m.capabilities.tools), (req.has_images(), |m| m.capabilities.vision)];
        for (needed, supports) in needs {
            if needed && candidates.iter().any(|id| snap.model(id).is_some_and(supports)) {
                candidates.retain(|id| snap.model(id).is_some_and(supports));
            }
        }
        Ok(RouteDecision { intent: route_intent, confidence, candidates, stage: "keyword" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliban_config::Config;

    fn snap() -> Snapshot {
        let cfg = Config::from_toml_str(include_str!("../../../config/caliban.example.toml")).unwrap();
        Snapshot::new(cfg, "t")
    }

    fn req(model: &str, text: &str) -> ChatRequest {
        let body = serde_json_body(model, text);
        ChatRequest::from_openai_json(body.as_bytes()).unwrap()
    }

    fn serde_json_body(model: &str, text: &str) -> String {
        format!(r#"{{"model":"{model}","messages":[{{"role":"user","content":"{text}"}}]}}"#)
    }

    #[test]
    fn auto_routes_by_intent_with_fallbacks() {
        let s = snap();
        let t = s.tenant(&"acme".into()).unwrap();
        let d = Router::default().route(&s, t, &req(AUTO_MODEL, "hi there"), Constraints::default()).unwrap();
        assert_eq!(d.intent, "chat");
        assert_eq!(d.candidates[0].as_str(), "local/qwen3-8b");
    }

    #[test]
    fn sovereign_constraint_drops_external_models() {
        let s = snap();
        let t = s.tenant(&"acme".into()).unwrap();
        let long = "please think carefully about the following long request that has many words in it ok";
        let d = Router::default()
            .route(&s, t, &req(AUTO_MODEL, long), Constraints { max_tier: TrustTier::T0Sovereign })
            .unwrap();
        assert_eq!(d.intent, "default");
        assert_eq!(d.candidates, vec![ModelId::from("local/gpt-oss-20b")]);
    }

    #[test]
    fn pinned_unknown_model_is_rejected() {
        let s = snap();
        let t = s.tenant(&"acme".into()).unwrap();
        let e = Router::default().route(&s, t, &req("nope/model", "x"), Constraints::default()).unwrap_err();
        assert_eq!(e, RouteError::UnknownModel("nope/model".into()));
    }
}
