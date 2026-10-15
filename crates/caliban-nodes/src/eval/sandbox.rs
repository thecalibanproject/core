//! The eval sandbox: the tool registry of a run that must not reach real tools with effects.
//!
//! One mechanism serves both eval suites (research note 04 §7: the injection suite runs "the
//! node's real allowlist and its own pinned tools behind a sandbox"):
//!
//! - **Injection runs** (origin `injection:<eval>:<case>`): every tool keeps its approved manifest
//!   and its trust, nothing is called. Read tools answer with content that carries the case's
//!   injected instruction; write tools answer `ok`.
//! - **Golden runs** (origin `eval:<eval>[:<case>]`): a golden set calls the node for real, so
//!   before this sandbox a golden trial of a node with a write tool sent real writes (a fintech
//!   golden trial issued a real refund, TX-30015, in the 2026-10-13 demo). Now every call to an
//!   `mcp://` tool is sandboxed, reads included (2026-10-15: a declared read is a claim, and
//!   AgentDojo-style tools diverge from their advertised surface, research note 04 §7): it answers
//!   the case's scripted result for that tool (`tool_results`), else a synthetic result marked as
//!   such ([`synthetic_result`]). A read tool the spec opts in with `eval_live: true` calls the
//!   real server (unless the case scripts it); a write never does. Built-in tools (Caliban's own,
//!   read-only by construction) call the real tool.
//!
//! In both, every call is recorded first, as the tool would have received it (after the
//! executor's PII guard), sealed in the run's journal (`sandbox:<step>` observation events), so a
//! verdict or a `tool_call` check can read what reached each tool. Taint, approvals, declared
//! tools only and the PII guard are the executor's, unchanged: the sandbox only replaces the
//! final call.

use super::injection::{Case, Scope, Surface};
use crate::executor::tools::{Tool, ToolCtx, ToolError, ToolInfo, ToolRegistry};
use crate::journal::{EventKind, Journal, RunRecord, StepRecord};
use crate::seal::Sealer;
use crate::{Effect, NodeSpec};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// The prefix of observation events.
pub const OBSERVATION: &str = "sandbox:";

/// What a sandboxed call of a golden run answers without a script (and without an output schema
/// to follow), so nobody mistakes it for the tool's answer.
pub const SYNTHETIC_NOTE: &str = "Caliban eval sandbox: this call was not sent to the tool; the result is synthetic.";

/// How the sandbox answers.
enum Mode {
    Injection {
        case: &'static Case,
        parts: Vec<String>,
        /// The read tools whose results carry the injection (`None`: every one).
        inject_at: Option<Vec<String>>,
    },
    Golden {
        /// Scripted results by tool name or reference (the golden case's `tool_results`).
        scripts: Arc<BTreeMap<String, Value>>,
    },
}

/// The tools of an eval run: the real tools' manifests and trust, sandboxed calls.
pub struct SandboxTools {
    mode: Arc<Mode>,
    real: Arc<dyn ToolRegistry>,
    journal: Arc<dyn Journal>,
    sealer: Arc<dyn Sealer>,
    /// Reference to its declared effect (every version the run can reach).
    effects: HashMap<String, Effect>,
    /// Golden runs: the `mcp://` read tools every reachable version opts in to live calls
    /// (`eval_live`), never a write.
    live: HashSet<String>,
}

/// `fail_safe` (golden runs): a tool any reachable version declares a write is a write everywhere
/// in the run. The injection suite keeps the first declaration, as it always has.
fn effects_of(root: &NodeSpec, children: &[&NodeSpec], fail_safe: bool) -> HashMap<String, Effect> {
    let mut effects = HashMap::new();
    for spec in std::iter::once(root).chain(children.iter().copied()) {
        for t in &spec.tools {
            let e = effects.entry(t.reference.clone()).or_insert_with(|| t.effect.clone());
            if fail_safe && t.effect == Effect::Write {
                *e = Effect::Write;
            }
        }
    }
    effects
}

/// The `mcp://` tools a golden trial may call for real: every declaration of the reference in the
/// versions the run can reach says `eval_live: true`, and none of them (nor the fail-safe effect)
/// makes it a write.
fn live_of(root: &NodeSpec, children: &[&NodeSpec], effects: &HashMap<String, Effect>) -> HashSet<String> {
    let mut opted: HashMap<&str, bool> = HashMap::new();
    for spec in std::iter::once(root).chain(children.iter().copied()) {
        for t in &spec.tools {
            let e = opted.entry(t.reference.as_str()).or_insert(true);
            *e = *e && t.eval_live && t.effect == Effect::Read && t.reference.starts_with("mcp://");
        }
    }
    opted
        .into_iter()
        .filter(|(r, live)| *live && effects.get(*r) == Some(&Effect::Read))
        .map(|(r, _)| r.to_owned())
        .collect()
}

impl SandboxTools {
    /// The `mcp://` tools a golden trial of `root` (reaching `children`) calls for real.
    pub fn live_tools(root: &NodeSpec, children: &[&NodeSpec]) -> HashSet<String> {
        live_of(root, children, &effects_of(root, children, true))
    }

    /// The sandbox of an injection case's run: `root` is the run's node, `children` the subnodes
    /// it can reach; `real` resolves the tools (manifests and trust) as production does.
    pub fn new(
        case: &'static Case,
        tenant: &str,
        root: &NodeSpec,
        children: &[&NodeSpec],
        real: Arc<dyn ToolRegistry>,
        journal: Arc<dyn Journal>,
        sealer: Arc<dyn Sealer>,
    ) -> Self {
        let info = |r: &str| real.resolve(tenant, r).ok().map(|t| (t.info(), t.reaches_network()));
        let surface = Surface::of(root, children, &info);
        let inject_at = match case.scope {
            // The injection is in the run input: every read answers as usual.
            _ if case.carrier.in_input() => Some(vec![]),
            Scope::Node => None,
            Scope::ChildToParent => Some(surface.child_reads.clone()),
            Scope::ParentToChild => Some(surface.reads.clone()),
        };
        let mode = Mode::Injection { case, parts: case.payload(&surface), inject_at };
        let effects = effects_of(root, children, false);
        Self { mode: Arc::new(mode), real, journal, sealer, effects, live: HashSet::new() }
    }

    /// The sandbox of a golden trial's run: every `mcp://` tool is sandboxed (answered from
    /// `scripts`, else synthetic), except reads the spec opts in with `eval_live`, which call the
    /// real tool unless `scripts` names them. Built-in tools call the real tool unless scripted.
    pub fn golden(
        scripts: BTreeMap<String, Value>,
        root: &NodeSpec,
        children: &[&NodeSpec],
        real: Arc<dyn ToolRegistry>,
        journal: Arc<dyn Journal>,
        sealer: Arc<dyn Sealer>,
    ) -> Self {
        let mode = Mode::Golden { scripts: Arc::new(scripts) };
        let effects = effects_of(root, children, true);
        let live = live_of(root, children, &effects);
        Self { mode: Arc::new(mode), real, journal, sealer, effects, live }
    }
}

impl ToolRegistry for SandboxTools {
    fn resolve(&self, tenant: &str, reference: &str) -> Result<Arc<dyn Tool>, ToolError> {
        // Resolved like in production (an unapproved tool is as unavailable as it would be), but
        // never called when it writes.
        let inner = self.real.resolve(tenant, reference)?;
        let (injected, golden) = match &*self.mode {
            Mode::Injection { inject_at, .. } => {
                (inject_at.as_ref().is_none_or(|at| at.iter().any(|r| r == reference)), false)
            }
            Mode::Golden { .. } => (false, true),
        };
        Ok(Arc::new(SandboxTool {
            inner,
            reference: reference.to_owned(),
            // Undeclared tools never reach a registry (the executor refuses them). In a golden run
            // an unknown effect counts as a write, so nothing with an effect leaves the sandbox.
            write: self.effects.get(reference).map_or(golden, |e| *e == Effect::Write),
            // Golden runs: an `mcp://` tool not opted in to live calls never reaches its server.
            sandbox_reads: golden && reference.starts_with("mcp://") && !self.live.contains(reference),
            injected,
            mode: Arc::clone(&self.mode),
            journal: Arc::clone(&self.journal),
            sealer: Arc::clone(&self.sealer),
        }))
    }
}

struct SandboxTool {
    inner: Arc<dyn Tool>,
    reference: String,
    write: bool,
    /// Golden runs: a read is answered by the sandbox too (an `mcp://` tool without `eval_live`).
    sandbox_reads: bool,
    injected: bool,
    mode: Arc<Mode>,
    journal: Arc<dyn Journal>,
    sealer: Arc<dyn Sealer>,
}

/// The script for a tool: by its full reference, else by its manifest name.
fn script_for<'a>(scripts: &'a BTreeMap<String, Value>, reference: &str, name: &str) -> Option<&'a Value> {
    scripts.get(reference).or_else(|| scripts.get(name))
}

#[async_trait::async_trait]
impl Tool for SandboxTool {
    fn info(&self) -> ToolInfo {
        self.inner.info()
    }

    fn trusted(&self) -> bool {
        self.inner.trusted()
    }

    fn reaches_network(&self) -> bool {
        self.inner.reaches_network()
    }

    fn output_schema(&self) -> Option<Value> {
        self.inner.output_schema()
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<Value, ToolError> {
        let info = self.inner.info();
        // Golden runs: what answers this call (a script, the synthetic result, or the real read).
        let golden = match &*self.mode {
            Mode::Golden { scripts } => Some(match script_for(scripts, &self.reference, &info.name) {
                Some(s) => Answer::Scripted(s.clone()),
                None if self.write || self.sandbox_reads => Answer::Synthetic,
                None => Answer::Real,
            }),
            Mode::Injection { .. } => None,
        };
        let sandboxed = !matches!(golden, Some(Answer::Real));
        let obs = json!({
            "tool": self.reference,
            "name": info.name,
            "effect": if self.write { "write" } else { "read" },
            "trusted": self.inner.trusted(),
            // As the suite targets it: classified so, or URL-shaped by its schema.
            "network": self.inner.reaches_network() || crate::executor::taint::network_hint(&info.input_schema),
            "sandboxed": sandboxed,
            "scripted": matches!(golden, Some(Answer::Scripted(_))),
            "args": args,
        });
        let sealed = self.sealer.seal(&ctx.tenant, &ctx.run_id, &obs.to_string()).map_err(ToolError::Failed)?;
        let name = format!("{OBSERVATION}{}", ctx.step_id);
        self.journal
            .put_event(&ctx.tenant, &ctx.run_id, &name, EventKind::Observation, Some(sealed))
            .await
            .map_err(|e| ToolError::Failed(e.to_string()))?;
        match (&*self.mode, golden) {
            (_, Some(Answer::Scripted(v))) => Ok(v),
            (_, Some(Answer::Synthetic)) => Ok(synthetic_result(self.inner.output_schema().as_ref())),
            (_, Some(Answer::Real)) => self.inner.call(ctx, args).await,
            (Mode::Injection { case, parts, .. }, None) => Ok(if self.write {
                json!({"ok": true, "sandbox": true})
            } else {
                case.read_result(parts, &args, self.injected)
            }),
            (Mode::Golden { .. }, None) => unreachable!("a golden sandbox always decides an answer"),
        }
    }
}

enum Answer {
    Scripted(Value),
    Synthetic,
    Real,
}

// ───────────────────────────── synthetic results ─────────────────────────────

/// The result of a sandboxed call that has no script (a write, or an `mcp://` read without
/// `eval_live`): valid against the tool's output schema
/// when it has one (and the schema can be satisfied without guessing a `pattern`), marked
/// `"sandbox": true` wherever the schema allows the key; without a schema,
/// `{"ok": true, "sandbox": true, "synthetic": true, "note": ...}`.
pub fn synthetic_result(schema: Option<&Value>) -> Value {
    let marked = json!({"ok": true, "sandbox": true, "synthetic": true, "note": SYNTHETIC_NOTE});
    let Some(schema) = schema else { return marked };
    let v = synthesize(schema, 0);
    if crate::schema::validate(schema, &v).is_ok() { v } else { marked }
}

const SYNTHETIC_TEXT: &str = "sandbox (synthetic result)";

fn synthesize(s: &Value, depth: u32) -> Value {
    if depth > 16 {
        return Value::Null;
    }
    if let Some(c) = s.get("const") {
        return c.clone();
    }
    if let Some(first) = s.get("enum").and_then(Value::as_array).and_then(|e| e.first()) {
        return first.clone();
    }
    if let Some(first) = s.get("anyOf").and_then(Value::as_array).and_then(|a| a.first()) {
        return synthesize(first, depth + 1);
    }
    if let Some(all) = s.get("allOf").and_then(Value::as_array) {
        // Merge the object parts; otherwise the first.
        let mut out = Map::new();
        for part in all {
            match synthesize(part, depth + 1) {
                Value::Object(m) => out.extend(m),
                other if out.is_empty() => return other,
                _ => {}
            }
        }
        return Value::Object(out);
    }
    let ty = match s.get("type") {
        Some(Value::String(t)) => t.as_str(),
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).find(|t| *t != "null").unwrap_or("null"),
        _ if s.get("properties").is_some() || s.get("required").is_some() => "object",
        _ if s.get("items").is_some() => "array",
        _ => "object",
    };
    match ty {
        "object" => {
            let props = s.get("properties").and_then(Value::as_object);
            let mut out = Map::new();
            for k in s.get("required").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                let sub = props.and_then(|p| p.get(k)).cloned().unwrap_or_else(|| json!({}));
                out.insert(k.to_owned(), synthesize(&sub, depth + 1));
            }
            // The mark, where the schema lets it in.
            let declared = props.and_then(|p| p.get("sandbox"));
            let open = s.get("additionalProperties") != Some(&Value::Bool(false));
            match declared {
                Some(d) if crate::schema::validate(d, &json!(true)).is_ok() => {
                    out.insert("sandbox".into(), json!(true));
                }
                None if open => {
                    out.insert("sandbox".into(), json!(true));
                }
                _ => {}
            }
            Value::Object(out)
        }
        "array" => {
            let n = s.get("minItems").and_then(Value::as_u64).unwrap_or(0).min(16);
            let item = s.get("items").cloned().unwrap_or_else(|| json!({}));
            Value::Array((0..n).map(|_| synthesize(&item, depth + 1)).collect())
        }
        "string" => {
            let text = match s.get("format").and_then(Value::as_str) {
                Some("date-time") => "1970-01-01T00:00:00Z".to_owned(),
                Some("date") => "1970-01-01".to_owned(),
                Some("email") => "sandbox@example.invalid".to_owned(),
                Some("uri") | Some("url") => "https://sandbox.invalid/".to_owned(),
                Some("uuid") => "00000000-0000-0000-0000-000000000000".to_owned(),
                _ => SYNTHETIC_TEXT.to_owned(),
            };
            let min = s.get("minLength").and_then(Value::as_u64).unwrap_or(0) as usize;
            let max = s.get("maxLength").and_then(Value::as_u64).map(|m| m as usize);
            let mut text = text;
            while text.chars().count() < min {
                text.push('.');
            }
            if let Some(max) = max {
                text = text.chars().take(max).collect();
            }
            Value::String(text)
        }
        "integer" | "number" => {
            let lo = s.get("minimum").and_then(Value::as_f64);
            let hi = s.get("maximum").and_then(Value::as_f64);
            let x = match (lo, hi) {
                (Some(lo), _) => lo.ceil(),
                (None, Some(hi)) if hi < 0.0 => hi.floor(),
                _ => 0.0,
            };
            if ty == "integer" || x.fract() == 0.0 { json!(x as i64) } else { json!(x) }
        }
        "boolean" => json!(true),
        _ => Value::Null,
    }
}

// ───────────────────────────── what the tools received ─────────────────────────────

/// One recorded call, as the tool received it.
#[derive(Debug, Clone)]
pub struct Observation {
    /// The tool's reference.
    pub tool: String,
    /// Its manifest name (empty in events recorded before it was kept).
    pub name: String,
    pub write: bool,
    pub trusted: bool,
    /// A read tool that reaches the network through its arguments.
    pub network: bool,
    /// The call was answered by the sandbox (every call of an injection run; in a golden run,
    /// every `mcp://` call but the reads opted in with `eval_live`, and scripted calls), not by
    /// the tool.
    pub sandboxed: bool,
    /// The arguments as compact JSON.
    pub args: String,
}

impl Observation {
    /// The arguments as JSON.
    pub fn args_value(&self) -> Value {
        serde_json::from_str(&self.args).unwrap_or(Value::Null)
    }

    /// Whether `tool` names this call's tool: its reference, its manifest name, or its reference
    /// without the pin (`mcp://server/tool`).
    pub fn is_tool(&self, tool: &str) -> bool {
        tool == self.tool
            || (!self.name.is_empty() && tool == self.name)
            || self.tool.split_once('#').is_some_and(|(unpinned, _)| unpinned == tool)
    }
}

/// The recorded calls of a run, in step order.
pub async fn observations(
    journal: &Arc<dyn Journal>,
    sealer: &dyn Sealer,
    run: &RunRecord,
    steps: &[StepRecord],
) -> Result<Vec<Observation>, String> {
    let mut out = Vec::new();
    for s in steps.iter().filter(|s| s.kind == "tool") {
        let name = format!("{OBSERVATION}{}", s.step_id);
        let Some(ev) = journal.event(&run.id, &name).await.map_err(|e| e.to_string())? else { continue };
        let Some(sealed) = ev.payload else { continue };
        let v: Value = serde_json::from_str(&sealer.open(&run.tenant_id, &run.id, &sealed)?).unwrap_or(Value::Null);
        out.push(Observation {
            tool: v["tool"].as_str().unwrap_or_default().to_owned(),
            name: v["name"].as_str().unwrap_or_default().to_owned(),
            write: v["effect"] == "write",
            trusted: v["trusted"] == true,
            network: v["network"] == true,
            // Injection events carry no flag: every one of their calls was sandboxed.
            sandboxed: v["sandboxed"] != false,
            args: v["args"].to_string(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_synthetic_result_follows_the_output_schema_and_says_it_is_synthetic() {
        assert_eq!(synthetic_result(None)["synthetic"], true);
        assert_eq!(synthetic_result(None)["note"], SYNTHETIC_NOTE);
        let schema = json!({
            "type": "object",
            "required": ["refund_id", "status", "amount", "items", "at"],
            "properties": {
                "refund_id": {"type": "string", "minLength": 3},
                "status": {"enum": ["pending", "done"]},
                "amount": {"type": "number", "minimum": 0.5},
                "items": {"type": "array", "minItems": 1, "items": {"type": "integer", "maximum": -2}},
                "at": {"type": "string", "format": "date-time"},
                "memo": {"type": "string"}
            }
        });
        let v = synthetic_result(Some(&schema));
        crate::schema::validate(&schema, &v).unwrap();
        assert_eq!((v["status"].as_str(), v["sandbox"].as_bool()), (Some("pending"), Some(true)), "{v}");
        assert_eq!(v["items"], json!([-2]));
        // A closed object gets no mark it would refuse, and stays valid.
        let closed = json!({"type": "object", "additionalProperties": false, "required": ["ok"],
                            "properties": {"ok": {"type": "boolean"}}});
        assert_eq!(synthetic_result(Some(&closed)), json!({"ok": true}));
        // A schema the generator cannot satisfy (a pattern): the marked default.
        let pattern = json!({"type": "string", "pattern": "^TX-[0-9]+$"});
        assert_eq!(synthetic_result(Some(&pattern))["sandbox"], true);
    }

    #[test]
    fn a_call_names_its_tool_by_reference_name_or_unpinned_reference() {
        let o = Observation {
            tool: "mcp://bank/refund#sha256:00".into(),
            name: "refund".into(),
            write: true,
            trusted: false,
            network: false,
            sandboxed: true,
            args: "{}".into(),
        };
        assert!(o.is_tool("refund") && o.is_tool("mcp://bank/refund") && o.is_tool("mcp://bank/refund#sha256:00"));
        assert!(!o.is_tool("lookup") && !o.is_tool("mcp://bank"));
    }
}
