//! Workflow graphs: a token walks the graph from the entry vertex. Each vertex receives the value
//! on the edge it came in by (the run input for the entry vertex), validated against its
//! `input_schema`, and produces a value (validated against its `output_schema`) and, for `router`
//! and `verify`, a label. The first outgoing edge (in declaration order) whose `when` is absent or
//! equals the label is taken; no matching edge ends the run with the last value. Fan-out happens
//! only inside a `map` vertex.
//!
//! **Loops.** A vertex with `max_iterations: N` runs at most N times per run. Once it has, its
//! edges back into vertices already visited (the loop) are no longer taken; the walk continues on
//! another matching edge, or ends with the last value and a note in `stop_reason`.

use super::agent;
use super::taint::{self, Taint};
use super::template::{Scope, as_text, extract_json, render_str, render_value};
use super::tools::{ToolCtx, ToolError};
use super::{ResolvedNode, RunCx, StepOut, Stop, Suspension, idempotency_key};
use crate::budget::{Budget, Ledger};
use crate::journal::RunStatus;
use crate::{Effect, NodeKind, ToolTarget, Vertex, VertexKind};
use futures::future::BoxFuture;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

/// Runs a node (workflow or agent) inside the current run, under `ledger`.
/// Runs a node (workflow or agent) inside the current run, under `ledger`. `taint`: the input's
/// labels; returns the output and its labels.
pub(super) fn run_node<'a>(
    cx: &'a RunCx,
    node: &'a ResolvedNode,
    input: Value,
    taint: Taint,
    prefix: &'a str,
    ledger: &'a Ledger,
    depth: u32,
) -> BoxFuture<'a, Result<(Value, Taint), Stop>> {
    Box::pin(async move {
        match node.spec.kind {
            NodeKind::Workflow => run_graph(cx, node, input, taint, prefix, ledger, depth).await,
            NodeKind::Agent => agent::run_agent_at(cx, node, input, taint, prefix, ledger, depth).await,
        }
    })
}

pub(super) async fn run_graph(
    cx: &RunCx,
    node: &ResolvedNode,
    input: Value,
    input_taint: Taint,
    prefix: &str,
    ledger: &Ledger,
    depth: u32,
) -> Result<(Value, Taint), Stop> {
    let g = node.spec.graph.as_ref().ok_or_else(|| Stop::Fail("workflow node without a graph".into()))?;
    let mut current = g.entry_vertex().ok_or_else(|| Stop::Fail("the graph has no vertices".into()))?;
    let mut value = input;
    let mut taint = input_taint;
    let mut visits: HashMap<&str, u32> = HashMap::new();
    let mut visited: HashSet<&str> = HashSet::new();
    let mut outputs: BTreeMap<String, Value> = BTreeMap::new();
    let mut taints: BTreeMap<String, Taint> = BTreeMap::new();
    loop {
        let n = visits.get(current.id.as_str()).copied().unwrap_or(0);
        if let Some(max) = current.max_iterations
            && n >= max
        {
            note(cx, format!("vertex '{}' reached max_iterations ({max}); the run ended there", current.id));
            return Ok((value, taint));
        }
        // What the vertex consumes: the value it receives and every output its config names.
        let mut in_taint = taint.clone();
        for id in taint::referenced_outputs(&current.config) {
            in_taint.extend(taints.get(&id).cloned().unwrap_or_default());
        }
        if let Some(s) = current.config.get("input_schema") {
            crate::schema::validate(s, &value).map_err(|e| {
                Stop::Fail(format!("vertex '{}': input does not match its input_schema: {e}", current.id))
            })?;
        }
        let base = format!("{prefix}{}#{n}", current.id);
        let (out, out_taint) =
            exec_vertex(cx, node, current, &value, &in_taint, &base, &outputs, ledger, depth).await?;
        if let Some(s) = current.config.get("output_schema")
            && current.kind() != Some(VertexKind::Llm)
        {
            crate::schema::validate(s, &out.output).map_err(|e| {
                Stop::Fail(format!("vertex '{}': output does not match its output_schema: {e}", current.id))
            })?;
        }
        visits.insert(current.id.as_str(), n + 1);
        visited.insert(current.id.as_str());
        cx.set_last(&out.output);
        outputs.insert(current.id.clone(), out.output.clone());
        taints.insert(current.id.clone(), out_taint.clone());
        value = out.output;
        taint = out_taint;

        let capped = current.max_iterations.is_some_and(|max| n + 1 >= max);
        let mut skipped_loop = false;
        let next = g.edges.iter().filter(|e| e.from == current.id).find(|e| {
            let matches = e.when.as_deref().is_none_or(|w| out.label.as_deref() == Some(w));
            if matches && capped && visited.contains(e.to.as_str()) {
                skipped_loop = true;
                return false;
            }
            matches
        });
        if skipped_loop {
            let max = current.max_iterations.unwrap_or_default();
            note(cx, format!("vertex '{}' reached max_iterations ({max}); its loop stopped", current.id));
        }
        match next.and_then(|e| g.vertex(&e.to)) {
            Some(v) => current = v,
            None => return Ok((value, taint)),
        }
    }
}

fn note(cx: &RunCx, msg: String) {
    let mut n = cx.note.lock();
    if n.is_none() {
        *n = Some(msg);
    }
}

/// `input` with `key` set (objects), or `{"input": input, key: value}`.
fn with_field(input: &Value, key: &str, v: Value) -> Value {
    match input {
        Value::Object(m) => {
            let mut m = m.clone();
            m.insert(key.into(), v);
            Value::Object(m)
        }
        other => json!({"input": other, key: v}),
    }
}

#[allow(clippy::too_many_arguments)]
/// Runs one vertex. Returns its output and the output's taint labels (`in_taint`: what it
/// consumes).
fn exec_vertex<'a>(
    cx: &'a RunCx,
    node: &'a ResolvedNode,
    v: &'a Vertex,
    input: &'a Value,
    in_taint: &'a Taint,
    base: &'a str,
    outputs: &'a BTreeMap<String, Value>,
    ledger: &'a Ledger,
    depth: u32,
) -> BoxFuture<'a, Result<(StepOut, Taint), Stop>> {
    Box::pin(super::consuming(in_taint.clone(), async move {
        let scope = Scope { input, outputs };
        let c = &v.config;
        // A model call passes on the labels of what it consumed.
        let same = |out: StepOut| (out, in_taint.clone());
        match v.kind() {
            Some(VertexKind::Llm) => llm(cx, node, v, input, base, outputs, ledger, "llm").await.map(same),
            Some(VertexKind::Router) => router(cx, node, v, input, base, outputs, ledger).await.map(same),
            Some(VertexKind::Tool) => {
                let reference = c.get("tool").and_then(Value::as_str).unwrap_or_default();
                let args = c.get("args").map_or_else(|| input.clone(), |a| render_value(a, &scope));
                let out = call_tool(cx, node, &v.id, reference, args, in_taint.clone(), base, ledger, depth).await?;
                let t = out.taint.clone();
                Ok((out, t))
            }
            Some(VertexKind::Map) => map(cx, node, v, input, in_taint, base, outputs, ledger, depth).await,
            Some(VertexKind::Reduce) => reduce(cx, node, v, input, base, outputs, ledger).await.map(same),
            Some(VertexKind::Verify) => verify(cx, node, v, input, base, outputs, ledger).await.map(same),
            Some(VertexKind::Human) => human(cx, v, input, base, &scope, ledger).await.map(same),
            Some(VertexKind::Subnode) => {
                let reference = c.get("node").and_then(Value::as_str).unwrap_or_default();
                let child_input = c.get("input").map_or_else(|| input.clone(), |t| render_value(t, &scope));
                let (out, t) =
                    subnode(cx, node, reference, child_input, in_taint.clone(), &format!("{base}>"), ledger, depth)
                        .await?;
                Ok((StepOut::value(out), t))
            }
            Some(VertexKind::Code) => {
                Err(Stop::Fail(format!("vertex '{}': code vertices are not yet supported", v.id)))
            }
            None => Err(Stop::Fail(format!("vertex '{}': unknown type '{}'", v.id, v.vertex_type))),
        }
    }))
}

/// The chat request of an `llm`-like vertex.
fn chat_body(
    cx: &RunCx,
    node: &ResolvedNode,
    v: &Vertex,
    system: Option<String>,
    user: String,
    ledger: &Ledger,
) -> Value {
    let c = &v.config;
    let model = c.get("model").and_then(Value::as_str).map_or_else(|| node.spec.default_model(), str::to_owned);
    let mut messages = Vec::new();
    if let Some(s) = system.filter(|s| !s.is_empty()) {
        messages.push(json!({"role": "system", "content": s}));
    }
    messages.push(json!({"role": "user", "content": user}));
    let wanted = c.get("max_tokens").and_then(Value::as_u64).unwrap_or(1024);
    json!({
        "model": model,
        "messages": messages,
        "temperature": c.get("temperature").cloned().unwrap_or(json!(0)),
        "max_tokens": cx.max_tokens(ledger, wanted),
    })
}

fn content_of(message: &Value) -> String {
    match message.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts.iter().filter_map(|p| p.get("text").and_then(Value::as_str)).collect(),
        _ => String::new(),
    }
}

/// One model call as a journaled step; the step's recorded output is the reply's text.
async fn model_step(
    cx: &RunCx,
    ledger: &Ledger,
    step_id: &str,
    vertex: &str,
    kind: &str,
    body: Value,
) -> Result<StepOut, Stop> {
    let input = body.clone();
    cx.step(ledger, step_id, vertex, kind, &input, async {
        let r = cx.model(step_id, body).await?;
        Ok(StepOut::model(Value::String(content_of(&r.message)), &r))
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn llm(
    cx: &RunCx,
    node: &ResolvedNode,
    v: &Vertex,
    input: &Value,
    base: &str,
    outputs: &BTreeMap<String, Value>,
    ledger: &Ledger,
    kind: &str,
) -> Result<StepOut, Stop> {
    let scope = Scope { input, outputs };
    let c = &v.config;
    let mut system = c
        .get("system")
        .and_then(Value::as_str)
        .map(|s| render_str(s, &scope))
        .or_else(|| node.spec.system_prompt().map(str::to_owned))
        .unwrap_or_default();
    let schema = c.get("output_schema");
    if let Some(s) = schema {
        system.push_str("\n\nAnswer with one JSON value that matches this JSON Schema, and nothing else:\n");
        system.push_str(&s.to_string());
    }
    let user = c.get("prompt").and_then(Value::as_str).map_or_else(|| as_text(input), |t| render_str(t, &scope));
    let body = chat_body(cx, node, v, Some(system), user, ledger);
    let first = model_step(cx, ledger, base, &v.id, kind, body.clone()).await?;
    let Some(schema) = schema else { return Ok(first) };
    let text = first.output.as_str().unwrap_or_default().to_owned();
    let problem = match extract_json(&text) {
        Some(j) => match crate::schema::validate(schema, &j) {
            Ok(()) => return Ok(StepOut { output: j, ..first }),
            Err(e) => e,
        },
        None => "the answer is not JSON".to_owned(),
    };
    // One corrective attempt, as its own step.
    let mut retry = body;
    if let Some(m) = retry.get_mut("messages").and_then(Value::as_array_mut) {
        m.push(json!({"role": "assistant", "content": text}));
        m.push(json!({"role": "user", "content": format!(
            "That answer does not match the required JSON Schema ({problem}). Answer again with only the JSON value."
        )}));
    }
    let second = model_step(cx, ledger, &format!("{base}~r1"), &v.id, kind, retry).await?;
    let text = second.output.as_str().unwrap_or_default();
    match extract_json(text).map(|j| crate::schema::validate(schema, &j).map(|()| j)) {
        Some(Ok(j)) => Ok(StepOut { output: j, ..second }),
        Some(Err(e)) => Err(Stop::Fail(format!("vertex '{}': output does not match its output_schema: {e}", v.id))),
        None => Err(Stop::Fail(format!("vertex '{}': output is not the JSON its output_schema asks for", v.id))),
    }
}

/// Which label a classifier answer names: an exact label, else the first label that appears as a
/// word in it.
fn pick_label<'a>(answer: &str, labels: &'a [String]) -> Option<&'a String> {
    let a = answer.trim().trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-').to_lowercase();
    if let Some(l) = labels.iter().find(|l| l.to_lowercase() == a) {
        return Some(l);
    }
    let words: Vec<String> = answer
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '-'))
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    words.iter().find_map(|w| labels.iter().find(|l| l.to_lowercase() == *w))
}

async fn router(
    cx: &RunCx,
    node: &ResolvedNode,
    v: &Vertex,
    input: &Value,
    base: &str,
    outputs: &BTreeMap<String, Value>,
    ledger: &Ledger,
) -> Result<StepOut, Stop> {
    let scope = Scope { input, outputs };
    let c = &v.config;
    // Sorted: the prompt (and so the step's input hash) must not depend on the JSON map's key
    // order, which differs between builds (`serde_json`'s `preserve_order`).
    let mut routes: Vec<(String, Value)> =
        c.get("routes").and_then(Value::as_object).map(|m| m.clone().into_iter().collect()).unwrap_or_default();
    routes.sort_by(|a, b| a.0.cmp(&b.0));
    let labels: Vec<String> = routes.iter().map(|(l, _)| l.clone()).collect();
    let mut system = c.get("system").and_then(Value::as_str).map(|s| render_str(s, &scope)).unwrap_or_else(|| {
        "Classify the input into exactly one of the labels below. Answer with the label only.".to_owned()
    });
    system.push_str("\n\nLabels:");
    for (label, desc) in &routes {
        system.push_str(&format!("\n- {label}: {}", as_text(desc)));
    }
    let user = c.get("prompt").and_then(Value::as_str).map_or_else(|| as_text(input), |t| render_str(t, &scope));
    let body = chat_body(cx, node, v, Some(system), user, ledger);
    let out = model_step(cx, ledger, base, &v.id, "router", body).await?;
    let answer = out.output.as_str().unwrap_or_default();
    let label = pick_label(answer, &labels)
        .cloned()
        .or_else(|| c.get("default").and_then(Value::as_str).map(str::to_owned))
        .ok_or_else(|| Stop::Fail(format!("vertex '{}': the classifier answered none of the labels", v.id)))?;
    Ok(StepOut { output: with_field(input, "route", json!(label)), label: Some(label), ..out })
}

/// A tool call as a journaled step: `node://` runs the node inside this run, anything else goes
/// through the tool registry. `args_taint`: the labels of the arguments. A write with tainted
/// arguments waits for a human approval unless the node allowlists those labels. The returned
/// step's `taint` is the output's labels (journaled, so a replay sees the same).
#[allow(clippy::too_many_arguments)]
pub(super) async fn call_tool(
    cx: &RunCx,
    node: &ResolvedNode,
    vertex: &str,
    reference: &str,
    args: Value,
    args_taint: Taint,
    step_id: &str,
    ledger: &Ledger,
    depth: u32,
) -> Result<StepOut, Stop> {
    let declared = node.spec.tools.iter().find(|t| t.reference == reference);
    if let Some(t) = declared
        && t.effect == Effect::Write
        && !taint::untrusted(&args_taint).is_empty()
        && !taint::allowed(&args_taint, &t.allow_tainted)
    {
        super::consuming(args_taint.clone(), approve_write(cx, vertex, reference, &args, &args_taint, step_id, ledger))
            .await?;
    }
    let input = json!({"tool": reference, "args": args});
    let consumed = args_taint.clone();
    let call = cx.step(ledger, step_id, vertex, "tool", &input, async {
        let mut out_taint = args_taint.clone();
        let out = match ToolTarget::parse(reference) {
            Ok(ToolTarget::Node { .. }) => {
                let (out, t) =
                    subnode(cx, node, reference, args, args_taint.clone(), &format!("{step_id}>"), ledger, depth)
                        .await?;
                out_taint = t;
                out
            }
            _ => {
                let tool = cx.ex.tools.resolve(cx.tenant(), reference).map_err(|e| Stop::Fail(e.to_string()))?;
                let ctx = ToolCtx {
                    tenant: cx.tenant().to_owned(),
                    node: cx.run.node.clone(),
                    node_version: cx.run.version,
                    run_id: cx.run.id.clone(),
                    datasource_scopes: node.spec.datasource_scopes(),
                    invoker_key_hash: cx.run.invoker_key_hash.clone(),
                    step_id: step_id.to_owned(),
                    idempotency_key: idempotency_key(&cx.run.id, step_id),
                };
                let out = guarded_call(cx, reference, tool.as_ref(), &ctx, args).await?;
                out_taint.extend(taint::label_for(reference));
                out
            }
        };
        Ok(StepOut { taint: out_taint, ..StepOut::value(out) })
    });
    super::consuming(consumed, call).await
}

/// A write whose arguments carry untrusted labels: waits for a human (`<step>@approve`, the run
/// in `input_required`), then journals the decision with who made it. A refusal fails the call.
#[allow(clippy::too_many_arguments)]
async fn approve_write(
    cx: &RunCx,
    vertex: &str,
    reference: &str,
    args: &Value,
    args_taint: &Taint,
    step_id: &str,
    ledger: &Ledger,
) -> Result<(), Stop> {
    let id = format!("{step_id}@approve");
    let labels: Vec<&String> = taint::untrusted(args_taint);
    if !cx.is_recorded(&id) && cx.answer(&id).await?.is_none() {
        cx.admit_step(ledger)?;
        let mut shown = args.to_string();
        if shown.len() > 2000 {
            shown.truncate(shown.floor_char_boundary(2000));
            shown.push_str("...");
        }
        let question = format!(
            "Approve this write? Tool {reference} (effect: write) would be called with arguments derived from untrusted \
             data ({}): {shown}. Answer {{\"approve\": true}} or {{\"approve\": false}}.",
            labels.iter().map(|l| l.as_str()).collect::<Vec<_>>().join(", ")
        );
        return Err(Stop::Suspend(Suspension {
            status: RunStatus::InputRequired,
            awaiting: Some(id),
            question: Some(question),
            wake_at: None,
        }));
    }
    let step_input = json!({"tool": reference, "args": args, "labels": labels});
    let out = cx
        .step(ledger, &id, vertex, "approval", &step_input, async {
            let (answer, by) = cx.answer_by(&id).await?.unwrap_or((Value::Null, None));
            let ok = taint::approved(&answer);
            tracing::info!(target: "caliban::audit", tenant = cx.tenant(), run = %cx.run.id, step = %id, tool = reference,
                approved = ok, by = by.as_deref().unwrap_or("unknown"), labels = ?labels, "tainted write decision");
            Ok(StepOut::value(json!({"approved": ok, "by": by, "labels": labels})))
        })
        .await?;
    if out.output["approved"] == true {
        Ok(())
    } else {
        Err(Stop::Fail(format!(
            "the write to '{reference}' was refused by a human (its arguments carry {})",
            labels.iter().map(|l| l.as_str()).collect::<Vec<_>>().join(", ")
        )))
    }
}

/// A tool call behind its circuit breaker, retried while it fails transiently (at most
/// `guards.tool_retries` times).
async fn guarded_call(
    cx: &RunCx,
    reference: &str,
    tool: &dyn super::tools::Tool,
    ctx: &ToolCtx,
    args: Value,
) -> Result<Value, Stop> {
    let ex = &cx.ex;
    let key = (cx.tenant().to_owned(), super::breaker::tool_key(reference));
    let admitted = ex.breakers.lock().entry(key.clone()).or_default().admit(Instant::now(), ex.opts.breaker_cooldown);
    if let Err(wait) = admitted {
        return Err(Stop::Fail(format!(
            "tool '{reference}': circuit open after repeated failures; next trial in {} s",
            wait.as_secs()
        )));
    }
    // Personal data: surrogates for a tool not trusted with it.
    let args = if tool.trusted() {
        args
    } else {
        ex.data
            .protect(cx.tenant(), args)
            .await
            .map_err(|e| {
                Stop::Fail(format!("tool '{reference}': its arguments could not be checked for personal data: {e}"))
            })?
            .0
    };
    let mut attempt = 0;
    let mut pause = Duration::from_millis(50);
    let result = loop {
        match tool.call(ctx, args.clone()).await {
            Err(ToolError::Transient(e)) if attempt < cx.guards.tool_retries => {
                tracing::debug!(tool = reference, attempt, error = %e, "tool call failed transiently; retrying");
                attempt += 1;
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(Duration::from_secs(2));
            }
            other => break other,
        }
    };
    let failed = matches!(result, Err(ToolError::Transient(_) | ToolError::Unavailable(..)));
    if let Some(b) = ex.breakers.lock().get_mut(&key) {
        b.record(!failed, Instant::now(), ex.opts.breaker_failures);
    }
    let out = result.map_err(|e| match e {
        ToolError::Transient(m) if attempt > 0 => {
            Stop::Fail(format!("tool '{reference}': {m} (after {} attempts)", attempt + 1))
        }
        other => Stop::Fail(format!("tool '{reference}': {other}")),
    })?;
    // Untrusted input: anonymized as it enters the run.
    ex.data
        .anonymize(cx.tenant(), out)
        .await
        .map_err(|e| Stop::Fail(format!("tool '{reference}': its result could not be anonymized: {e}")))
}

/// Runs `node://name@vN` inside this run: its steps are journaled under `prefix`, its budget is a
/// child of `ledger` (capped by both), and nesting is limited by `budgets.depth`.
#[allow(clippy::too_many_arguments)]
pub(super) async fn subnode(
    cx: &RunCx,
    _parent: &ResolvedNode,
    reference: &str,
    input: Value,
    taint: Taint,
    prefix: &str,
    ledger: &Ledger,
    depth: u32,
) -> Result<(Value, Taint), Stop> {
    let Ok(ToolTarget::Node { name, version }) = ToolTarget::parse(reference) else {
        return Err(Stop::Fail(format!("'{reference}' is not a node reference")));
    };
    let child = cx.node(&name, version).map_err(|e| Stop::Fail(format!("subnode {name}@v{version}: {e}")))?;
    let b = &child.spec.budgets;
    let cap = Budget {
        steps: b.steps,
        tokens: b.tokens,
        usd: b.usd.unwrap_or(f64::INFINITY),
        wall_clock_ms: b.wall_clock_s.saturating_mul(1000),
        depth: b.depth,
        fanout: b.fanout,
    };
    let child_ledger = ledger
        .child(cap, cx.elapsed_ms())
        .map_err(|e| Stop::Budget(format!("subnode {name}@v{version} cannot start: {e}")))?;
    cx.note_depth(child_ledger.level());
    run_node(cx, &child, input, taint, prefix, &child_ledger, depth + 1).await
}

#[allow(clippy::too_many_arguments)]
async fn map(
    cx: &RunCx,
    node: &ResolvedNode,
    v: &Vertex,
    input: &Value,
    in_taint: &Taint,
    base: &str,
    outputs: &BTreeMap<String, Value>,
    ledger: &Ledger,
    depth: u32,
) -> Result<(StepOut, Taint), Stop> {
    let c = &v.config;
    let items = match c.get("over").and_then(Value::as_str) {
        Some(p) => input.pointer(p),
        None => Some(input),
    }
    .and_then(Value::as_array)
    .ok_or_else(|| Stop::Fail(format!("vertex '{}': map needs an array to fan out over", v.id)))?;
    let mut body: Vertex = serde_json::from_value(c.get("body").cloned().unwrap_or(Value::Null))
        .map_err(|e| Stop::Fail(format!("vertex '{}': config.body: {e}", v.id)))?;
    if body.id.is_empty() {
        body.id = format!("{}.body", v.id);
    }
    // At most the ledger's fan-out (the node's `budgets.fanout`, capped by its parents').
    let cap = ledger.fanout();
    let width = c
        .get("concurrency")
        .and_then(Value::as_u64)
        .map_or(cap, |n| u32::try_from(n).unwrap_or(u32::MAX).min(cap))
        .max(1) as usize;
    cx.note_fanout(u32::try_from(width.min(items.len())).unwrap_or(u32::MAX));
    let slots = tokio::sync::Semaphore::new(width);
    let branches = items.iter().enumerate().map(|(i, item)| {
        let (slots, body) = (&slots, &body);
        async move {
            let _slot = slots.acquire().await.map_err(|_| Stop::Fail("map closed".into()))?;
            exec_vertex(cx, node, body, item, in_taint, &format!("{base}/{i}"), outputs, ledger, depth).await
        }
    });
    let results = futures::future::join_all(branches).await;
    let mut out = Vec::with_capacity(results.len());
    let (mut tokens, mut prompt, mut completion, mut usd) = (0, 0, 0, 0.0);
    // A lost lease wins over everything, then a cancellation, failures, then budget stops.
    let rank = |s: &Stop| match s {
        Stop::LeaseLost => 0,
        Stop::Cancelled(_) => 1,
        Stop::Fail(_) => 2,
        Stop::Budget(_) => 3,
        _ => 4,
    };
    let mut stop: Option<Stop> = None;
    let mut taint = in_taint.clone();
    for r in results {
        match r {
            Ok((s, t)) => {
                taint.extend(t);
                tokens += s.tokens;
                prompt += s.prompt_tokens;
                completion += s.completion_tokens;
                usd += s.usd;
                out.push(s.output);
            }
            Err(e) => {
                if stop.as_ref().is_none_or(|cur| rank(&e) < rank(cur)) {
                    stop = Some(e);
                }
            }
        }
    }
    if let Some(s) = stop {
        cx.set_last(&Value::Array(out));
        return Err(s);
    }
    let out = StepOut {
        tokens,
        prompt_tokens: prompt,
        completion_tokens: completion,
        usd,
        ..StepOut::value(Value::Array(out))
    };
    Ok((out, taint))
}

async fn reduce(
    cx: &RunCx,
    node: &ResolvedNode,
    v: &Vertex,
    input: &Value,
    base: &str,
    outputs: &BTreeMap<String, Value>,
    ledger: &Ledger,
) -> Result<StepOut, Stop> {
    match v.config.get("mode").and_then(Value::as_str).unwrap_or("concat") {
        "concat" => Ok(StepOut::value(match input {
            Value::Array(a) => Value::Array(
                a.iter()
                    .flat_map(|x| match x {
                        Value::Array(inner) => inner.clone(),
                        other => vec![other.clone()],
                    })
                    .collect(),
            ),
            other => other.clone(),
        })),
        "merge" => {
            let mut m = serde_json::Map::new();
            for x in input.as_array().into_iter().flatten() {
                if let Value::Object(o) = x {
                    m.extend(o.clone());
                }
            }
            Ok(StepOut::value(Value::Object(m)))
        }
        "llm" => llm(cx, node, v, input, base, outputs, ledger, "reduce").await,
        other => Err(Stop::Fail(format!("vertex '{}': unknown reduce mode '{other}' (concat, merge or llm)", v.id))),
    }
}

async fn verify(
    cx: &RunCx,
    node: &ResolvedNode,
    v: &Vertex,
    input: &Value,
    base: &str,
    outputs: &BTreeMap<String, Value>,
    ledger: &Ledger,
) -> Result<StepOut, Stop> {
    let c = &v.config;
    let (pass, feedback, spent) = match c.get("check").and_then(Value::as_str).unwrap_or("schema") {
        "schema" => {
            let schema = c.get("schema").cloned().unwrap_or(Value::Bool(true));
            match crate::schema::validate(&schema, input) {
                Ok(()) => (true, None, StepOut::value(Value::Null)),
                Err(e) => (false, Some(e), StepOut::value(Value::Null)),
            }
        }
        _ => {
            let scope = Scope { input, outputs };
            let criteria = c.get("criteria").map(as_text).unwrap_or_else(|| "the work is correct and complete".into());
            let system = format!(
                "You check work against these criteria: {criteria}\nReply PASS if it meets them. Otherwise reply FAIL: followed by a short reason."
            );
            let user =
                c.get("prompt").and_then(Value::as_str).map_or_else(|| as_text(input), |t| render_str(t, &scope));
            let body = chat_body(cx, node, v, Some(system), user, ledger);
            let out = model_step(cx, ledger, base, &v.id, "verify", body).await?;
            let answer = out.output.as_str().unwrap_or_default().trim().to_owned();
            let pass = answer.to_uppercase().starts_with("PASS");
            let reason = answer.split_once(':').map_or(answer.as_str(), |(_, r)| r).trim().to_owned();
            (pass, (!pass).then_some(reason), out)
        }
    };
    let output = if pass { input.clone() } else { json!({"previous": input, "feedback": feedback}) };
    Ok(StepOut { output, label: Some(if pass { "pass" } else { "fail" }.into()), ..spent })
}

async fn human(
    cx: &RunCx,
    v: &Vertex,
    input: &Value,
    step_id: &str,
    scope: &Scope<'_>,
    ledger: &Ledger,
) -> Result<StepOut, Stop> {
    let c = &v.config;
    let question = render_str(c.get("question").and_then(Value::as_str).unwrap_or_default(), scope);
    let default = c.get("default").cloned();
    if !cx.is_recorded(step_id) && cx.answer(step_id).await?.is_none() {
        let mut wake_at = None;
        let mut timed_out = false;
        if let Some(secs) = c.get("timeout_s").and_then(Value::as_u64) {
            let deadline = cx.deadline(&format!("{step_id}:deadline"), Duration::from_secs(secs)).await?;
            if chrono::Utc::now() < deadline {
                wake_at = Some(deadline);
            } else if default.is_some() {
                timed_out = true;
            } else {
                return Err(Stop::Fail(format!("vertex '{}': no answer before its deadline ({secs} s)", v.id)));
            }
        }
        if !timed_out {
            cx.admit_step(ledger)?;
            return Err(Stop::Suspend(Suspension {
                status: RunStatus::InputRequired,
                awaiting: Some(step_id.to_owned()),
                question: Some(question),
                wake_at,
            }));
        }
    }
    let step_input = json!({"question": question});
    let out = cx
        .step(ledger, step_id, &v.id, "human", &step_input, async {
            let answer = cx.answer(step_id).await?.or(default).unwrap_or(Value::Null);
            Ok(StepOut::value(answer))
        })
        .await?;
    Ok(StepOut::value(with_field(input, "answer", out.output)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_picked_from_answers() {
        let labels = vec!["billing".to_owned(), "clinical".to_owned(), "other".to_owned()];
        assert_eq!(pick_label("clinical", &labels).map(String::as_str), Some("clinical"));
        assert_eq!(pick_label(" Billing.\n", &labels).map(String::as_str), Some("billing"));
        assert_eq!(pick_label("I think this is clinical, not billing", &labels).map(String::as_str), Some("clinical"));
        assert_eq!(pick_label("no idea", &labels), None);
    }
}
