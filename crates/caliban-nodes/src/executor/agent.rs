//! `agent` nodes: a bounded ReAct-style loop over the node's tools.
//!
//! Each turn is one model call (step `agent#<turn>`) with the node's tools offered as functions.
//! Tool calls in the answer run as steps (`agent#<turn>.<n>`) and their results go back to the
//! model; an answer without tool calls is the final answer. The loop is bounded by the step and
//! token budgets and by `agent.max_turns` (default: `budgets.steps`). A tool that fails returns an
//! error object to the model instead of ending the run; an unknown or unavailable tool refuses the
//! run before the first call.
//!
//! **Taint.** The conversation carries the labels of the run input and of every tool result the
//! model saw; every tool call made after a result is labelled with them (a write may then need an
//! approval, see `taint`), and so is the final answer.

use super::graph::call_tool;
use super::taint::Taint;
use super::template::{as_text, extract_json};
use super::tools::Tool;
use super::{ResolvedNode, RunCx, StepOut, Stop};
use crate::ToolTarget;
use crate::budget::Ledger;
use serde_json::{Value, json};
use std::sync::Arc;

/// A tool as the model sees it, and what calling it does.
struct Bound {
    function: String,
    reference: String,
    description: String,
    schema: Value,
    /// Resolved up front so an unavailable tool refuses the run before the first call.
    _tool: Option<Arc<dyn Tool>>,
}

/// Function names: `[a-zA-Z0-9_-]`, at most 64 characters.
fn function_name(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).take(64).collect()
}

fn bind_tools(cx: &RunCx, node: &ResolvedNode) -> Result<Vec<Bound>, Stop> {
    let mut out: Vec<Bound> = Vec::new();
    for t in &node.spec.tools {
        let target = ToolTarget::parse(&t.reference).map_err(|e| Stop::Fail(e.to_string()))?;
        let b = match target {
            ToolTarget::Node { name, version } => Bound {
                function: function_name(&format!("{name}_v{version}")),
                reference: t.reference.clone(),
                description: format!("Runs the node {name} (version {version}) on the given input."),
                schema: json!({"type": "object"}),
                _tool: None,
            },
            ToolTarget::Mcp { .. } => {
                let tool = cx.ex.tools.resolve(cx.tenant(), &t.reference).map_err(|e| Stop::Fail(e.to_string()))?;
                let info = tool.info();
                Bound {
                    function: function_name(&info.name),
                    reference: t.reference.clone(),
                    description: info.description,
                    schema: info.input_schema,
                    _tool: Some(tool),
                }
            }
        };
        if out.iter().any(|x| x.function == b.function) {
            return Err(Stop::Fail(format!("two tools share the function name '{}'", b.function)));
        }
        out.push(b);
    }
    Ok(out)
}

pub(super) async fn run_agent_at(
    cx: &RunCx,
    node: &ResolvedNode,
    input: Value,
    input_taint: Taint,
    prefix: &str,
    ledger: &Ledger,
    depth: u32,
) -> Result<(Value, Taint), Stop> {
    let mut seen = input_taint;
    let tools = bind_tools(cx, node)?;
    let spec = &node.spec;
    let max_turns = spec
        .rest
        .get("agent")
        .and_then(|a| a.get("max_turns"))
        .and_then(Value::as_u64)
        .map_or(spec.budgets.steps, |n| u32::try_from(n).unwrap_or(u32::MAX));
    let mut system = spec.system_prompt().unwrap_or_default().to_owned();
    if let Some(s) = spec.output_schema() {
        system.push_str("\n\nYour final answer must be one JSON value that matches this JSON Schema:\n");
        system.push_str(&s.to_string());
    }
    let mut messages = Vec::new();
    if !system.is_empty() {
        messages.push(json!({"role": "system", "content": system}));
    }
    messages.push(json!({"role": "user", "content": as_text(&input)}));
    let functions: Vec<Value> = tools
        .iter()
        .map(|t| json!({"type": "function", "function": {"name": t.function, "description": t.description, "parameters": t.schema}}))
        .collect();
    let model = spec.default_model();
    for turn in 0..max_turns {
        let step_id = format!("{prefix}agent#{turn}");
        let mut body = json!({
            "model": model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": cx.max_tokens(ledger, 1024),
        });
        if !functions.is_empty() {
            body["tools"] = Value::Array(functions.clone());
        }
        let request = body.clone();
        let reply = cx
            .step(ledger, &step_id, "agent", "llm", &request, async {
                let r = cx.model(&step_id, body).await?;
                Ok(StepOut { output: r.message, label: None, tokens: r.tokens, usd: r.usd, taint: Taint::new() })
            })
            .await?;
        let message = reply.output;
        let calls: Vec<Value> = message.get("tool_calls").and_then(Value::as_array).cloned().unwrap_or_default();
        let content = message.get("content").and_then(Value::as_str).unwrap_or_default().to_owned();
        if !content.is_empty() {
            cx.set_last(&Value::String(content.clone()));
        }
        if calls.is_empty() {
            let out = match spec.output_schema() {
                Some(_) => extract_json(&content).unwrap_or(Value::String(content)),
                None => Value::String(content),
            };
            return Ok((out, seen));
        }
        messages.push(json!({"role": "assistant", "content": message.get("content").cloned().unwrap_or(Value::Null), "tool_calls": calls}));
        for (n, call) in calls.iter().enumerate() {
            let id = call.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
            let name = call.pointer("/function/name").and_then(Value::as_str).unwrap_or_default();
            let args = call
                .pointer("/function/arguments")
                .and_then(Value::as_str)
                .and_then(|a| serde_json::from_str::<Value>(a).ok())
                .unwrap_or_else(|| json!({}));
            let tool_step = format!("{step_id}.{n}");
            let result = match tools.iter().find(|t| t.function == name) {
                None => json!({"error": format!("there is no tool named '{name}'")}),
                Some(t) => match tool_result(cx, node, t, args, seen.clone(), &tool_step, ledger, depth).await {
                    Ok((v, labels)) => {
                        seen.extend(labels);
                        v
                    }
                    Err(Stop::Fail(e)) => json!({"error": e}),
                    Err(other) => return Err(other),
                },
            };
            messages.push(json!({"role": "tool", "tool_call_id": id, "content": as_text(&result)}));
        }
    }
    Err(Stop::Budget(format!("the agent reached its turn limit ({max_turns}) without a final answer")))
}

#[allow(clippy::too_many_arguments)]
async fn tool_result(
    cx: &RunCx,
    node: &ResolvedNode,
    t: &Bound,
    args: Value,
    args_taint: Taint,
    step_id: &str,
    ledger: &Ledger,
    depth: u32,
) -> Result<(Value, Taint), Stop> {
    call_tool(cx, node, "agent", &t.reference, args, args_taint, step_id, ledger, depth)
        .await
        .map(|s| (s.output, s.taint))
}
