//! Nodes: versioned, declarative AI sub-apps (docs/research/04-agent-orchestration.md).
//!
//! A node is config, not code. This crate owns the spec (mirrors `schemas/node.schema.json`),
//! static validation of workflow graphs, and the hierarchical budget ledger.
//!
//! TODO(P3): DAG/state-machine executor on tokio, event-sourced run journal on Postgres
//! (idempotency keys, replay), plan-then-execute templates, taint tracking, WASM `code` vertices.

pub mod budget;

pub use budget::{Budget, BudgetError, Ledger};

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Agent,
    Workflow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolRef {
    /// `mcp://server/tool#sha256:<hash>` (pinned) or `node://name@vN`.
    #[serde(rename = "ref")]
    pub reference: String,
    pub effect: Effect,
    #[serde(default)]
    pub requires: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Budgets {
    pub steps: u32,
    #[serde(default = "d3")]
    pub depth: u32,
    #[serde(default = "d8")]
    pub fanout: u32,
    pub tokens: u64,
    pub wall_clock_s: u64,
}

fn d3() -> u32 {
    3
}
fn d8() -> u32 {
    8
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vertex {
    pub id: String,
    #[serde(rename = "type")]
    pub vertex_type: String,
    #[serde(default)]
    pub config: serde_json::Value,
    pub max_iterations: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub when: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Graph {
    #[serde(default)]
    pub vertices: Vec<Vertex>,
    #[serde(default)]
    pub edges: Vec<Edge>,
}

/// Subset of the node spec that the core enforces. Unknown sections are kept in `rest`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeSpec {
    pub kind: NodeKind,
    #[serde(default)]
    pub tools: Vec<ToolRef>,
    pub budgets: Budgets,
    pub graph: Option<Graph>,
    #[serde(flatten)]
    pub rest: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SpecError {
    #[error("MCP tool '{0}' must be pinned with #sha256:<hash>")]
    UnpinnedTool(String),
    #[error("workflow nodes need a graph")]
    MissingGraph,
    #[error("edge references unknown vertex '{0}'")]
    UnknownVertex(String),
    #[error("cycle through '{0}' without max_iterations on a vertex in the cycle")]
    UnboundedCycle(String),
}

impl NodeSpec {
    /// Static checks run when a node version is published.
    pub fn validate(&self) -> Result<(), SpecError> {
        for t in &self.tools {
            if t.reference.starts_with("mcp://") && !t.reference.contains("#sha256:") {
                return Err(SpecError::UnpinnedTool(t.reference.clone()));
            }
        }
        if self.kind == NodeKind::Workflow {
            let g = self.graph.as_ref().ok_or(SpecError::MissingGraph)?;
            validate_graph(g)?;
        }
        Ok(())
    }
}

fn validate_graph(g: &Graph) -> Result<(), SpecError> {
    let ids: HashSet<&str> = g.vertices.iter().map(|v| v.id.as_str()).collect();
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in &g.edges {
        for end in [&e.from, &e.to] {
            if !ids.contains(end.as_str()) {
                return Err(SpecError::UnknownVertex(end.clone()));
            }
        }
        adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
    }
    let bounded: HashSet<&str> =
        g.vertices.iter().filter(|v| v.max_iterations.is_some()).map(|v| v.id.as_str()).collect();
    // DFS for cycles; every cycle must contain a bounded vertex.
    fn dfs<'a>(
        v: &'a str,
        adj: &HashMap<&'a str, Vec<&'a str>>,
        bounded: &HashSet<&'a str>,
        stack: &mut Vec<&'a str>,
        done: &mut HashSet<&'a str>,
    ) -> Result<(), SpecError> {
        if let Some(pos) = stack.iter().position(|&s| s == v) {
            if !stack[pos..].iter().any(|s| bounded.contains(s)) {
                return Err(SpecError::UnboundedCycle(v.to_owned()));
            }
            return Ok(());
        }
        if done.contains(v) {
            return Ok(());
        }
        stack.push(v);
        for &n in adj.get(v).map(Vec::as_slice).unwrap_or(&[]) {
            dfs(n, adj, bounded, stack, done)?;
        }
        stack.pop();
        done.insert(v);
        Ok(())
    }
    let mut done = HashSet::new();
    for v in &g.vertices {
        dfs(v.id.as_str(), &adj, &bounded, &mut Vec::new(), &mut done)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(json: serde_json::Value) -> NodeSpec {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn unpinned_mcp_tool_rejected() {
        let s = spec(serde_json::json!({
            "kind": "agent", "prompt": {"system": "x"}, "model_policy": {},
            "tools": [{"ref": "mcp://erp/lookup", "effect": "read"}],
            "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30}
        }));
        assert!(matches!(s.validate(), Err(SpecError::UnpinnedTool(_))));
    }

    #[test]
    fn cycles_need_max_iterations() {
        let base = |bounded: bool| {
            spec(serde_json::json!({
                "kind": "workflow", "prompt": {"system": "x"}, "model_policy": {},
                "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30},
                "graph": {
                    "vertices": [{"id": "draft", "type": "llm"},
                                 {"id": "check", "type": "verify", "max_iterations": if bounded { serde_json::json!(3) } else { serde_json::Value::Null }}],
                    "edges": [{"from": "draft", "to": "check"}, {"from": "check", "to": "draft", "when": "fail"}]
                }
            }))
        };
        assert!(matches!(base(false).validate(), Err(SpecError::UnboundedCycle(_))));
        assert_eq!(base(true).validate(), Ok(()));
    }
}
