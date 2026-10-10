//! Nodes: versioned, declarative AI sub-apps (docs/research/04-agent-orchestration.md, P3 plan).
//!
//! A node is config, not code. This crate owns:
//! - the spec (mirrors `schemas/node.schema.json`) and its static checks ([`NodeSpec::validate`]);
//! - content hashes and publish-time validation against the tenant ([`hash`], [`publish`]);
//! - the hierarchical budget ledger ([`budget`]).
//!
//! TODO(P3 M3): USD, depth and fan-out caps in the ledger, tenant spend caps. TODO(P3 M4): MCP
//! client tools and the approved tool registry. TODO(P3 M8): WASM `code` vertices.

pub mod budget;
pub mod diff;
pub mod hash;
pub mod publish;
pub mod schema;

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

/// A parsed tool reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ToolTarget {
    /// `mcp://server/tool#sha256:<hex>`: a tool of a customer MCP server, pinned to its manifest.
    Mcp { server: String, tool: String, pin: String },
    /// `node://name@vN`: another node of the same tenant, pinned to a version.
    Node { name: String, version: u32 },
}

impl ToolTarget {
    pub fn parse(reference: &str) -> Result<Self, SpecError> {
        if let Some(rest) = reference.strip_prefix("mcp://") {
            let (path, pin) = rest.split_once('#').ok_or_else(|| SpecError::UnpinnedTool(reference.to_owned()))?;
            let hex = pin.strip_prefix("sha256:").ok_or_else(|| SpecError::UnpinnedTool(reference.to_owned()))?;
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(SpecError::UnpinnedTool(reference.to_owned()));
            }
            let (server, tool) = path.split_once('/').ok_or_else(|| SpecError::BadToolRef(reference.to_owned()))?;
            if server.is_empty() || tool.is_empty() || tool.contains('/') {
                return Err(SpecError::BadToolRef(reference.to_owned()));
            }
            return Ok(ToolTarget::Mcp { server: server.into(), tool: tool.into(), pin: pin.to_ascii_lowercase() });
        }
        if let Some(rest) = reference.strip_prefix("node://") {
            return parse_node_ref(rest).ok_or_else(|| SpecError::BadNodeRef(reference.to_owned()));
        }
        Err(SpecError::UnknownToolKind(reference.to_owned()))
    }
}

/// `name@vN` (the part after `node://`).
fn parse_node_ref(s: &str) -> Option<ToolTarget> {
    let (name, v) = s.split_once("@v")?;
    let version: u32 = v.parse().ok().filter(|v| *v > 0)?;
    valid_node_name(name).then(|| ToolTarget::Node { name: name.to_owned(), version })
}

/// Node names: 1 to 64 characters of `[a-z0-9_-]`, starting with a letter or digit.
pub fn valid_node_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
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

/// Vertex kinds of a workflow graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VertexKind {
    Llm,
    Tool,
    Router,
    Map,
    Reduce,
    Verify,
    Human,
    Subnode,
    /// WASM-sandboxed transform: not yet supported (P3 M8), refused at publish.
    Code,
}

impl VertexKind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "llm" => Self::Llm,
            "tool" => Self::Tool,
            "router" => Self::Router,
            "map" => Self::Map,
            "reduce" => Self::Reduce,
            "verify" => Self::Verify,
            "human" => Self::Human,
            "subnode" => Self::Subnode,
            "code" => Self::Code,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Llm => "llm",
            Self::Tool => "tool",
            Self::Router => "router",
            Self::Map => "map",
            Self::Reduce => "reduce",
            Self::Verify => "verify",
            Self::Human => "human",
            Self::Subnode => "subnode",
            Self::Code => "code",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vertex {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "type")]
    pub vertex_type: String,
    #[serde(default)]
    pub config: serde_json::Value,
    pub max_iterations: Option<u32>,
}

impl Vertex {
    pub fn kind(&self) -> Option<VertexKind> {
        VertexKind::parse(&self.vertex_type)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub when: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Graph {
    /// The vertex a run starts at; the first vertex when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    #[serde(default)]
    pub vertices: Vec<Vertex>,
    #[serde(default)]
    pub edges: Vec<Edge>,
}

impl Graph {
    pub fn vertex(&self, id: &str) -> Option<&Vertex> {
        self.vertices.iter().find(|v| v.id == id)
    }

    pub fn entry_vertex(&self) -> Option<&Vertex> {
        match &self.entry {
            Some(e) => self.vertex(e),
            None => self.vertices.first(),
        }
    }
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
    #[error("MCP tool '{0}' must be pinned with #sha256:<64 hex characters>")]
    UnpinnedTool(String),
    #[error("tool reference '{0}' is malformed (expected mcp://server/tool#sha256:<hash>)")]
    BadToolRef(String),
    #[error("node reference '{0}' is malformed (expected node://name@vN)")]
    BadNodeRef(String),
    #[error("tool '{0}' has an unknown kind (only mcp:// and node:// are supported)")]
    UnknownToolKind(String),
    #[error("workflow nodes need a graph")]
    MissingGraph,
    #[error("the graph has no vertices")]
    EmptyGraph,
    #[error("duplicate or empty vertex id '{0}'")]
    DuplicateVertex(String),
    #[error("edge references unknown vertex '{0}'")]
    UnknownVertex(String),
    #[error("cycle through '{0}' without max_iterations on a vertex in the cycle")]
    UnboundedCycle(String),
    #[error("vertex '{0}': unknown type '{1}'")]
    UnknownVertexType(String, String),
    #[error("vertex '{0}': the `code` vertex type is not yet supported (it arrives with the WASM sandbox)")]
    CodeNotSupported(String),
    #[error("vertex '{0}': {1}")]
    BadVertex(String, String),
    #[error("budgets: {0}")]
    BadBudgets(String),
    #[error("{0}")]
    BadSchema(String),
}

impl NodeSpec {
    /// Static checks run when a node version is created and again when it is published.
    pub fn validate(&self) -> Result<(), SpecError> {
        let b = &self.budgets;
        if b.steps == 0 || b.tokens == 0 || b.wall_clock_s == 0 || b.depth == 0 || b.fanout == 0 {
            return Err(SpecError::BadBudgets("steps, tokens, wall_clock_s, depth and fanout must be positive".into()));
        }
        for t in &self.tools {
            ToolTarget::parse(&t.reference)?;
        }
        if let Some(s) = self.output_schema() {
            schema::check_supported(s).map_err(|e| SpecError::BadSchema(format!("prompt.output_schema: {e}")))?;
        }
        if self.kind == NodeKind::Workflow {
            let g = self.graph.as_ref().ok_or(SpecError::MissingGraph)?;
            validate_graph(g)?;
            for v in &g.vertices {
                self.validate_vertex(v, true)?;
            }
        }
        Ok(())
    }

    /// `prompt.system`, if any.
    pub fn system_prompt(&self) -> Option<&str> {
        self.rest.get("prompt").and_then(|p| p.get("system")).and_then(serde_json::Value::as_str)
    }

    /// `prompt.output_schema`, if any.
    pub fn output_schema(&self) -> Option<&serde_json::Value> {
        self.rest.get("prompt").and_then(|p| p.get("output_schema"))
    }

    /// `prompt.input_schema`, if any: validated against the run input.
    pub fn input_schema(&self) -> Option<&serde_json::Value> {
        self.rest.get("prompt").and_then(|p| p.get("input_schema"))
    }

    /// `datasources.scopes`.
    pub fn datasource_scopes(&self) -> Vec<String> {
        self.rest
            .get("datasources")
            .and_then(|d| d.get("scopes"))
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_owned)).collect())
            .unwrap_or_default()
    }

    /// The model the node's calls ask for: `model_policy.model`, else the first candidate that is a
    /// model id (not a `tier:` class), else `caliban/auto` (the router picks).
    pub fn default_model(&self) -> String {
        let mp = self.rest.get("model_policy");
        if let Some(m) = mp.and_then(|m| m.get("model")).and_then(serde_json::Value::as_str) {
            return m.to_owned();
        }
        mp.and_then(|m| m.get("candidates"))
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .find(|c| !c.starts_with("tier:"))
            .unwrap_or("caliban/auto")
            .to_owned()
    }

    /// Every `node://` this version calls (tools and subnode vertices), deduplicated.
    pub fn node_refs(&self) -> Vec<(String, u32)> {
        let mut out: Vec<(String, u32)> = Vec::new();
        let mut push = |t: ToolTarget| {
            if let ToolTarget::Node { name, version } = t
                && !out.iter().any(|(n, v)| *n == name && *v == version)
            {
                out.push((name, version));
            }
        };
        for t in &self.tools {
            if let Ok(t) = ToolTarget::parse(&t.reference) {
                push(t);
            }
        }
        for v in self.graph.iter().flat_map(|g| g.vertices.iter()) {
            for c in std::iter::once(&v.config).chain(v.config.get("body").and_then(|b| b.get("config"))) {
                if let Some(r) = c.get("node").and_then(serde_json::Value::as_str)
                    && let Ok(t) = ToolTarget::parse(r)
                {
                    push(t);
                }
            }
        }
        out
    }

    /// Whether `r` is declared in `tools`.
    pub fn declares_tool(&self, r: &str) -> bool {
        self.tools.iter().any(|t| t.reference == r)
    }

    fn validate_vertex(&self, v: &Vertex, top: bool) -> Result<(), SpecError> {
        let bad = |m: &str| SpecError::BadVertex(v.id.clone(), m.to_owned());
        let kind = v.kind().ok_or_else(|| SpecError::UnknownVertexType(v.id.clone(), v.vertex_type.clone()))?;
        let c = &v.config;
        if !c.is_null() && !c.is_object() {
            return Err(bad("config must be an object"));
        }
        for key in ["input_schema", "output_schema"] {
            if let Some(s) = c.get(key) {
                schema::check_supported(s).map_err(|e| bad(&format!("{key}: {e}")))?;
            }
        }
        let str_field = |k: &str| c.get(k).and_then(serde_json::Value::as_str);
        match kind {
            VertexKind::Code => return Err(SpecError::CodeNotSupported(v.id.clone())),
            VertexKind::Llm | VertexKind::Reduce => {}
            VertexKind::Tool => {
                let r = str_field("tool").ok_or_else(|| bad("config.tool (a tool reference) is required"))?;
                ToolTarget::parse(r)?;
                if !self.declares_tool(r) {
                    return Err(bad(&format!("tool '{r}' is not declared in the node's tools")));
                }
            }
            VertexKind::Router => {
                let routes = c.get("routes").and_then(serde_json::Value::as_object);
                if routes.is_none_or(serde_json::Map::is_empty) {
                    return Err(bad("config.routes (label -> description) must name at least one route"));
                }
            }
            VertexKind::Map => {
                if !top {
                    return Err(bad("map vertices cannot be nested"));
                }
                let body =
                    c.get("body").ok_or_else(|| bad("config.body (the vertex applied to each item) is required"))?;
                let mut body: Vertex = serde_json::from_value(body.clone())
                    .map_err(|e| bad(&format!("config.body is not a vertex: {e}")))?;
                if body.id.is_empty() {
                    body.id = format!("{}.body", v.id);
                }
                if matches!(body.kind(), Some(VertexKind::Human | VertexKind::Map)) {
                    return Err(bad("config.body cannot be a human or map vertex"));
                }
                self.validate_vertex(&body, false)?;
            }
            VertexKind::Verify => match str_field("check").unwrap_or("schema") {
                "schema" => {
                    let s = c.get("schema").ok_or_else(|| bad("check \"schema\" needs config.schema"))?;
                    schema::check_supported(s).map_err(|e| bad(&format!("schema: {e}")))?;
                }
                "llm" => {}
                other => return Err(bad(&format!("unknown check '{other}' (schema or llm)"))),
            },
            VertexKind::Human => {
                if str_field("question").is_none() {
                    return Err(bad("config.question is required"));
                }
            }
            VertexKind::Subnode => {
                let r = str_field("node").ok_or_else(|| bad("config.node (node://name@vN) is required"))?;
                match ToolTarget::parse(r)? {
                    ToolTarget::Node { .. } => {}
                    ToolTarget::Mcp { .. } => return Err(bad("config.node must be a node:// reference")),
                }
            }
        }
        Ok(())
    }
}

fn validate_graph(g: &Graph) -> Result<(), SpecError> {
    if g.vertices.is_empty() {
        return Err(SpecError::EmptyGraph);
    }
    let mut ids: HashSet<&str> = HashSet::new();
    for v in &g.vertices {
        if v.id.is_empty() || !ids.insert(v.id.as_str()) {
            return Err(SpecError::DuplicateVertex(v.id.clone()));
        }
    }
    if let Some(e) = &g.entry
        && !ids.contains(e.as_str())
    {
        return Err(SpecError::UnknownVertex(e.clone()));
    }
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
    use serde_json::json;

    fn spec(json: serde_json::Value) -> NodeSpec {
        serde_json::from_value(json).unwrap()
    }

    const PIN: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn unpinned_mcp_tool_rejected() {
        let s = spec(json!({
            "kind": "agent", "prompt": {"system": "x"}, "model_policy": {},
            "tools": [{"ref": "mcp://erp/lookup", "effect": "read"}],
            "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30}
        }));
        assert!(matches!(s.validate(), Err(SpecError::UnpinnedTool(_))));
        let s = spec(json!({
            "kind": "agent", "prompt": {"system": "x"}, "model_policy": {},
            "tools": [{"ref": "mcp://erp/lookup#sha256:abc", "effect": "read"}],
            "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30}
        }));
        assert!(matches!(s.validate(), Err(SpecError::UnpinnedTool(_))), "a short pin is not a pin");
    }

    #[test]
    fn tool_references_parse() {
        assert_eq!(
            ToolTarget::parse(&format!("mcp://erp/lookup#{PIN}")).unwrap(),
            ToolTarget::Mcp { server: "erp".into(), tool: "lookup".into(), pin: PIN.into() }
        );
        assert_eq!(
            ToolTarget::parse("node://vendor-risk@v3").unwrap(),
            ToolTarget::Node { name: "vendor-risk".into(), version: 3 }
        );
        for bad in ["node://x", "node://x@v0", "node://X@v1", "node://@v1"] {
            assert!(matches!(ToolTarget::parse(bad), Err(SpecError::BadNodeRef(_))), "{bad}");
        }
        assert!(matches!(ToolTarget::parse("http://evil/tool"), Err(SpecError::UnknownToolKind(_))));
    }

    #[test]
    fn cycles_need_max_iterations() {
        let base = |bounded: bool| {
            spec(json!({
                "kind": "workflow", "prompt": {"system": "x"}, "model_policy": {},
                "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30},
                "graph": {
                    "vertices": [{"id": "draft", "type": "llm"},
                                 {"id": "check", "type": "verify", "config": {"check": "llm"}, "max_iterations": if bounded { json!(3) } else { serde_json::Value::Null }}],
                    "edges": [{"from": "draft", "to": "check"}, {"from": "check", "to": "draft", "when": "fail"}]
                }
            }))
        };
        assert!(matches!(base(false).validate(), Err(SpecError::UnboundedCycle(_))));
        assert_eq!(base(true).validate(), Ok(()));
    }

    #[test]
    fn code_vertices_are_not_yet_supported() {
        let s = spec(json!({
            "kind": "workflow", "prompt": {"system": "x"}, "model_policy": {},
            "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30},
            "graph": {"vertices": [{"id": "transform", "type": "code"}], "edges": []}
        }));
        let e = s.validate().unwrap_err();
        assert!(matches!(e, SpecError::CodeNotSupported(_)));
        assert!(e.to_string().contains("not yet supported"), "{e}");
    }

    #[test]
    fn vertex_configs_are_checked() {
        let with = |v: serde_json::Value, tools: serde_json::Value| {
            spec(json!({
                "kind": "workflow", "prompt": {"system": "x"}, "model_policy": {}, "tools": tools,
                "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30},
                "graph": {"vertices": [v], "edges": []}
            }))
            .validate()
        };
        let tool = format!("mcp://cat/search#{PIN}");
        assert!(with(json!({"id": "t", "type": "tool", "config": {"tool": tool}}), json!([])).is_err(), "undeclared");
        assert!(
            with(
                json!({"id": "t", "type": "tool", "config": {"tool": tool}}),
                json!([{"ref": tool, "effect": "read"}])
            )
            .is_ok()
        );
        assert!(with(json!({"id": "r", "type": "router", "config": {}}), json!([])).is_err());
        assert!(with(json!({"id": "h", "type": "human", "config": {}}), json!([])).is_err());
        assert!(with(json!({"id": "s", "type": "subnode", "config": {"node": "node://x@v1"}}), json!([])).is_ok());
        assert!(
            with(json!({"id": "m", "type": "map", "config": {"body": {"id": "b", "type": "human"}}}), json!([]))
                .is_err()
        );
        assert!(
            with(
                json!({"id": "v", "type": "verify", "config": {"check": "schema", "schema": {"$ref": "#/x"}}}),
                json!([])
            )
            .is_err(),
            "unsupported schema keywords are refused"
        );
        assert!(with(json!({"id": "x", "type": "nope"}), json!([])).is_err());
    }

    #[test]
    fn node_refs_cover_tools_and_subnodes() {
        let s = spec(json!({
            "kind": "workflow", "prompt": {"system": "x"}, "model_policy": {},
            "tools": [{"ref": "node://a@v1", "effect": "read"}],
            "budgets": {"steps": 5, "tokens": 1000, "wall_clock_s": 30},
            "graph": {"vertices": [{"id": "s", "type": "subnode", "config": {"node": "node://b@v2"}},
                                   {"id": "m", "type": "map", "config": {"body": {"id": "x", "type": "subnode", "config": {"node": "node://a@v1"}}}}],
                      "edges": []}
        }));
        assert_eq!(s.node_refs(), vec![("a".to_owned(), 1), ("b".to_owned(), 2)]);
    }

    #[test]
    fn default_model_prefers_explicit_ids() {
        let with = |mp: serde_json::Value| {
            spec(json!({"kind": "agent", "model_policy": mp, "budgets": {"steps": 1, "tokens": 1, "wall_clock_s": 1}}))
                .default_model()
        };
        assert_eq!(with(json!({})), "caliban/auto");
        assert_eq!(with(json!({"candidates": ["tier:small", "local/qwen"]})), "local/qwen");
        assert_eq!(with(json!({"model": "ext/gpt", "candidates": ["local/qwen"]})), "ext/gpt");
    }
}
