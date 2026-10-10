//! Tools a node can call.
//!
//! `node://name@vN` tools are other nodes of the tenant: the executor runs them itself (as a
//! subnode, inside the same run and journal). Every other reference is resolved through a
//! [`ToolRegistry`]. This batch ships no real MCP client: [`NoTools`] refuses `mcp://` references
//! with a clear error (TODO(P3 M4): the `rmcp` client, the per-tenant approved tool registry with
//! pinned manifests, minted per-call tokens and the egress allowlist), and [`StaticTools`] maps
//! pinned references to in-process implementations (tests and the reference node's stub).

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// What a model sees of a tool (and what a pin hashes, for `mcp://` tools).
#[derive(Debug, Clone, PartialEq)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// The context of one tool call.
#[derive(Debug, Clone)]
pub struct ToolCtx {
    pub tenant: String,
    pub run_id: String,
    pub step_id: String,
    /// Derived from (run id, step id): a tool with side effects uses it to apply a call once.
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ToolError {
    #[error("tool '{0}' is not available: {1}")]
    Unavailable(String, String),
    #[error("tool '{0}' has an unknown kind")]
    UnknownKind(String),
    #[error("{0}")]
    Failed(String),
}

#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    fn info(&self) -> ToolInfo;
    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<Value, ToolError>;
}

/// Resolves a tool reference (never `node://`, which the executor handles).
pub trait ToolRegistry: Send + Sync {
    fn resolve(&self, tenant: &str, reference: &str) -> Result<Arc<dyn Tool>, ToolError>;
}

/// No tools: `mcp://` is refused until the MCP client exists (P3 M4); other kinds are unknown.
pub struct NoTools;

impl ToolRegistry for NoTools {
    fn resolve(&self, _tenant: &str, reference: &str) -> Result<Arc<dyn Tool>, ToolError> {
        Err(refusal(reference))
    }
}

fn refusal(reference: &str) -> ToolError {
    if reference.starts_with("mcp://") {
        ToolError::Unavailable(
            reference.to_owned(),
            "MCP client tools are not available in this release (the approved tool registry and MCP client arrive in P3 M4)"
                .into(),
        )
    } else {
        ToolError::UnknownKind(reference.to_owned())
    }
}

/// In-process tools by exact reference (for any tenant), falling back to [`NoTools`].
#[derive(Default, Clone)]
pub struct StaticTools {
    tools: HashMap<String, Arc<dyn Tool>>,
}

impl StaticTools {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, reference: impl Into<String>, tool: Arc<dyn Tool>) -> Self {
        self.tools.insert(reference.into(), tool);
        self
    }
}

impl ToolRegistry for StaticTools {
    fn resolve(&self, _tenant: &str, reference: &str) -> Result<Arc<dyn Tool>, ToolError> {
        self.tools.get(reference).cloned().ok_or_else(|| refusal(reference))
    }
}

/// A tool from a closure (tests, stubs).
pub struct FnTool<F> {
    pub info: ToolInfo,
    pub f: F,
}

#[async_trait::async_trait]
impl<F> Tool for FnTool<F>
where
    F: Fn(&ToolCtx, Value) -> Result<Value, ToolError> + Send + Sync,
{
    fn info(&self) -> ToolInfo {
        self.info.clone()
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<Value, ToolError> {
        (self.f)(ctx, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_mcp_tools_fail_clearly() {
        let e = NoTools.resolve("acme", "mcp://erp/lookup#sha256:00").err().unwrap();
        assert!(e.to_string().contains("not available") && e.to_string().contains("M4"), "{e}");
        assert_eq!(NoTools.resolve("acme", "ftp://x").err().unwrap(), ToolError::UnknownKind("ftp://x".into()));
    }
}
