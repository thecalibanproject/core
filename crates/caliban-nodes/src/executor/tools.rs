//! Tools a node can call.
//!
//! `node://name@vN` tools are other nodes of the tenant: the executor runs them itself (as a
//! subnode, inside the same run and journal). Every other reference is resolved through a
//! [`ToolRegistry`]: on the data plane, the tenant's approved MCP tools from the snapshot and the
//! built-in tools (`caliban-gateway`). [`NoTools`] refuses everything; [`StaticTools`] maps pinned
//! references to in-process implementations (tests).
//!
//! **Personal data across tools.** A tool not trusted with personal data (the default) receives
//! its arguments with PII replaced by the tenant's surrogates (the same ones its model calls
//! see); a trusted one gets the values as they are. A tool's result is anonymized as it enters
//! the run, like any untrusted input. Both go through the executor's [`DataGuard`].

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
    /// The run's node and version (minted tokens name them).
    pub node: String,
    pub node_version: u32,
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
    /// The call failed and is worth retrying (network, a 5xx): retried up to `guards.tool_retries`
    /// times, then counted against the tool's circuit breaker.
    #[error("{0}")]
    Transient(String),
    #[error("{0}")]
    Failed(String),
}

#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    fn info(&self) -> ToolInfo;
    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<Value, ToolError>;
    /// The tenant trusts this tool with personal data: its arguments are not pseudonymized.
    fn trusted(&self) -> bool {
        false
    }
}

/// Keeps personal data where the tenant's policy allows it (the data plane implements it with
/// its PII engine and the tenant's surrogate keys).
#[async_trait::async_trait]
pub trait DataGuard: Send + Sync {
    /// Arguments for a tool not trusted with personal data: PII replaced by the tenant's
    /// surrogates (or masked). Returns them and whether any PII was found. `Err` refuses the call
    /// (a detector failed: nothing leaves unchecked).
    async fn protect(&self, _tenant: &str, v: Value) -> Result<(Value, bool), String> {
        Ok((v, false))
    }
    /// A value from an untrusted source (a tool result, rows, documents) as it enters the run,
    /// with its PII anonymized.
    async fn anonymize(&self, _tenant: &str, v: Value) -> Result<Value, String> {
        Ok(v)
    }
    /// Whether the value holds personal data (the `pii` taint label).
    async fn has_pii(&self, _tenant: &str, _v: &Value) -> bool {
        false
    }
}

/// No PII handling (tests, and tenants whose PII mode is off).
pub struct NoGuard;
impl DataGuard for NoGuard {}

/// Resolves a tool reference (never `node://`, which the executor handles).
pub trait ToolRegistry: Send + Sync {
    fn resolve(&self, tenant: &str, reference: &str) -> Result<Arc<dyn Tool>, ToolError>;
}

/// No tools (a registry for tests and processes without tools): everything is refused.
pub struct NoTools;

impl ToolRegistry for NoTools {
    fn resolve(&self, _tenant: &str, reference: &str) -> Result<Arc<dyn Tool>, ToolError> {
        Err(refusal(reference))
    }
}

fn refusal(reference: &str) -> ToolError {
    if reference.starts_with("mcp://") {
        ToolError::Unavailable(reference.to_owned(), "no tool registry is configured on this process".into())
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
        assert!(e.to_string().contains("not available") && e.to_string().contains("no tool registry"), "{e}");
        assert_eq!(NoTools.resolve("acme", "ftp://x").err().unwrap(), ToolError::UnknownKind("ftp://x".into()));
    }
}
