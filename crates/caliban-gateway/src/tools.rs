//! Node tools on the data plane (P3 M4): the tenant's approved MCP tools from the snapshot, and
//! personal-data handling across tools. See docs/tools.md.
//!
//! - [`SnapshotTools`] resolves `mcp://server/tool#sha256:...` to an [`McpTool`] only when the
//!   snapshot carries that exact approved manifest for a server the tenant registered. Each call
//!   connects to the registered URL through the egress guard, re-checks the pin against what the
//!   server lists, and authenticates with a token minted for this call (tenant, node@version, run,
//!   tool; audience-bound; 60 s) or the server's own sealed credential. The run's API key and any
//!   client token never leave the gateway.
//! - [`PiiGuard`] pseudonymizes the arguments of tools not trusted with personal data (with the
//!   tenant's surrogate key: the same surrogates the node's model calls see) and anonymizes tool
//!   results as they enter the run.

use crate::Gateway;
use crate::error::ApiError;
use caliban_config::{ApprovedTool, ConfigHandle, Keyring, ToolServerConfig};
use caliban_ir::{ChatRequest, Message};
use caliban_mcp::client::{McpClient, McpError, ServerTarget};
use caliban_mcp::token::ToolTokenSigner;
use caliban_nodes::ToolTarget;
use caliban_nodes::executor::{DataGuard, Tool, ToolCtx, ToolError, ToolInfo, ToolRegistry};
use caliban_types::PiiMode;
use serde_json::{Map, Value};
use std::sync::{Arc, Weak};

/// The approved MCP tools of each tenant, from the snapshot (plus built-in tools).
pub struct SnapshotTools {
    config: ConfigHandle,
    keyring: Arc<Keyring>,
    client: Arc<McpClient>,
    signer: Option<Arc<ToolTokenSigner>>,
    builtins: Option<Arc<dyn ToolRegistry>>,
}

impl SnapshotTools {
    pub fn new(
        config: ConfigHandle,
        keyring: Arc<Keyring>,
        client: Arc<McpClient>,
        signer: Option<Arc<ToolTokenSigner>>,
    ) -> Self {
        Self { config, keyring, client, signer, builtins: None }
    }

    /// Resolves `builtin://` references there.
    #[must_use]
    pub fn with_builtins(mut self, builtins: Arc<dyn ToolRegistry>) -> Self {
        self.builtins = Some(builtins);
        self
    }
}

impl ToolRegistry for SnapshotTools {
    fn resolve(&self, tenant: &str, reference: &str) -> Result<Arc<dyn Tool>, ToolError> {
        if reference.starts_with("builtin://")
            && let Some(b) = &self.builtins
        {
            return b.resolve(tenant, reference);
        }
        let Ok(ToolTarget::Mcp { server, tool, pin }) = ToolTarget::parse(reference) else {
            return Err(ToolError::UnknownKind(reference.to_owned()));
        };
        let snap = self.config.load();
        let unavailable = |why: &str| ToolError::Unavailable(reference.to_owned(), why.to_owned());
        let t = snap.tenant(&tenant.into()).ok_or_else(|| unavailable("unknown tenant"))?;
        let srv = t
            .tool_servers
            .iter()
            .find(|s| s.name == server)
            .ok_or_else(|| unavailable("the tenant has no tool server with this name"))?;
        let approved = t
            .tools
            .iter()
            .find(|a| a.server == server && a.name == tool && a.pin == pin)
            .ok_or_else(|| unavailable("no approved manifest with this pin (approve it in the tool registry)"))?;
        Ok(Arc::new(McpTool {
            server: srv.clone(),
            approved: approved.clone(),
            client: Arc::clone(&self.client),
            signer: self.signer.clone(),
            keyring: Arc::clone(&self.keyring),
        }))
    }
}

/// One approved tool of a registered MCP server.
pub struct McpTool {
    server: ToolServerConfig,
    approved: ApprovedTool,
    client: Arc<McpClient>,
    signer: Option<Arc<ToolTokenSigner>>,
    keyring: Arc<Keyring>,
}

#[async_trait::async_trait]
impl Tool for McpTool {
    fn info(&self) -> ToolInfo {
        // What the model sees is the approved manifest, never what the server says now.
        ToolInfo {
            name: self.approved.name.clone(),
            description: self.approved.description.clone(),
            input_schema: self.approved.input_schema.clone(),
        }
    }

    fn trusted(&self) -> bool {
        self.server.trusted
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<Value, ToolError> {
        let secret = match &self.server.credential {
            Some(r) => Some(
                r.resolve_with(&self.keyring)
                    .map_err(|e| ToolError::Failed(format!("the server's credential cannot be opened: {e}")))?,
            ),
            None => None,
        };
        let now = chrono::Utc::now().timestamp();
        let mint = |aud: &str| {
            self.signer.as_ref().map(|s| {
                s.mint(
                    aud,
                    &ctx.tenant,
                    &ctx.node,
                    ctx.node_version,
                    &ctx.run_id,
                    &self.approved.name,
                    &ctx.idempotency_key,
                    now,
                )
            })
        };
        let auth = self
            .client
            .auth_for(&self.server.url, &self.server.auth, secret.as_ref().map(caliban_config::Secret::expose), mint)
            .await
            .map_err(mcp_error)?;
        let target = ServerTarget { url: self.server.url.clone(), auth };
        let out = self.client.call(&target, &self.approved.name, &self.approved.pin, args).await.map_err(mcp_error)?;
        if out.is_error {
            let msg = match &out.value {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            return Err(ToolError::Failed(format!("the tool reported an error: {msg}")));
        }
        Ok(out.value)
    }
}

fn mcp_error(e: McpError) -> ToolError {
    match e {
        McpError::Unavailable(m) => ToolError::Transient(m),
        other => ToolError::Failed(other.to_string()),
    }
}

/// Personal data across tools, with the tenant's PII mode and surrogate key.
pub struct PiiGuard {
    gw: Weak<Gateway>,
}

impl PiiGuard {
    pub fn new(gw: &Arc<Gateway>) -> Self {
        Self { gw: Arc::downgrade(gw) }
    }

    /// Runs the PII engine over every string of `v` (keys are left alone). Returns the rewritten
    /// value and how many entities it found.
    async fn rewrite(&self, tenant: &str, v: Value) -> Result<(Value, usize), String> {
        let gw = self.gw.upgrade().ok_or("the gateway is shutting down")?;
        let (mode, key) = {
            let snap = gw.config.load();
            let t = snap.tenant(&tenant.into()).ok_or("unknown tenant")?;
            let mode = snap.pii_mode_for(t);
            (mode, gw.pii_keys.scope_key(snap.pii_surrogate_scope_for(t), tenant))
        };
        if mode == PiiMode::Off {
            return Ok((v, 0));
        }
        let mut texts = Vec::new();
        collect(&v, &mut texts);
        if texts.is_empty() {
            return Ok((v, 0));
        }
        let req = ChatRequest {
            model: String::new(),
            messages: texts
                .into_iter()
                .map(|t| Message { role: "user".into(), content: Value::String(t), extra: Map::new() })
                .collect(),
            stream: false,
            caliban: None,
            extra: Map::new(),
        };
        let (req, p) = gw.protect(req, mode, &key).await.map_err(|e: ApiError| e.error.to_string())?;
        let mut rewritten = req.messages.into_iter().map(|m| match m.content {
            Value::String(s) => s,
            _ => String::new(),
        });
        let mut v = v;
        replace(&mut v, &mut rewritten);
        Ok((v, p.entities))
    }
}

fn collect(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect(x, out)),
        _ => {}
    }
}

fn replace(v: &mut Value, with: &mut impl Iterator<Item = String>) {
    match v {
        Value::String(s) => {
            if let Some(t) = with.next() {
                *s = t;
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| replace(x, with)),
        Value::Object(m) => m.values_mut().for_each(|x| replace(x, with)),
        _ => {}
    }
}

#[async_trait::async_trait]
impl DataGuard for PiiGuard {
    async fn protect(&self, tenant: &str, v: Value) -> Result<(Value, bool), String> {
        self.rewrite(tenant, v).await.map(|(v, n)| (v, n > 0))
    }

    async fn anonymize(&self, tenant: &str, v: Value) -> Result<Value, String> {
        self.rewrite(tenant, v).await.map(|(v, _)| v)
    }

    async fn has_pii(&self, tenant: &str, v: &Value) -> bool {
        self.rewrite(tenant, v.clone()).await.is_ok_and(|(_, n)| n > 0)
    }
}
