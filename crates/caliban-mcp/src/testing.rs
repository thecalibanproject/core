//! A small Streamable HTTP MCP server for tests (`test-server` feature), built with `rmcp`.
//!
//! Its tools are set at start and can be replaced at any time (a manifest change after approval,
//! a "rug pull"). It records the `Authorization` header of every request and every tool call it
//! served, and can check each request's bearer token (a Caliban tool token) before serving it.

use crate::ToolManifest;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::Value;
use std::sync::Arc;

/// What a test tool does with its arguments.
pub type Handler = Arc<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;

#[derive(Clone)]
pub struct TestTool {
    pub manifest: ToolManifest,
    pub handler: Handler,
}

impl TestTool {
    pub fn new(manifest: ToolManifest, f: impl Fn(&Value) -> Result<Value, String> + Send + Sync + 'static) -> Self {
        Self { manifest, handler: Arc::new(f) }
    }
}

/// A call the server served.
#[derive(Debug, Clone, PartialEq)]
pub struct Received {
    pub tool: String,
    pub args: Value,
}

/// Checks a request's `Authorization` header (`None` when absent); `Err` answers 401.
pub type AuthCheck = Arc<dyn Fn(Option<&str>) -> Result<(), String> + Send + Sync>;

#[derive(Default)]
struct State {
    tools: Mutex<Vec<TestTool>>,
    calls: Mutex<Vec<Received>>,
    authorizations: Mutex<Vec<Option<String>>>,
    rejected: Mutex<Vec<String>>,
    auth: Mutex<Option<AuthCheck>>,
}

#[derive(Clone)]
pub struct TestMcpServer {
    state: Arc<State>,
    /// `http://127.0.0.1:<port>/mcp`.
    pub url: String,
    pub port: u16,
    task: Arc<tokio::task::JoinHandle<()>>,
}

impl Drop for TestMcpServer {
    fn drop(&mut self) {
        if Arc::strong_count(&self.task) == 1 {
            self.task.abort();
        }
    }
}

#[derive(Clone)]
struct Handle(Arc<State>);

impl ServerHandler for Handle {
    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = self.0.tools.lock().iter().map(|t| tool_of(&t.manifest)).collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let args = request.arguments.map_or(Value::Null, Value::Object);
        let tool = self.0.tools.lock().iter().find(|t| t.manifest.name == request.name).cloned();
        let Some(tool) = tool else {
            return Err(ErrorData::invalid_params(format!("no tool named {}", request.name), None));
        };
        self.0.calls.lock().push(Received { tool: tool.manifest.name.clone(), args: args.clone() });
        let result = match (tool.handler)(&args) {
            Ok(v) => CallToolResult::success(vec![ContentBlock::text(v.to_string())]),
            Err(e) => CallToolResult::error(vec![ContentBlock::text(e)]),
        };
        Ok(result.into())
    }
}

fn tool_of(m: &ToolManifest) -> Tool {
    let schema = match &m.input_schema {
        Value::Object(o) => o.clone(),
        _ => serde_json::Map::new(),
    };
    let mut t = Tool::default();
    t.name = m.name.clone().into();
    t.description = Some(m.description.clone().into());
    t.input_schema = Arc::new(schema);
    t
}

impl TestMcpServer {
    /// Starts on `127.0.0.1:<random port>`; `hosts` are the extra `Host` names it accepts (the
    /// names tests register it under).
    pub async fn start(tools: Vec<TestTool>, hosts: &[&str]) -> Self {
        let state = Arc::new(State::default());
        *state.tools.lock() = tools;
        let handle = Handle(Arc::clone(&state));
        let mut allowed: Vec<String> = vec!["localhost".into(), "127.0.0.1".into()];
        allowed.extend(hosts.iter().map(|h| (*h).to_owned()));
        let config = StreamableHttpServerConfig::default().with_allowed_hosts(allowed);
        let service =
            StreamableHttpService::new(move || Ok(handle.clone()), Arc::new(LocalSessionManager::default()), config);
        let st = Arc::clone(&state);
        let app = axum::Router::new().nest_service("/mcp", service).layer(axum::middleware::from_fn(
            move |req: Request, next: Next| {
                let st = Arc::clone(&st);
                async move {
                    let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_owned);
                    st.authorizations.lock().push(auth.clone());
                    let check = st.auth.lock().clone();
                    if let Some(check) = check
                        && let Err(e) = check(auth.as_deref())
                    {
                        st.rejected.lock().push(e.clone());
                        return (axum::http::StatusCode::UNAUTHORIZED, e).into_response();
                    }
                    let resp: Response = next.run(req).await;
                    resp
                }
            },
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { state, url: format!("http://127.0.0.1:{port}/mcp"), port, task: Arc::new(task) }
    }

    /// Replaces the tools (a manifest change after approval).
    pub fn set_tools(&self, tools: Vec<TestTool>) {
        *self.state.tools.lock() = tools;
    }

    /// Checks every request's `Authorization` header from now on.
    pub fn require_auth(&self, check: impl Fn(Option<&str>) -> Result<(), String> + Send + Sync + 'static) {
        *self.state.auth.lock() = Some(Arc::new(check));
    }

    pub fn calls(&self) -> Vec<Received> {
        self.state.calls.lock().clone()
    }

    /// The `Authorization` header of every request it received.
    pub fn authorizations(&self) -> Vec<Option<String>> {
        self.state.authorizations.lock().clone()
    }

    /// Why requests were refused by the auth check.
    pub fn rejected(&self) -> Vec<String> {
        self.state.rejected.lock().clone()
    }
}
