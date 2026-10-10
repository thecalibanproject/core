//! The MCP server (P3 M5): every published node a tenant API key may run is an MCP tool, at `/mcp`
//! (Streamable HTTP, stateless: any router answers any request, so a fleet behind a load balancer
//! needs no session affinity).
//!
//! - **Auth**: the tenant API key as bearer token (`Authorization: Bearer cal_...`, or `x-api-key`);
//!   anything else is a `401` before MCP is spoken.
//! - **`tools/list`**: the live (promoted) version of each published node of the key's tenant that
//!   the key may run (its node allowlist). Name: the node's name. Description: the spec's
//!   `description`. Input schema: the node's `prompt.input_schema` when it is an object schema;
//!   another schema is wrapped as `{"input": <schema>}`; without one, `{"input": <any JSON>}`.
//!   (Specs are sealed: a router opens them with `CALIBAN_KEK`; without it, tools are listed with
//!   the generic `{"input"}` schema.)
//! - **`tools/call`**: runs the node through the same path as the run API (a router forwards it to
//!   a worker) and waits for it, at most `CALIBAN_NODE_SYNC_WAIT_SECS`. The result is the node's
//!   output (text, and `structuredContent` when it is an object). A run that fails is an error
//!   result; a run still going at the cap, or waiting for a human, returns its state and run id
//!   (follow it with the run API).
//! - **Tasks** (`CALIBAN_MCP_TASKS=true`; off by default, the spec marks Tasks experimental): a
//!   client that declares the tasks extension gets a task for every `tools/call` instead of
//!   waiting. The task id is the run id, so tasks are as durable as runs and any router answers
//!   `tasks/get` (the run's state; a human step is an elicitation request whose answer goes in
//!   `tasks/update` as `{"answer": ...}`) and `tasks/cancel` (cancels the run).

use crate::Gateway;
use crate::runs::{Caller, RunError, Runs, Start, final_run};
use axum::Router;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use caliban_nodes::chat::output_text;
use futures::StreamExt;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams, ContentBlock, CreateTaskResult,
    DetailedTask, GetTaskParams, GetTaskResult, InputRequest, InputRequests, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerConfig, Task, TaskPayload, TaskStatus, Tool, UpdateTaskParams,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// MCP server settings (`CALIBAN_MCP_TASKS`, `CALIBAN_MCP_ALLOWED_HOSTS`).
#[derive(Debug, Clone, Default)]
pub struct McpSettings {
    /// Answer `tools/call` with a task when the client declares the tasks extension.
    pub tasks: bool,
    /// `Host` values accepted (DNS-rebinding protection). Empty: any (every request needs an API
    /// key anyway).
    pub allowed_hosts: Vec<String>,
}

impl McpSettings {
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let tasks = match get("CALIBAN_MCP_TASKS").map(|v| v.trim().to_ascii_lowercase()) {
            None => false,
            Some(v) if v.is_empty() || v == "false" || v == "0" => false,
            Some(v) if v == "true" || v == "1" => true,
            Some(v) => return Err(format!("CALIBAN_MCP_TASKS must be true or false, got {v:?}")),
        };
        let allowed_hosts = get("CALIBAN_MCP_ALLOWED_HOSTS")
            .map(|v| v.split(',').map(|h| h.trim().to_owned()).filter(|h| !h.is_empty()).collect())
            .unwrap_or_default();
        Ok(Self { tasks, allowed_hosts })
    }
}

/// `/mcp` (merged into the data-plane app).
pub(crate) fn routes(gw: &Arc<Gateway>) -> Router<Arc<Gateway>> {
    let settings = gw.mcp_settings();
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(settings.allowed_hosts.clone());
    let handler = NodesServer { gw: Arc::clone(gw), tasks: settings.tasks };
    let service =
        StreamableHttpService::new(move || Ok(handler.clone()), Arc::new(NeverSessionManager::default()), config);
    let auth_gw = Arc::clone(gw);
    Router::new().nest_service("/mcp", service).route_layer(axum::middleware::from_fn(
        move |req: Request, next: Next| {
            let gw = Arc::clone(&auth_gw);
            async move {
                // The API key first: MCP is spoken only with a tenant.
                if Caller::from_headers(&gw, req.headers()).is_err() {
                    let mut resp = crate::runs::unauthenticated().into_response();
                    resp.headers_mut()
                        .insert("www-authenticate", axum::http::HeaderValue::from_static("Bearer realm=\"caliban\""));
                    return resp;
                }
                next.run(req).await
            }
        },
    ))
}

#[derive(Clone)]
struct NodesServer {
    gw: Arc<Gateway>,
    tasks: bool,
}

fn rpc(e: RunError) -> ErrorData {
    match e.status {
        StatusCode::NOT_FOUND => ErrorData::invalid_params(e.message, None),
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => ErrorData::invalid_request(e.message, None),
        s if s.is_client_error() => ErrorData::invalid_params(e.message, None),
        _ => ErrorData::internal_error(e.message, None),
    }
}

/// How a node appears as a tool, and how its arguments become the run input.
struct NodeTool {
    description: String,
    /// The node's own input schema, if it has one.
    schema: Option<Value>,
}

impl NodeTool {
    fn input_schema(&self) -> Map<String, Value> {
        let s = match &self.schema {
            Some(s) if s.get("type").and_then(Value::as_str) == Some("object") => s.clone(),
            Some(s) => json!({"type": "object", "properties": {"input": s}, "required": ["input"]}),
            None => {
                json!({"type": "object", "properties": {"input": {"description": "The node's input (any JSON; most nodes take text)"}}})
            }
        };
        s.as_object().cloned().unwrap_or_default()
    }

    fn run_input(&self, args: Map<String, Value>) -> Value {
        let wrapped = !self.schema.as_ref().is_some_and(|s| s.get("type").and_then(Value::as_str) == Some("object"));
        if wrapped && args.len() == 1 && args.contains_key("input") {
            return args.get("input").cloned().unwrap_or(Value::Null);
        }
        Value::Object(args)
    }
}

impl NodesServer {
    fn caller(&self, ctx: &RequestContext<RoleServer>) -> Result<(Caller, axum::http::HeaderMap), ErrorData> {
        let parts = ctx
            .extensions
            .get::<axum::http::request::Parts>()
            .ok_or_else(|| ErrorData::internal_error("no HTTP request", None))?;
        let caller = Caller::from_headers(&self.gw, &parts.headers).map_err(rpc)?;
        Ok((caller, parts.headers.clone()))
    }

    fn runs(&self) -> Result<Runs<'_>, ErrorData> {
        Runs::of(&self.gw).ok_or_else(|| rpc(crate::runs::not_enabled()))
    }

    /// The live nodes the caller may run, with what the snapshot says about them.
    fn tools(&self, caller: &Caller) -> Vec<(String, NodeTool)> {
        let snap = self.gw.config.load();
        let Some(t) = snap.tenant(&caller.tenant.as_str().into()) else { return vec![] };
        t.nodes
            .iter()
            .filter(|n| n.live && caller.may_run(&n.name))
            .map(|n| (n.name.clone(), self.node_tool(&caller.tenant, &n.name, n.version)))
            .collect()
    }

    fn node_tool(&self, tenant: &str, name: &str, version: u32) -> NodeTool {
        let generic = || NodeTool { description: format!("Runs the node {name} (version {version})."), schema: None };
        match self.gw.resolve_node(tenant, name, None) {
            Some(n) => NodeTool {
                description: n
                    .spec
                    .rest
                    .get("description")
                    .and_then(Value::as_str)
                    .map_or_else(|| generic().description, str::to_owned),
                schema: n.spec.input_schema().cloned(),
            },
            None => generic(),
        }
    }

    async fn task_of(
        &self,
        caller: &Caller,
        headers: &axum::http::HeaderMap,
        id: &str,
    ) -> Result<DetailedTask, ErrorData> {
        let run = self.runs()?.view(caller, headers, id).await.map_err(rpc)?;
        let at = |k: &str| run[k].as_str().unwrap_or_default().to_owned();
        let task = Task::new(id, TaskStatus::Working, at("created_at"), chrono::Utc::now().to_rfc3339())
            .with_poll_interval_ms(1000);
        let payload = match run["status"].as_str().unwrap_or_default() {
            "succeeded" | "budget_exhausted" | "failed" => TaskPayload::Completed {
                result: serde_json::to_value(tool_result(&run))
                    .ok()
                    .and_then(|v| v.as_object().cloned())
                    .unwrap_or_default(),
            },
            "cancelled" => TaskPayload::Cancelled,
            "input_required" => {
                let step = run["awaiting"]["step"].as_str().unwrap_or("answer").to_owned();
                let question = run["awaiting"]["question"].as_str().unwrap_or_default();
                match elicitation(question) {
                    Some(r) => TaskPayload::InputRequired { input_requests: InputRequests::from([(step, r)]) },
                    None => TaskPayload::Working,
                }
            }
            _ => TaskPayload::Working,
        };
        Ok(DetailedTask::new(task, payload))
    }
}

/// A human step as an MCP elicitation request (form: one `answer` text field).
fn elicitation(question: &str) -> Option<InputRequest> {
    serde_json::from_value(json!({
        "method": "elicitation/create",
        "params": {
            "mode": "form",
            "message": question,
            "requestedSchema": {"type": "object", "properties": {"answer": {"type": "string", "description": "Your answer"}}, "required": ["answer"]}
        }
    }))
    .ok()
}

/// A finished (or waiting) run as a tool result.
fn tool_result(run: &Value) -> CallToolResult {
    let id = run["id"].as_str().unwrap_or_default();
    let state = json!({"run_id": id, "status": run["status"], "node": run["node"], "version": run["version"]});
    match run["status"].as_str().unwrap_or_default() {
        "succeeded" | "budget_exhausted" => {
            let out = &run["output"];
            let mut r = CallToolResult::success(vec![ContentBlock::text(output_text(out))]);
            r.structured_content = Some(out.clone()).filter(Value::is_object);
            r
        }
        "input_required" => {
            let q = run["awaiting"]["question"].as_str().unwrap_or_default();
            let mut r = CallToolResult::success(vec![ContentBlock::text(format!(
                "The node is waiting for an answer: {q}\n(run {id}: answer it with POST /v1/runs/{id}/input)"
            ))]);
            r.structured_content = Some(json!({"run": state, "question": q}));
            r
        }
        "failed" | "cancelled" => CallToolResult::error(vec![ContentBlock::text(format!(
            "node run {id} {}: {}",
            run["status"].as_str().unwrap_or_default(),
            run["error"].as_str().or(run["stop_reason"].as_str()).unwrap_or("no detail")
        ))]),
        _ => {
            let mut r = CallToolResult::success(vec![ContentBlock::text(format!(
                "The node is still running (run {id}); follow it with GET /v1/runs/{id}"
            ))]);
            r.structured_content = Some(json!({"run": state}));
            r
        }
    }
}

impl ServerHandler for NodesServer {
    fn get_info(&self) -> ServerConfig {
        let caps = if self.tasks {
            ServerCapabilities::builder().enable_tools().enable_tasks().build()
        } else {
            ServerCapabilities::builder().enable_tools().build()
        };
        let mut info = ServerConfig::new(caps);
        info.instructions = Some("Each tool runs a Caliban node (an AI sub-app of your tenant).".into());
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let (caller, _) = self.caller(&context)?;
        let tools = self
            .tools(&caller)
            .into_iter()
            .map(|(name, t)| {
                let mut tool = Tool::default();
                tool.name = name.into();
                tool.description = Some(t.description.clone().into());
                tool.input_schema = Arc::new(t.input_schema());
                tool
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let (caller, headers) = self.caller(&context)?;
        let name = request.name.to_string();
        let tool = self
            .tools(&caller)
            .into_iter()
            .find(|(n, _)| *n == name)
            .map(|(_, t)| t)
            .ok_or_else(|| ErrorData::invalid_params(format!("no tool named '{name}'"), None))?;
        let input = tool.run_input(request.arguments.unwrap_or_default());
        let runs = self.runs()?;
        let (run_id, _, events) =
            runs.start(&caller, &headers, Start { node: name, input, ..Start::default() }).await.map_err(rpc)?;
        let as_task = self.tasks && context.client_capabilities().is_some_and(|c| c.supports_tasks());
        if as_task {
            let now = chrono::Utc::now().to_rfc3339();
            let task = Task::new(run_id, TaskStatus::Working, now.clone(), now).with_poll_interval_ms(1000);
            return Ok(CallToolResponse::Task(CreateTaskResult::new(task)));
        }
        let wait = runs.sync_wait();
        let mut events = events;
        let last = tokio::time::timeout(wait, async {
            while let Some(e) = events.next().await {
                if let Some(r) = final_run(&e) {
                    return Some(r.clone());
                }
            }
            None
        })
        .await;
        let run = match last {
            Ok(Some(run)) => run,
            // Still going (or the stream broke): its current state.
            _ => runs.view(&caller, &headers, &run_id).await.map_err(rpc)?,
        };
        Ok(tool_result(&run).into())
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        let (caller, headers) = self.caller(&context)?;
        Ok(GetTaskResult::new(self.task_of(&caller, &headers, &request.task_id).await?))
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let (caller, headers) = self.caller(&context)?;
        let (_, response) = request
            .input_responses
            .into_iter()
            .next()
            .ok_or_else(|| ErrorData::invalid_params("no input response", None))?;
        // An elicitation result: {"action": "accept", "content": {"answer": ...}}.
        if response.get("action").and_then(Value::as_str).is_some_and(|a| a != "accept") {
            return Err(ErrorData::invalid_params("the question was not answered (declined)", None));
        }
        let answer = response
            .pointer("/content/answer")
            .cloned()
            .or_else(|| response.get("content").cloned())
            .unwrap_or(response);
        let runs = self.runs()?;
        runs.deliver(
            &caller,
            &headers,
            &request.task_id,
            None,
            caliban_nodes::chat::answer_from_text(&output_text(&answer)),
        )
        .await
        .map_err(rpc)?;
        Ok(())
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let (caller, headers) = self.caller(&context)?;
        self.runs()?.cancel(&caller, &headers, &request.task_id).await.map_err(rpc)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_human_step_is_an_elicitation_and_settings_parse() {
        let r = elicitation("Since when?").expect("an elicitation request");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "elicitation/create");
        assert_eq!(v["params"]["message"], "Since when?");
        let s = McpSettings::from_env(|k| (k == "CALIBAN_MCP_TASKS").then(|| "true".into())).unwrap();
        assert!(s.tasks && s.allowed_hosts.is_empty());
        assert!(McpSettings::from_env(|_| Some("maybe".into())).is_err());
        // Arguments: object schemas as is; others under "input".
        let t = NodeTool { description: String::new(), schema: Some(json!({"type": "object"})) };
        assert_eq!(t.run_input(json!({"case": "x"}).as_object().unwrap().clone()), json!({"case": "x"}));
        let t = NodeTool { description: String::new(), schema: None };
        assert_eq!(t.run_input(json!({"input": "hello"}).as_object().unwrap().clone()), json!("hello"));
        assert_eq!(
            t.input_schema()["properties"]["input"]["description"].as_str().map(|s| s.contains("JSON")),
            Some(true)
        );
    }
}
