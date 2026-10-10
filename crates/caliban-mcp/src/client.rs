//! The MCP client: the official `rmcp` SDK over Streamable HTTP, through the egress guard.
//!
//! Each call opens its own connection to the registered URL (resolved, checked and pinned by
//! [`crate::egress`]), lists the server's tools, checks that the tool's manifest still matches its
//! approved pin, calls it, and closes. Listing on every call is what makes a manifest change
//! after approval (a rug pull) fail the call instead of reaching the model; `tools/list_changed`
//! notifications are ignored (never trusted: nothing is re-approved by the server's say-so).

use crate::ToolManifest;
use crate::egress::{self, EgressError, EgressPolicy, Resolve};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// How a call authenticates to the server.
#[derive(Clone, PartialEq, Eq)]
pub enum ServerAuth {
    None,
    /// `Authorization: Bearer <token>` (a minted Caliban token, or an OAuth access token).
    Bearer(String),
    /// A static credential in a header (an API key).
    Header {
        name: String,
        value: String,
    },
}

impl std::fmt::Debug for ServerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Self::Header { name, .. } => write!(f, "Header({name}: <redacted>)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerTarget {
    pub url: String,
    pub auth: ServerAuth,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum McpError {
    #[error(transparent)]
    Egress(#[from] EgressError),
    /// The server could not be reached or answered with a transport error (worth retrying).
    #[error("tool server unavailable: {0}")]
    Unavailable(String),
    #[error("tool server error: {0}")]
    Protocol(String),
    #[error("the server has no tool named '{0}'")]
    NoSuchTool(String),
    /// The manifest the server lists now is not the approved one.
    #[error(
        "the manifest of tool '{tool}' changed since it was approved (pinned {pinned}, now {now}); it needs re-approval"
    )]
    ManifestChanged { tool: String, pinned: String, now: String },
}

/// What a tool returned.
#[derive(Debug, Clone, PartialEq)]
pub struct CallOutput {
    /// The structured content, else the text content (parsed as JSON when it is JSON).
    pub value: Value,
    /// The tool reported an error (`isError`).
    pub is_error: bool,
}

pub struct McpClient {
    pub policy: EgressPolicy,
    resolver: Arc<dyn Resolve>,
    timeout: Duration,
    /// OAuth access tokens by (token URL, client id, scope), until shortly before they expire.
    oauth: parking_lot::Mutex<HashMap<OauthKey, (String, std::time::Instant)>>,
}

/// (token URL, client id, scope).
type OauthKey = (String, String, String);

/// The audience of a server's minted tokens: its registered audience, else its URL's origin.
pub fn audience(url: &str, configured: Option<&str>) -> String {
    configured.map_or_else(
        || url::Url::parse(url).map_or_else(|_| url.to_owned(), |u| u.origin().ascii_serialization()),
        str::to_owned,
    )
}

impl McpClient {
    pub fn new(policy: EgressPolicy, resolver: Arc<dyn Resolve>, timeout: Duration) -> Self {
        Self { policy, resolver, timeout, oauth: parking_lot::Mutex::default() }
    }

    /// How to authenticate to a server for one call. `secret`: the server's opened credential;
    /// `mint`: mints a Caliban token for an audience (`None` when no signing key is configured).
    pub async fn auth_for(
        &self,
        url: &str,
        auth: &caliban_config::ToolAuth,
        secret: Option<&str>,
        mint: impl FnOnce(&str) -> Option<String>,
    ) -> Result<ServerAuth, McpError> {
        use caliban_config::ToolAuth;
        let missing = || McpError::Protocol("the server's credential is not available".into());
        match auth {
            ToolAuth::None => Ok(ServerAuth::None),
            ToolAuth::CalibanToken { audience: a } => {
                mint(&audience(url, a.as_deref())).map(ServerAuth::Bearer).ok_or_else(|| {
                    McpError::Protocol("no tool token signing key (CALIBAN_TOOL_TOKEN_KEY) is configured".into())
                })
            }
            ToolAuth::ApiKey { header } => {
                let key = secret.ok_or_else(missing)?.to_owned();
                Ok(match header.as_deref() {
                    None => ServerAuth::Bearer(key),
                    Some(h) if h.eq_ignore_ascii_case("authorization") => ServerAuth::Bearer(key),
                    Some(h) => ServerAuth::Header { name: h.to_owned(), value: key },
                })
            }
            ToolAuth::OauthClientCredentials { token_url, client_id, scope } => {
                let token =
                    self.oauth_token(token_url, client_id, secret.ok_or_else(missing)?, scope.as_deref()).await?;
                Ok(ServerAuth::Bearer(token))
            }
        }
    }

    /// An OAuth 2.0 client-credentials access token, through the same egress guard.
    async fn oauth_token(
        &self,
        token_url: &str,
        client_id: &str,
        secret: &str,
        scope: Option<&str>,
    ) -> Result<String, McpError> {
        let key = (token_url.to_owned(), client_id.to_owned(), scope.unwrap_or_default().to_owned());
        if let Some((t, until)) = self.oauth.lock().get(&key)
            && std::time::Instant::now() < *until
        {
            return Ok(t.clone());
        }
        let u = egress::check_url(token_url, self.policy)?;
        let addr = egress::resolve_pinned(&u, self.resolver.as_ref(), self.policy).await?;
        let http = egress::pinned_client(&u, addr, self.timeout)?;
        let form = {
            let mut f = url::form_urlencoded::Serializer::new(String::new());
            f.append_pair("grant_type", "client_credentials");
            if let Some(s) = scope {
                f.append_pair("scope", s);
            }
            f.finish()
        };
        let resp = http
            .post(token_url)
            .basic_auth(client_id, Some(secret))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|e| McpError::Unavailable(format!("token endpoint: {e}")))?;
        let status = resp.status();
        let body: Value = resp.json().await.map_err(|e| McpError::Unavailable(format!("token endpoint: {e}")))?;
        if !status.is_success() {
            return Err(McpError::Protocol(format!("token endpoint answered {status}")));
        }
        let token =
            body["access_token"].as_str().ok_or_else(|| McpError::Protocol("no access_token".into()))?.to_owned();
        let ttl = body["expires_in"].as_u64().unwrap_or(300).saturating_sub(30).max(1);
        self.oauth.lock().insert(key, (token.clone(), std::time::Instant::now() + Duration::from_secs(ttl)));
        Ok(token)
    }

    /// The system resolver, 30 s per call.
    pub fn system(policy: EgressPolicy) -> Self {
        Self::new(policy, Arc::new(egress::SystemResolver), Duration::from_secs(30))
    }

    async fn connect(
        &self,
        target: &ServerTarget,
    ) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ()>, McpError> {
        let u = egress::check_url(&target.url, self.policy)?;
        let addr = egress::resolve_pinned(&u, self.resolver.as_ref(), self.policy).await?;
        let http = egress::pinned_client(&u, addr, self.timeout)?;
        let mut config = StreamableHttpClientTransportConfig::with_uri(target.url.as_str());
        match &target.auth {
            ServerAuth::None => {}
            ServerAuth::Bearer(t) => config = config.auth_header(t.clone()),
            ServerAuth::Header { name, value } => {
                let name = http::HeaderName::try_from(name.as_str()).map_err(|e| McpError::Protocol(e.to_string()))?;
                let value =
                    http::HeaderValue::try_from(value.as_str()).map_err(|e| McpError::Protocol(e.to_string()))?;
                config = config.custom_headers(HashMap::from([(name, value)]));
            }
        }
        let transport = StreamableHttpClientTransport::with_client(http, config);
        tokio::time::timeout(self.timeout, ().serve(transport))
            .await
            .map_err(|_| McpError::Unavailable("timed out connecting".into()))?
            .map_err(|e| McpError::Unavailable(e.to_string()))
    }

    /// The server's tools, as manifests (discovery).
    pub async fn list_tools(&self, target: &ServerTarget) -> Result<Vec<ToolManifest>, McpError> {
        let session = self.connect(target).await?;
        let tools = tokio::time::timeout(self.timeout, session.list_all_tools()).await;
        let _ = session.cancel().await;
        let tools =
            tools.map_err(|_| McpError::Unavailable("timed out listing tools".into()))?.map_err(service_error)?;
        Ok(tools.into_iter().map(manifest_of).collect())
    }

    /// Calls `tool` with `args`, after checking that its manifest still has the pin `pinned`.
    pub async fn call(
        &self,
        target: &ServerTarget,
        tool: &str,
        pinned: &str,
        args: Value,
    ) -> Result<CallOutput, McpError> {
        let session = self.connect(target).await?;
        let out = tokio::time::timeout(self.timeout, async {
            let tools = session.list_all_tools().await.map_err(service_error)?;
            let found = tools
                .into_iter()
                .map(manifest_of)
                .find(|m| m.name == tool)
                .ok_or_else(|| McpError::NoSuchTool(tool.into()))?;
            let now = found.pin();
            if now != pinned {
                return Err(McpError::ManifestChanged { tool: tool.into(), pinned: pinned.into(), now });
            }
            let arguments = match args {
                Value::Object(m) => Some(m),
                Value::Null => None,
                other => {
                    return Err(McpError::Protocol(format!("tool arguments must be a JSON object, not {other}")));
                }
            };
            let mut params = CallToolRequestParams::new(tool.to_owned());
            params.arguments = arguments;
            let r = session.call_tool(params).await.map_err(service_error)?;
            Ok(output_of(r))
        })
        .await;
        let _ = session.cancel().await;
        out.map_err(|_| McpError::Unavailable("timed out calling the tool".into()))?
    }
}

fn service_error(e: rmcp::ServiceError) -> McpError {
    match e {
        rmcp::ServiceError::McpError(d) => McpError::Protocol(d.message.to_string()),
        other => McpError::Unavailable(other.to_string()),
    }
}

fn manifest_of(t: rmcp::model::Tool) -> ToolManifest {
    ToolManifest {
        name: t.name.to_string(),
        description: t.description.map(|d| d.to_string()).unwrap_or_default(),
        input_schema: Value::Object((*t.input_schema).clone()),
    }
}

fn output_of(r: rmcp::model::CallToolResult) -> CallOutput {
    let is_error = r.is_error.unwrap_or(false);
    if let Some(v) = r.structured_content {
        return CallOutput { value: v, is_error };
    }
    let text: Vec<String> = r.content.iter().filter_map(|c| c.as_text().map(|t| t.text.clone())).collect();
    let joined = text.join("\n");
    let value = serde_json::from_str(&joined).unwrap_or(Value::String(joined));
    CallOutput { value, is_error }
}

#[cfg(test)]
mod send_check {
    fn is_send<T: Send>(_: T) {}
    #[allow(dead_code)]
    fn futures_are_send(c: &super::McpClient, t: &super::ServerTarget) {
        is_send(c.list_tools(t));
        is_send(c.call(t, "x", "p", serde_json::Value::Null));
        is_send(c.auth_for("u", &caliban_config::ToolAuth::None, None, |_| None));
    }
}
