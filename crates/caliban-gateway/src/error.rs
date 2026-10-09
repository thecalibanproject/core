use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use caliban_types::CalibanError;
use std::time::Duration;

/// Which wire dialect the client speaks; decides error and response shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dialect {
    #[default]
    OpenAi,
    Anthropic,
}

impl Dialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::OpenAi => "openai",
            Dialect::Anthropic => "anthropic",
        }
    }
}

/// API error. OpenAI shape (`{"error": {"message", "type", "code"}}`) by default; Anthropic shape
/// (`{"type": "error", "error": {"type", "message"}}`) on `/v1/messages`. Rate-limit errors carry
/// `retry-after` (seconds).
#[derive(Debug)]
pub struct ApiError {
    pub error: CalibanError,
    pub retry_after: Option<Duration>,
    /// Machine-readable detail, e.g. the limit that was hit (`tokens_per_minute`).
    pub code: Option<&'static str>,
    pub dialect: Dialect,
}

impl ApiError {
    pub fn rate_limited(scope: &'static str, retry_after: Duration) -> Self {
        Self {
            error: CalibanError::RateLimited(format!("{scope} limit exceeded; retry after {}s", caliban_meter::quota::retry_secs(retry_after))),
            retry_after: Some(retry_after),
            code: Some(scope),
            dialect: Dialect::OpenAi,
        }
    }

    /// 503 with `retry-after`: over capacity, retry later.
    pub fn overloaded(message: impl Into<String>, scope: &'static str, retry_after: Duration) -> Self {
        Self { error: CalibanError::Overloaded(message.into()), retry_after: Some(retry_after), code: Some(scope), dialect: Dialect::OpenAi }
    }

    pub fn with_dialect(mut self, dialect: Dialect) -> Self {
        self.dialect = dialect;
        self
    }

    /// Anthropic `error.type` for a Caliban error.
    fn anthropic_type(&self) -> &'static str {
        match self.error {
            CalibanError::InvalidRequest(_) => "invalid_request_error",
            CalibanError::Unauthenticated => "authentication_error",
            CalibanError::PolicyViolation(_) => "permission_error",
            CalibanError::RateLimited(_) => "rate_limit_error",
            CalibanError::Upstream(_) | CalibanError::Internal(_) => "api_error",
            CalibanError::Overloaded(_) => "overloaded_error",
        }
    }
}

impl From<CalibanError> for ApiError {
    fn from(error: CalibanError) -> Self {
        Self { error, retry_after: None, code: None, dialect: Dialect::OpenAi }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = match self.dialect {
            Dialect::OpenAi => serde_json::json!({
                "error": { "message": self.error.to_string(), "type": self.error.kind(), "code": self.code }
            }),
            Dialect::Anthropic => caliban_ir::anthropic::error_body(self.anthropic_type(), &self.error.to_string()),
        };
        let mut resp = (status, axum::Json(body)).into_response();
        if let Some(ra) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&caliban_meter::quota::retry_secs(ra).to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        if let Some(code) = self.code.filter(|_| self.retry_after.is_some() && matches!(self.error, CalibanError::RateLimited(_))) {
            resp.headers_mut().insert("x-caliban-ratelimit-scope", HeaderValue::from_static(code));
        }
        resp
    }
}
