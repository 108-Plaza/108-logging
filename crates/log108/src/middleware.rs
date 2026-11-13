use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;
use tower::{Layer, Service};
use tracing::Instrument;
use uuid::Uuid;

/// Canonical HTTP header name for request correlation IDs.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Maximum accepted length (in bytes) of an incoming `x-request-id` header.
pub const MAX_REQUEST_ID_LEN: usize = 128;

/// Request extension holding the active request's resolved `request_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestId(pub String);

impl RequestId {
    /// Returns the request ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RequestId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Returns `true` if `value` is non-empty, at most [`MAX_REQUEST_ID_LEN`] (128) bytes,
/// and consists exclusively of ASCII graphic characters (`0x21..=0x7E`, no whitespace or control bytes).
pub fn is_valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_LEN
        && value.bytes().all(|b| b.is_ascii_graphic())
}

/// Extracts a valid `x-request-id` from `headers`, or generates a new UUID v4 if missing or invalid.
pub fn resolve_request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| is_valid_request_id(s))
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// Axum middleware (`axum::middleware::from_fn`) that validates or generates `x-request-id`,
/// stores [`RequestId`] in request extensions, instruments the request with a tracing span
/// carrying `request_id`, and echoes `x-request-id` on the response.
pub async fn trace_request_with_id(mut req: Request, next: Next) -> Response {
    let request_id = resolve_request_id(req.headers());
    if let Ok(header_val) = HeaderValue::from_str(&request_id) {
        req.headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), header_val);
    }
    req.extensions_mut().insert(RequestId(request_id.clone()));

    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %req.method(),
        path = %req.uri().path(),
    );

    let mut response = next.run(req).instrument(span).await;
    if let Ok(header_val) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), header_val);
    }
    response
}

/// Alias for [`trace_request_with_id`] matching the `friend-hire` middleware function name.
pub async fn handle_request_id(req: Request, next: Next) -> Response {
    trace_request_with_id(req, next).await
}

/// Returns a Tower [`RequestIdLayer`] that attaches `x-request-id` validation, span instrumentation,
/// and response header echoing to any Axum `Router` or Tower service.
pub const fn request_id_layer() -> RequestIdLayer {
    RequestIdLayer
}

/// Tower [`Layer`] that wraps a service in [`RequestIdService`].
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestIdLayer;

impl RequestIdLayer {
    /// Creates a new [`RequestIdLayer`].
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequestIdLayer {
    type Service = RequestIdService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestIdService { inner }
    }
}

/// Tower [`Service`] that assigns or propagates `x-request-id`, opens a request span with `request_id`,
/// and echoes `x-request-id` on the HTTP response.
#[derive(Clone, Debug)]
pub struct RequestIdService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for RequestIdService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = http::Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<ReqBody>) -> Self::Future {
        let request_id = resolve_request_id(req.headers());
        if let Ok(header_val) = HeaderValue::from_str(&request_id) {
            req.headers_mut()
                .insert(HeaderName::from_static(REQUEST_ID_HEADER), header_val);
        }
        req.extensions_mut().insert(RequestId(request_id.clone()));

        let span = tracing::info_span!(
            "http_request",
            request_id = %request_id,
            method = %req.method(),
            path = %req.uri().path(),
        );

        let fut = self.inner.call(req).instrument(span);
        Box::pin(async move {
            let mut response = fut.await?;
            if let Ok(header_val) = HeaderValue::from_str(&request_id) {
                response
                    .headers_mut()
                    .insert(HeaderName::from_static(REQUEST_ID_HEADER), header_val);
            }
            Ok(response)
        })
    }
}
