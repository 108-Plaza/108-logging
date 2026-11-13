//! Shared structured logging, redaction, and `x-request-id` middleware for 108-Plaza services.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! log108::init("line-bot");
//! ```
//!
//! When stdout is reserved (such as `tq` MCP servers), write logs to stderr via [`init_with`]:
//!
//! ```rust,no_run
//! log108::init_with(log108::Options {
//!     service: "tq",
//!     writer: std::io::stderr,
//!     json: true,
//! });
//! ```

pub mod redact;

#[cfg(feature = "axum")]
pub mod middleware;

use std::fmt;
use std::io::{self, IsTerminal};

use chrono::SecondsFormat;
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber};
use tracing_log::NormalizeEvent;
use tracing_subscriber::fmt::format::Writer as FmtWriter;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

pub use self::redact::{
    is_sensitive_field, redact, redact_field, redact_json, redact_str, Redacted, REDACTED,
    REDACTED_FIELDS, SENSITIVE_FIELDS,
};

#[cfg(feature = "axum")]
pub use self::middleware::{
    handle_request_id, is_valid_request_id, request_id_layer, resolve_request_id,
    trace_request_with_id, RequestId, RequestIdLayer, RequestIdService, MAX_REQUEST_ID_LEN,
    REQUEST_ID_HEADER,
};

/// Standard output or standard error sink selector.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Writer {
    /// Write log lines to standard output (`stdout`).
    #[default]
    Stdout,
    /// Write log lines to standard error (`stderr`).
    Stderr,
}

/// Concrete [`io::Write`] handle produced by [`Writer`].
pub enum StdIoWriter {
    /// Standard output handle.
    Stdout(io::Stdout),
    /// Standard error handle.
    Stderr(io::Stderr),
}

impl io::Write for StdIoWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(w) => w.write(buf),
            Self::Stderr(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout(w) => w.flush(),
            Self::Stderr(w) => w.flush(),
        }
    }
}

impl<'a> MakeWriter<'a> for Writer {
    type Writer = StdIoWriter;

    fn make_writer(&'a self) -> Self::Writer {
        match self {
            Self::Stdout => StdIoWriter::Stdout(io::stdout()),
            Self::Stderr => StdIoWriter::Stderr(io::stderr()),
        }
    }
}

/// Configuration options for [`init_with`] and [`build_subscriber`].
#[derive(Clone, Debug)]
pub struct Options<W = fn() -> io::Stdout, S = &'static str> {
    /// Stable service name attached to every log record (`"service"` field).
    pub service: S,
    /// Destination writer (`std::io::stdout`, `std::io::stderr`, [`Writer`], or any [`MakeWriter`]).
    pub writer: W,
    /// Emit single-line JSON objects when `true`, or human-readable text when `false`.
    pub json: bool,
}

impl<S: AsRef<str>> Options<fn() -> io::Stdout, S> {
    /// Creates default options for `service` writing to `stdout`, choosing JSON unless `stdout` is a tty
    /// or `LOG_FORMAT` overrides the format.
    pub fn new(service: S) -> Self {
        Self {
            service,
            writer: io::stdout,
            json: resolve_json_format(io::stdout().is_terminal()),
        }
    }
}

impl<S: AsRef<str>> Options<fn() -> io::Stderr, S> {
    /// Creates options for `service` writing to `stderr` (e.g. `tq`), choosing JSON unless `stderr` is a tty
    /// or `LOG_FORMAT` overrides the format.
    pub fn stderr(service: S) -> Self {
        Self {
            service,
            writer: io::stderr,
            json: resolve_json_format(io::stderr().is_terminal()),
        }
    }
}

/// Resolves whether JSON formatting should be used based on `LOG_FORMAT` (`json` | `pretty`)
/// and whether the output stream is a terminal (`is_tty`).
///
/// Defaults to `true` (JSON) when `is_tty` is `false`.
pub fn resolve_json_format(is_tty: bool) -> bool {
    let env_val = std::env::var("LOG_FORMAT").ok();
    resolve_json_format_from(env_val.as_deref(), !is_tty)
}

/// Resolves whether JSON formatting should be used from an optional `LOG_FORMAT` value
/// (`"json"` or `"pretty"`, case-insensitive) and a `default_json` fallback.
pub fn resolve_json_format_from(log_format: Option<&str>, default_json: bool) -> bool {
    match log_format.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("json") => true,
        Some(v) if v.eq_ignore_ascii_case("pretty") => false,
        _ => default_json,
    }
}

/// Builds an [`EnvFilter`] from `RUST_LOG` or `LOG_FILTER` environment variables,
/// defaulting to `"info"` when neither is set or valid.
pub fn build_env_filter() -> EnvFilter {
    let rust_log = std::env::var("RUST_LOG").ok();
    let log_filter = std::env::var("LOG_FILTER").ok();
    build_env_filter_from(rust_log.as_deref(), log_filter.as_deref())
}

/// Builds an [`EnvFilter`] with precedence `rust_log` -> `log_filter` -> `"info"`.
pub fn build_env_filter_from(rust_log: Option<&str>, log_filter: Option<&str>) -> EnvFilter {
    if let Some(val) = rust_log.map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(filter) = EnvFilter::try_new(val) {
            return filter;
        }
    }
    if let Some(val) = log_filter.map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(filter) = EnvFilter::try_new(val) {
            return filter;
        }
    }
    EnvFilter::new("info")
}

/// Initializes the global `tracing` subscriber for `service` writing to `stdout`.
///
/// Safe to call more than once (subsequent calls are no-ops).
pub fn init(service: impl AsRef<str>) {
    init_with(Options::new(service.as_ref()));
}

/// Initializes the global `tracing` subscriber using the provided [`Options`].
///
/// Safe to call more than once (subsequent calls are no-ops).
pub fn init_with<W, S>(options: Options<W, S>)
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    S: AsRef<str>,
{
    let env_format = std::env::var("LOG_FORMAT").ok();
    let json = resolve_json_format_from(env_format.as_deref(), options.json);
    let subscriber = build_subscriber_with_filter(
        options.service.as_ref(),
        options.writer,
        json,
        build_env_filter(),
    );
    let _ = subscriber.try_init();
}

/// Builds a configured `tracing` [`Subscriber`] from [`Options`] and the current environment
/// (`RUST_LOG` / `LOG_FILTER` and `LOG_FORMAT`).
pub fn build_subscriber<W, S>(options: Options<W, S>) -> impl Subscriber + Send + Sync + use<W, S>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    S: AsRef<str>,
{
    let env_format = std::env::var("LOG_FORMAT").ok();
    let json = resolve_json_format_from(env_format.as_deref(), options.json);
    build_subscriber_with_filter(
        options.service.as_ref(),
        options.writer,
        json,
        build_env_filter(),
    )
}

/// Builds a configured `tracing` [`Subscriber`] with an explicit [`EnvFilter`].
pub fn build_subscriber_with_filter<W>(
    service: &str,
    writer: W,
    json: bool,
    filter: EnvFilter,
) -> impl Subscriber + Send + Sync + use<W>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let formatter = EventFormatter {
        service: service.to_owned(),
        json,
    };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .event_format(formatter);

    Registry::default()
        .with(filter)
        .with(SpanFieldsLayer)
        .with(fmt_layer)
}

#[derive(Clone, Debug, Default)]
struct SpanFields(Map<String, Value>);

struct SpanFieldsLayer;

impl<S> Layer<S> for SpanFieldsLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: LayerContext<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut map = Map::new();
            let mut visitor = JsonFieldVisitor(&mut map);
            attrs.record(&mut visitor);
            span.extensions_mut().replace(SpanFields(map));
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: LayerContext<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut ext = span.extensions_mut();
            if let Some(fields) = ext.get_mut::<SpanFields>() {
                let mut visitor = JsonFieldVisitor(&mut fields.0);
                values.record(&mut visitor);
            } else {
                let mut map = Map::new();
                let mut visitor = JsonFieldVisitor(&mut map);
                values.record(&mut visitor);
                ext.insert(SpanFields(map));
            }
        }
    }
}

struct JsonFieldVisitor<'a>(&'a mut Map<String, Value>);

impl JsonFieldVisitor<'_> {
    fn insert_redacted_or(&mut self, field: &Field, make_value: impl FnOnce() -> Value) {
        let name = field.name();
        let value = if is_sensitive_field(name) {
            Value::String(REDACTED.to_owned())
        } else {
            make_value()
        };
        self.0.insert(name.to_owned(), value);
    }
}

impl Visit for JsonFieldVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert_redacted_or(field, || Value::String(value.to_owned()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert_redacted_or(field, || Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert_redacted_or(field, || Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert_redacted_or(field, || Value::Number(value.into()));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.insert_redacted_or(field, || Value::String(value.to_string()));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.insert_redacted_or(field, || Value::String(value.to_string()));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert_redacted_or(field, || {
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        });
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert_redacted_or(field, || Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert_redacted_or(field, || Value::String(format!("{value:?}")));
    }
}

#[derive(Clone, Debug)]
struct EventFormatter {
    service: String,
    json: bool,
}

impl<S, N> FormatEvent<S, N> for EventFormatter
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: FmtWriter<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let normalized = event.normalized_metadata();
        let meta = normalized.as_ref().unwrap_or_else(|| event.metadata());

        let mut span_fields = Map::new();
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let ext = span.extensions();
                if let Some(fields) = ext.get::<SpanFields>() {
                    for (k, v) in &fields.0 {
                        span_fields.insert(k.clone(), v.clone());
                    }
                }
            }
        }

        let mut event_fields = Map::new();
        let mut visitor = JsonFieldVisitor(&mut event_fields);
        event.record(&mut visitor);

        let message = event_fields
            .remove("message")
            .map(|v| match v {
                Value::String(s) => s,
                other => other.to_string(),
            })
            .unwrap_or_default();

        let request_id = event_fields
            .remove("request_id")
            .or_else(|| span_fields.remove("request_id"))
            .and_then(|v| match v {
                Value::String(s) if !s.is_empty() => Some(s),
                Value::Null | Value::String(_) => None,
                other => Some(other.to_string()),
            });

        let ts = chrono::Local::now().to_rfc3339_opts(SecondsFormat::Millis, false);
        let level = meta.level().as_str().to_ascii_lowercase();
        let target = meta.target();

        if self.json {
            let mut out = Map::new();
            out.insert("ts".to_owned(), Value::String(ts));
            out.insert("level".to_owned(), Value::String(level));
            out.insert("service".to_owned(), Value::String(self.service.clone()));
            if let Some(req_id) = request_id {
                out.insert("request_id".to_owned(), Value::String(req_id));
            }
            out.insert("target".to_owned(), Value::String(target.to_owned()));
            out.insert("message".to_owned(), Value::String(message));

            for (k, v) in span_fields {
                if !is_reserved_key(&k) {
                    out.insert(k, v);
                }
            }
            for (k, v) in event_fields {
                if !is_reserved_key(&k) {
                    out.insert(k, v);
                }
            }

            let line = serde_json::to_string(&Value::Object(out)).map_err(|_| fmt::Error)?;
            writeln!(writer, "{line}")
        } else {
            write!(
                writer,
                "{ts} {:<5} [{}]",
                level.to_ascii_uppercase(),
                self.service
            )?;
            if let Some(req_id) = request_id {
                write!(writer, " request_id={req_id}")?;
            }
            write!(writer, " {target}: {message}")?;

            for (k, v) in span_fields.into_iter().chain(event_fields) {
                if !is_reserved_key(&k) {
                    match v {
                        Value::String(s) => write!(writer, " {k}={s}")?,
                        other => write!(writer, " {k}={other}")?,
                    }
                }
            }
            writeln!(writer)
        }
    }
}

fn is_reserved_key(key: &str) -> bool {
    matches!(
        key,
        "ts" | "level"
            | "service"
            | "request_id"
            | "target"
            | "message"
            | "log.target"
            | "log.module_path"
            | "log.file"
            | "log.line"
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

    struct GuardWriter<'a>(std::sync::MutexGuard<'a, Vec<u8>>);

    impl io::Write for GuardWriter<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for BufferWriter {
        type Writer = GuardWriter<'a>;

        fn make_writer(&'a self) -> Self::Writer {
            GuardWriter(self.0.lock().expect("lock test buffer"))
        }
    }

    impl BufferWriter {
        fn take_string(&self) -> String {
            let mut guard = self.0.lock().expect("lock test buffer");
            String::from_utf8(std::mem::take(&mut *guard)).expect("valid utf-8 log")
        }
    }

    #[test]
    fn init_and_init_with_are_idempotent() {
        let buf = BufferWriter::default();
        init_with(Options {
            service: "tq",
            writer: buf,
            json: true,
        });
        init("line-bot");
    }

    #[test]
    fn json_output_includes_required_fields_and_span_fields() {
        let buf = BufferWriter::default();
        let sub =
            build_subscriber_with_filter("line-bot", buf.clone(), true, EnvFilter::new("info"));

        tracing::subscriber::with_default(sub, || {
            tracing::info!(host = "dell", latency_ms = 12u64, "startup complete");

            let span =
                tracing::info_span!("http_request", request_id = "req-108-abc", user_id = "u_42");
            let _enter = span.enter();
            tracing::warn!(status = 200u64, "handled webhook");
        });

        let output = buf.take_string();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 JSON log lines, got: {output}");

        let first: Value = serde_json::from_str(lines[0]).expect("valid JSON line 1");
        assert!(
            chrono::DateTime::parse_from_rfc3339(first["ts"].as_str().unwrap()).is_ok(),
            "ts must be RFC 3339 with offset: {}",
            first["ts"]
        );
        assert_eq!(first["level"], "info");
        assert_eq!(first["service"], "line-bot");
        assert!(
            first.get("request_id").is_none(),
            "request_id must be omitted when outside a request span"
        );
        assert_eq!(first["message"], "startup complete");
        assert!(first["target"].as_str().unwrap().contains("log108"));
        assert_eq!(first["host"], "dell");
        assert_eq!(first["latency_ms"], 12);

        let second: Value = serde_json::from_str(lines[1]).expect("valid JSON line 2");
        assert_eq!(second["level"], "warn");
        assert_eq!(second["service"], "line-bot");
        assert_eq!(second["request_id"], "req-108-abc");
        assert_eq!(second["user_id"], "u_42");
        assert_eq!(second["status"], 200);
        assert_eq!(second["message"], "handled webhook");
    }

    #[test]
    fn env_filter_and_log_format_resolution() {
        assert!(resolve_json_format_from(Some("json"), false));
        assert!(!resolve_json_format_from(Some("PRETTY"), true));
        assert!(resolve_json_format_from(None, true));
        assert!(!resolve_json_format_from(None, false));

        // RUST_LOG wins over LOG_FILTER; LOG_FILTER is used when RUST_LOG is unset; default is info.
        let buf = BufferWriter::default();
        let filter = build_env_filter_from(None, Some("debug"));
        let sub = build_subscriber_with_filter("matcher", buf.clone(), false, filter);

        tracing::subscriber::with_default(sub, || {
            tracing::debug!("debug visible via LOG_FILTER");
            tracing::trace!("trace hidden");
        });

        let text = buf.take_string();
        assert!(text.contains("debug visible via LOG_FILTER"), "got: {text}");
        assert!(!text.contains("trace hidden"), "got: {text}");

        let buf2 = BufferWriter::default();
        let default_filter = build_env_filter_from(None, None);
        let sub2 = build_subscriber_with_filter("matcher", buf2.clone(), true, default_filter);
        tracing::subscriber::with_default(sub2, || {
            tracing::debug!("debug filtered out by default info");
            tracing::info!("info visible by default");
        });
        let text2 = buf2.take_string();
        assert!(!text2.contains("debug filtered out"));
        assert!(text2.contains("info visible by default"));
    }

    #[test]
    fn redacts_dangerous_fields_in_logs_and_helpers() {
        for dangerous in [
            "password",
            "user_password",
            "token",
            "access_token",
            "secret",
            "client_secret",
            "authorization",
            "cookie",
            "set-cookie",
            "otp",
            "slip",
            "slip_image",
            "ocr",
            "ocr_text",
            "phone",
            "email",
            "national_id",
            "citizen_id",
            "bank_account",
            "account_number",
            "promptpay",
        ] {
            assert!(
                is_sensitive_field(dangerous),
                "expected {dangerous} to be classified as sensitive"
            );
            assert_eq!(redact_field(dangerous, "raw-secret"), REDACTED);
        }

        for safe in [
            "service",
            "request_id",
            "user_id",
            "status",
            "latency_ms",
            "target",
            "message",
            "order_id",
        ] {
            assert!(
                !is_sensitive_field(safe),
                "expected {safe} NOT to be classified as sensitive"
            );
            assert_eq!(redact_field(safe, "visible"), "visible");
        }

        assert_eq!(format!("{}", redact("my-secret-token")), REDACTED);
        assert_eq!(format!("{:?}", redact("my-secret-token")), REDACTED);
        assert_eq!(
            serde_json::to_value(redact("my-secret-token")).unwrap(),
            Value::String(REDACTED.to_owned())
        );

        let mut payload = serde_json::json!({
            "user_id": "u-108",
            "password": "plain-password",
            "nested": {
                "slip_image": "base64...",
                "ocr_text": "นาย ก 500.00",
                "status": "ok"
            }
        });
        redact_json(&mut payload);
        assert_eq!(payload["user_id"], "u-108");
        assert_eq!(payload["password"], REDACTED);
        assert_eq!(payload["nested"]["slip_image"], REDACTED);
        assert_eq!(payload["nested"]["ocr_text"], REDACTED);
        assert_eq!(payload["nested"]["status"], "ok");

        // Verify subscriber automatically masks sensitive fields in spans and events
        let buf = BufferWriter::default();
        let sub =
            build_subscriber_with_filter("bank-bot", buf.clone(), true, EnvFilter::new("info"));
        tracing::subscriber::with_default(sub, || {
            let span = tracing::info_span!("auth", authorization = "Bearer eyJhbGciOi...");
            let _enter = span.enter();
            tracing::info!(
                password = "super-secret-password",
                token = "tok_live_123",
                slip = "raw-slip-bytes",
                ocr = "raw-ocr-text",
                otp = "123456",
                user_id = "u_99",
                "processed transfer"
            );
        });

        let line = buf.take_string();
        assert!(!line.contains("Bearer eyJhbGciOi"));
        assert!(!line.contains("super-secret-password"));
        assert!(!line.contains("tok_live_123"));
        assert!(!line.contains("raw-slip-bytes"));
        assert!(!line.contains("raw-ocr-text"));
        assert!(!line.contains("123456"));

        let parsed: Value = serde_json::from_str(line.trim()).expect("valid JSON");
        assert_eq!(parsed["authorization"], REDACTED);
        assert_eq!(parsed["password"], REDACTED);
        assert_eq!(parsed["token"], REDACTED);
        assert_eq!(parsed["slip"], REDACTED);
        assert_eq!(parsed["ocr"], REDACTED);
        assert_eq!(parsed["otp"], REDACTED);
        assert_eq!(parsed["user_id"], "u_99");
    }

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn axum_request_id_middleware_validates_echoes_and_propagates_to_logs() {
        use axum::body::Body;
        use axum::extract::Extension;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use http_body_util::BodyExt as _;
        use tower::ServiceExt as _;
        use uuid::Uuid;

        let app = Router::new()
            .route(
                "/ping",
                get(|Extension(req_id): Extension<RequestId>| async move {
                    tracing::info!("inside ping handler");
                    (StatusCode::OK, req_id.0)
                }),
            )
            .layer(request_id_layer());

        // 1. Valid ASCII graphic x-request-id <= 128 chars is preserved, echoed, and logged in span
        let supplied = "req-108_valid.id:42";
        let buf = BufferWriter::default();
        let sub =
            build_subscriber_with_filter("test-api", buf.clone(), true, EnvFilter::new("info"));
        let _guard = tracing::subscriber::set_default(sub);

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header(REQUEST_ID_HEADER, supplied)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(REQUEST_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some(supplied)
        );
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], supplied.as_bytes());

        let log_output = buf.take_string();
        let log_json: Value =
            serde_json::from_str(log_output.lines().next().expect("logged line")).unwrap();
        assert_eq!(log_json["request_id"], supplied);
        assert_eq!(log_json["message"], "inside ping handler");

        // 2. Missing or invalid x-request-id (spaces, >128 chars, empty) generates a UUID
        for invalid in [
            None,
            Some(""),
            Some("bad id with spaces"),
            Some(&"x".repeat(129)),
        ] {
            let mut builder = Request::builder().uri("/ping");
            if let Some(val) = invalid {
                builder = builder.header(REQUEST_ID_HEADER, val);
            }
            let response = app
                .clone()
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            let echoed = response
                .headers()
                .get(REQUEST_ID_HEADER)
                .and_then(|v| v.to_str().ok())
                .expect("x-request-id header must be present")
                .to_owned();
            assert!(
                Uuid::parse_str(&echoed).is_ok(),
                "expected generated UUID for {invalid:?}, got: {echoed}"
            );

            let resp_body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&resp_body[..], echoed.as_bytes());
        }
    }
}
