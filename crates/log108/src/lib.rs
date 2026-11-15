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
                        Value::String(s) => write!(writer, " {k}={s:?}")?,
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

        // 1. RUST_LOG wins over LOG_FILTER when both are set.
        let precedence_buf = BufferWriter::default();
        let precedence_filter = build_env_filter_from(Some("warn"), Some("debug"));
        let precedence_sub = build_subscriber_with_filter(
            "matcher",
            precedence_buf.clone(),
            false,
            precedence_filter,
        );
        tracing::subscriber::with_default(precedence_sub, || {
            tracing::info!("info filtered out because RUST_LOG=warn beats LOG_FILTER=debug");
            tracing::warn!("warn visible via RUST_LOG");
        });
        let precedence_text = precedence_buf.take_string();
        assert!(
            !precedence_text.contains("info filtered out"),
            "expected RUST_LOG=warn to override LOG_FILTER=debug, got: {precedence_text}"
        );
        assert!(
            precedence_text.contains("warn visible via RUST_LOG"),
            "got: {precedence_text}"
        );

        // 2. LOG_FILTER is used when RUST_LOG is unset.
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

        // 3. Default is info when both are unset.
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
            // Snake_case and kebab-case forms
            "password",
            "user_password",
            "user_pass",
            "passphrase",
            "token",
            "access_token",
            "refresh_token",
            "secret",
            "client_secret",
            "api_key",
            "x-api-key",
            "X-Api-Key",
            "private_key",
            "signing_key",
            "access_key",
            "aws_access_key_id",
            "secret_key",
            "credential",
            "credentials",
            "session",
            "session_id",
            "signature",
            "x-line-signature",
            "hmac",
            "authorization",
            "Authorization",
            "cookie",
            "set_cookie",
            "set-cookie",
            "otp",
            "OTP",
            "otp_code",
            "otp_value",
            "otpcode",
            "userotp",
            "OTPCode",
            "pin",
            "pin_code",
            "slip",
            "slip_image",
            "ocr",
            "ocr_text",
            "phone",
            "phone_number",
            "email",
            "email_address",
            "user_email",
            "first_name",
            "last_name",
            "full_name",
            "national_id",
            "citizen_id",
            "tax_id",
            "birth_date",
            "date_of_birth",
            "bank_account",
            "account_number",
            "card_number",
            "promptpay",
            // camelCase forms (JSON / Dart clients)
            "accessToken",
            "apiKey",
            "clientSecret",
            "refreshToken",
            "setCookie",
            "ocrText",
            "slipImage",
            "otpCode",
            "phoneNumber",
            "firstName",
            "lastName",
            "fullName",
            "bankAccount",
            "accountNumber",
            "cardNumber",
            "privateKey",
            "signingKey",
            "nationalId",
            "citizenId",
            "birthDate",
            "taxId",
            "emailAddress",
            "userEmail",
            "pinCode",
            "userPass",
            "dateOfBirth",
            "sessionId",
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
            "footprint",
            "session_count",
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
            "phoneNumber": "0812345678",
            "sessionId": "sess-xyz",
            "nested": {
                "slip_image": "base64...",
                "ocr_text": "นาย ก 500.00",
                "accountNumber": "123-4-56789-0",
                "status": "ok"
            }
        });
        redact_json(&mut payload);
        assert_eq!(payload["user_id"], "u-108");
        assert_eq!(payload["password"], REDACTED);
        assert_eq!(payload["phoneNumber"], REDACTED);
        assert_eq!(payload["sessionId"], REDACTED);
        assert_eq!(payload["nested"]["slip_image"], REDACTED);
        assert_eq!(payload["nested"]["ocr_text"], REDACTED);
        assert_eq!(payload["nested"]["accountNumber"], REDACTED);
        assert_eq!(payload["nested"]["status"], "ok");

        // Verify subscriber automatically masks sensitive fields in spans and events (both snake_case and camelCase)
        let buf = BufferWriter::default();
        let sub =
            build_subscriber_with_filter("bank-bot", buf.clone(), true, EnvFilter::new("info"));
        tracing::subscriber::with_default(sub, || {
            let span = tracing::info_span!(
                "auth",
                authorization = "Bearer eyJhbGciOi...",
                sessionId = "sess_secret_1",
                phoneNumber = "0899999999",
            );
            let _enter = span.enter();
            tracing::info!(
                password = "super-secret-password",
                passphrase = "correct-horse-battery-staple",
                token = "tok_live_123",
                accessToken = "at_live_456",
                apiKey = "ak_live_789",
                clientSecret = "cs_live_000",
                refreshToken = "rt_live_111",
                setCookie = "sid=secret",
                credential = "cred_val",
                credentials = "creds_val",
                session_id = "sid_val",
                signature = "sig_val",
                hmac = "hmac_val",
                access_key = "AKIA_TEST",
                aws_access_key_id = "AKIA_AWS",
                secret_key = "sk_test",
                privateKey = "pk_val",
                signingKey = " sign_val",
                slip = "raw-slip-bytes",
                slipImage = "raw-slip-image",
                ocr = "raw-ocr-text",
                ocrText = "raw-ocr-camel",
                otp = "123456",
                otpCode = "654321",
                firstName = "Somchai",
                lastName = "Jaidee",
                fullName = "Somchai Jaidee",
                bankAccount = "111222333",
                accountNumber = "444555666",
                cardNumber = "4111222233334444",
                nationalId = "1100000000001",
                citizenId = "1100000000002",
                birthDate = "1990-01-01",
                dateOfBirth = "1990-01-02",
                taxId = "0105550000001",
                emailAddress = "a@b.com",
                userEmail = "c@d.com",
                pinCode = "9999",
                userPass = "hunter2",
                user_id = "u_99",
                "processed transfer"
            );
        });

        let line = buf.take_string();
        for leaked in [
            "Bearer eyJhbGciOi",
            "sess_secret_1",
            "0899999999",
            "super-secret-password",
            "correct-horse-battery-staple",
            "tok_live_123",
            "at_live_456",
            "ak_live_789",
            "cs_live_000",
            "rt_live_111",
            "sid=secret",
            "cred_val",
            "creds_val",
            "sid_val",
            "sig_val",
            "hmac_val",
            "AKIA_TEST",
            "AKIA_AWS",
            "sk_test",
            "pk_val",
            "sign_val",
            "raw-slip-bytes",
            "raw-slip-image",
            "raw-ocr-text",
            "raw-ocr-camel",
            "123456",
            "654321",
            "Somchai",
            "Jaidee",
            "111222333",
            "444555666",
            "4111222233334444",
            "1100000000001",
            "1100000000002",
            "1990-01-01",
            "1990-01-02",
            "0105550000001",
            "a@b.com",
            "c@d.com",
            "9999",
            "hunter2",
        ] {
            assert!(
                !line.contains(leaked),
                "expected secret value {leaked:?} not to appear in log line: {line}"
            );
        }

        let parsed: Value = serde_json::from_str(line.trim()).expect("valid JSON");
        for masked_key in [
            "authorization",
            "sessionId",
            "phoneNumber",
            "password",
            "passphrase",
            "token",
            "accessToken",
            "apiKey",
            "clientSecret",
            "refreshToken",
            "setCookie",
            "credential",
            "credentials",
            "session_id",
            "signature",
            "hmac",
            "access_key",
            "aws_access_key_id",
            "secret_key",
            "privateKey",
            "signingKey",
            "slip",
            "slipImage",
            "ocr",
            "ocrText",
            "otp",
            "otpCode",
            "firstName",
            "lastName",
            "fullName",
            "bankAccount",
            "accountNumber",
            "cardNumber",
            "nationalId",
            "citizenId",
            "birthDate",
            "dateOfBirth",
            "taxId",
            "emailAddress",
            "userEmail",
            "pinCode",
            "userPass",
        ] {
            assert_eq!(
                parsed[masked_key], REDACTED,
                "expected {masked_key} to be [REDACTED]"
            );
        }
        assert_eq!(parsed["user_id"], "u_99");
    }

    #[test]
    fn redacts_lowercase_otp_concatenations_and_preserves_existing_otp_names() {
        for otp_field in [
            "otp",
            "OTP",
            "otp_code",
            "otp_value",
            "otpCode",
            "OTPCode",
            "otpcode",
            "userotp",
        ] {
            assert!(
                is_sensitive_field(otp_field),
                "expected {otp_field} to be classified as sensitive"
            );
            assert_eq!(redact_field(otp_field, "123456"), REDACTED);
        }
        assert!(!is_sensitive_field("footprint"));

        let buf = BufferWriter::default();
        let sub =
            build_subscriber_with_filter("otp-svc", buf.clone(), true, EnvFilter::new("info"));
        tracing::subscriber::with_default(sub, || {
            tracing::info!(
                otp = "111111",
                otp_code = "222222",
                otpCode = "333333",
                OTPCode = "444444",
                otpcode = "555555",
                userotp = "666666",
                otp_value = "777777",
                "verified otp"
            );
        });

        let line = buf.take_string();
        for secret in [
            "111111", "222222", "333333", "444444", "555555", "666666", "777777",
        ] {
            assert!(
                !line.contains(secret),
                "expected {secret} to be masked in {line}"
            );
        }
        let parsed: Value = serde_json::from_str(line.trim()).expect("valid JSON");
        for key in [
            "otp",
            "otp_code",
            "otpCode",
            "OTPCode",
            "otpcode",
            "userotp",
            "otp_value",
        ] {
            assert_eq!(parsed[key], REDACTED, "expected {key} to be [REDACTED]");
        }
    }

    #[test]
    fn session_matching_masks_credentials_but_not_session_count() {
        for sensitive in [
            "session",
            "session_id",
            "sessionId",
            "x-session-id",
            "X-Session-Id",
            "sessionid",
            "user_session",
            "user_session_id",
            "current_session_id",
            "login_session",
            "refresh_session",
            "session_token",
        ] {
            assert!(
                is_sensitive_field(sensitive),
                "expected {sensitive} to be sensitive"
            );
            assert_eq!(redact_field(sensitive, "secret-sess"), REDACTED);
        }
        for non_sensitive in [
            "session_count",
            "sessionCount",
            "active_sessions",
            "session_total",
        ] {
            assert!(
                !is_sensitive_field(non_sensitive),
                "expected {non_sensitive} NOT to be sensitive"
            );
            assert_eq!(redact_field(non_sensitive, "5"), "5");
        }

        let buf = BufferWriter::default();
        let sub =
            build_subscriber_with_filter("sess-svc", buf.clone(), true, EnvFilter::new("info"));
        tracing::subscriber::with_default(sub, || {
            tracing::info!(
                session = "s_raw",
                session_id = "sid_raw",
                sessionId = "sid_camel",
                sessionid = "sid_flat",
                user_session = "u_sess",
                user_session_id = "u_sid",
                current_session_id = "cur_sid",
                login_session = "login_sess",
                refresh_session = "ref_sess",
                session_count = 5u64,
                sessionCount = 6u64,
                active_sessions = 7u64,
                session_total = 8u64,
                "session check"
            );
        });

        let parsed: Value = serde_json::from_str(buf.take_string().trim()).expect("valid JSON");
        for masked_key in [
            "session",
            "session_id",
            "sessionId",
            "sessionid",
            "user_session",
            "user_session_id",
            "current_session_id",
            "login_session",
            "refresh_session",
        ] {
            assert_eq!(
                parsed[masked_key], REDACTED,
                "expected {masked_key} to be [REDACTED]"
            );
        }
        assert_eq!(parsed["session_count"], 5);
        assert_eq!(parsed["sessionCount"], 6);
        assert_eq!(parsed["active_sessions"], 7);
        assert_eq!(parsed["session_total"], 8);
    }

    #[test]
    fn pretty_mode_escapes_field_values_and_prevents_newline_injection() {
        let buf = BufferWriter::default();
        let sub =
            build_subscriber_with_filter("pretty-svc", buf.clone(), false, EnvFilter::new("info"));
        tracing::subscriber::with_default(sub, || {
            let span = tracing::info_span!("req", note = "hello world", session_id = "sess-secret");
            let _enter = span.enter();
            tracing::info!(
                injected = "line1\n2026-11-13T00:00:00Z ERROR [fake] forged",
                otpcode = "987654",
                count = 3u64,
                "pretty event"
            );
        });

        let output = buf.take_string();
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "newline in field value must not start a second log line, got: {output:?}"
        );
        let line = lines[0];
        assert!(
            line.contains(r#"note="hello world""#),
            "expected escaped string field, got: {line}"
        );
        assert!(
            line.contains(r#"injected="line1\n2026-11-13T00:00:00Z ERROR [fake] forged""#),
            "expected newline to be escaped in field value, got: {line}"
        );
        assert!(
            line.contains(r#"session_id="[REDACTED]""#),
            "expected redacted span field to appear as [REDACTED], got: {line}"
        );
        assert!(
            line.contains(r#"otpcode="[REDACTED]""#),
            "expected redacted event field to appear as [REDACTED], got: {line}"
        );
        assert!(!line.contains("sess-secret"));
        assert!(!line.contains("987654"));
        assert!(line.contains("count=3"));
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
                    tracing::warn!("warn inside ping handler");
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

        // 2. Under RUST_LOG=warn, warn/error lines inside a request still carry request_id
        let warn_buf = BufferWriter::default();
        let warn_sub = build_subscriber_with_filter(
            "test-api",
            warn_buf.clone(),
            true,
            EnvFilter::new("warn"),
        );
        let _warn_guard = tracing::subscriber::set_default(warn_sub);

        let warn_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header(REQUEST_ID_HEADER, "rid-warn-1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(warn_res.status(), StatusCode::OK);
        let warn_output = warn_buf.take_string();
        let warn_lines: Vec<&str> = warn_output.lines().collect();
        assert_eq!(
            warn_lines.len(),
            1,
            "expected only warn line under EnvFilter::new(\"warn\"), got: {warn_output}"
        );
        let warn_json: Value = serde_json::from_str(warn_lines[0]).unwrap();
        assert_eq!(warn_json["level"], "warn");
        assert_eq!(warn_json["request_id"], "rid-warn-1");
        assert_eq!(warn_json["message"], "warn inside ping handler");

        // 3. Missing or invalid x-request-id (spaces, non-graphic tab "a\tb", >128 chars, empty) generates a UUID
        for invalid in [
            None,
            Some(""),
            Some("bad id with spaces"),
            Some("a\tb"),
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

        // 4. `axum::middleware::from_fn(trace_request_with_id)` echoes and attaches request_id to logs
        let fn_app = Router::new()
            .route(
                "/fn",
                get(|Extension(req_id): Extension<RequestId>| async move {
                    tracing::warn!("inside from_fn handler");
                    (StatusCode::OK, req_id.0)
                }),
            )
            .layer(axum::middleware::from_fn(trace_request_with_id));

        let fn_buf = BufferWriter::default();
        let fn_sub =
            build_subscriber_with_filter("test-api", fn_buf.clone(), true, EnvFilter::new("warn"));
        let _fn_guard = tracing::subscriber::set_default(fn_sub);

        let fn_supplied = "req-from-fn-108";
        let fn_res = fn_app
            .oneshot(
                Request::builder()
                    .uri("/fn")
                    .header(REQUEST_ID_HEADER, fn_supplied)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(fn_res.status(), StatusCode::OK);
        assert_eq!(
            fn_res
                .headers()
                .get(REQUEST_ID_HEADER)
                .and_then(|v| v.to_str().ok()),
            Some(fn_supplied)
        );
        let fn_body = fn_res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&fn_body[..], fn_supplied.as_bytes());

        let fn_log_output = fn_buf.take_string();
        let fn_log_json: Value =
            serde_json::from_str(fn_log_output.lines().next().expect("logged line")).unwrap();
        assert_eq!(fn_log_json["request_id"], fn_supplied);
        assert_eq!(fn_log_json["message"], "inside from_fn handler");
    }
}
