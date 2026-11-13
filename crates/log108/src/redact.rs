use std::fmt;

use serde::{Serialize, Serializer};
use serde_json::Value;

/// Placeholder string used whenever a sensitive value or field is masked.
pub const REDACTED: &str = "[REDACTED]";

/// Canonical list of dangerous/sensitive field names that must always be masked as [`REDACTED`].
///
/// Covers tokens, secrets, authentication headers/cookies, OTPs, slip images, OCR text,
/// and personal data (PII).
pub const REDACTED_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "pwd",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "session_token",
    "api_key",
    "apikey",
    "private_key",
    "signing_key",
    "authorization",
    "auth",
    "cookie",
    "set_cookie",
    "set-cookie",
    "jwt",
    "bearer",
    "otp",
    "otp_code",
    "pin",
    "cvv",
    "cvc",
    "slip",
    "slip_image",
    "slip_bytes",
    "slip_base64",
    "slip_data",
    "image_bytes",
    "image_base64",
    "raw_image",
    "ocr",
    "ocr_text",
    "ocr_raw",
    "raw_ocr",
    "national_id",
    "citizen_id",
    "thai_id",
    "passport",
    "passport_number",
    "ssn",
    "tax_id",
    "phone",
    "phone_number",
    "mobile",
    "email",
    "address",
    "full_name",
    "first_name",
    "last_name",
    "bank_account",
    "account_number",
    "card_number",
    "promptpay",
    "birth_date",
    "dob",
];

/// Alias for [`REDACTED_FIELDS`].
pub const SENSITIVE_FIELDS: &[&str] = REDACTED_FIELDS;

const SUBSTRING_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "signing_key",
    "authorization",
    "cookie",
    "otp",
    "slip",
    "ocr",
    "national_id",
    "citizen_id",
    "thai_id",
    "passport",
    "bank_account",
    "account_number",
    "card_number",
    "promptpay",
    "birth_date",
    "full_name",
    "first_name",
    "last_name",
    "tax_id",
    "image_bytes",
    "image_base64",
    "raw_image",
];

const SEGMENT_MARKERS: &[&str] = &[
    "pass", "pwd", "auth", "jwt", "bearer", "pin", "cvv", "cvc", "ssn", "phone", "mobile", "email",
    "address", "dob",
];

/// Returns `true` if `field_name` matches a known dangerous field name (tokens, secrets,
/// slip images, OCR text, or personal data) and must be masked as [`REDACTED`].
pub fn is_sensitive_field(field_name: &str) -> bool {
    let trimmed = field_name.trim();
    if trimmed.is_empty() {
        return false;
    }

    let normalized: String = trimmed
        .chars()
        .map(|c| match c {
            '-' | '.' | '/' | ' ' => '_',
            _ => c.to_ascii_lowercase(),
        })
        .collect();

    if REDACTED_FIELDS
        .iter()
        .any(|&f| f == normalized || f.eq_ignore_ascii_case(trimmed))
    {
        return true;
    }

    if SUBSTRING_MARKERS.iter().any(|&m| normalized.contains(m)) {
        return true;
    }

    normalized
        .split('_')
        .filter(|seg| !seg.is_empty())
        .any(|seg| SEGMENT_MARKERS.contains(&seg))
}

/// Returns [`REDACTED`] if `field_name` is a known dangerous field name, or `value` unchanged.
pub fn redact_field<'a>(field_name: &str, value: &'a str) -> &'a str {
    if is_sensitive_field(field_name) {
        REDACTED
    } else {
        value
    }
}

/// Always returns [`REDACTED`], for explicitly masking a raw string value in logs.
pub const fn redact_str(_value: &str) -> &'static str {
    REDACTED
}

/// Recursively masks any object key in `value` whose name matches [`is_sensitive_field`]
/// with `" [REDACTED] "`.
pub fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_sensitive_field(k) {
                    *v = Value::String(REDACTED.to_string());
                } else {
                    redact_json(v);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_json(item);
            }
        }
        _ => {}
    }
}

/// Wrapper type that formats and serializes any inner value as [`REDACTED`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Redacted<T>(pub T);

impl<T> Redacted<T> {
    /// Consumes the wrapper and returns the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> Serialize for Redacted<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

/// Wraps `value` in [`Redacted`] so `Display`, `Debug`, and `Serialize` emit [`REDACTED`].
pub const fn redact<T>(value: T) -> Redacted<T> {
    Redacted(value)
}
