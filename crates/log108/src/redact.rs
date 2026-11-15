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
    "access_key",
    "secret_key",
    "credential",
    "credentials",
    "session",
    "session_id",
    "session_key",
    "signature",
    "passphrase",
    "hmac",
    "authorization",
    "auth",
    "cookie",
    "set_cookie",
    "set-cookie",
    "jwt",
    "bearer",
    "otp",
    "otp_code",
    "otpcode",
    "userotp",
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
    "date_of_birth",
    "dob",
];

/// Alias for [`REDACTED_FIELDS`].
pub const SENSITIVE_FIELDS: &[&str] = REDACTED_FIELDS;

const SUBSTRING_MARKERS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "signing_key",
    "access_key",
    "secret_key",
    "credential",
    "signature",
    "hmac",
    "authorization",
    "cookie",
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
    "date_of_birth",
    "full_name",
    "first_name",
    "last_name",
    "tax_id",
    "image_bytes",
    "image_base64",
    "raw_image",
];

const SEGMENT_MARKERS: &[&str] = &[
    "pass", "pwd", "auth", "jwt", "bearer", "otp", "pin", "cvv", "cvc", "ssn", "phone", "mobile",
    "email", "address", "dob",
];

const SESSION_EXEMPT_SUFFIXES: &[&str] = &[
    "count", "total", "num", "number", "len", "size", "max", "min", "limit",
];

/// Returns `true` if `field_name` matches a known dangerous field name (tokens, secrets,
/// slip images, OCR text, or personal data) and must be masked as [`REDACTED`].
pub fn is_sensitive_field(field_name: &str) -> bool {
    let trimmed = field_name.trim();
    if trimmed.is_empty() {
        return false;
    }

    let chars: Vec<char> = trimmed.chars().collect();
    let mut normalized = String::with_capacity(trimmed.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if matches!(c, '-' | '.' | '/' | ' ') {
            normalized.push('_');
        } else {
            if i > 0 && c.is_ascii_uppercase() {
                let prev = chars[i - 1];
                let next_is_lower = chars.get(i + 1).is_some_and(|n| n.is_ascii_lowercase());
                if prev.is_ascii_lowercase()
                    || prev.is_ascii_digit()
                    || (prev.is_ascii_uppercase() && next_is_lower)
                {
                    normalized.push('_');
                }
            }
            normalized.push(c.to_ascii_lowercase());
        }
    }

    if REDACTED_FIELDS
        .iter()
        .any(|&f| f == normalized || f.eq_ignore_ascii_case(trimmed))
    {
        return true;
    }

    if SUBSTRING_MARKERS.iter().any(|&m| normalized.contains(m)) {
        return true;
    }

    let segments: Vec<&str> = normalized
        .split('_')
        .filter(|seg| !seg.is_empty())
        .collect();

    if segments.iter().any(|&seg| {
        SEGMENT_MARKERS.contains(&seg) || seg.starts_with("otp") || seg.ends_with("otp")
    }) {
        return true;
    }

    segments
        .iter()
        .any(|&seg| seg == "session" || seg == "sessionid")
        && !segments
            .last()
            .is_some_and(|last| SESSION_EXEMPT_SUFFIXES.contains(last))
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
