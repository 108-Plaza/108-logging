# 108-logging

Shared logging standard and libraries for 108-Plaza services.

Approved 2026-11-13 (Asia/Bangkok): one JSON log format across all projects, a shared Rust crate every service calls once at startup, and a central collector — VictoriaLogs on Dell plus a Vector shipper on each host, both native under systemd, retained 30 days, reached at https://logs.108plaza.net through a Cloudflare tunnel.

## JSON schema (required fields)

Each production log line is one UTF-8 JSON object on stdout (stderr for tq, whose stdout is reserved for MCP). systemd collects this into journald. On a dev tty, pretty text is allowed.

| Field | Meaning |
| --- | --- |
| `ts` | RFC 3339 timestamp with offset, e.g. `2026-11-13T08:30:00+07:00` |
| `level` | `error` \| `warn` \| `info` \| `debug` \| `trace` |
| `service` | Stable service name, e.g. `line-bot` |
| `request_id` | Value of `x-request-id`, or a new UUID; omit when there is no HTTP request |
| `target` | tracing/log module path |
| `message` | Short text. No secrets, slip images, OCR, or personal data |

Optional fields include `host`, `instance`, hashed or internal `user_id`, `latency_ms`, `status`, and other span fields.

## Rust crate (`log108`)

### Startup initialization

Call once at startup:

```rust
log108::init("service-name");
```

Use `init_with` when the process must write to stderr (such as `tq` MCP servers) or customize the output format:

```rust
log108::init_with(log108::Options {
    service: "tq",
    writer: std::io::stderr,
    json: true,
});
```

### Environment variables

- `RUST_LOG` or `LOG_FILTER`: filter directives (precedence: `RUST_LOG` -> `LOG_FILTER` -> `info`).
- `LOG_FORMAT`: `json` or `pretty`. When unset, `log108::init` defaults to `json` when stdout is not a tty and `pretty` on a dev tty.

### Redaction

Do not log tokens, secrets, slip images, OCR text, or personal data.
- `log108`'s subscriber automatically masks structured span and event fields whose names match [`log108::REDACTED_FIELDS`] / [`log108::is_sensitive_field`] (`password`, `token`, `secret`, `authorization`, `cookie`, `otp`, `slip`, `ocr`, `phone`, `email`, `national_id`, `bank_account`, `promptpay`, etc.) as `"[REDACTED]"`.
- Explicit helpers:
  - `log108::redact(value)` / `log108::Redacted(value)` — wrapper whose `Display`, `Debug`, and `Serialize` implementations emit `"[REDACTED]"`.
  - `log108::redact_field(field_name, value)` — returns `"[REDACTED]"` for dangerous field names or `value` unchanged.
  - `log108::redact_json(&mut serde_json::Value)` — recursively masks dangerous keys in JSON payloads.

### Axum / Tower `x-request-id` middleware

Enabled by default via the `axum` / `tower` Cargo features (disable with `default-features = false` for non-HTTP binaries). Applications do not need `pos-infra` to log or propagate request IDs:

```rust
use axum::{Router, routing::get};

let app = Router::new()
    .route("/health", get(|| async { "ok" }))
    .layer(log108::request_id_layer());
```

Or with `axum::middleware::from_fn(log108::trace_request_with_id)`.
- If the incoming `x-request-id` header is ASCII graphic (`0x21..=0x7E`) and at most 128 characters, it is preserved; otherwise a new UUID v4 is generated.
- Stores `log108::RequestId` in request extensions, records `request_id` on the request `tracing` span so every log line inside the request includes `request_id`, and echoes `x-request-id` on the HTTP response.

## Rules

- Native build only. No Docker, and no CI that uses Docker.
- Services write only to stdout/stderr; do not add new files under `/var/log`.
- This repo starts as the Rust library. Dart and TypeScript helpers are later, separate work.
