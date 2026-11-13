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

Call once at startup:

```rust
log108::init("service-name");
```

Use `init_with` when the process must write to stderr (tq). Filter with `RUST_LOG` or `LOG_FILTER` (default `info`). This repository will also provide feature-gated axum/tower `x-request-id` middleware. Applications must not depend on `pos-infra` just to log.

Do not log tokens, secrets, slip images, OCR text, or personal data. Dangerous field names (`password`, `token`, `secret`, `authorization`, `cookie`, `otp`, `slip`, `ocr`, and similar) must be masked as `[REDACTED]`.

## Rules

- Native build only. No Docker, and no CI that uses Docker.
- Services write only to stdout/stderr; do not add new files under `/var/log`.
- This repo starts as the Rust library. Dart and TypeScript helpers are later, separate work.
