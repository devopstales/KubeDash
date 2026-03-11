# Logging & Observability – Product Requirements Document

**Version:** 1.0  
**Date:** March 2026  
**Status:** Draft

---

## 1. Overview

### 1.1 Purpose

This PRD defines a unified logging strategy for KubeDash so that:

- **All log streams use the same format** (application, Alembic migrations, Gunicorn access/error) for consistent parsing and correlation.
- **Trace/correlation IDs** flow from proxy headers through Gunicorn, Flask, and OpenTelemetry for request tracing.
- **Structured (JSON) logging** is available in production for ELK/Loki and other aggregators.
- **Error handling and logging** are standardized across the codebase.
- **Audit logging** records sensitive user actions for compliance.

### 1.2 Goals

- **Single log format**: One canonical format for every component: `[timestamp] [trace-id] [logger] [LEVEL] message`.
- **Trace ID propagation**: Read tracing ID from proxy headers (e.g. `X-Request-ID`, `X-Trace-ID`); use it in Gunicorn logs, Flask logs, and OpenTelemetry spans.
- **Structured logging**: Add JSON logging option for production (ELK/Loki compatible); keep human-readable (optionally colored) format for development.
- **Consistent error handling**: Standardize on explicit exception types and structured logging at error sites; avoid bare `except Exception` without logging.
- **Audit logging**: Add an audit trail for user actions (login, logout, privilege changes, destructive operations) for compliance.

---

## 2. Canonical Log Format

### 2.1 Standard Format (Human-Readable)

All KubeDash-originated logs MUST use this format so that grep, splunk, and log pipelines can parse them uniformly:

```
[YYYY-MM-DD HH:MM:SS,mmm] [trace-id] [logger_name] [LEVEL] message
```

**Fields:**

| Field        | Description                    | Example        |
|-------------|---------------------------------|----------------|
| timestamp   | ISO-like date and time, milliseconds | `2026-03-11 13:21:45,246` |
| trace-id    | Request/correlation ID; `no-id` when not in a request | `no-id`, `abc-123`, or value from proxy header |
| logger_name | Logger name (e.g. `kubedash`, `alembic.env`) | `kubedash`, `lib.config_validator` |
| LEVEL       | Log level                       | `INFO`, `WARNING`, `ERROR` |
| message     | Log message (no leading/trailing format tokens) | `Plugin models loaded for migrations: plugins.ai_chat.model` |

**Current vs target examples:**

| Source        | Current example | Target |
|---------------|------------------|--------|
| Flask/app     | `[2026-03-11 13:21:45,246] [no-id] [kubedash] [INFO] ...` | Already compliant |
| Alembic       | `INFO  [alembic.env] Plugin models loaded: ...` | `[2026-03-11 13:21:45,246] [no-id] [alembic.env] [INFO] Plugin models loaded: ...` |
| Gunicorn access | `[11/Mar/2026:13:22:07 +0100] [-] 127.0.0.1 "GET ..."` | Same format style where possible; include trace-id and timestamp in canonical form (see § 2.3) |

### 2.2 JSON Format (Production)

When structured logging is enabled (e.g. `logging_format = json`), each log line MUST be a single JSON object with at least:

```json
{
  "timestamp": "2026-03-11T13:21:45.246Z",
  "trace_id": "no-id",
  "logger": "kubedash",
  "level": "INFO",
  "message": "Plugin models loaded for migrations: plugins.ai_chat.model"
}
```

Optional fields: `user_id`, `request_path`, `duration_ms`, `error_type`, `stack_trace` (for errors). This enables ELK/Loki and other aggregators to index by trace_id, level, and logger.

### 2.3 Gunicorn Access Logs

Access logs SHOULD include the same trace-id and a consistent timestamp style:

- **Current:** `access_log_format = '%(t)s [%(correlation_id)s] %(h)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'`
- **Requirement:** Keep correlation_id in the format; ensure `%(t)s` is configurable so it can align with canonical timestamp format where needed. Optionally add a “canonical line” that matches the standard format for ingestion (e.g. one line per request in `[timestamp] [trace-id] [gunicorn.access] [INFO] method path status size`).

---

## 3. Trace ID Propagation

### 3.1 Flow

```
Proxy / Ingress (X-Request-ID or X-Trace-ID)
    → Gunicorn pre_request (store on worker)
    → Gunicorn access + error logs (correlation_id)
    → Flask (g.correlation_id or request headers)
    → get_logger() / CorrelationIDFilter (record.correlation_id)
    → OpenTelemetry span attributes (trace_id / span_id or link to header)
```

### 3.2 Requirements

1. **Read from proxy**: In Gunicorn `pre_request`, read `X-Request-ID` or `X-Trace-ID` from incoming headers; store on the worker and use as `correlation_id` in log records and access log format.
2. **Flask**: In a before_request or middleware, set `g.correlation_id` (and optionally request-scoped logger context) from the same header so all Flask and app logs use it.
3. **Gunicorn logs**: Use the same trace ID in Gunicorn error and access log format (already partially in place via `%(correlation_id)s`).
4. **OpenTelemetry**: Ensure the trace ID from the header is used or linked in spans (e.g. W3C Trace Context); so that logs and traces can be correlated by the same ID in production.

---

## 4. Error Handling & Logging Standards

### 4.1 Problem

- Some code uses bare `except Exception` with no or ad-hoc logging; others use specific exception types and structured messages.
- Recommendation: Standardize so that all catch sites either re-raise with context or log with a consistent pattern.

### 4.2 Requirements

1. **Avoid bare `except Exception`** without at least one of: (a) structured log (level, message, optional exception type and traceback), or (b) re-raise after adding context.
2. **Structured logging at error sites**: Use logger methods with explicit level and message; for exceptions include `exc_info=True` or equivalent so that stack traces appear in logs when appropriate.
3. **Shared helper**: Prefer a single pattern (e.g. `ErrorHandler(logger, e, "context")`) for API and critical paths so that format and level are consistent.
4. **No emoji in log text**: Keep log messages free of emoji so that parsing and grep remain reliable.

---

## 5. Structured Logging (JSON) for Production

### 5.1 Problem

- Today only a custom color (human-readable) logger is used; there is no JSON option for production log aggregation (ELK/Loki).

### 5.2 Requirements

1. **Configuration**: Add a `[logging]` section (or equivalent) with an option such as `format = text | json` (default `text` for backward compatibility).
2. **JSON formatter**: When `format = json`, use a formatter that emits one JSON object per line with at least `timestamp`, `trace_id`, `logger`, `level`, `message`; optional fields as in § 2.2.
3. **Compatibility**: Ensure the same trace_id and logger names are used in both text and JSON so that switching format does not break correlation.
4. **Air-gapped**: Implementation must work in air-gapped environments (no external services required for JSON logging itself).

---

## 6. Audit Logging

### 6.1 Problem

- There is no audit trail for user actions (login, logout, privilege changes, destructive operations), which is often required for compliance.

### 6.2 Requirements

1. **Audit events**: Record at least: login success/failure, logout, user/group/privilege changes, and destructive or sensitive operations (e.g. delete conversation, delete resource) with user identity, timestamp, action, and outcome.
2. **Storage**: Define a minimal audit log store (e.g. dedicated table or append-only log file) with retention considerations; query/export for compliance reviews.
3. **Format**: Audit entries MUST use the same canonical format (§ 2.1) or the same JSON schema (§ 2.2) with an `audit: true` or `event_type: audit` marker and required fields (user_id, action, resource, result).
4. **Performance**: Audit logging MUST be non-blocking (e.g. async write or fire-and-forget) so that request latency is not significantly impacted.

---

## 7. Alembic (Migrations) Logging

### 7.1 Problem

- Alembic uses its own logging configuration (`fileConfig` in `env.py`), producing a different format: `INFO  [alembic.env] ...` instead of the canonical format.

### 7.2 Requirements

1. **Unify format**: When Alembic runs (e.g. `flask db upgrade`), configure its root and `alembic.*` loggers to use the same format as the application: `[timestamp] [trace-id] [logger_name] [LEVEL] message`. Use `no-id` for trace-id when not in an HTTP request.
2. **Implementation options**: (a) Configure Alembic’s logging in `env.py` to use a custom formatter that matches the canonical format; or (b) run migrations in a context that attaches the same logging config as the app so that all output is consistent.

---

## 8. Implementation Layout

### 8.1 Components

| Component | Responsibility |
|-----------|----------------|
| `lib/initializers/logging.py` | Initialize app logging; apply format (text vs JSON) from config; attach correlation filter. |
| `lib/helper_functions.py` (get_logger) | Keep correlation_id support; support formatter selection (text/JSON) from config; avoid removing root handlers in a way that breaks Alembic when run in same process. |
| `gunicorn_conf.py` | Read trace ID from headers; expose in access_log_format; ensure worker passes correlation_id to app. |
| Flask before_request / middleware | Set `g.correlation_id` from `X-Request-ID` / `X-Trace-ID`. |
| `migrations/env.py` | Configure Alembic loggers to use canonical format (and optional JSON when enabled). |
| Audit module (new or plugin) | Emit audit events in canonical or JSON format; write to audit store. |

### 8.2 Configuration (Proposed)

```ini
[logging]
# Format: text (human-readable, optional color) or json (one JSON object per line)
format = text

# Optional: log level for root (DEBUG, INFO, WARNING, ERROR)
level = INFO
```

When `format = json`, the same trace_id and logger names as in text mode MUST be used.

---

## 9. Phases and Status

### Phase 1 – Unified Format & Trace ID (Priority)

- [ ] Define and document canonical format; ensure Flask/app logs already comply.
- [ ] Propagate trace ID from proxy headers in Gunicorn and Flask; use in all app logs and Gunicorn access/error logs.
- [ ] Align Alembic logging in `env.py` with canonical format (`[timestamp] [no-id] [alembic.env] [LEVEL] message`).
- [ ] Optionally align Gunicorn access log line format (timestamp style + trace-id) for consistency.

### Phase 2 – Structured Logging & Error Handling

- [ ] Add `[logging]` config and JSON formatter; wire to get_logger / initializers.
- [ ] Standardize error handling: reduce bare `except Exception`; use ErrorHandler or explicit log + re-raise; structured logging at error sites.

### Phase 3 – Audit Logging

- [ ] Design audit event schema and storage (table or file).
- [ ] Implement audit logging for login/logout, user/privilege changes, and key destructive actions.
- [ ] Use same canonical/JSON format and non-blocking write.

### Phase 4 – Optional

- [ ] OpenTelemetry: ensure trace ID from header is linked to span context for log-trace correlation in backends.
- [ ] Dashboard or API for audit log query/export for compliance.

---

## 10. Appendix

### A. Example Canonical Lines

```
[2026-03-11 13:21:45,246] [no-id] [kubedash] [INFO] Plugin models loaded for migrations: plugins.ai_chat.model
[2026-03-11 13:21:45,248] [no-id] [alembic.env] [INFO] Plugin models loaded: plugins.ai_chat.model
[2026-03-11 13:21:45,250] [no-id] [alembic.runtime.migration] [INFO] Context impl PostgresqlImpl.
[2026-03-11 13:22:07,123] [req-abc-123] [gunicorn.access] [INFO] GET /dashboard/cluster-metric 200 81777
```

### B. Example JSON Line

```json
{"timestamp":"2026-03-11T13:21:45.246Z","trace_id":"no-id","logger":"kubedash","level":"INFO","message":"Plugin models loaded for migrations: plugins.ai_chat.model"}
```

### C. References

- Platform Hardening & Observability PRD: `docs/prd/platform-hardening-observability.md` (Structured Logging, Audit Logging)
- OpenTelemetry integration: `docs/development/opentelemetry-integration.md`
- Gunicorn config: `src/kubedash/gunicorn_conf.py`
- Logging init: `src/kubedash/lib/initializers/logging.py`
- Logger helper: `src/kubedash/lib/helper_functions.py` (`get_logger`)

---

**Document Version:** 1.0  
**Last Updated:** March 2026
