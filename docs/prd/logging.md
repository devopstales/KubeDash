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

### 1.2 Goals

- **Single log format**: One canonical format for every component: `[timestamp] [trace-id] [logger] [LEVEL] message`.
- **Trace ID propagation**: Read tracing ID from proxy headers (e.g. `X-Request-ID`, `X-Trace-ID`); use it in Gunicorn logs, Flask logs, and OpenTelemetry spans.
- **Structured logging**: Add JSON logging option for production (ELK/Loki compatible); keep human-readable (optionally colored) format for development.
- **Consistent error handling**: Standardize on explicit exception types and structured logging at error sites; avoid bare `except Exception` without logging.

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

| Source        | Before Phase 1 | After Phase 1 (target) |
|---------------|-----------------|--------------------------|
| Flask/app     | Already compliant | `[2026-03-11 13:21:45,246] [trace-id] [kubedash] [INFO] ...` |
| Alembic       | `INFO  [alembic.env] ...` | `[2026-03-11 13:21:45,246] [no-id] [alembic.env] [INFO] ...` |
| Gunicorn access | `[11/Mar/2026:13:22:07 +0100] [-] 127.0.0.1 "GET ..."` | `[2026-03-11 13:22:07,123] [trace-id] [gunicorn.access] [INFO] 127.0.0.1 "GET ..."` (via `CanonicalAccessLogger`) |

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

### 2.3 Gunicorn Access Logs (Phase 1 implemented)

Access logs use the same trace-id and canonical timestamp via a custom Logger:

- **Implementation:** `CanonicalAccessLogger` (in `gunicorn_conf.py`) overrides `now()` to return `[YYYY-MM-DD HH:MM:SS,mmm]` and `atoms()` to add `correlation_id` from request headers or WSGI environ (`HTTP_X_REQUEST_ID`, `HTTP_X_TRACE_ID`), default `no-id`.
- **Format:** `access_log_format` includes `[gunicorn.access] [INFO]` and `%(correlation_id)s`; same config in `src/kubedash/gunicorn_conf.py` and `docker/kubedash/gunicorn_conf.py`.
- **Verification:** Ensure the app is started with the config that sets `logger_class = CanonicalAccessLogger` (e.g. `gunicorn -c gunicorn_conf.py` from the directory containing that config).
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

## 6. Alembic (Migrations) Logging

### 6.1 Problem

- Alembic uses its own logging configuration (`fileConfig` in `env.py`), producing a different format: `INFO  [alembic.env] ...` instead of the canonical format.

### 6.2 Requirements

1. **Unify format**: When Alembic runs (e.g. `flask db upgrade`), configure its root and `alembic.*` loggers to use the same format as the application: `[timestamp] [trace-id] [logger_name] [LEVEL] message`. Use `no-id` for trace-id when not in an HTTP request.
2. **Implementation options**: (a) Configure Alembic’s logging in `env.py` to use a custom formatter that matches the canonical format; or (b) run migrations in a context that attaches the same logging config as the app so that all output is consistent.

---

## 7. Implementation Layout

### 7.1 Components

| Component | Responsibility |
|-----------|----------------|
| `lib/initializers/logging.py` | Initialize app logging; apply format (text vs JSON) from config; attach correlation filter. |
| `lib/helper_functions.py` (get_logger) | Keep correlation_id support; support formatter selection (text/JSON) from config; avoid removing root handlers in a way that breaks Alembic when run in same process. |
| `gunicorn_conf.py` | Read trace ID from headers; expose in access_log_format; ensure worker passes correlation_id to app. |
| Flask before_request / middleware | Set `g.correlation_id` from `X-Request-ID` / `X-Trace-ID`. |
| `migrations/env.py` | Configure Alembic loggers to use canonical format (and optional JSON when enabled). |

### 7.2 Configuration (Proposed)

```ini
[logging]
# Format: text (human-readable, optional color) or json (one JSON object per line)
format = text

# Optional: log level for root (DEBUG, INFO, WARNING, ERROR)
level = INFO
```

When `format = json`, the same trace_id and logger names as in text mode MUST be used.

---

## 8. Phases and Status

### Phase 1 – Unified Format & Trace ID (Priority) ✅

- [x] **Canonical format defined**: `[YYYY-MM-DD HH:MM:SS,mmm] [trace-id] [logger_name] [LEVEL] message` (Section 2).
- [x] **Flask/app logs**: `get_logger()` uses `BooleanColorFormatter` with `formatTime()` for msecs; `CorrelationIDFilter` sets `correlation_id` from `g.correlation_id` or `no-id`.
- [x] **Trace ID in Flask**: `before_request` sets `g.correlation_id` from `X-Request-ID` or `X-Trace-ID`, default `no-id` (`lib/before_request.py`).
- [x] **Trace ID in Gunicorn**: `pre_request` always sets `worker.correlation_id` from same headers or `no-id` (`gunicorn_conf.py`).
- [x] **Alembic**: `migrations/env.py` applies `CanonicalFormatter` to root handlers after `fileConfig`, so migration output uses `[timestamp] [no-id] [alembic.env] [LEVEL] message`.
- [x] **Gunicorn error log**: `on_starting` sets `_CanonicalFormatter` on `server.log.error_log` handlers for timestamp consistency.
- [x] **Gunicorn access log**: Custom `CanonicalAccessLogger` (subclasses `gunicorn_color.Logger`) overrides `now()` (canonical timestamp) and `atoms()` (adds `correlation_id` from request headers or WSGI `HTTP_X_REQUEST_ID`/`HTTP_X_TRACE_ID`). `logger_class = CanonicalAccessLogger`; `access_log_format` includes `[gunicorn.access] [INFO]`. Same logger and format in `docker/kubedash/gunicorn_conf.py`.
- [x] **Cert and Ticker**: `lib/cert_utils.py` and `ThreadedTicker` in `helper_functions.py` use canonical timestamp formatter.

**Verification**: If Gunicorn access lines still show `[11/Mar/2026:... +0100] [-]`, ensure the process is started with the config that defines `CanonicalAccessLogger` (e.g. `gunicorn -c gunicorn_conf.py` from `src/kubedash`, or the same config in Docker). With eventlet workers, the Logger is created from `cfg.logger_class`; both string and class reference are supported by Gunicorn.

### Phase 2 – Structured Logging & Error Handling ✅

- [x] **`[logging]` config**: Added to `kubedash.ini.example` and default config when file missing: `format = text | json`, `level = INFO`. Read via `_get_logging_config(ini_config)` from file or from app config; `get_logger(ini_config=app.config['kubedash.ini'])` in `initialize_app_logging(app)`.
- [x] **JSON formatter**: `JsonFormatter` in `lib/helper_functions.py` emits one JSON object per line with `timestamp` (ISO UTC), `trace_id`, `logger`, `level`, `message`; optional `error_type` and `stack_trace` when `exc_info` present. Same trace_id and logger names as text mode.
- [x] **Wire to get_logger / initializers**: `get_logger()` uses `_get_logging_config()` to choose text (BooleanColorFormatter) or JSON formatter and root log level; `initialize_app_logging(app)` passes app ini so format/level come from app config.
- [x] **ErrorHandler**: Enhanced to log with `exc_info=True` when error is a `BaseException`; docstring updated for structured use at API/critical paths.
- [x] **Structured logging at error sites**: CorrelationIDFilter keeps intentional swallow with comment. Flux plugin `get_flux_objects` (and websocket equivalent) now use a `_get_or_empty` helper that logs `logger.warning(..., exc_info=True)` on failure instead of bare `except Exception`.

### Phase 3 – Optional

- [ ] OpenTelemetry: ensure trace ID from header is linked to span context for log-trace correlation in backends.

---

## 9. Appendix

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

- Platform Hardening & Observability PRD: `docs/prd/platform-hardening-observability.md` (Structured Logging)
- OpenTelemetry integration: `docs/development/opentelemetry-integration.md`
- Logging (developer doc): `docs/development/logging.md`
- Gunicorn config: `src/kubedash/gunicorn_conf.py`
- Logging init: `src/kubedash/lib/initializers/logging.py`
- Logger helper: `src/kubedash/lib/helper_functions.py` (`get_logger`)

**Related:** For audit events (user actions, compliance), see the separate [Audit Logging PRD](audit-logging.md) and [Audit logging](../development/audit-logging.md) doc.

---

**Document Version:** 1.0  
**Last Updated:** March 2026
