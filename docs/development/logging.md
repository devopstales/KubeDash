# Logging

KubeDash uses a unified logging strategy so that application logs, Gunicorn access/error logs, and Alembic migration logs share the same format and support trace/correlation IDs. This document summarizes how logging works and how to use it in code.

## Overview

- **Canonical format**: All KubeDash-originated logs use `[YYYY-MM-DD HH:MM:SS,mmm] [trace-id] [logger_name] [LEVEL] message` so that grep and log pipelines can parse them uniformly.
- **Trace ID**: Request correlation ID is read from `X-Request-ID` or `X-Trace-ID` and set on `g.correlation_id` in Flask; it appears in log records and Gunicorn access logs.
- **Structured (JSON) logging**: Optional JSON format (one JSON object per line) for production aggregation (ELK, Loki). Configured via `[logging] format = json` in `kubedash.ini`.
- **Error handling**: Use explicit logging at error sites with `exc_info=True` where appropriate; avoid bare `except Exception` without logging.

## Configuration

Logging is configured in `kubedash.ini` (or equivalent) under a `[logging]` section:

| Option   | Default | Description |
|----------|---------|-------------|
| `format` | `text`  | `text` (human-readable, optional color) or `json` (one JSON object per line). |
| `level`  | `INFO`  | Root log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |

Example:

```ini
[logging]
format = text
level = INFO
```

When `format = json`, each log line is a single JSON object with at least `timestamp`, `trace_id`, `logger`, `level`, and `message`.

## Using the logger in code

1. **Get a logger**: Use `get_logger()` from `lib.helper_functions`. The logger automatically receives the current request’s correlation ID when available (from `g.correlation_id`).

   ```python
   from lib.helper_functions import get_logger
   logger = get_logger()
   logger.info("Plugin loaded: %s", name)
   logger.warning("Retry failed: %s", e, exc_info=True)
   ```

2. **Do not** configure your own handlers or formatters for application logs; initialization is done in `lib.initializers.logging` and uses the app’s config (format, level).

3. **Error sites**: Prefer structured logging with `exc_info=True` for exceptions so that stack traces appear in logs. Use the shared `ErrorHandler` pattern where applicable.

## Trace ID flow

1. Proxy/Ingress (or client) sends `X-Request-ID` or `X-Trace-ID`.
2. `lib/before_request.py` sets `g.correlation_id` from that header (default `no-id`).
3. Gunicorn’s `CanonicalAccessLogger` uses the same header for the access log line.
4. `CorrelationIDFilter` (used by `get_logger()`) attaches `correlation_id` to each log record so the formatter can include it.

OpenTelemetry can use the same header for trace context so logs and traces can be correlated (see [OpenTelemetry integration](opentelemetry-integration.md)).

## Key files

| File | Purpose |
|------|---------|
| `lib/initializers/logging.py` | Initialize app logging; apply format and level from config. |
| `lib/helper_functions.py` | `get_logger()`, `_get_logging_config()`, text/JSON formatters, `ErrorHandler`. |
| `lib/before_request.py` | Set `g.correlation_id` from request headers. |
| `gunicorn_conf.py` | `CanonicalAccessLogger`, trace ID in access log format. |
| `migrations/env.py` | Alembic loggers use canonical format. |

## References

- [OpenTelemetry integration](opentelemetry-integration.md) – Tracing and log-trace correlation.
