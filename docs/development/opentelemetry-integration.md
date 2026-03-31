# OpenTelemetry integration

KubeDash uses [OpenTelemetry](https://opentelemetry.io/) for distributed tracing. Spans are exported over OTLP (HTTP) to a backend such as [Jaeger](https://www.jaeger.io/), so you can inspect request flows, database and cache calls, and custom operations.

## Overview

When tracing is enabled:

- **Service name**: `KubeDash` (with a unique `service.instance.id` per process).
- **Exporter**: OTLP over HTTP to the configured endpoint (e.g. Jaeger OTLP ingest).
- **Instrumentation**: Flask, WSGI, logging, outgoing HTTP (requests), Redis (if enabled), and SQLAlchemy are instrumented automatically. Correlation IDs (e.g. `X-Request-ID`) are propagated and attached to spans and logs.

If the collector is unreachable, span export failures are handled gracefully: connection errors are logged once and spans are dropped without tracebacks.

## Configuration

Tracing is controlled by the `[monitoring]` section in `kubedash.ini`.

| Option | Default | Description |
|--------|---------|--------------|
| `jaeger_enabled` | `false` | Set to `true` or `1` to enable OpenTelemetry tracing. |
| `jaeger_http_endpoint` | `http://127.0.0.1:4318` | Base URL of the OTLP HTTP endpoint (no path). KubeDash appends `/v1/traces`. |

Example:

```ini
[monitoring]
jaeger_enabled = true
jaeger_http_endpoint = http://127.0.0.1:4318
```

For Kubernetes (e.g. Helm), the endpoint is often the Jaeger OTLP service:

```ini
jaeger_http_endpoint = http://kubedash-jaeger:4318
```

At startup, KubeDash checks connectivity to the endpoint. If the connection fails, tracing is not initialized and the app runs without tracing.

## Running with Jaeger

### Docker Compose

Use the provided Jaeger stack (OTLP enabled):

```bash
docker compose -f deploy/docker-compose/dc-jaeger.yaml up -d
```

Jaeger listens on:

- **16686** – Jaeger UI (http://localhost:16686)
- **4318** – OTLP HTTP (used by KubeDash)

Point `jaeger_http_endpoint` at `http://localhost:4318` (or `http://kubedash-jaeger:4318` if KubeDash runs in the same Compose project).

### Helm

Enable the bundled Jaeger and monitoring config in your values:

```yaml
jaeger:
  enabled: true
```

The chart configures `jaeger_http_endpoint` in the UI ConfigMap (e.g. `http://<release>-jaeger:4318`). The UI pod can wait for Jaeger to be ready before starting.

## What is instrumented

| Component | Details |
|----------|---------|
| **Flask** | Requests, routes; excluded: `/vendor/*`, `/static/*`, `/css/*`, etc. |
| **WSGI** | OpenTelemetry middleware wraps the WSGI app. |
| **Logging** | Log records get trace/span IDs and correlation ID via a log hook. |
| **Requests** | Outgoing HTTP calls (e.g. Kubernetes API, registries). |
| **Redis** | When Redis cache is enabled: commands, connection, optional commenter. |
| **SQLAlchemy** | Database engine; framework/driver set for span attributes. |

### Frontend–backend trace linking

Page loads (e.g. `/dashboard/cluster-metric`) and the API calls that the page’s JavaScript makes (e.g. `/api/v1/cluster/metrics`) are linked in a single trace:

- The server injects the current request’s [W3C Trace Context](https://www.w3.org/TR/trace-context/) (`traceparent`) into the HTML (meta tag and a global).
- A small script in the base template wraps `fetch()` and adds the `traceparent` header to every same-origin request.
- The Flask/WSGI instrumentation extracts that header on API requests and continues the same trace, so in Jaeger you see the page request and its API children (e.g. cluster metrics, events) as one trace.

Span attributes added automatically include:

- `http.url`, `http.method`, `http.route`, `http.status_code`, `http.user_agent`
- `correlation_id` (from `g.correlation_id` or `X-Request-ID`)
- Redis: `redis.command`, connection host/port/db
- SQLAlchemy: db framework and driver (from commenter options)

## Adding custom spans

Use the shared tracer and standard OpenTelemetry APIs:

```python
from lib.opentelemetry import get_tracer
from opentelemetry import trace
from opentelemetry.trace.status import Status, StatusCode

tracer = get_tracer()

with tracer.start_as_current_span("my-operation") as span:
    span.set_attribute("key", "value")
    span.add_event("event-name", {"detail": "info"})
    try:
        # your code
        pass
    except Exception as e:
        span.set_status(Status(StatusCode.ERROR, str(e)))
        raise
```

Many blueprints and plugins already create spans for key operations (e.g. API handlers, K8s calls, cache access).

## Debug trace endpoint

When tracing is enabled and the user is authenticated, you can get the current trace context for the request:

```http
GET /api/debug-trace
```

Response (example):

```json
{
  "flask_correlation_id": "uuid",
  "jaeger_trace_id": "hex-32-chars",
  "span_id": "hex-16-chars",
  "span_attributes": {}
}
```

Use the trace ID in Jaeger (e.g. “Find Trace”) to open the full trace.

## Correlating logs with Jaeger

Application and Gunicorn logs use a **correlation ID** in the same place as the trace ID: `[timestamp] [correlation_id] [logger] [LEVEL] message`. You can use that value in Jaeger in two ways:

1. **Find by Trace ID**  
   When tracing is enabled and no `X-Request-ID`/`X-Trace-ID` header is sent, the app uses the OpenTelemetry trace ID as the correlation ID (32 hex chars). Copy the ID from the log (e.g. `1c9d9f37c70705d80a2b5e1d7d528668`) and in Jaeger UI go to **Search** → **Trace ID** → paste the value → **Find Trace**.

2. **Find by tag**  
   Every span has a `correlation_id` attribute (from the request header or the OTEL trace ID). In Jaeger **Search**, add a tag: `correlation_id=<value>` (e.g. `correlation_id=1c9d9f37c70705d80a2b5e1d7d528668`) and run the search to get traces for that request.

So: **log line** → copy the ID in the second bracket → use it in Jaeger as Trace ID or as tag `correlation_id`.

## Dependencies

Relevant packages (see `pyproject.toml`):

- `opentelemetry-api`, `opentelemetry-sdk`
- `opentelemetry-exporter-otlp-proto-http`
- `opentelemetry-instrumentation-flask`, `-wsgi`, `-logging`, `-requests`, `-redis`, `-sqlalchemy`

## References

- [OpenTelemetry Python](https://opentelemetry.io/docs/instrumentation/python/)
- [Jaeger](https://www.jaeger.io/) and [Jaeger OTLP](https://www.jaeger.io/docs/latest/deployment/#collector)
- [OTLP HTTP specification](https://opentelemetry.io/docs/specs/otlp/#otlphttp)
