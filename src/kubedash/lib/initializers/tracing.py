#!/usr/bin/env python3
"""OpenTelemetry tracing initialization for KubeDash."""

import uuid
from flask import Flask, g, request, has_request_context
from opentelemetry import trace
from opentelemetry.instrumentation.wsgi import OpenTelemetryMiddleware
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor


def inject_trace_context_processor():
    """Inject W3C traceparent into template context so frontend can propagate it on API calls.

    When the browser loads a page (e.g. /dashboard/cluster-metric), the server creates a trace span.
    This makes the current span's traceparent available to the template. The base template then
    exposes it to JavaScript and wraps fetch() so that subsequent API calls (e.g. /api/v1/cluster/metrics)
    send the traceparent header. The backend continues the same trace, linking page load and API spans.
    """
    if not has_request_context():
        return {}
    span = trace.get_current_span()
    if not span or not span.get_span_context().is_valid or not span.is_recording():
        return {}
    ctx = span.get_span_context()
    # Avoid injecting all-zero (no-op) context
    if ctx.trace_id == 0 and ctx.span_id == 0:
        return {}
    # W3C Trace Context: version-trace_id-span_id-flags (e.g. 00-4bf92f...-00f067aa...-01)
    traceparent = f"00-{ctx.trace_id:032x}-{ctx.span_id:016x}-{ctx.trace_flags:02x}"
    return {"traceparent": traceparent}


def initialize_app_tracing(app: Flask):
    """Initialize OpenTelemetry tracing

    Args:
        app (Flask): Flask instance

    Returns:
        jaeger_enabled (global): True if tracing is enabled
    """
    from lib.helper_functions import bool_var_test

    if not bool_var_test(app.config['kubedash.ini'].get('monitoring', 'jaeger_enabled')):
        return False

    jaeger_url = app.config['kubedash.ini'].get('monitoring', 'jaeger_http_endpoint')

    # 1. First setup exporter
    from lib.opentelemetry import init_opentelemetry_exporter
    if not init_opentelemetry_exporter(app, jaeger_url):
        return False

    # 2. Then initialize instrumentors
    initialize_instrumentors(app)

    # 3. Add additional span enrichment
    @app.before_request
    def enrich_spans():
        if has_request_context() and hasattr(g, 'correlation_id'):
            span = trace.get_current_span()
            if span.is_recording():
                span.set_attribute("correlation_id", g.correlation_id)
                span.set_attribute("http.url", request.url)
                span.set_attribute("http.method", request.method)

    return True


def initialize_instrumentors(app: Flask):
    """Initialize OpenTelemetry instrumentors with full correlation ID support

    Args:
        app (Flask): Flask app object
    """

    def get_correlation_id():
        """Unified correlation ID source with fallbacks"""
        # 1. First try Flask's g context (this will work after before_request)
        if has_request_context() and hasattr(g, 'correlation_id'):
            return g.correlation_id
        # 2. Check request headers (standard X-Request-ID header from ingress)
        if has_request_context() and 'X-Request-ID' in request.headers:
            return request.headers['X-Request-ID']
        ## 3. Generate new if none exists
        #return str(uuid.uuid4())
        return None

    def request_hook(span, environ):
        """Set correlation ID on spans, but don't generate new ones here"""
        # Don't generate new ID here - let before_request handle it
        if has_request_context() and 'X-Request-ID' in request.headers:
            span.set_attribute("correlation_id", request.headers['X-Request-ID'])

        # Mirror important HTTP attributes
        span.set_attribute("http.route", environ.get('PATH_INFO'))
        span.set_attribute("http.method", environ.get('REQUEST_METHOD'))
        HTTP_USER_AGENT = environ.get('HTTP_USER_AGENT')
        if HTTP_USER_AGENT:
            span.set_attribute("http.user_agent", HTTP_USER_AGENT)
        else:
            span.set_attribute("http.user_agent", "Unknown")

    def response_hook(span, status, response_headers):
        """Ensure request ID header exists"""
        correlation_id = get_correlation_id()

        if correlation_id:
            # Add header if not present (standard X-Request-ID header)
            if not any(k.lower() == 'x-request-id' for k, _ in response_headers):
                response_headers.append(('X-Request-ID', correlation_id))

        # Record final status
        span.set_attribute("http.status_code", status.split()[0])
        span.set_attribute("http.status_text", status)

    def log_hook(span, record):
        """Inject correlation ID into all log records"""
        record.correlation_id = get_correlation_id()

        # Additional useful context
        if has_request_context():
            record.endpoint = request.endpoint or ''
            record.path = request.path or ''
            record.method = request.method or ''
        else:
            record.endpoint = ''
            record.path = ''
            record.method = ''

    def redis_request_hook(span, instance, args, kwargs=None):
        """Updated Redis request hook with all arguments"""
        correlation_id = get_correlation_id()
        if correlation_id:
            span.set_attribute("correlation_id", correlation_id)

        # Handle both args and kwargs
        command_args = list(args)
        if kwargs:
            command_args.extend(f"{k}={v}" for k, v in kwargs.items())

        # Sanitize and truncate arguments
        sanitized_args = []
        for arg in command_args[:3]:  # Only show first 3 args
            if isinstance(arg, bytes):
                try:
                    sanitized_args.append(arg.decode('utf-8'))
                except UnicodeDecodeError:
                    # Binary data (e.g., pickled session data) - show placeholder
                    sanitized_args.append(f"<binary:{len(arg)} bytes>")
            else:
                sanitized_args.append(str(arg))
        span.set_attribute("redis.command", " ".join(sanitized_args))

        # Add connection context
        if hasattr(instance, 'connection_pool'):
            span.set_attributes({
                "redis.connection.host": instance.connection_pool.connection_kwargs.get('host'),
                "redis.connection.port": instance.connection_pool.connection_kwargs.get('port'),
                "redis.connection.db": instance.connection_pool.connection_kwargs.get('db')
            })

    def redis_response_hook(span, instance, response):
        """Record response metrics"""
        if response is not None:
            response_size = len(response) if isinstance(response, (bytes, str, list, dict)) else 1
            span.set_attribute("redis.response_size", response_size)

        # Record cache hit/miss for GET operations
        if span.is_recording() and hasattr(span, 'name') and 'get' in span.name.lower():
            span.set_attribute("redis.cache_hit", response is not None)

    app_config = app.config['kubedash.ini']
    redis_enabled = app_config.get('remote_cache', 'redis_enabled', fallback='none').lower() == 'true'

    # Initialize Redis instrumentation
    if redis_enabled:
        app.logger.info("\tInitializing tracing for Redis")
        RedisInstrumentor().instrument(
            tracer_provider=trace.get_tracer_provider(),
            request_hook=redis_request_hook,
            response_hook=redis_response_hook,
            # Enable these for more detailed tracing
            enable_commenter=True,  # Adds trace context to Redis commands
            suppress_instrumentation=False,
            # Custom span names
            span_name_formatter=lambda cmd: f"redis.{cmd.decode('utf-8').split()[0].lower()}"
        )

    # Instrumentation with all hooks
    app.logger.info("\tInitializing tracing for Flask")
    FlaskInstrumentor().instrument_app(
        app,
        excluded_urls="/vendor/*,/css/*,/scss/*,/js/*,/img/*,/static/*,/favicon.ico",
        request_hook=request_hook,
        response_hook=response_hook,
        tracer_provider=trace.get_tracer_provider()
    )

    app.logger.info("\tInitializing tracing for SQLAlchemy")
    RequestsInstrumentor().instrument(
        tracer_provider=trace.get_tracer_provider()
    )

    app.logger.info("\tInitializing tracing for Logging")
    LoggingInstrumentor().instrument(
        tracer_provider=trace.get_tracer_provider()
    )

    # Ensure WSGI middleware is properly instrumented
    app.logger.info("\tInitializing OpenTelemetry WSGI Middleware")
    app.wsgi_app = OpenTelemetryMiddleware(
        app.wsgi_app,
        tracer_provider=trace.get_tracer_provider()
    )
