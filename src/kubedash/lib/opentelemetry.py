import logging
import os
import uuid
import socket
from flask import Flask
from urllib.parse import urlparse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExportResult,
)

# Initialize default no-op tracer
tracer = trace.get_tracer(__name__)

# Suppress SDK export tracebacks from the start (they are noisy when collector is down)
logging.getLogger("opentelemetry.sdk._shared_internal").setLevel(logging.WARNING)

# Log connection failures at most once per process to avoid log spam
_export_connection_error_logged = False

try:
    import requests.exceptions as _req_exc
except ImportError:
    _req_exc = None
try:
    import urllib3.exceptions as _urllib3_exc
except ImportError:
    _urllib3_exc = None


def _is_connection_error(exc: BaseException) -> bool:
    """Return True if exc is a connection/refused error or has one in its cause chain."""
    err_indicators = (
        "econnrefused",
        "connection refused",
        "connectionrefusederror",
        "max retries exceeded",
        "failed to establish",
        "connection error",
    )
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, (ConnectionError, OSError)):
            return True
        if _req_exc and isinstance(exc, _req_exc.ConnectionError):
            return True
        if _urllib3_exc and isinstance(exc, _urllib3_exc.MaxRetryError):
            return True
        exc_str = str(exc)
        if "ECONNREFUSED" in exc_str or "ConnectionRefusedError" in type(exc).__name__:
            return True
        if any(ind in exc_str.lower() for ind in err_indicators):
            return True
        exc = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
    return False


class _OTLPSpanExporterWithGracefulFailure(OTLPSpanExporter):
    """Wraps OTLPSpanExporter to catch connection errors and return SUCCESS.

    When the OTLP collector (e.g. Jaeger) is unreachable, the default exporter
    raises and the SDK logs full tracebacks. This wrapper catches connection
    errors and returns SUCCESS so spans are dropped without tracebacks.
    """

    def export(self, spans):
        global _export_connection_error_logged
        try:
            return super().export(spans)
        except Exception as e:  # noqa: BLE001
            if _is_connection_error(e):
                if not _export_connection_error_logged:
                    _export_connection_error_logged = True
                    logging.getLogger(__name__).warning(
                        "OTLP trace export failed (collector unreachable): %s. "
                        "Spans will be dropped; further export errors will not be logged.",
                        e,
                    )
                return SpanExportResult.SUCCESS
            raise

def init_opentelemetry_exporter(app: Flask, jaeger_base_url: str):
    """Initialize Jaeger exporter with proper error handling
    
    Args:
        app (Flask): Flask application instance
        jaeger_base_url (str): Base URL for Jaeger exporter
    Returns:
        bool: True if initialization was successful, False otherwise
    """
    if not jaeger_base_url:
        app.logger.info("Jaeger URL not configured, skipping tracing setup")
        return False

    endpoint = f"{jaeger_base_url}/v1/traces"
    
    # 1. Connection check
    try:
        url = urlparse(jaeger_base_url)
        with socket.create_connection((url.hostname, url.port), timeout=2):
            pass
    except (socket.timeout, ConnectionRefusedError, ValueError) as e:
        app.logger.error(f"Jaeger connection failed: {str(e)}")
        return False

    # 2. Setup proper tracer provider
    try:
        resource = Resource.create({
            "service.name": "KubeDash",
            "service.instance.id": str(uuid.uuid4()),
            "telemetry.sdk.name": "opentelemetry",
            "telemetry.sdk.language": "python",
        })
        
        trace.set_tracer_provider(TracerProvider(resource=resource, shutdown_on_exit=False))
        trace.get_tracer_provider().add_span_processor(
            BatchSpanProcessor(
                _OTLPSpanExporterWithGracefulFailure(endpoint=endpoint)
            )
        )
        # Avoid log spam when OTLP collector is down: SDK logs full tracebacks on export failure
        logging.getLogger("opentelemetry.sdk._shared_internal").setLevel(logging.WARNING)
        # Optionally add console exporter for debugging
        if app.config['ENV'] == 'production' and app.debug:
            trace.get_tracer_provider().add_span_processor(
                BatchSpanProcessor(ConsoleSpanExporter())
            )
                
        global tracer
        tracer = trace.get_tracer(__name__)
        
        app.logger.info(f"Jaeger exporter ready at {endpoint}")
        return True
    except Exception as e:
        app.logger.error(f"Failed to initialize Jaeger exporter: {str(e)}")
        return False

def get_tracer():
    """Safe access to the tracer instance"""
    return tracer