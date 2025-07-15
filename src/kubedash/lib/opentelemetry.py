import os
import uuid
import socket
import logging
from urllib.parse import urlparse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

# Initialize basic logger that doesn't depend on tracing
_logger = logging.getLogger(__name__)
_logger.propagate = False  # This prevents the log from being handled by parent loggers
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter(
    fmt=f'[%(asctime)s] [no-id] [%(name)s] [%(levelname)s] %(message)s',
))
_logger.addHandler(_handler)


# Initialize default no-op tracer
tracer = trace.get_tracer(__name__)

def init_opentelemetry_exporter(jaeger_base_url: str):
    """Initialize Jaeger exporter with proper error handling"""
    if not jaeger_base_url:
        _logger.info("Jaeger URL not configured, skipping tracing setup")
        return False

    endpoint = f"{jaeger_base_url}/v1/traces"
    
    # 1. Connection check
    try:
        url = urlparse(jaeger_base_url)
        with socket.create_connection((url.hostname, url.port), timeout=2):
            pass
    except (socket.timeout, ConnectionRefusedError, ValueError) as e:
        _logger.error(f"Jaeger connection failed: {str(e)}")
        return False

    # 2. Setup proper tracer provider
    try:
        resource = Resource.create({
            "service.name": "KubeDash",
            "service.instance.id": str(uuid.uuid4()),
            "telemetry.sdk.name": "opentelemetry",
            "telemetry.sdk.language": "python",
        })
        
        trace.set_tracer_provider(TracerProvider(resource=resource))
        trace.get_tracer_provider().add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
        )
        #trace.get_tracer_provider().add_span_processor(
        #    BatchSpanProcessor(ConsoleSpanExporter())
        #)
        
        global tracer
        tracer = trace.get_tracer(__name__)
        
        _logger.info(f"Jaeger exporter ready at {endpoint}")
        return True
    except Exception as e:
        _logger.error(f"Failed to initialize Jaeger exporter: {str(e)}")
        return False

def get_tracer():
    """Safe access to the tracer instance"""
    return tracer