import os
import uuid
import socket
from flask import Flask
from urllib.parse import urlparse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

# Initialize default no-op tracer
tracer = trace.get_tracer(__name__)

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
            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
        )
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