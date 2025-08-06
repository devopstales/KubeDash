import os
import uuid
import socket
import time
from typing import Optional
from flask import Flask
from urllib.parse import urlparse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_INSTANCE_ID
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)

# Initialize default no-op tracer
tracer = trace.get_tracer(__name__)

def init_opentelemetry_exporter(
    app: Flask,
    jaeger_base_url: Optional[str] = None,
    enable_console_exporter: bool = False,
    timeout: int = 5,
    max_retries: int = 3,
    retry_delay: float = 1.0
) -> bool:
    """Initialize OpenTelemetry exporter with proper error handling and retry logic.
    
    Args:
        app: Flask application instance
        jaeger_base_url: Base URL for Jaeger exporter (e.g., "http://jaeger:4318")
        enable_console_exporter: Whether to enable console exporter for debugging
        timeout: Connection timeout in seconds
        max_retries: Number of retry attempts for connection
        retry_delay: Delay between retries in seconds
        
    Returns:
        bool: True if initialization was successful, False otherwise
    """
    if not jaeger_base_url:
        app.logger.info("Jaeger URL not configured, skipping tracing setup")
        return False

    endpoint = f"{jaeger_base_url}/v1/traces"
    
    # Connection check with retries
    connected = False
    last_error = None
    
    for attempt in range(1, max_retries + 1):
        # 1. Connection check
        try:
            url = urlparse(jaeger_base_url)
            with socket.create_connection((url.hostname, url.port), timeout=2):
                connected = True
                break
        except (socket.timeout, ConnectionRefusedError, ValueError, socket.gaierror) as e:
            last_error = str(e)
            if attempt < max_retries:
                app.logger.warning(
                    f"Jaeger connection attempt {attempt}/{max_retries} failed: {last_error}. "
                    f"Retrying in {retry_delay} seconds..."
                )
                time.sleep(retry_delay)
                
    if not connected:
        app.logger.error(f"Failed to connect to Jaeger after {max_retries} attempts: {last_error}")
        return False

    # 2. Setup proper tracer provider
    try:
        resource = Resource.create({
            SERVICE_NAME: "KubeDash",
            SERVICE_INSTANCE_ID: str(uuid.uuid4()),
            "telemetry.sdk.language": "python",
            "environment": app.config.get("ENV", "development"),
        })
        
        trace.set_tracer_provider(TracerProvider(resource=resource))
        
        # Configure OTLP exporter with retry policy
        otlp_exporter = OTLPSpanExporter(
            endpoint=endpoint,
            timeout=timeout,
            # These are the default retry parameters in OTLP HTTP exporter
            max_retries=max_retries,
            retry_delay=retry_delay * 1000,  # in milliseconds
        )
        
        trace.get_tracer_provider().add_span_processor(
            BatchSpanProcessor(otlp_exporter)
        )
        
        # Add console exporter if enabled
        if enable_console_exporter or (app.config.get('ENV') == 'development'):
            trace.get_tracer_provider().add_span_processor(
                SimpleSpanProcessor(ConsoleSpanExporter())
            )
            app.logger.info("Console span exporter enabled")
        
        global tracer
        tracer = trace.get_tracer(__name__)
        
        app.logger.info(f"OpenTelemetry initialized successfully with endpoint: {endpoint}")
        return True
        
    except Exception as e:
        app.logger.error(f"Failed to initialize OpenTelemetry: {str(e)}", exc_info=True)
        return False

def get_tracer() -> trace.Tracer:
    """Get the tracer instance. Falls back to no-op tracer if initialization failed.
    
    Returns:
        The configured tracer or a no-op tracer if initialization failed
    """
    return tracer
