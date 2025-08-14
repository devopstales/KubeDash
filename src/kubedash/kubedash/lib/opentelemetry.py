import os
import uuid
import socket
import time
from typing import Optional, Union
from flask import Flask
from urllib.parse import urlparse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter as OTLPSpanExporterGRPC
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
    collector_url: Optional[str] = None,
    enable_console_exporter: bool = False,
    timeout: int = 5,
    max_retries: int = 3,
    retry_delay: float = 1.0,
    protocol: str = "http",
    batch_timeout_millis: int = 5000,
    max_export_batch_size: int = 512,
    max_queue_size: int = 2048,
) -> bool:
    """Initialize OpenTelemetry exporter with robust error handling and configuration options.
    
    Args:
        app: Flask application instance
        collector_url: URL for OTLP collector (e.g., "http://jaeger:4318" or "grpc://otel-collector:4317")
        enable_console_exporter: Whether to enable console exporter for debugging
        timeout: Connection timeout in seconds
        max_retries: Number of retry attempts for connection
        retry_delay: Delay between retries in seconds
        protocol: Preferred protocol ("http" or "grpc")
        batch_timeout_millis: Batch processor timeout in milliseconds
        max_export_batch_size: Maximum batch size for export
        max_queue_size: Maximum queue size for spans
        
    Returns:
        bool: True if initialization was successful, False otherwise
    """
    # Fallback to environment variable if collector_url not provided
    collector_url = collector_url or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    
    if not collector_url:
        app.logger.info("OpenTelemetry collector URL not configured, skipping tracing setup")
        return False

    # Validate and parse URL
    try:
        parsed_url = urlparse(collector_url)
        if not parsed_url.scheme or not parsed_url.hostname:
            raise ValueError(f"Invalid collector URL: {collector_url}")
        
        # Determine protocol from URL if not specified
        if protocol == "auto":
            protocol = parsed_url.scheme
        
        # Set default ports if not specified
        if not parsed_url.port:
            if protocol == "grpc":
                parsed_url = parsed_url._replace(netloc=f"{parsed_url.hostname}:4317")
            else:
                parsed_url = parsed_url._replace(netloc=f"{parsed_url.hostname}:4318")
    except Exception as e:
        app.logger.error(f"Invalid collector URL configuration: {str(e)}")
        return False

    # Connection check with retries
    connected = False
    last_error = None
    
    for attempt in range(1, max_retries + 1):
        try:
            with socket.create_connection(
                (parsed_url.hostname, parsed_url.port), 
                timeout=min(2, timeout)
            ):
                connected = True
                break
        except (socket.timeout, ConnectionRefusedError, ValueError, socket.gaierror) as e:
            last_error = str(e)
            if attempt < max_retries:
                app.logger.warning(
                    f"OpenTelemetry collector connection attempt {attempt}/{max_retries} failed: {last_error}. "
                    f"Retrying in {retry_delay} seconds..."
                )
                time.sleep(retry_delay)
                
    if not connected:
        app.logger.error(f"Failed to connect to OpenTelemetry collector after {max_retries} attempts: {last_error}")
        if enable_console_exporter:
            app.logger.info("Falling back to console exporter only")
            return _setup_console_only_exporter(app)
        return False

    # Setup proper tracer provider
    try:
        resource = Resource.create({
            SERVICE_NAME: app.name or "KubeDash",
            SERVICE_INSTANCE_ID: str(uuid.uuid4()),
            "telemetry.sdk.language": "python",
            "environment": app.config.get("ENV", "development"),
            "version": app.config.get("VERSION", "unknown"),
        })
        
        trace.set_tracer_provider(TracerProvider(resource=resource))
        
        # Configure exporter based on protocol
        endpoint = f"{parsed_url.geturl()}/v1/traces"
        
        if protocol == "grpc":
            exporter = OTLPSpanExporterGRPC(
                endpoint=endpoint,
                timeout=timeout,
            )
        else:
            exporter = OTLPSpanExporter(
                endpoint=endpoint,
                timeout=timeout,
            )
        
        # Configure batch processor with parameters
        trace.get_tracer_provider().add_span_processor(
            BatchSpanProcessor(
                exporter,
                schedule_delay_millis=batch_timeout_millis,
                max_export_batch_size=max_export_batch_size,
                max_queue_size=max_queue_size,
            )
        )
        
        # Add console exporter if enabled (only in development)
        if enable_console_exporter and app.config.get('ENV', 'development') == 'development':
            trace.get_tracer_provider().add_span_processor(
                SimpleSpanProcessor(ConsoleSpanExporter())
            )
            app.logger.info("Console span exporter enabled")
        
        global tracer
        tracer = trace.get_tracer(__name__)
        
        app.logger.info(f"OpenTelemetry initialized successfully with {protocol.upper()} endpoint: {endpoint}")
        return True
        
    except Exception as e:
        app.logger.error(f"Failed to initialize OpenTelemetry: {str(e)}", exc_info=True)
        if enable_console_exporter:
            app.logger.info("Falling back to console exporter only")
            return _setup_console_only_exporter(app)
        return False

def _setup_console_only_exporter(app: Flask) -> bool:
    """Fallback to console-only exporter when collector connection fails."""
    try:
        trace.set_tracer_provider(TracerProvider())
        trace.get_tracer_provider().add_span_processor(
            SimpleSpanProcessor(ConsoleSpanExporter())
        )
        global tracer
        tracer = trace.get_tracer(__name__)
        app.logger.warning("Using console-only span exporter as fallback")
        return True
    except Exception as e:
        app.logger.error(f"Failed to setup console exporter: {str(e)}")
        return False

def get_tracer() -> trace.Tracer:
    """Get the tracer instance. Falls back to no-op tracer if initialization failed.
    
    Returns:
        The configured tracer or a no-op tracer if initialization failed
    """
    return tracer