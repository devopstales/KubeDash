import socket, os
from urllib.parse import urlparse

from lib_functions.helper_functions import get_logger

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

##############################################################
## Helpers
##############################################################

logger = get_logger()
tracer = None

##############################################################
## OTEL Functions
##############################################################

def init_opentelemetry_exporter(jaeger_base_url: str):
    """Initialize the OpenTelemetry exporter
    
    Args:
        jaeger_base_url (str): The base URL of jaeger HTTP client
    """
    endpoint=jaeger_base_url+"/v1/traces"
    resource = Resource(attributes={
        "service.name": "KubeDash",
        "service.instance.id": "2193801",
        "telemetry.sdk.name": "opentelemetry",
        "telemetry.sdk.language": "python",
    })

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    url = urlparse(jaeger_base_url)
    result = sock.connect_ex((url.hostname, url.port))

    if result == 0:
        trace.set_tracer_provider(TracerProvider(resource=resource))
        trace.get_tracer_provider().add_span_processor(
            BatchSpanProcessor(
                OTLPSpanExporter(endpoint=endpoint)
            )
        )
        tracer = trace.get_tracer(__name__)
        logger.info("Jaeger connection established")
    else:
        logger.error("Cannot Connect to Jaeger %s" % endpoint)