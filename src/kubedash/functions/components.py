import logging, socket
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

logger = logging.getLogger(__name__)
logging.basicConfig(
        level="INFO",
        format='[%(asctime)s] %(name)s        %(levelname)s %(message)s'
    )

login_manager = LoginManager()
db = SQLAlchemy()
csrf = CSRFProtect()

endpoint="http://127.0.0.1:4318"+"/v1/traces"
# what other attributes ?
resource = Resource(attributes={
    "service.name": "KubeDash",
    "service.instance.id": "2193801",
    "telemetry.sdk.name": "opentelemetry",
    "telemetry.sdk.language": "python",
    "telemetry.sdk.version": "0.16.0",
})

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('127.0.0.1',4318))

if result == 0:
    trace.set_tracer_provider(TracerProvider(resource=resource))
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(endpoint=endpoint)
        )
    )
    tracer = trace.get_tracer(__name__)
    logger.info("Jaeger endpoint connection established")
else:
    tracer = None
    logger.error("Cannot Connect to Jaeger endpoint")