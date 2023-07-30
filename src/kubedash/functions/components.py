import socket, os
from urllib.parse import urlparse
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO

from functions.helper_functions import get_logger

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

logger = get_logger(__name__)

login_manager = LoginManager()
login_manager.login_message_category = "warning"
db = SQLAlchemy()
sess = Session()
csrf = CSRFProtect()
socketio = SocketIO()
tracer = None
jager_url = os.environ.get('JAEGER_HTTP_ENDPOINT', None) # "http://127.0.0.1:4318"

if jager_url:
    endpoint=jager_url+"/v1/traces"
    # what other attributes ?
    resource = Resource(attributes={
        "service.name": "KubeDash",
        "service.instance.id": "2193801",
        "telemetry.sdk.name": "opentelemetry",
        "telemetry.sdk.language": "python",
    })

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    urlparse = urlparse(jager_url)
    result = sock.connect_ex((urlparse.hostname, urlparse.port))

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
        logger.error("Cannot Connect to Jaeger endpoint %s" % endpoint)