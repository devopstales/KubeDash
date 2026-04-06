import logging
import os
import uuid
import time
from datetime import datetime as dt
from statsd import StatsClient

from gunicorn_color import Logger as GunicornColorLogger
from lib.cert_utils import generate_self_signed_cert


def _canonical_timestamp():
    """Timestamp in canonical format: [YYYY-MM-DD HH:MM:SS,mmm]"""
    now = time.time()
    ct = dt.fromtimestamp(now)
    s = ct.strftime("%Y-%m-%d %H:%M:%S")
    msecs = int((now % 1) * 1000)
    return "[%s,%03d]" % (s, msecs)


class CanonicalAccessLogger(GunicornColorLogger):
    """Gunicorn Logger that emits access logs in canonical format: [timestamp] [trace-id] [pod_name] [gunicorn.access] [INFO] ..."""

    def now(self):
        return _canonical_timestamp()

    def atoms(self, resp, req, environ, request_time):
        atoms = super().atoms(resp, req, environ, request_time)
        # Correlation ID: OTEL trace_id first (set by Flask so log ID = Jaeger trace ID), then headers
        cid = None
        try:
            if environ:
                cid = environ.get("OTEL_TRACE_ID")
            if not cid:
                req_headers = getattr(req, "headers", None) if hasattr(req, "headers") else None
                if req_headers is not None:
                    if hasattr(req_headers, "get"):
                        cid = req_headers.get("X-Request-ID") or req_headers.get("X-Trace-ID")
                    else:
                        cid = get_header_value(req_headers, "X-Request-ID") or get_header_value(req_headers, "X-Trace-ID")
                if not cid and environ:
                    cid = environ.get("HTTP_X_REQUEST_ID") or environ.get("HTTP_X_TRACE_ID")
        except Exception:
            pass
        atoms["correlation_id"] = cid if cid else "no-id"
        
        # Pod name: from environment variables (Kubernetes downward API)
        atoms["pod_name"] = (
            os.environ.get('POD_NAME')
            or os.environ.get('HOSTNAME')
            or os.uname().nodename
            or 'unknown'
        )
        return atoms


def get_header_value(headers, key):
    """Helper to get header value from list of tuples or dict"""
    if isinstance(headers, dict):
        return headers.get(key)
    if isinstance(headers, list):
        return next((v for k, v in headers if k.lower() == key.lower()), None)
    return None


class _CanonicalFormatter(logging.Formatter):
    """Same timestamp format as app logs: YYYY-MM-DD HH:MM:SS,mmm."""

    def formatTime(self, record, datefmt=None):
        ct = dt.fromtimestamp(record.created)
        s = ct.strftime("%Y-%m-%d %H:%M:%S")
        return "%s,%03d" % (s, record.msecs)

cert_path, key_path, ca_cert_path = generate_self_signed_cert()
# ========================
# 1. Server Configuration
# ========================
keyfile = key_path
certfile = cert_path
ca_certs = ca_cert_path
bind = "0.0.0.0:8000"
workers = 1
threads = 4
worker_tmp_dir = "/tmp/kubedash"
timeout = 120
graceful_timeout = 120
keepalive = 5

# ========================
# 2. Logging Configuration
# ========================
logger_class = CanonicalAccessLogger
loglevel = "info"
errorlog = "-"  # stderr
accesslog = "-"  # stdout
# Canonical format: [timestamp] [trace-id] [pod_name] [gunicorn.access] [INFO] method path status size ...
access_log_format = '%(t)s [%(correlation_id)s] [%(pod_name)s] [gunicorn.access] [INFO] %(h)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# ========================
# 3. Correlation ID Setup
# ========================

def pre_request(worker, req):
    """Executed before each request. Set correlation_id for access/error logs (PRD: trace ID propagation)."""
    try:
        # Trace ID from proxy: X-Request-ID or X-Trace-ID; always set for access_log_format %(correlation_id)s
        request_id = get_header_value(req.headers, 'X-Request-ID') or get_header_value(req.headers, 'X-Trace-ID')
        worker.correlation_id = request_id if request_id else 'no-id'
        worker.start_time = time.time()
        return worker.correlation_id
    except Exception as e:
        worker.correlation_id = str(uuid.uuid4())
        worker.log.error("Error in pre_request: %s", e)
        return worker.correlation_id

def post_request(worker, req, environ, resp):
    """Executed after each request."""
    try:
        # Get correlation ID from worker (set in pre_request)
        #correlation_id = getattr(worker, 'correlation_id', 'no-id')
        
        # Get status safely (resp might be None)
        status = getattr(resp, 'status', '500')
        
        #if correlation_id:
            # Log request completion
            #worker.log.info(f"Request completed | {correlation_id} | {req.method} {req.path} {status}")
        
        # Send metrics to StatsD
        statsd = StatsClient(
            host=os.getenv("STATSD_HOST", "localhost"),
            port=int(os.getenv("STATSD_PORT", "9125")),
            prefix=os.getenv("STATSD_PREFIX", "kubedash")
        )
        statsd.incr("gunicorn.requests")
        statsd.incr(f"gunicorn.request.status.{status}")
        
        if hasattr(worker, 'start_time'):
            duration = (time.time() - worker.start_time) * 1000  # Convert to ms
            statsd.timing("gunicorn.request.duration", duration)
        
        statsd.gauge("gunicorn.workers", worker.cfg.workers)
    except Exception as e:
        worker.log.error(f"Error in post_request: {str(e)}")

"""Exclude requests logging"""
class NoPing(logging.Filter):
    def filter(self, record):
        """Filter requests for /api/ping endpoint"""
        return record.getMessage().find('/api/ping') == -1

class NoHealth(logging.Filter):
    def filter(self, record):
        """Filter requests for /api/health endpoint"""
        return record.getMessage().find('/api/health') == -1

class NoMetrics(logging.Filter):
    def filter(self, record):
        """Filter requests for /api/metrics endpoint"""
        return record.getMessage().find('/metrics') == -1

class NoSocketIo(logging.Filter):
    def filter(self, record):
        """Filter requests for /socket.io endpoint"""
        return record.getMessage().find('/socket.io') == -1

class ExtensionAPIFilter(logging.Filter):
    """Filter /openapi and /apis paths - only log if not 200"""
    def filter(self, record):
        msg = record.getMessage()
        # Check if this is an /openapi or /apis request
        if '/openapi' in msg or '"/apis' in msg or ' /apis' in msg:
            # Only log if status is not 200 (look for " 200 " in the log message)
            return ' 200 ' not in msg
        # Allow all other requests
        return True

def on_starting(server):
    """Executed when Gunicorn starts."""
    # Use canonical timestamp format (YYYY-MM-DD HH:MM:SS,mmm) for error log
    pod_name = (
        os.environ.get('POD_NAME')
        or os.environ.get('HOSTNAME')
        or os.uname().nodename
        or 'unknown'
    )
    canonical = _CanonicalFormatter(
        f"[%(asctime)s] [{pod_name}] [%(process)d] [%(levelname)s] %(message)s"
    )
    try:
        for handler in getattr(server.log.error_log, "handlers", []):
            handler.setFormatter(canonical)
    except Exception:
        pass

    server.log.access_log.addFilter(NoPing())
    server.log.access_log.addFilter(NoHealth())
    server.log.access_log.addFilter(NoMetrics())
    server.log.access_log.addFilter(NoSocketIo())
    server.log.access_log.addFilter(ExtensionAPIFilter())
    
    # Initialize StatsD client
    server.statsd = StatsClient(
        host=os.getenv("STATSD_HOST", "localhost"),
        port=int(os.getenv("STATSD_PORT", "9125")),
        prefix=os.getenv("STATSD_PREFIX", "kubedash")
    )

# ========================
# 4. Register Hooks
# ========================
pre_request = pre_request
post_request = post_request
on_starting = on_starting
