#import eventlet
#eventlet.monkey_patch()
from gevent import monkey
monkey.patch_all()

import logging
import os
import uuid
import time
from statsd import StatsClient

from gunicorn.glogging import Logger as GunicornBaseLogger
from kubedash.lib.cert_utils import generate_self_signed_cert

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
logger_class = "gunicorn_color.Logger"
loglevel = "info"
errorlog = "-"  # stderr
accesslog = "-"  # stdout
access_log_format = '[%(asctime)s] [%(correlation_id)s] %(h)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# ========================
# 3. Correlation ID Setup
# ========================

def get_header_value(headers, key):
    """Helper to get header value from list of tuples or dict"""
    if isinstance(headers, dict):
        return headers.get(key)
    if isinstance(headers, list):
        return next((v for k, v in headers if k.lower() == key.lower()), None)
    return None

def pre_request(worker, req):
    """Executed before each request."""
    try:
        # Get correlation ID from headers or generate new
        correlation_id = get_header_value(req.headers, 'X-Correlation-ID') or None #str(uuid.uuid4())
        
        if correlation_id:
            # Store in worker environment
            worker.correlation_id = correlation_id   
            # Log the request start
            #worker.log.info(f"Request started | {correlation_id} | {req.method} {req.path}")
        
        # Store start time for duration calculation
        worker.start_time = time.time()
        
        return correlation_id
    except Exception as e:
        worker.log.error(f"Error in pre_request: {str(e)}")
        return str(uuid.uuid4())  # Fallback ID

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

def on_starting(server):
    """Executed when Gunicorn starts."""
    server.log.access_log.addFilter(NoPing())
    server.log.access_log.addFilter(NoHealth())
    server.log.access_log.addFilter(NoMetrics())
    server.log.access_log.addFilter(NoSocketIo())
    
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