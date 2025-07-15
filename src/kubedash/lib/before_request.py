import time
import uuid

from flask import g, Flask, request
from lib.cache import cached_base, cached_base2
from lib.helper_functions import get_logger
from lib.prometheus import REQUEST_COUNT, REQUEST_LATENCY

##############################################################
## Helpers
##############################################################

logger = get_logger()

##############################################################

def init_before_request(app: Flask):
    SKIP_PATH = (
        '/vendor/', '/css/', 
        '/js/', '/img/', 
        '/assets/', '/api/health', 
        '/socket.io', '/metrics'
    )

    @app.before_request
    def before_request():
        path = request.path
        if any(path.startswith(p) for p in SKIP_PATH) or request.endpoint is None:
            return

        # Start timer
        g._start_time = time.time()
        
        # Get correlation ID from headers or generate new
        correlation_id = request.headers.get('X-Correlation-ID', None) #str(uuid.uuid4()))
        if correlation_id:
            g.correlation_id = correlation_id
        
        cached_base(app)
        cached_base2(app)

    @app.after_request
    def after_request(response):
        path = request.path
        
        if not any(path.startswith(p) for p in SKIP_PATH) and request.endpoint is not None:
            latency = time.time() - getattr(g, '_start_time', time.time())
            REQUEST_LATENCY.labels(endpoint=request.endpoint).observe(latency)
            REQUEST_COUNT.labels(method=request.method, endpoint=request.endpoint).inc()
            
        # Ensure correlation ID is in response headers
        if hasattr(g, 'correlation_id'):
            response.headers['X-Correlation-ID'] = g.correlation_id

        return response