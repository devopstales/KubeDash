import time
import uuid

from flask import g, Flask, request
from lib.cache import cached_base, cached_base2
from lib.helper_functions import get_logger
from lib.prometheus import REQUEST_COUNT, REQUEST_LATENCY
from lib.components import db

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
    
    # Paths to skip page caching (API endpoints don't need base templates)
    SKIP_PAGE_CACHE_PATH = (
        '/openapi', '/apis'
    )

    @app.before_request
    def before_request():
        path = request.path
        if any(path.startswith(p) for p in SKIP_PATH) or request.endpoint is None:
            return

        # Start timer
        g._start_time = time.time()
        
        # Get request ID from headers (standard X-Request-ID header from ingress)
        request_id = request.headers.get('X-Request-ID', None)
        if request_id:
            g.correlation_id = request_id
        
        # Skip page cache for API paths (they don't use HTML templates)
        if not any(path.startswith(p) for p in SKIP_PAGE_CACHE_PATH):
            cached_base(app)
            cached_base2(app)

    @app.after_request
    def after_request(response):
        path = request.path
        
        if not any(path.startswith(p) for p in SKIP_PATH) and request.endpoint is not None:
            # For /openapi and /apis paths, only log if response is not 200
            if any(path.startswith(p) for p in SKIP_PAGE_CACHE_PATH):
                if response.status_code != 200:
                    latency = time.time() - getattr(g, '_start_time', time.time())
                    REQUEST_LATENCY.labels(endpoint=request.endpoint).observe(latency)
                    REQUEST_COUNT.labels(method=request.method, endpoint=request.endpoint).inc()
                    logger.warning(f"Extension API request failed: {request.method} {path} - {response.status_code}")
            else:
                latency = time.time() - getattr(g, '_start_time', time.time())
                REQUEST_LATENCY.labels(endpoint=request.endpoint).observe(latency)
                REQUEST_COUNT.labels(method=request.method, endpoint=request.endpoint).inc()
            
        # Ensure request ID is in response headers
        if hasattr(g, 'correlation_id'):
            response.headers['X-Request-ID'] = g.correlation_id

        return response
    
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        """Remove database session after each request to prevent connection leaks"""
        db.session.remove()