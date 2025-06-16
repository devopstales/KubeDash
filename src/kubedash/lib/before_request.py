import time

from flask import g, Flask, request
from lib.cache import cached_base, cached_base2

from lib.prometheus import REQUEST_COUNT, REQUEST_LATENCY

def initbefore_request(app: Flask):

  @app.before_request
  def before_request():
      # Skip if it's a static file request
      if request.path.startswith('/vendor/'):
          return
      if request.path.startswith('/css/'):
          return
      if request.path.startswith('/js/'):
          return
      if request.path.startswith('/img/'):
          return
      if request.path.startswith('/assets/'):
          return
      if request.path.startswith('/api/'):
          return
      if request.path.startswith('/socket.io'):
          return
      if request.path.startswith('/metrics'):
          return
      # Skip 404s (i.e., unmatched routes)
      if request.endpoint is None:
          return
      
      cached_base(app)
      cached_base2(app)
      
def initbefore_request(app: Flask):
    @app.before_request
    def before_request():
        path = request.path
        skip_paths = ('/vendor/', '/css/', '/js/', '/img/', '/assets/', '/api/', '/socket.io', '/metrics')
        if any(path.startswith(p) for p in skip_paths) or request.endpoint is None:
            return

        # Start timer
        g._start_time = time.time()

        cached_base(app)
        cached_base2(app)

    @app.after_request
    def after_request(response):
        path = request.path
        skip_paths = ('/vendor/', '/css/', '/js/', '/img/', '/assets/', '/api/', '/socket.io', '/metrics')
        if not any(path.startswith(p) for p in skip_paths) and request.endpoint is not None:
            latency = time.time() - getattr(g, '_start_time', time.time())
            REQUEST_LATENCY.labels(endpoint=request.endpoint).observe(latency)
            REQUEST_COUNT.labels(method=request.method, endpoint=request.endpoint).inc()
        return response
