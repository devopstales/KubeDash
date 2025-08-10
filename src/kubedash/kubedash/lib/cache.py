import time
from flask import Flask, render_template
from kubedash.lib.components import cache

from kubedash.lib.opentelemetry import get_tracer
from opentelemetry import trace
tracer = get_tracer()


##############################################################
## Cache request
##############################################################
@tracer.start_as_current_span("cache.request")
class cache_request_with_timeout:
    """
    A decorator that caches the result with OpenTelemetry instrumentation
    """
    DEFAULT_TIMEOUT = 60

    def __init__(self, timeout=None):
        self.__cache = {}
        self.__timeout = timeout or self.DEFAULT_TIMEOUT
        self.tracer = trace.get_tracer("custom.cache")

    def __call__(self, f):
        def decorator(*args, **kwargs):
            with self.tracer.start_as_current_span(f"cache_request.{f.__name__}") as span:
                key = (args, frozenset(kwargs))
                
                # Record cache check
                span.set_attributes({
                    "cache.key": str(key)[:100],  # Truncate long keys
                    "cache.timeout": self.__timeout,
                    "cache.system": "memory"
                })

                if key in self.__cache:
                    ts, result = self.__cache[key]
                    if (time.time() - ts) < self.__timeout:
                        span.set_attributes({
                            "cache.hit": True,
                            "cache.age_seconds": time.time() - ts
                        })
                        return result

                # Cache miss
                span.set_attribute("cache.hit", False)
                result = f(*args, **kwargs)
                self.__cache[key] = (time.time(), result)
                
                return result
        return decorator    

# Cache the base template (structure/layout only)
@tracer.start_as_current_span("cache.base_template")
@cache.cached(key_prefix='page.base2')
def cached_base2(app: Flask):
    tracer = trace.get_tracer("template.cache")
    with tracer.start_as_current_span("render.base2"):
        with app.app_context():
            with app.test_request_context():
                return render_template('base2.html.j2')

@tracer.start_as_current_span("cache.base_template")
@cache.cached(key_prefix='page.base')
def cached_base(app: Flask):
    tracer = trace.get_tracer("template.cache")
    with tracer.start_as_current_span("render.base"):
        with app.app_context():
            with app.test_request_context():
                return render_template('base.html.j2')

# Dynamic Home Page will uses the cached base template through inheritance