import time
from flask import Flask, render_template
from lib.components import cache

##############################################################
## Cache request
##############################################################

class cache_request_with_timeout:
    """
    A decorator that caches the result of a function for a specified timeout.
    """
    DEFAULT_TIMEOUT = 60

    def __init__(self, timeout=None):
        self.__cache = {}
        self.__timeout = timeout

    def __call__(self, f):
        def decorator(*args, **kwargs):
            timeout = self.__timeout or cache_request_with_timeout.DEFAULT_TIMEOUT
            key = (args, frozenset(kwargs))

            if key in self.__cache:
                ts, result = self.__cache[key]
                if (time.time() - ts) < timeout:
                    return result

            result = f(*args, **kwargs)
            self.__cache[key] = (time.time(), result)

            return result
        return decorator
    

# Cache the base template (structure/layout only)
@cache.cached(key_prefix='base2')
def cached_base2(app: Flask):
    with app.app_context():
        with app.test_request_context():
            return render_template('base2.html.j2')
        
@cache.cached(key_prefix='base')
def cached_base(app: Flask):
    with app.app_context():
        with app.test_request_context():
            return render_template('base.html.j2')

# Dynamic Home Page will uses the cached base template through inheritance