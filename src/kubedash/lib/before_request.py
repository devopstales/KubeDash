from flask import Flask, request
from lib.cache import cached_base, cached_base2

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