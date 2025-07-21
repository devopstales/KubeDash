import logging
import os

from gunicorn.glogging import Logger as GunicornBaseLogger

# Gunicorn config variables
bind = "0.0.0.0:5000"
logger_class = "gunicorn_color.Logger"
loglevel = "info"
errorlog = "-"  # stderr
accesslog = "-"  # stdout
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
worker_tmp_dir = "/tmp/kubedash"
workers = 1
threads = 4
graceful_timeout = 120
timeout = 120
keepalive = 5
threads = 100

#def pre_request(worker, req):
#    if req.path == '/api/health/live':
#        return
#    elif req.path == '/api/health/ready':
#        return
#    worker.log.debug("%s %s" % (req.method, req.path))

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
    server.log.access_log.addFilter(NoPing())
    server.log.access_log.addFilter(NoHealth())
    server.log.access_log.addFilter(NoMetrics())
    server.log.access_log.addFilter(NoSocketIo())
