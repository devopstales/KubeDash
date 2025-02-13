import os

# Gunicorn config variables
bind = "0.0.0.0:8000"
loglevel = "info"
errorlog = "-"  # stderr
accesslog = "-"  # stdout
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
worker_tmp_dir = "/tmp/kubedash"
workers = 1
graceful_timeout = 120
timeout = 120
keepalive = 5
threads = 100

def pre_request(worker, req):
    if req.path == '/api/health/live':
        return
    elif req.path == '/api/health/ready':
        return
    worker.log.debug("%s %s" % (req.method, req.path))
