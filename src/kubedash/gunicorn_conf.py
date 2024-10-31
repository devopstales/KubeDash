import os

# Gunicorn config variables
bind = "127.0.0.1:8000"
loglevel = "info"
errorlog = "-"  # stderr
accesslog = "-"  # stdout
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
worker_tmp_dir = "/tmp/kubedash"
workers = 4
graceful_timeout = 120
timeout = 120
keepalive = 5
threads = 3
