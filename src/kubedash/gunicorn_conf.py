import os

# Gunicorn config variables
bind = "0.0.0.0:80"
loglevel = "info"
errorlog = "-"  # stderr
accesslog = "-"  # stdout
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
worker_tmp_dir = "/tmp/kubedash"
workers = os.cpu_count() * 2 + 1
graceful_timeout = 120
timeout = 120
keepalive = 5
threads = 3
