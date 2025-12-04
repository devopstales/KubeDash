##############################################################
## Eventlet monkey patching - MUST be first!
##############################################################
import eventlet
eventlet.monkey_patch()

##############################################################
## Main Application variable for WSGI Like Gunicorn
##############################################################
from kubedash import create_app

app = create_app()
