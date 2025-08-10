from kubedash import create_app

##############################################################
## Main Application variable for WSGI Like Gunicorn
##############################################################
app = create_app()

##############################################################
import atexit
import logging
##############################################################
@atexit.register
def shutdown_logging():
    logging.shutdown()
