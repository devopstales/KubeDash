from flask import Blueprint
from contextlib import nullcontext
from flask_healthz import HealthError
from flask_swagger_ui import get_swaggerui_blueprint

from lib_functions.init_functions import connect_database
from lib_functions.helper_functions import get_logger
from lib_functions.opentelemetry import tracer

##############################################################
## Helpers
##############################################################

api = Blueprint("api", __name__)
logger = get_logger()

##############################################################
## API
##############################################################

swaggerui_blueprint = get_swaggerui_blueprint(
    base_url = '/api',
    api_url  = '/static/swagger.json',
    config   = {
        'app_name': "Kubedash"
    },
)

##############################################################
## API ping
##############################################################

@api.route('/api/ping', methods=['GET'])
def ping():
    """Simple ping Api endpoint"""
    with tracer.start_as_current_span("ping-pong", 
                                        attributes={ 
                                            "http.route": "/api/ping",
                                            "http.method": "GET",
                                        }
                                    ) if tracer else nullcontext() as span:
        return 'pong'
    
##############################################################
## Liveness and redyes probe
##############################################################

def liveness():
    """
    Liveness probe api endpoint: /api/health/live
    """
    pass

def readiness():
    """
    Rediness probe api endpoint: /api/health/ready
    
    Checks
    -----
    - Check if the application is ready to serve requests
    - Check database connection

    Raises
    ------
        any : HealthError
    """
    try:
        connect_database()
    except Exception:
        raise HealthError("Can't connect to the database")
    # test k8s connection
    # test sso connection
