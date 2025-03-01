from flask import Blueprint
from contextlib import nullcontext

from lib.init_functions import connect_database
from lib.sso import SSOServerTest
from lib.k8s.server import k8sGetClusterStatus

from lib.helper_functions import get_logger
from lib.opentelemetry import tracer

##############################################################
## Helpers
##############################################################

"""api Api Blueprint"""
api = Blueprint("api", __name__, url_prefix="/api")
logger = get_logger()

##############################################################
## API ping
##############################################################

@api.get('/ping')
def ping():
    """Just Say Pong

    It will always return a greeting like this:
    ```
    {'message': 'pong'}
    ```
    """
    with tracer.start_as_current_span("ping-pong", 
                                        attributes={ 
                                            "http.route": "/api/ping",
                                            "http.method": "GET",
                                        }
                                    ) if tracer else nullcontext() as span:
        return {'message': 'pong'}

##############################################################
## API liveness rediness
##############################################################

@api.get('/health/live')
def liveness():
    """
    Liveness probe api endpoint: /api/health/live
    """
    return {'message': 'OK'}, 200
    
@api.get('/health/ready')
def readiness():
    """
    Rediness probe api endpoint: /api/api/ready
    
    Checks
    -----
    - Check if the application is ready to serve requests
    - Check database connection
    - Check K8S connection
    - Check SSO connection

    Raises
    ------
        any : apiError
    """
    code = 200
    
    database_status = connect_database()
    oidc_test, OIDC_ISSUER_URL_OLD = SSOServerTest()
    k8s_status = k8sGetClusterStatus()

    if not database_status:
        code = 503
    elif not oidc_test:
        code = 503
    elif not k8s_status:
        code = 503

    return {
        'database': database_status,
        'oidc': oidc_test,
        'kubernetes': k8s_status,
    }, code