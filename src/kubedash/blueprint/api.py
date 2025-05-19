from flask import send_from_directory
from flask_smorest import Blueprint
from contextlib import nullcontext
import swagger_ui_bundle

from lib.init_functions import connect_database
from lib.sso import SSOServerTest
from lib.k8s.server import k8sGetClusterStatus

from lib.helper_functions import get_logger
from lib.opentelemetry import tracer

##############################################################
## Helpers
##############################################################

"""api Api Blueprint"""
api = Blueprint("api", "api", url_prefix="/api", description="API endpoints")
logger = get_logger()

##############################################################
# Static file route for Swagger UI
##############################################################
@api.route('/swagger-ui/<path:filename>')
def swagger_ui_static(filename):
    """Serve Swagger UI static files (JS, CSS) locally under /api"""
    return send_from_directory(swagger_ui_bundle.dist_path, filename)


##############################################################
## API ping
##############################################################

@api.route('/ping')
class PingResource:
    @api.response(200)
    def get(self):
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

@api.route('/health/live')
class livenessResource:
    @api.response(200)
    def get(self):
        """
        Liveness probe api endpoint: /api/health/live
        """
        return {'message': 'OK'}, 200
    
@api.route('/health/ready')
class readinessResource:
    @api.response(200)
    def get(self):
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