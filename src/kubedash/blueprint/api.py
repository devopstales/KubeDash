from flask import send_from_directory
from flask.views import MethodView
from flask_smorest import Blueprint
from contextlib import nullcontext
from swagger_ui_bundle import swagger_ui_path

from lib.helper_functions import get_logger
from lib.init_functions import connect_database
from lib.k8s.server import k8sGetClusterStatus
from lib.opentelemetry import tracer
from lib.sso import SSOServerTest

##############################################################
## Helpers
##############################################################

"""api Api Blueprint"""
api_bp = Blueprint("api", "api", url_prefix="/api")
logger = get_logger()

##############################################################
# Static file route for Swagger UI
##############################################################
@api_bp.route('/swagger-ui/<path:filename>')
def swagger_ui_static(filename):
    """Serve Swagger UI static files (JS, CSS) locally under /api"""
    return send_from_directory(swagger_ui_path, filename)


##############################################################
## API ping
##############################################################

@api_bp.route('/ping')
class PingResource(MethodView):
    @api_bp.response(200)
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

@api_bp.route('/health/live')
class livenessResource(MethodView):
    @api_bp.response(200)
    def get(self):
        """
        Liveness probe api endpoint: /api/health/live
        """
        return {'message': 'OK'}, 200
    
@api_bp.route('/health/ready')
class readinessResource(MethodView):
    @api_bp.response(200)
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