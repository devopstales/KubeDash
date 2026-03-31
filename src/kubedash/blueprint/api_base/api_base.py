"""
KubeDash REST API Blueprint

This blueprint provides the main API endpoints for KubeDash.
All endpoints are automatically documented with Swagger UI at /api/swagger-ui

API Documentation:
- Swagger UI: /api/swagger-ui
- OpenAPI Spec: /api/openapi.json
"""

from flask import g, send_from_directory, jsonify
from flask.views import MethodView
from flask_login import login_required
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
api_bp = Blueprint(
    "api",
    "api",
    url_prefix="/api",
    description="KubeDash REST API - Main API endpoints for health checks, debugging, and system information"
)
logger = get_logger()

from lib.opentelemetry import get_tracer
from opentelemetry import trace
tracer = get_tracer()

##############################################################
# Static file route for Swagger UI
##############################################################
@api_bp.route('/swagger-ui/<path:filename>')
@login_required
def swagger_ui_static(filename):
    """Serve Swagger UI static files (JS, CSS) locally under /api"""
    return send_from_directory(swagger_ui_path, filename)


##############################################################
## API ping
##############################################################

@api_bp.route('/ping')
class PingResource(MethodView):
    """
    Ping endpoint for API health check.
    
    Simple endpoint that returns a pong message to verify the API is responding.
    """
    
    @api_bp.response(200, description="API is responding", example={'message': 'pong'})
    @api_bp.doc(tags=['Health'])
    def get(self):
        """
        Ping the API
        
        Returns a simple pong message to verify the API is accessible and responding.
        This endpoint does not require authentication.
        
        Returns:
            dict: Response with pong message:
                {
                    "message": "pong"
                }
        
        Example Response:
            {
                "message": "pong"
            }
        """
        with tracer.start_as_current_span("ping-pong", 
                                        attributes={ 
                                            "http.route": "/api/ping",
                                            "http.method": "GET",
                                        }
                                    ) if tracer else nullcontext() as span:
            return {'message': 'pong'}

##############################################################
## API liveness and readiness
##############################################################

@api_bp.route('/health/live')
class LivenessResource(MethodView):
    """
    Liveness probe endpoint.
    
    Kubernetes liveness probe endpoint. Returns 200 if the application is alive.
    This endpoint does not require authentication.
    """
    
    @api_bp.response(200, description="Application is alive", example={'message': 'OK'})
    @api_bp.doc(tags=['Health'])
    def get(self):
        """
        Liveness probe
        
        Kubernetes liveness probe endpoint. Returns 200 OK if the application
        process is running. This is used by Kubernetes to determine if the
        container should be restarted.
        
        Returns:
            dict: Liveness status:
                {
                    "message": "OK"
                }
        
        Example Response:
            {
                "message": "OK"
            }
        """
        return {'message': 'OK'}, 200
    
@api_bp.route('/health/ready')
class ReadinessResource(MethodView):
    """
    Readiness probe endpoint.
    
    Kubernetes readiness probe endpoint. Checks if the application is ready
    to serve requests by verifying database, Kubernetes, and SSO connections.
    This endpoint does not require authentication.
    """
    
    @api_bp.response(200, description="Application is ready", 
                     example={
                         'database': True,
                         'oidc': True,
                         'kubernetes': True
                     })
    @api_bp.response(503, description="Application is not ready",
                     example={
                         'database': False,
                         'oidc': True,
                         'kubernetes': False
                     })
    @api_bp.doc(tags=['Health'])
    def get(self):
        """
        Readiness probe
        
        Kubernetes readiness probe endpoint. Checks if the application is ready
        to serve requests by verifying:
        - Database connection
        - Kubernetes cluster connection
        - SSO/OIDC connection (optional)
        
        Returns 200 if all checks pass, 503 if any check fails.
        
        Returns:
            dict: Readiness status with component checks:
                {
                    "database": bool,
                    "oidc": bool,
                    "kubernetes": bool
                }
        
        Example Response (Ready):
            {
                "database": true,
                "oidc": true,
                "kubernetes": true
            }
        
        Example Response (Not Ready):
            {
                "database": false,
                "oidc": true,
                "kubernetes": false
            }
        """
        code = 200
        
        database_status = connect_database()
        oidc_test, OIDC_ISSUER_URL_OLD = SSOServerTest()
        k8s_status = k8sGetClusterStatus()

        if not database_status:
            code = 503
        elif not k8s_status:
            code = 503
        #elif not oidc_test:
        #    code = 503

        return {
            'database': database_status,
            'oidc': oidc_test,
            'kubernetes': k8s_status,
        }, code
        
##############################################################
# Debug Trace endpoint
##############################################################

@api_bp.route('/debug-trace')
class DebugTraceResource(MethodView):
    """
    Debug trace endpoint.
    
    Returns OpenTelemetry trace information for debugging purposes.
    Requires authentication.
    """
    
    @api_bp.response(200, description="Successfully retrieved trace information",
                     example={
                         "flask_correlation_id": "abc123",
                         "jaeger_trace_id": "0123456789abcdef0123456789abcdef",
                         "span_id": "0123456789abcdef",
                         "trace_flags": "0x1",
                         "is_remote": False,
                         "span_attributes": {}
                     })
    @api_bp.response(400, description="No active span found",
                     example={"error": "No active span"})
    @api_bp.doc(tags=['Debug'])
    @login_required
    def get(self):
        """
        Get debug trace information
        
        Returns OpenTelemetry trace and span information for the current request.
        Useful for debugging distributed tracing issues.
        
        Returns:
            dict: Trace information including:
                - flask_correlation_id: Flask request correlation ID
                - jaeger_trace_id: OpenTelemetry trace ID
                - span_id: Current span ID
                - trace_flags: Trace flags
                - is_remote: Whether span is remote
                - span_attributes: Current span attributes
        
        Example Response:
            {
                "flask_correlation_id": "abc123",
                "jaeger_trace_id": "0123456789abcdef0123456789abcdef",
                "span_id": "0123456789abcdef",
                "trace_flags": "0x1",
                "is_remote": false,
                "span_attributes": {
                    "http.method": "GET",
                    "http.route": "/api/debug-trace"
                }
            }
        """
        current_span = trace.get_current_span()
        
        if not current_span or not current_span.get_span_context().is_valid:
            return jsonify({"error": "No active span"}), 400
        
        ctx = current_span.get_span_context()
        
        logger.info("Trigger debug-trace")
        
        return jsonify({
            "flask_correlation_id": g.correlation_id,
            "jaeger_trace_id": f"{ctx.trace_id:032x}",
            "span_id": f"{ctx.span_id:016x}",
            "trace_flags": hex(ctx.trace_flags),
            "is_remote": ctx.is_remote,
            "span_attributes": dict(current_span.attributes) if current_span.attributes else {}
        })