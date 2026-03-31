"""
Gateway API endpoints.
"""

from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.sso import get_user_token

##############################################################
## Blueprint Definition
##############################################################

gateway_api_api_bp = Blueprint(
    "gateway_api_api",
    "gateway_api_api",
    url_prefix="/gateway-api",
    description="Gateway API endpoints - Provides API access to Gateway API resources"
)
# Note: This blueprint is registered under /plugins prefix in initialize_plugin_apis()
# Final URL will be: /api/v1/plugins/gateway-api/...

logger = get_logger()

##############################################################
## Gateway API Endpoints
##############################################################

@gateway_api_api_bp.route('/gateway-classes')
class GatewayAPIGatewayClassesResource(MethodView):
    """
    Gateway API GatewayClasses endpoint.
    
    Returns a list of GatewayClasses (cluster-scoped).
    """
    
    @gateway_api_api_bp.response(200, description="Successfully retrieved gateway classes")
    @gateway_api_api_bp.doc(tags=['Plugins API - Gateway API'])
    @login_required
    def get(self):
        """
        Get gateway classes
        
        Returns:
            dict: List of gateway classes
        """
        from plugins.gateway_api.functions import GatewayApiGetGatewayClasses
        
        user_token = get_user_token(session)
        
        try:
            gateway_classes = GatewayApiGetGatewayClasses(session['user_role'], user_token)
            return jsonify({
                "data": gateway_classes,
                "metadata": {
                    "count": len(gateway_classes)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving gateway classes: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e)
            }), 500


@gateway_api_api_bp.route('/gateways')
class GatewayAPIGatewaysResource(MethodView):
    """
    Gateway API Gateways endpoint.
    
    Returns a list of Gateways in the specified namespace.
    """
    
    @gateway_api_api_bp.response(200, description="Successfully retrieved gateways")
    @gateway_api_api_bp.doc(tags=['Plugins API - Gateway API'])
    @login_required
    def get(self):
        """
        Get gateways
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional, defaults to session namespace)
        
        Returns:
            dict: List of gateways
        """
        from plugins.gateway_api.functions import GatewayApiGetGateways
        
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            gateways = GatewayApiGetGateways(session['user_role'], user_token, namespace)
            return jsonify({
                "data": gateways,
                "metadata": {
                    "namespace": namespace,
                    "count": len(gateways)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving gateways: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "namespace": namespace
                }
            }), 500


@gateway_api_api_bp.route('/httproutes')
class GatewayAPIHTTPRoutesResource(MethodView):
    """
    Gateway API HTTPRoutes endpoint.
    
    Returns a list of HTTPRoutes in the specified namespace.
    """
    
    @gateway_api_api_bp.response(200, description="Successfully retrieved HTTP routes")
    @gateway_api_api_bp.doc(tags=['Plugins API - Gateway API'])
    @login_required
    def get(self):
        """
        Get HTTP routes
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional, defaults to session namespace)
        
        Returns:
            dict: List of HTTP routes
        """
        from plugins.gateway_api.functions import GatewayApiGetHTTPRoutes
        
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            httproutes = GatewayApiGetHTTPRoutes(session['user_role'], user_token, namespace)
            return jsonify({
                "data": httproutes,
                "metadata": {
                    "namespace": namespace,
                    "count": len(httproutes)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving HTTP routes: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "namespace": namespace
                }
            }), 500


@gateway_api_api_bp.route('/grpcroutes')
class GatewayAPIGRPCRoutesResource(MethodView):
    """Gateway API GRPCRoutes endpoint."""
    @gateway_api_api_bp.response(200, description="Successfully retrieved GRPC routes")
    @gateway_api_api_bp.doc(tags=['Plugins API - Gateway API'])
    @login_required
    def get(self):
        from plugins.gateway_api.functions import GatewayApiGetGRPCRoutes
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        try:
            grpcroutes = GatewayApiGetGRPCRoutes(session['user_role'], user_token, namespace)
            return jsonify({"data": grpcroutes, "metadata": {"namespace": namespace, "count": len(grpcroutes)}})
        except Exception as e:
            logger.error(f"Error retrieving GRPC routes: {str(e)}")
            return jsonify({"data": [], "error": "InternalError", "message": str(e), "metadata": {"namespace": namespace}}), 500


@gateway_api_api_bp.route('/tcproutes')
class GatewayAPITCPRoutesResource(MethodView):
    """Gateway API TCPRoutes endpoint."""
    @gateway_api_api_bp.response(200, description="Successfully retrieved TCP routes")
    @gateway_api_api_bp.doc(tags=['Plugins API - Gateway API'])
    @login_required
    def get(self):
        from plugins.gateway_api.functions import GatewayApiGetTCPRoutes
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        try:
            tcproutes = GatewayApiGetTCPRoutes(session['user_role'], user_token, namespace)
            return jsonify({"data": tcproutes, "metadata": {"namespace": namespace, "count": len(tcproutes)}})
        except Exception as e:
            logger.error(f"Error retrieving TCP routes: {str(e)}")
            return jsonify({"data": [], "error": "InternalError", "message": str(e), "metadata": {"namespace": namespace}}), 500


@gateway_api_api_bp.route('/tlsroutes')
class GatewayAPITLSRoutesResource(MethodView):
    """Gateway API TLSRoutes endpoint."""
    @gateway_api_api_bp.response(200, description="Successfully retrieved TLS routes")
    @gateway_api_api_bp.doc(tags=['Plugins API - Gateway API'])
    @login_required
    def get(self):
        from plugins.gateway_api.functions import GatewayApiGetTLSRoutes
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        try:
            tlsroutes = GatewayApiGetTLSRoutes(session['user_role'], user_token, namespace)
            return jsonify({"data": tlsroutes, "metadata": {"namespace": namespace, "count": len(tlsroutes)}})
        except Exception as e:
            logger.error(f"Error retrieving TLS routes: {str(e)}")
            return jsonify({"data": [], "error": "InternalError", "message": str(e), "metadata": {"namespace": namespace}}), 500


@gateway_api_api_bp.route('/reference-grants')
class GatewayAPIReferenceGrantsResource(MethodView):
    """Gateway API ReferenceGrants endpoint."""
    @gateway_api_api_bp.response(200, description="Successfully retrieved reference grants")
    @gateway_api_api_bp.doc(tags=['Plugins API - Gateway API'])
    @login_required
    def get(self):
        from plugins.gateway_api.functions import GatewayApiGetReferenceGrants
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        try:
            referencegrants = GatewayApiGetReferenceGrants(session['user_role'], user_token, namespace)
            return jsonify({"data": referencegrants, "metadata": {"namespace": namespace, "count": len(referencegrants)}})
        except Exception as e:
            logger.error(f"Error retrieving reference grants: {str(e)}")
            return jsonify({"data": [], "error": "InternalError", "message": str(e), "metadata": {"namespace": namespace}}), 500


@gateway_api_api_bp.route('/backend-tls-policies')
class GatewayAPIBackendTLSPoliciesResource(MethodView):
    """Gateway API BackendTLSPolicies endpoint."""
    @gateway_api_api_bp.response(200, description="Successfully retrieved backend TLS policies")
    @gateway_api_api_bp.doc(tags=['Plugins API - Gateway API'])
    @login_required
    def get(self):
        from plugins.gateway_api.functions import GatewayApiGetBackendTLSPolicies
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        try:
            backendtlspolicies = GatewayApiGetBackendTLSPolicies(session['user_role'], user_token, namespace)
            return jsonify({"data": backendtlspolicies, "metadata": {"namespace": namespace, "count": len(backendtlspolicies)}})
        except Exception as e:
            logger.error(f"Error retrieving backend TLS policies: {str(e)}")
            return jsonify({"data": [], "error": "InternalError", "message": str(e), "metadata": {"namespace": namespace}}), 500


@gateway_api_api_bp.route('/status')
class GatewayAPIStatusResource(MethodView):
    """Gateway API installation status endpoint."""
    @gateway_api_api_bp.response(200, description="Successfully retrieved Gateway API status")
    @gateway_api_api_bp.doc(tags=['Plugins API - Gateway API'])
    @login_required
    def get(self):
        from plugins.gateway_api.functions import check_gateway_api_installed
        user_token = get_user_token(session)
        try:
            status = check_gateway_api_installed(session['user_role'], user_token)
            return jsonify({"data": status, "metadata": {}})
        except Exception as e:
            logger.error(f"Error checking Gateway API status: {str(e)}")
            return jsonify({"data": {"installed": False}, "error": "InternalError", "message": str(e)}), 500
