"""
Cert-Manager API endpoints.
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

cert_manager_api_bp = Blueprint(
    "cert_manager_api",
    "cert_manager_api",
    url_prefix="/cert-manager",
    description="Cert-Manager API endpoints - Provides API access to cert-manager resources"
)

logger = get_logger()

##############################################################
## Cert-Manager API Endpoints
##############################################################

@cert_manager_api_bp.route('/issuers')
class CertManagerIssuersResource(MethodView):
    """
    Cert-Manager Issuers endpoint.
    
    Returns a list of Issuers in the specified namespace.
    """
    
    @cert_manager_api_bp.response(200, description="Successfully retrieved issuers")
    @cert_manager_api_bp.doc(tags=['Plugins API - Cert-Manager'])
    @login_required
    def get(self):
        """
        Get issuers
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional, defaults to session namespace)
        
        Returns:
            dict: List of issuers
        """
        from plugins.cert_manager.functions import IssuerGet
        
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            issuers = IssuerGet(session['user_role'], user_token, namespace)
            return jsonify({
                "data": issuers,
                "metadata": {
                    "namespace": namespace,
                    "count": len(issuers)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving issuers: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "namespace": namespace
                }
            }), 500


@cert_manager_api_bp.route('/cluster-issuers')
class CertManagerClusterIssuersResource(MethodView):
    """
    Cert-Manager ClusterIssuers endpoint.
    
    Returns a list of ClusterIssuers (cluster-scoped).
    """
    
    @cert_manager_api_bp.response(200, description="Successfully retrieved cluster issuers")
    @cert_manager_api_bp.doc(tags=['Plugins API - Cert-Manager'])
    @login_required
    def get(self):
        """
        Get cluster issuers
        
        Returns:
            dict: List of cluster issuers
        """
        from plugins.cert_manager.functions import ClusterIssuerGet
        
        user_token = get_user_token(session)
        
        try:
            cluster_issuers = ClusterIssuerGet(session['user_role'], user_token)
            return jsonify({
                "data": cluster_issuers,
                "metadata": {
                    "count": len(cluster_issuers)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster issuers: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e)
            }), 500


@cert_manager_api_bp.route('/certificates')
class CertManagerCertificatesResource(MethodView):
    """
    Cert-Manager Certificates endpoint.
    
    Returns a list of Certificates in the specified namespace.
    """
    
    @cert_manager_api_bp.response(200, description="Successfully retrieved certificates")
    @cert_manager_api_bp.doc(tags=['Plugins API - Cert-Manager'])
    @login_required
    def get(self):
        """
        Get certificates
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional, defaults to session namespace)
        
        Returns:
            dict: List of certificates
        """
        from plugins.cert_manager.functions import CertificatesGet
        
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            certificates = CertificatesGet(session['user_role'], user_token, namespace)
            return jsonify({
                "data": certificates,
                "metadata": {
                    "namespace": namespace,
                    "count": len(certificates)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving certificates: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "namespace": namespace
                }
            }), 500


@cert_manager_api_bp.route('/certificate-requests')
class CertManagerCertificateRequestsResource(MethodView):
    """
    Cert-Manager CertificateRequests endpoint.
    
    Returns a list of CertificateRequests in the specified namespace.
    """
    
    @cert_manager_api_bp.response(200, description="Successfully retrieved certificate requests")
    @cert_manager_api_bp.doc(tags=['Plugins API - Cert-Manager'])
    @login_required
    def get(self):
        """
        Get certificate requests
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional, defaults to session namespace)
        
        Returns:
            dict: List of certificate requests
        """
        from plugins.cert_manager.functions import CertificateRequestsGet
        
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            certificate_requests = CertificateRequestsGet(session['user_role'], user_token, namespace)
            return jsonify({
                "data": certificate_requests,
                "metadata": {
                    "namespace": namespace,
                    "count": len(certificate_requests)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving certificate requests: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "namespace": namespace
                }
            }), 500


@cert_manager_api_bp.route('/<object_type>/<name>')
class CertManagerObjectResource(MethodView):
    """
    Cert-Manager individual object endpoint.
    
    Returns details for a specific cert-manager object (issuer, cluster-issuer, certificate, certificate-request).
    """
    
    @cert_manager_api_bp.response(200, description="Successfully retrieved object")
    @cert_manager_api_bp.response(404, description="Object not found")
    @cert_manager_api_bp.doc(tags=['Plugins API - Cert-Manager'])
    @login_required
    def get(self, object_type, name):
        """
        Get cert-manager object details
        
        Path Parameters:
            object_type (str): Type of object (issuer, cluster-issuer, certificate, certificate-request)
            name (str): Name of the object
        
        Query Parameters:
            namespace (str): Kubernetes namespace (required for issuer, certificate, certificate-request)
        
        Returns:
            dict: Object details
        """
        from plugins.cert_manager.functions import IssuerGet, ClusterIssuerGet, CertificatesGet, CertificateRequestsGet
        
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            object_data = None
            
            if object_type == 'cluster-issuer' or object_type == 'cluster_issuer':
                cluster_issuers = ClusterIssuerGet(session['user_role'], user_token)
                object_data = next((ci for ci in cluster_issuers if ci.get('name') == name), None)
            elif object_type == 'issuer':
                issuers = IssuerGet(session['user_role'], user_token, namespace)
                object_data = next((i for i in issuers if i.get('name') == name), None)
            elif object_type == 'certificate':
                certificates = CertificatesGet(session['user_role'], user_token, namespace)
                object_data = next((c for c in certificates if c.get('name') == name), None)
            elif object_type == 'certificate-request' or object_type == 'certificate_request':
                certificate_requests = CertificateRequestsGet(session['user_role'], user_token, namespace)
                object_data = next((cr for cr in certificate_requests if cr.get('name') == name), None)
            else:
                return jsonify({
                    "error": "BadRequest",
                    "message": f"Invalid object type: {object_type}"
                }), 400
            
            if not object_data:
                return jsonify({
                    "error": "NotFound",
                    "message": f"{object_type} '{name}' not found"
                }), 404
            
            return jsonify({
                "data": object_data,
                "metadata": {
                    "name": name,
                    "type": object_type,
                    "namespace": namespace if object_type != 'cluster-issuer' and object_type != 'cluster_issuer' else None
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving {object_type} {name}: {str(e)}")
            return jsonify({
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "name": name,
                    "type": object_type,
                    "namespace": namespace
                }
            }), 500
