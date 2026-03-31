"""
External LoadBalancer API endpoints.
"""

from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger

##############################################################
## Blueprint Definition
##############################################################

external_loadbalancer_api_bp = Blueprint(
    "external_loadbalancer_api",
    "external_loadbalancer_api",
    url_prefix="/external-loadbalancer",
    description="External LoadBalancer API endpoints - Provides API access to external loadbalancer resources (MetalLB, Cilium)"
)

logger = get_logger()

##############################################################
## External LoadBalancer API Endpoints
##############################################################

@external_loadbalancer_api_bp.route('/ip-address-pools')
class ExternalLoadBalancerIPAddressPoolsResource(MethodView):
    """
    External LoadBalancer IP Address Pools endpoint.
    
    Returns a list of IP Address Pools (MetalLB or Cilium).
    """
    
    @external_loadbalancer_api_bp.response(200, description="Successfully retrieved IP address pools")
    @external_loadbalancer_api_bp.doc(tags=['Plugins API - External LoadBalancer'])
    @login_required
    def get(self):
        """
        Get IP address pools
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional, defaults to session namespace)
        
        Returns:
            dict: List of IP address pools
        """
        from plugins.external_loadbalancer.helper import ipaddresspoolTest
        
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            pools = ipaddresspoolTest(namespace)
            return jsonify({
                "data": pools,
                "metadata": {
                    "namespace": namespace,
                    "count": len(pools)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving IP address pools: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "namespace": namespace
                }
            }), 500


@external_loadbalancer_api_bp.route('/l2-advertisements')
class ExternalLoadBalancerL2AdvertisementsResource(MethodView):
    """
    External LoadBalancer L2 Advertisements endpoint.
    
    Returns a list of L2 Advertisements (MetalLB).
    """
    
    @external_loadbalancer_api_bp.response(200, description="Successfully retrieved L2 advertisements")
    @external_loadbalancer_api_bp.doc(tags=['Plugins API - External LoadBalancer'])
    @login_required
    def get(self):
        """
        Get L2 advertisements
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional, defaults to session namespace)
        
        Returns:
            dict: List of L2 advertisements
        """
        from plugins.external_loadbalancer.helper import l2advertisementsTest
        
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            advertisements = l2advertisementsTest(namespace)
            return jsonify({
                "data": advertisements,
                "metadata": {
                    "namespace": namespace,
                    "count": len(advertisements)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving L2 advertisements: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "namespace": namespace
                }
            }), 500


@external_loadbalancer_api_bp.route('/bgp-advertisements')
class ExternalLoadBalancerBGPAdvertisementsResource(MethodView):
    """
    External LoadBalancer BGP Advertisements endpoint.
    
    Returns a list of BGP Advertisements (MetalLB).
    """
    
    @external_loadbalancer_api_bp.response(200, description="Successfully retrieved BGP advertisements")
    @external_loadbalancer_api_bp.doc(tags=['Plugins API - External LoadBalancer'])
    @login_required
    def get(self):
        """
        Get BGP advertisements
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional, defaults to session namespace)
        
        Returns:
            dict: List of BGP advertisements
        """
        from plugins.external_loadbalancer.helper import bgpadvertisementsTest
        
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            advertisements = bgpadvertisementsTest(namespace)
            return jsonify({
                "data": advertisements,
                "metadata": {
                    "namespace": namespace,
                    "count": len(advertisements)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving BGP advertisements: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "namespace": namespace
                }
            }), 500


@external_loadbalancer_api_bp.route('/bgp-peers')
class ExternalLoadBalancerBGPPeersResource(MethodView):
    """
    External LoadBalancer BGP Peers endpoint.
    
    Returns a list of BGP Peers (MetalLB or Cilium).
    """
    
    @external_loadbalancer_api_bp.response(200, description="Successfully retrieved BGP peers")
    @external_loadbalancer_api_bp.doc(tags=['Plugins API - External LoadBalancer'])
    @login_required
    def get(self):
        """
        Get BGP peers
        
        Query Parameters:
            namespace (str): Kubernetes namespace (optional, defaults to session namespace)
        
        Returns:
            dict: List of BGP peers
        """
        from plugins.external_loadbalancer.helper import bgppeersTest
        
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            peers = bgppeersTest(namespace)
            return jsonify({
                "data": peers if peers else [],
                "metadata": {
                    "namespace": namespace,
                    "count": len(peers) if peers else 0
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving BGP peers: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {
                    "namespace": namespace
                }
            }), 500
