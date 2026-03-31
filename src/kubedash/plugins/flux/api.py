"""
Flux API endpoints for managing FluxCD objects.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token
from .graph import build_flux_graph, get_graph_stats
from .__init__ import _fetch_all_flux_objects

##############################################################
## Blueprint Definition
##############################################################

flux_api_bp = Blueprint(
    "flux_api",
    "flux_api",
    url_prefix="/flux",
    description="Flux API endpoints - Manage FluxCD objects"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Flux Objects List
##############################################################

@flux_api_bp.route('/objects')
class FluxObjectsListResource(MethodView):
    """
    Flux objects list endpoint.
    """
    
    @flux_api_bp.response(200, description="Successfully retrieved flux objects list")
    @flux_api_bp.doc(tags=['Plugins API - Flux'])
    @login_required
    def get(self):
        """
        List all flux objects
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Dictionary of flux objects by type with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "flux-objects-list",
            attributes={
                "http.route": "/api/v1/plugins/flux/objects",
                "http.method": "GET",
                "namespace": namespace
            }
        ) if tracer else nullcontext():
            try:
                # Temporarily set ns_select for fetching
                original_ns = session.get('ns_select')
                session['ns_select'] = namespace
                
                flux_objects = _fetch_all_flux_objects(user_token)
                
                # Restore original ns_select
                if original_ns:
                    session['ns_select'] = original_ns
                else:
                    session.pop('ns_select', None)
                
                # Build graph data
                graph_data = build_flux_graph(flux_objects)
                graph_stats = get_graph_stats(graph_data)
                
                return jsonify({
                    "data": flux_objects,
                    "graph": graph_data,
                    "stats": graph_stats,
                    "metadata": {
                        "namespace": namespace,
                        "count": sum(len(objs) if objs else 0 for objs in flux_objects.values())
                    }
                })
            except Exception as e:
                logger.error(f"Error retrieving flux objects: {str(e)}")
                return jsonify({
                    "data": {},
                    "error": "InternalError",
                    "message": str(e),
                    "metadata": {
                        "namespace": namespace
                    }
                }), 500

