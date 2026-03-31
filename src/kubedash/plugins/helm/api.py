"""
Helm Charts API endpoints for managing Helm releases.
"""

from contextlib import nullcontext
from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer
from lib.sso import get_user_token
from .functions import k8sHelmChartListGet, k8sHelmChartReleaseGet

##############################################################
## Blueprint Definition
##############################################################

helm_api_bp = Blueprint(
    "helm_api",
    "helm_api",
    url_prefix="/helm",
    description="Helm Charts API endpoints - Manage Helm releases"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Helm Charts List
##############################################################

@helm_api_bp.route('/charts')
class HelmChartsListResource(MethodView):
    """
    Helm charts list endpoint.
    """
    
    @helm_api_bp.response(200, description="Successfully retrieved helm charts list")
    @helm_api_bp.doc(tags=['Plugins API - Helm'])
    @login_required
    def get(self):
        """
        List helm charts
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: List of helm charts with metadata
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "helm-charts-list",
            attributes={
                "http.route": "/api/v1/plugins/helm/charts",
                "http.method": "GET",
                "namespace": namespace
            }
        ) if tracer else nullcontext():
            try:
                has_chart, chart_list = k8sHelmChartListGet(session['user_role'], user_token, namespace)
                
                # Convert chart_list dict to a list format for easier consumption
                charts_data = []
                for release_name, releases in chart_list.items():
                    for release in releases:
                        charts_data.append({
                            'release_name': release_name,
                            'icon': release.get('icon'),
                            'status': release.get('status'),
                            'chart_name': release.get('chart_name'),
                            'chart_version': release.get('chart_version'),
                            'app_version': release.get('app_version'),
                            'release_version': release.get('release_version'),
                            'updated': release.get('updated')
                        })
                
                return jsonify({
                    "data": charts_data,
                    "metadata": {
                        "namespace": namespace,
                        "count": len(charts_data),
                        "has_chart": has_chart
                    }
                })
            except Exception as e:
                logger.error(f"Error retrieving helm charts: {str(e)}")
                return jsonify({
                    "data": [],
                    "error": "InternalError",
                    "message": str(e),
                    "metadata": {
                        "namespace": namespace,
                        "has_chart": False
                    }
                }), 500


##############################################################
## Helm Chart Data
##############################################################

@helm_api_bp.route('/charts/<release_name>/<int:release_version>/data')
class HelmChartDataResource(MethodView):
    """
    Helm chart data endpoint.
    """
    
    @helm_api_bp.response(200, description="Successfully retrieved helm chart data")
    @helm_api_bp.doc(tags=['Plugins API - Helm'])
    @login_required
    def get(self, release_name, release_version):
        """
        Get helm chart data
        
        Path Parameters:
            release_name (str): Helm release name
            release_version (int): Helm release version
        
        Query Parameters:
            namespace (str): Kubernetes namespace (default: from session)
        
        Returns:
            dict: Helm chart data
        """
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        with tracer.start_as_current_span(
            "helm-chart-data",
            attributes={
                "http.route": "/api/v1/plugins/helm/charts/<release_name>/<release_version>/data",
                "http.method": "GET",
                "namespace": namespace,
                "release_name": release_name,
                "release_version": str(release_version)
            }
        ) if tracer else nullcontext():
            try:
                chart_data = k8sHelmChartReleaseGet(
                    session['user_role'],
                    user_token,
                    namespace,
                    release_name,
                    release_version
                )
                
                if chart_data:
                    return jsonify({
                        "data": chart_data,
                        "metadata": {
                            "namespace": namespace,
                            "release_name": release_name,
                            "release_version": release_version
                        }
                    })
                else:
                    return jsonify({
                        "data": None,
                        "error": "NotFound",
                        "message": f"Helm chart {release_name} version {release_version} not found",
                        "metadata": {
                            "namespace": namespace,
                            "release_name": release_name,
                            "release_version": release_version
                        }
                    }), 404
            except Exception as e:
                logger.error(f"Error retrieving helm chart data: {str(e)}")
                return jsonify({
                    "data": None,
                    "error": "InternalError",
                    "message": str(e),
                    "metadata": {
                        "namespace": namespace,
                        "release_name": release_name,
                        "release_version": release_version
                    }
                }), 500

