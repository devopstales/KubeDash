"""
Trivy Operator API endpoints.
"""

from flask import jsonify, request, session
from flask.views import MethodView
from flask_login import login_required
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.sso import get_user_token

from .functions import (
    check_trivy_operator_installed,
    TrivyGetVulnerabilityReports,
    TrivyGetVulnerabilityReport,
    TrivyGetConfigAuditReports,
    TrivyGetConfigAuditReport,
    TrivyGetExposedSecretReports,
    TrivyGetExposedSecretReport,
    TrivyGetRbacAssessmentReports,
    TrivyGetRbacAssessmentReport,
    TrivyGetSbomReports,
    TrivyGetSbomReport,
    TrivyGetInfraAssessmentReports,
    TrivyGetInfraAssessmentReport,
    TrivyGetClusterComplianceReports,
    TrivyGetClusterComplianceReport,
    TrivyGetClusterVulnerabilityReports,
    TrivyGetClusterVulnerabilityReport,
    TrivyGetClusterConfigAuditReports,
    TrivyGetClusterConfigAuditReport,
    TrivyGetClusterInfraAssessmentReports,
    TrivyGetClusterInfraAssessmentReport,
    TrivyGetClusterRbacAssessmentReports,
    TrivyGetClusterRbacAssessmentReport,
    TrivyGetEvents,
)

##############################################################
## Blueprint Definition
##############################################################

trivy_operator_api_bp = Blueprint(
    "trivy_operator_api",
    "trivy_operator_api",
    url_prefix="/trivy-operator",
    description="Trivy Operator API endpoints - Provides API access to Trivy Operator security reports"
)

logger = get_logger()

##############################################################
## Trivy Operator Status Endpoint
##############################################################

@trivy_operator_api_bp.route('/status')
class TrivyOperatorStatusResource(MethodView):
    """
    Trivy Operator status endpoint.
    
    Returns the installation status and detected API group/version.
    """
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved Trivy Operator status")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """
        Get Trivy Operator status
        
        Returns:
            dict: Status information including installed flag and API group/version
        """
        user_token = get_user_token(session)
        
        try:
            status = check_trivy_operator_installed(session['user_role'], user_token)
            return jsonify({
                "data": status,
                "metadata": {}
            })
        except Exception as e:
            logger.error(f"Error retrieving Trivy Operator status: {str(e)}")
            return jsonify({
                "data": {"installed": False},
                "error": "InternalError",
                "message": str(e),
                "metadata": {}
            }), 500

##############################################################
## Namespace-scoped Report Endpoints
##############################################################

@trivy_operator_api_bp.route('/vulnerability-reports')
class TrivyOperatorVulnerabilityReportsResource(MethodView):
    """VulnerabilityReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved vulnerability reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get vulnerability reports"""
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            reports = TrivyGetVulnerabilityReports(session['user_role'], user_token, namespace)
            return jsonify({
                "data": reports,
                "metadata": {
                    "namespace": namespace,
                    "count": len(reports)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving vulnerability reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace}
            }), 500


@trivy_operator_api_bp.route('/vulnerability-reports/<namespace>/<name>')
class TrivyOperatorVulnerabilityReportResource(MethodView):
    """VulnerabilityReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved vulnerability report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, namespace, name):
        """Get a specific vulnerability report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetVulnerabilityReport(session['user_role'], user_token, namespace, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"VulnerabilityReport {namespace}/{name} not found",
                    "metadata": {"namespace": namespace, "name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('VulnerabilityReport', name, namespace, session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"namespace": namespace, "name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving vulnerability report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace, "name": name}
            }), 500


@trivy_operator_api_bp.route('/config-audit-reports')
class TrivyOperatorConfigAuditReportsResource(MethodView):
    """ConfigAuditReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved config audit reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get config audit reports"""
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            reports = TrivyGetConfigAuditReports(session['user_role'], user_token, namespace)
            return jsonify({
                "data": reports,
                "metadata": {
                    "namespace": namespace,
                    "count": len(reports)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving config audit reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace}
            }), 500


@trivy_operator_api_bp.route('/config-audit-reports/<namespace>/<name>')
class TrivyOperatorConfigAuditReportResource(MethodView):
    """ConfigAuditReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved config audit report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, namespace, name):
        """Get a specific config audit report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetConfigAuditReport(session['user_role'], user_token, namespace, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"ConfigAuditReport {namespace}/{name} not found",
                    "metadata": {"namespace": namespace, "name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('ConfigAuditReport', name, namespace, session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"namespace": namespace, "name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving config audit report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace, "name": name}
            }), 500


@trivy_operator_api_bp.route('/exposed-secret-reports')
class TrivyOperatorExposedSecretReportsResource(MethodView):
    """ExposedSecretReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved exposed secret reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get exposed secret reports"""
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            reports = TrivyGetExposedSecretReports(session['user_role'], user_token, namespace)
            return jsonify({
                "data": reports,
                "metadata": {
                    "namespace": namespace,
                    "count": len(reports)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving exposed secret reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace}
            }), 500


@trivy_operator_api_bp.route('/exposed-secret-reports/<namespace>/<name>')
class TrivyOperatorExposedSecretReportResource(MethodView):
    """ExposedSecretReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved exposed secret report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, namespace, name):
        """Get a specific exposed secret report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetExposedSecretReport(session['user_role'], user_token, namespace, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"ExposedSecretReport {namespace}/{name} not found",
                    "metadata": {"namespace": namespace, "name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('ExposedSecretReport', name, namespace, session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"namespace": namespace, "name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving exposed secret report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace, "name": name}
            }), 500


@trivy_operator_api_bp.route('/rbac-assessment-reports')
class TrivyOperatorRbacAssessmentReportsResource(MethodView):
    """RbacAssessmentReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved RBAC assessment reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get RBAC assessment reports"""
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            reports = TrivyGetRbacAssessmentReports(session['user_role'], user_token, namespace)
            return jsonify({
                "data": reports,
                "metadata": {
                    "namespace": namespace,
                    "count": len(reports)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving RBAC assessment reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace}
            }), 500


@trivy_operator_api_bp.route('/rbac-assessment-reports/<namespace>/<name>')
class TrivyOperatorRbacAssessmentReportResource(MethodView):
    """RbacAssessmentReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved RBAC assessment report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, namespace, name):
        """Get a specific RBAC assessment report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetRbacAssessmentReport(session['user_role'], user_token, namespace, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"RbacAssessmentReport {namespace}/{name} not found",
                    "metadata": {"namespace": namespace, "name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('RbacAssessmentReport', name, namespace, session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"namespace": namespace, "name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving RBAC assessment report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace, "name": name}
            }), 500


@trivy_operator_api_bp.route('/sbom-reports')
class TrivyOperatorSbomReportsResource(MethodView):
    """SbomReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved SBOM reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get SBOM reports"""
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            reports = TrivyGetSbomReports(session['user_role'], user_token, namespace)
            return jsonify({
                "data": reports,
                "metadata": {
                    "namespace": namespace,
                    "count": len(reports)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving SBOM reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace}
            }), 500


@trivy_operator_api_bp.route('/sbom-reports/<namespace>/<name>')
class TrivyOperatorSbomReportResource(MethodView):
    """SbomReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved SBOM report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, namespace, name):
        """Get a specific SBOM report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetSbomReport(session['user_role'], user_token, namespace, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"SbomReport {namespace}/{name} not found",
                    "metadata": {"namespace": namespace, "name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('SbomReport', name, namespace, session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"namespace": namespace, "name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving SBOM report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace, "name": name}
            }), 500


@trivy_operator_api_bp.route('/infra-assessment-reports')
class TrivyOperatorInfraAssessmentReportsResource(MethodView):
    """InfraAssessmentReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved infra assessment reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get infra assessment reports"""
        user_token = get_user_token(session)
        namespace = request.args.get('namespace', session.get('ns_select', 'default'))
        
        try:
            reports = TrivyGetInfraAssessmentReports(session['user_role'], user_token, namespace)
            return jsonify({
                "data": reports,
                "metadata": {
                    "namespace": namespace,
                    "count": len(reports)
                }
            })
        except Exception as e:
            logger.error(f"Error retrieving infra assessment reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace}
            }), 500


@trivy_operator_api_bp.route('/infra-assessment-reports/<namespace>/<name>')
class TrivyOperatorInfraAssessmentReportResource(MethodView):
    """InfraAssessmentReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved infra assessment report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, namespace, name):
        """Get a specific infra assessment report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetInfraAssessmentReport(session['user_role'], user_token, namespace, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"InfraAssessmentReport {namespace}/{name} not found",
                    "metadata": {"namespace": namespace, "name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('InfraAssessmentReport', name, namespace, session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"namespace": namespace, "name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving infra assessment report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"namespace": namespace, "name": name}
            }), 500

##############################################################
## Cluster-scoped Report Endpoints
##############################################################

@trivy_operator_api_bp.route('/cluster/compliance-reports')
class TrivyOperatorClusterComplianceReportsResource(MethodView):
    """ClusterComplianceReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster compliance reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get cluster compliance reports"""
        user_token = get_user_token(session)
        
        try:
            reports = TrivyGetClusterComplianceReports(session['user_role'], user_token)
            return jsonify({
                "data": reports,
                "metadata": {"count": len(reports)}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster compliance reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {}
            }), 500


@trivy_operator_api_bp.route('/cluster/compliance-reports/<name>')
class TrivyOperatorClusterComplianceReportResource(MethodView):
    """ClusterComplianceReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster compliance report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, name):
        """Get a specific cluster compliance report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetClusterComplianceReport(session['user_role'], user_token, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"ClusterComplianceReport {name} not found",
                    "metadata": {"name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('ClusterComplianceReport', name, '', session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster compliance report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"name": name}
            }), 500


@trivy_operator_api_bp.route('/cluster/vulnerability-reports')
class TrivyOperatorClusterVulnerabilityReportsResource(MethodView):
    """ClusterVulnerabilityReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster vulnerability reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get cluster vulnerability reports"""
        user_token = get_user_token(session)
        
        try:
            reports = TrivyGetClusterVulnerabilityReports(session['user_role'], user_token)
            return jsonify({
                "data": reports,
                "metadata": {"count": len(reports)}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster vulnerability reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {}
            }), 500


@trivy_operator_api_bp.route('/cluster/vulnerability-reports/<name>')
class TrivyOperatorClusterVulnerabilityReportResource(MethodView):
    """ClusterVulnerabilityReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster vulnerability report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, name):
        """Get a specific cluster vulnerability report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetClusterVulnerabilityReport(session['user_role'], user_token, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"ClusterVulnerabilityReport {name} not found",
                    "metadata": {"name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('ClusterVulnerabilityReport', name, '', session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster vulnerability report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"name": name}
            }), 500


@trivy_operator_api_bp.route('/cluster/config-audit-reports')
class TrivyOperatorClusterConfigAuditReportsResource(MethodView):
    """ClusterConfigAuditReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster config audit reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get cluster config audit reports"""
        user_token = get_user_token(session)
        
        try:
            reports = TrivyGetClusterConfigAuditReports(session['user_role'], user_token)
            return jsonify({
                "data": reports,
                "metadata": {"count": len(reports)}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster config audit reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {}
            }), 500


@trivy_operator_api_bp.route('/cluster/config-audit-reports/<name>')
class TrivyOperatorClusterConfigAuditReportResource(MethodView):
    """ClusterConfigAuditReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster config audit report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, name):
        """Get a specific cluster config audit report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetClusterConfigAuditReport(session['user_role'], user_token, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"ClusterConfigAuditReport {name} not found",
                    "metadata": {"name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('ClusterConfigAuditReport', name, '', session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster config audit report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"name": name}
            }), 500


@trivy_operator_api_bp.route('/cluster/infra-assessment-reports')
class TrivyOperatorClusterInfraAssessmentReportsResource(MethodView):
    """ClusterInfraAssessmentReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster infra assessment reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get cluster infra assessment reports"""
        user_token = get_user_token(session)
        
        try:
            reports = TrivyGetClusterInfraAssessmentReports(session['user_role'], user_token)
            return jsonify({
                "data": reports,
                "metadata": {"count": len(reports)}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster infra assessment reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {}
            }), 500


@trivy_operator_api_bp.route('/cluster/infra-assessment-reports/<name>')
class TrivyOperatorClusterInfraAssessmentReportResource(MethodView):
    """ClusterInfraAssessmentReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster infra assessment report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, name):
        """Get a specific cluster infra assessment report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetClusterInfraAssessmentReport(session['user_role'], user_token, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"ClusterInfraAssessmentReport {name} not found",
                    "metadata": {"name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('ClusterInfraAssessmentReport', name, '', session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster infra assessment report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"name": name}
            }), 500


@trivy_operator_api_bp.route('/cluster/rbac-assessment-reports')
class TrivyOperatorClusterRbacAssessmentReportsResource(MethodView):
    """ClusterRbacAssessmentReports endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster RBAC assessment reports")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self):
        """Get cluster RBAC assessment reports"""
        user_token = get_user_token(session)
        
        try:
            reports = TrivyGetClusterRbacAssessmentReports(session['user_role'], user_token)
            return jsonify({
                "data": reports,
                "metadata": {"count": len(reports)}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster RBAC assessment reports: {str(e)}")
            return jsonify({
                "data": [],
                "error": "InternalError",
                "message": str(e),
                "metadata": {}
            }), 500


@trivy_operator_api_bp.route('/cluster/rbac-assessment-reports/<name>')
class TrivyOperatorClusterRbacAssessmentReportResource(MethodView):
    """ClusterRbacAssessmentReport detail endpoint."""
    
    @trivy_operator_api_bp.response(200, description="Successfully retrieved cluster RBAC assessment report")
    @trivy_operator_api_bp.doc(tags=['Plugins API - Trivy Operator'])
    @login_required
    def get(self, name):
        """Get a specific cluster RBAC assessment report"""
        user_token = get_user_token(session)
        
        try:
            report = TrivyGetClusterRbacAssessmentReport(session['user_role'], user_token, name)
            if not report:
                return jsonify({
                    "data": None,
                    "error": "NotFound",
                    "message": f"ClusterRbacAssessmentReport {name} not found",
                    "metadata": {"name": name}
                }), 404
            
            # Get events
            uid = report.get('raw', {}).get('metadata', {}).get('uid')
            events, _ = TrivyGetEvents('ClusterRbacAssessmentReport', name, '', session['user_role'], user_token, uid=uid)
            report['events'] = events
            
            return jsonify({
                "data": report,
                "metadata": {"name": name}
            })
        except Exception as e:
            logger.error(f"Error retrieving cluster RBAC assessment report: {str(e)}")
            return jsonify({
                "data": None,
                "error": "InternalError",
                "message": str(e),
                "metadata": {"name": name}
            }), 500

