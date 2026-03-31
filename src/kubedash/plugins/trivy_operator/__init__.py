#!/usr/bin/env python3
"""
Trivy Operator Plugin for KubeDash

This plugin provides visibility into Trivy Operator security reports including:
- VulnerabilityReports: Container image vulnerabilities
- ConfigAuditReports: Configuration misconfigurations
- ExposedSecretReports: Exposed secrets detection
- RbacAssessmentReports: RBAC security assessments
- SbomReports: Software Bill of Materials (SBOM) for container images

Routes:
- /plugins/trivy-operator: Main view with tabs for all report types
- /plugins/trivy-operator/vulnerability/<ns>/<name>: VulnerabilityReport detail view
- /plugins/trivy-operator/configaudit/<ns>/<name>: ConfigAuditReport detail view
- /plugins/trivy-operator/exposedsecret/<ns>/<name>: ExposedSecretReport detail view
- /plugins/trivy-operator/rbacassessment/<ns>/<name>: RbacAssessmentReport detail view
- /plugins/trivy-operator/sbom/<ns>/<name>: SbomReport detail view
"""

from flask import Blueprint, render_template, request, session, redirect, url_for
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
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
## Variables
##############################################################

trivy_operator_bp = Blueprint(
    "trivy_operator",
    __name__,
    url_prefix="/plugins",
    template_folder="templates"
)
logger = get_logger()

##############################################################
# Main Trivy Operator View
##############################################################

@trivy_operator_bp.route("/trivy-operator/namespace", methods=['GET', 'POST'])
@login_required
def trivy_operator_namespace():
    """
    Namespace-scoped Trivy Operator reports view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    user_token = get_user_token(session)
    active_tab = request.args.get('tab', 'vulnerabilityreports')
    
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        if request.form.get('active_tab'):
            active_tab = request.form.get('active_tab')
    
    # Get namespace list for topbar selector
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if error:
        namespace_list = []
    
    # Check if Trivy Operator is installed (for status display)
    trivy_status = check_trivy_operator_installed(session['user_role'], user_token)
    
    # Template now loads data via JavaScript from API
    return render_template(
        'trivy-operator-namespace.html.j2',
        namespaces=namespace_list,
        trivy_status=trivy_status,
        active_tab=active_tab,
    )


@trivy_operator_bp.route("/trivy-operator/cluster", methods=['GET', 'POST'])
@login_required
def trivy_operator_cluster():
    """
    Cluster-scoped Trivy Operator reports view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    user_token = get_user_token(session)
    active_tab = request.args.get('tab', 'clustercompliancereports')
    
    if request.method == 'POST':
        if request.form.get('active_tab'):
            active_tab = request.form.get('active_tab')
    
    # Check if Trivy Operator is installed (for status display)
    trivy_status = check_trivy_operator_installed(session['user_role'], user_token)
    
    # Template now loads data via JavaScript from API
    return render_template(
        'trivy-operator-cluster.html.j2',
        trivy_status=trivy_status,
        active_tab=active_tab,
    )


##############################################################
# VulnerabilityReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/vulnerability/<namespace>/<name>", methods=['GET'])
@login_required
def vulnerability_detail(namespace, name):
    """
    VulnerabilityReport detail view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from API
    return render_template(
        'vulnerability-detail.html.j2',
        namespace=namespace,
        name=name,
    )


##############################################################
# ConfigAuditReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/configaudit/<namespace>/<name>", methods=['GET'])
@login_required
def configaudit_detail(namespace, name):
    """
    ConfigAuditReport detail view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    return render_template(
        'configaudit-detail.html.j2',
        namespace=namespace,
        name=name,
    )


##############################################################
# ExposedSecretReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/exposedsecret/<namespace>/<name>", methods=['GET'])
@login_required
def exposedsecret_detail(namespace, name):
    """
    ExposedSecretReport detail view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    return render_template(
        'exposedsecret-detail.html.j2',
        namespace=namespace,
        name=name,
    )


##############################################################
# RbacAssessmentReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/rbacassessment/<namespace>/<name>", methods=['GET'])
@login_required
def rbacassessment_detail(namespace, name):
    """
    RbacAssessmentReport detail view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    return render_template(
        'rbacassessment-detail.html.j2',
        namespace=namespace,
        name=name,
    )


##############################################################
# SbomReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/sbom/<namespace>/<name>", methods=['GET'])
@login_required
def sbom_detail(namespace, name):
    """
    SbomReport detail view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    return render_template(
        'sbom-detail.html.j2',
        namespace=namespace,
        name=name,
    )


##############################################################
# InfraAssessmentReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/infraassessment/<namespace>/<name>", methods=['GET'])
@login_required
def infraassessment_detail(namespace, name):
    """
    InfraAssessmentReport detail view.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    return render_template(
        'infraassessment-detail.html.j2',
        namespace=namespace,
        name=name,
    )


##############################################################
# Cluster-scoped Report Detail Views
##############################################################

@trivy_operator_bp.route("/trivy-operator/cluster/compliance/<name>", methods=['GET'])
@login_required
def clustercompliance_detail(name):
    """ClusterComplianceReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetClusterComplianceReport(session['user_role'], user_token, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_cluster'))
    
    # Get events (cluster-scoped, no namespace)
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('ClusterComplianceReport', name, '', session['user_role'], user_token, uid=uid)
    
    return render_template(
        'clustercompliance-detail.html.j2',
        report=report,
        events=events,
    )


@trivy_operator_bp.route("/trivy-operator/cluster/vulnerability/<name>", methods=['GET'])
@login_required
def clustervulnerability_detail(name):
    """ClusterVulnerabilityReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetClusterVulnerabilityReport(session['user_role'], user_token, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_cluster'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('ClusterVulnerabilityReport', name, '', session['user_role'], user_token, uid=uid)
    
    return render_template(
        'clustervulnerability-detail.html.j2',
        report=report,
        events=events,
    )


@trivy_operator_bp.route("/trivy-operator/cluster/configaudit/<name>", methods=['GET'])
@login_required
def clusterconfigaudit_detail(name):
    """ClusterConfigAuditReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetClusterConfigAuditReport(session['user_role'], user_token, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_cluster'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('ClusterConfigAuditReport', name, '', session['user_role'], user_token, uid=uid)
    
    return render_template(
        'clusterconfigaudit-detail.html.j2',
        report=report,
        events=events,
    )


@trivy_operator_bp.route("/trivy-operator/cluster/infraassessment/<name>", methods=['GET'])
@login_required
def clusterinfraassessment_detail(name):
    """ClusterInfraAssessmentReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetClusterInfraAssessmentReport(session['user_role'], user_token, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_cluster'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('ClusterInfraAssessmentReport', name, '', session['user_role'], user_token, uid=uid)
    
    return render_template(
        'clusterinfraassessment-detail.html.j2',
        report=report,
        events=events,
    )


@trivy_operator_bp.route("/trivy-operator/cluster/rbacassessment/<name>", methods=['GET'])
@login_required
def clusterrbacassessment_detail(name):
    """ClusterRbacAssessmentReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetClusterRbacAssessmentReport(session['user_role'], user_token, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_cluster'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('ClusterRbacAssessmentReport', name, '', session['user_role'], user_token, uid=uid)
    
    return render_template(
        'clusterrbacassessment-detail.html.j2',
        report=report,
        events=events,
    )
