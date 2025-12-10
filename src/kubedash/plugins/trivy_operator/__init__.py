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
    """Namespace-scoped Trivy Operator reports view."""
    user_token = get_user_token(session)
    active_tab = request.args.get('tab', 'vulnerabilityreports')
    
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        if request.form.get('active_tab'):
            active_tab = request.form.get('active_tab')
    
    # Get namespace list
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if error:
        namespace_list = []
    
    # Check if Trivy Operator is installed
    trivy_status = check_trivy_operator_installed(session['user_role'], user_token)
    
    # Fetch all namespace-scoped report types
    vulnerability_reports = []
    configaudit_reports = []
    exposedsecret_reports = []
    rbacassessment_reports = []
    sbom_reports = []
    infraassessment_reports = []
    
    if trivy_status.get('installed', False):
        # Fetch namespaced resources based on selected namespace
        ns = session.get('ns_select', 'default')
        
        vulnerability_reports = TrivyGetVulnerabilityReports(session['user_role'], user_token, ns)
        configaudit_reports = TrivyGetConfigAuditReports(session['user_role'], user_token, ns)
        exposedsecret_reports = TrivyGetExposedSecretReports(session['user_role'], user_token, ns)
        rbacassessment_reports = TrivyGetRbacAssessmentReports(session['user_role'], user_token, ns)
        sbom_reports = TrivyGetSbomReports(session['user_role'], user_token, ns)
        infraassessment_reports = TrivyGetInfraAssessmentReports(session['user_role'], user_token, ns)
    
    return render_template(
        'trivy-operator-namespace.html.j2',
        namespaces=namespace_list,
        trivy_status=trivy_status,
        vulnerability_reports=vulnerability_reports,
        configaudit_reports=configaudit_reports,
        exposedsecret_reports=exposedsecret_reports,
        rbacassessment_reports=rbacassessment_reports,
        sbom_reports=sbom_reports,
        infraassessment_reports=infraassessment_reports,
        active_tab=active_tab,
    )


@trivy_operator_bp.route("/trivy-operator/cluster", methods=['GET', 'POST'])
@login_required
def trivy_operator_cluster():
    """Cluster-scoped Trivy Operator reports view."""
    user_token = get_user_token(session)
    active_tab = request.args.get('tab', 'clustercompliancereports')
    
    if request.method == 'POST':
        if request.form.get('active_tab'):
            active_tab = request.form.get('active_tab')
    
    # Check if Trivy Operator is installed
    trivy_status = check_trivy_operator_installed(session['user_role'], user_token)
    
    # Fetch all cluster-scoped report types
    clustercompliance_reports = []
    clustervulnerability_reports = []
    clusterconfigaudit_reports = []
    clusterinfraassessment_reports = []
    clusterrbacassessment_reports = []
    
    if trivy_status.get('installed', False):
        clustercompliance_reports = TrivyGetClusterComplianceReports(session['user_role'], user_token)
        clustervulnerability_reports = TrivyGetClusterVulnerabilityReports(session['user_role'], user_token)
        clusterconfigaudit_reports = TrivyGetClusterConfigAuditReports(session['user_role'], user_token)
        clusterinfraassessment_reports = TrivyGetClusterInfraAssessmentReports(session['user_role'], user_token)
        clusterrbacassessment_reports = TrivyGetClusterRbacAssessmentReports(session['user_role'], user_token)
    
    return render_template(
        'trivy-operator-cluster.html.j2',
        trivy_status=trivy_status,
        clustercompliance_reports=clustercompliance_reports,
        clustervulnerability_reports=clustervulnerability_reports,
        clusterconfigaudit_reports=clusterconfigaudit_reports,
        clusterinfraassessment_reports=clusterinfraassessment_reports,
        clusterrbacassessment_reports=clusterrbacassessment_reports,
        active_tab=active_tab,
    )


##############################################################
# VulnerabilityReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/vulnerability/<namespace>/<name>", methods=['GET'])
@login_required
def vulnerability_detail(namespace, name):
    """VulnerabilityReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetVulnerabilityReport(session['user_role'], user_token, namespace, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_namespace'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('VulnerabilityReport', name, namespace, session['user_role'], user_token, uid=uid)
    
    return render_template(
        'vulnerability-detail.html.j2',
        report=report,
        events=events,
    )


##############################################################
# ConfigAuditReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/configaudit/<namespace>/<name>", methods=['GET'])
@login_required
def configaudit_detail(namespace, name):
    """ConfigAuditReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetConfigAuditReport(session['user_role'], user_token, namespace, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_namespace'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('ConfigAuditReport', name, namespace, session['user_role'], user_token, uid=uid)
    
    return render_template(
        'configaudit-detail.html.j2',
        report=report,
        events=events,
    )


##############################################################
# ExposedSecretReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/exposedsecret/<namespace>/<name>", methods=['GET'])
@login_required
def exposedsecret_detail(namespace, name):
    """ExposedSecretReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetExposedSecretReport(session['user_role'], user_token, namespace, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_namespace'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('ExposedSecretReport', name, namespace, session['user_role'], user_token, uid=uid)
    
    return render_template(
        'exposedsecret-detail.html.j2',
        report=report,
        events=events,
    )


##############################################################
# RbacAssessmentReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/rbacassessment/<namespace>/<name>", methods=['GET'])
@login_required
def rbacassessment_detail(namespace, name):
    """RbacAssessmentReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetRbacAssessmentReport(session['user_role'], user_token, namespace, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_namespace'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('RbacAssessmentReport', name, namespace, session['user_role'], user_token, uid=uid)
    
    return render_template(
        'rbacassessment-detail.html.j2',
        report=report,
        events=events,
    )


##############################################################
# SbomReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/sbom/<namespace>/<name>", methods=['GET'])
@login_required
def sbom_detail(namespace, name):
    """SbomReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetSbomReport(session['user_role'], user_token, namespace, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_namespace'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('SbomReport', name, namespace, session['user_role'], user_token, uid=uid)
    
    return render_template(
        'sbom-detail.html.j2',
        report=report,
        events=events,
    )


##############################################################
# InfraAssessmentReport Detail View
##############################################################

@trivy_operator_bp.route("/trivy-operator/infraassessment/<namespace>/<name>", methods=['GET'])
@login_required
def infraassessment_detail(namespace, name):
    """InfraAssessmentReport detail view."""
    user_token = get_user_token(session)
    
    report = TrivyGetInfraAssessmentReport(session['user_role'], user_token, namespace, name)
    
    if not report:
        return redirect(url_for('trivy_operator.trivy_operator_namespace'))
    
    # Get events
    uid = report.get('raw', {}).get('metadata', {}).get('uid') if report else None
    events, _ = TrivyGetEvents('InfraAssessmentReport', name, namespace, session['user_role'], user_token, uid=uid)
    
    return render_template(
        'infraassessment-detail.html.j2',
        report=report,
        events=events,
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
