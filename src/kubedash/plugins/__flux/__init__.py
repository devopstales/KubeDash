#!/usr/bin/env python3

import json

from flask import Blueprint, render_template, request, session, redirect, url_for
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.sso import get_user_token
from lib.k8s.namespace import k8sNamespaceListGet

from .helm_releases import FluxHelmReleaseGet
from .kustomizations import FluxKustomizationGet
from .notifications import FluxAlertNotificationGet, FluxProviderNotificationGet, FluxReceiverNotificationGet
from .sources import FluxBucketRepositoryGet, FluxGitRepositoryGet, FluxHelmRepositoryGet, FluxOCIRepositoryGet
from .actions import SuspendAction, ResumeAction, SyncAction


##############################################################
## variables
##############################################################

flux_bp = Blueprint("flux", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
# Flux sources
##############################################################

@flux_bp.route("/flux", methods=['GET', 'POST'])
@login_required
def get_flux_objects():
    selected = None
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
            
    flux_objects = {}
    flux_objects["HelmReleases"] = FluxHelmReleaseGet(session['user_role'], user_token, session['ns_select'])
    flux_objects["Kustomizations"] = FluxKustomizationGet(session['user_role'], user_token, session['ns_select'])
    flux_objects["Alerts"] = FluxAlertNotificationGet(session['user_role'], user_token, session['ns_select'])
    flux_objects["Providers"] = FluxProviderNotificationGet(session['user_role'], user_token, session['ns_select'])
    flux_objects["Receivers"] = FluxReceiverNotificationGet(session['user_role'], user_token, session['ns_select'])
    flux_objects["Buckets"] = FluxBucketRepositoryGet(session['user_role'], user_token, session['ns_select'])
    flux_objects["GitRepositories"] = FluxGitRepositoryGet(session['user_role'], user_token, session['ns_select'])
    flux_objects["HelmRepositories"] = FluxHelmRepositoryGet(session['user_role'], user_token, session['ns_select'])
    flux_objects["OCIRepositories"] = FluxOCIRepositoryGet(session['user_role'], user_token, session['ns_select'])
       
    return render_template("flux_objects.html.j2",
        namespaces = namespace_list,
        selected = selected,
        flux_objects = flux_objects,
    )

##############################################################  
# ForceRecon
##############################################################

##############################################################
# Suspend, Resume
##############################################################

@flux_bp.route("/flux/suspend", methods=['POST'])
@login_required
def flux_suspend():
    """
    Suspend action for Flux objects.
    This endpoint is a placeholder for the sync functionality.
    """
    if request.method == 'POST':
        flux_object = json.loads(request.form.get('flux_object'))
        user_token = get_user_token(session)
        
        SuspendAction(flux_object, session['user_role'], user_token)
        
        return redirect(url_for('flux.get_flux_objects'))
    else:
        return redirect(url_for('flux.get_flux_objects'))
    
@flux_bp.route("/flux/resume", methods=['POST'])
@login_required
def flux_resume():
    """
    Resume action for Flux objects.
    This endpoint is a placeholder for the sync functionality.
    """
    if request.method == 'POST':
        flux_object = json.loads(request.form.get('flux_object'))
        user_token = get_user_token(session)
        
        ResumeAction(flux_object, session['user_role'], user_token)
        
        return redirect(url_for('flux.get_flux_objects'))
    else:
        return redirect(url_for('flux.get_flux_objects'))
    

##############################################################
# Sync
##############################################################

@flux_bp.route("/flux/sync", methods=['POST'])
@login_required
def flux_sync():
    """
    Sync action for Flux objects.
    This endpoint is a placeholder for the sync functionality.
    """
    if request.method == 'POST':
        flux_object = json.loads(request.form.get('flux_object'))
        user_token = get_user_token(session)
        
        SyncAction(flux_object, session['user_role'], user_token)
        
        return redirect(url_for('flux.get_flux_objects'))
    else:
        return redirect(url_for('flux.get_flux_objects'))