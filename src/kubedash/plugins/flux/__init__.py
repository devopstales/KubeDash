#!/usr/bin/env python3

from flask import Blueprint, render_template, request, session, redirect, url_for
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.sso import get_user_token

from .helm_releases import FluxHelmReleaseGet
from .kustomizations import FluxKustomizationGet
from .notifications import FluxAlertNotificationGet, FluxProviderNotificationGet, FluxReceiverNotificationGet
from .source import FluxBucketRepositoryGet, FluxGitRepositoryGet, FluxHelmRepositoryGet, FluxOCIRepositoryGet


##############################################################
## variables
##############################################################

flux = Blueprint("flux", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
# Flux sources
##############################################################

@flux.route("/flux-objects", methods=['GET', 'POST'])
def get_flux_objects():
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
            
    results = {}
    errors = {}

    flux_getters = {
        "HelmReleases": FluxHelmReleaseGet(session['user_role'], user_token, session['ns_select']),
        "Kustomizations": FluxKustomizationGet(session['user_role'], user_token, session['ns_select']),
        "Alerts": FluxAlertNotificationGet(session['user_role'], user_token, session['ns_select']),
        "Providers": FluxProviderNotificationGet(session['user_role'], user_token, session['ns_select']),
        "Receivers": FluxReceiverNotificationGet(session['user_role'], user_token, session['ns_select']),
        "Buckets": FluxBucketRepositoryGet(session['user_role'], user_token, session['ns_select']),
        "GitRepositories": FluxGitRepositoryGet(session['user_role'], user_token, session['ns_select']),
        "HelmRepositories": FluxHelmRepositoryGet(session['user_role'], user_token, session['ns_select']),
        "OCIRepositories": FluxOCIRepositoryGet(session['user_role'], user_token, session['ns_select']),
    }

    flux_objects = {}
    for kind, func in flux_getters.items():
        try:
            flux_objects[kind] = func()
        except Exception as e:
            flux_objects[kind] = []

    return render_template("flux_objects.html.j2", flux_objects=flux_objects)