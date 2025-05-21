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