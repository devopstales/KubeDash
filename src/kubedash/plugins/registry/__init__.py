from datetime import datetime

from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_login import login_required

from lib.components import csrf
from lib.helper_functions import get_logger

from .registry import (RegistryDeleteTag, RegistryGetManifest,
                       RegistryGetRepositories, RegistryGetTags)
from .registry_server import (RegistryEventCreate, RegistryGetEvent,
                              RegistryServerCreate, RegistryServerDelete,
                              RegistryServerListGet, RegistryServerUpdate)

#############################################################
## variables
##############################################################

registry_bp = Blueprint("registry", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
# OCI Registry Routes
##############################################################


@registry_bp.route("/registry", methods=['GET', 'POST'])
@login_required
def registry_main():
    """
    Registry main page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/plugins/registry
    return render_template('registry.html.j2')

@registry_bp.route("/registry/image/list", methods=['GET', 'POST'])
@login_required
def image_list():
    """
    Registry image list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/plugins/registry/<url>/images
    # registry_server_url is passed via sessionStorage or query parameter
    return render_template('registry-image-list.html.j2')
    
@registry_bp.route("/registry/image/tags", methods=['GET', 'POST'])
@login_required
def image_tags():
    """
    Registry image tags page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/plugins/registry/<url>/images/<image>/tags
    # registry_server_url and image_name are passed via query parameters or sessionStorage
    return render_template('registry-image-tag-list.html.j2')

@registry_bp.route("/registry/image/tag/delete", methods=['GET', 'POST'])
@login_required
def image_tag_delete():
    if request.method == 'POST':
        tag_name = request.form.get('tag_name')
        image_name = request.form.get('image_name')
        RegistryDeleteTag(session['registry_server_url'], image_name, tag_name)
        return redirect(url_for('.image_tags'), code=307)
    else:
        return redirect(url_for('auth.login'))

@registry_bp.route("/registry/image/data", methods=['GET', 'POST'])
@login_required
def image_data():
    """
    Registry image tag data page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Template now loads data via JavaScript from /api/v1/plugins/registry/<url>/images/<image>/tags/<tag>/data
    # registry_server_url, image_name, and tag_name are passed via query parameters or sessionStorage
    return render_template('registry-image-tag-data.html.j2')

@registry_bp.route("/registry/events", methods=['POST'])
@csrf.exempt
def registry_events():
    events = request.json["events"]
    for event in events:
        timestamp = datetime.now()
        try:
            actor = event["actor"]["name"]
        except KeyError:
            actor = None
        if "tag" in event["target"]:
            if event["request"]["useragent"] != "KubeDash":
                RegistryEventCreate(event["action"], event["target"]["repository"], 
                event["target"]["tag"], event["target"]["digest"], event["request"]["addr"].split(":")[0], actor, timestamp)

    resp = jsonify(success=True)
    return resp
