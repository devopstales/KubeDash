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

registry = Blueprint("registry", __name__, url_prefix="/plugins", \
    template_folder="templates")
logger = get_logger()

##############################################################
# OCI Registry Routes
##############################################################


@registry.route("/registry", methods=['GET', 'POST'])
@login_required
def registry_main():
    selected = None
    registry_server_auth_user = None
    registry_server_auth_pass = None
    registry_server_auth = False
    if request.method == 'POST':
        selected = request.form.get('selected')
        request_type = request.form['request_type']
        if request_type == "create":
            registry_server_tls = request.form.get('registry_server_tls_register_value') in ['True']
            insecure_tls = request.form.get('insecure_tls_register_value') in ['True']
            registry_server_url = request.form.get('registry_server_url')
            registry_server_port = request.form.get('registry_server_port')
            if request.form.get('registry_server_auth_user') and request.form.get('registry_server_auth_pass'):
                registry_server_auth_user = request.form.get('registry_server_auth_user')
                registry_server_auth_pass = request.form.get('registry_server_auth_pass') # bas64 encoded
                registry_server_auth = True

            RegistryServerCreate(registry_server_url, registry_server_port, registry_server_auth, 
                        registry_server_tls, insecure_tls, registry_server_auth_user, 
                        registry_server_auth_pass)
            flash("Registry Created Successfully", "success")
        elif request_type == "edit":
            registry_server_tls = request.form.get('registry_server_tls_edit_value') in ['True']
            insecure_tls = request.form.get('insecure_tls_edit_value') in ['True']
            registry_server_url = request.form.get('registry_server_url')
            registry_server_url_old = request.form.get('registry_server_url_old')
            registry_server_port = request.form.get('registry_server_port')
            registry_server_auth = request.form.get('registry_server_auth')
            if request.form.get('registry_server_auth_user') and request.form.get('registry_server_auth_pass'):
                registry_server_auth_user = request.form.get('registry_server_auth_user')
                registry_server_auth_pass = request.form.get('registry_server_auth_pass')
                registry_server_auth = True

            RegistryServerUpdate(registry_server_url, registry_server_url_old, registry_server_port, 
                        registry_server_auth, registry_server_tls, insecure_tls, registry_server_auth_user, 
                        registry_server_auth_pass)
            flash("Registry Updated Successfully", "success")
        elif request_type == "delete":
            registry_server_url = request.form.get('registry_server_url')

            RegistryServerDelete(registry_server_url)
            flash("Registry Deleted Successfully", "success")

    registries = RegistryServerListGet()

    return render_template(
      'registry.html.j2',
        registries = registries,
        selected = selected,
    )

@registry.route("/image/list", methods=['GET', 'POST'])
@login_required
def image_list():
    selected = None
    if request.method == 'POST':
        selected = request.form.get('selected')
        session['registry_server_url'] = request.form.get('registry_server_url')

    image_list = RegistryGetRepositories(session['registry_server_url'])

    return render_template(
        'registry-image-list.html.j2',
        image_list = image_list,
        selected = selected,
    )
    
@registry.route("/image/tags", methods=['GET', 'POST'])
@login_required
def image_tags():
    selected = None
    if request.method == 'POST':
        selected = request.form.get('selected')
        if 'image_name' in request.form:
            session['image_name'] = request.form.get('image_name')

    tag_list = RegistryGetTags(session['registry_server_url'], session['image_name'])

    return render_template(
        'registry-image-tag-list.html.j2',
        tag_list = tag_list,
        selected = selected,
        image_name = session['image_name'],
    )

@registry.route("/image/tag/delete", methods=['GET', 'POST'])
@login_required
def image_tag_delete():
    if request.method == 'POST':
        tag_name = request.form.get('tag_name')
        image_name = request.form.get('image_name')
        RegistryDeleteTag(session['registry_server_url'], image_name, tag_name)
        return redirect(url_for('.image_tags'), code=307)
    else:
        return redirect(url_for('auth.login'))

@registry.route("/image/data", methods=['GET', 'POST'])
@login_required
def image_data():
    if request.method == 'POST':
        if 'tag_name' in request.form:
            session['tag_name'] = request.form.get('tag_name')

    tag_data = RegistryGetManifest(session['registry_server_url'], session['image_name'], session['tag_name'])
    tag_events = RegistryGetEvent(session['image_name'], session['tag_name'])

    return render_template(
        'registry-image-tag-data.html.j2',
        tag_data = tag_data,
        tag_events = tag_events,
        image_name = session['image_name'],
        tag_name = session['tag_name'],
    )

@registry.route("/registry/events", methods=['POST'])
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
