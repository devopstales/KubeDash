from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.metrics import k8sPVCMetric
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.storage import (k8sConfigmapListGet,
                             k8sPersistentVolumeClaimListGet,
                             k8sPersistentVolumeListGet,
                             k8sPersistentVolumeSnapshotListGet,
                             k8sSnapshotClassListGet, k8sStorageClassListGet)
from lib.sso import get_user_token

##############################################################network
## Helpers
##############################################################

storage = Blueprint("storage", __name__, url_prefix="/storage")
logger = get_logger()

##############################################################
## Storage
##############################################################
## storage Class
##############################################################

@storage.route("/storage-class", methods=['GET', 'POST'])
@login_required
def storage_class():
    selected = "default"
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    storage_classes = k8sStorageClassListGet(session['user_role'], user_token)

    return render_template(
        'storage/storage-class.html.j2',
        storage_classes = storage_classes,
        selected = selected,
    )

@storage.route('/storage-class/data', methods=['GET', 'POST'])
@login_required
def storage_class_data():
    if request.method == 'POST':
        sc_name = request.form.get('sc_name')
        user_token = get_user_token(session)

        storage_classes = k8sStorageClassListGet(session['user_role'], user_token)
        sc_data = None
        for sc in storage_classes:
            if sc["name"] == sc_name:
                sc_data = sc

        if sc_data:
            return render_template(
                'storage/storage-class-data.html.j2',
                sc_data = sc_data
            )
        else:
                flash("Cannot iterate StorageClassList", "danger")
                return redirect(url_for('.storage_class'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
## SnapshotClass
##############################################################

@storage.route("/snapshot-class", methods=['GET', 'POST'])
@login_required
def snapshot_class():
    selected = "default"
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    snapshot_classes = k8sSnapshotClassListGet(session['user_role'], user_token)
    print(snapshot_classes)

    return render_template(
        'storage/snapshot-class.html.j2',
        snapshot_classes = snapshot_classes,
        selected = selected,
    )

@storage.route('/snapshot-class/data', methods=['GET', 'POST'])
@login_required
def snapshot_class_data():
    if request.method == 'POST':
        sc_name = request.form.get('sc_name')
        user_token = get_user_token(session)

        snapshot_classes = k8sSnapshotClassListGet(session['user_role'], user_token)
        sc_data = None
        for sc in snapshot_classes:
            if sc["name"] == sc_name:
                sc_data = sc

        if sc_data:
            return render_template(
                'storage/snapshot-class-data.html.j2',
                sc_data = sc_data
            )
        else:
                flash("Cannot iterate SnapshotClassList", "danger")
                return redirect(url_for('.snapshot_classes'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
## Persistent Volume Claim
##############################################################

@storage.route("/pvc", methods=['GET', 'POST'])
@login_required
def pvc():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        pvc_list = k8sPersistentVolumeClaimListGet(session['user_role'], user_token, session['ns_select'])
        pvc_metrics = k8sPVCMetric(session['ns_select'])
    else:
        pvc_list = list()
        pvc_metrics = list()

    return render_template(
        'storage/pvc.html.j2',
        pvc_list = pvc_list,
        pvc_metrics = pvc_metrics,
        namespaces = namespace_list,
        selected = selected,
    )

@storage.route('/pvc/data', methods=['GET', 'POST'])
@login_required
def pvc_data():
    if request.method == 'POST':
        selected = request.form.get('selected')
        user_token = get_user_token(session)

        pvc_list = k8sPersistentVolumeClaimListGet(session['user_role'], user_token, session['ns_select'])
        pvc_data = None
        for pvc in pvc_list:
            if pvc["name"] == selected:
                pvc_data = pvc

        if pvc_data:
            return render_template(
                'storage/pvc-data.html.j2',
                pvc_data = pvc_data,
                namespace = session['ns_select'],
            )
        else:
                    flash("Cannot iterate PersistentVolumeClaimList", "danger")
                    return redirect(url_for('.pvc'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
## Persistent Volume
##############################################################

@storage.route("/pv", methods=['GET', 'POST'])
@login_required
def pv():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        pv_list = k8sPersistentVolumeListGet(session['user_role'], user_token, session['ns_select'])
    else:
        pv_list = []
        namespace_list = []
      
    return render_template(
        'storage/pv.html.j2',
        pv_list = pv_list,
        selected = selected,
        namespaces = namespace_list,
    )

@storage.route('/pv/data', methods=['GET', 'POST'])
@login_required
def pv_data():
    pv_data = None
    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')
        user_token = get_user_token(session)

        pv_list = k8sPersistentVolumeListGet(session['user_role'], user_token, session['ns_select'])
        pv_data = None
        for pv in pv_list:
            if pv["name"] == selected:
                pv_data = pv

        if pv_data:
            return render_template(
                'storage/pv-data.html.j2',
                pv_data = pv_data,
                namespace = session['ns_select'],
            )
        else:
                flash("Cannot iterate PersistentVolumeList", "danger")
                return redirect(url_for('.pv'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
## Volume Snapshot
##############################################################

@storage.route("/volumesnapshot", methods=['GET', 'POST'])
@login_required
def volumesnapshots():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    snapshot_list = k8sPersistentVolumeSnapshotListGet(session['user_role'], user_token)
      
    return render_template(
        'storage/volumesnapshot.html.j2',
        snapshot_list = snapshot_list,
        selected = selected,
    )

##############################################################
## ConfigMap
##############################################################

@storage.route("/configmap", methods=['GET', 'POST'])
@login_required
def configmap():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        configmaps = k8sConfigmapListGet(session['user_role'], user_token, session['ns_select'])
    else:
        configmaps = list()

    return render_template(
        'storage/configmap.html.j2',
        configmaps = configmaps,
        namespaces = namespace_list,
        selected = selected,
    )

@storage.route('/configmap/data', methods=['GET', 'POST'])
@login_required
def configmap_data():
    if request.method == 'POST':
        configmap_name = request.form.get('configmap_name')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        configmaps = k8sConfigmapListGet(session['user_role'], user_token, session['ns_select'])
        configmap_data = None
        for configmap in configmaps:
            if configmap["name"] == configmap_name:
                configmap_data = configmap

        if configmap_data:
            return render_template(
                'storage/configmap-data.html.j2',
                configmap_data = configmap_data,
                namespace = session['ns_select'],
            )
        else:
                flash("Cannot iterate ConfigmapList", "danger")
                return redirect(url_for('.configmap'))
    else:
        return redirect(url_for('auth.login'))
