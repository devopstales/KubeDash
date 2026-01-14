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

storage_bp = Blueprint("storage", __name__, url_prefix="/storage")
logger = get_logger()

##############################################################
## Storage
##############################################################
## storage Class
##############################################################

@storage_bp.route("/storage-class", methods=['GET', 'POST'])
@login_required
def storage_class():
    """
    Storage Classes list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        selected = request.form.get('selected') or request.form.get('sc_name')
    
    # Template now loads data via JavaScript from /api/v1/storage/storage-classes
    return render_template('storage/storage-class.html.j2')

@storage_bp.route('/storage-class/data', methods=['GET', 'POST'])
@login_required
def storage_class_data():
    """
    Storage Class detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests - redirect with query parameters
    if request.method == 'POST':
        selected = request.form.get('selected') or request.form.get('sc_name')
        
        # Redirect with query parameters so JavaScript can read them
        if selected:
            return redirect(url_for('storage.storage_class_data', selected=selected, sc_name=selected))
        else:
            # If no storage class name, just redirect to list
            return redirect(url_for('storage.storage_class'))
    
    # Template now loads data via JavaScript from /api/v1/storage/storage-classes/<name>
    return render_template('storage/storage-class-data.html.j2')

##############################################################
## SnapshotClass
##############################################################

@storage_bp.route("/snapshot-class", methods=['GET', 'POST'])
@login_required
def snapshot_class():
    """
    Snapshot Classes list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        selected = request.form.get('selected') or request.form.get('sc_name')
    
    # Template now loads data via JavaScript from /api/v1/storage/snapshot-classes
    return render_template('storage/snapshot-class.html.j2')

@storage_bp.route('/snapshot-class/data', methods=['GET', 'POST'])
@login_required
def snapshot_class_data():
    """
    Snapshot Class detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests - redirect with query parameters
    if request.method == 'POST':
        selected = request.form.get('selected') or request.form.get('sc_name')
        
        # Redirect with query parameters so JavaScript can read them
        if selected:
            return redirect(url_for('storage.snapshot_class_data', selected=selected, sc_name=selected))
        else:
            # If no snapshot class name, just redirect to list
            return redirect(url_for('storage.snapshot_class'))
    
    # Template now loads data via JavaScript from /api/v1/storage/snapshot-classes/<name>
    return render_template('storage/snapshot-class-data.html.j2')

##############################################################
## Persistent Volume Claim
##############################################################

@storage_bp.route("/pvc", methods=['GET', 'POST'])
@login_required
def pvc():
    """
    Persistent Volume Claims list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/storage/pvcs and /api/v1/storage/pvcs/metrics
    return render_template('storage/pvc.html.j2', namespaces=namespaces)

@storage_bp.route('/pvc/data', methods=['GET', 'POST'])
@login_required
def pvc_data():
    """
    Persistent Volume Claim detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests - redirect with query parameters
    if request.method == 'POST':
        selected = request.form.get('selected')
        ns_select = request.form.get('ns_select', session.get('ns_select', 'default'))
        
        if 'ns_select' in request.form:
            session['ns_select'] = ns_select
        
        # Redirect with query parameters so JavaScript can read them
        if selected:
            return redirect(url_for('storage.pvc_data', selected=selected, namespace=ns_select))
        else:
            # If no PVC name, just redirect to list
            return redirect(url_for('storage.pvc'))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/storage/pvcs/<name>
    return render_template('storage/pvc-data.html.j2', namespaces=namespaces)

##############################################################
## Persistent Volume
##############################################################

@storage_bp.route("/pv", methods=['GET', 'POST'])
@login_required
def pv():
    """
    Persistent Volumes list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/storage/pvs
    return render_template('storage/pv.html.j2', namespaces=namespaces)

@storage_bp.route('/pv/data', methods=['GET', 'POST'])
@login_required
def pv_data():
    """
    Persistent Volume detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests - redirect with query parameters
    if request.method == 'POST':
        selected = request.form.get('selected')
        ns_select = request.form.get('ns_select', session.get('ns_select', 'default'))
        
        if 'ns_select' in request.form:
            session['ns_select'] = ns_select
        
        # Redirect with query parameters so JavaScript can read them
        if selected:
            return redirect(url_for('storage.pv_data', selected=selected, namespace=ns_select))
        else:
            # If no PV name, just redirect to list
            return redirect(url_for('storage.pv'))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []
    
    # Template now loads data via JavaScript from /api/v1/storage/pvs/<name>
    return render_template('storage/pv-data.html.j2', namespaces=namespaces)

##############################################################
## Volume Snapshot
##############################################################

@storage_bp.route("/volumesnapshot", methods=['GET', 'POST'])
@login_required
def volumesnapshots():
    """
    Volume Snapshots list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/storage/volume-snapshots
    return render_template('storage/volumesnapshot.html.j2', namespaces=namespaces)

@storage_bp.route('/volumesnapshot/data', methods=['GET', 'POST'])
@login_required
def volumesnapshot_data():
    """
    Volume Snapshot detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests - redirect with query parameters
    if request.method == 'POST':
        selected = request.form.get('selected')
        ns_select = request.form.get('ns_select', session.get('ns_select', 'default'))
        
        if 'ns_select' in request.form:
            session['ns_select'] = ns_select
        
        # Redirect with query parameters so JavaScript can read them
        if selected:
            return redirect(url_for('storage.volumesnapshot_data', selected=selected, namespace=ns_select))
        else:
            # If no snapshot name, just redirect to list
            return redirect(url_for('storage.volumesnapshots'))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []
    
    # Template now loads data via JavaScript from /api/v1/storage/volume-snapshots/<name>
    return render_template('storage/volumesnapshot-data.html.j2', namespaces=namespaces)

##############################################################
## ConfigMap
##############################################################

@storage_bp.route("/configmap", methods=['GET', 'POST'])
@login_required
def configmap():
    """
    ConfigMaps list page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests for backward compatibility
    if request.method == 'POST':
        if 'ns_select' in request.form:
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/storage/configmaps
    return render_template('storage/configmap.html.j2', namespaces=namespaces)

@storage_bp.route('/configmap/data', methods=['GET', 'POST'])
@login_required
def configmap_data():
    """
    ConfigMap detail page.
    
    Data is now loaded client-side via JavaScript API calls.
    This route only renders the template structure.
    """
    # Handle POST requests - redirect with query parameters
    if request.method == 'POST':
        configmap_name = request.form.get('configmap_name')
        ns_select = request.form.get('ns_select', session.get('ns_select', 'default'))
        
        if 'ns_select' in request.form:
            session['ns_select'] = ns_select
        
        # Redirect with query parameters so JavaScript can read them
        if configmap_name:
            return redirect(url_for('storage.configmap_data', configmap_name=configmap_name, namespace=ns_select))
        else:
            # If no configmap name, just redirect to list
            return redirect(url_for('storage.configmap'))
    
    # Get namespaces for topbar selector
    user_token = get_user_token(session)
    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    namespaces = namespace_list if not error else []

    # Template now loads data via JavaScript from /api/v1/storage/configmaps/<name>
    return render_template('storage/configmap-data.html.j2', namespaces=namespaces)
