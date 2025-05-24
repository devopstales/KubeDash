from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import login_required

from lib.helper_functions import get_logger
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.other import k8sPriorityClassList
from lib.k8s.security import k8sPolicyListGet, k8sSecretListGet
from lib.sso import get_user_token

##############################################################
## Helpers
##############################################################

security = Blueprint("security", __name__, url_prefix="/security")
logger = get_logger()

##############################################################
# Security
##############################################################
## Secrets
##############################################################

@security.route("/secret", methods=['GET', 'POST'])
@login_required
def secrets():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        secrets = k8sSecretListGet(session['user_role'], user_token, session['ns_select'])
    else:
        secrets = list()

    return render_template(
        'security/secret.html.j2',
        secrets = secrets,
        namespaces = namespace_list,
        selected = selected,
    )

@security.route('/secret/data', methods=['GET', 'POST'])
@login_required
def secrets_data():
    if request.method == 'POST':
        secret_name = request.form.get('secret_name')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        secrets = k8sSecretListGet(session['user_role'], user_token, session['ns_select'])
        secret_data = None
        for secret in secrets:
            if secret["name"] == secret_name:
                secret_data = secret
        
        if secret_data:
            return render_template(
                'security/secret-data.html.j2',
                secret_data = secret_data,
                namespace = session['ns_select'],
            )
        else:
                flash("Cannot iterate SecretList", "danger")
                return redirect(url_for('.secrets'))
    else:
        return redirect(url_for('auth.login'))
    
##############################################################
## Network Policies
##############################################################

@security.route('/network-policy', methods=['GET', 'POST'])
@login_required
def policies_list():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        policies = k8sPolicyListGet(session['user_role'], user_token, session['ns_select'])
    else:
        policies = list()

    return render_template(
        'security/network-policy.html.j2',
        policies = policies,
        namespaces = namespace_list,
        selected = selected,
    )

@security.route('/network-policy/data', methods=['GET', 'POST'])
@login_required
def policies_data():
    if request.method == 'POST':
        policy_name = request.form.get('policy_name')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        policies =  k8sPolicyListGet(session['user_role'], user_token, session['ns_select'])
        policy_data = None
        for policy in policies:
            if policy["name"] == policy_name:
                policy_data = policy

        if policy_data:
            return render_template(
                'security/network-policy-data.html.j2',
                policy_data = policy_data,
                namespace = session['ns_select'],
            )
        else:
                flash("Cannot iterate PolicyList", "danger")
                return redirect(url_for('.policies_list'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
## PriorityClass
##############################################################
@security.route('/priorityclass', methods=['GET', 'POST'])
@login_required
def priorityclass_list():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    priorityclass = k8sPriorityClassList(session['user_role'], user_token)

    return render_template(
        'security/priorityclass.html.j2',
        priorityclass = priorityclass,
        selected = selected,
    )

@security.route('/priorityclass/data', methods=['GET', 'POST'])
@login_required
def priorityclass_data():
    if request.method == 'POST':
        pc_name = request.form.get('pc_name')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        priorityclass = k8sPriorityClassList(session['user_role'], user_token)
        pc_data = None
        for pc in priorityclass:
            if pc["name"] == pc_name:
                pc_data = pc

        if pc_data:
            return render_template(
                'security/priorityclass-data.html.j2',
                pc_data = pc_data,
                namespace = session['ns_select'],
            )
        else:
                flash("Cannot iterate PriorityClassList", "danger")
                return redirect(url_for('.priorityclass_list'))
    else:
        return redirect(url_for('auth.login'))
