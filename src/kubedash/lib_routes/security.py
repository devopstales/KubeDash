from flask import Blueprint, request, session,render_template, redirect, url_for, flash
from flask_login import login_required

from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNamespaceListGet, k8sSecretListGet, k8sPolicyListGet, \
    k8sPriorityClassList

from lib_functions.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

security = Blueprint("security", __name__)
logger = get_logger(__name__.split(".")[1])


##############################################################
# Security
##############################################################
## Secrets
##############################################################

@security.route("/secrets", methods=['GET', 'POST'])
@login_required
def secrets():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        secrets = k8sSecretListGet(session['user_role'], user_token, session['ns_select'])
    else:
        secrets = list()

    return render_template(
        'secrets.html.j2',
        secrets = secrets,
        namespaces = namespace_list,
        selected = selected,
    )

@security.route('/secrets/data', methods=['GET', 'POST'])
@login_required
def secrets_data():
    if request.method == 'POST':
        secret_name = request.form.get('secret_name')
        session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        secrets = k8sSecretListGet(session['user_role'], user_token, session['ns_select'])
        secret_data = None
        for secret in secrets:
            if secret["name"] == secret_name:
                secret_data = secret
        
        if secret_data:
            return render_template(
                'secret-data.html.j2',
                secret_data = secret_data,
                namespace = session['ns_select'],
            )
        else:
                flash("Cannot iterate SecretList", "danger")
                return redirect(url_for('security.secrets'))
    else:
        return redirect(url_for('security.login'))
    
##############################################################
## Network Policies
##############################################################

@security.route('/policies', methods=['GET', 'POST'])
@login_required
def policies_list():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    if not error:
        policies = k8sPolicyListGet(session['user_role'], user_token, session['ns_select'])
    else:
        policies = list()

    return render_template(
        'policies.html.j2',
        policies = policies,
        namespaces = namespace_list,
        selected = selected,
    )

@security.route('/policies/data', methods=['GET', 'POST'])
@login_required
def policies_data():
    if request.method == 'POST':
        policy_name = request.form.get('policy_name')
        session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        policies =  k8sPolicyListGet(session['user_role'], user_token, session['ns_select'])
        policy_data = None
        for policy in policies:
            if policy["name"] == policy_name:
                policy_data = policy

        if policy_data:
            return render_template(
                'policy-data.html.j2',
                policy_data = policy_data,
                namespace = session['ns_select'],
            )
        else:
                flash("Cannot iterate PolicyList", "danger")
                return redirect(url_for('security.policies_list'))
    else:
        return redirect(url_for('security.login'))

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
        'priorityclass.html.j2',
        priorityclass = priorityclass,
        selected = selected,
    )

@security.route('/priorityclass/data', methods=['GET', 'POST'])
@login_required
def priorityclass_data():
    if request.method == 'POST':
        pc_name = request.form.get('pc_name')
        session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        priorityclass = k8sPriorityClassList(session['user_role'], user_token)
        pc_data = None
        for pc in priorityclass:
            if pc["name"] == pc_name:
                pc_data = pc

        if pc_data:
            return render_template(
                'priorityclass-data.html.j2',
                pc_data = pc_data,
                namespace = session['ns_select'],
            )
        else:
                flash("Cannot iterate PriorityClassList", "danger")
                return redirect(url_for('security.priorityclass_list'))
    else:
        return redirect(url_for('security.login'))
