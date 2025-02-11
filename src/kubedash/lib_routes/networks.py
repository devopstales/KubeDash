from flask import Blueprint, request, session,render_template, redirect, url_for, flash
from flask_login import login_required

from lib_functions.sso import get_user_token
from lib_functions.k8s import k8sNamespaceListGet, k8sIngressClassListGet, k8sIngressListGet, \
    k8sServiceListGet, k8sPodSelectorListGet

from lib_functions.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

networks = Blueprint("networks", __name__)
logger = get_logger()

##############################################################
# Network
##############################################################
## Ingress Class
##############################################################

@networks.route("/ingress-class", methods=['GET', 'POST'])
@login_required
def ingresses_class():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    ingresses_classes = k8sIngressClassListGet(session['user_role'], user_token)

    return render_template(
        'ingress-classes.html.j2',
        ingresses_classes = ingresses_classes,
        selected = selected,
    )

@networks.route('/ingress-class/data', methods=['GET', 'POST'])
@login_required
def ingresses_class_data():
    if request.method == 'POST':
        ic_name = request.form.get('ic_name')

        user_token = get_user_token(session)

        ingresses_classes = k8sIngressClassListGet(session['user_role'], user_token)
        ic_data = None
        for ic in ingresses_classes:
            if ic["name"] == ic_name:
                ic_data = ic

        if ic_data:
            return render_template(
                'ingress-class-data.html.j2',
                ic_data = ic_data
            )
        else:
                flash("Cannot iterate IngressClassList", "danger")
                return redirect(url_for('networks.ingresses_class'))
    else:
        return redirect(url_for('networks.login'))

##############################################################
## Ingresses
##############################################################

@networks.route("/ingress", methods=['GET', 'POST'])
@login_required
def ingresses():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    ingresses = k8sIngressListGet(session['user_role'], user_token, session['ns_select'])

    return render_template(
        'ingress.html.j2',
        namespaces = namespace_list,
        ingresses = ingresses,
        selected = selected,
    )

@networks.route('/ingress/data', methods=['GET', 'POST'])
@login_required
def ingresses_data():
    if request.method == 'POST':
        i_name = request.form.get('i_name')
        user_token = get_user_token(session)

        ingresses = k8sIngressListGet(session['user_role'], user_token, session['ns_select'])
        i_data = None
        for i in ingresses:
            if i["name"] == i_name:
                i_data = i

        if i_data:
            return render_template(
                'ingress-data.html.j2',
                i_data = i_data
            )
        else:
                flash("Cannot iterate IngressList", "danger")
                return redirect(url_for('networks.ingresses'))
    else:
        return redirect(url_for('networks.login'))

##############################################################
# Service
##############################################################

@networks.route("/services", methods=['GET', 'POST'])
@login_required
def services():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')
        selected = request.form.get('selected')

    namespace_list, error = k8sNamespaceListGet(session['user_role'], user_token)
    services = k8sServiceListGet(session['user_role'], user_token, session['ns_select'])

    return render_template(
      'services.html.j2',
        services = services,
        namespaces = namespace_list,
        selected = selected,
    )

@networks.route('/services/data', methods=['GET', 'POST'])
@login_required
def services_data():
    pod_list = None
    if request.method == 'POST':
        service_name = request.form.get('service_name')
        if request.form.get('ns_select', None):
            session['ns_select'] = request.form.get('ns_select')

        user_token = get_user_token(session)

        services = k8sServiceListGet(session['user_role'], user_token, session['ns_select'])
        for service in services:
            if service["name"] == service_name:
                service_data = service
        if service_data["selector"]:
            pod_list = k8sPodSelectorListGet(session['user_role'], user_token, session['ns_select'], service_data["selector"])

        return render_template(
          'service-data.html.j2',
            service_data = service_data,
            namespace = session['ns_select'],
            pod_list = pod_list,
        )
    else:
        return redirect(url_for('networks.login'))
