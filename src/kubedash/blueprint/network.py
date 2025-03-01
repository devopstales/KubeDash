from flask import Blueprint, request, session,render_template, redirect, url_for, flash
from flask_login import login_required

from lib.sso import get_user_token
from lib.k8s.namespace import k8sNamespaceListGet
from lib.k8s.network import k8sIngressClassListGet, k8sIngressListGet, \
    k8sServiceListGet, k8sPodSelectorListGet

from lib.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

network = Blueprint("network", __name__, url_prefix="/network")
logger = get_logger()

##############################################################
# Network
##############################################################
## Ingress Class
##############################################################

@network.route("/ingress-class", methods=['GET', 'POST'])
@login_required
def ingresses_class():
    selected = None
    user_token = get_user_token(session)

    if request.method == 'POST':
        selected = request.form.get('selected')

    ingresses_classes = k8sIngressClassListGet(session['user_role'], user_token)

    return render_template(
        'network/ingress-class.html.j2',
        ingresses_classes = ingresses_classes,
        selected = selected,
    )

@network.route('/ingress-class/data', methods=['GET', 'POST'])
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
                'network/ingress-class-data.html.j2',
                ic_data = ic_data
            )
        else:
                flash("Cannot iterate IngressClassList", "danger")
                return redirect(url_for('.ingresses_class'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
## Ingresses
##############################################################

@network.route("/ingress", methods=['GET', 'POST'])
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
        'network/ingress.html.j2',
        namespaces = namespace_list,
        ingresses = ingresses,
        selected = selected,
    )

@network.route('/ingress/data', methods=['GET', 'POST'])
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
                'network/ingress-data.html.j2',
                i_data = i_data
            )
        else:
                flash("Cannot iterate IngressList", "danger")
                return redirect(url_for('.ingresses'))
    else:
        return redirect(url_for('auth.login'))

##############################################################
# Service
##############################################################

@network.route("/service", methods=['GET', 'POST'])
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
      'network/service.html.j2',
        services = services,
        namespaces = namespace_list,
        selected = selected,
    )

@network.route('/service/data', methods=['GET', 'POST'])
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
          'network/service-data.html.j2',
            service_data = service_data,
            namespace = session['ns_select'],
            pod_list = pod_list,
        )
    else:
        return redirect(url_for('auth.login'))
