#!/usr/bin/env python3

from flask import (Blueprint, request, Response, current_app, abort, render_template, 
                   request, make_response)
import requests
from urllib.parse import urlparse, urljoin
from flask_login import login_required

from lib.helper_functions import get_logger, is_valid_url, ErrorHandler

from .helpers import init_applications, update_security_policies
from .application import ApplicationGet

##############################################################
## variables
##############################################################

application_catalog_bp = Blueprint(
    "app_catalog", 
    __name__, 
    url_prefix="/plugins/app-catalog", \
    template_folder="templates"
)

logger = get_logger()

application_list = [
    {
        'name': 'kubeview',
        'url': 'https://kubeview.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'redis-ui',
        'url': 'https://p3x-redis-ui.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'pgweb',
        'url': 'https://pgweb.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'jaeger',
        'url': 'https://jaeger.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'cilium',
        'url': 'https://cilium.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'kyverno',
        'url': 'https://kyverno.example.com',
        'icon': '',
        'enable': True,
    },
#    {
#        'name': 'Prometheus',
#        'url': 'https://prometheus.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'Grafana',
#        'url': 'https://grafana.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'Jira',
#        'url': 'https://jira.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'Confluence',
#        'url': 'https://confluence.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'DefectDojo',
#        'url': 'https://defectdojo.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'DependencyTrack',
#        'url': 'https://dependencytrack.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'SonarQube',
#        'url': 'https://sonarqube.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'Nexus',
#        'url': 'https://nexus.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'ArgoCD',
#        'url': 'https://argocd.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'Kibana',
#        'url': 'https://kibana.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'Harbor',
#        'url': 'https://harbor.example.com',
#        'icon': '',
#        'enable': True,
#    },
#    {
#        'name': 'GitLab',
#        'url': 'https://gitlab.example.com',
#        'icon': '',
#        'enable': True
#    }
]


            
# Thread-safe initialization flag
_initialized = False

"""
To enbedd applications to the page the urls shoud be in the Content Security Policy.
So we need to update Talisman Content Security Policy after it is started.
This soud be done in a weri early stage of the application initialization.
This is done in the `initialize_application_catalog` function.
This function is called when the application is first loaded.
It will read the application configuration from the `kubedash.ini` file and update the application
catalog accordingly.

Normally Flask app object is not accessible in the module scope,
so we use `state.app` to access it. Than we can use `app.before_request`
to ensure that the application catalog is initialized only once,
and only when the application is first requested.
This way we can ensure that the application catalog is initialized with the proper application context.
"""
def initialize_application_catalog(app):
    """Initialize plugin data with proper application context"""
    
    @app.before_request
    def initialize_on_first_request():
        global _initialized
        if not _initialized:
            # Ensure we're working within application context
            with app.app_context():
                try:
                    app_config = app.config['kubedash.ini']
                except KeyError as error:
                    app_config = {}
                    ErrorHandler(logger, error, f"Initialize application catalog: - {error}")

                for app_info in application_list:
                    app_name = app_info['name']
                    
                    if 'plugin_settings' in app_config and app_name in app_config['plugin_settings']:
                        app_info['enable'] = app_config['plugin_settings'].getboolean(
                            app_name, fallback=False)
                    
                    section_name = f'plugin_settings.{app_name}'
                    if section_name in app_config:
                        app_url = app_config[section_name].get('url')
                        if app_url and is_valid_url(app_url):
                            app_info['url'] = app_url
                            app_info['icon'] = app_config[section_name].get('icon', app_info['icon'])
                            app_info['enable'] = app_config[section_name].getboolean(
                                'enable', fallback=app_info.get('enable', False))
                
                init_applications(application_list)
                #update_security_policies(app, application_list)
                
                _initialized = True
        
# Apps:      
## Kubeview
## p3x-redis-ui
## pgweb
## Jaeger

## Kyverno
## Prometheus
## Grafana

## Jira
## Confluence
## DefectDojo
## DependencyTrack
## SonarQube
## Nexus
## ArgoCD
## Kibana
## Harbor
## GitLab
## Jenkins
## Keycloak
## Tekton

##############################################################

@application_catalog_bp.record_once
def on_load(state):
    """Run initialization when blueprint is registered"""
    # Create app context explicitly to be safe
    with state.app.app_context():
        initialize_application_catalog(state.app)

##############################################################
# Service Catalog Routes
###############################################################

@application_catalog_bp.route('/kubeview', methods=['GET'])
@login_required
def kubeview():
    app_url = None
    app_object = ApplicationGet('Kubeview')
    
    if app_object.application_enabled:
        app_url = app_object.application_url
    
    return render_template(
        'app_embed.html.j2',
        app_url=app_url,
    )
    
@application_catalog_bp.route('/pgweb', methods=['GET'])
@login_required
def pgweb():
    app_url = None
    app_object = ApplicationGet('pgweb')
    
    if app_object.application_enabled:
        app_url = app_object.application_url
    
    return render_template(
        'app_embed.html.j2',
        app_url=app_url,
    )
    
@application_catalog_bp.route('/p3x-redis-ui', methods=['GET'])
@login_required
def p3x_redis_ui():
    app_url = None
    app_object = ApplicationGet('p3x-redis-ui')
    
    if app_object.application_enabled:
        app_url = app_object.application_url
    
    return render_template(
        'app_embed.html.j2',
        app_url=app_url,
    )  