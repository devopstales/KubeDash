#!/usr/bin/env python3

from flask import (Blueprint, app, redirect, render_template, request, session,
                   url_for)
from flask_login import login_required

from lib.helper_functions import get_logger, is_valid_url, ErrorHandler

from .helpers import init_applications, local_app, update_security_policies
from .application import ApplicationGet

##############################################################
## variables
##############################################################

application_catalog_bp = Blueprint("app_catalog", __name__, url_prefix="/plugins/app-catalog", \
    template_folder="templates")
logger = get_logger()

application_list = [
    {
        'name': 'Kubeview',
        'url': 'https://kubeview.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'p3x-redis-ui',
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
        'name': 'Jaeger',
        'url': 'https://jaeger.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'Kyverno',
        'url': 'https://kyverno.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'Prometheus',
        'url': 'https://prometheus.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'Grafana',
        'url': 'https://grafana.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'Jira',
        'url': 'https://jira.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'Confluence',
        'url': 'https://confluence.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'DefectDojo',
        'url': 'https://defectdojo.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'DependencyTrack',
        'url': 'https://dependencytrack.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'SonarQube',
        'url': 'https://sonarqube.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'Nexus',
        'url': 'https://nexus.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'ArgoCD',
        'url': 'https://argocd.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'Kibana',
        'url': 'https://kibana.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'Harbor',
        'url': 'https://harbor.example.com',
        'icon': '',
        'enable': True,
    },
    {
        'name': 'GitLab',
        'url': 'https://gitlab.example.com',
        'icon': '',
        'enable': True
    }
]


            
# Thread-safe initialization flag
_initialized = False

@application_catalog_bp.before_app_request
def initialize_on_first_request():
    """Initialize plugin data on first request"""
    global _initialized
    if not _initialized:
        try:
            app_config = local_app.config['kubedash.ini']
        except KeyError as error:
            app_config = {}
            ErrorHandler(logger, error, "Initialize application catalog: - %s" % error.status)

        for app_info in application_list:
            app_name = app_info['name']
            
            if app_name in app_config['plugin_settings']:
                app_info['enable'] = app_config['plugin_settings'].getboolean(app_name, fallback=False)
            
            
            section_name = f'plugin_settings.{app_name}'
            if section_name in app_config:
                app_url = app_config[section_name].get('url')
                if app_url and is_valid_url(app_url):
                    app_info['url'] = app_url
                    app_info['icon'] = app_config[section_name].get('icon', app_info['icon'])
                    app_info['enable'] = app_config[section_name].getboolean('enable', fallback=app_info.get('enable', False))                    
        with local_app.app_context():
            init_applications(application_list)
            update_security_policies(local_app, application_list)


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
# Service Catalog Routes
##############################################################

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
