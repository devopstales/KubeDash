#!/usr/bin/env python3

from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    url_for,
)
import re
from flask_login import login_required

from lib.helper_functions import get_logger, is_valid_url, ErrorHandler

from .helpers import application_links_init, update_security_policies, discover_ingress_applications, discover_service_applications
from .application import ApplicationGet

##############################################################
## variables
##############################################################

application_catalog_bp = Blueprint(
    "app_catalog", 
    __name__, 
    url_prefix="/plugins/app-catalog", 
    template_folder="templates"
)

logger = get_logger()

"""
To embed applications to the page the urls should be in the Content Security Policy.
So we need to update Talisman Content Security Policy after it is started.
This should be done after the database and Talisman are initialized.
This is done in the `initialize_application_catalog` function.
This function is called on the first request after everything is initialized.
It will read the application configuration from the `kubedash.ini` file and update the application
catalog accordingly, syncing the database with the config file.
"""
_initialized = False

def initialize_application_catalog(app):
    """Initialize plugin data with proper application context - runs on first request"""
    global _initialized
    if _initialized:
        return
    
    # Ensure we're working within application context
    with app.app_context():
        try:
            # Check if database is initialized
            from lib.components import db
            if not hasattr(db, 'engine') or db.engine is None:
                logger.warning("Database not initialized yet, skipping application catalog init")
                return
            
            app_config = app.config.get('kubedash.ini')
            if not app_config:
                logger.warning("kubedash.ini config not found")
                return
        except Exception as error:
            ErrorHandler(logger, error, f"Initialize application catalog: - {error}")
            return

        try:
            # Sync database with config file
            application_links_init(app_config)
            
            # Discover and register ingresses with application-catalog annotation
            discover_ingress_applications()
            
            # Discover and register services with application-catalog annotation
            discover_service_applications()
            
            # Build applications list for CSP update from all sources (config + discovered ingresses)
            # Get all enabled applications from database (includes both config and discovered)
            from .application import ApplicationListGet
            all_apps = ApplicationListGet(enabled_only=True)
            applications = []
            for app_obj in all_apps:
                applications.append({
                    "name": app_obj.application_name,
                    "url": app_obj.application_url,
                    "enable": app_obj.application_enabled,
                    "embed": app_obj.application_embedded,
                })

            # Update CSP with embedded applications
            update_security_policies(app, applications)
            
            _initialized = True
            logger.info("Application catalog initialized and synced with config")
        except Exception as error:
            ErrorHandler(logger, error, f"Error in application catalog initialization: {error}")
        
##############################################################

@application_catalog_bp.record_once
def on_load(state):
    """Register initialization to run on first request after everything is ready"""
    @state.app.before_request
    def init_on_first_request():
        initialize_application_catalog(state.app)

##############################################################
# Settings Route
###############################################################

@application_catalog_bp.route('/settings', methods=['GET'])
@login_required
def settings():
    """Application catalog settings page"""
    return render_template('application_catalog/applications.html.j2')

##############################################################
# Embedded App Routes
###############################################################

def _render_app_embed(app_name):
    app_url = None
    embed_mode = False
    app_object = ApplicationGet(app_name)

    if app_object and app_object.application_url:
        embed_mode = bool(app_object.application_enabled and app_object.application_embedded)
        if embed_mode and current_app.config.get("plugins", {}).get("iframe_proxy"):
            app_url = url_for("iframe_proxy.proxy_app", app_name=app_name, path="")
        else:
            app_url = app_object.application_url

    return render_template(
        "application_catalog/app_embed.html.j2",
        app_url=app_url,
        embed_mode=embed_mode,
        app_name=app_object.application_name if app_object else app_name,
    )


@application_catalog_bp.route('/<app_name>', methods=['GET'])
@application_catalog_bp.route('/<app_name>/', methods=['GET'])
@login_required
def embedded_app(app_name):
    app_object = ApplicationGet(app_name)
    
    # If app is not embedded, redirect directly to the URL
    if app_object and app_object.application_url:
        if not (app_object.application_enabled and app_object.application_embedded):
            return redirect(app_object.application_url)
    
    return _render_app_embed(app_name)
