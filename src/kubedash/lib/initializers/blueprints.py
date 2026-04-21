#!/usr/bin/env python3
"""Blueprint registration for KubeDash."""

from flask import Flask


def initialize_blueprints(app: Flask):
    """Initialize blueprints"""
    from blueprint.api_base import api_bp  # Main API blueprint (ping, health, debug)
    from blueprint.api import api_v1_bp  # API v1 blueprint (all resource endpoints)
    from blueprint.auth import auth_bp
    from blueprint.cluster import cluster_bp
    from blueprint.cluster_permission import cluster_permission_bp
    from blueprint.dashboard import dashboard_bp
    from blueprint.extension_api import extension_api_bp
    from blueprint.metrics import metrics_bp
    from blueprint.network import network_bp
    from blueprint.other_resources import other_resources_bp
    from blueprint.security import security_bp
    from blueprint.settings import settings_bp, sso_bp
    from blueprint.storage import storage_bp
    from blueprint.user import users_bp
    from blueprint.workload import workload_bp
    from blueprint.history import history_bp
    from lib.components import api_doc

    app.logger.info("Initialize blueprints")
    #app.register_blueprint(api_bp)
    api_doc.register_blueprint(api_bp)  # Main API blueprint (ping, health, debug)
    api_doc.register_blueprint(api_v1_bp)  # API v1 blueprint (all resource endpoints)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(history_bp)

    app.register_blueprint(auth_bp)
    app.register_blueprint(sso_bp)

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(cluster_permission_bp)
    app.register_blueprint(cluster_bp)
    app.register_blueprint(workload_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(storage_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(other_resources_bp)
    app.register_blueprint(settings_bp)

    from lib.components import csrf
    from blueprint.api.kdlogin import kdlogin_api_bp

    csrf.exempt(kdlogin_api_bp)

    # Kubernetes Extension API Server blueprint
    app.logger.info("Initialize Extension API blueprint")
    api_doc.register_blueprint(extension_api_bp)

    # Root-level endpoints for Kubernetes API aggregation (openapi, healthz)
    from blueprint.extension_root import extension_root_bp
    app.register_blueprint(extension_root_bp)


def initialize_commands(app: Flask):
    """Initialize commands"""
    from lib.commands import cli
    app.register_blueprint(cli)
