"""
KubeDash Flask Blueprints

Central registration point for all blueprints.
"""

from blueprint.api_base import api_bp
from blueprint.api import api_v1_bp
from blueprint.auth import auth_bp
from blueprint.cluster import cluster_bp
from blueprint.cluster_permission import cluster_permission_bp
from blueprint.dashboard import dashboard_bp
from blueprint.extension_api import extension_api_bp
from blueprint.extension_root import extension_root_bp
from blueprint.history import history_bp
from blueprint.metrics import metrics_bp
from blueprint.network import network_bp
from blueprint.other_resources import other_resources_bp
from blueprint.security import security_bp
from blueprint.settings import settings_bp, sso_bp
from blueprint.storage import storage_bp
from blueprint.user import users_bp
from blueprint.workload import workload_bp

__all__ = [
    'api_bp',
    'api_v1_bp',
    'auth_bp',
    'cluster_bp',
    'cluster_permission_bp',
    'dashboard_bp',
    'extension_api_bp',
    'extension_root_bp',
    'history_bp',
    'metrics_bp',
    'network_bp',
    'other_resources_bp',
    'security_bp',
    'settings_bp',
    'sso_bp',
    'storage_bp',
    'users_bp',
    'workload_bp',
]


def register_all_blueprints(app):
    """Register all blueprints with the Flask app.
    
    Args:
        app: Flask application instance
    """
    from lib.components import api_doc
    
    app.logger.info("Initialize blueprints")
    
    # Main API blueprints
    api_doc.register_blueprint(api_bp)
    api_doc.register_blueprint(api_v1_bp)
    
    # Core blueprints
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
    
    # Kubernetes Extension API Server blueprint
    api_doc.register_blueprint(extension_api_bp)
    
    # Root-level endpoints for Kubernetes API aggregation
    app.register_blueprint(extension_root_bp)
