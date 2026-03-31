"""
KubeDash REST API

Main API blueprint that registers all sub-blueprints for organized API endpoints.
All resource requests (K8s objects, users, settings, etc.) are served under /api/v1/
"""

from flask_smorest import Blueprint

from lib.helper_functions import get_logger

##############################################################
## Main API Blueprint
##############################################################

api_v1_bp = Blueprint(
    "api_v1",
    "api_v1",
    url_prefix="/api/v1",
    description="KubeDash REST API v1 - Unified API for all resource operations including Kubernetes objects, user management, settings, and plugins"
)

logger = get_logger()

##############################################################
## Register Sub-Blueprints
##############################################################

# Kubernetes Resources
from blueprint.api.cluster import cluster_api_bp
from blueprint.api.workloads import workloads_api_bp
from blueprint.api.network import network_api_bp
from blueprint.api.storage import storage_api_bp
from blueprint.api.security import security_api_bp
from blueprint.api.nodes import nodes_api_bp
from blueprint.api.namespaces import namespaces_api_bp
from blueprint.api.rbac import rbac_api_bp
from blueprint.api.other_resources import other_resources_api_bp

# Application Resources
from blueprint.api.users import users_api_bp
from blueprint.api.settings import settings_api_bp
from blueprint.api.audit import audit_api_bp

# Register all sub-blueprints
api_v1_bp.register_blueprint(cluster_api_bp)
api_v1_bp.register_blueprint(workloads_api_bp)
api_v1_bp.register_blueprint(network_api_bp)
api_v1_bp.register_blueprint(storage_api_bp)
api_v1_bp.register_blueprint(security_api_bp)
api_v1_bp.register_blueprint(nodes_api_bp)
api_v1_bp.register_blueprint(namespaces_api_bp)
api_v1_bp.register_blueprint(rbac_api_bp)
api_v1_bp.register_blueprint(other_resources_api_bp)

api_v1_bp.register_blueprint(users_api_bp)
api_v1_bp.register_blueprint(settings_api_bp)
api_v1_bp.register_blueprint(audit_api_bp)

# Note: Plugin API blueprints are dynamically loaded in lib/initializers.initialize_plugin_apis()

