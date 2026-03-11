"""
Registry API endpoints for OCI registry management.
"""

from contextlib import nullcontext
from flask import g, jsonify, request, session
from flask.views import MethodView
from flask_login import current_user, login_required
from flask_smorest import Blueprint
from itsdangerous import base64_decode, base64_encode

from lib.audit import log_audit_event
from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer
from .registry_server import (
    RegistryServerCreate, RegistryServerDelete, RegistryServerListGet,
    RegistryServerUpdate, RegistrySererGet
)

##############################################################
## Blueprint Definition
##############################################################

registry_api_bp = Blueprint(
    "registry_api",
    "registry_api",
    url_prefix="/registry",
    description="Registry API endpoints - Manage OCI registry servers"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Registry Servers
##############################################################

@registry_api_bp.route('')
class RegistryServersResource(MethodView):
    """
    Registry servers list endpoint.
    """
    
    @registry_api_bp.response(200, description="Successfully retrieved registry servers list")
    @registry_api_bp.doc(tags=['Plugins API - Registry'])
    @login_required
    def get(self):
        """
        List all registry servers
        
        Returns:
            dict: List of registry servers with metadata
        """
        with tracer.start_as_current_span(
            "registry-servers-list",
            attributes={
                "http.route": "/api/v1/plugins/registry",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            registries = RegistryServerListGet()
            
            # Convert to list of dictionaries
            registries_data = []
            for registry in registries:
                registry_data = {
                    "registry_server_url": registry.registry_server_url,
                    "registry_server_port": registry.registry_server_port,
                    "registry_server_auth": registry.registry_server_auth,
                    "registry_server_tls": registry.registry_server_tls,
                    "insecure_tls": registry.insecure_tls,
                }
                
                # Decode auth token if present (for editing)
                if registry.registry_server_auth and registry.registry_server_auth_token:
                    try:
                        decoded = str(base64_decode(registry.registry_server_auth_token), 'UTF-8')
                        if ':' in decoded:
                            username, password = decoded.split(':', 1)
                            registry_data["registry_server_auth_user"] = username
                            # Don't return password for security - will be optional on edit
                    except Exception as e:
                        logger.warning(f"Failed to decode auth token: {e}")
                
                registries_data.append(registry_data)
            
            return jsonify({
                "data": registries_data,
                "metadata": {
                    "count": len(registries_data)
                }
            })
    
    @registry_api_bp.response(201, description="Successfully created registry server")
    @registry_api_bp.response(400, description="Bad request - Invalid input")
    @registry_api_bp.doc(tags=['Plugins API - Registry'])
    @login_required
    def post(self):
        """
        Create a new registry server
        
        Request Body:
            dict: Registry server data:
                {
                    "registry_server_url": str (required),
                    "registry_server_port": str (required),
                    "registry_server_tls": bool (default: False),
                    "insecure_tls": bool (default: False),
                    "registry_server_auth_user": str (optional),
                    "registry_server_auth_pass": str (optional)
                }
        
        Returns:
            dict: Created registry server information
        """
        data = request.get_json() or {}
        
        registry_server_url = data.get('registry_server_url')
        registry_server_port = data.get('registry_server_port')
        registry_server_tls = data.get('registry_server_tls', False)
        insecure_tls = data.get('insecure_tls', False)
        registry_server_auth_user = data.get('registry_server_auth_user')
        registry_server_auth_pass = data.get('registry_server_auth_pass')
        
        registry_server_auth = bool(registry_server_auth_user and registry_server_auth_pass)
        
        if not registry_server_url or not registry_server_port:
            return jsonify({
                "error": "BadRequest",
                "message": "registry_server_url and registry_server_port are required"
            }), 400
        
        try:
            RegistryServerCreate(
                registry_server_url, registry_server_port, registry_server_auth,
                registry_server_tls, insecure_tls, registry_server_auth_user,
                registry_server_auth_pass
            )
            
            return jsonify({
                "message": "Registry server created successfully",
                "data": {
                    "registry_server_url": registry_server_url,
                    "registry_server_port": registry_server_port
                }
            }), 201
        except Exception as e:
            logger.error(f"Error creating registry server: {e}")
            return jsonify({
                "error": "InternalServerError",
                "message": f"Failed to create registry server: {str(e)}"
            }), 500


@registry_api_bp.route('/<path:registry_server_url>')
class RegistryServerResource(MethodView):
    """
    Individual registry server endpoint.
    """
    
    @registry_api_bp.response(200, description="Successfully retrieved registry server")
    @registry_api_bp.response(404, description="Registry server not found")
    @registry_api_bp.doc(tags=['Plugins API - Registry'])
    @login_required
    def get(self, registry_server_url):
        """
        Get registry server details
        
        Path Parameters:
            registry_server_url (str): URL of the registry server
        
        Returns:
            dict: Registry server details
        """
        registry = RegistrySererGet(registry_server_url)
        
        if not registry:
            return jsonify({
                "error": "NotFound",
                "message": f"Registry server '{registry_server_url}' not found"
            }), 404
        
        registry_data = {
            "registry_server_url": registry.registry_server_url,
            "registry_server_port": registry.registry_server_port,
            "registry_server_auth": registry.registry_server_auth,
            "registry_server_tls": registry.registry_server_tls,
            "insecure_tls": registry.insecure_tls,
        }
        
        # Decode auth token if present
        if registry.registry_server_auth and registry.registry_server_auth_token:
            try:
                decoded = str(base64_decode(registry.registry_server_auth_token), 'UTF-8')
                if ':' in decoded:
                    username, password = decoded.split(':', 1)
                    registry_data["registry_server_auth_user"] = username
            except Exception as e:
                logger.warning(f"Failed to decode auth token: {e}")
        
        return jsonify({
            "data": registry_data
        })
    
    @registry_api_bp.response(200, description="Successfully updated registry server")
    @registry_api_bp.response(400, description="Bad request - Invalid input")
    @registry_api_bp.response(404, description="Registry server not found")
    @registry_api_bp.doc(tags=['Plugins API - Registry'])
    @login_required
    def put(self, registry_server_url):
        """
        Update registry server
        
        Path Parameters:
            registry_server_url (str): Current URL of the registry server (old URL)
        
        Request Body:
            dict: Registry server update data:
                {
                    "registry_server_url": str (required),
                    "registry_server_port": str (required),
                    "registry_server_tls": bool (default: False),
                    "insecure_tls": bool (default: False),
                    "registry_server_auth_user": str (optional),
                    "registry_server_auth_pass": str (optional) - only required if changing auth
                }
        
        Returns:
            dict: Updated registry server information
        """
        data = request.get_json() or {}
        
        new_registry_server_url = data.get('registry_server_url')
        registry_server_port = data.get('registry_server_port')
        registry_server_tls = data.get('registry_server_tls', False)
        insecure_tls = data.get('insecure_tls', False)
        registry_server_auth_user = data.get('registry_server_auth_user')
        registry_server_auth_pass = data.get('registry_server_auth_pass')
        
        if not new_registry_server_url or not registry_server_port:
            return jsonify({
                "error": "BadRequest",
                "message": "registry_server_url and registry_server_port are required"
            }), 400
        
        # Check if old registry exists
        old_registry = RegistrySererGet(registry_server_url)
        if not old_registry:
            return jsonify({
                "error": "NotFound",
                "message": f"Registry server '{registry_server_url}' not found"
            }), 404
        
        # Determine auth status
        # If auth_user and auth_pass provided, use them
        # If not provided but auth was enabled, keep existing auth
        registry_server_auth = bool(registry_server_auth_user and registry_server_auth_pass)
        if not registry_server_auth and old_registry.registry_server_auth:
            # Keep existing auth if not changing
            registry_server_auth = True
            if old_registry.registry_server_auth_token:
                try:
                    decoded = str(base64_decode(old_registry.registry_server_auth_token), 'UTF-8')
                    if ':' in decoded:
                        registry_server_auth_user, registry_server_auth_pass = decoded.split(':', 1)
                except Exception as e:
                    logger.warning(f"Failed to decode existing auth token: {e}")
        
        try:
            RegistryServerUpdate(
                new_registry_server_url, registry_server_url, registry_server_port,
                registry_server_auth, registry_server_tls, insecure_tls,
                registry_server_auth_user, registry_server_auth_pass
            )
            
            return jsonify({
                "message": "Registry server updated successfully",
                "data": {
                    "registry_server_url": new_registry_server_url,
                    "registry_server_port": registry_server_port
                }
            })
        except Exception as e:
            logger.error(f"Error updating registry server: {e}")
            return jsonify({
                "error": "InternalServerError",
                "message": f"Failed to update registry server: {str(e)}"
            }), 500
    
    @registry_api_bp.response(200, description="Successfully deleted registry server")
    @registry_api_bp.response(404, description="Registry server not found")
    @registry_api_bp.doc(tags=['Plugins API - Registry'])
    @login_required
    def delete(self, registry_server_url):
        """
        Delete registry server
        
        Path Parameters:
            registry_server_url (str): URL of the registry server to delete
        
        Returns:
            dict: Deletion confirmation
        """
        registry = RegistrySererGet(registry_server_url)
        
        if not registry:
            return jsonify({
                "error": "NotFound",
                "message": f"Registry server '{registry_server_url}' not found"
            }), 404
        
        try:
            RegistryServerDelete(registry_server_url)
            
            return jsonify({
                "message": "Registry server deleted successfully"
            })
        except Exception as e:
            logger.error(f"Error deleting registry server: {e}")
            return jsonify({
                "error": "InternalServerError",
                "message": f"Failed to delete registry server: {str(e)}"
            }), 500


##############################################################
## Registry Images
##############################################################

@registry_api_bp.route('/<path:registry_server_url>/images')
class RegistryImagesResource(MethodView):
    """
    Registry images (repositories) endpoint.
    """
    
    @registry_api_bp.response(200, description="Successfully retrieved images list")
    @registry_api_bp.response(400, description="Bad request - Invalid registry server URL")
    @registry_api_bp.doc(tags=['Plugins API - Registry'])
    @login_required
    def get(self, registry_server_url):
        """
        Get list of images (repositories) from a registry server
        
        Path Parameters:
            registry_server_url (str): URL of the registry server
        
        Returns:
            dict: List of images with metadata
        """
        from .registry import RegistryGetRepositories
        
        try:
            # URL is already decoded by Flask's path converter
            # But handle any edge cases
            repositories = RegistryGetRepositories(registry_server_url)
            
            # Convert to list of dictionaries
            images_data = []
            for repo in repositories:
                images_data.append({
                    "name": repo if isinstance(repo, str) else repo.name if hasattr(repo, 'name') else str(repo)
                })
            
            return jsonify({
                "data": images_data,
                "metadata": {
                    "count": len(images_data),
                    "registry_server_url": registry_server_url
                }
            })
        except Exception as e:
            logger.error(f"Error getting images from registry {registry_server_url}: {e}")
            return jsonify({
                "error": "InternalServerError",
                "message": f"Failed to get images from registry: {str(e)}"
            }), 500


@registry_api_bp.route('/<path:registry_server_url>/images/<path:image_name>/tags')
class RegistryImageTagsResource(MethodView):
    """
    Registry image tags endpoint.
    """
    
    @registry_api_bp.response(200, description="Successfully retrieved image tags")
    @registry_api_bp.response(400, description="Bad request - Invalid parameters")
    @registry_api_bp.doc(tags=['Plugins API - Registry'])
    @login_required
    def get(self, registry_server_url, image_name):
        """
        Get list of tags for a specific image
        
        Path Parameters:
            registry_server_url (str): URL of the registry server
            image_name (str): Name of the image
        
        Returns:
            dict: List of tags with metadata
        """
        from .registry import RegistryGetTags
        
        try:
            tag_list = RegistryGetTags(registry_server_url, image_name)
            
            return jsonify({
                "data": {
                    "registry": tag_list.get('registry', ''),
                    "image": tag_list.get('image', image_name),
                    "tags": tag_list.get('tags', [])
                },
                "metadata": {
                    "registry_server_url": registry_server_url,
                    "image_name": image_name,
                    "tag_count": len(tag_list.get('tags', []))
                }
            })
        except Exception as e:
            logger.error(f"Error getting tags for image {image_name} from registry {registry_server_url}: {e}")
            return jsonify({
                "error": "InternalServerError",
                "message": f"Failed to get tags: {str(e)}"
            }), 500


@registry_api_bp.route('/<path:registry_server_url>/images/<path:image_name>/tags/<path:tag_name>/data')
class RegistryImageTagDataResource(MethodView):
    """
    Registry image tag data (manifest) endpoint.
    """
    
    @registry_api_bp.response(200, description="Successfully retrieved tag data")
    @registry_api_bp.response(400, description="Bad request - Invalid parameters")
    @registry_api_bp.doc(tags=['Plugins API - Registry'])
    @login_required
    def get(self, registry_server_url, image_name, tag_name):
        """
        Get manifest and event data for a specific image tag
        
        Path Parameters:
            registry_server_url (str): URL of the registry server
            image_name (str): Name of the image
            tag_name (str): Tag name
        
        Returns:
            dict: Tag data including manifest and events
        """
        from .registry import RegistryGetManifest
        from .registry_server import RegistryGetEvent
        
        try:
            tag_data = RegistryGetManifest(registry_server_url, image_name, tag_name)
            tag_events = RegistryGetEvent(image_name, tag_name)
            
            # Convert events to list of dictionaries
            events_data = []
            if tag_events:
                for event in tag_events:
                    events_data.append({
                        "action": event.action,
                        "ip": event.ip,
                        "user": event.user,
                        "created": event.created.isoformat() if hasattr(event.created, 'isoformat') else str(event.created)
                    })
            
            return jsonify({
                "data": {
                    "tag_data": tag_data,
                    "tag_events": events_data,
                    "image_name": image_name,
                    "tag_name": tag_name
                },
                "metadata": {
                    "registry_server_url": registry_server_url
                }
            })
        except Exception as e:
            logger.error(f"Error getting tag data for {image_name}:{tag_name} from registry {registry_server_url}: {e}")
            return jsonify({
                "error": "InternalServerError",
                "message": f"Failed to get tag data: {str(e)}"
            }), 500

