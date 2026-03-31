"""
Application Catalog API endpoints for managing applications.
"""

from contextlib import nullcontext
from flask import current_app, g, jsonify, request, session
from flask.views import MethodView
from flask_login import current_user, login_required
from flask_smorest import Blueprint

from lib.audit import log_audit_event
from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer
from .application import (
    ApplicationGet, ApplicationListGet, ApplicationCreate,
    ApplicationUpdate, ApplicationDelete
)
from .helpers import update_security_policies

##############################################################
## Blueprint Definition
##############################################################

application_catalog_api_bp = Blueprint(
    "application_catalog_api",
    "application_catalog_api",
    url_prefix="/application-catalog",
    description="Application Catalog API endpoints - Manage application catalog entries"
)

logger = get_logger()
tracer = get_tracer()

##############################################################
## Applications
##############################################################

@application_catalog_api_bp.route('')
class ApplicationsResource(MethodView):
    """
    Applications list endpoint.
    """
    
    @application_catalog_api_bp.response(200, description="Successfully retrieved applications list")
    @application_catalog_api_bp.doc(tags=['Plugins API - Application Catalog'])
    @login_required
    def get(self):
        """
        List all applications
        
        Returns:
            dict: List of applications with metadata
        """
        with tracer.start_as_current_span(
            "applications-list",
            attributes={
                "http.route": "/api/v1/plugins/application-catalog",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            applications = ApplicationListGet()
            
            # Convert to list of dictionaries
            applications_data = []
            for app in applications:
                applications_data.append({
                    "application_name": app.application_name,
                    "application_url": app.application_url,
                    "application_icon": app.application_icon,
                    "application_enabled": app.application_enabled,
                    "application_embedded": app.application_embedded,
                })
            
            return jsonify({
                "data": applications_data,
                "metadata": {
                    "count": len(applications_data)
                }
            })
    
    @application_catalog_api_bp.response(201, description="Successfully created application")
    @application_catalog_api_bp.response(400, description="Bad request - Invalid input")
    @application_catalog_api_bp.doc(tags=['Plugins API - Application Catalog'])
    @login_required
    def post(self):
        """
        Create a new application
        
        Request Body:
            dict: Application data:
                {
                    "application_name": str (required),
                    "application_url": str (required),
                    "application_icon": str (optional),
                    "application_enabled": bool (default: True),
                    "application_embedded": bool (default: False)
                }
        
        Returns:
            dict: Created application information
        """
        data = request.get_json() or {}
        
        application_name = data.get('application_name', '').strip()
        application_url = data.get('application_url', '').strip()
        application_icon = data.get('application_icon', '').strip() or None
        application_enabled = data.get('application_enabled', True)
        application_embedded = data.get('application_embedded', False)
        
        if not application_name or not application_url:
            return jsonify({
                "error": "BadRequest",
                "message": "application_name and application_url are required"
            }), 400
        
        try:
            application = ApplicationCreate(
                application_name=application_name,
                application_url=application_url,
                application_icon=application_icon,
                application_enabled=application_enabled,
                application_embedded=application_embedded
            )
            
            # Update CSP after adding application
            if application_embedded:
                update_security_policies(current_app, [{
                    'url': application_url,
                    'embed': application_embedded
                }])
            actor = session.get("user_name", "unknown")
            log_audit_event(
                user_id=actor,
                action="application_create",
                resource=f"application:{application_name}",
                result="success",
                trace_id=getattr(g, "correlation_id", None),
                details={"url": application_url},
            )
            return jsonify({
                "message": "Application created successfully",
                "data": {
                    "application_name": application.application_name,
                    "application_url": application.application_url,
                    "application_enabled": application.application_enabled,
                    "application_embedded": application.application_embedded,
                }
            }), 201
        except ValueError as e:
            return jsonify({
                "error": "BadRequest",
                "message": str(e)
            }), 400
        except Exception as e:
            logger.error(f"Error creating application: {e}")
            return jsonify({
                "error": "InternalServerError",
                "message": f"Failed to create application: {str(e)}"
            }), 500


@application_catalog_api_bp.route('/<path:application_name>')
class ApplicationResource(MethodView):
    """
    Individual application endpoint.
    """
    
    @application_catalog_api_bp.response(200, description="Successfully retrieved application")
    @application_catalog_api_bp.response(404, description="Application not found")
    @application_catalog_api_bp.doc(tags=['Plugins API - Application Catalog'])
    @login_required
    def get(self, application_name):
        """
        Get application details
        
        Path Parameters:
            application_name (str): Name of the application
        
        Returns:
            dict: Application details
        """
        application = ApplicationGet(application_name)
        
        if not application:
            return jsonify({
                "error": "NotFound",
                "message": f"Application '{application_name}' not found"
            }), 404
        
        return jsonify({
            "data": {
                "application_name": application.application_name,
                "application_url": application.application_url,
                "application_icon": application.application_icon,
                "application_enabled": application.application_enabled,
                "application_embedded": application.application_embedded,
            }
        })
    
    @application_catalog_api_bp.response(200, description="Successfully updated application")
    @application_catalog_api_bp.response(400, description="Bad request - Invalid input")
    @application_catalog_api_bp.response(404, description="Application not found")
    @application_catalog_api_bp.doc(tags=['Plugins API - Application Catalog'])
    @login_required
    def put(self, application_name):
        """
        Update application
        
        Path Parameters:
            application_name (str): Current name of the application (old name)
        
        Request Body:
            dict: Application update data:
                {
                    "application_name": str (required),
                    "application_url": str (required),
                    "application_icon": str (optional),
                    "application_enabled": bool (default: True),
                    "application_embedded": bool (default: False)
                }
        
        Returns:
            dict: Updated application information
        """
        data = request.get_json() or {}
        
        new_application_name = data.get('application_name', '').strip()
        application_url = data.get('application_url', '').strip()
        application_icon = data.get('application_icon', '').strip() or None
        application_enabled = data.get('application_enabled', True)
        application_embedded = data.get('application_embedded', False)
        
        if not new_application_name or not application_url:
            return jsonify({
                "error": "BadRequest",
                "message": "application_name and application_url are required"
            }), 400
        
        try:
            application = ApplicationUpdate(
                application_name_old=application_name,
                application_name=new_application_name,
                application_url=application_url,
                application_icon=application_icon,
                application_enabled=application_enabled,
                application_embedded=application_embedded
            )
            
            # Update CSP after updating application
            if application_embedded:
                update_security_policies(current_app, [{
                    'url': application_url,
                    'embed': application_embedded
                }])
            actor = session.get("user_name", "unknown")
            log_audit_event(
                user_id=actor,
                action="application_update",
                resource=f"application:{new_application_name}",
                result="success",
                trace_id=getattr(g, "correlation_id", None),
                details={"old_name": application_name, "url": application_url},
            )
            return jsonify({
                "message": "Application updated successfully",
                "data": {
                    "application_name": application.application_name,
                    "application_url": application.application_url,
                    "application_enabled": application.application_enabled,
                    "application_embedded": application.application_embedded,
                }
            })
        except ValueError as e:
            return jsonify({
                "error": "BadRequest",
                "message": str(e)
            }), 400
        except Exception as e:
            logger.error(f"Error updating application: {e}")
            return jsonify({
                "error": "InternalServerError",
                "message": f"Failed to update application: {str(e)}"
            }), 500
    
    @application_catalog_api_bp.response(200, description="Successfully deleted application")
    @application_catalog_api_bp.response(404, description="Application not found")
    @application_catalog_api_bp.doc(tags=['Plugins API - Application Catalog'])
    @login_required
    def delete(self, application_name):
        """
        Delete application
        
        Path Parameters:
            application_name (str): Name of the application to delete
        
        Returns:
            dict: Deletion confirmation
        """
        application = ApplicationGet(application_name)
        
        if not application:
            return jsonify({
                "error": "NotFound",
                "message": f"Application '{application_name}' not found"
            }), 404
        
        try:
            ApplicationDelete(application_name)
            actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
            log_audit_event(
                user_id=actor,
                action="delete_application",
                resource=f"application:{application_name}",
                result="success",
                trace_id=getattr(g, "correlation_id", None),
            )
            return jsonify({
                "message": "Application deleted successfully"
            })
        except Exception as e:
            logger.error(f"Error deleting application: {e}")
            actor = getattr(current_user, "username", None) or session.get("user_name", "unknown")
            log_audit_event(
                user_id=actor,
                action="delete_application",
                resource=f"application:{application_name}",
                result="failure",
                trace_id=getattr(g, "correlation_id", None),
                details={"error": str(e)},
            )
            return jsonify({
                "error": "InternalServerError",
                "message": f"Failed to delete application: {str(e)}"
            }), 500

