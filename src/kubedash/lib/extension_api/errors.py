"""
Error handling for Kubernetes Extension API Server.

This module provides JSON error responses in Kubernetes Status format
for all API errors.
"""

from flask import jsonify

from . import logger

##############################################################
## Kubernetes Status Response Builder
##############################################################

def build_error_response(code: int, reason: str, message: str) -> dict:
    """
    Build a Kubernetes Status error response.
    
    Args:
        code: HTTP status code
        reason: Machine-readable reason (e.g., "NotFound", "BadRequest")
        message: Human-readable error message
        
    Returns:
        dict: Kubernetes Status object
    """
    return {
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "code": code
    }


##############################################################
## Error Handler Functions
##############################################################

def handle_bad_request(e):
    """Return JSON for 400 Bad Request errors"""
    message = str(e.description) if hasattr(e, 'description') else "Bad Request"
    return jsonify(build_error_response(400, "BadRequest", message)), 400


def handle_unauthorized(e):
    """Return JSON for 401 Unauthorized errors"""
    return jsonify(build_error_response(401, "Unauthorized", "Unauthorized")), 401


def handle_forbidden(e):
    """Return JSON for 403 Forbidden errors"""
    message = str(e.description) if hasattr(e, 'description') else "Forbidden"
    return jsonify(build_error_response(403, "Forbidden", message)), 403


def handle_not_found(e):
    """Return JSON for 404 Not Found errors"""
    message = str(e.description) if hasattr(e, 'description') else "Not Found"
    return jsonify(build_error_response(404, "NotFound", message)), 404


def handle_method_not_allowed(e):
    """Return JSON for 405 Method Not Allowed errors"""
    message = str(e.description) if hasattr(e, 'description') else "Method Not Allowed"
    return jsonify(build_error_response(405, "MethodNotAllowed", message)), 405


def handle_conflict(e):
    """Return JSON for 409 Conflict errors"""
    message = str(e.description) if hasattr(e, 'description') else "Conflict"
    return jsonify(build_error_response(409, "AlreadyExists", message)), 409


def handle_internal_error(e):
    """Return JSON for 500 Internal Server errors"""
    logger.error(f"Internal server error in extension API: {e}")
    return jsonify(build_error_response(500, "InternalError", "Internal Server Error")), 500


def handle_unexpected_error(e):
    """Return JSON for unexpected errors"""
    logger.error(f"Unexpected error in extension API: {e}")
    return jsonify(build_error_response(500, "InternalError", "Internal Server Error")), 500


##############################################################
## Blueprint Error Handler Registration
##############################################################

def register_error_handlers(blueprint):
    """
    Register all JSON error handlers on a Flask blueprint.
    
    Args:
        blueprint: Flask Blueprint to register error handlers on
    """
    blueprint.errorhandler(400)(handle_bad_request)
    blueprint.errorhandler(401)(handle_unauthorized)
    blueprint.errorhandler(403)(handle_forbidden)
    blueprint.errorhandler(404)(handle_not_found)
    blueprint.errorhandler(405)(handle_method_not_allowed)
    blueprint.errorhandler(409)(handle_conflict)
    blueprint.errorhandler(500)(handle_internal_error)
    blueprint.errorhandler(Exception)(handle_unexpected_error)
