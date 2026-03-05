"""
Root-level endpoints for Kubernetes API Aggregation.

Kubernetes expects certain endpoints at the root level (not under /apis):
- /openapi/v2 - OpenAPI specification
- /openapi/v3 - OpenAPI v3 specification  
- /healthz - Health check (also available under /apis)
"""

from flask import Blueprint, jsonify
from flask.views import MethodView

from lib.components import csrf

API_GROUP = "kubedash.devopstales.github.io"
API_VERSION = "v1"

# Blueprint without url_prefix for root-level routes
extension_root_bp = Blueprint(
    "extension_root",
    __name__,
    url_prefix=""
)

# Exempt from CSRF protection
csrf.exempt(extension_root_bp)


@extension_root_bp.route('/openapi/v2')
def openapi_v2():
    """
    OpenAPI v2 specification at root level.
    Required by Kubernetes API aggregation.
    """
    return jsonify({
        "swagger": "2.0",
        "info": {
            "title": "KubeDash Extension API",
            "version": "v1",
            "description": "Kubernetes Extension API Server for KubeDash Projects"
        },
        "basePath": "/apis",
        "paths": {
            f"/{API_GROUP}/{API_VERSION}/projects": {
                "get": {
                    "summary": "List projects",
                    "operationId": "listProjects",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {"description": "ProjectList"}
                    }
                },
                "post": {
                    "summary": "Create a project",
                    "operationId": "createProject",
                    "produces": ["application/json"],
                    "responses": {
                        "201": {"description": "Project created"}
                    }
                }
            },
            f"/{API_GROUP}/{API_VERSION}/projects/{{name}}": {
                "get": {
                    "summary": "Get a project",
                    "operationId": "getProject",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {"description": "Project"}
                    }
                },
                "put": {
                    "summary": "Update a project",
                    "operationId": "updateProject",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {"description": "Project updated"}
                    }
                },
                "patch": {
                    "summary": "Patch a project",
                    "operationId": "patchProject",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {"description": "Project patched"}
                    }
                },
                "delete": {
                    "summary": "Delete a project",
                    "operationId": "deleteProject",
                    "produces": ["application/json"],
                    "responses": {
                        "200": {"description": "Project deleted"}
                    }
                }
            }
        },
        "definitions": {
            "Project": {
                "type": "object",
                "properties": {
                    "apiVersion": {"type": "string"},
                    "kind": {"type": "string"},
                    "metadata": {"type": "object"},
                    "spec": {"type": "object"},
                    "status": {"type": "object"}
                }
            }
        }
    })


@extension_root_bp.route('/openapi/v3')
def openapi_v3():
    """
    OpenAPI v3 discovery endpoint.
    Returns available API groups for OpenAPI v3.
    """
    return jsonify({
        "paths": {
            f"apis/{API_GROUP}/{API_VERSION}": {
                "serverRelativeURL": f"/openapi/v3/apis/{API_GROUP}/{API_VERSION}"
            }
        }
    })


@extension_root_bp.route(f'/openapi/v3/apis/{API_GROUP}/{API_VERSION}')
def openapi_v3_group():
    """
    OpenAPI v3 specification for the API group.
    """
    return jsonify({
        "openapi": "3.0.0",
        "info": {
            "title": "KubeDash Extension API",
            "version": API_VERSION
        },
        "paths": {}
    })


@extension_root_bp.route('/healthz')
def healthz_root():
    """
    Health check at root level.
    Some Kubernetes components check /healthz at root.
    """
    return "ok", 200, {"Content-Type": "text/plain"}


@extension_root_bp.route('/readyz')
def readyz_root():
    """
    Readiness check at root level.
    """
    return "ok", 200, {"Content-Type": "text/plain"}


@extension_root_bp.route('/livez')
def livez_root():
    """
    Liveness check at root level.
    """
    return "ok", 200, {"Content-Type": "text/plain"}
