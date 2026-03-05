"""
Kubernetes Extension API Server Blueprint

This blueprint implements the Kubernetes API Aggregation Layer endpoints
for serving custom resources like Projects.

API Endpoints:
- /apis                              - API group list
- /apis/kubedash.io                  - API group versions  
- /apis/kubedash.io/v1               - API resources
- /apis/kubedash.io/v1/projects      - Projects resource
"""

from contextlib import nullcontext

from flask import jsonify, request, session
from flask.views import MethodView
from flask_smorest import Blueprint

from lib.helper_functions import get_logger
from lib.opentelemetry import get_tracer
from lib.components import csrf

from lib.extension_api import (
    get_resource_version,
    build_not_found_response,
    build_unauthorized_response,
    get_user_from_session_or_token,
    list_projects as ext_list_projects,
    get_project as ext_get_project,
    create_project as ext_create_project,
    update_project as ext_update_project,
    delete_project as ext_delete_project,
    register_error_handlers,
)

##############################################################
## Constants
##############################################################

API_GROUP = "kubedash.devopstales.github.io"
API_VERSION = "v1"
API_GROUP_VERSION = f"{API_GROUP}/{API_VERSION}"

##############################################################
## Helpers
##############################################################

extension_api_bp = Blueprint(
    "extension_api",
    "extension_api", 
    url_prefix="/apis",
    description="Kubernetes Extension API Server for KubeDash"
)
logger = get_logger()
tracer = get_tracer()

# Exempt this blueprint from CSRF protection (uses Bearer token auth)
csrf.exempt(extension_api_bp)

# Register JSON error handlers for Kubernetes-style responses
register_error_handlers(extension_api_bp)

##############################################################
## Kubernetes API Discovery Endpoints
##############################################################

@extension_api_bp.route('/')
class APIGroupListResource(MethodView):
    """
    Returns the list of API groups available.
    This is the entry point for Kubernetes API discovery.
    """
    @extension_api_bp.response(200)
    def get(self):
        """
        List all API groups
        
        Returns the APIGroupList containing all available API groups.
        This endpoint is called by kubectl and other clients for API discovery.
        
        Returns:
            APIGroupList: Kubernetes APIGroupList object
        """
        with tracer.start_as_current_span(
            "api-group-list",
            attributes={
                "http.route": "/apis",
                "http.method": "GET",
            }
        ) if tracer else nullcontext():
            return jsonify({
                "kind": "APIGroupList",
                "apiVersion": "v1",
                "groups": [
                    {
                        "name": API_GROUP,
                        "versions": [
                            {
                                "groupVersion": API_GROUP_VERSION,
                                "version": API_VERSION
                            }
                        ],
                        "preferredVersion": {
                            "groupVersion": API_GROUP_VERSION,
                            "version": API_VERSION
                        }
                    }
                ]
            })


@extension_api_bp.route(f'/{API_GROUP}')
class APIGroupResource(MethodView):
    """
    Returns information about the kubedash.io API group.
    """
    @extension_api_bp.response(200)
    def get(self):
        """
        Get API group details
        
        Returns the APIGroup resource for kubedash.io containing
        available versions and preferred version.
        
        Returns:
            APIGroup: Kubernetes APIGroup object
        """
        with tracer.start_as_current_span(
            "api-group-get",
            attributes={
                "http.route": f"/apis/{API_GROUP}",
                "http.method": "GET",
                "api.group": API_GROUP,
            }
        ) if tracer else nullcontext():
            return jsonify({
                "kind": "APIGroup",
                "apiVersion": "v1",
                "name": API_GROUP,
                "versions": [
                    {
                        "groupVersion": API_GROUP_VERSION,
                        "version": API_VERSION
                    }
                ],
                "preferredVersion": {
                    "groupVersion": API_GROUP_VERSION,
                    "version": API_VERSION
                }
            })


@extension_api_bp.route(f'/{API_GROUP}/{API_VERSION}')
class APIResourceListResource(MethodView):
    """
    Returns the list of resources available in kubedash.io/v1.
    """
    @extension_api_bp.response(200)
    def get(self):
        """
        List API resources in kubedash.io/v1
        
        Returns the APIResourceList containing all resources available
        in the kubedash.io/v1 API group version.
        
        Returns:
            APIResourceList: Kubernetes APIResourceList object
        """
        with tracer.start_as_current_span(
            "api-resource-list",
            attributes={
                "http.route": f"/apis/{API_GROUP}/{API_VERSION}",
                "http.method": "GET",
                "api.group": API_GROUP,
                "api.version": API_VERSION,
            }
        ) if tracer else nullcontext():
            return jsonify({
                "kind": "APIResourceList",
                "apiVersion": "v1",
                "groupVersion": API_GROUP_VERSION,
                "resources": [
                    {
                        "name": "projects",
                        "singularName": "project",
                        "namespaced": False,
                        "kind": "Project",
                        "verbs": ["get", "list", "create", "update", "patch", "delete"],
                        "shortNames": ["proj"],
                        "categories": ["all"],
                        "storageVersionHash": ""
                    }
                ]
            })


##############################################################
## Table Format Helper (for kubectl display)
##############################################################

def _format_age(creation_timestamp: str) -> str:
    """Format creation timestamp as human-readable age."""
    if not creation_timestamp:
        return "<unknown>"
    
    from datetime import datetime, timezone
    try:
        # Parse ISO format timestamp
        if creation_timestamp.endswith('Z'):
            created = datetime.fromisoformat(creation_timestamp.replace('Z', '+00:00'))
        else:
            created = datetime.fromisoformat(creation_timestamp)
        
        now = datetime.now(timezone.utc)
        delta = now - created
        
        days = delta.days
        if days > 365:
            return f"{days // 365}y"
        elif days > 0:
            return f"{days}d"
        
        hours = delta.seconds // 3600
        if hours > 0:
            return f"{hours}h"
        
        minutes = delta.seconds // 60
        if minutes > 0:
            return f"{minutes}m"
        
        return f"{delta.seconds}s"
    except Exception:
        return "<unknown>"


def _build_table_response(project_list: dict) -> dict:
    """
    Convert ProjectList to Table format for kubectl display.
    
    This provides nice columnar output with custom columns like PROTECTED, OWNER.
    """
    items = project_list.get("items", [])
    
    # Define columns
    column_definitions = [
        {
            "name": "Name",
            "type": "string",
            "format": "name",
            "description": "Name of the project",
            "priority": 0
        },
        {
            "name": "Protected",
            "type": "string",
            "description": "Whether the project is protected from deletion",
            "priority": 0
        },
        {
            "name": "Owner",
            "type": "string",
            "description": "Owner of the project",
            "priority": 0
        },
        {
            "name": "Status",
            "type": "string",
            "description": "Current status of the project",
            "priority": 0
        },
        {
            "name": "Age",
            "type": "string",
            "description": "Age of the project",
            "priority": 0
        }
    ]
    
    # Build rows
    rows = []
    for project in items:
        metadata = project.get("metadata", {})
        spec = project.get("spec", {})
        status = project.get("status", {})
        
        # Get values
        name = metadata.get("name", "")
        protected = "Yes" if spec.get("protected") else "No"
        owner = spec.get("owner", "") or "-"
        phase = status.get("phase", "Unknown")
        age = _format_age(metadata.get("creationTimestamp", ""))
        
        rows.append({
            "cells": [name, protected, owner, phase, age],
            "object": {
                "kind": "PartialObjectMetadata",
                "apiVersion": "meta.k8s.io/v1",
                "metadata": metadata
            }
        })
    
    return {
        "kind": "Table",
        "apiVersion": "meta.k8s.io/v1",
        "metadata": {
            "resourceVersion": project_list.get("metadata", {}).get("resourceVersion", "")
        },
        "columnDefinitions": column_definitions,
        "rows": rows
    }


def _wants_table_format(req) -> bool:
    """Check if client wants Table format (kubectl default)."""
    accept = req.headers.get('Accept', '')
    return 'as=Table' in accept


##############################################################
## Projects Resource Endpoints
##############################################################

@extension_api_bp.route(f'/{API_GROUP}/{API_VERSION}/projects')
class ProjectListResource(MethodView):
    """
    List Projects resource.
    Projects are namespace-like resources filtered by user permissions.
    """
    @extension_api_bp.response(200)
    def get(self):
        """
        List all projects
        
        Returns a list of projects (namespaces) that the authenticated
        user has permission to access. This filters namespaces based on
        the user's RBAC permissions.
        
        Query Parameters:
            watch (bool): If true, watch for changes (not implemented yet)
            labelSelector (str): Filter by labels
            fieldSelector (str): Filter by fields
            limit (int): Maximum number of results
            continue (str): Continuation token for pagination
        
        Returns:
            ProjectList: List of Project objects
        """
        with tracer.start_as_current_span(
            "project-list",
            attributes={
                "http.route": f"/apis/{API_GROUP}/{API_VERSION}/projects",
                "http.method": "GET",
                "api.group": API_GROUP,
                "api.version": API_VERSION,
                "api.resource": "projects",
            }
        ) if tracer else nullcontext() as span:
            
            # Authenticate the request
            user = get_user_from_session_or_token(request, session)
            
            if not user:
                logger.warning("Unauthenticated request to list projects")
                if tracer and span and span.is_recording():
                    span.set_attribute("auth.result", "unauthenticated")
                return jsonify(build_unauthorized_response()), 401
            
            logger.debug(f"List projects for user: {user.username}")
            if tracer and span and span.is_recording():
                span.set_attribute("user", user.username)
            
            # Get query parameters
            label_selector = request.args.get('labelSelector')
            field_selector = request.args.get('fieldSelector')
            limit = request.args.get('limit', type=int)
            
            # List projects with permission filtering
            project_list, error = ext_list_projects(
                user=user,
                label_selector=label_selector,
                field_selector=field_selector,
                limit=limit
            )
            
            if error:
                logger.error(f"Error listing projects: {error}")
                if tracer and span and span.is_recording():
                    span.set_attribute("error", error)
                return jsonify({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": error,
                    "code": 500
                }), 500
            
            if tracer and span and span.is_recording():
                span.set_attribute("project.count", len(project_list.get("items", [])))
            
            # Return Table format if requested by kubectl
            if _wants_table_format(request):
                return jsonify(_build_table_response(project_list))
            
            return jsonify(project_list)

    @extension_api_bp.response(201)
    def post(self):
        """
        Create a new project
        
        Creates a new project (namespace) with optional metadata.
        Requires namespace creation permissions in the cluster.
        
        Request Body:
            {
                "apiVersion": "kubedash.devopstales.github.io/v1",
                "kind": "Project",
                "metadata": {
                    "name": "my-project",
                    "labels": {}
                },
                "spec": {
                    "owner": "Owner Name",
                    "protected": false,
                    "repository": "https://github.com/...",
                    "pipeline": "https://ci.example.com/..."
                }
            }
        
        Returns:
            Project: The created Project object
        """
        with tracer.start_as_current_span(
            "project-create",
            attributes={
                "http.route": f"/apis/{API_GROUP}/{API_VERSION}/projects",
                "http.method": "POST",
                "api.group": API_GROUP,
                "api.version": API_VERSION,
                "api.resource": "projects",
            }
        ) if tracer else nullcontext() as span:
            
            # Authenticate the request
            user = get_user_from_session_or_token(request, session)
            
            if not user:
                logger.warning("Unauthenticated request to create project")
                if tracer and span and span.is_recording():
                    span.set_attribute("auth.result", "unauthenticated")
                return jsonify(build_unauthorized_response()), 401
            
            logger.debug(f"Create project request from user: {user.username}")
            if tracer and span and span.is_recording():
                span.set_attribute("user", user.username)
            
            # Parse request body
            try:
                body = request.get_json()
                if not body:
                    return jsonify({
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "message": "Request body is required",
                        "reason": "BadRequest",
                        "code": 400
                    }), 400
            except Exception as e:
                return jsonify({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": f"Invalid JSON: {str(e)}",
                    "reason": "BadRequest",
                    "code": 400
                }), 400
            
            # Extract project details
            metadata = body.get("metadata", {})
            spec = body.get("spec", {})
            
            # Validate required fields
            name = metadata.get("name")
            if not name:
                return jsonify({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": "metadata.name is required",
                    "reason": "BadRequest",
                    "code": 400
                }), 400
            
            # Owner is optional - if not provided, will use authenticated user's username
            owner = spec.get("owner")
            
            if "protected" not in spec:
                return jsonify({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": "spec.protected is required",
                    "reason": "BadRequest",
                    "code": 400
                }), 400
            
            protected = spec.get("protected")
            if not isinstance(protected, bool):
                return jsonify({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": "spec.protected must be a boolean",
                    "reason": "BadRequest",
                    "code": 400
                }), 400
            
            if tracer and span and span.is_recording():
                span.set_attribute("project.name", name)
            
            # Create the project (owner defaults to authenticated user if not provided)
            project, error, status_code = ext_create_project(
                user=user,
                name=name,
                protected=protected,
                owner=owner,  # Optional - uses user.username if None
                labels=metadata.get("labels"),
                repository=spec.get("repository"),
                pipeline=spec.get("pipeline")
            )
            
            if error:
                logger.warning(f"Failed to create project {name}: {error}")
                if tracer and span and span.is_recording():
                    span.set_attribute("error", error)
                
                reason = "AlreadyExists" if status_code == 409 else "Forbidden" if status_code == 403 else "InternalError"
                return jsonify({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": error,
                    "reason": reason,
                    "details": {
                        "name": name,
                        "group": API_GROUP,
                        "kind": "projects"
                    },
                    "code": status_code
                }), status_code
            
            logger.info(f"Project {name} created successfully by {user.username}")
            return jsonify(project), 201


@extension_api_bp.route(f'/{API_GROUP}/{API_VERSION}/projects/<string:name>')
class ProjectResource(MethodView):
    """
    Get a specific Project resource.
    """
    @extension_api_bp.response(200)
    def get(self, name: str):
        """
        Get a specific project
        
        Returns the Project resource with the given name if the user
        has permission to access it.
        
        Args:
            name: The name of the project to retrieve
        
        Returns:
            Project: The requested Project object
            
        Raises:
            404: If the project is not found or user lacks permission
        """
        with tracer.start_as_current_span(
            "project-get",
            attributes={
                "http.route": f"/apis/{API_GROUP}/{API_VERSION}/projects/{{name}}",
                "http.method": "GET",
                "api.group": API_GROUP,
                "api.version": API_VERSION,
                "api.resource": "projects",
                "project.name": name,
            }
        ) if tracer else nullcontext() as span:
            
            # Authenticate the request
            user = get_user_from_session_or_token(request, session)
            
            if not user:
                logger.warning(f"Unauthenticated request to get project {name}")
                if tracer and span and span.is_recording():
                    span.set_attribute("auth.result", "unauthenticated")
                return jsonify(build_unauthorized_response()), 401
            
            logger.debug(f"Get project {name} for user: {user.username}")
            if tracer and span and span.is_recording():
                span.set_attribute("user", user.username)
            
            # Get the project with permission check
            project, error, status_code = ext_get_project(user, name)
            
            if error:
                logger.debug(f"Get project {name} failed: {error}")
                if tracer and span and span.is_recording():
                    span.set_attribute("error", error)
                return jsonify(build_not_found_response("projects", name)), status_code
            
            # Return Table format if requested by kubectl
            if _wants_table_format(request):
                project_list = {
                    "items": [project],
                    "metadata": {"resourceVersion": project.get("metadata", {}).get("resourceVersion", "")}
                }
                return jsonify(_build_table_response(project_list))
            
            return jsonify(project)

    @extension_api_bp.response(200)
    def put(self, name: str):
        """
        Update a project (full replacement)
        
        Updates a Project resource with the provided spec.
        
        Args:
            name: The name of the project to update
        
        Returns:
            Project: The updated Project object
        """
        return self._update_project(name)

    @extension_api_bp.response(200)
    def patch(self, name: str):
        """
        Patch a project (partial update)
        
        Partially updates a Project resource.
        
        Args:
            name: The name of the project to patch
        
        Returns:
            Project: The patched Project object
        """
        return self._update_project(name)

    def _update_project(self, name: str):
        """Internal method to handle both PUT and PATCH"""
        with tracer.start_as_current_span(
            "project-update",
            attributes={
                "http.route": f"/apis/{API_GROUP}/{API_VERSION}/projects/{{name}}",
                "http.method": request.method,
                "api.group": API_GROUP,
                "api.version": API_VERSION,
                "api.resource": "projects",
                "project.name": name,
            }
        ) if tracer else nullcontext() as span:
            
            # Authenticate the request
            user = get_user_from_session_or_token(request, session)
            
            if not user:
                logger.warning(f"Unauthenticated request to update project {name}")
                if tracer and span and span.is_recording():
                    span.set_attribute("auth.result", "unauthenticated")
                return jsonify(build_unauthorized_response()), 401
            
            logger.debug(f"Update project {name} for user: {user.username}")
            if tracer and span and span.is_recording():
                span.set_attribute("user", user.username)
            
            # Parse request body
            try:
                body = request.get_json()
                if not body:
                    return jsonify({
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "message": "Request body is required",
                        "reason": "BadRequest",
                        "code": 400
                    }), 400
            except Exception as e:
                return jsonify({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": f"Invalid JSON: {str(e)}",
                    "reason": "BadRequest",
                    "code": 400
                }), 400
            
            # Extract update fields
            metadata = body.get("metadata", {})
            spec = body.get("spec", {})
            
            # Update the project
            project, error, status_code = ext_update_project(
                user=user,
                name=name,
                owner=spec.get("owner"),
                protected=spec.get("protected"),
                labels=metadata.get("labels"),
                repository=spec.get("repository"),
                pipeline=spec.get("pipeline")
            )
            
            if error:
                logger.warning(f"Failed to update project {name}: {error}")
                if tracer and span and span.is_recording():
                    span.set_attribute("error", error)
                
                reason = "NotFound" if status_code == 404 else "Forbidden" if status_code == 403 else "InternalError"
                return jsonify({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": error,
                    "reason": reason,
                    "details": {
                        "name": name,
                        "group": API_GROUP,
                        "kind": "projects"
                    },
                    "code": status_code
                }), status_code
            
            logger.info(f"Project {name} updated successfully by {user.username}")
            return jsonify(project)

    @extension_api_bp.response(200)
    def delete(self, name: str):
        """
        Delete a project
        
        Deletes the Project resource with the given name.
        Protected projects cannot be deleted.
        
        Args:
            name: The name of the project to delete
        
        Returns:
            Status: Success status if deleted
        """
        with tracer.start_as_current_span(
            "project-delete",
            attributes={
                "http.route": f"/apis/{API_GROUP}/{API_VERSION}/projects/{{name}}",
                "http.method": "DELETE",
                "api.group": API_GROUP,
                "api.version": API_VERSION,
                "api.resource": "projects",
                "project.name": name,
            }
        ) if tracer else nullcontext() as span:
            
            # Authenticate the request
            user = get_user_from_session_or_token(request, session)
            
            if not user:
                logger.warning(f"Unauthenticated request to delete project {name}")
                if tracer and span and span.is_recording():
                    span.set_attribute("auth.result", "unauthenticated")
                return jsonify(build_unauthorized_response()), 401
            
            logger.debug(f"Delete project {name} for user: {user.username}")
            if tracer and span and span.is_recording():
                span.set_attribute("user", user.username)
            
            # Delete the project
            result, error, status_code = ext_delete_project(user, name)
            
            if error:
                logger.warning(f"Failed to delete project {name}: {error}")
                if tracer and span and span.is_recording():
                    span.set_attribute("error", error)
                
                reason = "NotFound" if status_code == 404 else "Forbidden" if status_code == 403 else "InternalError"
                return jsonify({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": error,
                    "reason": reason,
                    "details": {
                        "name": name,
                        "group": API_GROUP,
                        "kind": "projects"
                    },
                    "code": status_code
                }), status_code
            
            logger.info(f"Project {name} deleted successfully by {user.username}")
            return jsonify(result)


##############################################################
## Health Check Endpoint (Required for API Aggregation)
##############################################################

@extension_api_bp.route('/healthz')
class HealthzResource(MethodView):
    """
    Health check endpoint required by Kubernetes API Aggregation Layer.
    """
    @extension_api_bp.response(200)
    def get(self):
        """
        Health check for Extension API Server
        
        Returns 'ok' if the server is healthy. This endpoint is used by
        the Kubernetes API server to verify the extension API is available.
        
        Returns:
            str: 'ok' if healthy
        """
        return 'ok', 200, {'Content-Type': 'text/plain'}


##############################################################
## OpenAPI / Swagger Spec Endpoint
##############################################################

@extension_api_bp.route('/openapi/v2')
class OpenAPISpecResource(MethodView):
    """
    OpenAPI v2 specification for the Extension API.
    """
    @extension_api_bp.response(200)
    def get(self):
        """
        Get OpenAPI v2 specification
        
        Returns the OpenAPI/Swagger specification for the Extension API.
        
        Returns:
            dict: OpenAPI v2 specification
        """
        return jsonify({
            "swagger": "2.0",
            "info": {
                "title": "KubeDash Extension API",
                "description": "Kubernetes Extension API Server for KubeDash Projects",
                "version": API_VERSION
            },
            "basePath": "/apis",
            "paths": {
                "/": {
                    "get": {
                        "summary": "List API groups",
                        "operationId": "getAPIVersions",
                        "produces": ["application/json"],
                        "responses": {
                            "200": {
                                "description": "APIGroupList"
                            }
                        }
                    }
                },
                f"/{API_GROUP}": {
                    "get": {
                        "summary": "Get API group",
                        "operationId": "getAPIGroup",
                        "produces": ["application/json"],
                        "responses": {
                            "200": {
                                "description": "APIGroup"
                            }
                        }
                    }
                },
                f"/{API_GROUP}/{API_VERSION}": {
                    "get": {
                        "summary": "List API resources",
                        "operationId": "getAPIResources",
                        "produces": ["application/json"],
                        "responses": {
                            "200": {
                                "description": "APIResourceList"
                            }
                        }
                    }
                },
                f"/{API_GROUP}/{API_VERSION}/projects": {
                    "get": {
                        "summary": "List projects",
                        "operationId": "listProjects",
                        "produces": ["application/json"],
                        "parameters": [
                            {
                                "name": "labelSelector",
                                "in": "query",
                                "type": "string",
                                "description": "Label selector for filtering"
                            },
                            {
                                "name": "limit",
                                "in": "query", 
                                "type": "integer",
                                "description": "Maximum number of results"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "ProjectList"
                            }
                        }
                    },
                    "post": {
                        "summary": "Create a project",
                        "operationId": "createProject",
                        "consumes": ["application/json"],
                        "produces": ["application/json"],
                        "parameters": [
                            {
                                "name": "body",
                                "in": "body",
                                "required": True,
                                "schema": {"$ref": "#/definitions/Project"},
                                "description": "Project to create"
                            }
                        ],
                        "responses": {
                            "201": {
                                "description": "Project created",
                                "schema": {"$ref": "#/definitions/Project"}
                            },
                            "400": {
                                "description": "Bad request"
                            },
                            "403": {
                                "description": "Forbidden"
                            },
                            "409": {
                                "description": "Already exists"
                            }
                        }
                    }
                },
                f"/{API_GROUP}/{API_VERSION}/projects/{{name}}": {
                    "get": {
                        "summary": "Get a project",
                        "operationId": "getProject",
                        "produces": ["application/json"],
                        "parameters": [
                            {
                                "name": "name",
                                "in": "path",
                                "required": True,
                                "type": "string",
                                "description": "Name of the project"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Project"
                            },
                            "404": {
                                "description": "Not found"
                            }
                        }
                    },
                    "put": {
                        "summary": "Update a project",
                        "operationId": "updateProject",
                        "consumes": ["application/json"],
                        "produces": ["application/json"],
                        "parameters": [
                            {
                                "name": "name",
                                "in": "path",
                                "required": True,
                                "type": "string",
                                "description": "Name of the project"
                            },
                            {
                                "name": "body",
                                "in": "body",
                                "required": True,
                                "schema": {"$ref": "#/definitions/Project"},
                                "description": "Project update"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Project updated",
                                "schema": {"$ref": "#/definitions/Project"}
                            },
                            "403": {
                                "description": "Forbidden"
                            },
                            "404": {
                                "description": "Not found"
                            }
                        }
                    },
                    "patch": {
                        "summary": "Patch a project",
                        "operationId": "patchProject",
                        "consumes": ["application/json"],
                        "produces": ["application/json"],
                        "parameters": [
                            {
                                "name": "name",
                                "in": "path",
                                "required": True,
                                "type": "string",
                                "description": "Name of the project"
                            },
                            {
                                "name": "body",
                                "in": "body",
                                "required": True,
                                "schema": {"$ref": "#/definitions/Project"},
                                "description": "Project patch"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Project patched",
                                "schema": {"$ref": "#/definitions/Project"}
                            },
                            "403": {
                                "description": "Forbidden"
                            },
                            "404": {
                                "description": "Not found"
                            }
                        }
                    },
                    "delete": {
                        "summary": "Delete a project",
                        "operationId": "deleteProject",
                        "produces": ["application/json"],
                        "parameters": [
                            {
                                "name": "name",
                                "in": "path",
                                "required": True,
                                "type": "string",
                                "description": "Name of the project"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Project deleted"
                            },
                            "403": {
                                "description": "Forbidden (protected project)"
                            },
                            "404": {
                                "description": "Not found"
                            }
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
                        "metadata": {"$ref": "#/definitions/ObjectMeta"},
                        "spec": {"$ref": "#/definitions/ProjectSpec"},
                        "status": {"$ref": "#/definitions/ProjectStatus"}
                    }
                },
                "ProjectSpec": {
                    "type": "object",
                    "required": ["protected"],
                    "properties": {
                        "finalizers": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "protected": {
                            "type": "boolean",
                            "description": "Whether the project is protected from deletion (required)"
                        },
                        "owner": {
                            "type": "string",
                            "description": "Owner of the project (optional, defaults to authenticated user)"
                        },
                        "repository": {
                            "type": "string",
                            "description": "Git repository URL (optional)"
                        },
                        "pipeline": {
                            "type": "string",
                            "description": "CI/CD pipeline URL (optional)"
                        }
                    }
                },
                "ProjectStatus": {
                    "type": "object",
                    "properties": {
                        "phase": {"type": "string"},
                        "namespace": {"type": "string"}
                    }
                },
                "ObjectMeta": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "uid": {"type": "string"},
                        "creationTimestamp": {"type": "string"},
                        "labels": {"type": "object"},
                        "annotations": {"type": "object"}
                    }
                },
                "ProjectList": {
                    "type": "object",
                    "properties": {
                        "apiVersion": {"type": "string"},
                        "kind": {"type": "string"},
                        "metadata": {"$ref": "#/definitions/ListMeta"},
                        "items": {
                            "type": "array",
                            "items": {"$ref": "#/definitions/Project"}
                        }
                    }
                },
                "ListMeta": {
                    "type": "object",
                    "properties": {
                        "resourceVersion": {"type": "string"},
                        "continue": {"type": "string"}
                    }
                }
            }
        })


##############################################################
## Catch-all for Invalid Paths (must be last)
##############################################################

@extension_api_bp.route('/<path:invalid_path>')
def catch_all_not_found(invalid_path):
    """
    Catch-all route for invalid paths under /apis.
    Returns JSON 404 response instead of HTML.
    """
    return jsonify({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": f'the server could not find the requested resource',
        "reason": "NotFound",
        "details": {
            "name": invalid_path,
            "group": "",
            "kind": ""
        },
        "code": 404
    }), 404

