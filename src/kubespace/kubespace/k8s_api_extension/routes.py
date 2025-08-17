from flask.views import MethodView
from flask import request, Response, jsonify, current_app

import json
from datetime import datetime, timezone

from .schemas import SpaceSchema
from . import extension_api_space_bp
from .service import (
    validate_user, format_age,
    list_visible_spaces, get_space, to_space,
    create_space, update_space, delete_space
)
@extension_api_space_bp.route("")
class APIGroupResource(MethodView):
    def get(self):
        """API group discovery for devopstales.github.io"""
        return {
            "kind": "APIGroup",
            "apiVersion": "v1",
            "name": "devopstales.github.io",
            "versions": [
                {
                    "groupVersion": "devopstales.github.io/v1",
                    "version": "v1"
                }
            ],
            "preferredVersion": {
                "groupVersion": "devopstales.github.io/v1",
                "version": "v1"
            }
        }


@extension_api_space_bp.route('/v1')
class SpaceResource(MethodView):
    @extension_api_space_bp.response(200)
    def get(self):
        """Serve the APIResourceList for discovery"""
        return jsonify({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": "devopstales.github.io/v1",
            "resources": [
                {
                    "name": "spaces",
                    "singularName": "space",
                    "namespaced": False,
                    "kind": "Space",
                    "verbs": [
                        "get", 
                        "list", 
                        "watch", 
                        "create", 
                        "update", 
                        "patch", 
                        "delete"
                    ],
                    "shortNames": ["spc"]
                }
            ]
        })

@extension_api_space_bp.route('/v1/spaces')
class SpaceListResource(MethodView):
    @extension_api_space_bp.doc(parameters=[
        {
            "in": "header",
            "name": "X-Remote-User",
            "required": True,
            "schema": {"type": "string"},
            "description": "The username to impersonate or authenticate as."
        },
        {
            "in": "header",
            "name": "X-Remote-Group",
            "required": False,
            "schema": {"type": "string"},
            "description": "Comma-separated list of groups the user belongs to (e.g. devs,admins)."
        },
        {
            "in": "header",
            "name": "Impersonate-User",
            "required": False,
            "schema": {"type": "string"},
            "description": "Alternative impersonation header (Kubernetes-style)."
        },
        {
            "in": "header",
            "name": "Impersonate-Group",
            "required": False,
            "schema": {"type": "string"},
            "description": "Alternative impersonation group header (can appear multiple times)."
        },
        {
            "in": "header",
            "name": "Authorization",
            "required": False,
            "schema": {"type": "string"},
            "description": "Bearer token or service account used for system components."
        }
    ])
    @extension_api_space_bp.response(200)
    def get(self):
        """List spaces the user has access to"""
        
        user, groups, error = validate_user(request)
        if error:
            return error
        
        allowed_ns_list = list_visible_spaces(user, groups)
        
        # Detect if client wants a Table
        accept_header = request.headers.get("Accept", "")
        wants_table = "as=Table" in accept_header
        
        if wants_table:
            # Return Table format
            table = {
                "kind": "Table",
                "apiVersion": "meta.k8s.io/v1",
                "columnDefinitions": [
                    {"name": "Name", "type": "string", "format": "name",
                    "description": "Space name", "jsonPath": ".metadata.name"},
                    {"name": "Status", "type": "string",
                    "description": "Space status", "jsonPath": ".status.phase"},
                    {"name": "Age", "type": "date",
                    "description": "Creation timestamp", "jsonPath": ".metadata.creationTimestamp"}
                ],
                "rows": []
            }

            for ns in allowed_ns_list:
                space_obj = to_space(ns, user, None)
                ts = ns.metadata.creation_timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                table["rows"].append({
                    "cells": [
                        space_obj["metadata"]["name"],
                        space_obj.get("status", {}).get("phase", ""),
                        format_age(ts)
                    ],
                    "object": space_obj
                })
            
            return Response(
                json.dumps(table),
                status=200,
                content_type="application/json;as=Table;g=meta.k8s.io;v=v1"
            )
        else:
            # Return full list of objects
            space_list = {
                "kind": "SpaceList",
                "apiVersion": "devopstales.github.io/v1",
                "items": [to_space(ns, user, None) for ns in allowed_ns_list]
            }
            return Response(
                json.dumps(space_list),
                status=200,
                content_type="application/json"
            )
        
    @extension_api_space_bp.arguments(SpaceSchema)
    @extension_api_space_bp.response(201, SpaceSchema)
    def post(self, data):
        """Create a new space (namespace) [X]"""
        user, groups, error = validate_user(request)
        if error:
            return error
        
        name = data["metadata"]["name"]
        spec = data.get("spec", {})
        space_obj = create_space(name, user, spec)
        return space_obj

@extension_api_space_bp.route('/v1/spaces/<string:name>')
class SpaceResource(MethodView):
    @extension_api_space_bp.doc(parameters=[
        {"in": "path", "name": "name", "required": True, "schema": {"type": "string"},
        "description": "The name of the space to retrieve"},
        {"in": "header", "name": "X-Remote-User", "required": False,
        "schema": {"type": "string"}, "description": "Authenticated user name"},
        {"in": "header", "name": "X-Remote-Group", "required": False,
        "schema": {"type": "string"}, "description": "Groups of the user"},
        {"in": "header", "name": "Impersonate-User", "required": False,
        "schema": {"type": "string"}, "description": "Optional impersonation user"},
        {"in": "header", "name": "Impersonate-Group", "required": False,
        "schema": {"type": "string"}, "description": "Optional impersonation groups"},
    ])
    @extension_api_space_bp.response(200)
    def get(self, name):
        """Get a single space [X]"""
        user, groups, error = validate_user(request)
        if error:
            return error

        space, status = get_space(name, user, groups)
        if status != 200:
            if status == 401:
                return {"error": "Unauthorized"}, 401
            elif status == 404:
                return {"error": "Not found"}, 404
            else:
                return {"error": "Unknown Error"}, 500

        accept_header = request.headers.get("Accept", "")
        wants_table = "as=Table" in accept_header

        if wants_table:
            table_response = {
                "kind": "Table",
                "apiVersion": "meta.k8s.io/v1",
                "columnDefinitions": [
                    {"name": "Name", "type": "string", "format": "name",
                     "description": "Space name", "priority": 0},
                    {"name": "Status", "type": "string",
                     "description": "Space status", "priority": 0},
                    {"name": "Age", "type": "string",
                     "description": "Creation timestamp", "priority": 0}
                ],
                "rows": [{
                    "cells": [
                        space["metadata"]["name"],
                        space.get("status", {}).get("phase", "Unknown"),
                        format_age(space["metadata"]["creationTimestamp"])
                    ],
                    "object": space
                }]
            }
            return Response(
                json.dumps(table_response),
                status=200,
                content_type="application/json;as=Table;g=meta.k8s.io;v=v1"
            )
        else:
            return Response(
                json.dumps(space),
                status=200,
                content_type="application/json"
            )

    @extension_api_space_bp.arguments(dict)
    @extension_api_space_bp.response(200)
    def put(self, data, name):
        """Update a space (labels/annotations) [ ]"""
        updated = update_space(name, data)
        if not updated:
            return {"error": "Space not found"}, 404
        return updated

    @extension_api_space_bp.response(200)
    def delete(self, name):
        """Delete a space (namespace) [X]"""
        deleted = delete_space(name)
        if not deleted:
            return {"error": "Space not found"}, 404
        return {"message": f"Space {name} deleted"}
