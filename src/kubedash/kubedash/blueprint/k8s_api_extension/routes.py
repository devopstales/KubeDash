from flask.views import MethodView
from flask import request, Response, jsonify, current_app

import json
from datetime import datetime, timezone

from .schemas import ProjectSchema
from . import extension_api_project_bp
from .service import (
    validate_user, format_age,
    list_visible_projects, get_project, to_project,
    create_project, update_project, delete_project
)
@extension_api_project_bp.route("")
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


@extension_api_project_bp.route('/v1')
class ProjectResource(MethodView):
    @extension_api_project_bp.response(200)
    def get(self):
        """Serve the APIResourceList for discovery"""
        return jsonify({
            "kind": "APIResourceList",
            "apiVersion": "v1",
            "groupVersion": "devopstales.github.io/v1",
            "resources": [
                {
                    "name": "projects",
                    "singularName": "project",
                    "namespaced": False,
                    "kind": "Project",
                    "verbs": [
                        "get", 
                        "list", 
                        "watch", 
                        "create", 
                        "update", 
                        "patch", 
                        "delete"
                    ],
                    "shortNames": ["prj"]
                },
                {
                    "name": "projects/finalize",
                    "singularName": "",
                    "namespaced": False,
                    "kind": "Project",
                    "verbs": [
                        "update"
                    ]
                },
                {
                    "name": "projects/status",
                    "singularName": "",
                    "namespaced": False,
                    "kind": "Project",
                    "verbs": [
                        "get",
                        "patch",
                        "update"
                    ]
                }
            ]
        })

@extension_api_project_bp.route('/v1/projects')
class ProjectListResource(MethodView):
    @extension_api_project_bp.response(200)
    def get(self):
        """List projects the user has access to"""
        
        user, groups = validate_user(request)
        allowed_ns_list = list_visible_projects(user, groups)
        
        #project_obj_list = {
        #    "kind": "ProjectList",
        #    "apiVersion": "devopstales.github.io/v1",
        #    "items": []
        #}
        
        project_obj_list = {
            "kind": "Table",
            "apiVersion": "meta.k8s.io/v1",
            "columnDefinitions": [
                {
                    "name": "Name",
                    "type": "string",
                    "format": "name",
                    "description": "Project name",
                    "jsonPath": ".metadata.name"
                },
                {
                    "name": "Status",
                    "type": "string",
                    "description": "Project status",
                    "jsonPath": ".status.phase"
                },
                {
                    "name": "Age",
                    "type": "date",  # lets kubectl render human-readable "3y 316d"
                    "description": "Creation timestamp",
                    "jsonPath": ".metadata.creationTimestamp"
                }
            ],
            "rows": []
        }
        
        for allowed_ns in allowed_ns_list:
            project_obj = to_project(allowed_ns, user, None)
            #project_obj_list["items"].append(project_obj)
            
            ts = allowed_ns.metadata.creation_timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        
            project_obj_list["rows"].append({
                "cells": [
                    project_obj["metadata"]["name"],
                    project_obj.get("status", {}).get("phase", ""),
                    format_age(ts)
                ],
                "object": project_obj
            })
            
        return Response(
            json.dumps(project_obj_list),
            status=200,
            content_type="application/json;as=Table;g=meta.k8s.io;v=v1"
        )

    @extension_api_project_bp.arguments(ProjectSchema)
    @extension_api_project_bp.response(201, ProjectSchema)
    def post(self, data):
        """Create a new project (namespace) [ ]"""
        name = data["metadata"]["name"]
        project_obj = create_project(name, data.get("spec", {}))
        return project_obj

@extension_api_project_bp.route('/v1/projects/<string:name>')
class ProjectResource(MethodView):
    @extension_api_project_bp.response(200)
    def get(self, name):
        """Get a single project [X]"""
        user, groups = validate_user(request)

        project, status = get_project(name, user, groups)
        if status == 200:
            return project
        elif status == 401:
            return {"error": "Unauthorized"}, 401
        elif status == 404:
            return {"error": "Not found"}, 404
        else:
            return {"error": "Unknown Error"}, 500

    @extension_api_project_bp.arguments(dict)
    @extension_api_project_bp.response(200)
    def put(self, data, name):
        """Update a project (labels/annotations) [ ]"""
        updated = update_project(name, data)
        if not updated:
            return {"error": "Project not found"}, 404
        return updated

    @extension_api_project_bp.response(200)
    def delete(self, name):
        """Delete a project (namespace) [X]"""
        deleted = delete_project(name)
        if not deleted:
            return {"error": "Project not found"}, 404
        return {"message": f"Project {name} deleted"}
