from flask.views import MethodView
from flask import request, jsonify, current_app

from .schemas import ProjectSchema
from . import project_bp
from .service import (
    list_visible_projects, get_project, to_project,
    create_project, update_project, delete_project
)

@project_bp.route('/v1')
class ProjectResource(MethodView):
    @project_bp.response(200)
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
                        "get", "list", "watch", "create", "update", "patch", "delete"
                    ],
                    "shortNames": ["prj"]
                }
            ]
        })

@project_bp.route('/v1/projects')
class ProjectListResource(MethodView):
    @project_bp.response(200)
    def get(self):
        """List projects the user has access to"""
        project_obj_list = {
            "kind": "ProjectList",
            "apiVersion": "devopstales.github.io/v1",
            "items": []
        }
        
        # Get user identity
        user = request.headers.get("X-Remote-User") or request.headers.get("Impersonate-User")
        
        # Handle group headers properly
        groups = []
        group_header = request.headers.get("X-Remote-Group") or request.headers.get("Impersonate-Group")
        if group_header:
            groups = [g.strip() for g in group_header.split(',') if g.strip()]
        
        # Handle system components
        if not user and not groups:
            auth_header = request.headers.get("Authorization")
            if auth_header and ("system:serviceaccount" in auth_header or "system:kube-controller-manager" in auth_header):
                user = auth_header.split(":")[-1] if ":" in auth_header else auth_header
                groups = ["system:authenticated"]
        
        if not user and not groups:
            return {"message": "Authorization credentials required"}, 401
        
        # Get visible projects
        allowed_ns_list = list_visible_projects(user, groups)
        
        for allowed_ns in allowed_ns_list:
            project_objs = to_project(allowed_ns, user, None)
            project_obj_list["items"].append(project_objs)
            
        return project_obj_list

    @project_bp.arguments(ProjectSchema)
    @project_bp.response(201, ProjectSchema)
    def post(self, data):
        """Create a new project (namespace) [ ]"""
        name = data["metadata"]["name"]
        project_obj = create_project(name, data.get("spec", {}))
        return project_obj

@project_bp.route('/v1/projects/<string:name>')
class ProjectResource(MethodView):
    @project_bp.response(200)
    def get(self, name):
        """Get a single project [X]"""
        user = request.headers.get("Impersonate-User")
        groups = request.headers.getlist("Impersonate-Group")
        project, status = get_project(name, user, groups)
        if status == 200:
            return project
        elif status == 401:
            return {"error": "Unauthorized"}, 401
        elif status == 404:
            return {"error": "Not found"}, 404
        else:
            return {"error": "Unknown Error"}, 500

    @project_bp.arguments(dict)
    @project_bp.response(200)
    def put(self, data, name):
        """Update a project (labels/annotations) [ ]"""
        updated = update_project(name, data)
        if not updated:
            return {"error": "Project not found"}, 404
        return updated

    @project_bp.response(200)
    def delete(self, name):
        """Delete a project (namespace) [X]"""
        deleted = delete_project(name)
        if not deleted:
            return {"error": "Project not found"}, 404
        return {"message": f"Project {name} deleted"}
