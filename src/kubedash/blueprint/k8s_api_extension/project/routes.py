from flask.views import MethodView
from flask import request
from . import project_bp
from .service import (
    list_visible_projects, get_project,
    create_project, update_project, delete_project
)

@project_bp.route('/')
class ProjectListResource(MethodView):
    @project_bp.response(200)
    def get(self):
        """List projects the user has access to"""
        user = request.headers.get("Impersonate-User")
        groups = request.headers.getlist("Impersonate-Group")
        return {
            "kind": "ProjectList",
            "apiVersion": "mygroup.example.com/v1",
            "items": list_visible_projects(user, groups)
        }

    @project_bp.arguments(dict)  # you can later define Marshmallow schemas
    @project_bp.response(201)
    def post(self, data):
        """Create a new project (namespace)"""
        name = data.get("metadata", {}).get("name")
        return create_project(name)

@project_bp.route('/<string:name>')
class ProjectResource(MethodView):
    @project_bp.response(200)
    def get(self, name):
        """Get a single project"""
        user = request.headers.get("Impersonate-User")
        groups = request.headers.getlist("Impersonate-Group")
        project = get_project(name, user, groups)
        if not project:
            return {"error": "Not found or unauthorized"}, 404
        return project

    @project_bp.arguments(dict)
    @project_bp.response(200)
    def put(self, data, name):
        """Update a project (labels/annotations)"""
        updated = update_project(name, data)
        if not updated:
            return {"error": "Project not found"}, 404
        return updated

    @project_bp.response(200)
    def delete(self, name):
        """Delete a project (namespace)"""
        deleted = delete_project(name)
        if not deleted:
            return {"error": "Project not found"}, 404
        return {"message": f"Project {name} deleted"}
