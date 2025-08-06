from flask import Flask
from .project import project_bp

def register_api_extension(app: Flask):
    app.register_blueprint(project_bp, url_prefix="/apis/mygroup.example.com/v1/projects")
    # Later you might also import: user_bp, group_bp, etc.

##################################################################
# Register api service
##################################################################
# apiVersion: apiregistration.k8s.io/v1
# kind: APIService
# metadata:
#   name: v1.mygroup.example.com
# spec:
#   group: mygroup.example.com
#   version: v1
#   insecureSkipTLSVerify: true
#   groupPriorityMinimum: 1000
#   versionPriority: 15
#   service: null
#   caBundle: ""
#   url: https://YOUR_NGROK_URL/apis/mygroup.example.com/v1


#
# kubectl get --raw /apis/mygroup.example.com/v1/projects \
#  --as=YOUR_USERNAME
#
# curl -k \
#   -H "Impersonate-User: alice" \
#   -H "Impersonate-Group: dev-team" \
#   -H "Impersonate-Group: qa-team" \
#   https://localhost:8443/apis/mygroup.example.com/v1/projects
#
# curl -k -H "Impersonate-User: YOUR_USERNAME" \
#   https://localhost:8443/apis/mygroup.example.com/v1/projects
#
## LIST
# curl -k -H "Impersonate-User: alice" \
#      https://localhost:8443/apis/mygroup.example.com/v1/projects
# 
## GET
# curl -k -H "Impersonate-User: alice" \
#      https://localhost:8443/apis/mygroup.example.com/v1/projects/dev
# 
## CREATE
# curl -k -H "Content-Type: application/json" \
#      -d '{"metadata": {"name": "newproj"}}' \
#      https://localhost:8443/apis/mygroup.example.com/v1/projects -X POST
# 
## UPDATE (labels or annotations)
# curl -k -H "Content-Type: application/json" \
#      -d '{"metadata": {"annotations": {"owner": "bob"}}}' \
#      https://localhost:8443/apis/mygroup.example.com/v1/projects/dev -X PUT
# 
## DELETE
# curl -k https://localhost:8443/apis/mygroup.example.com/v1/projects/dev -X DELETE
# 