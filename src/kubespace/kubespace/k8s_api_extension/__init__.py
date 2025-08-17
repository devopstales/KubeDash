from flask_smorest import Blueprint
from flask.views import MethodView

from flask import jsonify

##################################################################
# Root Api Blueprint
##################################################################

extension_api_root_bp = Blueprint(
    "extension apis",
    __name__,
    description="Kubernetes Extension APIs"
)

@extension_api_root_bp.route("/apis")
class APIGroupListResource(MethodView):
    def get(self):
        """Root API discovery - lists all API groups"""
        return {
            "kind": "APIGroupList",
            "apiVersion": "v1",
            "groups": [
                {
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
            ]
        }

@extension_api_root_bp.route("/openapi/v2")
def openapi_v2():
    """
    Minimal OpenAPI v2 spec for Kubernetes discovery
    """
    # Example: only include your Space CRD
    spec = {
        "swagger": "2.0",
        "info": {"title": "DevOpsTales Extension API", "version": "v1"},
        "paths": {
            "/apis/devopstales.github.io/v1/spaces": {
                "get": {
                    "summary": "List spaces",
                    "responses": {"200": {"description": "List of spaces"}}
                },
                "post": {
                    "summary": "Create a space",
                    "responses": {"201": {"description": "Space created"}}
                }
            },
            "/apis/devopstales.github.io/v1/spaces/{name}": {
                "get": {"summary": "Get space"},
                "put": {"summary": "Update space"},
                "delete": {"summary": "Delete space"}
            }
        }
    }
    return jsonify(spec)

@extension_api_root_bp.route("/openapi/v3")
def openapi_v3():
    """Serve OpenAPI v3 spec for Kubernetes discovery (minimal, reusing v2)"""
    # For now, just reuse the v2 spec to satisfy dashboard requests
    return openapi_v2()

##################################################################
# Space Object Blueprint
##################################################################

extension_api_space_bp = Blueprint(
    "extension apis space",
    __name__,
    url_prefix="/apis/devopstales.github.io",
    description="Kubernetes Space Extension API"
)



from . import routes


##################################################################
# Register api service
##################################################################
# kubectl get --raw /apis/devopstales.github.io/v1/spaces \
#  --as=YOUR_USERNAME
#
## LIST
# curl -k \
#   -H "Impersonate-User: alice" \
#   -H "Impersonate-Group: dev-team" \
#   -H "Impersonate-Group: qa-team" \
#   https://localhost:8443/apis/devopstales.github.io/v1/spaces
#
# curl -k -H "Impersonate-User: alice" \
#      https://localhost:8443/apis/devopstales.github.io/v1/spaces
# 
## GET
# curl -k -H "Impersonate-User: alice" \
#      https://localhost:8443/apis/devopstales.github.io/v1/spaces/dev
# 
## CREATE
# curl -k -H "Content-Type: application/json" \
#      -d '{"metadata": {"name": "newproj"}}' \
#      https://localhost:8443/apis/devopstales.github.io/v1/spaces -X POST
# 
## UPDATE (labels or annotations)
# curl -k -H "Content-Type: application/json" \
#      -d '{"metadata": {"annotations": {"owner": "bob"}}}' \
#      https://localhost:8443/apis/devopstales.github.io/v1/spaces/dev -X PUT
# 
## DELETE
# curl -k https://localhost:8443/apis/devopstales.github.io/v1/spaces/dev -X DELETE
# 