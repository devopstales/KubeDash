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

@extension_api_root_bp.route('/openapi/v2')
def openapi_schema():
    """Serve OpenAPI v2 spec for Kubernetes discovery"""
    schema = {
        "swagger": "2.0",
        "info": {"title": "Spaces API", "version": "v1"},
        "paths": {
            "/apis/devopstales.github.io/v1/spaces": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "OK",
                            "schema": {
                                "$ref": "#/definitions/SpaceList"
                            }
                        }
                    }
                }
            }
        },
        "definitions": {
            "Space": {
                # Match your CRD schema here
                "type": "object",
                "required": ["apiVersion", "kind", "metadata"],
                "properties": {
                    "apiVersion": {"type": "string"},
                    "kind": {"type": "string"},
                    "metadata": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "labels": {"type": "object"},
                            "annotations": {"type": "object"}
                        }
                    },
                    "spec": {
                        "type": "object",
                        "properties": {
                            "description": {"type": "string"},
                            "owner": {"type": "string"},
                            "resources": {
                                "type": "object",
                                "properties": {
                                    "limits": {
                                        "type": "object",
                                        "properties": {
                                            "cpu": {"type": "string"},
                                            "memory": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "status": {
                        "type": "object",
                        "properties": {
                            "phase": {"type": "string"}
                        }
                    }
                }
            },
            "SpaceList": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "$ref": "#/definitions/Space"
                        }
                    }
                }
            }
        }
    }
    return jsonify(schema)

@extension_api_root_bp.route("/openapi/v3")
def openapi_v3():
    """Serve OpenAPI v3 spec for Kubernetes discovery"""
    # For now, just reuse the v2 spec to satisfy dashboard requests
    return openapi_schema()

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