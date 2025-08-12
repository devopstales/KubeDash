from flask_smorest import Blueprint

project_bp = Blueprint(
    "project",
    __name__,
   url_prefix="/apis/devopstales.github.io",
    description="Kubernetes Project Extension API"
)

from . import routes


##################################################################
# Register api service
##################################################################
# kubectl get --raw /apis/devopstales.github.io/v1/projects \
#  --as=YOUR_USERNAME
#
## LIST
# curl -k \
#   -H "Impersonate-User: alice" \
#   -H "Impersonate-Group: dev-team" \
#   -H "Impersonate-Group: qa-team" \
#   https://localhost:8443/apis/devopstales.github.io/v1/projects
#
# curl -k -H "Impersonate-User: alice" \
#      https://localhost:8443/apis/devopstales.github.io/v1/projects
# 
## GET
# curl -k -H "Impersonate-User: alice" \
#      https://localhost:8443/apis/devopstales.github.io/v1/projects/dev
# 
## CREATE
# curl -k -H "Content-Type: application/json" \
#      -d '{"metadata": {"name": "newproj"}}' \
#      https://localhost:8443/apis/devopstales.github.io/v1/projects -X POST
# 
## UPDATE (labels or annotations)
# curl -k -H "Content-Type: application/json" \
#      -d '{"metadata": {"annotations": {"owner": "bob"}}}' \
#      https://localhost:8443/apis/devopstales.github.io/v1/projects/dev -X PUT
# 
## DELETE
# curl -k https://localhost:8443/apis/devopstales.github.io/v1/projects/dev -X DELETE
# 