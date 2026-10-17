# ponytail: Task 5 replaces this placeholder with the real ResourceApi (R4).
# Minimal one-route stub so the R9 file-map guard stays green before Wave 5.
"""Generic K8s resource CRUD — per .skillgrid/artifacts/04-adr-0004-rbac-proxy-sar.md
(ADR-0004). Task 5 (Wave 5) overwrites this module with the real
``/clusters/<id>/resources/<kind>`` route; the route shape below is 501."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("resources", __name__, url_prefix="/v1")


class ResourceApi(Api):
    resources_namespace = "resources"
    tags = ["Resources"]
    blp = blp  # register_apis registers instance.blp

    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/resources/<kind>", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def list_resources(self, kind: str) -> object:
        raise NotImplementedError_("resources not implemented in base structure")
