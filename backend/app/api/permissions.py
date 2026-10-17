"""Permission management — per .skillgrid/artifacts/04-adr-0013-permission-management.md
(ADR-0013): /admin/permissions/* (bind, unbind, templates). Role templates
live in Postgres (``rbac_templates``), not as prefixed ClusterRoles.
Stub routes return 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("permissions", __name__, url_prefix="/v1")


class PermissionsApi(Api):
    resources_namespace = "permissions"
    tags = ["Permissions"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/admin/permissions/bind", methods=["POST"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def bind(self) -> object:
        raise NotImplementedError_("permissions bind not implemented in base structure")

    @blp.route("/admin/permissions/templates", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def list_templates(self) -> object:
        raise NotImplementedError_("permissions templates not implemented in base structure")
