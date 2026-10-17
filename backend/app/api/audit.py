"""Audit log read + export — per .skillgrid/artifacts/04-adr-0013-permission-management.md
(permission change owns the audit reads) and §3.3 timeline/audit service.
The ``audit_log`` table already exists (Task 2 migration); the read/export
routes land with the owning change. Stub routes return 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("audit", __name__, url_prefix="/v1")


class AuditApi(Api):
    resources_namespace = "audit"
    tags = ["Audit"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/audit", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def read(self) -> object:
        raise NotImplementedError_("audit read not implemented in base structure")

    @blp.route("/audit/export", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def export(self) -> object:
        raise NotImplementedError_("audit export not implemented in base structure")
