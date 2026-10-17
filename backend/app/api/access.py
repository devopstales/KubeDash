"""Privileged Access Management (PAM) — per
.skillgrid/artifacts/04-adr-0016-privileged-access-management.md (ADR-0016):
additive elevation requests, auto-revert at TTL, break-glass.
Stub routes return 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("access", __name__, url_prefix="/v1")


class AccessApi(Api):
    resources_namespace = "access"
    tags = ["Access"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/access/requests", methods=["POST"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def request(self) -> object:
        raise NotImplementedError_("access request not implemented in base structure")

    @blp.route("/access/requests/<int:request_id>/revoke", methods=["POST"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def revoke(self, request_id: int) -> object:
        raise NotImplementedError_("access revoke not implemented in base structure")
