"""Namespace-as-a-Service — per .skillgrid/artifacts/04-adr-0015-namespace-as-a-service.md
(ADR-0015): self-service NaaS onboarding requests + approval, TTL'd grants.
Stub routes return 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("namespaces", __name__, url_prefix="/v1")


class NamespacesApi(Api):
    resources_namespace = "namespaces"
    tags = ["Namespaces"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/namespaces/requests", methods=["POST"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def request(self) -> object:
        raise NotImplementedError_("namespace request not implemented in base structure")

    @blp.route("/namespaces/requests/<int:request_id>/approve", methods=["POST"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def approve(self, request_id: int) -> object:
        raise NotImplementedError_("namespace approval not implemented in base structure")
