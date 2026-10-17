"""Trace search + detail — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md
(ADR-0003). Tempo/Jaeger clients land with the observability change.
Stub routes return 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("traces", __name__, url_prefix="/v1")


class TracesApi(Api):
    resources_namespace = "traces"
    tags = ["Traces"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/traces", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def search(self) -> object:
        raise NotImplementedError_("traces search not implemented in base structure")

    @blp.route("/traces/<trace_id>", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def detail(self, trace_id: str) -> object:
        raise NotImplementedError_("traces detail not implemented in base structure")
