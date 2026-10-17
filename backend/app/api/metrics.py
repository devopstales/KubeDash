"""Metrics query — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md
(ADR-0003). Thin Prometheus query/query_range clients land with the
observability change. Stub routes return 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("metrics", __name__, url_prefix="/v1")


class MetricsApi(Api):
    resources_namespace = "metrics"
    tags = ["Metrics"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/metrics/query", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def query(self) -> object:
        raise NotImplementedError_("metrics query not implemented in base structure")

    @blp.route("/metrics/query_range", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def query_range(self) -> object:
        raise NotImplementedError_("metrics query_range not implemented in base structure")
