"""Log query — per .skillgrid/artifacts/04-adr-0003-observability-query-only.md
(ADR-0003). Live Loki query lands with the observability change; SSE log tail
per ADR-0009. Stub route returns 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("logs", __name__, url_prefix="/v1")


class LogsApi(Api):
    resources_namespace = "logs"
    tags = ["Logs"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/logs/query", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def query(self) -> object:
        raise NotImplementedError_("logs query not implemented in base structure")
