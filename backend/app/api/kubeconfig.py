"""Self-service kubeconfig — per .skillgrid/ARCHITECTURE.md §5B and
.skillgrid/artifacts/04-adr-0013-permission-management.md (ADR-0013):
multi-cluster YAML referencing the kubectl credential plugin (ADR-0011), no
embedded token. TICKET-05 (tracer 2) replaces the 501 stub.

The handler is thin: it calls ``permission.generate_kubeconfig`` (the service
does the binding load, per-cluster CA extraction, and rendering) and wraps
the result in the YAML attachment. The stable error envelope (404
NO_BINDINGS, 500 INTERNAL_ERROR) is the app's ``KubeDashHttpError`` handler
— raised from the service, answered in JSON. The 200 path is the YAML file,
NOT a JSON envelope.
"""
from flask import Response, g
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.config import get_settings
from app.extensions import db
from app.services import permission

#: §5B: the browser download name (the brief pins this exact filename).
FILENAME = "kubedash-kubeconfig.yaml"


class KubeconfigApi(Api):
    """``GET /api/v1/kubeconfig`` — any authenticated user (the shared
    ``apply_auth`` hook covers ``/api/v1/*``; NO ``require_admin`` — a
    non-admin downloads the kubeconfig for THEIR bindings)."""

    resources_namespace = "kubeconfig"
    tags = ["Kubeconfig"]
    blp = Blueprint("kubeconfig", __name__, url_prefix="/v1")

    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/kubeconfig", methods=["GET"])
    @blp.doc(
        responses={
            200: ("The caller's kubeconfig as a YAML attachment.", None),
            401: "UNAUTHORIZED",
            404: "NO_BINDINGS",
            500: "INTERNAL_ERROR",
        }
    )
    def download(self) -> Response:
        yaml_text = permission.generate_kubeconfig(
            user_sub=g.current_user.sub,
            db_session=db.session,
            settings=get_settings(),
        )
        # The 200 path is a file, not the JSON envelope: explicit mimetype +
        # the attachment header the browser download contract pins.
        response = Response(yaml_text, mimetype="application/yaml")
        response.headers["Content-Disposition"] = f'attachment; filename="{FILENAME}"'
        return response
