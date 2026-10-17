"""Self-service kubeconfig — per .skillgrid/artifacts/04-adr-0013-permission-management.md
(ADR-0013): multi-cluster YAML referencing the kubectl credential plugin
(ADR-0011), no embedded token. Stub route returns 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("kubeconfig", __name__, url_prefix="/v1")


class KubeconfigApi(Api):
    resources_namespace = "kubeconfig"
    tags = ["Kubeconfig"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/kubeconfig", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def download(self) -> object:
        raise NotImplementedError_("kubeconfig download not implemented in base structure")
