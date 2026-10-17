"""kubectl credential plugin bootstrap — per
.skillgrid/artifacts/04-adr-0011-kubectl-credential-plugin.md (ADR-0011):
unauthenticated (bootstrapping auth) AuthConfig endpoint,
TLS + rate-limited. The in-flight kubectl-oidc-plugin change replaces this
body; the file-map guard + the ``register_apis`` line below keep the
registration point alive until then. Stub route returns 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.core.errors import NotImplementedError_

blp = Blueprint("kubectl_auth", __name__, url_prefix="/v1")


class KubectlAuthApi(Api):
    resources_namespace = "kubectl_auth"
    tags = ["KubectlAuth"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        # Unauthenticated by design (the plugin calls this BEFORE it has a
        # token) — no apply_auth. TLS + rate limiting land with the plugin
        # change.
        pass

    @blp.route("/kubectl/auth/v1/config", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def auth_config(self) -> object:
        raise NotImplementedError_("kubectl auth config not implemented in base structure")
