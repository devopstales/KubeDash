"""Aggregated SSOUsers — per .skillgrid/artifacts/04-adr-0012-aggregated-api.md
(ADR-0012): GET /apis/auth.kubedash.io/v1/sso-users. Served on the port-8443
mTLS app, not the main /api/v1 app (registered by the owning change); stub
module + route shape only."""
from flask_smorest import Api, Blueprint

from app.core.errors import NotImplementedError_

blp = Blueprint("agg_sso_users", __name__, url_prefix="/apis/auth.kubedash.io/v1")


class AggregatedSsoUsersApi(Api):
    resources_namespace = "agg_sso_users"
    tags = ["Aggregated"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        # The 8443 app is mTLS-protected at the TLS layer, not JWT.
        pass

    @blp.route("/sso-users", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def list(self) -> object:
        raise NotImplementedError_("aggregated sso-users not implemented in base structure")
