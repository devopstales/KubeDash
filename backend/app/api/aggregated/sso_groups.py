"""Aggregated SSOGroups — per .skillgrid/artifacts/04-adr-0012-aggregated-api.md
(ADR-0012): GET /apis/auth.kubedash.io/v1/sso-groups. Served on the port-8443
mTLS app, not the main /api/v1 app (registered by the owning change); stub
module + route shape only."""
from flask_smorest import Api, Blueprint

from app.core.errors import NotImplementedError_

blp = Blueprint("agg_sso_groups", __name__, url_prefix="/apis/auth.kubedash.io/v1")


class AggregatedSsoGroupsApi(Api):
    resources_namespace = "agg_sso_groups"
    tags = ["Aggregated"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        # The 8443 app is mTLS-protected at the TLS layer, not JWT.
        pass

    @blp.route("/sso-groups", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def list(self) -> object:
        raise NotImplementedError_("aggregated sso-groups not implemented in base structure")
