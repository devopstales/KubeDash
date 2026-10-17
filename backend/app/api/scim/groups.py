"""SCIM groups — per .skillgrid/artifacts/04-adr-0018-scim-2-0-gateway.md
(ADR-0018): IdP/HR push of SCIM Group resources. Stub route returns
501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("scim_groups", __name__, url_prefix="/v1")


class ScimGroupsApi(Api):
    resources_namespace = "scim_groups"
    tags = ["SCIM"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/scim/v2/groups", methods=["POST"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def create(self) -> object:
        raise NotImplementedError_("scim groups not implemented in base structure")
