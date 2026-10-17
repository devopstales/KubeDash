"""Admin — users, cluster bindings, settings (ARCHITECTURE.md §3.2 admin Api).
The user/binding CRUD rides on Task 2's models + Task 4's cluster registry;
the routes land with the owning change. Stub routes return 501 NOT_IMPLEMENTED."""
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import NotImplementedError_

blp = Blueprint("admin", __name__, url_prefix="/v1")


class AdminApi(Api):
    resources_namespace = "admin"
    tags = ["Admin"]
    blp = blp  # register_apis registers instance.blp
    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/admin/users", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def list_users(self) -> object:
        raise NotImplementedError_("admin users not implemented in base structure")

    @blp.route("/admin/clusters", methods=["GET"])
    @blp.doc(responses={501: "NOT_IMPLEMENTED"})
    def list_clusters(self) -> object:
        raise NotImplementedError_("admin clusters not implemented in base structure")
