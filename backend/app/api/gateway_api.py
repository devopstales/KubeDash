"""GatewayApi — the Ingress → Gateway API converter endpoint."""

from flask import g, request
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.api._cluster import cluster_for as _cluster_for
from app.core.errors import RbacDeniedError, ResourceKindNotSupportedError
from app.extensions import db
from app.schemas.gateway_api import GatewayConvertOut
from app.services import rbac
from app.services.gateway_convert import convert_ingress
from app.services.k8s_client import pool

_INGRESS_RBAC_GROUP = "networking.k8s.io"


class GatewayApi(Api):
    """The real ``/api/v1/clusters/<id>/gateway-api/convert`` route."""

    resources_namespace = "gateway-api"
    tags = ["Gateway API"]
    blp = Blueprint("gateway_api", __name__, url_prefix="/v1")

    def on_init(self, app: object) -> None:
        apply_auth(app)

    @blp.route("/clusters/<int:cluster_id>/gateway-api/convert", methods=["POST"])
    @blp.response(200, GatewayConvertOut)
    def convert(self, cluster_id: int) -> dict[str, object]:
        body = request.get_json(silent=True) or {}
        ingress_name = str(body.get("ingressName") or "")
        provider = str(body.get("provider") or "envoy")
        cluster = _cluster_for(g.current_user, cluster_id)
        # ADR-0004 addendum: resolve the namespace ONCE — ingresses is a
        # namespaced kind, so the SAR and the read must ride the SAME
        # namespace. An omitted namespace resolves to "default" (the read
        # default); asking the SAR cluster-wide (namespace=None) for a
        # namespaced resource denies users who hold only a namespaced grant
        # (e.g. in another namespace) → the denial surfaced as 502 on the
        # read instead of the read even being asked.
        ns = str(body.get("namespace") or "") or "default"
        if not rbac.can(
            g.current_user,
            cluster,
            "get",
            "ingresses",
            ns,
            ingress_name,
            _INGRESS_RBAC_GROUP,
            engine=db.engine,
        ):
            raise RbacDeniedError("get on ingresses")
        items = pool.get(cluster).get_ingress(ns, ingress_name)
        if not items:
            raise ResourceKindNotSupportedError(f"Ingress '{ingress_name}' not found")
        ingress = items[0]
        resources, warnings = convert_ingress(ingress, provider=provider)
        return {
            "cluster": cluster.name,
            "namespace": ns,
            "source": "ingress",
            "gatewayClassName": ((resources[0].get("metadata") or {}).get("name") or ""),
            "resources": resources,
            "warnings": warnings,
        }
