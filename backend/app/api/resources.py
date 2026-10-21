"""ResourceApi (R4) — the generic cluster-resource list endpoint:
``GET /api/v1/clusters/<id>/resources/<kind>`` (query ``namespace?``,
``name?``). With ``name`` (kinds in ``_GETTERS`` only) the SAR verb is
``get`` on that one object and ``items`` holds zero or one entry.

Replaces the Task 6 placeholder. The kind routing table ``_KINDS`` is the
seam later kinds (deployments, services, …) plug into: adding a kind is one
table row + one ``K8sClient.list_<kind>`` method, no API changes. The ADR-0004
enforcement point is ``rbac.can`` — asked BEFORE the list, 403 RBAC_DENIED
on deny; the binding gate is Task 4's ``bound_cluster_or_404`` (404
CLUSTER_NOT_FOUND, which does not distinguish missing cluster from missing
binding).
"""
from flask import g, request
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import RbacDeniedError, ResourceKindNotSupportedError
from app.schemas.resource import ResourceListOut
from app.services import rbac
from app.services.k8s_client import LOCAL_CLUSTER_ID, bound_cluster_or_404, pool

#: kind → (K8sClient method, kubernetes resource name, API group)
_RBAC_GROUP = "rbac.authorization.k8s.io"
_KINDS: dict[str, tuple[str, str, str]] = {
    "pods": ("list_pods", "pods", ""),
    "namespaces": ("list_namespaces", "namespaces", ""),
    "serviceaccounts": ("list_serviceaccounts", "serviceaccounts", ""),
    "roles": ("list_roles", "roles", _RBAC_GROUP),
    "rolebindings": ("list_rolebindings", "rolebindings", _RBAC_GROUP),
    "clusterroles": ("list_cluster_roles", "clusterroles", _RBAC_GROUP),
    "secrets": ("list_secrets", "secrets", ""),
}

#: kind → K8sClient method for a single-object ``?name=`` lookup
_GETTERS: dict[str, str] = {
    "secrets": "get_secret",
}


class ResourceApi(Api):
    """The real ``/api/v1/clusters/<id>/resources/<kind>`` route."""

    resources_namespace = "resources"
    tags = ["Resources"]
    blp = Blueprint("resources", __name__, url_prefix="/v1")

    def on_init(self, app: object) -> None:
        # The shared auth-hook pattern (app-wide before_request scoped to
        # /api/v1/* domain routes): identical to Task 4's ClusterApi.
        apply_auth(app)

    @blp.route("/clusters/<int:cluster_id>/resources/<kind>", methods=["GET"])
    @blp.response(200, ResourceListOut)
    @blp.doc(
        responses={
            404: "RESOURCE_KIND_NOT_SUPPORTED or CLUSTER_NOT_FOUND (binding gate)",
            403: "RBAC_DENIED",
        }
    )
    def list_resources(self, cluster_id: int, kind: str) -> dict[str, object]:
        if kind not in _KINDS:
            raise ResourceKindNotSupportedError(f"kind '{kind}' not supported")
        if cluster_id == LOCAL_CLUSTER_ID:
            # id 0: the synthetic local cluster bypasses the binding gate (no
            # row 0 exists) and goes straight to the pool, whose id-0 branch
            # routes to the admin client or raises CLUSTER_NOT_FOUND. The
            # synthetic object is built by clusters._local_cluster() (the
            # single source for the OD-D reserved id-0 row).
            from app.api.clusters import _local_cluster

            cluster = _local_cluster()
        else:
            cluster = bound_cluster_or_404(g.current_user, cluster_id)
        method, api_resource, api_group = _KINDS[kind]
        namespace = request.args.get("namespace")
        name = request.args.get("name")
        if name:
            if kind not in _GETTERS:
                raise ResourceKindNotSupportedError(f"name lookup on kind '{kind}' not supported")
            namespace = namespace or "default"
            if not rbac.can(g.current_user, cluster, "get", api_resource, namespace, name, api_group):
                raise RbacDeniedError(f"get on {api_resource}")
            items = getattr(pool.get(cluster), _GETTERS[kind])(namespace, name)
            return {"items": items, "kind": kind, "cluster": cluster.name}
        if not rbac.can(g.current_user, cluster, "list", api_resource, namespace, None, api_group):
            raise RbacDeniedError(f"list on {api_resource}")
        items = getattr(pool.get(cluster), method)(namespace)
        return {"items": items, "kind": kind, "cluster": cluster.name}
