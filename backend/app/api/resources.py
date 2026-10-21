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
import re

from flask import g, request
from flask_smorest import Api, Blueprint

from app.api._authhook import apply_auth
from app.core.errors import (
    ClusterAlreadyExistsError,
    InvalidKubeconfigError,
    RbacDeniedError,
    ResourceKindNotSupportedError,
)
from app.core.security import require_admin
from app.schemas.resource import NamespaceIn, NamespaceMutationOut, ResourceListOut
from app.services import rbac
from app.services.k8s_client import LOCAL_CLUSTER_ID, bound_cluster_or_404, pool

_NAMESPACE_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_PROTECTED_NAMESPACES = frozenset(
    {"default", "kube-system", "kube-public", "kube-node-lease"}
)


def _cluster_for(user: object, cluster_id: int) -> object:
    if cluster_id == LOCAL_CLUSTER_ID:
        from app.api.clusters import _local_cluster

        return _local_cluster()
    return bound_cluster_or_404(user, cluster_id)

#: kind → (K8sClient method, kubernetes resource name, API group)
_RBAC_GROUP = "rbac.authorization.k8s.io"
_KINDS: dict[str, tuple[str, str, str]] = {
    "pods": ("list_pods", "pods", ""),
    "namespaces": ("list_namespaces", "namespaces", ""),
    "serviceaccounts": ("list_serviceaccounts", "serviceaccounts", ""),
    "roles": ("list_roles", "roles", _RBAC_GROUP),
    "rolebindings": ("list_rolebindings", "rolebindings", _RBAC_GROUP),
    "clusterroles": ("list_cluster_roles", "clusterroles", _RBAC_GROUP),
    "clusterrolebindings": ("list_cluster_role_bindings", "clusterrolebindings", _RBAC_GROUP),
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
        cluster = _cluster_for(g.current_user, cluster_id)
        method, api_resource, api_group = _KINDS[kind]
        namespace = request.args.get("namespace")
        name = request.args.get("name")
        if name:
            if kind not in _GETTERS:
                raise ResourceKindNotSupportedError(f"name lookup on kind '{kind}' not supported")
            namespace = namespace or "default"
            allowed = rbac.can(
                g.current_user, cluster, "get", api_resource, namespace, name, api_group
            )
            if not allowed:
                raise RbacDeniedError(f"get on {api_resource}")
            items = getattr(pool.get(cluster), _GETTERS[kind])(namespace, name)
            return {"items": items, "kind": kind, "cluster": cluster.name}
        if not rbac.can(g.current_user, cluster, "list", api_resource, namespace, None, api_group):
            raise RbacDeniedError(f"list on {api_resource}")
        items = getattr(pool.get(cluster), method)(namespace)
        return {"items": items, "kind": kind, "cluster": cluster.name}

    @blp.route("/clusters/<int:cluster_id>/resources/namespaces", methods=["POST"])
    @blp.arguments(NamespaceIn)
    @blp.response(201, NamespaceMutationOut)
    @blp.doc(
        responses={
            403: "RBAC_DENIED",
            404: "CLUSTER_NOT_FOUND",
            409: "CLUSTER_ALREADY_EXISTS",
            422: "INVALID_KUBECONFIG",
            502: "CLUSTER_UNREACHABLE",
        }
    )
    def create_namespace(
        self, args: dict[str, object], cluster_id: int
    ) -> tuple[dict[str, str], int]:
        require_admin()
        name = str(args["name"])
        if not _NAMESPACE_NAME.fullmatch(name):
            raise InvalidKubeconfigError("invalid Kubernetes namespace name")
        cluster = _cluster_for(g.current_user, cluster_id)
        if not rbac.can(g.current_user, cluster, "create", "namespaces", None, None, ""):
            raise RbacDeniedError("create on namespaces")
        pool.get(cluster).create_namespace(name)
        return {"name": name}, 201

    @blp.route(
        "/clusters/<int:cluster_id>/resources/namespaces/<name>",
        methods=["DELETE"],
    )
    @blp.response(200, NamespaceMutationOut)
    @blp.doc(
        responses={
            403: "RBAC_DENIED",
            404: "CLUSTER_NOT_FOUND",
            409: "CLUSTER_ALREADY_EXISTS (protected namespace)",
            502: "CLUSTER_UNREACHABLE",
        }
    )
    def delete_namespace(self, cluster_id: int, name: str) -> tuple[dict[str, str], int]:
        require_admin()
        if name in _PROTECTED_NAMESPACES:
            raise ClusterAlreadyExistsError(f"namespace '{name}' is protected")
        cluster = _cluster_for(g.current_user, cluster_id)
        if not rbac.can(g.current_user, cluster, "delete", "namespaces", None, name, ""):
            raise RbacDeniedError("delete on namespaces")
        pool.get(cluster).delete_namespace(name)
        return {"name": name}, 200
