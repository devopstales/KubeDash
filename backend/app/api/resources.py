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
from app.api._cluster import cluster_for as _cluster_for
from app.core.errors import (
    ClusterAlreadyExistsError,
    ClusterNotFoundError,
    ClusterUnreachableError,
    InvalidKubeconfigError,
    RbacDeniedError,
    ResourceKindNotSupportedError,
)
from app.core.security import require_admin
from app.schemas.resource import NamespaceIn, NamespaceMutationOut, ResourceListOut
from app.services import rbac
from app.services.k8s_client import pool

_NAMESPACE_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_PROTECTED_NAMESPACES = frozenset(
    {"default", "kube-system", "kube-public", "kube-node-lease"}
)

#: kind → (K8sClient method, kubernetes resource name, API group)
_RBAC_GROUP = "rbac.authorization.k8s.io"
_CRD_GROUP = "apiextensions.k8s.io"
_KINDS: dict[str, tuple[str, str, str]] = {
    "pods": ("list_pods", "pods", ""),
    "namespaces": ("list_namespaces", "namespaces", ""),
    "nodes": ("list_nodes", "nodes", ""),
    "serviceaccounts": ("list_serviceaccounts", "serviceaccounts", ""),
    "roles": ("list_roles", "roles", _RBAC_GROUP),
    "rolebindings": ("list_rolebindings", "rolebindings", _RBAC_GROUP),
    "clusterroles": ("list_cluster_roles", "clusterroles", _RBAC_GROUP),
    "clusterrolebindings": ("list_cluster_role_bindings", "clusterrolebindings", _RBAC_GROUP),
    "secrets": ("list_secrets", "secrets", ""),
    "crds": ("list_crds", "customresourcedefinitions", _CRD_GROUP),
    "networkpolicies": ("list_network_policies", "networkpolicies", "networking.k8s.io"),
    "ciliumnetworkpolicies": ("list_cilium_network_policies", "ciliumnetworkpolicies", "cilium.io"),
    "ciliumclusterwidenetworkpolicies": (
        "list_cilium_clusterwide_network_policies",
        "ciliumclusterwidenetworkpolicies",
        "cilium.io",
    ),
    "priorityclasses": ("list_priority_classes", "priorityclasses", "scheduling.k8s.io"),
    # RuntimeClass (node.k8s.io, cluster-scoped) — the 4.1-parity nav leaf
    # resolved by TASK-046 (list + data views; ADR-0022 placement).
    "runtimeclasses": ("list_runtime_classes", "runtimeclasses", "node.k8s.io"),
    # StorageClass (storage/v1, cluster-scoped) — the 4.1-parity nav leaf
    # resolved by TASK-052 (list + data views; ADR-0022 placement). The 4.1
    # route name was singular; the API kind is the plural.
    "storageclasses": ("list_storage_classes", "storageclasses", ""),
    # ResourceQuota (core, namespaced) — the 4.1-parity nav leaf resolved by
    # TASK-047 (list + data views; ADR-0022 placement). The 4.1 route name was
    # singular; the API kind is the plural.
    "resourcequotas": ("list_resource_quotas", "resourcequotas", ""),
    # PodDisruptionBudget (policy, namespaced) — the 4.1-parity nav leaf
    # resolved by TASK-048 (list + data views; ADR-0022 placement). The 4.1
    # route name was singular; the API kind is the plural.
    "poddisruptionbudgets": ("list_pod_disruption_budgets", "poddisruptionbudgets", "policy"),
    # VerticalPodAutoscaler (autoscaling.k8s.io, namespaced CRD) — the 4.1-parity
    # nav leaf resolved by TASK-049 (list + data views; ADR-0022 placement).
    # Full custom object (the Cilium CRD seam): the CRD's own served version is
    # the authority, CRD absent -> [] (first-class empty state).
    "verticalpodautoscalers": (
        "list_vertical_pod_autoscalers",
        "verticalpodautoscalers",
        "autoscaling.k8s.io",
    ),
    # HorizontalPodAutoscaler (autoscaling/v1, namespaced core kind) — the
    # 4.1-parity nav leaf resolved by TASK-050 (list + data views;
    # ADR-0022 placement). The 4.1 route name was singular; the API kind is
    # the plural.
    "horizontalpodautoscalers": (
        "list_horizontal_pod_autoscalers",
        "horizontalpodautoscalers",
        "",
    ),
    # LimitRange (core, namespaced) — the 4.1-parity nav leaf resolved by
    # TASK-054 (list + data views; ADR-0022 placement). The 4.1 route name was
    # singular; the API kind is the plural.
    "limitranges": ("list_limit_ranges", "limitranges", ""),
    # ConfigMap (core, namespaced) — the 4.1-parity nav leaf resolved by
    # TASK-064 (list + data views; ADR-0022 placement). The 4.1 route name was
    # singular; the API kind is the plural.
    "configmaps": ("list_configmaps", "configmaps", ""),
    # VolumeSnapshotClass (snapshot.storage.k8s.io, cluster-scoped CRD) — the
    # 4.1-parity nav leaf resolved by TASK-051 (list + data views; ADR-0022
    # placement). Full custom object (the Cilium CRD seam): the CRD's own
    # served version is the authority, CRD absent -> [] (first-class empty
    # state).
    "volumesnapshotclasses": (
        "list_volume_snapshot_classes",
        "volumesnapshotclasses",
        "snapshot.storage.k8s.io",
    ),
    # VolumeSnapshot (snapshot.storage.k8s.io, namespaced CRD) — the 4.1-parity
    # nav leaf resolved by TASK-053 (list + data views; ADR-0022 placement).
    # Full custom object (the Cilium CRD seam): the CRD's own served version is
    # the authority, CRD absent -> [] (first-class empty state). Namespaced:
    # the namespace is honored (a fix for 4.1's all-namespaces read).
    "volumesnapshots": (
        "list_volume_snapshots",
        "volumesnapshots",
        "snapshot.storage.k8s.io",
    ),
}

#: kind → K8sClient method for a single-object ``?name=`` lookup
_GETTERS: dict[str, str] = {
    "secrets": "get_secret",
    "crds": "get_crd",
    "networkpolicies": "get_network_policy",
    "ciliumnetworkpolicies": "get_cilium_network_policy",
    "priorityclasses": "get_priority_class",
    "runtimeclasses": "get_runtime_class",
    "storageclasses": "get_storage_class",
    "resourcequotas": "get_resource_quota",
    "poddisruptionbudgets": "get_pod_disruption_budget",
    "verticalpodautoscalers": "get_vertical_pod_autoscaler",
    "horizontalpodautoscalers": "get_horizontal_pod_autoscaler",
    "limitranges": "get_limit_range",
    "configmaps": "get_configmap",
    "volumesnapshotclasses": "get_volume_snapshot_class",
    "volumesnapshots": "get_volume_snapshot",
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

    @blp.route("/clusters/<int:cluster_id>/resources/crds/instances", methods=["GET"])
    @blp.response(200, ResourceListOut)
    @blp.doc(
        responses={
            403: "RBAC_DENIED (either SAR)",
            404: "CLUSTER_NOT_FOUND (binding gate) or the CRD does not exist",
            502: "CLUSTER_UNREACHABLE",
        }
    )
    def list_crd_instances(self, cluster_id: int) -> dict[str, object]:
        """Instances of one CRD's resource — the detail page behind a CRD.

        Two SAR gates, both asked BEFORE the read (ADR-0004: the SAR is the
        only gate, no exceptions — including for the CRD's own definition):
        ``list`` on the CRD (``customresourcedefinitions``, needed to resolve
        served version + scope) and ``list`` on the CRD's resource itself
        (e.g. ``applications`` in ``argoproj.io``). Each 403 names the denied
        resource so the view can say which grant is missing.

        Query: ``name`` = the CRD plural (e.g. ``applications.argoproj.io``);
        ``namespace`` = applied only when the CRD is namespaced-scoped.
        """
        name = request.args.get("name")
        if not name:
            raise ResourceKindNotSupportedError("instances lookup on kind 'crds' needs ?name=")
        cluster = _cluster_for(g.current_user, cluster_id)
        client = pool.get(cluster)
        if not rbac.can(g.current_user, cluster, "list", "customresourcedefinitions", None, name, _CRD_GROUP):
            raise RbacDeniedError("list on customresourcedefinitions")
        crds = client.get_crd(None, name)
        if not crds:
            raise ClusterNotFoundError(f"CRD '{name}' not found")
        crd = crds[0]
        spec = crd.get("spec") or {}
        group = spec.get("group") or ""
        # Prefer the storage version (the API server's write path); fall back
        # to any served version. Explicit over ``next(...)`` which would pick
        # the first declared version regardless of storage.
        versions = spec.get("versions") or []
        served = next(
            (v for v in versions if v.get("served") and v.get("name") and v.get("storage")), None
        ) or next((v for v in versions if v.get("served") and v.get("name")), None)
        if served is None:
            raise ClusterUnreachableError(f"CRD '{name}' has no served version")
        plural = ((spec.get("names") or {}).get("plural")) or name
        scope_namespaced = spec.get("scope") == "Namespaced"
        namespace = request.args.get("namespace") if scope_namespaced else None
        if not rbac.can(g.current_user, cluster, "list", plural, namespace, None, group):
            raise RbacDeniedError(f"list on {plural}")
        items = client.list_crd_instances(group, served["name"], plural, namespace)
        return {"items": items, "kind": "crds", "cluster": cluster.name}

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
