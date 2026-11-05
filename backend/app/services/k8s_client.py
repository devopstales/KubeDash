"""k8s client pool + encrypted-kubeconfig codec (ADR-0002 / R3).

The one-way door: every kubeconfig leaves the API and is stored as the frozen
OD-2 form (one-way-door — the cipher + key domain are a data migration to
change, not a behavior change):

    0x01 (version byte) || 12-byte nonce || AES-GCM(nonce, key, plaintext)

key = ``sha256(KUBEDASH_SECRET_KEY)`` — a distinct key domain from the JWT
secret. The version byte (currently ``0x01``) makes per-row cipher/key
rotation detectable without a schema change: ``encrypt_kubeconfig`` writes the
``0x01`` prefix, ``decrypt_kubeconfig`` validates it (unknown version ->
``ValueError``) and slices the nonce at ``enc[1:13]``.

``K8sClientPool`` is the SINGLE place that turns a ``Cluster`` row into a
live client (the seam where ADR-0010's informer cache interposes later
without touching the APIs). Its ``factory`` kwarg is the test seam: unit
tests inject a ``FakeK8s`` double, integration (Task 5) uses the default
real-kubernetes factory.
"""

import ast
import base64
import contextlib
import hashlib
import json
import os
import secrets
from typing import Any, Literal

import httpx
import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kubernetes import client as k8s_client
from kubernetes.client.exceptions import ApiException

from app.core.config import Settings, get_settings
from app.core.errors import (
    ClusterAlreadyExistsError,
    ClusterNotFoundError,
    ClusterUnreachableError,
)
from app.models.cluster import Cluster

# OD-2 frozen form: version byte (cipher/key generation marker), then the
# 96-bit nonce, then the AES-256-GCM ciphertext (includes the 16-byte tag).
_VERSION = 0x01
_NONCE_LEN = 12

# The AES key is derived from ``kubedash_secret_key`` LAZILY (I4): a
# REQUIRED field that resolves on first encrypt/decrypt, not at module
# import. Import-time resolution would fail-fast before the INI/env is
# configured (e.g. ``import app.services.k8s_client`` in a test that never
# builds an app). The key is invariant for the process lifetime, so cache
# the first derivation.
_key_cache: bytes | None = None


def _key() -> bytes:
    global _key_cache
    if _key_cache is None:
        _key_cache = hashlib.sha256(
            get_settings().kubedash_secret_key.encode()
        ).digest()
    return _key_cache


def encrypt_kubeconfig(plain: bytes) -> bytes:
    """Store form: ``0x01 || nonce || AES-GCM(nonce, key, plaintext)``."""
    nonce = secrets.token_bytes(_NONCE_LEN)
    ct = AESGCM(_key()).encrypt(nonce, plain, None)
    return bytes([_VERSION]) + nonce + ct


def decrypt_kubeconfig(enc: bytes) -> bytes:
    """Parse the OD-2 form back to plaintext.

    ``ValueError("unknown kubeconfig version")`` on an unrecognized version
    byte; ``ValueError("kubeconfig decryption failed")`` on any GCM failure
    (wrong key, tampered nonce/ciphertext).
    """
    if enc[0] != _VERSION:
        raise ValueError("unknown kubeconfig version")
    nonce = enc[1 : 1 + _NONCE_LEN]
    try:
        return AESGCM(_key()).decrypt(nonce, enc[1 + _NONCE_LEN :], None)
    except Exception as e:  # cryptography raises InvalidTag/ValueError
        raise ValueError("kubeconfig decryption failed") from e


def bound_cluster_or_404(user: Any, cluster_id: int) -> Cluster:
    """Binding gate shared by the clusters/resources APIs (Task 5 consumes it
    by name).

    Looks up BOTH the ``Cluster`` and the caller's ``ClusterBinding``: a
    missing cluster OR a missing binding raises ``ClusterNotFoundError``
    (404 CLUSTER_NOT_FOUND) — an unbound user cannot even see that a cluster
    exists.
    """
    from app.extensions import db
    from app.models.binding import ClusterBinding

    bound = db.session.execute(
        db.select(ClusterBinding)
        .join(Cluster, ClusterBinding.cluster_id == Cluster.id)
        .filter(Cluster.id == cluster_id, ClusterBinding.user_id == user.id)
    ).scalar_one_or_none()
    if bound is None:
        raise ClusterNotFoundError("cluster not found")
    cluster = db.session.get(Cluster, cluster_id)
    if cluster is None:  # pragma: no cover - FK integrity makes this unreachable
        raise ClusterNotFoundError("cluster not found")
    return cluster


# ADR-0021 (TICKET-15): the admin kubeconfig source — how KubeDash reaches
# the cluster IT runs in (in-cluster service account vs. a kubeconfig file).
# ``resolve_admin_source`` is the config→source seam (pure, no kubernetes);
# ``build_admin_client`` is the k8s-client seam (the unit tier injects a fake
# via the pool's ``admin_factory`` kwarg and never calls the real builder).
AdminSource = Literal["in-cluster", "kubeconfig-file", "local-kubeconfig"]

#: Synthetic id of the cluster KubeDash runs in — no ``clusters`` row exists,
#: so handlers pass a synthetic ``Cluster(id=0)`` straight to ``pool.get``
#: (the binding gate would 404 first — no row 0).
LOCAL_CLUSTER_ID = 0


def resolve_admin_source(s: Settings) -> AdminSource:
    """Config→source seam. Pure — no kubernetes import.

    Explicit path set → ``"kubeconfig-file"`` (no fallback, per main's
    Admin branch: the configured file is THE source). Empty → the
    main-4.x probe: a default kubeconfig (``KUBECONFIG`` / ``~/.kube/config``)
    present → ``"local-kubeconfig"``; absent → ``"in-cluster"`` (the pod
    service account). The presence check is a filesystem probe, not a load —
    the load happens in ``build_admin_client``.
    """
    if s.admin_kubeconfig:
        return "kubeconfig-file"
    if os.path.isfile(os.environ.get("KUBECONFIG", os.path.expanduser("~/.kube/config"))):
        return "local-kubeconfig"
    return "in-cluster"


def _parse_stats_body(raw: Any) -> dict[str, Any]:
    """Parse a kubelet ``/stats/summary`` body as the kubernetes client hands
    it back. For the ``str``-typed node-proxy return, the client deserializes
    the JSON response to a dict and then ``str()``s it — a PYTHON REPR
    (single quotes, ``True``/``None``), not JSON. 4.1 ``eval()``ed exactly
    this body; we keep the behavior with a safe parser: strict JSON first,
    then ``ast.literal_eval`` (literals only — no code execution) for the
    repr form. A dict (client versions that return the deserialized object)
    passes through. Raises ``ValueError``/``SyntaxError``/``TypeError`` on
    an unparseable body — the caller treats that as a skipped node
    (ADR-0003 degrade)."""
    if isinstance(raw, dict):
        return raw
    text = raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else str(raw)
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = ast.literal_eval(text)
    if not isinstance(parsed, dict):
        raise ValueError("stats/summary body is not an object")
    return parsed


def _pv_claim_namespace(pv: dict[str, Any]) -> str | None:
    """The PV's bound-claim namespace from a ``to_dict`` item, or ``None``
    for a free PV (no ``spec`` or no ``spec.claim_ref``)."""
    spec = pv.get("spec") or {}
    claim_ref = spec.get("claim_ref") or {}
    return claim_ref.get("namespace")


class K8sClient:
    """Per-cluster kubernetes client.

    Two shapes: the registry shape (``K8sClient(kubeconfig)``, built from the
    decrypted bytes) and the admin shape (``K8sClient()`` with
    ``load_*_config`` applied first, ``source = "admin"`` — ADR-0021). The
    host is taken VERBATIM from ``configuration.host`` — it already carries
    the scheme — so ``readyz`` never double-prefixes it.
    """

    #: The Metrics API (``metrics.k8s.io``) cluster node-metrics path. Read
    #: through the shared ``ApiClient`` (kubernetes 37.0.1 has no generated
    #: ``MetricsV1beta1Api`` — see ``node_usage``).
    _NODES_METRICS_PATH = "/apis/metrics.k8s.io/v1beta1/nodes"

    def __init__(self, kubeconfig: bytes | None = None, source: str = "registry") -> None:
        # ADR-0021: "registry" (decrypted kubeconfig row) or "admin"
        # (build_admin_client) — test assertions + future per-source policy.
        self.source = source
        if kubeconfig is not None:
            # ponytail: kubernetes 37's KubeConfigLoader API changed from 29.x
            # (from_custom_yaml is gone). We load the config_dict into a fresh
            # Configuration; the k8s API client + host + CA all come from it.
            from kubernetes.config import kube_config as _kc

            loaded = yaml.safe_load(kubeconfig.decode())
            client_config = k8s_client.Configuration()
            self._loader = _kc.KubeConfigLoader(loaded)  # type: ignore[no-untyped-call]
            self._loader.load_and_set(client_config)  # type: ignore[no-untyped-call]
            # The kubeconfig's CA bundle is the TLS verification authority;
            # fall back to the system bundle when the config carries none.
            cluster_entry = loaded["clusters"][0]["cluster"]
            ca = cluster_entry.get("certificate-authority-data")
            # httpx verify= treats a str as a FILE PATH (passed to
            # ssl.create_default_context as cafile), NOT as PEM content.
            # Write the CA to a temp file at init; readyz() passes that path.
            if ca:
                self._verify: str | bool = self._ca_to_tempfile(base64.b64decode(ca))
            else:
                self._verify = True
        else:
            # Admin shape (ADR-0021): build_admin_client applied
            # load_kube_config/load_incluster_config BEFORE this, which sets
            # the library's DEFAULT Configuration (not the module-global).
            # Read it back — a fresh Configuration() would be empty.
            try:
                client_config = k8s_client.Configuration.get_default_copy()
            except Exception:
                client_config = k8s_client.Configuration()
            # The kubeconfig's CA bundle is the TLS verification authority
            # (self-signed in kind). kubernetes writes the CA to a temp file
            # and stores the PATH in ssl_ca_cert — pass it directly to
            # httpx verify= (it expects a file path, not PEM content).
            # Falls back to True when no CA is set (in-cluster mode).
            ssl_ca = client_config.ssl_ca_cert
            if isinstance(ssl_ca, str) and ssl_ca:
                self._verify: str | bool = ssl_ca
            else:
                self._verify = True
        self._config = client_config
        api_client = k8s_client.ApiClient(self._config)
        # WHY stored: node_usage reads the Metrics API via the raw
        # ApiClient.call_api (kubernetes 37 has no generated MetricsV1beta1Api)
        # — dropping this line is an AttributeError in production, not the
        # clean (False, {})/502 contract. The generated APIs hold their own
        # handle, so only the raw read needs it here.
        self._api_client = api_client
        self._v1 = k8s_client.CoreV1Api(api_client)
        # AuthorizationV1Api is the SAR seam: services/rbac.py calls
        # client._auth_api.create_self_subject_access_review(...) against a
        # live cluster. (kubernetes 37 has no AuthV1Api — the SAR lives on
        # AuthorizationV1Api.) Sharing the same ApiClient keeps one auth ctx.
        self._auth_api = k8s_client.AuthorizationV1Api(api_client)
        # ADR-0013 (TICKET-03): RBAC apply seam for the bind/unbind service.
        # ponytail: kubernetes 37 has NO `RbacV1Api` — the Role/RoleBinding
        # APIs live on `RbacAuthorizationV1Api` (the brief's method names,
        # e.g. create_namespaced_role, DO match that class). Same ApiClient
        # keeps one auth context.
        self._rbac = k8s_client.RbacAuthorizationV1Api(api_client)
        self._networking = k8s_client.NetworkingV1Api(api_client)
        # PriorityClass (scheduling.k8s.io) — the R4 "priorityclasses" kind.
        self._scheduling = k8s_client.SchedulingV1Api(api_client)
        # StorageClass (storage/v1, cluster-scoped) — the R1
        # "storageclasses" kind (4.1-parity nav leaf; ADR-0022 placement).
        self._storage = k8s_client.StorageV1Api(api_client)
        # RuntimeClass (node.k8s.io) — cluster-scoped, the R4 "runtimeclasses"
        # kind (the 4.1 nav leaf had no view; ADR-0022 placement, TASK-046).
        self._node = k8s_client.NodeV1Api(api_client)
        # PodDisruptionBudget (policy/v1, namespaced) — the R4
        # "poddisruptionbudgets" kind (4.1-parity nav leaf; ADR-0022 placement).
        self._policy = k8s_client.PolicyV1Api(api_client)
        # HorizontalPodAutoscaler (autoscaling/v1, namespaced) — the R4
        # "horizontalpodautoscalers" kind (4.1-parity nav leaf; ADR-0022
        # placement). A generated core-API model: ``to_dict`` is snake_case.
        self._autoscaling = k8s_client.AutoscalingV1Api(api_client)
        self._host = self._v1.api_client.configuration.host

    @staticmethod
    def _ca_to_tempfile(ca_pem: bytes) -> str:
        """Write the CA PEM to a temp file and return its path.

        httpx ``verify=`` treats a str as a file path (``cafile``), not PEM
        content. The file lives for the process lifetime (one per cluster) —
        acceptable for a long-lived gunicorn worker.
        """
        import tempfile

        fd, path = tempfile.mkstemp(suffix=".ca.pem")
        with os.fdopen(fd, "wb") as f:
            f.write(ca_pem)
        return path

    def list_pods(self, namespace: str | None) -> list[dict[str, Any]]:
        """Pod list in the standard kubernetes dict form (``to_dict``)."""
        resp = (
            self._v1.list_namespaced_pod(namespace)
            if namespace
            else self._v1.list_pod_for_all_namespaces()
        )
        return [p.to_dict() for p in resp.items]

    def list_namespaces(self, _namespace: str | None) -> list[dict[str, Any]]:
        """Namespace list for the header selector. The resource route always
        passes the query namespace; it does not apply to this cluster-scoped kind."""
        return [n.to_dict() for n in self._v1.list_namespace().items]

    def list_nodes(self, _namespace: str | None) -> list[dict[str, Any]]:
        """Node list in the standard kubernetes dict form (``to_dict``).
        Cluster-scoped; the query namespace does not apply (mirrors
        ``list_namespaces``)."""
        return [n.to_dict() for n in self._v1.list_node().items]

    def list_priority_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
        """PriorityClass list in the standard kubernetes dict form
        (``to_dict``). Cluster-scoped: the namespace argument is accepted
        and ignored (the ``list_nodes`` pattern)."""
        try:
            resp = self._scheduling.list_priority_class()
        except ApiException as e:
            self._unreachable("list_priority_classes", e)
            raise AssertionError("unreachable") from e
        return [pc.to_dict() for pc in resp.items]

    def list_storage_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
        """StorageClass list in the standard kubernetes dict form
        (``to_dict``). Cluster-scoped: the namespace argument is accepted
        and ignored (the ``list_nodes`` pattern). No field stripping — the
        view renders ``reclaim_policy``/``volume_binding_mode``/
        ``provisioner`` and the data page the full object. A transport
        ApiException maps to ``ClusterUnreachableError`` (502)."""
        try:
            resp = self._storage.list_storage_class()
        except ApiException as e:
            self._unreachable("list_storage_classes", e)
            raise AssertionError("unreachable") from e
        return [sc.to_dict() for sc in resp.items]

    def list_runtime_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
        """RuntimeClass list in the standard kubernetes dict form
        (``to_dict``). Cluster-scoped: the namespace argument is accepted
        and ignored (the ``list_nodes`` pattern)."""
        try:
            resp = self._node.list_runtime_class()
        except ApiException as e:
            self._unreachable("list_runtime_classes", e)
            raise AssertionError("unreachable") from e
        return [rc.to_dict() for rc in resp.items]

    def _node_metrics(self) -> list[dict[str, Any]] | None:
        """Fetch the raw ``NodeMetricsList`` body from ``metrics.k8s.io``.

        Returns the parsed ``items`` list, or ``None`` when the Metrics API is
        absent/broken (404/5xx, a transport failure, or a non-JSON body) —
        the query-only degrade (ADR-0003): an unavailable metrics source is
        the EXPECTED state, never an error. A *different* ApiException (not
        404/5xx) is a transport failure → 502 ``ClusterUnreachableError``
        (the service never sees a raw ApiException).

        Shared by ``node_usage`` (cluster-wide) and ``node_usage(name)``
        (single node) — both parse the same body.
        """
        try:
            # call_api does NOT prepend ``self.configuration.host`` — the
            # generated API methods build the absolute URL before calling it.
            # Without the host, urllib3 gets a bare path and raises
            # ``LocationValueError("No host specified")`` (not ``ApiException``)
            # → 500 instead of the query-only degrade.
            metrics_url = f"{self._config.host}{self._NODES_METRICS_PATH}"
            resp = self._api_client.call_api("GET", metrics_url)
            # call_api returns the raw RESTResponse WITHOUT reading the body
            # (resp.data stays None until read() — the generated methods read
            # it via response_deserialize; we have no model to deserialize
            # into, so read the bytes ourselves). Read INSIDE the try: a
            # transport-level read failure is not an ``ApiException`` either.
            raw = resp.read().decode()
        except ApiException as e:
            if e.status in (404, 500, 502, 503):
                return None
            self._unreachable("node_usage", e)
            raise AssertionError("unreachable") from e
        except Exception:
            # Non-ApiException transport failure (urllib3 errors, a non-JSON
            # body such as an LB/ingress error page): the metrics source is
            # absent or broken — query-only, answer unavailable, never 500.
            return None
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return body.get("items", [])

    def node_usage(self, name: str | None = None) -> tuple[bool, dict[str, int] | None]:
        """Node resource usage from the Metrics API (``metrics.k8s.io``).

        With no ``name``: cluster-wide — returns
        ``(available, {node_name: {cpu_millicores, memory_bytes}})``. With a
        ``name``: single node — returns ``(available, {cpu_millicores,
        memory_bytes} | None)`` where ``None`` means the node is not in the
        metrics list (a node the metrics-server has not yet scraped, or one
        that vanished).

        ``available`` is False when the Metrics API itself is absent/broken
        (404/5xx) — a cluster without a metrics-server is the EXPECTED state,
        not an error (query-only, ADR-0003): the caller must render ``used``
        unknown, never 0.

        ponytail: kubernetes 37.0.1 has NO ``MetricsV1beta1Api`` and no
        ``V1NodeMetricsList`` model, so the read goes through the shared
        ``ApiClient.call_api`` and parses the raw JSON body directly. Ceiling:
        if a vendored Metrics API is ever added, swap this for the generated
        ``read_node_metrics()`` call (no consumer changes — the return
        contract is stable).
        """
        items = self._node_metrics()
        if items is None:
            return False, {} if name is None else None
        usage: dict[str, dict[str, int]] = {}
        for item in items:
            item_name = item["metadata"]["name"]
            u = item.get("usage", {})
            usage[item_name] = {
                "cpu_millicores": self._parse_cpu(u.get("cpu")),
                "memory_bytes": self._parse_bytes(u.get("memory")),
            }
        if name is None:
            return True, usage
        return True, usage.get(name)

    def node_metrics(self) -> tuple[bool, list[dict[str, Any]]]:
        """Per-node CPU/memory series for the node view (blueprint Task 3).

        Returns ``(available, series)`` where each series item is
        ``{name, cpu_used_millicores, cpu_capacity_millicores, memory_used_bytes,
        memory_capacity_bytes}``. ``cpu_used_*`` / ``memory_used_*`` come from
        the Metrics API (query-only, ADR-0003); ``*_capacity_*`` come from the
        core-v1 node ``status.capacity`` (declared state, always present when
        the node list is reachable). A node present in the metrics list but
        missing from ``list_nodes`` (or vice versa) gets ``None`` for the
        fields it lacks — the view renders ``unknown``, never ``0``.

        ``available`` is False when the Metrics API is absent/broken (404/5xx)
        — the caller renders the used tier unknown, never 0.
        """
        items = self._node_metrics()
        if items is None:
            return False, []
        capacities: dict[str, dict[str, Any]] = {}
        try:
            for node in self.list_nodes(None):
                name = (node.get("metadata") or {}).get("name")
                if name:
                    capacities[name] = (node.get("status") or {}).get("capacity") or {}
        except Exception:
            # The node list is a separate read; if it fails the capacity tier
            # degrades to unknown (the used tier is still served from metrics).
            capacities = {}
        usage: dict[str, dict[str, int]] = {}
        for item in items:
            name = item["metadata"]["name"]
            u = item.get("usage", {})
            usage[name] = {
                "cpu_millicores": self._parse_cpu(u.get("cpu")),
                "memory_bytes": self._parse_bytes(u.get("memory")),
            }
        series: list[dict[str, Any]] = []
        for name in sorted(set(usage) | set(capacities)):
            cap = capacities.get(name, {})
            series.append(
                {
                    "name": name,
                    "cpu_used_millicores": usage.get(name, {}).get("cpu_millicores"),
                    "cpu_capacity_millicores": self._parse_cpu(cap.get("cpu")),
                    "memory_used_bytes": usage.get(name, {}).get("memory_bytes"),
                    "memory_capacity_bytes": self._parse_bytes(cap.get("memory")),
                }
            )
        return True, series

    def pvc_usage(self, namespace: str) -> tuple[bool, list[dict[str, Any]]]:
        """PVC storage usage per namespace from the KUBELET /stats/summary
        endpoint (4.1's ``k8sPVCMetric`` read, re-implemented): for every
        node, ``connect_get_node_proxy_with_path(name,
        path="stats/summary")``, then aggregate each pod's
        ``volume[].pvcRef`` entries for ``namespace``.

        Returns ``(available, items)`` — ``items`` is one entry per PVC:
        ``{name, capacity_bytes, used_bytes, available_bytes,
        percentage_used}`` (bytes summed across all pods using the PVC;
        ``percentage_used`` = used / capacity * 100, ``0.0`` when capacity
        is zero — the 4.1 division-by-zero guard). The ADR-0003 query-only
        degrade: a node whose stats call fails (404/5xx/timeout — no
        kubelet, stats unavailable) is SKIPPED, never raised; zero healthy
        nodes → ``(False, [])``. The body is parsed by ``_parse_stats_body``
        (strict JSON first, then the kubernetes client's ``str(dict)`` repr
        via ``ast.literal_eval`` — 4.1's ``eval`` is not replicated).
        """
        try:
            nodes = self.list_nodes(None)
        except Exception:
            # The node list is a separate read; if it fails there are no
            # stats to aggregate (the ``node_metrics`` degrade pattern).
            return False, []
        aggregated: dict[str, dict[str, int]] = {}
        healthy = 0
        for node in nodes:
            name = (node.get("metadata") or {}).get("name")
            if not name:
                continue
            try:
                raw = self._v1.connect_get_node_proxy_with_path(
                    name, path="stats/summary", _request_timeout=2
                )
                body = _parse_stats_body(raw)
                for pod in body.get("pods") or []:
                    for vol in pod.get("volume") or []:
                        ref = vol.get("pvcRef")
                        # A pvcRef without a name cannot join to a PVC (the
                        # name is the join key) — skip the entry, never raise.
                        if (
                            not ref
                            or not ref.get("name")
                            or ref.get("namespace") != namespace
                        ):
                            continue
                        # Convert before the merge: a non-numeric byte count
                        # raises while the node is still unmerged, so the
                        # skip leaves no partial entry behind.
                        capacity = int(vol.get("capacityBytes") or 0)
                        used = int(vol.get("usedBytes") or 0)
                        available = int(vol.get("availableBytes") or 0)
                        entry = aggregated.setdefault(
                            ref["name"],
                            {"capacity_bytes": 0, "used_bytes": 0, "available_bytes": 0},
                        )
                        entry["capacity_bytes"] += capacity
                        entry["used_bytes"] += used
                        entry["available_bytes"] += available
            except (ApiException, ValueError, SyntaxError, TypeError, UnicodeDecodeError):
                # A per-node stats failure is the EXPECTED state (kubelet
                # absent/down/stats API off) — skip, never raise (ADR-0003).
                # A malformed body (unparseable, or a non-numeric byte
                # count) degrades the node the same way: skipped, and not
                # counted healthy.
                continue
            healthy += 1
        items = [
            {
                **entry,
                "percentage_used": (
                    round(entry["used_bytes"] / entry["capacity_bytes"] * 100, 1)
                    if entry["capacity_bytes"]
                    else 0.0
                ),
                "name": name,
            }
            for name, entry in aggregated.items()
        ]
        return healthy > 0, items

    @staticmethod
    def _parse_cpu(qty: str | None) -> int:
        """K8s CPU quantity → millicores (``"800m"`` → 800, ``"1"`` → 1000).

        The Metrics API reports ``usage.cpu`` in *nanocores* (``"270808684n"``)
        — the ``n`` branch is load-bearing for the ``node_usage`` path. Must
        be checked before ``m``; see the pure copy in
        ``cluster_allocation._parse_cpu`` for the full rationale.
        """
        if qty is None:
            return 0
        if qty.endswith("n"):
            return int(int(qty[:-1]) / 1_000_000)  # nanocores → millicores
        if qty.endswith("m"):
            return int(qty[:-1])
        return int(float(qty) * 1000)

    @staticmethod
    def _parse_bytes(qty: str | None) -> int:
        """K8s quantity → bytes (``"4Gi"`` → 4*2**30, ``"2000"`` → 2000)."""
        if qty is None:
            return 0
        # Binary suffixes first (``Gi`` before ``G``); a bare integer has no suffix.
        for suffix, mult in (
            ("Ki", 2**10),
            ("Mi", 2**20),
            ("Gi", 2**30),
            ("Ti", 2**40),
            ("Pi", 2**50),
            ("Ei", 2**60),
            ("K", 10**3),
            ("M", 10**6),
            ("G", 10**9),
            ("T", 10**12),
            ("P", 10**15),
            ("E", 10**18),
        ):
            if qty.endswith(suffix):
                return int(float(qty[: -len(suffix)]) * mult)
        return int(qty)

    def create_namespace(self, name: str) -> dict[str, Any]:
        body = k8s_client.V1Namespace(metadata=k8s_client.V1ObjectMeta(name=name))
        try:
            return self._v1.create_namespace(body).to_dict()
        except ApiException as e:
            if e.status == 409:
                raise ClusterAlreadyExistsError(f"namespace '{name}' already exists") from e
            self._unreachable("create_namespace", e)
            raise AssertionError("unreachable") from e

    def delete_namespace(self, name: str) -> None:
        self._delete("delete_namespace", lambda: self._v1.delete_namespace(name))

    def list_serviceaccounts(self, namespace: str | None) -> list[dict[str, Any]]:
        """ServiceAccount list in the standard kubernetes dict form (``to_dict``)."""
        resp = (
            self._v1.list_namespaced_service_account(namespace)
            if namespace
            else self._v1.list_service_account_for_all_namespaces()
        )
        return [sa.to_dict() for sa in resp.items]

    def list_roles(self, namespace: str | None) -> list[dict[str, Any]]:
        """Role list in the standard kubernetes dict form (``to_dict``)."""
        resp = (
            self._rbac.list_namespaced_role(namespace)
            if namespace
            else self._rbac.list_role_for_all_namespaces()
        )
        return [role.to_dict() for role in resp.items]

    def list_rolebindings(self, namespace: str | None) -> list[dict[str, Any]]:
        """RoleBinding list in the standard kubernetes dict form (``to_dict``)."""
        resp = (
            self._rbac.list_namespaced_role_binding(namespace)
            if namespace
            else self._rbac.list_role_binding_for_all_namespaces()
        )
        return [binding.to_dict() for binding in resp.items]

    def list_cluster_roles(self, _namespace: str | None) -> list[dict[str, Any]]:
        """ClusterRole list. Cluster-scoped; the query namespace does not apply."""
        return [role.to_dict() for role in self._rbac.list_cluster_role().items]

    def list_cluster_role_bindings(self, _namespace: str | None) -> list[dict[str, Any]]:
        """ClusterRoleBinding list. Cluster-scoped; the query namespace does not apply."""
        return [binding.to_dict() for binding in self._rbac.list_cluster_role_binding().items]

    def list_events(self, _namespace: str | None) -> list[dict[str, Any]]:
        """Cluster-wide event list (``to_dict`` form). Cluster-scoped: the
        namespace argument is ignored, matching the cluster-wide
        ``list events`` SAR gate (ADR-0004). ADR-0010's informer cache
        interposes here later; for now this is a live read."""
        return [e.to_dict() for e in self._v1.list_event_for_all_namespaces().items]

    # CRD reads (apiextensions.k8s.io/v1). kubernetes 37 has no generated
    # ApiextensionsV1Api — the same gap as metrics.k8s.io (see ``node_usage``)
    # — so the reads go through the shared ``ApiClient``'s CustomObjectsApi.
    _CRD_GROUP_VERSION = "apiextensions.k8s.io/v1"
    _CRD_PLURAL = "customresourcedefinitions"

    def _custom(self) -> Any:
        """A ``CustomObjectsApi`` on this client's ``ApiClient`` (one auth ctx).

        Unit tests substitute ``self._api_client`` with a fake exposing the
        ``select_header_*``/``param_serialize``/``_call_with_legacy_options``
        contract (the same seam ``node_usage`` relies on for metrics.k8s.io).
        """
        return k8s_client.CustomObjectsApi(self._api_client)

    @staticmethod
    def _crd_body(resp: Any) -> dict[str, Any]:
        """The generated ``CustomObjectsApi`` methods return the 3-tuple
        ``(data, status, headers)`` (the raw-``call_api`` path in
        ``node_usage`` reads the body itself; the CustomObjectsApi generated
        methods do not). ``data`` is a plain dict — no ``to_dict``.

        Only ``401`` is raised as an ``ApiException`` by the generated
        method (its ``_response_types_map``); any other non-2xx status comes
        back in the tuple and is mapped to ``ClusterUnreachableError`` here
        (the service never sees a raw status the caller must interpret).
        """
        if isinstance(resp, tuple):
            data, status = resp[0], resp[1]
        else:
            data, status = resp, 200
        if status is not None and status >= 400:
            raise ClusterUnreachableError(f"cluster unreachable (status {status})")
        return data if isinstance(data, dict) else {}

    def list_crds(self, _namespace: str | None) -> list[dict[str, Any]]:
        """CRD list in dict form. Cluster-scoped; the namespace argument does
        not apply (mirrors ``list_nodes``)."""
        group, _, version = self._CRD_GROUP_VERSION.partition("/")
        try:
            resp = self._custom().list_cluster_custom_object(group, version, self._CRD_PLURAL)
        except ApiException as e:
            self._unreachable("list_crds", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def get_crd(self, _namespace: str, name: str) -> list[dict[str, Any]]:
        """One CRD as a 0/1-item list (mirrors ``get_secret``); ``[]`` on 404.

        ``_namespace`` is accepted for the ``_GETTERS`` call convention but
        ignored — CRDs are cluster-scoped.
        """
        group, _, version = self._CRD_GROUP_VERSION.partition("/")
        try:
            item = self._custom().get_cluster_custom_object(group, version, self._CRD_PLURAL, name)
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_crd", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]

    @staticmethod
    def _crd_served(crd: dict[str, Any]) -> tuple[str, str] | None:
        """The established served version + scope of a CRD dict.

        Returns ``(version, scope)`` or ``None`` when the CRD has no
        established served version (a version being added is not served yet).
        The CRD's OWN status is the scope/version authority — no client-side
        guessing (the 4.1 namespaced→cluster fallback is deliberately absent).
        """
        spec = crd.get("spec") or {}
        scope = "Namespaced" if spec.get("scope") == "Namespaced" else "Cluster"
        for v in spec.get("versions") or []:
            if v.get("served") and v.get("name"):
                return (v["name"], scope)
        return None

    def list_crd_instances(
        self, group: str, version: str, plural: str, namespace: str | None
    ) -> list[dict[str, Any]]:
        """Instances of one CRD's resource, projected to the 4.1 shape:
        ``{name, namespace, status, type, reason, message, created}``.

        ``namespace`` is honored only for namespaced-scoped CRDs; a
        cluster-scoped list ignores it (the view reads the scope from the CRD
        itself and only sends the topbar namespace when it applies).
        Condition extraction prefers a ``Ready`` condition, else the first
        (4.1 ``get_custom_resource_data``), falling back to top-level
        ``status.phase``/``status.state``.
        """
        custom = self._custom()
        resp = (
            custom.list_namespaced_custom_object(group, version, namespace, plural)
            if namespace
            else custom.list_cluster_custom_object(group, version, plural)
        )
        body = self._crd_body(resp)
        results: list[dict[str, Any]] = []
        for item in body.get("items", []):
            item = item.to_dict() if hasattr(item, "to_dict") else item
            metadata = item.get("metadata") or {}
            status = item.get("status") or {}
            conditions = status.get("conditions") or []
            condition: dict[str, Any] = {}
            ready = next((c for c in conditions if c.get("type") == "Ready"), None)
            if ready is not None:
                condition = ready
            elif conditions:
                condition = conditions[0]
            results.append(
                {
                    "name": metadata.get("name") or "",
                    "namespace": metadata.get("namespace"),
                    "status": condition.get("status") or status.get("phase") or status.get("state") or "",
                    "type": condition.get("type") or "",
                    "reason": condition.get("reason") or status.get("reason") or "",
                    "message": condition.get("message") or status.get("message") or "",
                    "created": metadata.get("creationTimestamp"),
                }
            )
        return results

    # Cilium kinds (R2): served-version autodetect + absence degrade. The
    # CRD's OWN spec is the version+scope authority (no hardcoded
    # cilium.io/v2). Cilium absent (CRD 404) is the EXPECTED state -> [];
    # any other read failure -> ClusterUnreachableError (502).

    _CILIUM_GROUP = "cilium.io"

    def get_crd_served(self, group: str, plural: str) -> tuple[str, str] | None:
        """(served_version, scope) for a CRD, or None when the CRD is absent.

        The CRD's OWN spec is the version+scope authority (reuses
        ``_crd_served``). The CRD object is read by its FULLY-QUALIFIED name
        (``plural.group``) — ``get_crd`` takes the object name verbatim, and
        a bare plural 404s into the "absent" path. A 404 on the CRD read
        means the API group/CRD is not installed (e.g. Cilium absent) — the
        EXPECTED state, so it resolves to ``None`` instead of an error. Any
        other ApiException is a transport failure ->
        ``ClusterUnreachableError``.
        """
        crds = self.get_crd(None, f"{plural}.{group}")
        if not crds:
            return None
        served = self._crd_served(crds[0])
        if served is None:
            # A CRD that exists but declares no served version is
            # mis-registered Cilium, not "absent": mirror resources.py:147-148
            raise ClusterUnreachableError(f"CRD '{plural}' has no served version")
        return served

    # GatewayClass (gateway.networking.k8s.io, cluster-scoped CRD): the VPA
    # CRD seam (the CRD's own served version + scope is the authority; the
    # Gateway API CRDs are optional, so CRD absent -> [] as the first-class
    # empty state).

    _GATEWAY_API_GROUP = "gateway.networking.k8s.io"
    _GATEWAY_CLASS_PLURAL = "gatewayclasses"

    def list_gateway_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
        """GatewayClass items, FULL custom-object shape (spec + status intact,
        camelCase — the wire form, like the Cilium CRDs). Cluster-scoped: the
        namespace argument is accepted and ignored. The CRD read is ``None``
        (absent) -> ``[]`` (the expected state); any other read failure ->
        ``ClusterUnreachableError`` (502)."""
        served = self.get_crd_served(self._GATEWAY_API_GROUP, self._GATEWAY_CLASS_PLURAL)
        if served is None:
            return []
        version, scope = served
        custom = self._custom()
        try:
            resp = custom.list_cluster_custom_object(
                self._GATEWAY_API_GROUP, version, self._GATEWAY_CLASS_PLURAL
            )
        except ApiException as e:
            self._unreachable("list_gateway_classes", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def get_gateway_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
        """One GatewayClass as a 0/1-item FULL custom object; ``[]`` on 404 or
        when the CRD is absent (the optional-Gateway-API state). Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching the
        VPA getter."""
        served = self.get_crd_served(self._GATEWAY_API_GROUP, self._GATEWAY_CLASS_PLURAL)
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            item = custom.get_cluster_custom_object(
                self._GATEWAY_API_GROUP, version, self._GATEWAY_CLASS_PLURAL, name
            )
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_gateway_class", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]

    def list_gateways(self, namespace: str | None) -> list[dict[str, Any]]:
        """Gateway items, FULL custom-object shape (spec + status intact,
        camelCase — the wire form). Namespaced: the namespace is honored
        (``None`` spans all namespaces, the all-namespaces branch); a
        cluster-scoped kind ignores it. The CRD read is ``None`` (absent) ->
        ``[]`` (the expected state); any other read failure ->
        ``ClusterUnreachableError`` (502)."""
        served = self.get_crd_served(self._GATEWAY_API_GROUP, "gateways")
        if served is None:
            return []
        version, scope = served
        custom = self._custom()
        try:
            resp = (
                custom.list_namespaced_custom_object(
                    self._GATEWAY_API_GROUP, version, namespace, "gateways"
                )
                if namespace and scope == "Namespaced"
                else custom.list_cluster_custom_object(
                    self._GATEWAY_API_GROUP, version, "gateways"
                )
            )
        except ApiException as e:
            self._unreachable("list_gateways", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def get_gateway(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One Gateway as a 0/1-item FULL custom object; ``[]`` on 404 or when
        the CRD is absent (the optional-Gateway-API state). Any other ApiException
        maps to ``ClusterUnreachableError`` (502), matching ``get_gateway_class``."""
        served = self.get_crd_served(self._GATEWAY_API_GROUP, "gateways")
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            item = (
                custom.get_namespaced_custom_object(
                    self._GATEWAY_API_GROUP, version, namespace, "gateways", name
                )
                if namespace
                else custom.get_cluster_custom_object(
                    self._GATEWAY_API_GROUP, version, "gateways", name
                )
            )
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_gateway", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]

    def list_http_routes(self, namespace: str | None) -> list[dict[str, Any]]:
        """HTTPRoute items, FULL custom-object shape (spec + status intact,
        camelCase). Namespaced: the namespace is honored; CRD absent -> ``[]``
        (the expected state); other failures -> ``ClusterUnreachableError``
        (502)."""
        served = self.get_crd_served(self._GATEWAY_API_GROUP, "httproutes")
        if served is None:
            return []
        version, scope = served
        custom = self._custom()
        try:
            resp = (
                custom.list_namespaced_custom_object(
                    self._GATEWAY_API_GROUP, version, namespace, "httproutes"
                )
                if namespace and scope == "Namespaced"
                else custom.list_cluster_custom_object(
                    self._GATEWAY_API_GROUP, version, "httproutes"
                )
            )
        except ApiException as e:
            self._unreachable("list_http_routes", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def get_http_route(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One HTTPRoute as a 0/1-item FULL custom object; ``[]`` on 404 or when
        the CRD is absent. Any other ApiException maps to
        ``ClusterUnreachableError`` (502), matching ``get_gateway``."""
        served = self.get_crd_served(self._GATEWAY_API_GROUP, "httproutes")
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            item = (
                custom.get_namespaced_custom_object(
                    self._GATEWAY_API_GROUP, version, namespace, "httproutes", name
                )
                if namespace
                else custom.get_cluster_custom_object(
                    self._GATEWAY_API_GROUP, version, "httproutes", name
                )
            )
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_http_route", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]

    def list_reference_grants(self, namespace: str | None) -> list[dict[str, Any]]:
        """ReferenceGrant items, FULL custom-object shape (spec intact,
        camelCase). Cluster-scoped: the namespace argument is accepted and
        ignored; CRD absent -> ``[]`` (the expected state); other failures ->
        ``ClusterUnreachableError`` (502)."""
        served = self.get_crd_served(self._GATEWAY_API_GROUP, "referencegrants")
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            resp = custom.list_cluster_custom_object(
                self._GATEWAY_API_GROUP, version, "referencegrants"
            )
        except ApiException as e:
            self._unreachable("list_reference_grants", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def get_reference_grant(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One ReferenceGrant as a 0/1-item FULL custom object; ``[]`` on 404 or
        when the CRD is absent. Any other ApiException maps to
        ``ClusterUnreachableError`` (502), matching ``get_gateway``."""
        served = self.get_crd_served(self._GATEWAY_API_GROUP, "referencegrants")
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            item = custom.get_cluster_custom_object(
                self._GATEWAY_API_GROUP, version, "referencegrants", name
            )
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_reference_grant", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]


    def list_cilium_network_policies(self, namespace: str | None) -> list[dict[str, Any]]:
        """CiliumNetworkPolicy items, full to_dict() shape (spec intact).
        CRD absent -> [] (expected state); other failures -> 502 via
        _unreachable (inherited from the custom calls)."""
        served = self.get_crd_served(self._CILIUM_GROUP, "ciliumnetworkpolicies")
        if served is None:
            return []
        version, scope = served
        custom = self._custom()
        try:
            resp = (
                custom.list_namespaced_custom_object(
                    self._CILIUM_GROUP, version, namespace, "ciliumnetworkpolicies"
                )
                if namespace and scope == "Namespaced"
                else custom.list_cluster_custom_object(
                    self._CILIUM_GROUP, version, "ciliumnetworkpolicies"
                )
            )
        except ApiException as e:
            self._unreachable("list_cilium_network_policies", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def list_cilium_clusterwide_network_policies(
        self, _namespace: str | None
    ) -> list[dict[str, Any]]:
        """CiliumClusterwideNetworkPolicy items. Cluster-scoped: the namespace
        argument is accepted-and-ignored (mirrors list_crds). CRD absent -> [];
        other failures -> 502."""
        served = self.get_crd_served(self._CILIUM_GROUP, "ciliumclusterwidenetworkpolicies")
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            resp = custom.list_cluster_custom_object(
                self._CILIUM_GROUP, version, "ciliumclusterwidenetworkpolicies"
            )
        except ApiException as e:
            self._unreachable("list_cilium_clusterwide_network_policies", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def get_cilium_network_policy(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One CiliumNetworkPolicy as a 0/1-item list; ``[]`` on 404 or when
        the CRD is absent (Cilium not installed). Any other ApiException maps
        to ``ClusterUnreachableError`` (502), matching get_secret."""
        served = self.get_crd_served(self._CILIUM_GROUP, "ciliumnetworkpolicies")
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            item = custom.get_namespaced_custom_object(
                self._CILIUM_GROUP, version, namespace, "ciliumnetworkpolicies", name
            )
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_cilium_network_policy", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]

    # VolumeSnapshotClass (snapshot.storage.k8s.io, cluster-scoped CRD): the
    # same full-custom-object seam as the Cilium kinds — the CRD's OWN served
    # version is the authority (``get_crd_served`` — an improvement over
    # 4.1's hardcoded ``v1``); the snapshot operator is optional, so CRD
    # absent (None) degrades to [] as a first-class empty state. The read is
    # cluster-scoped (``list_cluster_custom_object`` /
    # ``get_cluster_custom_object``): the namespace argument is accepted and
    # ignored (mirrors ``list_crds`` / ``get_crd``).
    _SNAPSHOT_CLASS_GROUP = "snapshot.storage.k8s.io"
    _SNAPSHOT_CLASS_PLURAL = "volumesnapshotclasses"

    def list_volume_snapshot_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
        """VolumeSnapshotClass items, FULL custom-object shape (driver /
        deletionPolicy / parameters / metadata intact, camelCase — the wire
        form, like the Cilium CRDs). The CRD's OWN served version is the
        authority (``get_crd_served``). CRD absent (snapshot operator not
        installed) -> ``[]`` (the expected state, the Cilium absence
        contract); any other read failure -> ``ClusterUnreachableError``
        (502). Cluster-scoped: the namespace argument is accepted-and-ignored
        (mirrors ``list_crds``). The pages need ``driver`` /
        ``deletionPolicy`` / ``parameters``, so this returns the raw object —
        NOT the lossy ``list_crd_instances`` projection."""
        served = self.get_crd_served(self._SNAPSHOT_CLASS_GROUP, self._SNAPSHOT_CLASS_PLURAL)
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            resp = custom.list_cluster_custom_object(
                self._SNAPSHOT_CLASS_GROUP, version, self._SNAPSHOT_CLASS_PLURAL
            )
        except ApiException as e:
            self._unreachable("list_volume_snapshot_classes", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def get_volume_snapshot_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
        """One VolumeSnapshotClass as a 0/1-item FULL custom object; ``[]`` on
        404 or when the CRD is absent (snapshot operator not installed). Any
        other ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_cilium_network_policy``. Cluster-scoped: ``_namespace`` is
        accepted for the ``_GETTERS`` call convention but ignored (the
        ``get_crd`` cluster-scoped pattern)."""
        served = self.get_crd_served(self._SNAPSHOT_CLASS_GROUP, self._SNAPSHOT_CLASS_PLURAL)
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            item = custom.get_cluster_custom_object(
                self._SNAPSHOT_CLASS_GROUP, version, self._SNAPSHOT_CLASS_PLURAL, name
            )
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_volume_snapshot_class", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]

    # VerticalPodAutoscaler (autoscaling.k8s.io, namespaced CRD): same
    # full-custom-object seam as the Cilium kinds — the CRD's own served
    # version + scope is the authority; the VPA operator is optional, so
    # CRD absent (None) degrades to [] as a first-class empty state.
    _VPA_GROUP = "autoscaling.k8s.io"
    _VPA_PLURAL = "verticalpodautoscalers"

    def list_vertical_pod_autoscalers(self, namespace: str | None) -> list[dict[str, Any]]:
        """VerticalPodAutoscaler items, FULL custom-object shape (spec + status
        intact, camelCase — the wire form, like the Cilium CRDs). The VPA CRD's
        OWN served version + scope is the authority (``get_crd_served``). CRD
        absent (operator not installed) -> ``[]`` (the expected state, the
        Cilium absence contract); any other read failure ->
        ``ClusterUnreachableError`` (502). The VPA pages need
        ``spec.resourcePolicy.containerPolicies`` and ``status.conditions``,
        so this returns the raw object — NOT the lossy ``list_crd_instances``
        projection."""
        served = self.get_crd_served(self._VPA_GROUP, self._VPA_PLURAL)
        if served is None:
            return []
        version, scope = served
        custom = self._custom()
        try:
            resp = (
                custom.list_namespaced_custom_object(
                    self._VPA_GROUP, version, namespace, self._VPA_PLURAL
                )
                if namespace and scope == "Namespaced"
                else custom.list_cluster_custom_object(
                    self._VPA_GROUP, version, self._VPA_PLURAL
                )
            )
        except ApiException as e:
            self._unreachable("list_vertical_pod_autoscalers", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def get_vertical_pod_autoscaler(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One VerticalPodAutoscaler as a 0/1-item FULL custom object; ``[]``
        on 404 or when the CRD is absent (operator not installed). Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_cilium_network_policy``."""
        served = self.get_crd_served(self._VPA_GROUP, self._VPA_PLURAL)
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            item = custom.get_namespaced_custom_object(
                self._VPA_GROUP, version, namespace, self._VPA_PLURAL, name
            )
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_vertical_pod_autoscaler", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]

    # VolumeSnapshot (snapshot.storage.k8s.io, namespaced CRD): the same
    # full-custom-object seam as the Cilium / VPA kinds — the CRD's OWN
    # served version + scope is the authority (``get_crd_served``); the
    # snapshot operator is optional, so CRD absent (None) degrades to [] as
    # a first-class empty state. Unlike 4.1 (a hardcoded all-namespaces
    # ``list_cluster_custom_object`` read that ignored the selected
    # namespace), the namespaced read honors the namespace;
    # ``namespace=None`` spans all namespaces (the all-namespaces branch,
    # kept for the API).
    _SNAPSHOT_GROUP = "snapshot.storage.k8s.io"
    _SNAPSHOT_PLURAL = "volumesnapshots"

    def list_volume_snapshots(self, namespace: str | None) -> list[dict[str, Any]]:
        """VolumeSnapshot items, FULL custom-object shape (spec + status
        intact, camelCase — the wire form, like the Cilium CRDs). The CRD's
        OWN served version + scope is the authority (``get_crd_served``);
        the namespaced read honors the namespace (a fix for 4.1's hardcoded
        all-namespaces ``list_cluster_custom_object`` read), and
        ``namespace=None`` spans all namespaces (the all-namespaces branch,
        kept for the API). CRD absent (snapshot operator not installed) ->
        ``[]`` (the expected state, the Cilium absence contract); any other
        read failure -> ``ClusterUnreachableError`` (502). The pages need
        ``spec.source`` / ``spec.volumeSnapshotClassName`` / ``status``
        intact, so this returns the raw object — NOT the lossy
        ``list_crd_instances`` projection (and no deep-indexing: 4.1's
        KeyError-500 on a SourceMode-less snapshot is fixed in the view via
        ``—``)."""
        served = self.get_crd_served(self._SNAPSHOT_GROUP, self._SNAPSHOT_PLURAL)
        if served is None:
            return []
        version, scope = served
        custom = self._custom()
        try:
            resp = (
                custom.list_namespaced_custom_object(
                    self._SNAPSHOT_GROUP, version, namespace, self._SNAPSHOT_PLURAL
                )
                if namespace and scope == "Namespaced"
                else custom.list_cluster_custom_object(
                    self._SNAPSHOT_GROUP, version, self._SNAPSHOT_PLURAL
                )
            )
        except ApiException as e:
            self._unreachable("list_volume_snapshots", e)
            raise AssertionError("unreachable") from e
        body = self._crd_body(resp)
        items = body.get("items", [])
        return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

    def get_volume_snapshot(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One VolumeSnapshot as a 0/1-item FULL custom object; ``[]`` on 404
        or when the CRD is absent (snapshot operator not installed). Any
        other ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_cilium_network_policy``. The namespace is the one the data page
        was linked with (the ``?name=`` branch of the generic route falls
        back to ``"default"`` when absent — the data page always sends it)."""
        served = self.get_crd_served(self._SNAPSHOT_GROUP, self._SNAPSHOT_PLURAL)
        if served is None:
            return []
        version, _scope = served
        custom = self._custom()
        try:
            item = custom.get_namespaced_custom_object(
                self._SNAPSHOT_GROUP, version, namespace, self._SNAPSHOT_PLURAL, name
            )
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_volume_snapshot", e)
            raise AssertionError("unreachable") from e
        item = self._crd_body(item)
        return [item.to_dict() if hasattr(item, "to_dict") else item]

    def list_resource_quotas(self, namespace: str | None) -> list[dict[str, Any]]:
        """ResourceQuota list in the standard kubernetes dict form
        (``to_dict``) for one namespace, or across all namespaces when the
        namespace is ``None`` (the ``list_secrets`` branch). No field
        stripping — the view renders ``status.used``/``status.hard`` and the
        data page the full object. A transport ApiException maps to
        ``ClusterUnreachableError`` (502)."""
        try:
            resp = (
                self._v1.list_namespaced_resource_quota(namespace)
                if namespace
                else self._v1.list_resource_quota_for_all_namespaces()
            )
        except ApiException as e:
            self._unreachable("list_resource_quotas", e)
            raise AssertionError("unreachable") from e
        return [q.to_dict() for q in resp.items]

    def list_persistent_volume_claims(self, namespace: str | None) -> list[dict[str, Any]]:
        """PersistentVolumeClaim list in the standard kubernetes dict form
        (``to_dict``) for one namespace, or across all namespaces when the
        namespace is ``None`` (the ``list_secrets`` branch). No field
        stripping — the view renders ``spec``/``status`` and the data page
        the full object. A transport ApiException maps to
        ``ClusterUnreachableError`` (502)."""
        try:
            resp = (
                self._v1.list_namespaced_persistent_volume_claim(namespace)
                if namespace
                else self._v1.list_persistent_volume_claim_for_all_namespaces()
            )
        except ApiException as e:
            self._unreachable("list_persistent_volume_claims", e)
            raise AssertionError("unreachable") from e
        return [pvc.to_dict() for pvc in resp.items]

    def list_persistent_volumes(self, namespace: str | None) -> list[dict[str, Any]]:
        """PersistentVolume list in the standard kubernetes dict form
        (``to_dict``) for the WHOLE cluster (the kind is cluster-scoped),
        then 4.1's claim-namespace filter: when ``namespace`` is given, a
        bound PV shows only for its claim's namespace, and a FREE PV
        (``claim_ref`` None) shows for every namespace. Two recorded 4.1
        bug fixes (briefing.md): 4.1 crashed on free PVs (the
        ``claim_ref.namespace`` AttributeError was swallowed by the generic
        handler, returning a PARTIAL list) and silently skipped hostPath PVs
        (a stray ``continue``). ``namespace`` None (no query param) returns
        all PVs unfiltered. A transport ApiException maps to
        ``ClusterUnreachableError`` (502)."""
        try:
            resp = self._v1.list_persistent_volume()
        except ApiException as e:
            self._unreachable("list_persistent_volumes", e)
            raise AssertionError("unreachable") from e
        items = [pv.to_dict() for pv in resp.items]
        if namespace is None:
            return items
        return [pv for pv in items if _pv_claim_namespace(pv) in (None, namespace)]

    def list_secrets(self, namespace: str | None) -> list[dict[str, Any]]:
        """Secret list in the standard kubernetes dict form (``to_dict``)
        without ``data``/``string_data``: values are read one secret at a
        time through ``get_secret``."""
        resp = (
            self._v1.list_namespaced_secret(namespace)
            if namespace
            else self._v1.list_secret_for_all_namespaces()
        )
        items = []
        for secret in resp.items:
            item = secret.to_dict()
            item.pop("data", None)
            item.pop("string_data", None)
            items.append(item)
        return items

    def list_configmaps(self, namespace: str | None) -> list[dict[str, Any]]:
        """ConfigMap list in the standard kubernetes dict form (``to_dict``)
        for one namespace, or across all namespaces when the namespace is
        ``None`` (the ``list_secrets`` branch). UNLIKE ``list_secrets`` this
        does NOT pop ``data``/``binaryData``: a ConfigMap's ``data`` is
        public config (not a credential), and the list view's Data Keys
        column is computed from it — stripping it here would silently break
        that column. A transport ApiException maps to
        ``ClusterUnreachableError`` (502)."""
        try:
            resp = (
                self._v1.list_namespaced_config_map(namespace)
                if namespace
                else self._v1.list_config_map_for_all_namespaces()
            )
        except ApiException as e:
            self._unreachable("list_configmaps", e)
            raise AssertionError("unreachable") from e
        return [cm.to_dict() for cm in resp.items]

    def get_secret(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One Secret (``data`` base64-encoded) as a 0/1-item list; ``[]`` on 404."""
        try:
            return [self._v1.read_namespaced_secret(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            raise

    # Ingress (networking.k8s.io, namespaced core): the full ``to_dict`` form
    # (NO field stripping — the data page's Rules table + the converter read
    # ``spec``/``status``; stripping would break both). A transport
    # ApiException maps to ``ClusterUnreachableError`` (502).

    def list_ingresses(self, namespace: str | None) -> list[dict[str, Any]]:
        """Ingress list in the standard kubernetes dict form (``to_dict``) for
        one namespace, or across all namespaces when the namespace is ``None``
        (the ``list_secrets`` branch). UNLIKE ``list_secrets`` this does NOT strip
        any field: an Ingress's ``spec`` (rules, tls, ingress_class_name) and
        ``status`` (load_balancer) are public, and the data page's Rules table +
        the converter read them — stripping would break both. A transport
        ApiException maps to ``ClusterUnreachableError`` (502)."""
        try:
            resp = (
                self._networking.list_namespaced_ingress(namespace)
                if namespace
                else self._networking.list_ingress_for_all_namespaces()
            )
        except ApiException as e:
            self._unreachable("list_ingresses", e)
            raise AssertionError("unreachable") from e
        return [i.to_dict() for i in resp.items]

    def get_ingress(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One Ingress (full ``spec``/``status`` intact) as a 0/1-item list;
        ``[]`` on 404. Any other ApiException maps to ``ClusterUnreachableError``
        (502), matching ``get_secret``'s contract."""
        try:
            return [self._networking.read_namespaced_ingress(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_ingress", e)
            raise AssertionError("unreachable") from e

    def get_configmap(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One ConfigMap (``data`` plain strings, ``binaryData`` base64) as a
        0/1-item list; ``[]`` on 404. No field stripping (a ConfigMap's
        ``data`` is public config — see ``list_configmaps``). Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_resource_quota``'s transport contract."""
        try:
            return [self._v1.read_namespaced_config_map(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_configmap", e)
            raise AssertionError("unreachable") from e

    def get_resource_quota(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One ResourceQuota as a 0/1-item list; ``[]`` on 404. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_secret``'s transport contract."""
        try:
            return [self._v1.read_namespaced_resource_quota(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_resource_quota", e)
            raise AssertionError("unreachable") from e

    def get_persistent_volume_claim(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One PVC as a 0/1-item list; ``[]`` on 404. Any other ApiException
        maps to ``ClusterUnreachableError`` (502), matching
        ``get_resource_quota``'s transport contract."""
        try:
            return [self._v1.read_namespaced_persistent_volume_claim(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_persistent_volume_claim", e)
            raise AssertionError("unreachable") from e

    def get_persistent_volume(self, _namespace: str, name: str) -> list[dict[str, Any]]:
        """One PersistentVolume as a 0/1-item list; ``[]`` on 404. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_storage_class``'s transport contract. The kind is
        cluster-scoped: the namespace is accepted and ignored."""
        try:
            return [self._v1.read_persistent_volume(name).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_persistent_volume", e)
            raise AssertionError("unreachable") from e

    def list_network_policies(self, namespace: str | None) -> list[dict[str, Any]]:
        """NetworkPolicy list in the standard kubernetes dict form (``to_dict``).
        No field stripping — a policy's spec is what the view renders. A
        transport ApiException maps to ``ClusterUnreachableError`` (502)."""
        try:
            resp = (
                self._networking.list_namespaced_network_policy(namespace)
                if namespace
                else self._networking.list_network_policy_for_all_namespaces()
            )
        except ApiException as e:
            self._unreachable("list_network_policies", e)
            raise AssertionError("unreachable") from e
        return [p.to_dict() for p in resp.items]

    def get_network_policy(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One NetworkPolicy as a 0/1-item list; ``[]`` on 404. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_secret``'s transport contract."""
        try:
            return [self._networking.read_namespaced_network_policy(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_network_policy", e)
            raise AssertionError("unreachable") from e

    # IngressClass (networking.k8s.io, cluster-scoped core): the
    # ``list_runtime_classes``/``get_runtime_class`` cluster-scoped pattern —
    # the namespace is accepted and ignored.
    def list_ingress_classes(self, namespace: str | None) -> list[dict[str, Any]]:
        """IngressClass list in the standard kubernetes dict form (``to_dict``).
        Cluster-scoped: the namespace argument is accepted and ignored. A
        transport ApiException maps to ``ClusterUnreachableError`` (502)."""
        try:
            resp = self._networking.list_ingress_class()
        except ApiException as e:
            self._unreachable("list_ingress_classes", e)
            raise AssertionError("unreachable") from e
        return [i.to_dict() for i in resp.items]

    def get_ingress_class(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One IngressClass as a 0/1-item list; ``[]`` on 404. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_runtime_class``'s contract."""
        try:
            return [self._networking.read_ingress_class(name).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_ingress_class", e)
            raise AssertionError("unreachable") from e

    def list_horizontal_pod_autoscalers(self, namespace: str | None) -> list[dict[str, Any]]:
        """HorizontalPodAutoscaler list in the standard kubernetes dict form
        (``to_dict``) for one namespace, or across all namespaces when the
        namespace is ``None`` (the ``list_secrets`` branch). No field
        stripping — the view renders ``spec``/``status`` and the data page
        the full object. A transport ApiException maps to
        ``ClusterUnreachableError`` (502)."""
        try:
            resp = (
                self._autoscaling.list_namespaced_horizontal_pod_autoscaler(namespace)
                if namespace
                else self._autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces()
            )
        except ApiException as e:
            self._unreachable("list_horizontal_pod_autoscalers", e)
            raise AssertionError("unreachable") from e
        return [h.to_dict() for h in resp.items]

    def get_horizontal_pod_autoscaler(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One HorizontalPodAutoscaler as a 0/1-item list; ``[]`` on 404.
        Any other ApiException maps to ``ClusterUnreachableError`` (502),
        matching ``get_network_policy``'s transport contract."""
        try:
            return [self._autoscaling.read_namespaced_horizontal_pod_autoscaler(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_horizontal_pod_autoscaler", e)
            raise AssertionError("unreachable") from e

    def list_pod_disruption_budgets(self, namespace: str | None) -> list[dict[str, Any]]:
        """PodDisruptionBudget list in the standard kubernetes dict form
        (``to_dict``) for one namespace, or across all namespaces when the
        namespace is ``None`` (the ``list_secrets`` branch). No field
        stripping — the view renders ``spec.min_available``/
        ``spec.max_unavailable``/``status.disruptions_allowed`` and the data
        page the full object. A transport ApiException maps to
        ``ClusterUnreachableError`` (502)."""
        try:
            resp = (
                self._policy.list_namespaced_pod_disruption_budget(namespace)
                if namespace
                else self._policy.list_pod_disruption_budget_for_all_namespaces()
            )
        except ApiException as e:
            self._unreachable("list_pod_disruption_budgets", e)
            raise AssertionError("unreachable") from e
        return [p.to_dict() for p in resp.items]

    def get_pod_disruption_budget(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One PodDisruptionBudget as a 0/1-item list; ``[]`` on 404. Any
        other ApiException maps to ``ClusterUnreachableError`` (502),
        matching ``get_secret``'s transport contract."""
        try:
            return [self._policy.read_namespaced_pod_disruption_budget(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_pod_disruption_budget", e)
            raise AssertionError("unreachable") from e

    def get_priority_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
        """One PriorityClass as a 0/1-item list; ``[]`` on 404. Cluster-
        scoped: the namespace argument is accepted and ignored. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_secret``'s transport contract."""
        try:
            return [self._scheduling.read_priority_class(name).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_priority_class", e)
            raise AssertionError("unreachable") from e

    def get_storage_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
        """One StorageClass as a 0/1-item list; ``[]`` on 404. Cluster-
        scoped: the namespace argument is accepted and ignored. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_priority_class``'s transport contract."""
        try:
            return [self._storage.read_storage_class(name).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_storage_class", e)
            raise AssertionError("unreachable") from e

    def get_runtime_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
        """One RuntimeClass as a 0/1-item list; ``[]`` on 404. Cluster-
        scoped: the namespace argument is accepted and ignored. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_priority_class``'s transport contract."""
        try:
            return [self._node.read_runtime_class(name).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_runtime_class", e)
            raise AssertionError("unreachable") from e

    # The blueprint's service-test seam is the namespace branch only
    # (list_namespaced_limit_range); the all-namespaces branch matches the
    # other namespaced kinds (list_secrets/list_network_policies) and is
    # exercised by the API-tier FakeK8s, whose team-b item the
    # all-namespaces test asserts.
    def list_limit_ranges(self, namespace: str | None) -> list[dict[str, Any]]:
        """LimitRange list in the standard kubernetes dict form (``to_dict``)
        for one namespace, or across all namespaces when the namespace is
        ``None`` (the ``list_secrets`` branch). No field stripping — the
        view renders ``spec.limits`` and the data page the full object. A
        transport ApiException maps to ``ClusterUnreachableError`` (502)."""
        try:
            resp = (
                self._v1.list_namespaced_limit_range(namespace)
                if namespace
                else self._v1.list_limit_range_for_all_namespaces()
            )
        except ApiException as e:
            self._unreachable("list_limit_ranges", e)
            raise AssertionError("unreachable") from e
        return [lr.to_dict() for lr in resp.items]

    def get_limit_range(self, namespace: str, name: str) -> list[dict[str, Any]]:
        """One LimitRange as a 0/1-item list; ``[]`` on 404. Any other
        ApiException maps to ``ClusterUnreachableError`` (502), matching
        ``get_network_policy``'s transport contract."""
        try:
            return [self._v1.read_namespaced_limit_range(name, namespace).to_dict()]
        except ApiException as e:
            if e.status == 404:
                return []
            self._unreachable("get_limit_range", e)
            raise AssertionError("unreachable") from e

    def readyz(self) -> bool:
        """GET ``<host>/readyz`` with the kubeconfig's CA as ``verify=`` and a
        5 s timeout; ANY failure (including timeout) returns ``False`` — the
        caller maps that to ``ClusterUnreachableError``."""
        try:
            r = httpx.get(f"{self._host}/readyz", timeout=5.0, verify=self._verify)
            return r.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # ADR-0013 (TICKET-03) — idempotent, label-aware RBAC apply/delete.
    # ponytail (the ponytail rung): one `try create / except 409 -> patch`.
    # A re-call with the same rules/labels is a no-op (patch to the same
    # state). `ClusterUnreachableError` (502 CLUSTER_UNREACHABLE) wraps any
    # transport failure — the service never sees a raw ApiException.
    # ------------------------------------------------------------------

    def _rules(self, rules: list[dict[str, Any]]) -> list[Any]:
        """Dict rules → ``V1PolicyRule`` (kubernetes 37 keyword-only models)."""
        return [
            k8s_client.V1PolicyRule(
                api_groups=r["api_groups"], resources=r["resources"], verbs=r["verbs"]
            )
            for r in rules
        ]

    def _unreachable(self, kind: str, e: ApiException) -> None:
        """Map a transport ApiException to the stable 502 carrier (the
        service raises nothing but stable codes); raises, does not return."""
        raise ClusterUnreachableError(f"cluster unreachable ({kind})") from e

    def _apply(self, kind: str, name: str, namespace: str | None, body: Any) -> None:
        """Get-or-create + patch for a Role/RoleBinding/ClusterRole(/Binding).

        ponytail (the ponytail rung): ONE ``try create / except 409 -> patch``
        — no existence pre-check, no server-side apply, no conflict retry.
        A re-call with the same rules/labels/subjects is a no-op (patch to the
        same state). Any non-409 ApiException is a transport failure → 502
        ``ClusterUnreachableError``; the service never sees a raw ApiException.
        """
        api = self._rbac
        # (create, patch) per kind; the single tuple-union assignment keeps
        # mypy from inferring one branch's V1Role for every later branch.
        ops: tuple[Any, Any]
        if kind == "role" and namespace is not None:
            ops = (
                lambda: api.create_namespaced_role(namespace, body),
                lambda: api.patch_namespaced_role(name, namespace, body),
            )
        elif kind == "role_binding" and namespace is not None:
            ops = (
                lambda: api.create_namespaced_role_binding(namespace, body),
                lambda: api.patch_namespaced_role_binding(name, namespace, body),
            )
        elif kind == "cluster_role":
            ops = (
                lambda: api.create_cluster_role(body),
                lambda: api.patch_cluster_role(name, body),
            )
        else:  # cluster_role_binding
            ops = (
                lambda: api.create_cluster_role_binding(body),
                lambda: api.patch_cluster_role_binding(name, body),
            )
        create, patch = ops
        try:
            create()
        except ApiException as e:
            if e.status != 409:
                self._unreachable(kind, e)
            try:
                patch()
            except ApiException as pe:
                self._unreachable(kind, pe)

    def _delete(self, kind: str, fn: Any) -> None:
        """Run a delete; 404 = successful no-op (brief: a missing object is
        already the desired state), any other ApiException = transport → 502."""
        try:
            fn()
        except ApiException as e:
            if e.status == 404:
                return
            self._unreachable(kind, e)

    def apply_role(
        self, namespace: str, name: str, rules: list[dict[str, Any]], labels: dict[str, str]
    ) -> None:
        body = k8s_client.V1Role(
            metadata=k8s_client.V1ObjectMeta(name=name, labels=labels),
            rules=self._rules(rules),
        )
        self._apply("role", name, namespace, body)

    def apply_role_binding(
        self,
        namespace: str,
        name: str,
        role_name: str,
        subject_user: str,
        labels: dict[str, str],
        subject_kind: str = "User",
    ) -> None:
        body = k8s_client.V1RoleBinding(
            metadata=k8s_client.V1ObjectMeta(name=name, labels=labels),
            role_ref=k8s_client.V1RoleRef(
                kind="Role", name=role_name, api_group="rbac.authorization.k8s.io"
            ),
            subjects=[k8s_client.RbacV1Subject(kind=subject_kind, name=subject_user, api_group="")],
        )
        self._apply("role_binding", name, namespace, body)

    def apply_cluster_role(
        self, name: str, rules: list[dict[str, Any]], labels: dict[str, str]
    ) -> None:
        body = k8s_client.V1ClusterRole(
            metadata=k8s_client.V1ObjectMeta(name=name, labels=labels),
            rules=self._rules(rules),
        )
        self._apply("cluster_role", name, None, body)

    def apply_cluster_role_binding(
        self,
        name: str,
        role_name: str,
        subject_user: str,
        labels: dict[str, str],
        subject_kind: str = "User",
    ) -> None:
        body = k8s_client.V1ClusterRoleBinding(
            metadata=k8s_client.V1ObjectMeta(name=name, labels=labels),
            role_ref=k8s_client.V1RoleRef(
                kind="ClusterRole", name=role_name, api_group="rbac.authorization.k8s.io"
            ),
            subjects=[k8s_client.RbacV1Subject(kind=subject_kind, name=subject_user, api_group="")],
        )
        self._apply("cluster_role_binding", name, None, body)

    def apply_objects(self, namespace: str, objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generic apply: ONE per-object result list (create / 409 → patch).

        Idempotent get-or-create per object through the CustomObjectsApi
        (create / 409 → patch). Returns the ``applied`` entries
        (``created`` / ``unchanged``); a per-object ApiException is collected
        into ``errors`` (partial failure → the caller returns 200 with the
        errors array).
        """
        applied: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for obj in objects:
            kind = str(obj.get("kind") or "")
            api_version = str(obj.get("apiVersion") or "")
            meta = obj.get("metadata") or {}
            name = str(meta.get("name") or "")
            obj_ns = str(meta.get("namespace") or namespace or "default")
            group, _, version = api_version.partition("/")
            spec = obj.get("spec") or {}
            plural = {
                "GatewayClass": "gatewayclasses",
                "Gateway": "gateways",
                "HTTPRoute": "httproutes",
                "ReferenceGrant": "referencegrants",
            }.get(kind, kind.lower())
            cluster_scoped = kind in ("GatewayClass", "ReferenceGrant")
            custom = self._custom()
            try:
                if cluster_scoped:
                    custom.create_cluster_custom_object(group, version, plural, spec)()
                else:
                    custom.create_namespaced_custom_object(group, version, obj_ns, plural, spec)()
                status = "created"
                applied.append({"kind": kind, "name": name, "namespace": obj_ns, "status": status})
            except ApiException as e:
                if e.status != 409:
                    errors.append({"kind": kind, "name": name, "message": str(e)})
                    continue
                if cluster_scoped:
                    custom.patch_cluster_custom_object(group, version, plural, name, spec)()
                else:
                    custom.patch_namespaced_custom_object(
                        group, version, obj_ns, plural, name, spec
                    )()
                status = "unchanged"
                applied.append({"kind": kind, "name": name, "namespace": obj_ns, "status": status})
        return applied

    def delete_role_binding(self, namespace: str, name: str) -> None:
        self._delete(
            "delete_role_binding",
            lambda: self._rbac.delete_namespaced_role_binding(name, namespace),
        )

    def delete_cluster_role_binding(self, name: str) -> None:
        self._delete(
            "delete_cluster_role_binding", lambda: self._rbac.delete_cluster_role_binding(name)
        )

    def delete_role(self, namespace: str, name: str) -> None:
        self._delete("delete_role", lambda: self._rbac.delete_namespaced_role(name, namespace))

    def delete_cluster_role(self, name: str) -> None:
        self._delete("delete_cluster_role", lambda: self._rbac.delete_cluster_role(name))


def build_admin_client(s: Settings) -> K8sClient:
    """Build the admin client (``source = "admin"``) for the cluster
    KubeDash runs in.

    Source resolution (main-4.x ``k8sClientConfigGet`` pattern, copied):
    - ``kubeconfig-file``: ``load_kube_config(config_file=...)`` — a missing
      file is a config error (``ValueError`` naming the path), not a 500.
    - ``local-kubeconfig``: ``load_kube_config()`` (default path) — a load
      failure falls back to in-cluster, exactly like main's try/except.
    - ``in-cluster``: ``load_incluster_config()``.

    Both mutate the kubernetes client's module-global ``Configuration``,
    which the argless ``K8sClient()`` reads. The unit tier never calls this
    (the pool's ``admin_factory`` seam is injected).
    """
    from kubernetes import config as k8s_config

    src = resolve_admin_source(s)
    if src == "kubeconfig-file":
        if not os.path.isfile(s.admin_kubeconfig):
            raise ValueError(f"admin kubeconfig file not found: {s.admin_kubeconfig}")
        k8s_config.load_kube_config(config_file=s.admin_kubeconfig)  # type: ignore[no-untyped-call]
    elif src == "local-kubeconfig":
        # main's pattern: try the default kubeconfig, fall back to in-cluster,
        # and if that also fails (pod-less host), leave the config unset —
        # readyz() will report the cluster as unreachable.
        try:
            k8s_config.load_kube_config()  # type: ignore[no-untyped-call]
        except Exception:
            with contextlib.suppress(Exception):
                # no in-cluster env; readyz() will fail gracefully
                k8s_config.load_incluster_config()  # type: ignore[no-untyped-call]
    else:
        # in-cluster: the pod service account. On a pod-less host (dev box)
        # this raises ConfigException — catch it so the client is built with
        # an empty config; readyz() then reports the cluster as unreachable.
        with contextlib.suppress(Exception):
            k8s_config.load_incluster_config()  # type: ignore[no-untyped-call]
    return K8sClient(source="admin")


def admin_client_ok(s: Settings) -> bool:
    """readyz PROBE (I-NEW-6), not a re-resolver: ``kubeconfig-file`` source →
    ``isfile`` on the explicit path; ``local-kubeconfig`` and ``in-cluster``
    → True (no explicit file dependency to probe — the default path's presence
    was already established by ``resolve_admin_source``). It does NOT invalidate
    or touch the pooled client — a file deleted after a successful build still
    serves the cached client (its ``readyz()`` then answers the probe at use
    time)."""
    if resolve_admin_source(s) != "kubeconfig-file":
        return True
    return os.path.isfile(s.admin_kubeconfig)


class K8sClientPool:
    """Per-cluster cached clients keyed by ``Cluster.id``.

    The ``id: 0`` branch (ADR-0021, C-NEW-2) lives INSIDE ``get``: the
    synthetic local cluster routes to the admin client (in-cluster or
    kubeconfig-file source), so the five registry call sites — including
    ``rbac.can``'s SAR path — converge on the admin client with NO change at
    the call sites. The role gate is per caller (``g.current_user``); the
    built CLIENT is what's cached (the admin's client is the cluster's
    identity, not the user's).
    """

    def __init__(self, factory: Any = K8sClient, admin_factory: Any = build_admin_client) -> None:
        self._factory = factory
        self._admin_factory = admin_factory
        self._cache: dict[int, Any] = {}
        self._admin_cache: dict[int, Any] = {}

    def get(self, cluster: Any) -> Any:
        if cluster.id == LOCAL_CLUSTER_ID:
            from flask import g

            return self._get_admin_client_for(g.current_user)
        client = self._cache.get(cluster.id)
        if client is None:
            client = self._factory(decrypt_kubeconfig(cluster.kubeconfig_enc))
            self._cache[cluster.id] = client
        return client

    def _get_admin_client_for(self, user: Any) -> Any:
        """The admin client for the cluster KubeDash runs in, or
        ``ClusterNotFoundError`` (the stable 404 family, not a crash) when the
        caller is not an admin.

        LAZY (I4): ``get_settings()`` is resolved on first call, never at
        pool construction — the pool is built at module import, before env is
        guaranteed. The built client is cached (a file deleted after a
        successful build keeps serving the cached client; its ``readyz()``
        answers the probe at use time — I-NEW-6).
        """
        if getattr(user, "role", None) != "admin":
            raise ClusterNotFoundError("cluster not found")
        client = self._admin_cache.get(LOCAL_CLUSTER_ID)
        if client is None:
            client = self._admin_factory(get_settings())
            self._admin_cache[LOCAL_CLUSTER_ID] = client
        return client


#: App-level pool. Tests swap this out (``monkeypatch.setattr(kc, "pool", ...)``)
#: or inject a factory into their own instance; the APIs only ever reach the
#: k8s world through this module.
pool = K8sClientPool()
