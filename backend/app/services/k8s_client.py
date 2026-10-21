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
import base64
import contextlib
import hashlib
import os
import secrets
from typing import Any, Literal

import httpx
import yaml
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kubernetes import client as k8s_client
from kubernetes.client.exceptions import ApiException

from app.core.config import Settings, get_settings
from app.core.errors import ClusterNotFoundError, ClusterUnreachableError

# OD-2 frozen form: version byte (cipher/key generation marker), then the
# 96-bit nonce, then the AES-256-GCM ciphertext (includes the 16-byte tag).
_VERSION = 0x01
_NONCE_LEN = 12

_key: bytes = hashlib.sha256(get_settings().kubedash_secret_key.encode()).digest()


def encrypt_kubeconfig(plain: bytes) -> bytes:
    """Store form: ``0x01 || nonce || AES-GCM(nonce, key, plaintext)``."""
    nonce = secrets.token_bytes(_NONCE_LEN)
    ct = AESGCM(_key).encrypt(nonce, plain, None)
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
        return AESGCM(_key).decrypt(nonce, enc[1 + _NONCE_LEN :], None)
    except Exception as e:  # cryptography raises InvalidTag/ValueError
        raise ValueError("kubeconfig decryption failed") from e


def bound_cluster_or_404(user: Any, cluster_id: int) -> Any:
    """Binding gate shared by the clusters/resources APIs (Task 5 consumes it
    by name).

    Looks up BOTH the ``Cluster`` and the caller's ``ClusterBinding``: a
    missing cluster OR a missing binding raises ``ClusterNotFoundError``
    (404 CLUSTER_NOT_FOUND) — an unbound user cannot even see that a cluster
    exists.
    """
    from app.extensions import db
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster

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


class K8sClient:
    """Per-cluster kubernetes client.

    Two shapes: the registry shape (``K8sClient(kubeconfig)``, built from the
    decrypted bytes) and the admin shape (``K8sClient()`` with
    ``load_*_config`` applied first, ``source = "admin"`` — ADR-0021). The
    host is taken VERBATIM from ``configuration.host`` — it already carries
    the scheme — so ``readyz`` never double-prefixes it.
    """

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
            cluster_entry = loaded["clusters"][0]
            ca = cluster_entry.get("certificate-authority-data")
            # httpx verify= accepts str (PEM bundle) or bool — decode the CA
            # to a PEM string so mypy strict is happy.
            self._verify: str | bool = base64.b64decode(ca).decode() if ca else True
        else:
            # Admin shape (ADR-0021): build_admin_client applied
            # load_kube_config/load_incluster_config BEFORE this, which sets
            # the library's DEFAULT Configuration (not the module-global).
            # Read it back — a fresh Configuration() would be empty.
            try:
                client_config = k8s_client.Configuration.get_default_copy()
            except Exception:
                client_config = k8s_client.Configuration()
            self._verify = True
        self._config = client_config
        api_client = k8s_client.ApiClient(self._config)
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
        self._host = self._v1.api_client.configuration.host

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
            subjects=[
                k8s_client.RbacV1Subject(kind=subject_kind, name=subject_user, api_group="")
            ],
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
            subjects=[
                k8s_client.RbacV1Subject(kind=subject_kind, name=subject_user, api_group="")
            ],
        )
        self._apply("cluster_role_binding", name, None, body)

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

    def __init__(
        self, factory: Any = K8sClient, admin_factory: Any = build_admin_client
    ) -> None:
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
