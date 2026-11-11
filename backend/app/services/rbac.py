"""SAR decision service (ADR-0004, R4) — the single enforcement point for
per-user, per-cluster Kubernetes RBAC.

Every KubeDash API that lists or mutates cluster resources asks
``can(user, cluster, verb, resource, namespace, name)`` BEFORE it acts: the
cluster's own RBAC (SelfSubjectAccessReview) is the answer, and the 10 frozen
OD-1 codes carry the result (403 RBAC_DENIED on deny).

Decisions are cached in the Postgres ``kv`` table (ADR-0030) for ``SAR_TTL``
seconds under ``sar:<cluster.id>:<user.sub>:<verb>:<resource>:<group>:<namespace>:<name>``
(empty segment = unset). The key carries every SAR attribute: the API lists
with the registry's credentials, so the SAR is the only gate, and a verdict
for one namespace or object must never answer for another (ADR-0004
addendum). A cache hit never re-asks the cluster (the seam the unit tests
prove with a throwing ``pool.get``).

The storage backend moved Redis → ``kv`` under the SAME key (TICKET-06);
this module is Flask-free (``app/services/`` seam rule), so the engine
arrives from the call site as a parameter — never a module global.
"""

from typing import Any
from urllib.parse import quote

from kubernetes import client as k8s_client
from kubernetes.client.exceptions import ApiException
from sqlalchemy import Engine

from app.core import kvstore
from app.core.errors import ClusterUnreachableError
from app.services.k8s_client import pool

SAR_TTL = 30  # seconds (ARCHITECTURE.md §3.3)


def _cache_key(
    cluster_id: int,
    sub: str,
    verb: str,
    resource: str,
    group: str = "",
    namespace: str | None = None,
    name: str | None = None,
) -> str:
    return (
        f"sar:{cluster_id}:"
        f"{quote(str(sub), safe='')}:"
        f"{quote(str(verb), safe='')}:"
        f"{quote(str(resource), safe='')}:"
        f"{quote(str(group), safe='')}:"
        f"{quote(str(namespace or ''), safe='')}:"
        f"{quote(str(name or ''), safe='')}"
    )


def _cache_get(engine: Engine | None, key: str) -> str | None:
    # A miss (absent OR expired) is None; ``kv`` stores text, so the
    # redis-py bytes-decode branch is gone (ADR-0030).
    if engine is None:
        return None
    return kvstore.kv_get(engine, key)


def _cache_set(engine: Engine | None, key: str, value: str) -> None:
    if engine is None:
        return
    kvstore.kv_set(engine, key, value, SAR_TTL)


def _sar_allowed(
    client: Any,
    verb: str,
    resource: str,
    namespace: str | None,
    name: str | None,
    group: str = "",
) -> bool:
    """Ask the cluster: may the user's K8s identity do ``verb`` on
    ``resource`` (scoped to ``namespace``/``name`` when given)?"""
    # ponytail: kubernetes 37's generated models are pydantic-v2 with a
    # keyword-only __init__ (the 29.x positional style is gone), and the SAR
    # models are named V1SelfSubjectAccessReview / …Spec. The resource
    # attributes dict is validated into the V1ResourceAttributes model on
    # construction and camelCase-aliased on the wire; the response's
    # ``status.allowed`` is the bool verdict.
    attrs: dict[str, str | None] = {
        "verb": verb,
        "resource": resource,
        "namespace": namespace,
        "name": name,
    }
    if group:
        attrs["group"] = group
    sar = k8s_client.V1SelfSubjectAccessReview(
        spec=k8s_client.V1SelfSubjectAccessReviewSpec(
            resource_attributes=attrs  # type: ignore[arg-type]
        )
    )
    return bool(client._auth_api.create_self_subject_access_review(sar).status.allowed)


def can(
    user: Any,
    cluster: Any,
    verb: str,
    resource: str,
    namespace: str | None,
    name: str | None,
    group: str = "",
    engine: Engine | None = None,
) -> bool:
    """The ADR-0004 enforcement point: cached SAR verdict, ``True``/``False``.

    ``user`` needs only ``.sub`` (the cache key); ``cluster`` needs only
    ``.id`` (the key + the pool lookup). On a cache miss the cluster is
    asked through the pool's client (Task 4 seam) and the verdict is stored
    for ``SAR_TTL`` seconds.

    ``engine`` is the ``kv`` storage seam (ADR-0030): the API call sites
    pass ``db.engine``; the pure unit tests monkeypatch ``_cache_get``/
    ``_cache_set`` (the storage seam, not the caller), so ``None`` never
    reaches a storage function in unit tests.
    """
    key = _cache_key(cluster.id, user.sub, verb, resource, group, namespace, name)
    hit = _cache_get(engine, key)
    if hit is not None:
        return hit == "1"
    try:
        ok = _sar_allowed(pool.get(cluster), verb, resource, namespace, name, group)
    except ApiException as exc:
        raise ClusterUnreachableError("cluster unreachable during SAR check") from exc

    _cache_set(engine, key, "1" if ok else "0")
    return ok
