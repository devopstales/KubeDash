"""SAR decision service (ADR-0004, R4) — the single enforcement point for
per-user, per-cluster Kubernetes RBAC.

Every KubeDash API that lists or mutates cluster resources asks
``can(user, cluster, verb, resource, namespace, name)`` BEFORE it acts: the
cluster's own RBAC (SelfSubjectAccessReview) is the answer, and the 10 frozen
OD-1 codes carry the result (403 RBAC_DENIED on deny).

Decisions are cached in Redis for ``SAR_TTL`` seconds under
``sar:<cluster.id>:<user.sub>:<verb>:<resource>:<group>:<namespace>:<name>``
(empty segment = unset). The key carries every SAR attribute: the API lists
with the registry's credentials, so the SAR is the only gate, and a verdict
for one namespace or object must never answer for another (ADR-0004
addendum). A cache hit never re-asks the cluster (the seam the unit tests
prove with a throwing ``pool.get``).
"""
from typing import Any

from kubernetes import client as k8s_client

from app.extensions import redis_client
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
    return f"sar:{cluster_id}:{sub}:{verb}:{resource}:{group}:{namespace or ''}:{name or ''}"


def _cache_get(key: str) -> str | None:
    hit = redis_client.get(key)
    if hit is None:
        return None
    # redis-py returns bytes unless decode_responses is on. b"1" == "1" is
    # false, which turned every cache hit into a deny.
    return hit.decode() if isinstance(hit, bytes) else str(hit)


def _cache_set(key: str, value: str) -> None:
    redis_client.set(key, value, ex=SAR_TTL)


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
) -> bool:
    """The ADR-0004 enforcement point: cached SAR verdict, ``True``/``False``.

    ``user`` needs only ``.sub`` (the cache key); ``cluster`` needs only
    ``.id`` (the key + the pool lookup). On a cache miss the cluster is
    asked through the pool's client (Task 4 seam) and the verdict is stored
    for ``SAR_TTL`` seconds.
    """
    key = _cache_key(cluster.id, user.sub, verb, resource, group, namespace, name)
    hit = _cache_get(key)
    if hit is not None:
        return hit == "1"
    ok = _sar_allowed(pool.get(cluster), verb, resource, namespace, name, group)
    _cache_set(key, "1" if ok else "0")
    return ok
