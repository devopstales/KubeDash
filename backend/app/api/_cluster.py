"""Shared cluster-resolution helper for the cluster-scoped domain APIs
(metrics / events / resources).

The three domains each resolve ``cluster_id`` → cluster the same way: the
synthetic local cluster (id 0, ADR-0021) comes from the clusters domain's
``_local_cluster``; every other id passes the binding gate. Living in the
``app.api`` package (not a domain Api, not ``app.services`` — which must stay
pure-Python) keeps the imports same-package with no cross-domain cycle.
"""

from app.services.k8s_client import LOCAL_CLUSTER_ID, bound_cluster_or_404


def cluster_for(user: object, cluster_id: int) -> object:
    """Resolve ``cluster_id`` for a cluster-scoped read.

    Id 0 → the synthetic local cluster (no ``clusters`` row, so the binding
    gate is bypassed); any other id → ``bound_cluster_or_404`` (404
    CLUSTER_NOT_FOUND on a missing cluster OR a missing binding).
    """
    if cluster_id == LOCAL_CLUSTER_ID:
        from app.api.clusters import _local_cluster

        return _local_cluster()
    return bound_cluster_or_404(user, cluster_id)
