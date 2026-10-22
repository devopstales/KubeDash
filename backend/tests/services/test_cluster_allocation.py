"""Pure cluster-allocation rollup (Task 1).

Covers the acceptance scenarios ``summary-computes-overcommit`` and
``summary-metrics-unavailable-not-zero`` at the seam: dicts in (K8s
``to_dict`` node/pod shapes + a ``node_usage`` dict), dict out.

Certainty rule: a value the rollup cannot read is ``None``, never ``0`` —
``used`` is ``None`` when ``usage`` is ``None``; declared state
(requests/limits) is always present.
"""

from app.services.cluster_allocation import compute_summary


def _node(name: str, cpu: str, mem: str, pods: str | int = "110") -> dict:
    """One node in kubernetes ``to_dict`` form (``status.capacity`` /
    ``status.allocatable``)."""
    return {
        "apiVersion": "v1",
        "kind": "Node",
        "metadata": {"name": name},
        "spec": {},
        "status": {
            "capacity": {"cpu": cpu, "memory": mem, "pods": pods},
            "allocatable": {"cpu": cpu, "memory": mem, "pods": pods},
        },
    }


def _pod(
    name: str,
    cpu_req: str | None,
    mem_req: str | None,
    cpu_limit: str | None = None,
    mem_limit: str | None = None,
    phase: str = "Running",
) -> dict:
    """One pod in kubernetes ``to_dict`` form (``spec.containers[].resources``).

    A ``None`` request/limit is omitted from the dict — the K8s shape never
    carries empty-string quantities.
    """
    resources: dict = {}
    requests: dict = {}
    if cpu_req is not None:
        requests["cpu"] = cpu_req
    if mem_req is not None:
        requests["memory"] = mem_req
    if requests:
        resources["requests"] = requests
    limits: dict = {}
    if cpu_limit is not None:
        limits["cpu"] = cpu_limit
    if mem_limit is not None:
        limits["memory"] = mem_limit
    if limits:
        resources["limits"] = limits
    container: dict = {"name": "c", "image": "img"}
    if resources:
        container["resources"] = resources
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": "default"},
        "spec": {"containers": [container]},
        "status": {"phase": phase},
    }


def test_summary_computes_overcommit():
    """summary-computes-overcommit: declared sums over capacity, used from
    the Metrics API — all distinct fields, all present."""
    nodes = [_node("n1", cpu="4000m", mem="8Gi")]
    pods = [
        _pod("p1", cpu_req="1000m", mem_req="2Gi"),
        _pod("p2", cpu_req="1000m", mem_req="2Gi"),
    ]
    usage = {"n1": {"cpu_millicores": 800, "memory_bytes": 4 * 2**30}}
    s = compute_summary(nodes, pods, usage)
    assert s["cpu"]["capacity_millicores"] == 4000
    assert s["cpu"]["requests_millicores"] == 2000  # 2 pods x 1000m
    assert s["cpu"]["limits_millicores"] == 0  # no limits declared
    assert s["cpu"]["used_millicores"] == 800
    assert s["memory"]["capacity_bytes"] == 8 * 2**30
    assert s["memory"]["requests_bytes"] == 4 * 2**30
    assert s["memory"]["used_bytes"] == 4 * 2**30


def test_summary_metrics_unavailable_not_zero():
    """summary-metrics-unavailable-not-zero: ``usage is None`` → ``used`` is
    ``None`` (never 0), while declared state is still fully present."""
    s = compute_summary([_node("n1", "4000m", "8Gi")], [_pod("p1", "1000m", "2Gi")], usage=None)
    assert s["cpu"]["used_millicores"] is None
    assert s["memory"]["used_bytes"] is None
    assert s["cpu"]["requests_millicores"] == 1000  # declared state still present
    assert s["memory"]["requests_bytes"] == 2 * 2**30


def test_summary_multi_node_multi_container_limits_and_phases():
    """Triangulation: multi-node capacity, per-container requests/limits,
    pods counting by phase (Running/Pending/Succeeded/Failed→completed)."""
    nodes = [
        _node("n1", cpu="2", mem="4Gi", pods="110"),
        _node("n2", cpu="2000m", mem="2000Mi", pods=110),
    ]
    pods = [
        # multi-container: both containers count, mixed declared/absent limits
        _pod(
            "p1",
            cpu_req="250m",
            mem_req="128Mi",
            cpu_limit="500m",
            mem_limit="256Mi",
        ),
        _pod("p2", cpu_req=None, mem_req="1Gi", phase="Pending"),
        _pod("p3", cpu_req="1", mem_req=None, phase="Succeeded"),
        _pod("p4", cpu_req="100m", mem_req="512Mi", phase="Failed"),
    ]
    usage = {
        "n1": {"cpu_millicores": 100, "memory_bytes": 2 * 2**30},
        "n2": {"cpu_millicores": 50, "memory_bytes": 512 * 2**20},
    }
    s = compute_summary(nodes, pods, usage)
    # capacity across both nodes: 2 + 2000m = 4000 millicores; 4Gi + 2000Mi
    assert s["cpu"]["capacity_millicores"] == 4000
    assert s["memory"]["capacity_bytes"] == 4 * 2**30 + 2000 * 2**20
    # p1 (250m + 500m) + p2 (no cpu) + p3 (1 core) + p4 (100m)
    assert s["cpu"]["requests_millicores"] == 250 + 1000 + 100
    assert s["cpu"]["limits_millicores"] == 500  # only p1 declares a cpu limit
    assert s["memory"]["requests_bytes"] == 128 * 2**20 + 1024 * 2**20 + 512 * 2**20
    assert s["memory"]["limits_bytes"] == 256 * 2**20
    # used = sum over both nodes in the usage map
    assert s["cpu"]["used_millicores"] == 150
    assert s["memory"]["used_bytes"] == 2 * 2**30 + 512 * 2**20
    # pods: capacity from node allocatable (string int + int), phases counted
    assert s["pods"]["capacity"] == 110 + 110
    assert s["pods"]["running"] == 1
    assert s["pods"]["pending"] == 1
    assert s["pods"]["completed"] == 2  # Succeeded + Failed
