"""Pure cluster-allocation rollup (the dashboard overcommit signal).

Pure: plain dicts in (node ``to_dict``, pod ``to_dict``, a ``node_usage``
dict), one dict out — no Flask, no IO. The K8s layer (``k8s_client``)
produces the inputs; the metrics endpoint consumes the output.

Certainty rule (AGENTS.md): a value the rollup cannot read is ``None``,
never ``0`` — ``used`` is ``None`` when ``usage`` is ``None`` (Metrics API
unavailable), while declared state (requests/limits) is always present.
Declared and observed are distinct fields.

Overcommit is NOT precomputed here: the endpoint returns raw sums and the
client derives ``max(0, requests - capacity) / capacity`` (blueprint
Must-Haves). The red overflow bar lives in exactly one UI component.

Small private copies of the K8s quantity parsers live here on purpose
(``_parse_cpu`` / ``_parse_bytes`` mirror ``k8s_client``'s): the services
layer must not couple to the IO layer, and ``k8s_client`` is not a shared
util module.
"""

from typing import Any

__all__ = ["compute_summary"]


def _parse_cpu(qty: str | None) -> int:
    """K8s CPU quantity → millicores (``"800m"`` → 800, ``"1"`` → 1000)."""
    if qty is None:
        return 0
    if qty.endswith("m"):
        return int(qty[:-1])
    return int(float(qty) * 1000)


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


def _pod_resources(pod: dict[str, Any]) -> tuple[int, int, int, int]:
    """Sum (cpu_req, cpu_limit, mem_req, mem_limit) across a pod's containers.

    A container missing a request or limit contributes 0 (K8s omits the
    field, it does not write ``""``); a pod without ``spec`` is skipped.
    """
    cpu_req = cpu_lim = mem_req = mem_lim = 0
    for container in (pod.get("spec") or {}).get("containers") or []:
        resources = container.get("resources") or {}
        requests = resources.get("requests") or {}
        limits = resources.get("limits") or {}
        cpu_req += _parse_cpu(requests.get("cpu"))
        cpu_lim += _parse_cpu(limits.get("cpu"))
        mem_req += _parse_bytes(requests.get("memory"))
        mem_lim += _parse_bytes(limits.get("memory"))
    return cpu_req, cpu_lim, mem_req, mem_lim


def compute_summary(nodes: list[dict], pods: list[dict], usage: dict[str, dict] | None) -> dict:
    """Roll a node list, a pod list, and optional Metrics-API usage into the
    ``MetricsSummaryOut``-shaped dict.

    - capacity: Σ node ``status.capacity`` (cpu/memory) + pod count from
      ``status.allocatable.pods`` (an int or a string int).
    - requests/limits: Σ pod ``spec.containers[].resources`` — declared
      state, independent of metrics availability.
    - used: Σ ``usage`` values when ``usage is not None``, else ``None``
      (a missing Metrics API is the expected state — never render 0).
    - pods: phase counts (running/pending/completed, where completed =
      Succeeded + Failed).
    """
    cpu_capacity = mem_capacity = pod_capacity = 0
    for node in nodes:
        status = node.get("status") or {}
        capacity = status.get("capacity") or {}
        allocatable = status.get("allocatable") or {}
        cpu_capacity += _parse_cpu(capacity.get("cpu"))
        mem_capacity += _parse_bytes(capacity.get("memory"))
        # allocatable.pods may be an int or a string int (k8s dict form).
        raw = allocatable.get("pods")
        pod_capacity += int(raw) if raw is not None else 0

    cpu_req = cpu_lim = mem_req = mem_lim = 0
    running = pending = completed = 0
    for pod in pods:
        p_req, p_lim, m_req, m_lim = _pod_resources(pod)
        cpu_req += p_req
        cpu_lim += p_lim
        mem_req += m_req
        mem_lim += m_lim
        phase = (pod.get("status") or {}).get("phase")
        if phase == "Running":
            running += 1
        elif phase == "Pending":
            pending += 1
        elif phase in ("Succeeded", "Failed"):
            completed += 1

    if usage is None:
        used_cpu: int | None = None
        used_mem: int | None = None
    else:
        used_cpu = sum(u.get("cpu_millicores", 0) for u in usage.values())
        used_mem = sum(u.get("memory_bytes", 0) for u in usage.values())

    return {
        "cpu": {
            "capacity_millicores": cpu_capacity,
            "used_millicores": used_cpu,
            "requests_millicores": cpu_req,
            "limits_millicores": cpu_lim,
        },
        "memory": {
            "capacity_bytes": mem_capacity,
            "used_bytes": used_mem,
            "requests_bytes": mem_req,
            "limits_bytes": mem_lim,
        },
        "pods": {
            "capacity": pod_capacity,
            "running": running,
            "pending": pending,
            "completed": completed,
        },
    }
