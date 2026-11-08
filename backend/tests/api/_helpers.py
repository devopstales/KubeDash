"""Shared helpers for the cluster-scoped API suites (test_metrics_summary.py,
test_events.py).

Plain module (NOT a conftest.py function): ``tests/`` is a namespace layout
without a package ``__init__.py``, so a bare ``from conftest import …`` inside
a subdirectory resolves to the ROOT ``tests/conftest.py`` (pytest's
rootdir-inserted conftest), not this directory's — the module avoids that
shadowing. Kept out of conftest on purpose for the same reason.
"""

import pytest

#: A minimal valid kubeconfig the suites register their fake cluster with
# (valid YAML mapping; the API server is never dialed — FakeK8s stands in).
SHARED_KUBECONFIG = (
    "apiVersion: v1\n"
    "kind: Config\n"
    "clusters:\n"
    "- name: c\n"
    "  cluster:\n"
    "    server: https://1.2.3.4:6443\n"
    "contexts:\n"
    "- name: c\n"
    "  context:\n"
    "    cluster: c\n"
    "    user: u\n"
    "current-context: c\n"
    "users:\n"
    "- name: u\n"
    "  user: {}\n"
)


def register_cluster(api_client, headers, name="prod") -> None:
    """Register a fake cluster row (id 1 in a fresh sqlite app); 201."""
    r = api_client.post(
        "/api/v1/clusters",
        json={
            "name": name,
            "api_server": "https://1.2.3.4:6443",
            "kubeconfig": SHARED_KUBECONFIG,
            "context": name,
        },
        headers=headers,
    )
    assert r.status_code == 201


def sar(
    monkeypatch: pytest.MonkeyPatch,
    allow: set[tuple] | None = None,
    record: list[tuple] | None = None,
) -> None:
    """Patch the SAR seam: allow the exact (verb, resource, group) calls in
    ``allow`` (None = allow everything), record every call in ``record``."""
    import app.services.rbac as rb

    # ADR-0030: the SAR cache is the Postgres ``kv`` table; the storage seam
    # is ``_cache_get(engine, key)`` / ``_cache_set(engine, key, value)``.
    monkeypatch.setattr(rb, "_cache_get", lambda e, k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda e, k, v: None)

    def sar_allowed(client, verb, resource, ns, name, group=""):
        key = (verb, resource, group)
        if record is not None:
            record.append((verb, resource, ns, name, group))
        return True if allow is None else key in allow

    monkeypatch.setattr(rb, "_sar_allowed", sar_allowed)
