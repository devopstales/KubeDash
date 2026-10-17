"""File-map guard (R9): ARCHITECTURE.md §2 ↔ tree contract.

Every §2 ``backend/app/`` path is asserted to exist on disk; the test fails
the suite when a path goes missing. Updating §2 means updating EXPECTED in
the same PR (the list is copied verbatim from §2 at authoring time).
"""
import pathlib

import pytest

# ARCHITECTURE.md §2 — backend/app/ file map (spine paths + stub paths).
# Keep in sync with .skillgrid/ARCHITECTURE.md §2 when that file changes.
EXPECTED = [
    "app/__init__.py", "app/extensions.py",
    "app/core/config.py", "app/core/security.py", "app/core/leader.py", "app/core/errors.py",
    "app/api/__init__.py", "app/api/auth.py", "app/api/clusters.py", "app/api/resources.py",
    "app/api/logs.py", "app/api/metrics.py", "app/api/traces.py", "app/api/audit.py",
    "app/api/permissions.py", "app/api/namespaces.py", "app/api/access.py",
    "app/api/kubeconfig.py", "app/api/admin.py",
    "app/api/scim/__init__.py", "app/api/scim/users.py", "app/api/scim/groups.py",
    "app/api/aggregated/__init__.py", "app/api/aggregated/projects.py",
    "app/api/aggregated/sso_users.py", "app/api/aggregated/sso_groups.py",
    "app/models/user.py", "app/models/cluster.py", "app/models/binding.py",
    "app/models/token.py", "app/models/leader_lease.py",
    "app/models/rbac_template.py", "app/models/namespace_request.py",
    "app/models/access_request.py", "app/models/scim_map.py", "app/models/audit.py",
    "app/services/k8s_client.py", "app/services/rbac.py",
    "app/services/prometheus.py", "app/services/loki.py", "app/services/tempo.py",
    "app/services/grafana.py", "app/services/permission.py", "app/services/namespace.py",
    "app/services/access.py", "app/services/provisioning.py", "app/services/scim.py",
    "app/tasks/cluster_sync.py", "app/tasks/health.py", "app/tasks/alerts.py",
    "app/tasks/rbac_drift.py", "app/tasks/access_expiry.py", "app/tasks/ns_request_expiry.py",
    "app/sockets/events.py", "app/sockets/logs.py",
    # aggregated API service layer (§2, ADR-0012) — stubs
    "app/aggregated/__init__.py", "app/aggregated/project.py",
    "app/aggregated/sso_user.py", "app/aggregated/sso_group.py",
    # kubectl plugin bootstrap endpoint (§2 line: api/kubectl_auth.py) —
    # stub now; the in-flight kubectl-oidc-plugin change replaces its body
    "app/api/kubectl_auth.py", "app/schemas/kubectl_auth.py",
    "app/schemas/__init__.py",
    "app/schemas/auth.py", "app/schemas/cluster.py",
    "app/schemas/resource.py", "app/schemas/errors.py",
]


@pytest.mark.parametrize("rel", EXPECTED)
def test_path_exists(rel):
    base = pathlib.Path(__file__).resolve().parents[1]
    assert (base / rel).is_file(), f"ARCHITECTURE.md §2 path missing: {rel}"
