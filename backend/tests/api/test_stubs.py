"""R9 stub API surface: registered stub routes answer 501 NOT_IMPLEMENTED.

The user-management change (TICKET-04) replaced the ``/admin/users``,
``/admin/permissions/*``, and ``/permissions/my-access`` stubs with real
routes — they are NO LONGER in the 501 list below. The routes that remain
stubbed (``/namespaces/*``, ``/access/*``,
observability, audit reads, SCIM, aggregated) keep their 501 guard.

Uses the Docker-free sqlite + mock-OIDC ``app``/``client`` fixtures from
``tests/api/conftest.py`` (same env profile as the Task 3 auth suite).
"""
from tests.api.conftest import _jwt_of


def test_stub_routes_return_501_not_implemented(api_client, auth_client):
    auth_client.login()
    h = {"Authorization": f"Bearer {_jwt_of(auth_client)}"}
    for path in ("/api/v1/logs/query", "/api/v1/metrics/query", "/api/v1/traces"):
        r = api_client.get(path, headers=h)
        assert r.status_code == 501, path
        assert r.get_json()["error"]["code"] == "NOT_IMPLEMENTED", path


def test_admin_permissions_stub_routes_are_replaced(api_client, auth_client):
    """TICKET-04: the old 501 stubs for ``/admin/users`` +
    ``/admin/permissions/*`` are now real routes — a non-admin hits the
    403 admin gate (RBAC_DENIED), never a 501."""
    auth_client.login()
    h = {"Authorization": f"Bearer {_jwt_of(auth_client)}"}
    for method, path in (
        ("GET", "/api/v1/admin/users"),
        ("GET", "/api/v1/admin/permissions/templates"),
        ("GET", "/api/v1/admin/permissions/templates/any"),
    ):
        r = api_client.open(path, method=method, headers=h)
        assert r.status_code != 501, path
        assert r.status_code == 403, path
        assert r.get_json()["error"]["code"] == "RBAC_DENIED", path


def test_my_access_stub_route_is_replaced(api_client, auth_client):
    """TICKET-04: ``/permissions/my-access`` is a real route (any
    authenticated user, no admin gate) — 200 with the caller's bindings
    (``[]`` when the SSO login user has none), never a 501."""
    auth_client.login()
    h = {"Authorization": f"Bearer {_jwt_of(auth_client)}"}
    r = api_client.get("/api/v1/permissions/my-access", headers=h)
    assert r.status_code == 200
    assert r.get_json() == []


def test_stub_routes_require_auth(api_client):
    # The shared on_before_request hook 401s pre-JWT, like every domain route.
    r = api_client.get("/api/v1/logs/query")
    assert r.status_code == 401
    assert r.get_json()["error"]["code"] == "UNAUTHORIZED"
