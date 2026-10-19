"""R9 stub API surface: registered stub routes answer 501 NOT_IMPLEMENTED.

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


def test_stub_routes_require_auth(api_client):
    # The shared on_before_request hook 401s pre-JWT, like every domain route.
    r = api_client.get("/api/v1/logs/query")
    assert r.status_code == 401
    assert r.get_json()["error"]["code"] == "UNAUTHORIZED"
