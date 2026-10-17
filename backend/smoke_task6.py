"""Task 6 Docker-free smoke: create app (sqlite), hit each stub API route -> 501."""
from urllib.parse import parse_qs, urlparse

import app.core.security as sec
import app.extensions as ext
from app import create_app
from tests.api.conftest import MockOIDC, _FakeRedis

app = create_app({
    "TESTING": True,
    "DATABASE_URL": "sqlite://",
    "REDIS_URL": "redis://localhost:6390/0",
    "KUBEDASH_KUBEDASH_JWT_SECRET": "test-jwt-secret-32-bytes-long!!!!!01",
    "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
})
ext.redis_client = _FakeRedis()
sec.oidc_exchange = MockOIDC().exchange
sec.oidc_authorize_url = MockOIDC().authorize_url

with app.app_context():
    from app.extensions import db

    db.create_all()
    c = app.test_client()

    # Login to get a JWT
    r1 = c.post("/api/v1/auth/login")
    assert r1.status_code == 302, r1.status_code
    cb = r1.headers["Location"]
    state = parse_qs(urlparse(cb).query)["state"][0]
    r2 = c.get(f"{cb}&code={MockOIDC.CODE}&state={state}")
    assert r2.status_code == 302, r2.status_code
    tok = parse_qs(urlparse(r2.headers["Location"]).query)["token"][0]
    h = {"Authorization": f"Bearer {tok}"}
    print(f"PASS 1: JWT issued (sub={MockOIDC.USER['sub']})")

    # Every stub API route -> 501 NOT_IMPLEMENTED
    stub_routes = [
        "/api/v1/logs/query",
        "/api/v1/metrics/query",
        "/api/v1/metrics/query_range",
        "/api/v1/traces",
        "/api/v1/traces/t-1",
        "/api/v1/audit",
        "/api/v1/audit/export",
        "/api/v1/admin/permissions/bind",
        "/api/v1/admin/permissions/templates",
        "/api/v1/namespaces/requests",
        "/api/v1/access/requests",
        "/api/v1/kubeconfig",
        "/api/v1/admin/users",
        "/api/v1/admin/clusters",
        "/api/v1/scim/v2/users",
        "/api/v1/scim/v2/groups",
        "/api/v1/resources/pods",
    ]
    for p in stub_routes:
        post_routes = (
            "/api/v1/admin/permissions/bind",
            "/api/v1/namespaces/requests",
            "/api/v1/access/requests",
            "/api/v1/scim/v2/users",
            "/api/v1/scim/v2/groups",
        )
        method = "post" if p in post_routes else "get"
        r = c.open(p, method=method, headers=h)
        body = r.get_json() or {}
        code = body.get("error", {}).get("code")
        assert r.status_code == 501, f"{p}: {r.status_code} != 501"
        assert code == "NOT_IMPLEMENTED", f"{p}: {code} != NOT_IMPLEMENTED"
    print(f"PASS 2: {len(stub_routes)} stub routes all 501 NOT_IMPLEMENTED")

    # Unauthenticated -> 401 UNAUTHORIZED
    r = c.get("/api/v1/logs/query")
    assert r.status_code == 401, r.status_code
    assert r.get_json()["error"]["code"] == "UNAUTHORIZED"
    print("PASS 3: unauthenticated -> 401 UNAUTHORIZED")

    # Open routes (no JWT needed)
    for p in ("/healthz", "/readyz", "/api/openapi.json", "/api/docs"):
        r = c.get(p)
        assert r.status_code != 401, f"{p}: {r.status_code} should not be 401"
    print("PASS 4: open routes (healthz/readyz/openapi/docs) not 401")

    # kubectl_auth is open (no JWT) -> 501
    r = c.get("/api/v1/kubectl/auth/v1/config")
    assert r.status_code == 501, r.status_code
    assert r.get_json()["error"]["code"] == "NOT_IMPLEMENTED"
    print("PASS 5: kubectl_auth open route -> 501 NOT_IMPLEMENTED")

    # Aggregated routes are registered on the 8443 mTLS app, not the main
    # app (ADR-0012) — their 501 surfaces there, not here.
    print("PASS 6: aggregated routes on the 8443 app (not main app) — skipped")

print("All smoke checks passed.")
