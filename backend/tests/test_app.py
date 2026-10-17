def test_app_constructs_and_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200


def test_openapi_json_is_valid_openapi3(client):
    resp = client.get("/api/openapi.json")
    assert resp.status_code == 200
    assert resp.get_json()["openapi"].startswith("3.")


def test_openapi_routes_registered_without_deps():
    """Route registration is config-only — prove it without a container runtime.

    Guards the flask-smorest OPENAPI_URL_PREFIX wiring: /api/openapi.json and
    /api/docs must both be mapped (docs needs the CDN URL set too).
    """
    from app import create_app

    application = create_app({"DATABASE_URL": "sqlite://", "REDIS_URL": "redis://localhost:1/0"})
    rules = {rule.rule: rule.endpoint for rule in application.url_map.iter_rules()}
    assert rules["/api/openapi.json"] == "api-docs.openapi_json"
    assert rules["/api/docs"] == "api-docs.openapi_swagger_ui"
    # /healthz is always up; /readyz maps but its 200/503 is checked in test_health.
    assert "/healthz" in rules and "/readyz" in rules
