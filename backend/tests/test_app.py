def test_app_constructs_and_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200


def test_openapi_json_is_valid_openapi3(client):
    resp = client.get("/api/openapi.json")
    assert resp.status_code == 200
    assert resp.get_json()["openapi"].startswith("3.")
