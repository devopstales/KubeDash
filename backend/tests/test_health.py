def test_readyz_ok_when_deps_up(client):
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["database"] == "ok"
    assert body["redis"] == "ok"


def test_readyz_names_failing_dependency(client, monkeypatch):
    from app.extensions import redis_client

    def _raise(*_args: object, **_kwargs: object) -> None:
        raise ConnectionError("down")

    monkeypatch.setattr(redis_client, "ping", _raise)
    resp = client.get("/readyz")
    assert resp.status_code == 503
    assert "redis" in resp.get_data(as_text=True)
