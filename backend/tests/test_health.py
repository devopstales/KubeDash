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

    # FlaskRedis delegates via __getattr__, so patch the instance's client
    # (not the class) for the failure to be visible in /readyz.
    monkeypatch.setattr(redis_client._redis_client, "ping", _raise)
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["redis"] == "down"
    assert body["database"] == "ok"


def test_readyz_names_failing_database(client, monkeypatch):
    from app.extensions import db

    class _BrokenEngine:
        def connect(self) -> None:
            raise ConnectionError("db down")

    monkeypatch.setattr(db, "engine", _BrokenEngine())
    resp = client.get("/readyz")
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["database"] == "down"
    assert body["redis"] == "ok"
