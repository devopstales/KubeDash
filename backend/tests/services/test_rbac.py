"""ADR-0004 — the SAR decision service (R4).

Pure unit tier: no app, no Docker, no Redis. ``can`` is tested through the two
seams it exposes — ``_cache_get``/``_cache_set`` (the Redis production seam)
and ``pool.get`` (the k8s client seam, with a ``FakeSar`` double standing in
for the cluster's AuthorizationV1Api). The cache key is
``sar:<cluster.id>:<user.sub>:<verb>:<resource>:<group>:<namespace>:<name>``:
every SAR attribute is in it, so one namespace's verdict never answers for
another.
"""
from types import SimpleNamespace

import pytest


def _user(sub: str = "u-1") -> SimpleNamespace:
    return SimpleNamespace(sub=sub)


def _cluster(cid: int = 1) -> SimpleNamespace:
    return SimpleNamespace(id=cid)


def _client_allows(verbs: set[str]) -> SimpleNamespace:
    """A FakeK8s whose AuthorizationV1Api answers a canned SAR verdict
    (allowed iff the requested verb is in ``verbs``)."""

    class FakeStatus:
        def __init__(self, ok: bool) -> None:
            self.allowed = ok

    class FakeSarApi:
        def create_self_subject_access_review(self, body) -> SimpleNamespace:
            # The SAR nests the attributes under ``spec`` (k8s wire shape).
            return SimpleNamespace(
                status=FakeStatus(body.spec.resource_attributes.verb in verbs)
            )

    return SimpleNamespace(_auth_api=FakeSarApi())


def test_can_denied_returns_false(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.rbac as rb

    monkeypatch.setattr(rb.pool, "get", lambda c: _client_allows(set()))
    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    assert rb.can(_user(), _cluster(), "list", "pods", None, None) is False


def test_can_allowed_and_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.rbac as rb

    sets: list[tuple[str, str]] = []
    monkeypatch.setattr(rb.pool, "get", lambda c: _client_allows({"list"}))
    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: sets.append((k, v)))
    assert rb.can(_user(), _cluster(), "list", "pods", None, None) is True
    # The production seam wrote the verdict under the frozen key format.
    assert sets == [("sar:1:u-1:list:pods:::", "1")]


def test_cache_hit_decodes_redis_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stored allow is bytes from redis-py. It must still count as allow."""
    import app.services.rbac as rb

    monkeypatch.setattr(rb, "redis_client", SimpleNamespace(get=lambda k: b"1"))

    def _boom(_c):
        raise AssertionError("SAR called on cache hit")

    monkeypatch.setattr(rb.pool, "get", _boom)
    assert rb.can(_user(), _cluster(), "list", "pods", None, None) is True


def test_can_reads_cache_without_sar(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.rbac as rb

    monkeypatch.setattr(rb, "_cache_get", lambda k: "1")  # cache hit

    def _boom(_c):
        raise AssertionError("SAR called on cache hit")

    monkeypatch.setattr(rb.pool, "get", _boom)
    assert rb.can(_user(), _cluster(), "list", "pods", None, None) is True
    # A different sub is a DIFFERENT cache key — a hit for u-1 must not answer
    # for u-2 (the sub is in the key, the SAR is not re-asked for u-1).
    monkeypatch.setattr(
        rb, "_cache_get", lambda k: "1" if k == "sar:1:u-1:list:pods:::" else None
    )
    monkeypatch.setattr(rb.pool, "get", lambda c: _client_allows({"list"}))
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    assert rb.can(_user("u-2"), _cluster(), "list", "pods", None, None) is True


def test_denial_is_cached_too(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.rbac as rb

    gets: list[str] = []
    monkeypatch.setattr(rb.pool, "get", lambda c: _client_allows(set()))
    monkeypatch.setattr(rb, "_cache_get", lambda k: (gets.append(k), None)[1])
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    assert rb.can(_user(), _cluster(), "list", "pods", None, None) is False
    assert gets == ["sar:1:u-1:list:pods:::"]
    # The next call is a cache hit: the pool is never reached.
    monkeypatch.setattr(
        rb, "_cache_get", lambda k: "0" if k == "sar:1:u-1:list:pods:::" else None
    )
    monkeypatch.setattr(
        rb.pool, "get", lambda c: (_ for _ in ()).throw(AssertionError("SAR called"))
    )
    assert rb.can(_user(), _cluster(), "list", "pods", None, None) is False


def test_sar_carries_namespace_and_name(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.services.rbac as rb

    seen: list[tuple[str | None, str | None]] = []

    class FakeStatus:
        allowed = True

    class FakeSarApi:
        def create_self_subject_access_review(self, body) -> SimpleNamespace:
            ra = body.spec.resource_attributes
            seen.append((ra.namespace, ra.name))
            return SimpleNamespace(status=FakeStatus())

    monkeypatch.setattr(rb.pool, "get", lambda c: SimpleNamespace(_auth_api=FakeSarApi()))
    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    assert rb.can(_user(), _cluster(), "delete", "pods", "default", "nginx") is True
    assert seen == [("default", "nginx")]


def test_namespace_and_name_are_separate_cache_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    """An allow cached for team-a must not answer for kube-system, and an
    allow for one secret must not answer for another."""
    import app.services.rbac as rb

    cache: dict[str, str] = {}
    asked: list[tuple[str | None, str | None]] = []

    class FakeStatus:
        def __init__(self, ok: bool) -> None:
            self.allowed = ok

    class FakeSarApi:
        def create_self_subject_access_review(self, body) -> SimpleNamespace:
            ra = body.spec.resource_attributes
            asked.append((ra.namespace, ra.name))
            return SimpleNamespace(status=FakeStatus(ra.namespace == "team-a" and ra.name != "other"))

    monkeypatch.setattr(rb.pool, "get", lambda c: SimpleNamespace(_auth_api=FakeSarApi()))
    monkeypatch.setattr(rb, "_cache_get", cache.get)
    monkeypatch.setattr(rb, "_cache_set", cache.__setitem__)
    assert rb.can(_user(), _cluster(), "list", "secrets", "team-a", None) is True
    assert rb.can(_user(), _cluster(), "list", "secrets", "kube-system", None) is False
    assert rb.can(_user(), _cluster(), "get", "secrets", "team-a", "db") is True
    assert rb.can(_user(), _cluster(), "get", "secrets", "team-a", "other") is False
    assert asked == [("team-a", None), ("kube-system", None), ("team-a", "db"), ("team-a", "other")]
    assert rb.can(_user(), _cluster(), "list", "secrets", "team-a", None) is True
    assert len(asked) == 4


def test_sar_carries_api_group_for_rbac_resources(monkeypatch: pytest.MonkeyPatch) -> None:
    """Role lives in rbac.authorization.k8s.io. A core-group SAR is a deny."""
    import app.services.rbac as rb

    seen: list[str | None] = []

    class FakeStatus:
        allowed = True

    class FakeSarApi:
        def create_self_subject_access_review(self, body) -> SimpleNamespace:
            seen.append(body.spec.resource_attributes.group)
            return SimpleNamespace(status=FakeStatus())

    monkeypatch.setattr(rb.pool, "get", lambda c: SimpleNamespace(_auth_api=FakeSarApi()))
    monkeypatch.setattr(rb, "_cache_get", lambda k: None)
    monkeypatch.setattr(rb, "_cache_set", lambda k, v: None)
    assert (
        rb.can(_user(), _cluster(), "list", "roles", "default", None, "rbac.authorization.k8s.io")
        is True
    )
    assert seen == ["rbac.authorization.k8s.io"]
