"""OD-1: the frozen v1 error envelope and stable codes."""
import pytest

from tests.api.conftest import _FakeRedis


@pytest.fixture()
def _local_app(monkeypatch):
    """Docker-free app (the session `app` fixture needs containers)."""
    import app.extensions as ext
    from app import create_app
    from app.core.security import _oauth

    _oauth.app = None
    _oauth._clients.clear()
    application = create_app({
        "TESTING": True,
        "DATABASE_URL": "sqlite://",
        "REDIS_URL": "redis://localhost:6392/0",
        "KUBEDASH_KUBEDASH_JWT_SECRET": "test-jwt-secret-32-bytes-long!!!!!01",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
    })
    fake = _FakeRedis()
    with application.app_context():
        monkeypatch.setattr(ext, "redis_client", fake)
        from app.extensions import db

        db.create_all()
        # Disable the auth hook for envelope-shape checks: the ClustersApi
        # hook is registered during create_app, so it runs before any
        # fixture-registered hook. Replace it with a no-op.
        from flask import request

        def _no_auth() -> None:
            request.environ["KD_SKIP_AUTH"] = True

        if application.before_request_funcs[None]:
            application.before_request_funcs[None][0] = _no_auth  # type: ignore[index]
        else:
            application.before_request(_no_auth)  # type: ignore[no-untyped-call]
        try:
            yield application
        finally:
            _oauth.app = None
            _oauth._clients.clear()
            db.session.rollback()
            db.session.remove()
            db.drop_all()


def test_error_envelope_shape(_local_app):
    # A registered route that raises a KubeDashHttpError — proves the
    # KubeDashHttpError → as_dict() → {error:{code,message}} envelope.
    from app.core.errors import ClusterNotFoundError

    @_local_app.route("/test/envelope-404")
    def envelope_404():
        raise ClusterNotFoundError("cluster c-1 not found")

    c = _local_app.test_client()  # type: ignore[no-any-return]
    resp = c.get("/test/envelope-404")
    assert resp.status_code == 404
    assert resp.get_json() == {
        "error": {"code": "CLUSTER_NOT_FOUND", "message": "cluster c-1 not found"}
    }


def test_unhandled_exception_maps_to_internal_error_envelope(_local_app):
    """The 10th frozen code: any unhandled exception is INTERNAL_ERROR with a
    generic message — the exception text must not leak into the payload."""

    def boom() -> None:
        raise ValueError("secret-stack-trace-leak")

    @_local_app.route("/test/internal-error")
    def route() -> None:
        boom()

    c = _local_app.test_client()  # type: ignore[no-any-return]
    resp = c.get("/test/internal-error")
    assert resp.status_code == 500
    assert resp.get_json() == {
        "error": {"code": "INTERNAL_ERROR", "message": "internal server error"}
    }
    assert "secret-stack-trace-leak" not in resp.get_data(as_text=True)


def test_all_frozen_codes_are_distinct():
    import app.core.errors as errors

    codes = [cls.error_code for cls in errors.CODES]
    # 10 OD-1 codes + 2 ADR-0021 local-auth codes (OD-B) = 12.
    assert len(codes) == 12
    assert len(set(codes)) == 12
    assert "INTERNAL_ERROR" in codes and "STATE_MISMATCH" in codes
    assert "INVALID_CREDENTIALS" in codes and "LOCAL_AUTH_DISABLED" in codes


def test_error_code_to_status_mapping():
    import app.core.errors as errors

    assert errors.UNAUTHORIZED_STATUS == 401
    assert errors.StateMismatchError("x").code == 400
    assert errors.InternalError("x").code == 500
    assert errors.RbacDeniedError("x").code == 403
    assert errors.ClusterUnreachableError("x").code == 502
    assert errors.ClusterAlreadyExistsError("x").code == 409
    assert errors.InvalidKubeconfigError("x").code == 422
    assert errors.NotImplementedError_("x").code == 501
    assert errors.ClusterNotFoundError("x").code == 404
    assert errors.ResourceKindNotSupportedError("x").code == 404


def test_as_dict_envelope():
    import app.core.errors as errors

    d = errors.ClusterNotFoundError("cluster c-1 not found").as_dict()
    assert d == {"code": "CLUSTER_NOT_FOUND", "message": "cluster c-1 not found"}
    d2 = errors.InvalidKubeconfigError("bad", details={"field": "server"}).as_dict()
    assert d2["details"] == {"field": "server"}
    assert "details" not in errors.ClusterNotFoundError("x").as_dict()
