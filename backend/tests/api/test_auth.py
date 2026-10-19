"""OIDC spine: login → JWT delivery, state round-trip, refresh rotation.

SATISFIES: oidc-login-issues-jwt
"""
import hashlib
from urllib.parse import parse_qs, urlparse


def test_login_flow_issues_jwt_and_me_echoes_sub(api_client, auth_client):
    auth_client.login()
    r3 = api_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {auth_client.jwt}"}
    )
    assert r3.status_code == 200
    assert r3.get_json()["sub"] == "sub-oidc-1"
    assert r3.get_json()["email"] == "jdoe@example.com"


def test_me_shape_growth_me_out_fields(api_client, auth_client, api_app):
    """TICKET-16: the MeOut growth (profile-page-shows-identity, backend
    half) — every me response carries auth_source / kubeconfig_source /
    last_login_at. An OIDC-upserted user (role 'user') gets the source
    column value 'oidc' and kubeconfig_source None (non-admin)."""
    auth_client.login()
    me = api_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {auth_client.jwt}"}
    ).get_json()
    assert me["auth_source"] == "oidc"
    assert me["kubeconfig_source"] is None
    assert "last_login_at" in me and me["last_login_at"] is not None
    # The OIDC login stamped last_login_at on the upsert.
    with api_app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        u = db.session.execute(db.select(User).filter_by(sub="sub-oidc-1")).scalar_one()
        assert u.last_login_at is not None


def test_callback_redirect_is_exact_issued_pair(api_client, mock_oidc):
    """I-NEW-4 door check (pinned in test_auth.py, per the brief's file list):
    the OIDC callback's 302 Location must be EXACTLY the issued pair — the
    shared-builder contract (redirect_with_tokens) is pinned on BOTH sides;
    the local route mirrors this assertion in test_local_auth.py."""
    r1 = api_client.post("/api/v1/auth/login")
    cb = r1.headers["Location"]
    state = parse_qs(urlparse(cb).query)["state"][0]
    r2 = api_client.get(f"{cb}&code={mock_oidc.CODE}&state={state}")
    assert r2.status_code == 302
    loc = r2.headers["Location"]
    q = parse_qs(urlparse(loc).query)
    assert loc == f"/?token={q['token'][0]}&refresh={q['refresh'][0]}"


def test_state_mismatch_rejected(api_client, mock_oidc):
    r1 = api_client.post("/api/v1/auth/login")
    cb = r1.headers["Location"]
    state = parse_qs(urlparse(cb).query)["state"][0]
    # wrong state on the way back — the callback's state key never existed
    # (build the URL explicitly; the mock authorize URL embeds the same
    # state value, so a second `state=` would not be "wrong")
    r2 = api_client.get(f"/api/v1/auth/callback?state=not-{state}&code={mock_oidc.CODE}")
    assert r2.status_code == 400
    assert r2.get_json()["error"]["code"] == "STATE_MISMATCH"


def test_state_single_use(api_client, mock_oidc):
    """A consumed state key is deleted: replaying the same callback URL 400s."""
    r1 = api_client.post("/api/v1/auth/login")
    cb = r1.headers["Location"]
    state = parse_qs(urlparse(cb).query)["state"][0]
    r2 = api_client.get(f"{cb}&code={mock_oidc.CODE}&state={state}")
    assert r2.status_code == 302
    r3 = api_client.get(f"{cb}&code={mock_oidc.CODE}&state={state}")
    assert r3.status_code == 400
    assert r3.get_json()["error"]["code"] == "STATE_MISMATCH"


def test_callback_missing_code_is_400_envelope(api_client, mock_oidc):
    r1 = api_client.post("/api/v1/auth/login")
    cb = r1.headers["Location"]
    r2 = api_client.get(cb)  # no code= param
    assert r2.status_code == 400
    assert set(r2.get_json()["error"]) >= {"code", "message"}


def test_unauthenticated_api_returns_401_stable_shape(api_client):
    # /api/v1/clusters is the shared on_before_request exemplar route (Task 4
    # registers its real Api here; until then this stub carries the hook).
    resp = api_client.get("/api/v1/clusters")
    assert resp.status_code == 401
    assert resp.get_json() == {
        "error": {"code": "UNAUTHORIZED", "message": "missing or invalid token"}
    }


def test_expired_jwt_returns_401_not_500(api_client, api_app):
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.user import User

    with api_app.app_context():  # type: ignore[attr-defined]
        u = (
            db.session.execute(db.select(User).filter_by(sub="sub-oidc-1"))
            .scalar_one_or_none()
            or User(sub="sub-oidc-1", email="j@example.com")
        )
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u, expires_in=-10)  # already expired
    resp = api_client.get("/api/v1/clusters", headers={"Authorization": f"Bearer {access}"})
    assert resp.status_code == 401


def test_garbage_jwt_returns_401(api_client):
    resp = api_client.get(
        "/api/v1/clusters", headers={"Authorization": "Bearer not.a.jwt"}
    )
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_revoked_jti_returns_401(api_client, api_app):
    from app.core.config import get_settings
    from app.core.security import issue_token_pair
    from app.extensions import db
    from app.models.user import User

    with api_app.app_context():  # type: ignore[attr-defined]
        u = (
            db.session.execute(db.select(User).filter_by(sub="sub-oidc-1"))
            .scalar_one_or_none()
            or User(sub="sub-oidc-1", email="j@example.com")
        )
        db.session.add(u)
        db.session.commit()
        access, _ = issue_token_pair(u)
        import jwt as pyjwt

        jti = pyjwt.decode(access, get_settings().kubedash_jwt_secret, algorithms=["HS256"])["jti"]
        from app.extensions import redis_client

        redis_client.set(f"revoked:{jti}", "1", ex=900)
    resp = api_client.get("/api/v1/clusters", headers={"Authorization": f"Bearer {access}"})
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_refresh_rotation_reuse_rejected_and_row_deleted(api_client, auth_client, api_app):
    auth_client.login()
    old_refresh = auth_client.refresh
    # first use: succeeds, returns a NEW rotated pair
    r1 = api_client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r1.status_code == 200
    body = r1.get_json()
    assert body["access"] and body["refresh"]
    assert body["refresh"] != old_refresh
    # the rotated token works end-to-end
    r2 = api_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access']}"}
    )
    assert r2.status_code == 200
    # second use of the SAME (now-consumed) token: 401
    r3 = api_client.post("/api/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r3.status_code == 401
    assert r3.get_json()["error"]["code"] == "UNAUTHORIZED"
    # the consumed row is DELETED (T5), not merely revoked
    from app.extensions import db
    from app.models.token import RefreshToken

    with api_app.app_context():  # type: ignore[attr-defined]
        assert (
            db.session.execute(
                db.select(RefreshToken).filter_by(
                    token_hash=hashlib.sha256(old_refresh.encode()).hexdigest()
                )
            )
            .scalar_one_or_none()
            is None
        )


def test_refresh_unknown_token_is_401(api_client):
    r1 = api_client.post("/api/v1/auth/refresh", json={"refresh_token": "never-issued"})
    assert r1.status_code == 401
    assert r1.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_logout_then_refresh_rejected(api_client, auth_client, api_app):
    auth_client.login()
    refresh = auth_client.refresh
    r1 = api_client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {auth_client.jwt}"},
    )
    assert r1.status_code == 200
    r2 = api_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 401
    assert r2.get_json()["error"]["code"] == "UNAUTHORIZED"


def test_me_without_token_is_401(api_client):
    r1 = api_client.get("/api/v1/auth/me")
    assert r1.status_code == 401
    assert r1.get_json()["error"]["code"] == "UNAUTHORIZED"
