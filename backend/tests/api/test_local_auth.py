"""T1-T2, T5: local login + settings. The api-tier app (sqlite) seeds the
admin row DIRECTLY (db.session.add) — the PG-dialect bootstrap upsert is
exercised in tests/test_bootstrap.py (root PG tier); the local route itself
is dialect-agnostic.

SATISFIES: local-admin-login-issues-jwt, login-page-offers-sso-and-local
(backend half: the settings contract).
"""
from urllib.parse import parse_qs, urlparse

import pytest


@pytest.fixture()
def client_with_admin(client, app):
    with app.app_context():  # type: ignore[attr-defined]
        from app.core import security
        from app.extensions import db
        from app.models.user import User

        db.session.add(
            User(
                sub="local:admin@local",
                email="admin@local",
                role="admin",
                auth_source="local",
                password_hash=security.hash_password("correct-horse"),
            )
        )
        db.session.commit()
    return client


def test_local_login_issues_jwt_same_contract_as_oidc(client_with_admin):
    client = client_with_admin
    res = client.post(
        "/api/v1/auth/local", json={"email": "admin@local", "password": "correct-horse"}
    )
    assert res.status_code == 302
    loc = res.headers["Location"]
    # Door check (Hypothesis): EXACT match against the issued pair — the local
    # route must reuse the OIDC callback's redirect builder (T1 key link).
    q = parse_qs(urlparse(loc).query)
    assert set(q) == {"token", "refresh"} and len(q["token"]) == 1 and len(q["refresh"]) == 1
    access, refresh = q["token"][0], q["refresh"][0]
    # The issued JWT decodes to the admin's claims (the pair is real, not echo):
    from app.core.security import verify_jwt

    claims = verify_jwt(access)
    assert claims["sub"].startswith("local:")  # the bootstrap admin's sub convention
    assert loc == f"/?token={access}&refresh={refresh}"


def test_local_login_wrong_password_401(client_with_admin):
    res = client_with_admin.post(
        "/api/v1/auth/local", json={"email": "admin@local", "password": "nope"}
    )
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_local_login_unknown_email_same_code(client_with_admin):
    res = client_with_admin.post(
        "/api/v1/auth/local", json={"email": "ghost@local", "password": "x"}
    )
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "INVALID_CREDENTIALS"  # no enumeration


def test_local_login_sso_row_same_email_401(client, app):
    # I-NEW-2: an SSO user's email (password_hash=None) at /auth/local → the
    # same 401 code (the no-enumeration guarantee holds across auth sources)
    with app.app_context():  # type: ignore[attr-defined]
        from app.extensions import db
        from app.models.user import User

        db.session.add(User(sub="sso:u1", email="sso@local", role="user", auth_source="oidc"))
        db.session.commit()
    res = client.post("/api/v1/auth/local", json={"email": "sso@local", "password": "x"})
    assert res.status_code == 401
    assert res.get_json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_local_login_disabled_when_env_unset(client_no_bootstrap):
    res = client_no_bootstrap.post(
        "/api/v1/auth/local", json={"email": "a@b", "password": "c"}
    )
    assert res.status_code == 403
    assert res.get_json()["error"]["code"] == "LOCAL_AUTH_DISABLED"


def test_auth_settings_open_route_reflects_config(client_no_bootstrap):
    res = client_no_bootstrap.get("/api/v1/auth/settings")  # pre-JWT: no Authorization header
    assert res.status_code == 200
    assert res.get_json() == {"sso_enabled": False, "local_enabled": False}


def test_local_login_malformed_email_is_422_envelope(client_with_admin):
    # Schema validator at the trust boundary: not a password check (that would
    # be 401) — smorest's marshmallow validation error is 422 with the error
    # envelope (the frozen-codes contract covers auth failures, not body shape).
    res = client_with_admin.post("/api/v1/auth/local", json={"email": "nope", "password": "x"})
    assert res.status_code == 422
    assert "error" in res.get_json()
