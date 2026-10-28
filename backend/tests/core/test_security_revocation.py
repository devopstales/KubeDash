"""Task 6 — the Postgres wiring of ``verify_jwt`` and the OIDC state nonce
(ADR-0030, TICKET-06).

Scenarios (acceptance.feature):
- ``revoked-jti-is-rejected-on-the-verify-hook`` (401 half — the verify
  hook reads the ``revoked_jtis`` deny-list; the PK-lookup half landed in
  Task 4's ``revocation.is_revoked``)
- ``oidc-state-is-stored-and-consumed-once`` (call-site half —
  ``new_state``/``consume_state`` go through ``kvstore``; the kv
  set/get/delete half landed in Task 4)
- ``logout-revokes-the-access-token-jti`` (the ``_current_jti()`` decode
  half — the logout route itself lands in the API tier)

The ``app`` fixture (tests/conftest.py) is Testcontainers Postgres +
``db.create_all()``; the ``revoked_jtis``/``kv`` tables come from
Task 1's models. Isolation: the Postgres CONTAINER is session-scoped, so
every test keys off fresh uuid4 jtis / a unique state nonce and sweeps
its rows in teardown (same pattern as Task 4's test files).
"""

from __future__ import annotations

import uuid

import jwt as pyjwt
import pytest
from sqlalchemy import text

from app.core import kvstore, security
from app.core.config import get_settings
from app.core.errors import StateMismatchError, UnauthorizedError
from app.extensions import db
from app.models.user import User
from app.services import revocation


@pytest.fixture()
def engine(app):
    """The fixture app's engine, with its app context active.

    Every read/write in these tests goes through ``db.engine`` connections
    — never the app-scoped ``db.session``: the wiring functions run on
    their OWN connections, and the app-scoped session's identity map
    would hand back pre-mutation stale copies. The teardown ``dispose()``
    is load-bearing (an idle open transaction on a pooled connection is
    rolled back when the NEXT test checks out a connection).
    """
    with app.app_context():
        try:
            yield db.engine
        finally:
            db.session.rollback()
            db.engine.dispose()


@pytest.fixture()
def jti(engine):
    """One fresh jti per test, swept away in teardown."""
    j = uuid.uuid4()
    yield j
    with db.engine.begin() as conn:
        conn.execute(text("DELETE FROM revoked_jtis WHERE jti = :j"), {"j": j})


@pytest.fixture()
def user_row(app, engine) -> str:
    """A User row to issue tokens for, sub swept in teardown."""
    sub = f"u-{uuid.uuid4().hex}"
    with app.app_context():
        db.session.add(User(sub=sub))
        db.session.commit()
    yield sub
    with db.engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE sub = :s"), {"s": sub})


def _token_for(sub: str, jti: uuid.UUID) -> str:
    """A signed access JWT with an explicit ``jti`` (issue_token_pair
    generates its own, so the tests need the row to match a known jti)."""
    from datetime import UTC, datetime, timedelta

    s = get_settings()
    now = datetime.now(UTC)
    return pyjwt.encode(
        {
            "sub": sub,
            "jti": str(jti),
            "iat": now,
            "exp": now + timedelta(seconds=security.ACCESS_TTL_SECONDS),
        },
        s.kubedash_jwt_secret,
        algorithm="HS256",
    )


def test_verify_jwt_rejects_a_revoked_jti(app, engine, jti, user_row):
    # BDD: revoked-jti-is-rejected-on-the-verify-hook
    token = _token_for(user_row, jti)
    revocation.revoke_jti(engine, jti, ttl_seconds=security.ACCESS_TTL_SECONDS)
    with pytest.raises(UnauthorizedError, match="token revoked"):
        security.verify_jwt(token)


def test_verify_jwt_accepts_a_valid_jti(app, engine, jti, user_row):
    # BDD: revoked-jti-is-rejected-on-the-verify-hook — only a deny-list
    # HIT rejects; a valid token whose sibling jti is revoked passes.
    token = _token_for(user_row, jti)
    revocation.revoke_jti(engine, uuid.uuid4(), ttl_seconds=security.ACCESS_TTL_SECONDS)
    claims = security.verify_jwt(token)
    assert claims["sub"] == user_row


def test_expired_revoke_is_not_a_revoke(app, engine, jti, user_row):
    # TRIANGULATE: the deny-list entry expires with the token's own TTL —
    # after expiry the jti verifies again (reaper half).
    token = _token_for(user_row, jti)
    revocation.revoke_jti(engine, jti, ttl_seconds=security.ACCESS_TTL_SECONDS)
    with db.engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE revoked_jtis SET expires_at = now() - interval '1 hour' "
                "WHERE jti = :j"
            ),
            {"j": jti},
        )
    assert security.verify_jwt(token)["sub"] == user_row


def test_current_jti_decodes_the_ambient_token(app, engine, jti, user_row):
    # BDD: logout-revokes-the-access-token-jti (decode half)
    token = _token_for(user_row, jti)
    with app.test_request_context(headers={"Authorization": f"Bearer {token}"}):
        assert security._current_jti() == jti


def test_current_jti_prefers_the_bearer_header_over_the_cookie(
    app, engine, jti, user_row
):
    # TRIANGULATE: the ambient credential is the Bearer header when present
    # (the same precedence _auth_check uses — the header wins the cookie).
    other = uuid.uuid4()
    token = _token_for(user_row, jti)
    cookie_token = _token_for(user_row, other)
    from werkzeug.test import EnvironBuilder

    # ponytail: the cookies ride in as a raw Cookie header (identical at the
    # point _current_jti reads request.cookies); EnvironBuilder builds the
    # WSGI environ (a Request object is NOT the environ).
    environ = EnvironBuilder(
        path="/x",
        headers={
            "Authorization": f"Bearer {token}",
            "Cookie": f"{security.ACCESS_COOKIE}={cookie_token}",
        },
    ).get_environ()
    with app.request_context(environ):
        assert security._current_jti() == jti


def test_current_jti_reads_the_cookie_when_no_header(app, engine, jti, user_row):
    # TRIANGULATE: a cookie-only request (the SPA path) decodes from the
    # ``kd_access`` cookie.
    cookie_token = _token_for(user_row, jti)
    from werkzeug.test import EnvironBuilder

    environ = EnvironBuilder(
        path="/x",
        headers={"Cookie": f"{security.ACCESS_COOKIE}={cookie_token}"},
    ).get_environ()
    with app.request_context(environ):
        assert security._current_jti() == jti


def test_current_jti_without_a_token_is_unauthorized(app):
    # TRIANGULATE: no header, no cookie → UnauthorizedError (the same 401
    # the verify hook raises, not a 500).
    with app.test_request_context():
        with pytest.raises(UnauthorizedError):
            security._current_jti()


def test_new_state_is_stored_and_consumed_once(app, engine):
    # BDD: oidc-state-is-stored-and-consumed-once
    st = security.new_state()
    # the row exists under the state key (value is a one-shot marker; the
    # ROW is what the consumer reads)
    with db.engine.connect() as conn:
        present = conn.execute(
            text("SELECT 1 FROM kv WHERE key = :k"), {"k": f"oidc_state:{st}"}
        ).scalar_one_or_none()
    assert present == 1
    security.consume_state(st)  # first consume: no error
    with pytest.raises(StateMismatchError):
        security.consume_state(st)  # second consume: one-shot


def test_consume_state_unknown_state_raises(app, engine):
    # BDD: oidc-state-is-stored-and-consumed-once — a state that was never
    # issued (or already expired) raises, never a 500.
    with pytest.raises(StateMismatchError):
        security.consume_state(f"never-issued-{uuid.uuid4().hex}")


def test_new_state_rows_expire(app, engine):
    # TRIANGULATE: an expired state row reads as absent — a callback after
    # the 300 s TTL raises StateMismatchError (the TTL half).
    st = security.new_state()
    with db.engine.begin() as conn:
        conn.execute(
            text("UPDATE kv SET expires_at = now() - interval '1 hour' WHERE key = :k"),
            {"k": f"oidc_state:{st}"},
        )
    assert kvstore.kv_get(engine, f"oidc_state:{st}") is None
    with pytest.raises(StateMismatchError):
        security.consume_state(st)
    # the expired tombstone row is pruned by the consume attempt
    with db.engine.connect() as conn:
        present = conn.execute(
            text("SELECT 1 FROM kv WHERE key = :k"), {"k": f"oidc_state:{st}"}
        ).scalar_one_or_none()
    assert present is None
