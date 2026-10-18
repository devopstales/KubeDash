"""ADR-0021 bootstrap hook — root PG tier (Testcontainers).

The hook is PG-dialect (``ON CONFLICT (email)``), so these tests run against
real Postgres via ``tests/conftest.py``; the sqlite api tier (tests/api/)
seeds rows directly and SKIPS the hook (C-NEW-1).

The conftest ``app`` fixture boots the app with BOTH bootstrap env vars set
(I-NEW-1 env triple: setenv -> cfg._settings = None -> create_app) and calls
``_bootstrap_local_admin`` after ``db.create_all()`` — the test path of the
same seam wsgi.py uses in production.

SATISFIES: local-admin-login-issues-jwt (T3 half: the row the route verifies
against is hook-created, not test-seeded), adr-0021-local-mode-in-force
(schema half: the row's shape), oidc-login-still-issues-jwt (SSO-collision
half: an IdP callback that claims the bootstrap email wins auth_source,
and a re-boot does NOT flip it back — I-NEW-2).
"""
import pytest
from testcontainers.postgres import PostgresContainer

from app.extensions import db
from app.models.user import User

# The conftest shims (tests/conftest.py:20-23) map get_container_host_ip /
# get_exposed_port onto the legacy attribute names; importing the container
# class here is what makes the session fixture below use the shimmed API.
_ = PostgresContainer


def _row(db_sess, email: str):
    return db.session.execute(db.select(User).filter_by(email=email)).scalars().all()


def test_bootstrap_creates_admin_row(app, db_sess):
    rows = _row(db_sess, "admin@local")
    assert len(rows) == 1
    u = rows[0]
    assert u.role == "admin" and u.auth_source == "local" and u.password_hash is not None
    assert u.sub == "local:admin@local"  # the sub convention (M2: pinned in test)


def test_bootstrap_idempotent_second_boot(app, db_sess):
    n1 = db.session.scalar(db.select(db.func.count()).select_from(User))
    from app import _bootstrap_local_admin

    _bootstrap_local_admin(app)  # second "boot", same env
    n2 = db.session.scalar(db.select(db.func.count()).select_from(User))
    assert n1 == n2  # ON CONFLICT: no duplicate row even under concurrent writers


def test_bootstrap_updates_hash_on_password_change(app, db_sess, monkeypatch):
    h1 = (
        db.session.execute(db.select(User.password_hash).filter_by(email="admin@local"))
        .scalar_one()
    )
    monkeypatch.setenv("KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD", "rotated-horse")
    import app.core.config as cfg

    cfg._settings = None  # reset the Settings cache
    from app import _bootstrap_local_admin

    _bootstrap_local_admin(app)
    h2 = (
        db.session.execute(db.select(User.password_hash).filter_by(email="admin@local"))
        .scalar_one()
    )
    assert h1 != h2  # env password change propagates on next boot


def test_bootstrap_noop_when_env_unset(app_no_bootstrap, db_sess):
    assert db.session.scalar(db.select(db.func.count()).select_from(User)) == 0


def test_sso_collision_keeps_oidc_and_freezes_hash(app, db_sess, monkeypatch):
    """I-NEW-2 (locked): an OIDC callback that lands on the bootstrap email
    flips the row to auth_source='oidc'; a re-boot must NOT flip it back AND
    must leave password_hash UNCHANGED (the case-gated refresh skips
    non-local rows) — the local password genuinely stops working (401 via
    the /auth/local auth_source gate, matching ADR-0021's 'SSO wins')."""
    # SSO claims the bootstrap email: the callback upserts on sub and writes
    # auth_source='oidc' explicitly (honest write — api/auth._upsert_user).
    # The collision is on email: the IdP row carries a DIFFERENT sub
    # (idp-sub-admin) but the SAME email (admin@local). With uq_users_email
    # in force, a second row at that email is impossible — so this test
    # models the collision by DELETING the local row and inserting the IdP
    # row at the same email (the net effect of the IdP callback having
    # claimed the email first). The re-boot's ON CONFLICT (email) upsert
    # then hits the IdP row and the case-gate is exercised.
    db.session.execute(db.delete(User))
    db.session.commit()
    u = User(
        sub="idp-sub-admin",
        email="admin@local",
        auth_source="oidc",
        groups=[],
        password_hash="pre-existing-oidc-hash",
    )
    db.session.add(u)
    db.session.commit()
    h_before = db.session.execute(
        db.select(User.password_hash).filter_by(email="admin@local")
    ).scalar_one()
    assert h_before == "pre-existing-oidc-hash"

    monkeypatch.setenv("KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD", "rotated-horse")
    import app.core.config as cfg

    cfg._settings = None
    from app import _bootstrap_local_admin

    _bootstrap_local_admin(app)  # next boot, with a changed env password

    rows = _row(db_sess, "admin@local")
    assert len(rows) == 1
    assert rows[0].auth_source == "oidc"  # SSO wins: not flipped back to local
    assert rows[0].password_hash == h_before  # hash untouched for non-local rows


@pytest.fixture()
def app_no_bootstrap(pg_container, redis_container, monkeypatch):
    """A PG app with BOTH bootstrap env vars EMPTY and NO hook invocation —
    the env-unset no-op is observable: zero users rows after create_all.
    (The root-tier ``app`` fixture sets the vars to non-empty values, so
    this fixture must override them explicitly.)"""
    import app.core.config as cfg

    monkeypatch.setenv("KUBEDASH_BOOTSTRAP_ADMIN_EMAIL", "")
    monkeypatch.setenv("KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD", "")
    cfg._settings = None
    from app import create_app

    application = create_app({
        "TESTING": True,
        "DATABASE_URL": pg_container.get_connection_url(driver="psycopg"),
        "REDIS_URL": f"redis://{redis_container.get_container_host()}:{redis_container.exposed_port(6379)}",
        "KUBEDASH_JWT_SECRET": "test-jwt-secret",
        "KUBEDASH_SECRET_KEY": "test-enc-key-32-bytes-long!!!!",
    })
    with application.app_context():
        from app.extensions import db

        db.create_all()
        # No hook call here — but the session-scoped PG is shared with the
        # ``app`` fixture (whose hook committed a row), so clean the table
        # for an honest "zero rows" observation.
        db.session.execute(db.delete(User))
        db.session.commit()
        yield application
        db.session.rollback()
