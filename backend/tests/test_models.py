"""Task 2 — core model round-trips and validation (Postgres-backed via conftest)."""
from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.user import User


def test_user_and_binding_roundtrip(app, db_sess):
    from app.models.binding import ClusterBinding
    from app.models.cluster import Cluster
    from app.models.user import User

    with app.app_context():
        u = User(sub="sub-1", email="jdoe@example.com", display_name="J Doe", role="user")
        c = Cluster(
            name="prod", api_server="https://1.2.3.4:6443", kubeconfig_enc=b"enc", context="prod"
        )
        db.session.add_all([u, c])
        db.session.flush()
        b = ClusterBinding(user_id=u.id, cluster_id=c.id, role="viewer")
        db.session.add(b)
        db.session.commit()
        assert ClusterBinding.query.filter_by(user_id=u.id).first().role == "viewer"


def test_binding_rejects_unknown_role(app, db_sess):
    from app.models.binding import ClusterBinding
    from app.models.user import User

    with app.app_context():
        u = User(sub="sub-2", email="x@example.com", display_name="X")
        db.session.add(u)
        db.session.flush()
        with pytest.raises(ValueError):
            db.session.add(ClusterBinding(user_id=u.id, cluster_id=1, role="superuser"))


def test_refresh_token_stores_hash_not_raw(app, db_sess):
    from app.models.token import RefreshToken
    from app.models.user import User

    with app.app_context():
        u = User(sub="sub-3", email="t@example.com", display_name="T")
        db.session.add(u)
        db.session.flush()
        # expires_at is NOT NULL in the schema (the model has no default) —
        # set it explicitly rather than relying on the column being nullable.
        tok = RefreshToken(
            user_id=u.id,
            token_hash=RefreshToken.hash_token("raw-token-abc"),
            expires_at=datetime.now(UTC),
        )
        db.session.add(tok)
        db.session.commit()
        assert tok.token_hash != "raw-token-abc"
        assert RefreshToken.hash_token("raw-token-abc") == RefreshToken.hash_token("raw-token-abc")


def test_user_auth_columns_schema(app, db_sess):
    """ADR-0021 (TICKET-14): the two auth columns exist with the right
    nullability, and users.email is UNIQUE (uq_users_email — C-NEW-1: the
    bootstrap upsert's ON CONFLICT (email) requires a matching unique
    constraint; it also backstops the OIDC path where two IdP subs can
    share an email)."""
    cols = {c.name: c for c in User.__table__.columns}
    assert "password_hash" in cols
    assert cols["password_hash"].nullable is True  # None for SSO rows
    assert "auth_source" in cols
    assert cols["auth_source"].nullable is False  # NOT NULL DEFAULT 'oidc'
    assert cols["auth_source"].default.arg == "oidc"
    assert cols["email"].unique is True
    # A second row with the same email must be rejected by the constraint,
    # not merely the model: insert two and expect IntegrityError.
    from sqlalchemy.exc import IntegrityError

    u1 = User(sub="sub-uc-1", email="dup@example.com")
    u2 = User(sub="sub-uc-2", email="dup@example.com")
    db.session.add_all([u1, u2])
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_user_email_unique_constraint_rejects_duplicate(app, db_sess):
    """uq_users_email (C-NEW-1): the constraint lives on the table, not the
    model — a raw INSERT bypassing the ORM's unique flag still collides
    (the bootstrap upsert's ON CONFLICT (email) needs exactly this)."""
    from sqlalchemy import text

    # The NOT NULL columns (groups/role/status/auth_source) are supplied so
    # the only candidate violation is the email uniqueness. A raw
    # ``db.session.execute(text(...))`` runs under psycopg's autocommit
    # (it raises immediately, not at flush/commit).
    u1 = User(sub="sub-uq-1", email="uq@example.com", groups=[])
    db.session.add(u1)
    db.session.commit()
    with pytest.raises(IntegrityError, match="unique"):
        db.session.execute(
            text(
                "INSERT INTO users (sub, email, groups, role, status, auth_source) "
                "VALUES ('sub-uq-2', 'uq@example.com', '[]'::jsonb, 'user', 'active', 'oidc')"
            )
        )
    db.session.rollback()


def test_migration_revision_lands_email_unique(app):
    """ADR-0021 (TICKET-14): run the actual Alembic revision's upgrade()
    against a scratch table shaped like the pre-migration ``users`` (no
    password_hash / auth_source / uq_users_email) and verify the revision
    produces the uq_users_email unique constraint (C-NEW-1: the bootstrap
    upsert's ON CONFLICT (email) requires a matching unique index — without
    it Postgres rejects the statement)."""
    import importlib.util
    from pathlib import Path

    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import text

    rev_path = (
        Path(__file__).resolve().parent.parent
        / "migrations" / "versions" / "6feadb091ff4_local_admin_auth_adr_0021.py"
    )
    spec = importlib.util.spec_from_file_location("_rev6feadb", rev_path)
    rev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rev)

    engine = db.engine
    with engine.begin() as conn:
        # Scratch table shaped like the pre-migration users (the columns the
        # initial domain-tables revision created — no password_hash /
        # auth_source, no uq_users_email).
        conn.execute(text("DROP TABLE IF EXISTS _rev_check_users CASCADE"))
        conn.execute(text(
            "CREATE TABLE _rev_check_users ("
            "  id SERIAL PRIMARY KEY,"
            "  sub VARCHAR(255) NOT NULL,"
            "  email VARCHAR(255),"
            "  display_name VARCHAR(255),"
            "  groups JSONB NOT NULL,"
            "  role VARCHAR(32) NOT NULL DEFAULT 'user',"
            "  status VARCHAR(32) NOT NULL DEFAULT 'active',"
            "  last_login_at TIMESTAMP WITH TIME ZONE"
            ")"
        ))
        # The revision hardcodes the table name "users"; swap it in over the
        # real table for the duration of upgrade(), then restore.
        conn.execute(text("ALTER TABLE users RENAME TO _users_backup"))
        conn.execute(text("ALTER TABLE _rev_check_users RENAME TO users"))
        try:
            with Operations.context(MigrationContext.configure(conn)):
                rev.upgrade()
            connames = [
                r[0]
                for r in conn.execute(text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conrelid = 'users'::regclass AND contype = 'u'"
                )).fetchall()
            ]
            assert "uq_users_email" in connames, connames
        finally:
            conn.execute(text("ALTER TABLE users RENAME TO _rev_check_users"))
            conn.execute(text("ALTER TABLE _users_backup RENAME TO users"))
            conn.execute(text("DROP TABLE IF EXISTS _rev_check_users CASCADE"))
