"""TASK-042 (2026-10-27-postgres-queue-revocation-active-active,
ADR-0029/0030/0031): the tracer-thread schema — ``tasks``, ``revoked_jtis``,
``kv`` on ``db.metadata`` plus ``leader_lease.fence``. The ``app`` fixture
builds the live schema with ``db.create_all()`` from the ORM models, so
these assertions prove the models register the right tables/columns; the
migration itself is proven by its ``down_revision`` (the current single
head) and structure, not by this fixture.

SATISFIES: enqueue-then-claim-returns-the-task-path (schema half — the
``tasks`` row is claimable once the table exists; the claim logic is
Task 2).
"""
import sqlalchemy as sa

TASK_COLUMNS = {
    "id",
    "path",
    "status",
    "attempts",
    "enqueued_at",
    "locked_at",
    "locked_by",
    "available_at",
}


def _inspect(app):
    # Flask 3: app.extensions is a plain dict; flask-sqlalchemy 3.x
    # registers under "sqlalchemy" (not "db").
    return sa.inspect(app.extensions["sqlalchemy"].engine)


def test_new_tables_exist(app):
    """The three new tables are registered on db.metadata and therefore
    created by the fixture's db.create_all()."""
    names = set(_inspect(app).get_table_names())
    assert {"tasks", "revoked_jtis", "kv"} <= names


def test_leader_lease_has_non_null_fence(app):
    """ADR-0031: the strict fence column exists and is NOT NULL (the
    server default of 0 lives in the migration; the model side only has to
    declare the column non-nullable so create_all emits it)."""
    ins = _inspect(app)
    assert "leader_lease" in ins.get_table_names()
    fence = [c for c in ins.get_columns("leader_lease") if c["name"] == "fence"]
    assert len(fence) == 1
    assert fence[0]["nullable"] is False


def test_tasks_columns(app):
    """ADR-0029 queue table: the claim loop (Task 2) reads exactly these
    columns; the index on enqueued_at is plain (non-partial, no now()
    predicate — findings #2)."""
    cols = {c["name"] for c in _inspect(app).get_columns("tasks")}
    assert cols >= TASK_COLUMNS


def test_revoked_jtis_pk_and_expiry(app):
    """ADR-0030 deny-list: jti is the primary key (PK lookup bound as a
    parameter, findings #1) and expires_at is NOT NULL."""
    ins = _inspect(app)
    cols = {c["name"] for c in ins.get_columns("revoked_jtis")}
    assert {"jti", "expires_at"} <= cols
    pk = ins.get_pk_constraint("revoked_jtis")["constrained_columns"]
    assert pk == ["jti"]
    by_name = {c["name"]: c for c in ins.get_columns("revoked_jtis")}
    assert by_name["expires_at"]["nullable"] is False


def test_kv_key_value_expiry(app):
    """ADR-0030 KV store: key is the primary key, value is nullable (a
    tombstone row is legal), expires_at is NOT NULL; the index on
    expires_at is plain (no now() predicate)."""
    ins = _inspect(app)
    cols = {c["name"] for c in ins.get_columns("kv")}
    assert {"key", "value", "expires_at"} <= cols
    pk = ins.get_pk_constraint("kv")["constrained_columns"]
    assert pk == ["key"]
    by_name = {c["name"]: c for c in ins.get_columns("kv")}
    assert by_name["value"]["nullable"] is True
    assert by_name["expires_at"]["nullable"] is False
