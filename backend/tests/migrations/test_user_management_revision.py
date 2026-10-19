"""TICKET-02 (user-management, ADR-0013): the one-way-door Alembic revision —
create + seed ``rbac_templates`` (4 built-ins), reconcile ``audit_log``
(ADDITIVE only), extend ``cluster_bindings`` (+unique triple).

Approach (and why): the unit tier's ``app`` fixture uses
``db.create_all()`` (models) on a Testcontainers Postgres, not Alembic — so
it cannot by itself prove the revision applies. This module runs the REAL
``upgrade()`` / ``downgrade()`` functions of the revision module against a
test engine, in two shapes:

1. ``fresh_engine`` — the create_all model shape (what ``db.create_all()``
   already produced: audit_log present in its MODEL shape,
   cluster_bindings present with namespace/template/created_at, and
   uq_cluster_binding_triple present from the model's ``__table_args__``;
   what is ABSENT is ``rbac_templates``): upgrade() creates + seeds
   ``rbac_templates`` and takes the guarded no-op path for every
   pre-existing column — the exact dev-DB idempotency branch. Downgrade()
   must fully reverse it (table + seeds gone).

2. ``legacy_audit_engine`` — same engine after the fixture re-shapes
   ``audit_log`` to the LEGACY form (nullable ``action`` — the Task-1
   carry-forward shape — plus a legacy ``username`` column and one row):
   upgrade() hits the ADDITIVE ``add_column`` reconcile branch; the
   nullable ``action`` must be untouched and the legacy row must survive;
   a second ``upgrade()`` proves idempotent safety.

Both engines are Testcontainers-backed (no live dev PG needed); the gate's
live ``flask db upgrade`` / ``downgrade`` against the dev Postgres is the
complementary backstop.

Test-ordering note: the ``app`` fixture rolls back the shared Testcontainers
session after each test but leaves committed schema changes behind, so this
module's tests are self-contained: every test upgrades, asserts, and
downgrades in its own ``try/finally`` (the same pattern
``tests/test_models.py::test_migration_revision_lands_email_unique`` uses
for the ADR-0021 revision). Because ``downgrade()`` legitimately drops the
extended ``cluster_bindings`` columns/constraint AND the added
``audit_log`` columns, every test that downgrades RESTORES BOTH model
(create_all) shapes right after (``_restore_cluster_bindings_model_shape`` +
``_restore_audit_log_shape``) — so the shared schema is left exactly as
``db.create_all()`` produced it and the full unit sweep is clean regardless
of module order (no FK/column artifact for later tests such as
``test_models.py::test_user_and_binding_roundtrip`` or
``tests/services/test_permission.py``'s AuditLog inserts).
"""

import importlib.util
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

from app.extensions import db

# The declared down_revision (Task 2's parent = the head before this change).
BASELINE_REVISION = "6feadb091ff4"
MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

# Alphabetical (the queries ORDER BY name) — the SET is the contract.
SEED_NAMES = ["admin", "cluster-admin", "developer", "viewer"]


def _load_revision_module() -> object:
    """Import the new revision by scanning versions/ for the TICKET-02 file
    (the filename carries the revision id, so no hard-coded id needed)."""
    paths = sorted(MIGRATIONS_DIR.glob("versions/*_user_management_adr_0013*.py"))
    if not paths:
        msg = f"no *_user_management_adr_0013.py under {MIGRATIONS_DIR / 'versions'}"
        raise FileNotFoundError(msg)
    path = paths[0]
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        msg = f"cannot import {path}"
        raise ImportError(msg)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _q(engine: sa.engine.Engine, sql: str):
    """Query helper — SQLAlchemy 2.x removed ``Engine.execute`` (use
    ``engine.connect()``), and the migration runs under an alembic
    MigrationContext so a raw connection is the honest tool here."""
    with engine.connect() as conn:
        return conn.execute(sa.text(sql))


def _run(fn: object, engine: sa.engine.Engine) -> None:
    """Run a revision's upgrade()/downgrade() against the given engine
    (alembic revisions take no args — the `op` proxy is bound by the
    MigrationContext on this connection)."""
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            fn()


def _restore_cluster_bindings_model_shape(engine: sa.engine.Engine) -> None:
    """Re-add whatever ``downgrade()`` removed from the SHARED
    ``cluster_bindings`` table so later tests see the create_all (model)
    shape: namespace (VARCHAR(255) nullable + index), template (VARCHAR(255)
    nullable), created_at (timestamptz NOT NULL DEFAULT now()), and the
    named uq_cluster_binding_triple unique constraint. Surgical (rows are
    preserved); each DDL is guarded by an inspector check so the helper is
    idempotent. Matches ``ClusterBinding.__table__`` exactly."""
    insp = sa.inspect(engine)
    cols = {c["name"] for c in insp.get_columns("cluster_bindings")}
    stmts: list[str] = []
    if "namespace" not in cols:
        stmts.append("ALTER TABLE cluster_bindings ADD COLUMN namespace VARCHAR(255)")
    if "template" not in cols:
        stmts.append("ALTER TABLE cluster_bindings ADD COLUMN template VARCHAR(255)")
    if "created_at" not in cols:
        stmts.append(
            "ALTER TABLE cluster_bindings ADD COLUMN created_at "
            "TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()"
        )
    if stmts:
        with engine.begin() as conn:
            for stmt in stmts:
                conn.execute(sa.text(stmt))
    idx_names = {i["name"] for i in sa.inspect(engine).get_indexes("cluster_bindings")}
    if not any("namespace" in n for n in idx_names):
        with engine.begin() as conn:
            conn.execute(sa.text("CREATE INDEX ix_cluster_bindings_namespace "
                                 "ON cluster_bindings (namespace)"))
    uqs = {
        uq.get("name") for uq in sa.inspect(engine).get_unique_constraints("cluster_bindings")
    }
    if "uq_cluster_binding_triple" not in uqs:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "ALTER TABLE cluster_bindings ADD CONSTRAINT uq_cluster_binding_triple "
                    "UNIQUE (user_id, cluster_id, namespace, template)"
                )
            )


def _restore_audit_log_shape(engine: sa.engine.Engine) -> None:
    """Drop and re-create the SHARED ``audit_log`` table from the model
    metadata so later tests see the create_all (model) shape. ``downgrade()``
    drops the added columns (actor_sub/target/cluster/namespace/template/at)
    but leaves any legacy columns behind — a plain ``create(checkfirst=True)``
    (as the legacy_audit_engine fixture uses on a legacy-shaped table) is
    not enough here, so drop first, then create. Drops the test's own
    probe rows (acceptable: nothing else reads audit_log in this tier);
    later tests insert their own rows."""
    from app.models.audit import AuditLog

    AuditLog.__table__.drop(bind=engine, checkfirst=True)
    AuditLog.__table__.create(bind=engine, checkfirst=True)


@pytest.fixture()
def fresh_engine(app) -> Iterator[sa.engine.Engine]:
    """The Testcontainers PG after ``db.create_all()``: the model-shaped
    baseline. rbac_templates does not exist yet (it is migration-created);
    uq_cluster_binding_triple exists from the model's ``__table_args__``,
    so upgrade()'s constraint guard takes the no-op path. Yielded as-is."""
    yield db.engine


@pytest.fixture()
def legacy_audit_engine(fresh_engine) -> Iterator[sa.engine.Engine]:
    """Re-shape audit_log to the LEGACY form (nullable action + a legacy
    column + one row), yield, then restore the model shape so later tests
    see the create_all baseline again."""
    from app.models.audit import AuditLog

    engine = fresh_engine
    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS audit_log"))
        conn.execute(
            sa.text(
                "CREATE TABLE audit_log (id SERIAL PRIMARY KEY, "
                "action VARCHAR(255), username VARCHAR(255))"
            )
        )
        conn.execute(
            sa.text("INSERT INTO audit_log (action, username) VALUES ('bind', 'jdoe')")
        )
    try:
        yield engine
    finally:
        AuditLog.__table__.create(bind=engine, checkfirst=True)


# ---------------------------------------------------------------------------
# 1. fresh (create_all) engine — full upgrade → asserts → downgrade
# ---------------------------------------------------------------------------


def test_revision_declares_baseline_down_revision() -> None:
    """The revision chains from the verified head — no branch, no orphan."""
    mod = _load_revision_module()
    assert mod.down_revision == BASELINE_REVISION
    assert mod.branch_labels is None
    assert mod.depends_on is None


def test_builtin_templates_are_seeded_and_protected(fresh_engine) -> None:
    """SATISFIES builtin-templates-are-seeded-and-protected (seed half):
    exactly 4 built-in rows, all ``builtin=True``, named per ADR-0013, with
    the rule sets from ARCHITECTURE.md §5B. Runs upgrade first, asserts,
    then downgrades (self-contained — safe to run in any order)."""
    mod = _load_revision_module()
    _run(mod.upgrade, fresh_engine)
    try:
        insp = sa.inspect(fresh_engine)
        rows = _q(
            fresh_engine, "SELECT name, scope, builtin, rules FROM rbac_templates ORDER BY name"
        ).all()
        assert len(rows) == 4
        assert [r.name for r in rows] == SEED_NAMES
        assert all(r.builtin is True for r in rows)
        by_name = {r.name: (r.scope, r.rules) for r in rows}
        assert by_name["viewer"][0] == "namespace"
        assert by_name["viewer"][1] == [
            {"api_groups": ["*"], "resources": ["*"], "verbs": ["get", "list", "watch"]}
        ]
        assert by_name["admin"] == (
            "namespace",
            [{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        )
        assert by_name["cluster-admin"] == (
            "cluster",
            [{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        )
        dev = by_name["developer"]
        assert dev[0] == "namespace"
        assert len(dev[1]) == 4
        assert dev[1][0] == {
            "api_groups": [""],
            "resources": ["pods", "pods/log", "pods/exec"],
            "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
        }
        # Table contract: name unique, rules JSONB, builtin NOT NULL.
        cols = {c["name"]: c for c in insp.get_columns("rbac_templates")}
        assert "JSONB" in str(cols["rules"]["type"])
        assert cols["builtin"]["nullable"] is False
        assert cols["name"]["nullable"] is False
    finally:
        _run(mod.downgrade, fresh_engine)
        # downgrade restored the pre-upgrade state: table gone, seeds gone.
        assert not sa.inspect(fresh_engine).has_table("rbac_templates")
        # Leave the SHARED cluster_bindings + audit_log in the model
        # (create_all) shape for later tests — downgrade() drops the
        # extended columns/constraint and the added audit_log columns.
        _restore_cluster_bindings_model_shape(fresh_engine)
        _restore_audit_log_shape(fresh_engine)


def test_cluster_bindings_extended_with_unique_triple(fresh_engine) -> None:
    """cluster_bindings gains namespace/template/created_at + the named
    unique constraint on (user_id, cluster_id, namespace, template)."""
    mod = _load_revision_module()
    _run(mod.upgrade, fresh_engine)
    try:
        insp = sa.inspect(fresh_engine)
        cols = {c["name"] for c in insp.get_columns("cluster_bindings")}
        assert {"namespace", "template", "created_at"} <= cols
        detail = {c["name"]: c for c in insp.get_columns("cluster_bindings")}
        assert detail["namespace"]["nullable"] is True
        assert detail["template"]["nullable"] is True
        assert detail["created_at"]["nullable"] is False
        uqs = insp.get_unique_constraints("cluster_bindings")
        assert any(
            uq.get("name") == "uq_cluster_binding_triple" for uq in uqs
        ), f"missing uq_cluster_binding_triple in {uqs}"
        idx_names = {i["name"] for i in insp.get_indexes("cluster_bindings")}
        assert any("namespace" in n for n in idx_names)
    finally:
        _run(mod.downgrade, fresh_engine)
        insp = sa.inspect(fresh_engine)
        cb_cols = {c["name"] for c in insp.get_columns("cluster_bindings")}
        assert {"namespace", "template", "created_at"} & cb_cols == set()
        assert not any(
            uq.get("name") == "uq_cluster_binding_triple"
            for uq in insp.get_unique_constraints("cluster_bindings")
        )
        # Restore the SHARED table's model shape for later tests (see
        # _restore_cluster_bindings_model_shape).
        _restore_cluster_bindings_model_shape(fresh_engine)
        restored = {
            c["name"] for c in sa.inspect(fresh_engine).get_columns("cluster_bindings")
        }
        assert {"namespace", "template", "created_at"} <= restored
        assert "uq_cluster_binding_triple" in {
            uq.get("name")
            for uq in sa.inspect(fresh_engine).get_unique_constraints("cluster_bindings")
        }
        _restore_audit_log_shape(fresh_engine)


# ---------------------------------------------------------------------------
# 2. legacy audit_log — additive reconcile + idempotent re-run
# ---------------------------------------------------------------------------


def test_audit_log_reconciled_additively(legacy_audit_engine) -> None:
    """Reconcile is ADDITIVE: the pre-existing nullable ``action`` column is
    untouched (Task-1 carry-forward ruling), the legacy ``username`` column
    survives, all missing model columns were added, ``at`` is NOT NULL, and
    the pre-seeded row survived the migration."""
    mod = _load_revision_module()
    _run(mod.upgrade, legacy_audit_engine)
    try:
        insp = sa.inspect(legacy_audit_engine)
        detail = {c["name"]: c for c in insp.get_columns("audit_log")}
        for col in ("actor_sub", "target", "cluster", "namespace", "template", "at"):
            assert col in detail, f"audit_log.{col} not added"
        assert detail["actor_sub"]["nullable"] is False
        assert detail["target"]["nullable"] is False
        assert detail["at"]["nullable"] is False
        # carry-forward ruling: action stays nullable, never flipped.
        assert detail["action"]["nullable"] is True
        # additive only: legacy column untouched.
        assert "username" in detail
        row = _q(
            legacy_audit_engine, "SELECT action FROM audit_log WHERE action = 'bind'"
        ).scalar_one()
        assert row == "bind"
    finally:
        _run(mod.downgrade, legacy_audit_engine)


def test_upgrade_is_idempotent_safe(legacy_audit_engine) -> None:
    """Re-running upgrade() on the already-migrated shape is a no-op:
    the guards (has_table/has_column/has_constraint) hold, seed rows stay
    at 4, the legacy row stays at 1."""
    mod = _load_revision_module()
    _run(mod.upgrade, legacy_audit_engine)
    try:
        _run(mod.upgrade, legacy_audit_engine)
        seeded = _q(
            legacy_audit_engine, "SELECT count(*) FROM rbac_templates WHERE builtin = TRUE"
        ).scalar_one()
        assert seeded == 4
        legacy = _q(
            legacy_audit_engine, "SELECT count(*) FROM audit_log WHERE action = 'bind'"
        ).scalar_one()
        assert legacy == 1
    finally:
        _run(mod.downgrade, legacy_audit_engine)
        _run(mod.downgrade, legacy_audit_engine)
        _restore_cluster_bindings_model_shape(legacy_audit_engine)
        _restore_audit_log_shape(legacy_audit_engine)
