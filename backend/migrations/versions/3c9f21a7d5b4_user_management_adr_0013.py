"""user management (ADR-0013): rbac_templates + 4 built-in seeds, audit_log
reconcile, cluster_bindings extension

Revision ID: 3c9f21a7d5b4
Revises: 6feadb091ff4
Create Date: 2026-10-19 12:00:00.000000

One-way-door (ADR-0002) — the migration-gated schema change for the
user-management change (TICKET-02):

- ``rbac_templates`` is created and seeded with the 4 ADR-0013 built-ins
  (viewer / developer / admin / cluster-admin; rules per
  ARCHITECTURE.md §5B, ``builtin=True``).
- ``audit_log`` reconciliation is ADDITIVE ONLY: every missing model column
  is added, but the live ``action`` column's nullability is never touched
  (Task-1 carry-forward ruling: a live table may have a nullable
  ``action``; the model is stricter and the gap is accepted).
- ``cluster_bindings`` gains ``namespace`` / ``template`` / ``created_at``
  plus ``uq_cluster_binding_triple`` — the one-way part (data loss not
  reversed by the rollback; ``flask db downgrade -1`` is the declared
  rollback unit).

Every op is guarded (has_table / has_column / constraint-exists checks) so
the revision applies cleanly on a fresh DB AND on a populated dev DB where
parts of the schema already exist (dev databases here are
``db.create_all()``-based and unstamped).

Seeded rows use ``created_by=NULL`` (system seed, no actor identity —
consistent for all four).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Used by postgresql.JSONB(astext_type=...) below.
Text = sa.Text


# revision identifiers, used by Alembic.
revision = '3c9f21a7d5b4'
down_revision = '6feadb091ff4'
branch_labels = None
depends_on = None


# ADR-0013 built-ins — rule sets per ARCHITECTURE.md §5B (the "developer"
# JSON is verbatim from that section; the other three per the §5B table).
BUILTIN_TEMPLATES = [
    {
        "name": "viewer",
        "description": "Read-only access to a namespace",
        "scope": "namespace",
        "rules": [
            {"api_groups": ["*"], "resources": ["*"], "verbs": ["get", "list", "watch"]}
        ],
    },
    {
        "name": "developer",
        "description": "Day-to-day development",
        "scope": "namespace",
        "rules": [
            {
                "api_groups": [""],
                "resources": ["pods", "pods/log", "pods/exec"],
                "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
            },
            {
                "api_groups": ["apps"],
                "resources": ["deployments", "statefulsets", "daemonsets"],
                "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
            },
            {
                "api_groups": [""],
                "resources": ["services", "configmaps", "secrets"],
                "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
            },
            {
                "api_groups": ["batch"],
                "resources": ["jobs", "cronjobs"],
                "verbs": ["get", "list", "watch", "create"],
            },
        ],
    },
    {
        "name": "admin",
        "description": "Namespace admin",
        "scope": "namespace",
        "rules": [{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    },
    {
        "name": "cluster-admin",
        "description": "Full cluster access",
        "scope": "cluster",
        "rules": [{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    },
]


def _table_columns(bind, table: str) -> set:
    insp = sa.inspect(bind)
    if not insp.has_table(table):
        return set()
    return {c["name"] for c in insp.get_columns(table)}


def _has_unique_constraint(bind, table: str, name: str) -> bool:
    insp = sa.inspect(bind)
    return any(
        uq.get("name") == name for uq in insp.get_unique_constraints(table)
    )


def upgrade():
    bind = op.get_bind()

    # 1. rbac_templates — create (guarded: a dev DB may already have it).
    if not sa.inspect(bind).has_table("rbac_templates"):
        op.create_table(
            "rbac_templates",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("description", sa.String(length=255), nullable=False, server_default=""),
            sa.Column("scope", sa.String(length=16), nullable=False),
            sa.Column(
                "rules",
                postgresql.JSONB(astext_type=Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column("created_by", sa.String(length=255), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )
        op.create_index(op.f("ix_rbac_templates_name"), "rbac_templates", ["name"], unique=True)

    # 2. Seed the 4 built-ins (skip any that already exist — idempotent).
    existing = {
        row[0]
        for row in bind.execute(sa.text("SELECT name FROM rbac_templates"))
    }
    op.bulk_insert(
        sa.table(
            "rbac_templates",
            sa.column("name", sa.String),
            sa.column("description", sa.String),
            sa.column("scope", sa.String),
            sa.column("rules", postgresql.JSONB),
            sa.column("created_by", sa.String),
            sa.column("builtin", sa.Boolean),
        ),
        [
            {
                "name": t["name"],
                "description": t["description"],
                "scope": t["scope"],
                "rules": t["rules"],
                "created_by": None,
                "builtin": True,
            }
            for t in BUILTIN_TEMPLATES
            if t["name"] not in existing
        ],
    )

    # 3. audit_log — ADDITIVE reconcile only; action's nullability is
    #    NEVER touched (Task-1 carry-forward ruling). The table may be
    #    missing entirely (dev DBs are create_all-based and the AuditLog
    #    model only landed in TICKET-01): create it with the full model
    #    shape in that case.
    audit_cols = _table_columns(bind, "audit_log")
    if not audit_cols:
        op.create_table(
            "audit_log",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("action", sa.String(length=255), nullable=False),
            sa.Column("actor_sub", sa.String(length=255), nullable=False),
            sa.Column("target", sa.String(length=255), nullable=False),
            sa.Column("cluster", sa.String(length=255), nullable=True),
            sa.Column("namespace", sa.String(length=255), nullable=True),
            sa.Column("template", sa.String(length=255), nullable=True),
            sa.Column(
                "at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.PrimaryKeyConstraint("id"),
        )
    else:
        # Legacy rows predate these columns: Postgres rejects a plain
        # NOT NULL ADD COLUMN on a non-empty table, so NOT NULL columns
        # are added nullable, backfilled with the migration-actor marker,
        # then made NOT NULL. ``at`` uses its server_default (no rows to
        # backfill — the default fills existing rows on ADD).
        if "actor_sub" not in audit_cols:
            op.add_column("audit_log", sa.Column("actor_sub", sa.String(length=255)))
            bind.execute(
                sa.text("UPDATE audit_log SET actor_sub = 'kubedash-migration' WHERE actor_sub IS NULL")
            )
            op.alter_column("audit_log", "actor_sub", nullable=False)
        if "target" not in audit_cols:
            op.add_column("audit_log", sa.Column("target", sa.String(length=255)))
            bind.execute(
                sa.text("UPDATE audit_log SET target = 'unknown' WHERE target IS NULL")
            )
            op.alter_column("audit_log", "target", nullable=False)
        if "cluster" not in audit_cols:
            op.add_column("audit_log", sa.Column("cluster", sa.String(length=255), nullable=True))
        if "namespace" not in audit_cols:
            op.add_column("audit_log", sa.Column("namespace", sa.String(length=255), nullable=True))
        if "template" not in audit_cols:
            op.add_column("audit_log", sa.Column("template", sa.String(length=255), nullable=True))
        if "at" not in audit_cols:
            op.add_column(
                "audit_log",
                sa.Column(
                    "at",
                    sa.DateTime(timezone=True),
                    server_default=sa.text("CURRENT_TIMESTAMP"),
                    nullable=False,
                ),
            )

    # 4. cluster_bindings — one-way extension + unique triple.
    if "namespace" not in _table_columns(bind, "cluster_bindings"):
        op.add_column("cluster_bindings", sa.Column("namespace", sa.String(length=255), nullable=True))
        op.create_index(
            op.f("ix_cluster_bindings_namespace"), "cluster_bindings", ["namespace"], unique=False
        )
    if "template" not in _table_columns(bind, "cluster_bindings"):
        op.add_column("cluster_bindings", sa.Column("template", sa.String(length=255), nullable=True))
    if "created_at" not in _table_columns(bind, "cluster_bindings"):
        op.add_column(
            "cluster_bindings",
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
        )
    if not _has_unique_constraint(bind, "cluster_bindings", "uq_cluster_binding_triple"):
        op.create_unique_constraint(
            "uq_cluster_binding_triple",
            "cluster_bindings",
            ["user_id", "cluster_id", "namespace", "template"],
        )


def downgrade():
    bind = op.get_bind()

    # Reverse of the one-way extension (data loss is NOT undone).
    if _has_unique_constraint(bind, "cluster_bindings", "uq_cluster_binding_triple"):
        op.drop_constraint("uq_cluster_binding_triple", "cluster_bindings", type_="unique")
    cb_cols = _table_columns(bind, "cluster_bindings")
    if "namespace" in cb_cols:
        op.drop_index(op.f("ix_cluster_bindings_namespace"), table_name="cluster_bindings")
        op.drop_column("cluster_bindings", "namespace")
    if "template" in cb_cols:
        op.drop_column("cluster_bindings", "template")
    if "created_at" in cb_cols:
        op.drop_column("cluster_bindings", "created_at")

    # Drop the audit_log columns this revision added. Pre-existing columns
    # (id / action / whatever a legacy dev table carried) are left alone.
    audit_cols = _table_columns(bind, "audit_log")
    for col in ("at", "template", "namespace", "cluster", "target", "actor_sub"):
        if col in audit_cols:
            op.drop_column("audit_log", col)

    # Delete the seeded built-ins, then drop the table (guarded: if the
    # table pre-existed with user data on a dev DB, downgrade only removes
    # what this revision created).
    if sa.inspect(bind).has_table("rbac_templates"):
        bind.execute(
            sa.text("DELETE FROM rbac_templates WHERE builtin = TRUE AND created_by IS NULL")
        )
        op.drop_table("rbac_templates")
