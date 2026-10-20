"""admin-managed groups: groups + user_groups tables (TASK-026)

Revision ID: 8b2c4d5e6f7a
Revises: 3c9f21a7d5b4
Create Date: 2026-10-20 19:30:00.000000

The ``/groups`` admin surface stores groups as first-class rows (the 5.0
analogue of the legacy ``sso_groups`` / ``sso_user_group_mapping`` tables):
an admin creates a group and assigns users to it via the UI. OIDC ``groups``
claims remain a second, merged-at-read source in the admin API.

Guarded like every other revision here (has_table checks) so the revision
applies cleanly on a fresh DB and on a create_all-era dev DB (the dev loop
is migration-managed, TASK-025 — but the guards keep the revision safe on
any shape, matching 3c9f21a7d5b4's pattern).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8b2c4d5e6f7a'
down_revision = '3c9f21a7d5b4'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()

    if not sa.inspect(bind).has_table("groups"):
        op.create_table(
            "groups",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )
        op.create_index(op.f("ix_groups_name"), "groups", ["name"], unique=True)

    if not sa.inspect(bind).has_table("user_groups"):
        op.create_table(
            "user_groups",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("group_id", sa.Integer(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["group_id"], ["groups.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("user_id", "group_id", name="uq_user_group_pair"),
        )
        op.create_index(op.f("ix_user_groups_user_id"), "user_groups", ["user_id"], unique=False)
        op.create_index(op.f("ix_user_groups_group_id"), "user_groups", ["group_id"], unique=False)


def downgrade():
    bind = op.get_bind()

    if sa.inspect(bind).has_table("user_groups"):
        op.drop_index(op.f("ix_user_groups_group_id"), table_name="user_groups")
        op.drop_index(op.f("ix_user_groups_user_id"), table_name="user_groups")
        op.drop_table("user_groups")
    if sa.inspect(bind).has_table("groups"):
        op.drop_index(op.f("ix_groups_name"), table_name="groups")
        op.drop_table("groups")
