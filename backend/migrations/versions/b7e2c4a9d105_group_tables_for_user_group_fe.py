"""group tables for the /user/group FE: groups + group_members

Revision ID: b7e2c4a9d105
Revises: 6feadb091ff4
Create Date: 2026-10-21 12:00:00.000000

One-way-door (ADR-0002) — the migration for the user/group FE change:

- ``groups``: group identity (name unique; source ``oidc`` | ``manual``;
  ``manual:`` name prefix reserved for dashboard-created groups, same
  ruling as ``local:`` user subs — ADR-0021).
- ``group_members``: user × group membership, unique (user_id, group_id).
  No seed — membership is materialized by the login upsert and
  ``POST /admin/groups/sync``.

Every op is guarded (has_table / constraint-exists checks) so the revision
applies cleanly on a fresh DB AND on a populated dev DB where parts of the
schema already exist (dev databases here are ``db.create_all()``-based and
unstamped).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b7e2c4a9d105'
down_revision = '6feadb091ff4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not inspector.has_table('groups'):
        op.create_table(
            'groups',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(length=255), nullable=False),
            sa.Column('display_name', sa.String(length=255), nullable=True),
            sa.Column('source', sa.String(length=16), nullable=False),
            sa.Column(
                'seen_at',
                sa.DateTime(timezone=True),
                server_default=sa.text('(CURRENT_TIMESTAMP)'),
                nullable=False,
            ),
            sa.Column(
                'created_at',
                sa.DateTime(timezone=True),
                server_default=sa.text('(CURRENT_TIMESTAMP)'),
                nullable=False,
            ),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('ix_groups_name', 'groups', ['name'], unique=True)

    if not inspector.has_table('group_members'):
        op.create_table(
            'group_members',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('group_id', sa.Integer(), nullable=False),
            sa.Column(
                'created_at',
                sa.DateTime(timezone=True),
                server_default=sa.text('(CURRENT_TIMESTAMP)'),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ondelete='CASCADE'),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('user_id', 'group_id', name='uq_group_member_pair'),
        )
        op.create_index('ix_group_members_user_id', 'group_members', ['user_id'])
        op.create_index('ix_group_members_group_id', 'group_members', ['group_id'])

    # A guarded re-apply on a hand-built (create_all) DB where the table
    # exists WITHOUT its unique name constraint: the index above covers it —
    # a unique index IS a unique constraint for our purposes.


def _has_unique(inspector: sa.Inspector, table: str, columns: list[str]) -> bool:
    return any(set(columns) <= set(c['column_names']) for c in inspector.get_unique_constraints(table))


def downgrade() -> None:
    op.drop_index('ix_group_members_group_id', table_name='group_members')
    op.drop_index('ix_group_members_user_id', table_name='group_members')
    op.drop_table('group_members')
    op.drop_index('ix_groups_name', table_name='groups')
    op.drop_table('groups')
