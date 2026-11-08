"""queue + revocation + kv tables, leader_lease.fence (ADR-0029/0030/0031)

Revision ID: 0e969d3c2e02
Revises: 2eb286befb21
Create Date: 2026-10-27 20:29:34

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0e969d3c2e02'
down_revision = '2eb286befb21'
branch_labels = None
depends_on = None


def upgrade():
    insp = sa.inspect(op.get_bind())
    # Guarded: a create_all-era dev DB (healed via stamp base + upgrade)
    # already has leader_lease.
    if not insp.has_table('tasks'):
        # Plain (non-partial) index: now() is STABLE, not IMMUTABLE, so a
        # partial WHERE available_at > now() is invalid (findings #2).
        op.create_table('tasks',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('path', sa.Text(), nullable=False),
        sa.Column('status', sa.Text(), server_default='pending', nullable=False),
        sa.Column('attempts', sa.Integer(), server_default='0', nullable=False),
        sa.Column('enqueued_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('locked_by', sa.Text(), nullable=True),
        sa.Column('available_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
        )
        op.create_index('tasks_pending_idx', 'tasks', ['enqueued_at'], unique=False)
    if not insp.has_table('revoked_jtis'):
        op.create_table('revoked_jtis',
        sa.Column('jti', sa.Uuid(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('jti')
        )
    if not insp.has_table('kv'):
        # Plain (non-partial) index, same now() reason as tasks.
        op.create_table('kv',
        sa.Column('key', sa.Text(), nullable=False),
        sa.Column('value', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('key')
        )
        op.create_index('kv_expires_idx', 'kv', ['expires_at'], unique=False)
    # A create_all-era dev DB already has leader_lease, but not fence yet.
    if 'fence' not in [c['name'] for c in insp.get_columns('leader_lease')]:
        op.add_column('leader_lease',
        sa.Column('fence', sa.Integer(), server_default='0', nullable=False))


def downgrade():
    insp = sa.inspect(op.get_bind())
    if 'fence' in [c['name'] for c in insp.get_columns('leader_lease')]:
        op.drop_column('leader_lease', 'fence')
    if insp.has_table('kv'):
        op.drop_index('kv_expires_idx', table_name='kv')
        op.drop_table('kv')
    if insp.has_table('revoked_jtis'):
        op.drop_table('revoked_jtis')
    if insp.has_table('tasks'):
        op.drop_index('tasks_pending_idx', table_name='tasks')
        op.drop_table('tasks')
