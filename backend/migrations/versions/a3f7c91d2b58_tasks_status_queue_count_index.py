"""tasks(status, enqueued_at) index — the ha-status queue count (W047)

Revision ID: a3f7c91d2b58
Revises: d3c8a1f09b47
Create Date: 2026-11-15 09:00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a3f7c91d2b58'
down_revision = 'd3c8a1f09b47'
branch_labels = None
depends_on = None


def upgrade():
    insp = sa.inspect(op.get_bind())
    # The ha-status endpoint polls
    #   SELECT status, count(*), min(enqueued_at) FROM tasks GROUP BY status
    # every 5 s, and the tasks table is never purged (W035). This composite
    # index serves that aggregation as an index-only scan. Retention
    # (delete-on-complete) remains the open ADR-0029 question (W035).
    existing = {i['name'] for i in insp.get_indexes('tasks')}
    if 'ix_tasks_status_enqueued_at' not in existing:
        op.create_index(
            'ix_tasks_status_enqueued_at', 'tasks', ['status', 'enqueued_at'],
            unique=False,
        )


def downgrade():
    op.drop_index('ix_tasks_status_enqueued_at', table_name='tasks')
