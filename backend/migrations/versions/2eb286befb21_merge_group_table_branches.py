"""merge the two group-table branches into a single head

Revision ID: 2eb286befb21
Revises: 8b2c4d5e6f7a, b7e2c4a9d105
Create Date: 2026-10-26 12:00:00.000000

The group-table work diverged into two parallel branches off 6feadb091ff4
(local-admin auth): 8b2c4d5e6f7a (TASK-026 admin-managed groups: ``groups`` +
``user_groups``) and b7e2c4a9d105 (user/group FE: ``groups`` + ``group_members``).
Two heads broke ``flask db upgrade`` (it can only target a single head).

This merge revision joins them. It carries no ops of its own: both branches
are has_table-guarded, so on any DB shape each branch's ops apply exactly
once (a table created by the branch applied first is skipped by the other).
``group_members`` is the live membership table (app/models/group.py);
``user_groups`` is what 8b2c4d5e6f7a created for the TASK-026 branch — the
guarded no-op is acceptable because no ORM model maps ``user_groups``
anymore, so it is only (re)created on DBs that never had the TASK-026 branch.
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '2eb286befb21'
down_revision = ('8b2c4d5e6f7a', 'b7e2c4a9d105')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
