"""merge the queue/revocation branch and the kubectl-config branch

Revision ID: d3c8a1f09b47
Revises: 0e969d3c2e02, 4f7a2c9d3e18
Create Date: 2026-11-08 09:00:00.000000

The branches diverged into two heads off 2eb286befb21 (group-table merge):
0e969d3c2e02 (queue/revocation/kv + leader_lease.fence, ADR-0029/0030/0031)
and 4f7a2c9d3e18 (kubectl_config table + ca_local_user 4.1 parity). Two
heads break ``flask db upgrade`` (it can only target a single head).

This merge revision joins them. It carries no ops of its own: both branches
are has_table-guarded, so on any DB shape each branch's ops apply exactly
once (a table created by the branch applied first is skipped by the other).
"""

# revision identifiers, used by Alembic.
revision = 'd3c8a1f09b47'
down_revision = ('0e969d3c2e02', '4f7a2c9d3e18')
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
