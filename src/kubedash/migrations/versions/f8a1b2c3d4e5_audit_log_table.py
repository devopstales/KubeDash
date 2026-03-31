"""add: audit_log table

Revision ID: f8a1b2c3d4e5
Revises: 51362c3e6384
Create Date: 2026-03-11

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision = 'f8a1b2c3d4e5'
down_revision = '51362c3e6384'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    if not inspect(conn).has_table("audit_log"):
        op.create_table(
            'audit_log',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('trace_id', sa.String(length=64), nullable=True),
            sa.Column('user_id', sa.String(length=255), nullable=False),
            sa.Column('action', sa.String(length=64), nullable=False),
            sa.Column('resource', sa.String(length=255), nullable=False),
            sa.Column('result', sa.String(length=32), nullable=False),
            sa.Column('details', sa.JSON(), nullable=True),
            sa.Column('message', sa.Text(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )


def downgrade():
    conn = op.get_bind()
    if inspect(conn).has_table("audit_log"):
        op.drop_table('audit_log')
