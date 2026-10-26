"""local admin auth (ADR-0021): users.password_hash + auth_source + uq_users_email

Revision ID: 6feadb091ff4
Revises: 704b7637d05c
Create Date: 2026-10-18 10:34:07.228263

Additive + reversible (OD-A): the columns back ADR-0021's local password
mode; auth_source NOT NULL DEFAULT 'oidc' declares existing SSO rows
honestly. uq_users_email (C-NEW-1) is REQUIRED by the bootstrap hook's
ON CONFLICT (email) upsert — without a matching unique index Postgres
rejects the statement — and it backstops the OIDC path where two IdP
subs can share an email.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6feadb091ff4'
down_revision = '704b7637d05c'
branch_labels = None
depends_on = None


def upgrade():
    # Guarded: a create_all-era dev DB (healed via stamp base + upgrade)
    # already carries these columns/constraint.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    cols = {c['name'] for c in inspector.get_columns('users')}
    uniques = {
        frozenset(c['column_names'])
        for c in inspector.get_unique_constraints('users')
    }

    if 'password_hash' not in cols:
        op.add_column('users', sa.Column('password_hash', sa.String(length=255), nullable=True))
    if 'auth_source' not in cols:
        op.add_column('users', sa.Column('auth_source', sa.String(length=16), nullable=False, server_default='oidc'))
    if frozenset(['email']) not in uniques:
        op.create_unique_constraint('uq_users_email', 'users', ['email'])


def downgrade():
    op.drop_constraint('uq_users_email', 'users', type_='unique')
    op.drop_column('users', 'auth_source')
    op.drop_column('users', 'password_hash')
