"""registry table

Revision ID: 5598d31e675a
Revises: d0be67da4314
Create Date: 2023-04-12 20:38:27.620672

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5598d31e675a'
down_revision = 'd0be67da4314'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('registry',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('registry_server_url', sa.Text(), nullable=False),
    sa.Column('registry_server_port', sa.Text(), nullable=False),
    sa.Column('registry_server_auth', sa.Boolean(), nullable=False),
    sa.Column('registry_server_tls', sa.Boolean(), nullable=False),
    sa.Column('insecure_tls', sa.Boolean(), nullable=False),
    sa.Column('registry_server_auth_token', sa.String(length=80), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('registry_server_url')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('registry')
    # ### end Alembic commands ###
