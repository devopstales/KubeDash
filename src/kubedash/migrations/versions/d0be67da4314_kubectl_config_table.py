"""kubectl_config table

Revision ID: d0be67da4314
Revises: 7253f5a7bfda
Create Date: 2023-03-14 15:49:02.495648

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd0be67da4314'
down_revision = '7253f5a7bfda'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('k8s_cluster_config',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('k8s_server_url', sa.Text(), nullable=False),
    sa.Column('k8s_context', sa.Text(), nullable=False),
    sa.Column('k8s_server_ca', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('k8s_context'),
    sa.UniqueConstraint('k8s_server_url')
    )
    op.create_table('kubectl_config',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=50), server_default='', nullable=False),
    sa.Column('cluster', sa.String(length=50), server_default='', nullable=False),
    sa.Column('private_key', sa.Text(), nullable=True),
    sa.Column('user_certificate', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users_kubectl',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['kubectl_config.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('k8s_config')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('k8s_config',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('k8s_server_url', sa.TEXT(), nullable=False),
    sa.Column('k8s_context', sa.TEXT(), nullable=False),
    sa.Column('k8s_server_ca', sa.TEXT(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('k8s_context'),
    sa.UniqueConstraint('k8s_server_url')
    )
    op.drop_table('users_kubectl')
    op.drop_table('kubectl_config')
    op.drop_table('k8s_cluster_config')
    # ### end Alembic commands ###