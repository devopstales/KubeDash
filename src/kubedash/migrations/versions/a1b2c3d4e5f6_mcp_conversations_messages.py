"""mcp_conversations and mcp_messages tables for MCP chat persistence

Revision ID: a1b2c3d4e5f6
Revises: ea51eddbcfb6
Create Date: 2026-02-20

"""
from alembic import op
import sqlalchemy as sa


revision = "a1b2c3d4e5f6"
down_revision = "ea51eddbcfb6"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "mcp_conversations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_mcp_conversations_user_id"), "mcp_conversations", ["user_id"], unique=False)

    op.create_table(
        "mcp_messages",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("conversation_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["conversation_id"], ["mcp_conversations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_mcp_messages_conversation_id"), "mcp_messages", ["conversation_id"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_mcp_messages_conversation_id"), table_name="mcp_messages")
    op.drop_table("mcp_messages")
    op.drop_index(op.f("ix_mcp_conversations_user_id"), table_name="mcp_conversations")
    op.drop_table("mcp_conversations")
