"""
MCP Integration plugin: persistence models for chat conversations and messages.
"""

from datetime import datetime, timezone

from lib.components import db


class McpConversation(db.Model):
    """One chat conversation per user. Created when the user sends the first message."""

    __tablename__ = "mcp_conversations"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    messages = db.relationship("McpMessage", backref="conversation", lazy="dynamic", order_by="McpMessage.created_at", cascade="all, delete-orphan")


class McpMessage(db.Model):
    """One message in a conversation (user or assistant)."""

    __tablename__ = "mcp_messages"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey("mcp_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    role = db.Column(db.String(20), nullable=False)  # "user" | "assistant"
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
