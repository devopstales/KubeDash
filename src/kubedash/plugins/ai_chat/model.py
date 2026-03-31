#!/usr/bin/env python3
"""
Database models for AI Chat plugin.

Stores conversation history and messages for users.
"""

from datetime import datetime, timezone
from lib.components import db


class McpConversation(db.Model):
    """Conversation thread for AI chat."""

    __tablename__ = 'ai_chat_conversations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(255), nullable=True)  # Auto-generated from first message
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    messages = db.relationship(
        'McpMessage',
        backref='conversation',
        cascade='all, delete-orphan',
        lazy='dynamic'
    )

    def to_dict(self):
        """Convert conversation to dictionary."""
        try:
            message_count = self.messages.count()
        except Exception:
            message_count = 0
        return {
            'id': self.id,
            'user_id': self.user_id,
            'title': self.title,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'message_count': message_count
        }

    def __repr__(self):
        return f'<McpConversation {self.id} - User {self.user_id}>'


class McpMessage(db.Model):
    """Individual message in a conversation."""

    __tablename__ = 'ai_chat_messages'

    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(
        db.Integer,
        db.ForeignKey('ai_chat_conversations.id'),
        nullable=False
    )
    role = db.Column(db.String(50), nullable=False)  # 'user' or 'assistant'
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # Optional: store tool execution results
    tool_calls = db.Column(db.JSON, nullable=True)
    tool_results = db.Column(db.JSON, nullable=True)

    def to_dict(self):
        """Convert message to dictionary."""
        return {
            'id': self.id,
            'conversation_id': self.conversation_id,
            'role': self.role,
            'content': self.content,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'tool_calls': self.tool_calls,
            'tool_results': self.tool_results
        }

    def __repr__(self):
        return f'<McpMessage {self.id} - {self.role} in Conversation {self.conversation_id}>'
