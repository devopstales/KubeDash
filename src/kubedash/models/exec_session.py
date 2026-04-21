"""
SQLAlchemy models for exec session recording and audit.

Defines:
- ExecSession: Records individual exec sessions with metadata
- ExecSessionEvent: Stores I/O events for session replay
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, BigInteger, Float, Text, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from lib.components import db


class ExecSession(db.Model):
    """
    Represents a single pod exec session.
    
    Tracks user, namespace, pod, container, timing, and exit status.
    Used for audit trail and session replay.
    """
    __tablename__ = 'exec_sessions'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    namespace = Column(String(255), nullable=False)
    pod = Column(String(255), nullable=False)
    container = Column(String(255), nullable=False)
    start_time = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    end_time = Column(DateTime(timezone=True), nullable=True)
    duration_ms = Column(BigInteger, nullable=True)
    exit_status = Column(
        String(50),
        nullable=True,
        comment='normal, timeout, error, user-disconnect, connection-lost'
    )
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    events = relationship('ExecSessionEvent', back_populates='session', cascade='all, delete-orphan', lazy='dynamic')

    def to_dict(self, include_events=False):
        """Serialize to dictionary for API responses."""
        data = {
            'id': str(self.id),
            'user_id': self.user_id,
            'namespace': self.namespace,
            'pod': self.pod,
            'container': self.container,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_ms': self.duration_ms,
            'exit_status': self.exit_status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        if include_events:
            data['event_count'] = self.events.count()
        return data

    def finalize(self, exit_status='normal'):
        """Mark session as ended with given exit status."""
        self.end_time = datetime.now(timezone.utc)
        self.exit_status = exit_status
        if self.start_time:
            self.duration_ms = int((self.end_time - self.start_time).total_seconds() * 1000)


class ExecSessionEvent(db.Model):
    """
    Stores individual I/O events for an exec session.
    
    Used for session replay and audit.
    Events are ordered by timestamp (relative seconds from session start).
    """
    __tablename__ = 'exec_session_events'

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    session_id = Column(UUID(as_uuid=True), ForeignKey('exec_sessions.id', ondelete='CASCADE'), nullable=False, index=True)
    timestamp = Column(Float, nullable=False, comment='Seconds from session start')
    event_type = Column(String(10), nullable=False, comment='input or output')
    data = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    session = relationship('ExecSession', back_populates='events')

    def to_dict(self):
        """Serialize to dictionary for API responses."""
        return {
            'id': self.id,
            'session_id': str(self.session_id),
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'data': self.data
        }


# Indexes for performance
Index('ix_exec_sessions_user_id', ExecSession.user_id)
Index('ix_exec_sessions_start_time', ExecSession.start_time.desc())
Index('ix_exec_session_events_session_id', ExecSessionEvent.session_id)
