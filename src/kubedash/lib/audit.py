#!/usr/bin/env python3
"""Audit logging for KubeDash (Logging PRD Phase 3).

Records user actions (login, logout, user/privilege changes, destructive operations)
in canonical or JSON format. Writes are non-blocking (queue + background thread).
"""

import json
import logging
import os
import queue
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from lib.components import db
from lib.helper_functions import _get_logging_config, get_logger

logger = get_logger()

# In-memory queue for non-blocking audit writes (max size to avoid unbounded growth)
_AUDIT_QUEUE: Optional[queue.Queue] = None
_AUDIT_WORKER: Optional[threading.Thread] = None
_AUDIT_APP = None
_AUDIT_QUEUE_MAXSIZE = 10000
_AUDIT_ENABLED = True


def _audit_worker(app):
    """Background thread: consume audit events from queue and write to DB (with app context)."""
    from lib.audit import AuditLog
    while True:
        try:
            event = _AUDIT_QUEUE.get()
            if event is None:
                break
            try:
                with app.app_context():
                    AuditLog.write_event(event)
            except Exception as e:
                logger.error("Audit write failed: %s", e, exc_info=True)
            finally:
                _AUDIT_QUEUE.task_done()
        except Exception as e:
            logger.error("Audit worker error: %s", e, exc_info=True)


def _start_audit_worker(app):
    global _AUDIT_WORKER
    if _AUDIT_WORKER is not None:
        return
    _AUDIT_WORKER = threading.Thread(target=_audit_worker, args=(app,), daemon=True)
    _AUDIT_WORKER.start()
    logger.info("Audit worker started (non-blocking writes to audit_log)")


def log_audit_event(
    user_id: str,
    action: str,
    resource: str,
    result: str,
    trace_id: Optional[str] = None,
    details: Optional[dict] = None,
    **extra: Any,
) -> None:
    """Emit an audit event (non-blocking). Uses same canonical/JSON format with event_type=audit.

    Args:
        user_id: User identifier (username or id).
        action: Action performed (e.g. login, logout, user_create, delete_conversation).
        resource: Affected resource (e.g. session, user, conversation, namespace).
        result: Outcome (success, failure, denied).
        trace_id: Request correlation ID if in request context.
        details: Optional dict of extra fields for compliance.
        **extra: Additional key/values for the audit record.
    """
    if not _AUDIT_ENABLED:
        return
    if _AUDIT_QUEUE is None:
        return
    if _AUDIT_QUEUE.qsize() >= _AUDIT_QUEUE_MAXSIZE:
        logger.warning("Audit queue full, dropping event action=%s resource=%s", action, resource)
        return
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%d %H:%M:%S") + ".%03d" % (now.microsecond // 1000,)
    ts_iso = now.strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % (now.microsecond // 1000,)
    event = {
        "event_type": "audit",
        "audit": True,
        "timestamp": ts_iso,
        "trace_id": trace_id or "no-id",
        "user_id": str(user_id),
        "action": action,
        "resource": resource,
        "result": result,
        "details": details or {},
        **{k: v for k, v in extra.items() if v is not None},
    }
    try:
        _AUDIT_QUEUE.put_nowait(event)
    except queue.Full:
        logger.warning("Audit queue full, dropping event action=%s", action)


def init_audit(app) -> None:
    """Initialize audit subsystem: create queue and start background worker. Call from app factory."""
    global _AUDIT_QUEUE, _AUDIT_ENABLED
    ini = app.config.get("kubedash.ini")
    if ini and ini.has_section("audit"):
        _AUDIT_ENABLED = ini.get("audit", "enabled", fallback="true").strip().lower() in ("true", "1", "yes")
    if not _AUDIT_ENABLED:
        return
    _AUDIT_QUEUE = queue.Queue(maxsize=_AUDIT_QUEUE_MAXSIZE)
    _start_audit_worker(app)


def shutdown_audit() -> None:
    """Signal audit worker to stop (send sentinel). Call on app teardown if needed."""
    global _AUDIT_QUEUE, _AUDIT_WORKER
    if _AUDIT_QUEUE is not None:
        try:
            _AUDIT_QUEUE.put(None)
        except Exception:
            pass
    _AUDIT_QUEUE = None
    _AUDIT_WORKER = None


class AuditLog(db.Model):
    """Persistent audit log table for query/export (compliance)."""

    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False)
    trace_id = db.Column(db.String(64), nullable=True)
    user_id = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(64), nullable=False)
    resource = db.Column(db.String(255), nullable=False)
    result = db.Column(db.String(32), nullable=False)
    details = db.Column(db.JSON, nullable=True)
    message = db.Column(db.Text, nullable=True)

    @classmethod
    def write_event(cls, event: dict) -> None:
        from datetime import datetime
        ts = event.get("timestamp")
        if isinstance(ts, str) and "T" in ts:
            try:
                created_at = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                created_at = datetime.now(timezone.utc)
        else:
            created_at = datetime.now(timezone.utc)
        entry = cls(
            created_at=created_at,
            trace_id=event.get("trace_id"),
            user_id=event.get("user_id", ""),
            action=event.get("action", ""),
            resource=event.get("resource", ""),
            result=event.get("result", ""),
            details=event.get("details"),
            message=event.get("message"),
        )
        db.session.add(entry)
        db.session.commit()
