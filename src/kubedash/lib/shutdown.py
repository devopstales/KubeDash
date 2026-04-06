"""
Graceful shutdown handler for KubeDash multi-replica deployment.

Handles:
- SIGTERM signal catching
- Leadership release (if leader in multi-replica mode)
- Request draining
- APScheduler graceful shutdown
- Session cleanup
- Database connection cleanup
"""

import signal
import sys
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Optional, Callable, List
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class GracefulShutdown:
    """Manage graceful shutdown of KubeDash application"""

    STATE_RUNNING = "running"
    STATE_SHUTTING_DOWN = "shutting_down"
    STATE_TERMINATED = "terminated"

    def __init__(
        self,
        app,
        db,
        scheduler=None,
        leader_elector=None,
    ):
        self.app = app
        self.db = db
        self.scheduler = scheduler
        self.leader_elector = leader_elector

        # State management
        self.state = self.STATE_RUNNING
        self.start_time = None
        self.end_time = None

        # Request tracking
        self.in_flight_requests = 0
        self._request_lock = threading.RLock()

        # Shutdown handlers
        self.handlers: List[tuple] = []
        self.handlers_lock = threading.RLock()

    def setup_signals(self, timeout_seconds: int = 30):
        """Setup signal handlers for graceful shutdown"""

        def handle_signal(signum, frame):
            signal_name = signal.Signals(signum).name
            logger.warning(
                f"Received {signal_name} signal. Initiating graceful shutdown..."
            )
            self.shutdown(timeout_seconds=timeout_seconds)

        signal.signal(signal.SIGTERM, handle_signal)
        signal.signal(signal.SIGINT, handle_signal)

    def register_handler(self, handler: Callable, name: Optional[str] = None):
        """Register a shutdown handler"""
        with self.handlers_lock:
            self.handlers.append((handler, name or handler.__name__))

    def shutdown(self, timeout_seconds: int = 30, reason: str = "sigterm"):
        """Execute graceful shutdown"""

        # Prevent multiple concurrent shutdowns
        if self.state != self.STATE_RUNNING:
            logger.warning(f"Shutdown already in progress (state={self.state})")
            return

        self.state = self.STATE_SHUTTING_DOWN
        self.start_time = datetime.utcnow()

        logger.info(
            f"Starting graceful shutdown (timeout={timeout_seconds}s, reason={reason})"
        )

        # Run all shutdown phases in order
        phases = [
            ("release_leadership", self._release_leadership),
            ("stop_requests", self._stop_accepting_requests),
            ("drain_requests", self._drain_in_flight_requests),
            ("stop_scheduler", self._stop_scheduler),
            ("run_handlers", self._run_shutdown_handlers),
            ("close_database", self._close_database),
        ]

        for phase_name, phase_func in phases:
            try:
                phase_func()
            except Exception as e:
                logger.error(f"  Error in {phase_name}: {e}")

        self.state = self.STATE_TERMINATED
        self.end_time = datetime.utcnow()

        duration = (self.end_time - self.start_time).total_seconds()
        logger.info(f"Graceful shutdown completed in {duration:.1f}s")

    def _release_leadership(self):
        """Phase 1: Release leadership (multi-replica only)"""
        if not self.leader_elector or not self.leader_elector.is_leader:
            return

        try:
            self.leader_elector.stop()
        except Exception as e:
            logger.error(f"Error releasing leadership: {e}")

    def _stop_accepting_requests(self):
        """Phase 2: Stop accepting new requests"""
        self.app.config["SHUTTING_DOWN"] = True

    def _drain_in_flight_requests(self):
        """Phase 3: Wait for in-flight requests to complete"""
        deadline_seconds = 20
        deadline = datetime.utcnow() + timedelta(seconds=deadline_seconds)

        last_count = self.in_flight_requests
        stable_count = 0

        while True:
            current_count = self.in_flight_requests
            remaining = (deadline - datetime.utcnow()).total_seconds()

            if remaining <= 0:
                if current_count > 0:
                    logger.warning(f"Timeout: {current_count} requests still in-flight")
                break

            if current_count == 0:
                break

            if current_count == last_count:
                stable_count += 1
                if stable_count > 5:
                    logger.warning(f"Requests stuck at {current_count}, continuing")
                    break
            else:
                stable_count = 0

            last_count = current_count
            threading.Event().wait(0.5)

    def _stop_scheduler(self):
        """Phase 4: Stop APScheduler"""
        if not self.scheduler or not self.scheduler.running:
            return

        try:
            self.scheduler.shutdown(wait=True)
        except Exception as e:
            logger.error(f"Error stopping scheduler: {e}")

    def _run_shutdown_handlers(self):
        """Phase 5: Run registered shutdown handlers"""
        with self.handlers_lock:
            if not self.handlers:
                return

            for handler, name in self.handlers:
                try:
                    handler()
                except Exception as e:
                    logger.error(f"Error in handler {name}: {e}")

    def _close_database(self):
        """Phase 6: Close database connections"""
        if not self.db:
            return

        try:
            with self.app.app_context():
                self.db.engine.dispose()
        except Exception as e:
            logger.error(f"Error disposing database: {e}")

    def track_request(self) -> bool:
        """
        Track an incoming request.
        Returns True if request should proceed, False if shutting down.
        """
        with self._request_lock:
            if self.state != self.STATE_RUNNING:
                return False
            self.in_flight_requests += 1
        return True

    def complete_request(self):
        """Mark a request as completed"""
        with self._request_lock:
            self.in_flight_requests = max(0, self.in_flight_requests - 1)

    @contextmanager
    def track_request_context(self):
        """Context manager for tracking request duration"""
        if not self.track_request():
            raise RuntimeError("Application is shutting down")

        try:
            yield
        finally:
            self.complete_request()

    def is_shutting_down(self) -> bool:
        """Check if application is shutting down"""
        return self.state != self.STATE_RUNNING

    def get_status(self) -> dict:
        """Get shutdown status"""
        return {
            "state": self.state,
            "in_flight_requests": self.in_flight_requests,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else None,
        }


# Global instance
_graceful_shutdown: Optional[GracefulShutdown] = None


def init_graceful_shutdown(app, db, scheduler=None, leader_elector=None) -> GracefulShutdown:
    """Initialize global graceful shutdown"""
    global _graceful_shutdown

    _graceful_shutdown = GracefulShutdown(app, db, scheduler, leader_elector)
    _graceful_shutdown.setup_signals()

    return _graceful_shutdown


def get_graceful_shutdown() -> Optional[GracefulShutdown]:
    """Get global graceful shutdown instance"""
    return _graceful_shutdown
