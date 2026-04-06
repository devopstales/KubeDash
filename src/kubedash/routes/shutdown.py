"""
Shutdown API endpoints for graceful termination.
"""

from flask import Blueprint, current_app, jsonify
from lib.shutdown import get_graceful_shutdown
import logging
import threading

logger = logging.getLogger(__name__)

shutdown_bp = Blueprint("shutdown", __name__, url_prefix="/api")


@shutdown_bp.route("/shutdown", methods=["POST"])
def initiate_shutdown():
    """
    Graceful shutdown endpoint
    Called by Kubernetes preStop hook during pod termination

    Returns 200 immediately, runs shutdown in background thread
    to allow response to be sent before termination
    """

    graceful_shutdown = get_graceful_shutdown()

    if not graceful_shutdown:
        return {"error": "Graceful shutdown not initialized"}, 500

    logger.warning("Shutdown endpoint called")

    # Run shutdown in background thread to return immediately
    shutdown_thread = threading.Thread(
        target=graceful_shutdown.shutdown,
        args=(28,),  # 28 second timeout (leave 2s buffer)
        kwargs={"reason": "api"},
        daemon=False,
    )
    shutdown_thread.start()

    return {"status": "shutting_down"}, 200


@shutdown_bp.route("/health/ready", methods=["GET"])
def readiness_probe():
    """
    Readiness probe endpoint
    
    Returns 200 when pod is ready to accept requests
    Returns 503 during shutdown or if unhealthy
    """

    graceful_shutdown = get_graceful_shutdown()

    if graceful_shutdown and graceful_shutdown.is_shutting_down():
        return (
            {"status": "not_ready", "reason": "shutting_down"},
            503,
        )

    # Check database connectivity
    try:
        from sqlalchemy import text
        current_app.db.session.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Database not ready: {e}")
        return {"status": "not_ready", "reason": "database_error"}, 503

    return {"status": "ready"}, 200


@shutdown_bp.route("/health/live", methods=["GET"])
def liveness_probe():
    """
    Liveness probe endpoint
    
    Returns 200 if process is alive
    (Does not check health, only if process exists)
    """
    return {"status": "alive"}, 200
