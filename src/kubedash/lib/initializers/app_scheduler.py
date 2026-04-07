#!/usr/bin/env python3
"""APScheduler initialization for KubeDash."""

from typing import Optional
from flask import Flask


def get_scheduler(app: Flask) -> Optional[object]:
    """Get the APScheduler instance from the app.

    Args:
        app: Flask application instance

    Returns:
        APScheduler instance or None if not configured
    """
    # Return the scheduler if it exists on the app
    return getattr(app, 'scheduler', None)