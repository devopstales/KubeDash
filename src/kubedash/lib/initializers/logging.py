#!/usr/bin/env python3
"""Logging initialization for KubeDash."""

import sys
import logging
from flask import Flask


def initialize_app_logging(app: Flask):
    """Initialize Flask app logging
    Args:
        app (Flask): Flask app object
    """
    from lib.logfilters import (NoHealth, NoMetrics, NoPing, NoSocketIoGet,
                                NoSocketIoPost)
    from lib.helper_functions import get_logger

    logger = get_logger()

    if sys.argv[1] != 'cli' and sys.argv[1] != 'db':
        app.logger.info("Initialize logging")

    # Use INFO in all modes (development and production). DEBUG is only for Flask (e.g. tracebacks).
    app.logger.setLevel(logging.INFO)
    logging.getLogger("werkzeug").addFilter(NoMetrics())
    logging.getLogger("werkzeug").addFilter(NoHealth())
    logging.getLogger("werkzeug").addFilter(NoPing())
    logging.getLogger("werkzeug").addFilter(NoSocketIoGet())
    logging.getLogger("werkzeug").addFilter(NoSocketIoPost())

    # Reduce noise from third-party libs (MCP client, httpx)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("mcp.client.streamable_http").setLevel(logging.WARNING)
