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

    if app.config['DEBUG']:
        app.logger.setLevel(logging.DEBUG)
        logging.getLogger("werkzeug").setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)
        logging.getLogger("werkzeug").addFilter(NoMetrics())
        logging.getLogger("werkzeug").addFilter(NoHealth())
        logging.getLogger("werkzeug").addFilter(NoPing())
        logging.getLogger("werkzeug").addFilter(NoSocketIoGet())
        logging.getLogger("werkzeug").addFilter(NoSocketIoPost())
