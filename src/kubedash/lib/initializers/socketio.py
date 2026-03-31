#!/usr/bin/env python3
"""Socket.IO initialization for KubeDash."""

from flask import Flask


def initialize_app_socket(app: Flask):
    """Initialize socketIO"""
    from lib.components import socketio, set_flask_app

    app.logger.info("Initialize SocketIO")
    socketio.init_app(app)
    # Store app reference for use in background threads
    set_flask_app(app)
