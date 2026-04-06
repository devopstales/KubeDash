#!/usr/bin/env python3
"""Session backend configuration for KubeDash."""

import os
import tempfile
from typing import Optional

from flask import Flask

from lib.prometheus import METRIC_SESSION_OPERATIONS, METRIC_SESSION_REDIS_ERRORS


def _build_redis_url_from_ini(app: Flask) -> Optional[str]:
    ini = app.config.get('kubedash.ini')
    if ini is None:
        return None

    redis_enabled = ini.get('remote_cache', 'redis_enabled', fallback='false').lower() == 'true'
    if not redis_enabled:
        return None

    redis_host = ini.get('remote_cache', 'redis_host', fallback='127.0.0.1')
    redis_port = ini.get('remote_cache', 'redis_port', fallback='6379')
    redis_db = ini.get('remote_cache', 'redis_db', fallback='0')
    redis_password = ini.get('remote_cache', 'redis_password', fallback=None) or None
    redis_ssl = ini.get('remote_cache', 'redis_ssl', fallback='false').lower() == 'true'

    if ':' in redis_host and not redis_host.startswith('['):
        redis_host, maybe_port = redis_host.rsplit(':', 1)
        if maybe_port.isdigit():
            redis_port = maybe_port

    scheme = 'rediss' if redis_ssl else 'redis'
    if redis_password:
        return f"{scheme}://:{redis_password}@{redis_host}:{redis_port}/{redis_db}"
    return f"{scheme}://{redis_host}:{redis_port}/{redis_db}"


def get_session_redis_url(app: Flask) -> Optional[str]:
    env_url = os.environ.get('SESSION_REDIS_URL')
    if env_url:
        return env_url
    return _build_redis_url_from_ini(app)


def configure_session_backend(app: Flask):
    """Configure the Flask-Session backend for KubeDash."""
    METRIC_SESSION_OPERATIONS.labels(operation='configure').inc()
    app.logger.info("Configuring session backend")
    app.config.setdefault('SESSION_KEY_PREFIX', 'kubedash:session:')
    app.config.setdefault('SESSION_FILE_DIR', os.path.join(tempfile.gettempdir(), 'kubedash-sessions'))
    app.config.setdefault('SESSION_PERMANENT', False)
    app.config.setdefault('SESSION_USE_SIGNER', True)

    session_redis_url = app.config.get('SESSION_REDIS_URL') or get_session_redis_url(app)
    if session_redis_url:
        app.config['SESSION_TYPE'] = 'redis'
        app.config['SESSION_REDIS_URL'] = session_redis_url
        app.logger.info(f"Attempting Redis session backend at {session_redis_url}")
        try:
            from redis import from_url

            redis_client = from_url(
                session_redis_url,
                decode_responses=False,  # Session data is pickled (binary)
                socket_connect_timeout=3,
                socket_timeout=3,
            )
            redis_client.ping()
            app.config['SESSION_REDIS'] = redis_client
            app.logger.info("Redis session backend configured successfully")
        except Exception as exc:
            METRIC_SESSION_REDIS_ERRORS.labels(operation='configure').inc()
            app.logger.warning(
                "Redis session backend unavailable: %s. Falling back to filesystem sessions.",
                exc,
            )
            app.config['SESSION_TYPE'] = 'filesystem'
            app.config['SESSION_REDIS'] = None
            app.config['SESSION_FILE_DIR'] = os.environ.get(
                'SESSION_FILE_DIR', app.config['SESSION_FILE_DIR']
            )
            app.config['SESSION_KEY_PREFIX'] = 'kubedash:session:'
            app.logger.warning(
                "Using filesystem sessions as fallback. This is not shared across replicas."
            )
    else:
        METRIC_SESSION_OPERATIONS.labels(operation='configure_sqlalchemy').inc()
        app.config['SESSION_TYPE'] = 'sqlalchemy'
        app.logger.info("Using SQLAlchemy session backend")
