#!/usr/bin/env python3
"""Replica mode detection and validation for KubeDash."""

import os
from typing import Optional
from flask import Flask

from lib.prometheus import METRIC_REPLICA_MODE_INFO, METRIC_REPLICA_DESIRED

VALID_REPLICA_MODES = {"single", "cluster"}
DEFAULT_REPLICA_MODE = "single"
DEFAULT_REPLICA_COUNT = 1


def _get_ini_value(app: Flask, section: str, option: str, fallback: Optional[str] = None) -> Optional[str]:
    ini = app.config.get('kubedash.ini')
    if ini is None:
        return fallback
    return ini.get(section, option, fallback=fallback)


def get_replica_mode(app: Flask) -> str:
    """Resolve replica mode from environment or configuration."""
    mode = os.environ.get('REPLICA_MODE')
    if not mode:
        mode = app.config.get('REPLICA_MODE')
    if not mode:
        mode = _get_ini_value(app, 'remote_cache', 'replica_mode', fallback=DEFAULT_REPLICA_MODE)
    mode = (mode or DEFAULT_REPLICA_MODE).strip().lower()
    if mode not in VALID_REPLICA_MODES:
        app.logger.warning(
            "Invalid REPLICA_MODE '%s' detected; falling back to '%s'",
            mode,
            DEFAULT_REPLICA_MODE,
        )
        return DEFAULT_REPLICA_MODE
    return mode


def get_replica_count(app: Flask) -> int:
    """Resolve replica count from environment or configuration."""
    count = os.environ.get('REPLICA_COUNT')
    if count is None:
        count = app.config.get('REPLICA_COUNT')
    if count is None:
        count = _get_ini_value(app, 'remote_cache', 'replica_count', fallback=str(DEFAULT_REPLICA_COUNT))
    try:
        return max(int(count), DEFAULT_REPLICA_COUNT)
    except (ValueError, TypeError):
        app.logger.warning(
            "Invalid REPLICA_COUNT '%s' detected; falling back to %d",
            count,
            DEFAULT_REPLICA_COUNT,
        )
        return DEFAULT_REPLICA_COUNT


def get_pod_identity(app: Flask) -> str:
    """Get the local pod identity from downward API or hostname."""
    return (
        os.environ.get('POD_NAME')
        or app.config.get('POD_NAME')
        or os.environ.get('HOSTNAME')
        or os.uname().nodename
    )


def get_pod_namespace(app: Flask) -> str:
    """Get the local pod namespace from downward API or default to 'default'."""
    return (
        os.environ.get('POD_NAMESPACE')
        or app.config.get('POD_NAMESPACE')
        or _get_ini_value(app, 'remote_cache', 'pod_namespace', fallback='default')
    )


def _is_redis_enabled(app: Flask) -> bool:
    value = _get_ini_value(app, 'remote_cache', 'redis_enabled', fallback='false')
    return str(value).strip().lower() == 'true'


def _get_redis_url(app: Flask) -> Optional[str]:
    from lib.session import get_session_redis_url

    return get_session_redis_url(app)


def _is_sqlite_database(app: Flask) -> bool:
    """Check if the application is configured to use SQLite database."""
    # Check the ini file configuration, not the SQLAlchemy URI (which may not be set yet)
    database_type = _get_ini_value(app, 'database', 'type', fallback='sqlite3')
    return database_type.lower() == 'sqlite3'


def validate_replica_config(app: Flask) -> None:
    """Validate replica mode configuration at startup."""
    mode = get_replica_mode(app)
    replica_count = get_replica_count(app)

    app.config['REPLICA_MODE'] = mode
    app.config['REPLICA_COUNT'] = replica_count
    app.config['POD_NAME'] = get_pod_identity(app)
    app.config['POD_NAMESPACE'] = get_pod_namespace(app)

    app.logger.info("Replica mode: %s", mode)
    app.logger.info("Replica count: %s", replica_count)
    app.logger.info("Pod identity: %s", app.config['POD_NAME'])
    app.logger.info("Pod namespace: %s", app.config['POD_NAMESPACE'])

    # Validate cluster mode requirements
    if mode == 'cluster':
        if _is_sqlite_database(app):
            error_msg = (
                "ERROR: Cluster mode requires PostgreSQL database, but SQLite is configured. "
                "SQLite does not support concurrent writes required for multi-replica deployments. "
                "Please set 'type = postgres' in kubedash.ini [database] section."
            )
            app.logger.error(error_msg)
            raise ValueError(error_msg)
        
        redis_url = _get_redis_url(app)
        if not redis_url:
            app.logger.warning(
                "WARNING: Cluster mode detected but Redis is not configured. "
                "Session state will not be shared across replicas. "
                "Configure SESSION_REDIS_URL or redis in kubedash.ini remote_cache section."
            )

    if mode == 'cluster':
        # Check database configuration from ini file (SQLALCHEMY_DATABASE_URI may not be set yet)
        database_type = _get_ini_value(app, 'database', 'type', fallback='sqlite3')
        if database_type.lower() == 'sqlite3':
            raise RuntimeError(
                "Cluster replica mode requires a shared database backend such as PostgreSQL. "
                "SQLite is only supported for single-replica deployments."
            )

        if not _get_redis_url(app):
            raise RuntimeError(
                "Cluster replica mode requires Redis session backend. "
                "Set SESSION_REDIS_URL or enable remote_cache.redis_enabled in kubedash.ini."
            )
        
        # Configuration warnings for cluster mode
        if replica_count < 2:
            app.logger.warning(
                "Cluster mode configured but replica_count (%d) is less than 2. "
                "This may indicate misconfiguration.", replica_count
            )
        
        if not os.environ.get('POD_NAME') and not app.config.get('POD_NAME'):
            app.logger.warning(
                "Running in cluster mode but POD_NAME not set. "
                "Leader election may not work correctly without unique pod identity."
            )
        
        if not os.environ.get('POD_NAMESPACE') and not app.config.get('POD_NAMESPACE'):
            app.logger.warning(
                "Running in cluster mode but POD_NAMESPACE not set. "
                "Using default namespace 'default' for leader election."
            )
    else:
        # Configuration warnings for single mode
        if replica_count > 1:
            app.logger.warning(
                "Single replica mode configured but replica_count (%d) > 1. "
                "This may indicate misconfiguration.", replica_count
            )


def initialize_replica_mode(app: Flask) -> None:
    """Initialize replica mode configuration and validate it."""
    try:
        validate_replica_config(app)
    except Exception as exc:
        app.logger.error("Replica mode validation failed: %s", exc)
        raise

    mode = app.config['REPLICA_MODE']
    replica_count = app.config['REPLICA_COUNT']

    # Emit replica mode metrics
    mode_value = 1 if mode == 'single' else 2
    METRIC_REPLICA_MODE_INFO.labels(mode=mode).set(mode_value)
    METRIC_REPLICA_DESIRED.set(replica_count)

    if mode == 'cluster':
        app.logger.info("Cluster replica mode enabled")
    else:
        app.logger.info("Single replica mode enabled")
