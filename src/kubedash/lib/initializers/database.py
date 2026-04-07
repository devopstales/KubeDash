#!/usr/bin/env python3
"""Database initialization for KubeDash."""

import os
import sys
from flask import Flask
from sqlalchemy import create_engine, text
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor


def _setup_minimal_database(app: Flask) -> str:
    """Set up SQLite database for minimal-config mode.

    Returns:
        str: The SQLite database URI that was configured.
    """
    from lib.minimal_config import get_minimal_db_path

    db_path = get_minimal_db_path()
    db_uri = f"sqlite:///{db_path}"
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.logger.info("   Minimal-config mode: using SQLite at %s", db_path)
    return db_uri


def initialize_app_database(app: Flask, filename: str):
    """Initialize the database

    Args:
        app (Flask): Flask app object
        filename (str): Name of the main file to find the database file
    """
    from lib.components import db, migrate, sess
    from lib.init_functions import get_database_url
    from lib.session import configure_session_backend

    app.logger.info("Initialize Database:")

    """Get Database Configuration"""
    app.logger.info("   Get Database Configuration")
    app.config['SESSION_SQLALCHEMY'] = db

    # Check if we're in minimal-config mode (no kubedash.ini)
    if app.config.get('MINIMAL_CONFIG'):
        database_uri = _setup_minimal_database(app)
        database_type = 'sqlite3'
    else:
        # Get database URL - this will use PostgreSQL if configured, even in testing mode
        app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url(app, filename)
        database_uri = app.config['SQLALCHEMY_DATABASE_URI']

        # Determine actual database type from the URI
        if database_uri.startswith('postgresql://') or database_uri.startswith('postgresql+'):
            database_type = 'postgres'
        else:
            database_type = 'sqlite3'

    """Test Database Connection"""
    app.logger.info("   Test Database Connection")
    if database_type == 'postgres':
        # Show connection target (without password)
        safe_uri = database_uri.split('@')[-1] if '@' in database_uri else database_uri
        app.logger.info(f"   Attempting to connect to PostgreSQL: {safe_uri}")
        try:
            # Create a temporary engine just for connection testing
            # Use a small pool for testing to avoid consuming too many connections
            test_engine = create_engine(
                database_uri,
                pool_size=1,
                max_overflow=0,
                pool_timeout=10,  # Shorter timeout for connection test
                connect_args={"connect_timeout": 10}  # PostgreSQL connection timeout
            )
            with test_engine.connect() as connection:
                result = connection.execute(text("SELECT 1"))
                app.logger.info("   PostgreSQL connection test successful")
            # Dispose of the test engine to release connections
            test_engine.dispose()
        except Exception as e:
            app.logger.error(f"   Failed to connect to PostgreSQL database: {type(e).__name__}: {e}")
            env = app.config.get('ENV', 'development')
            # Never silently fall back when PostgreSQL is selected; require explicit fix
            raise RuntimeError(
                f"Failed to connect to PostgreSQL database in '{env}' environment. "
                "Fix database configuration or disable PostgreSQL (set database.type to "
                "'sqlite3' in kubedash.ini) instead of relying on an automatic fallback."
            ) from e

    """Logging Database URL"""
    app.logger.info("   Database Configuration:")
    app.logger.info("   Database Type: %s" % database_type)
    app.logger.info("   Database URI: %s" % app.config['SQLALCHEMY_DATABASE_URI'])

    """Configure SQLAlchemy Engine Options for Connection Pool"""
    # Configure connection pool settings to prevent timeout errors
    # Only apply pool settings for PostgreSQL (SQLite doesn't use connection pooling)
    if database_type == 'postgres':
        # Use both modern ENGINE_OPTIONS and legacy config keys for maximum compatibility
        # Flask-Session may use legacy keys, while Flask-SQLAlchemy uses ENGINE_OPTIONS
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
            'pool_size': 10,           # Number of connections to maintain persistently
            'max_overflow': 20,         # Maximum number of connections to create in addition to pool_size
            'pool_timeout': 30,         # Seconds to wait before giving up on getting a connection
            'pool_recycle': 3600,       # Recycle connections after 1 hour (prevents stale connections)
            'pool_pre_ping': True,      # Verify connections before using them (handles dropped connections)
            'echo': False,              # Set to True for SQL query logging (useful for debugging)
        }
        # Legacy configuration keys for Flask-Session compatibility
        app.config['SQLALCHEMY_POOL_SIZE'] = 10
        app.config['SQLALCHEMY_MAX_OVERFLOW'] = 20
        app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
        app.config['SQLALCHEMY_POOL_RECYCLE'] = 3600
        app.config['SQLALCHEMY_POOL_PRE_PING'] = True
        app.logger.info("   Connection Pool Configuration:")
        app.logger.info("     pool_size: 10")
        app.logger.info("     max_overflow: 20")
        app.logger.info("     pool_timeout: 30")
        app.logger.info("     pool_recycle: 3600")
        app.logger.info("     pool_pre_ping: True")

    """Initialize SQLAlchemy"""
    app.logger.info("   Initialize SQLAlchemy")
    db.init_app(app)
    migrate.init_app(app, db)

    from lib.init_functions import (
        db_init_roles, init_db_test,
        k8s_config_int, k8s_roles_init, oidc_init
    )

    with app.app_context():
        """Initialize session"""
        # Ensure SESSION_SQLALCHEMY is set before Flask-Session initializes
        # This tells Flask-Session to use the same SQLAlchemy instance and engine
        app.config['SESSION_SQLALCHEMY'] = db

        # Verify the engine has the correct pool configuration (inside app context)
        if database_type == 'postgres':
            try:
                pool = db.engine.pool
                app.logger.info("   Verified Engine Pool Configuration:")
                app.logger.info(f"     pool.size(): {pool.size()}")
                app.logger.info(f"     pool._max_overflow: {pool._max_overflow}")
            except Exception as e:
                app.logger.warning(f"   Could not verify engine pool configuration: {e}")

        # Allow sessions table to be redefined (e.g. on reloader restart) to avoid
        # "Table 'sessions' is already defined for this MetaData instance"
        import sqlalchemy as sa
        _original_table = sa.Table
        def _patched_table(*args, **kwargs):
            if args and args[0] == 'sessions':
                kwargs['extend_existing'] = True
            return _original_table(*args, **kwargs)
        try:
            sa.Table = _patched_table
            configure_session_backend(app)
            sess.init_app(app)
        finally:
            sa.Table = _original_table

        """Create Tables"""
        app.logger.info("   Create Tables")
        app.logger.debug(f"Registered models: {db.metadata.tables.keys()}")  # Debugging output
        #db.create_all()

        if init_db_test(app):
            SQLAlchemyInstrumentor().instrument(
                engine=db.engine,
                enable_commenter=True,
                commenter_options={
                    "db_framework": "flask",
                    "db_driver": database_type
                }
            )
            db_init_roles(app.config['kubedash.ini'])

            """Add Contant to Tables"""
            app.logger.info("   Add Contant to Tables")
            app.logger.info("#######################################")

            # Print separator_long before migration runs (only in 'db' mode)
            # Use stderr to match Alembic's output stream for proper ordering
            if len(sys.argv) > 1 and sys.argv[1] == 'db':
                sys.stderr.write("###########################################################################################\n")
                sys.stderr.flush()

            if sys.argv[1] != 'cli' and sys.argv[1] != 'db':
                oidc_init(app.config['kubedash.ini'])
                k8s_config_int(app.config['kubedash.ini'])
                from lib.k8s.server import k8sGetClusterStatus
                if k8sGetClusterStatus():
                    k8s_roles_init()
