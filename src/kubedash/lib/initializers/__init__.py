#!/usr/bin/env python3
"""
KubeDash Application Initializers

This package contains all application initialization functions,
split into focused modules for better maintainability.
"""

from lib.initializers.config import (
    initialize_app_configuration,
    initialize_app_version,
    BLUE,
    RED,
    RESET,
    separator_short,
    separator_long,
)

from lib.initializers.logging import initialize_app_logging

from lib.initializers.errors import initialize_error_page

from lib.initializers.database import initialize_app_database

from lib.initializers.api_docs import initialize_app_swagger

from lib.initializers.blueprints import (
    initialize_blueprints,
    initialize_commands,
)

from lib.initializers.tracing import (
    initialize_app_tracing,
    initialize_instrumentors,
)

from lib.initializers.caching import initialize_app_caching

from lib.initializers.plugins import (
    initialize_app_plugins,
    initialize_plugin_apis,
)

from lib.initializers.templates import add_custom_jinja2_filters

from lib.initializers.socketio import initialize_app_socket

from lib.initializers.security import initialize_app_security

from lib.initializers.workload_cache import initialize_workloadcachers

__all__ = [
    # Config
    'initialize_app_configuration',
    'initialize_app_version',
    'BLUE',
    'RED',
    'RESET',
    'separator_short',
    'separator_long',
    # Logging
    'initialize_app_logging',
    # Errors
    'initialize_error_page',
    # Database
    'initialize_app_database',
    # API Docs
    'initialize_app_swagger',
    # Blueprints
    'initialize_blueprints',
    'initialize_commands',
    # Tracing
    'initialize_app_tracing',
    'initialize_instrumentors',
    # Caching
    'initialize_app_caching',
    # Plugins
    'initialize_app_plugins',
    'initialize_plugin_apis',
    # Templates
    'add_custom_jinja2_filters',
    # SocketIO
    'initialize_app_socket',
    # Security
    'initialize_app_security',
    # Workload Cache
    'initialize_workloadcachers',
]
