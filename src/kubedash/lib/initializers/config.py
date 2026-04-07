#!/usr/bin/env python3
"""Configuration and version initialization for KubeDash."""

import os
import logging
from flask import Flask

logger = logging.getLogger(__name__)

# ANSI escape codes for colors
BLUE = "\033[34m"
RED = "\033[31m"
RESET = "\033[0m"

separator_short = "#######################################"
separator_long = "###########################################################################################"


def initialize_app_configuration(app: Flask, external_config_name: str) -> bool:
    """Initialize the configuration and return error if missing

    Args:
        app (Flask): Flask app object
        external_config_name (str): The name of the external configuration file

    Returns:
        error (bool): A flag used to represent if the config initialization failed
    """
    import configparser
    from lib.config import app_config
    from lib.helper_functions import bool_var_test

    app.logger.info(separator_short)
    app.logger.info("Initializing app configuration")

    config_ini = configparser.ConfigParser()
    minimal_config_mode = False

    if os.path.isfile("kubedash.ini"):
        app.logger.info("Reading Config file")
        config_ini.read('kubedash.ini')
    else:
        minimal_config_mode = True
        app.logger.warning(
            "Config file kubedash.ini not found — entering minimal-config mode.\n"
            "KubeDash is starting with built-in defaults (SQLite, no Redis, no OIDC).\n"
            "This is safe for local development but NOT recommended for production.\n"
            "To use full configuration, create a kubedash.ini file."
        )
        # Set default configuration for minimal-config mode
        config_ini['DEFAULT'] = {'app_mode': 'development'}
        config_ini['logging'] = {'format': 'text', 'level': 'INFO'}
        config_ini['audit'] = {'enabled': 'true'}
        config_ini['security'] = {'admin_password': 'admin'}
        config_ini['database'] = {
            'type': 'sqlite3',
            'host': '127.0.0.1:5432',
            'name': 'kubedash'
        }
        config_ini['remote_cache'] = {
            'redis_enabled': 'false',
            'redis_host': '127.0.0.1',
            'redis_port': '6379',
            'redis_db': '0',
            'redis_password': '',
            'redis_ssl': 'false',
            'cluster_enabled': 'false',
            'replica_mode': 'single',
            'replica_count': '1',
            'leader_election_enabled': 'false',
            'leader_election_lease_name': 'kubedash-leader-election',
            'leader_election_lease_duration': '30',
            'leader_election_renew_deadline': '20',
            'leader_election_retry_period': '5',
            'cluster_startup_nodes': '',
            'short_cache_time': '60',
            'long_cache_time': '900'
        }
        config_ini['monitoring'] = {
            'jaeger_enabled': 'false',
            'jaeger_http_endpoint': 'http://127.0.0.1:4318'
        }
        config_ini['plugin_settings'] = {
            'registry': 'false',
            'helm': 'true',
            'gateway_api': 'false',
            'cert_manager': 'false',
            'ai_chat': 'false'
        }
        # Disable OIDC and external auth in minimal mode
        config_ini['oidc'] = {
            'enabled': 'false',
            'issuer': '',
            'client_id': '',
            'client_secret': '',
            'redirect_uri': '',
            'scope': 'openid email profile'
        }
        config_ini['kubernetes'] = {
            'auth_mode': 'kubeconfig',
            'in_cluster': 'false'
        }

    # Set MINIMAL_CONFIG flag for use by other modules
    app.config['MINIMAL_CONFIG'] = minimal_config_mode

    if minimal_config_mode:
        # Clear stale K8s config from database (left over from previous kubedash.ini run)
        try:
            from lib.k8s.server import k8sServerConfigDelete
            k8sServerConfigDelete()
        except Exception:
            pass  # No existing config to delete, or DB not ready yet

    app.config['kubedash.ini'] = config_ini

    if external_config_name is not None:
        config_name = external_config_name
    else:
        if 'FLASK_ENV' in os.environ:
            config_name = os.environ['FLASK_ENV']
        else:
            config_name = config_ini.get('DEFAULT', 'app_mode', fallback='development')

    app.config.from_object(app_config[config_name])
    app.config['ENV'] = config_name

    app.logger.info("Integrations:")
    app.logger.info("	Redis:	%s" % bool_var_test(app.config['kubedash.ini'].get('remote_cache', 'redis_enabled')))
    app.logger.info("	Jaeger:	%s" % bool_var_test(app.config['kubedash.ini'].get('monitoring', 'jaeger_enabled')))

    if minimal_config_mode:
        from lib.minimal_config import get_minimal_db_path
        from lib.prometheus import METRIC_CONFIG_MODE
        db_path = get_minimal_db_path()
        app.logger.info("Minimal-config mode summary:")
        app.logger.info("  Database: SQLite at %s", db_path)
        app.logger.info("  Redis: disabled")
        app.logger.info("  OIDC: disabled")
        app.logger.info("  Leader election: disabled")
        app.logger.info("  Replica mode: single (forced)")
        app.logger.info("To use full configuration, create a kubedash.ini file.")
        METRIC_CONFIG_MODE.labels(mode='minimal').set(2)
    else:
        from lib.prometheus import METRIC_CONFIG_MODE
        METRIC_CONFIG_MODE.labels(mode='full').set(1)

    app.logger.info(separator_short)

    # Validate configuration (skip in testing mode)
    if config_name != 'testing':
        try:
            from lib.config_validator import validate_config
            # Convert configparser to dict for validation
            ini_dict = {
                section: dict(app.config['kubedash.ini'][section])
                for section in app.config['kubedash.ini'].sections()
            }
            validate_config(dict(app.config), ini_dict)
            app.logger.info("Configuration validation passed")
        except Exception as e:
            app.logger.error(f"Configuration validation failed: {e}")
            raise

    return False


def initialize_app_version(app: Flask):
    """Initialize the application version

    Args:
        app (Flask): Flask app object
    """
    from flask_prometheus_metrics import register_metrics
    from lib.helper_functions import bool_var_test

    app.logger.info("Initializing app version")
    app_version = os.getenv('KUBEDASH_VERSION', default=None)

    if app_version:
        if app.config['ENV'] == 'production':
            kubedash_version = os.getenv('KUBEDASH_VERSION')
        elif app.config['ENV'] == 'development':
            kubedash_version = os.getenv('KUBEDASH_VERSION') + '-devel'
        elif app.config['ENV'] == 'testing':
            kubedash_version = "testing"
    elif app.config['ENV'] == 'testing':
            kubedash_version = "testing"
    else:
        kubedash_version = "Unknown"

    app.config['VERSION'] = kubedash_version
    app.jinja_env.globals['kubedash_version'] = kubedash_version

    """Prometheus endpoint"""
    register_metrics(app, app_version=kubedash_version, app_config=app.config['ENV'])

    LOGO = rf"""
{BLUE}     /$$   /$$           /$$                 /$$$$$$$                      /$$
    | $$  /$$/          | $$                | $$__  $$                    | $$
    | $$ /$$/  /$$   /$$| $$$$$$$   /$$$$$$ | $$  \ $$  /$$$$$$   /$$$$$$$| $$$$$$$
    | $$$$$/  | $$  | $$| $$__  $$ /$$__  $$| $$  | $$ |____  $$ /$$_____/| $$__  $$
    | $$  $$  | $$  | $$| $$  \ $$| $$$$$$$$| $$  | $$  /$$$$$$$|  $$$$$$ | $$  \ $$
    | $$\  $$ | $$  | $$| $$  | $$| $$_____/| $$  | $$ /$$__  $$ \____  $$| $$  | $$
    | $$ \  $$|  $$$$$$/| $$$$$$$/|  $$$$$$$| $$$$$$$/|  $$$$$$$ /$$$$$$$/| $$  | $$
    |__/  \__/ \______/ |_______/  \_______/|_______/  \_______/|_______/ |__/  |__/{RESET}
    version: {RED}{kubedash_version}{RESET}
"""

    # Use sys.stderr.write() to guarantee the logo appears regardless of logging state
    import sys
    sys.stderr.write(f"\n{separator_long}\n")
    sys.stderr.write(LOGO)
    sys.stderr.write(f"{separator_long}\n\n")
    sys.stderr.flush()

    app.logger.info("Initializing app Logo")
    app.logger.info("Running in %s mode" % app.config['ENV'])
