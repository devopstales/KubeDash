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

    if os.path.isfile("kubedash.ini"):
        app.logger.info("Reading Config file")
        config_ini.read('kubedash.ini')
    else:
        app.logger.warning("Config file kubedash.ini not found, using defaults")
        # Set default configuration
        config_ini['DEFAULT'] = {'app_mode': 'development'}
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
            'cluster_enabled': 'false',
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
            'mcp_integration': 'false'
        }

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
            app.logger.info("✅ Configuration validation passed")
        except Exception as e:
            app.logger.error(f"❌ Configuration validation failed: {e}")
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

    app.logger.info("Initializing app Logo\n" + separator_long + "\n" + LOGO + "\n" + separator_long)
    app.logger.info("Running in %s mode" % app.config['ENV'])
