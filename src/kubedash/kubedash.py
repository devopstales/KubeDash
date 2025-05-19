#!/usr/bin/env python3

from flask import Flask
import sys

from lib.initializers import (
    initialize_app_confifuration, 
    initialize_app_logging,
    initialize_error_page,
    initialize_app_swagger,
    initialize_app_tracing,
    initialize_app_database,
    initialize_app_plugins,
    initialize_blueprints,
    initialize_app_session_and_socket,
    add_custom_jinja2_filters,
    initialize_app_security,
    initialize_app_version,
    initialize_commands,
    inicialize_instrumentors,
)

#############################################################
## Variables
#############################################################

from lib.initializers import (
    separator_long
)

#############################################################
## Main App creation Function
#############################################################

def create_app(external_config_name=None):
    """Initialize Flask app object

    Args:
        external_config_name (str, optional): Name of the configuration file. Defaults to None.

    Returns:
        app (Flask): Flask app object
    """
    app = Flask(__name__, static_url_path='', static_folder='static')

    # instrument app
    inicialize_instrumentors(app)

    print(separator_long)
    if external_config_name is not None:
        error = initialize_app_confifuration(app, external_config_name)
    else:
        error = initialize_app_confifuration(app, None)

    initialize_app_logging(app)
    initialize_error_page(app)
    initialize_app_swagger(app)

    # manage cli commands
    if not error:
        if sys.argv[1] == 'cli':
            initialize_app_tracing(app)
            initialize_app_database(app, __file__)
            print(separator_long)
            initialize_commands(app)
        elif sys.argv[1] == 'db':
            initialize_app_tracing(app)
            initialize_app_database(app, __file__)
            print(separator_long)
        else:
            initialize_app_version(app)
            initialize_app_tracing(app)
            initialize_app_database(app, __file__)
            initialize_app_plugins(app)
            initialize_blueprints(app)
            initialize_app_session_and_socket(app)
            add_custom_jinja2_filters(app)
            initialize_app_security(app)

            print(separator_long)

    return app

##############################################################
## Main Application variable for WSGI Like Gunicorn
##############################################################

app = create_app()