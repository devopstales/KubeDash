#!/usr/bin/env python3

import sys
from flask import Flask, request

from kubedash.lib.initializers import (
    initialize_app_configuration, 
    initialize_app_logging,
    initialize_error_page,
    initialize_app_swagger,
    initialize_app_tracing,
    initialize_app_database,
    initialize_app_plugins,
    initialize_blueprints,
    initialize_app_socket,
    add_custom_jinja2_filters,
    initialize_app_security,
    initialize_app_version,
    initialize_commands,
    initialize_app_caching,
)
from kubedash.lib.metrics import (
    initialize_metrics_scraper
)
from kubedash.lib.before_request import init_before_request
#############################################################
## Variables
#############################################################

from kubedash.lib.initializers import (
    separator_long,
    separator_short
)

#############################################################
## Main App creation Function
#############################################################

def create_app(app_mode=None):
    """Initialize Flask app object

    Args:
        app_mode (str, optional): Application mode to start like testing

    Returns:
        app (Flask): Flask app object
    """
    app = Flask(__name__, static_url_path='', static_folder='static')
       
    print(separator_long)
    error = initialize_app_configuration(app, app_mode)
    
    initialize_app_logging(app)

    # manage cli commands
    if not error:
        if len(sys.argv) > 1 and sys.argv[1] == 'cli':
            initialize_app_database(app)
            print(separator_long)
            initialize_commands(app)
        elif len(sys.argv) > 1 and sys.argv[1] == 'db':
            initialize_app_plugins(app)
            initialize_app_database(app)
            print(separator_long)
        else:
            initialize_error_page(app)
            initialize_app_swagger(app)
            initialize_app_tracing(app)
            initialize_app_version(app)
            initialize_app_plugins(app)
            # connections
            app.logger.info(separator_short)
            initialize_app_database(app)
            initialize_app_caching(app)
            init_before_request(app)
            app.logger.info(separator_short)
            with app.app_context():
                initialize_metrics_scraper(app)
            app.logger.info(separator_short)
            initialize_app_socket(app)
            initialize_blueprints(app)
            add_custom_jinja2_filters(app)
            initialize_app_security(app)
            
            
            print(separator_long)
            
   
    return app