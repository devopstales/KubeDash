#!/usr/bin/env python3

import sys
from flask import Flask, request

from lib.initializers import (
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
from lib.metrics import (
    initialize_metrics_scraper
)
from lib.before_request import init_before_request
#############################################################
## Variables
#############################################################

from lib.initializers import (
    separator_long,
    separator_short
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
       
    print(separator_long)
    if external_config_name is not None:
        error = initialize_app_configuration(app, external_config_name)
    else:
        error = initialize_app_configuration(app, None)
    
    initialize_app_logging(app)
    
    # Then initialize tracing (before request handlers)
    if not error and len(sys.argv) > 1 and sys.argv[1] not in ('cli', 'db'):
        initialize_app_tracing(app)
    

    # manage cli commands
    if not error:
        initialize_error_page(app)
        initialize_app_swagger(app)
        if sys.argv[1] == 'cli':
            initialize_app_database(app, __file__)
            print(separator_long)
            initialize_commands(app)
        elif sys.argv[1] == 'db':
            initialize_app_plugins(app)
            initialize_app_database(app, __file__)
            print(separator_long)
        else:
            initialize_app_version(app)
            initialize_app_plugins(app)
            # connections
            app.logger.info(separator_short)
            initialize_app_database(app, __file__)
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


##############################################################
## Main Application variable for WSGI Like Gunicorn
##############################################################

app = create_app()