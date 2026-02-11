#!/usr/bin/env python3

import os
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
    initialize_plugin_apis,
    initialize_app_socket,
    add_custom_jinja2_filters,
    initialize_app_security,
    initialize_app_version,
    initialize_commands,
    initialize_app_caching,
)
from lib.metrics import (
    initialize_metrics_scraper,
    update_metrics
)
from lib.components import db
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
            # separator_long will be printed after migration completes in entrypoint.sh
        else:
            initialize_app_version(app)
            initialize_app_plugins(app)
            # connections
            app.logger.info(separator_short)
            initialize_app_caching(app)
            initialize_app_database(app, __file__)
            init_before_request(app)
            app.logger.info(separator_short)
            with app.app_context():
                # Skip metrics update in testing mode to avoid database issues
                # and because tests don't need real metrics data
                if not app.config.get('TESTING', False):
                    # Run initial metrics scrape synchronously before starting the ticker
                    # This ensures the metrics logs appear before the separator
                    try:
                        update_metrics(app, db, 30)
                    except Exception as e:
                        # Gracefully handle metrics update failures (e.g., missing tables, no K8s cluster)
                        app.logger.warning(f"Metrics update skipped: {e}")
                    # Now start the periodic ticker for future updates
                    initialize_metrics_scraper(app)
            app.logger.info(separator_short)
            initialize_app_socket(app)
            initialize_blueprints(app)
            initialize_plugin_apis(app)
            add_custom_jinja2_filters(app)
            initialize_app_security(app)
            
            # Trigger application catalog initialization synchronously if needed
            # This ensures all initialization logs appear before the separator
            try:
                from plugins.application_catalog import initialize_application_catalog
                with app.app_context():
                    initialize_application_catalog(app)
            except Exception:
                # If it fails, it will be initialized on first request
                pass
            
            # Print separator_long at the end of all initialization (only once)
            # Use sys.stdout to ensure it's not buffered and appears only once
            sys.stdout.write(separator_long + '\n')
            sys.stdout.flush()
   
    return app


##############################################################
## Main Application variable for WSGI Like Gunicorn
##############################################################

# Only create app at module level if not running tests
# Tests will create their own app instance via create_app("testing")
if 'pytest' not in sys.modules and 'PYTEST_CURRENT_TEST' not in os.environ:
    app = create_app()
else:
    app = None