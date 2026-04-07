#!/usr/bin/env python3

import os
import sys
import time
from datetime import datetime
from flask import Flask, request

from lib.initializers import (
    initialize_app_configuration,
    initialize_app_logging,
    initialize_error_page,
    initialize_app_swagger,
    initialize_app_tracing,
    initialize_app_database,
    initialize_app_plugins,
    initialize_plugin_models,
    ensure_plugin_models_loaded,
    initialize_blueprints,
    initialize_plugin_apis,
    initialize_app_socket,
    add_custom_jinja2_filters,
    initialize_app_security,
    initialize_app_version,
    initialize_commands,
    initialize_app_caching,
)
from lib.replica_mode import initialize_replica_mode
from lib.leader_election import initialize_leader_election
from lib.leader_tasks import initialize_leader_tasks
from lib.metrics import (
    initialize_metrics_scraper,
    update_metrics
)
from lib.initializers.cluster_metrics_warmup import initialize_cluster_metrics_warmup
from lib.components import db
from lib.before_request import init_before_request
from lib.audit import init_audit
from lib.shutdown import init_graceful_shutdown, get_graceful_shutdown

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
    
    # Initialize graceful shutdown early (before logging to handle SIGTERM)
    # Note: leader_election will be initialized later
    graceful_shutdown = init_graceful_shutdown(app, None, None, None)
       
    print(separator_long)
    if external_config_name is not None:
        error = initialize_app_configuration(app, external_config_name)
    else:
        error = initialize_app_configuration(app, None)
    
    initialize_replica_mode(app)
    initialize_app_logging(app)
    
    # Then initialize tracing (before request handlers)
    if not error and len(sys.argv) > 1 and sys.argv[1] not in ('cli', 'db'):
        initialize_app_tracing(app)
    
    # Setup request tracking for graceful shutdown (must be after Flask setup)
    graceful_shutdown = get_graceful_shutdown()
    
    @app.before_request
    def before_request_shutdown():
        """Track incoming request for graceful shutdown"""
        # Set prometheus metrics start time early to avoid AttributeError in after_request
        if not hasattr(request, '_prometheus_metrics_request_start_time'):
            request._prometheus_metrics_request_start_time = time.time()
        
        if app.config.get('SHUTTING_DOWN', False):
            return {"error": "Service is shutting down"}, 503

        if graceful_shutdown and not graceful_shutdown.track_request():
            return {"error": "Service is shutting down"}, 503
    
    @app.after_request
    def after_request_shutdown(response):
        """Complete request tracking"""
        if graceful_shutdown:
            graceful_shutdown.complete_request()
        return response

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
            # Load plugin model modules into db.metadata for Alembic autogenerate (no db.create_all).
            ensure_plugin_models_loaded(app)
        else:
            initialize_app_version(app)
            initialize_app_plugins(app)
            # connections
            app.logger.info(separator_short)
            initialize_app_caching(app)
            initialize_app_database(app, __file__)
            initialize_leader_election(app)
            initialize_leader_tasks(app)
            initialize_plugin_models(app)
            init_before_request(app)
            init_audit(app)
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
                    # Warm cluster-metrics cache periodically (configurable; can be disabled)
                    initialize_cluster_metrics_warmup(app)
            app.logger.info(separator_short)
            initialize_app_socket(app)
            initialize_blueprints(app)
            initialize_plugin_apis(app)
            
            # Register shutdown endpoint (10.5 - 10.6)
            from routes.shutdown import shutdown_bp
            app.register_blueprint(shutdown_bp)
            
            # Register shutdown handlers (sessions, metrics)
            def cleanup_sessions():
                """Clean up sessions on shutdown"""
                app.logger.info("Cleaning up sessions...")
                try:
                    # Session cleanup handled by session backend
                    pass
                except Exception as e:
                    app.logger.error(f"Error cleaning up sessions: {e}")
            
            graceful_shutdown = get_graceful_shutdown()
            if graceful_shutdown:
                graceful_shutdown.register_handler(cleanup_sessions, "cleanup_sessions")
            
            add_custom_jinja2_filters(app)
            # Register trace context processor so HTML pages get traceparent for frontend propagation
            from lib.initializers.tracing import inject_trace_context_processor
            app.context_processor(inject_trace_context_processor)
            # Inject current year for footer copyright (dynamic 2021-<year>)
            app.context_processor(lambda: {"current_year": datetime.now().year})
            initialize_app_security(app)
            
            # Update graceful shutdown with app references (scheduler, db, leader_elector)
            graceful_shutdown = get_graceful_shutdown()
            if graceful_shutdown:
                from lib.initializers.app_scheduler import get_scheduler
                scheduler = get_scheduler(app) if hasattr(app, 'scheduler') else None
                leader_elector = getattr(app, 'leader_elector', None)
                
                # Update shutdown handler with actual references
                graceful_shutdown.db = db
                graceful_shutdown.scheduler = scheduler
                graceful_shutdown.leader_elector = leader_elector
                app.logger.info("Graceful shutdown fully initialized with leader election")
            
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