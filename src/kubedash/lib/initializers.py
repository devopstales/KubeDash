#!/usr/bin/env python3

from email.policy import HTTP
import logging
import os
import uuid
import sys
import socket
import redis
import importlib
from pathlib import Path
from redis.exceptions import AuthenticationError, ConnectionError, RedisError
from redis.cluster import RedisCluster
from sqlalchemy import create_engine, text

from flask import g, Flask, render_template, request, has_request_context
from flask_smorest import Blueprint

from opentelemetry import trace
from opentelemetry.instrumentation.wsgi import OpenTelemetryMiddleware
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor

from lib.components import csrf, db, migrate, login_manager, socketio, sess, api_doc
from lib.init_functions import get_database_url
from lib.helper_functions import bool_var_test, get_logger
from lib.k8s.server import k8sGetClusterStatus

from lib.helper_functions import ThreadedTicker
from lib.k8s.workload_cahers import (
    fetch_and_cache_pods_all_namespaces,
    fetch_and_cache_deployments_all_namespaces,
    fetch_and_cache_statefulsets_all_namespaces,
    fetch_and_cache_daemonsets_all_namespaces,
    fetch_and_cache_replicasets_all_namespaces,
)

##############################################################
## Variables
##############################################################

# ANSI escape codes for colors
BLUE = "\033[34m"
RED = "\033[31m"
RESET = "\033[0m"


separator_long = r"###########################################################################################"
separator_short = r"#######################################"


##############################################################
## Helper Functions
##############################################################



##############################################################
## Initialization Functions
##############################################################

def initialize_app_logging(app: Flask):
    """Initialize Flask app logging
    Args:
        app (Flask): Flask app object
    """
    from lib.logfilters import (NoHealth, NoMetrics, NoPing, NoSocketIoGet,
                                NoSocketIoPost) 
    
    logger = get_logger()
    
    if sys.argv[1] != 'cli' and sys.argv[1] != 'db':
        app.logger.info("Initialize logging")

    if app.config['DEBUG']:
        app.logger.setLevel(logging.DEBUG)
        logging.getLogger("werkzeug").setLevel(logging.DEBUG)
    else:
        app.logger.setLevel(logging.INFO)
        logging.getLogger("werkzeug").addFilter(NoMetrics())
        logging.getLogger("werkzeug").addFilter(NoHealth())
        logging.getLogger("werkzeug").addFilter(NoPing())
        logging.getLogger("werkzeug").addFilter(NoSocketIoGet()) 
        logging.getLogger("werkzeug").addFilter(NoSocketIoPost())
         
def initialize_error_page(app: Flask):
    """Initialize error pages

    Args:
        app (Flask): Flask app object
    """
    @app.errorhandler(400)
    def page_not_found400(e):
        from flask import request
        # Check if this is a CSRF error from a security scanner (ZAP)
        is_security_scanner = False
        if hasattr(request, 'user_agent'):
            user_agent = str(request.user_agent)
            # ZAP uses specific User-Agent patterns
            if any(pattern in user_agent.lower() for pattern in ['zap', 'owasp', 'scanner', 'security']):
                is_security_scanner = True
        # Also check if request is from localhost (common for ZAP in Docker)
        if request.remote_addr in ['127.0.0.1', '::1', 'localhost']:
            # Check if it's a CSRF error (expected during security scanning)
            if 'csrf' in str(e.description).lower():
                is_security_scanner = True
        
        # Log security scanner CSRF errors at DEBUG level (expected behavior)
        # Log real CSRF errors at ERROR level
        if is_security_scanner and 'csrf' in str(e.description).lower():
            app.logger.debug(f"400 Error (Security Scanner): {e.description} - This is expected during security scanning")
        else:
            app.logger.error(f"400 Error: {e.description}")
        return render_template(
            'errors/400.html.j2',
            description=e.description,
            ), 400
        
    @app.errorhandler(403)
    def page_not_found400(e):
        app.logger.error(f"403 Error: {e.description}")
        return render_template(
            'errors/403.html.j2',
            description=e.description,
            ), 403
        
    @app.errorhandler(404)
    def page_not_found404(e):
        from flask import request
        app.logger.error(f"404 Error: {e.description} {request.url}")
        return render_template('errors/404.html.j2'), 404


    @app.errorhandler(500)
    def internal_server_error(e):
        # Handle cases where description might not exist
        description = getattr(e, 'description', 'Internal Server Error')
        app.logger.error(f"500 Error: {description}")
        return render_template(
            'errors/500.html.j2',
            description=description,
            ), 500

    # Also handle generic exceptions
    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        app.logger.error(f"Unexpected error: {str(e)}")
        description = "An unexpected error occurred"
        return render_template(
            'errors/500.html.j2',
            description=description,
            ), 500
        
    @app.errorhandler(502)
    def bad_gateway(e):
        return render_template('errors/502.html.j2', description=e.description), 502

    @app.errorhandler(504)
    def gateway_timeout(e):
        return render_template('errors/504.html.j2', description=e.description), 504


def initialize_app_configuration(app: Flask, external_config_name: str) -> bool:
    """Initialize the configuration and return error if missing

    Args:
        app (Flask): Flask app object
        external_config_name (str): The name of the external configuration file

    Returns:
        error (bool): A flag used to represent if the config initialization failed
    """
    
    app.logger.info(separator_short)
    app.logger.info("Initializing app configuration")
    
    import configparser
    from lib.config import app_config

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

    return False
    

def initialize_app_version(app: Flask):
    """Initialize the application version

    Args:
        app (Flask): Flask app object
    """
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
    #from lib.prometheus import METRIC_APP_VERSION 
    #METRIC_APP_VERSION.info({'version': kubedash_version})
    from flask_prometheus_metrics import register_metrics
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

    app.logger.info("Initializing app Logo\n" + separator_long + "\n" + LOGO + "\n" + separator_long)  # Use logger instead of print
    app.logger.info("Running in %s mode" % app.config['ENV'])


def initialize_app_database(app: Flask, filename: str):
    """Initialize the database

    Args:
        app (Flask): Flask app object
        filename (str): Name of the main file to find the database file
    """
    app.logger.info("Initialize Database:")
    
    """Get Database Configuration"""
    app.logger.info("   Get Database Configuration")    
    app.config['SESSION_SQLALCHEMY'] = db
    
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
            app.logger.warning("   Falling back to SQLite database")
            basedir = os.path.abspath(os.path.dirname(filename))
            sqlite_url =  "sqlite:///"+basedir+"/database/"+ app.config['ENV'] +".db"
            app.config['SQLALCHEMY_DATABASE_URI'] = sqlite_url
            database_type = 'sqlite3'
            
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
        
        sess.init_app(app)
         
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
            app.logger.info(separator_short)
            
            # Print separator_long before migration runs (only in 'db' mode)
            # Use stderr to match Alembic's output stream for proper ordering
            if len(sys.argv) > 1 and sys.argv[1] == 'db':
                sys.stderr.write(separator_long + '\n')
                sys.stderr.flush()
            
            if sys.argv[1] != 'cli' and sys.argv[1] != 'db':
                oidc_init(app.config['kubedash.ini'])
                k8s_config_int(app.config['kubedash.ini'])
                if k8sGetClusterStatus():
                    k8s_roles_init()
                    
def initialize_app_swagger(app: Flask):
    """Initialize Swagger UI

    Args:
        app (Flask): Flask app object
    """
    app.logger.info("Initialize Swagger UI")
    api_description = """
KubeDash REST API Documentation

This API provides programmatic access to KubeDash functionality including:
- Kubernetes resource management (pods, deployments, services, etc.)
- Cluster metrics and monitoring
- User and role management
- Application settings and configuration
- Plugin resources (Flux, Gateway API, Cert Manager, etc.)

## Authentication

Most endpoints require authentication via Flask-Login session cookies.
Some endpoints may support Bearer token authentication.

## Base URL

All API endpoints are prefixed with `/api/v1/`

## Response Format

All responses follow a consistent format:
```json
{
    "data": {...},
    "metadata": {
        "count": 10,
        "namespace": "default"
    }
}
```

## Error Format

Errors follow this format:
```json
{
    "error": "Error type",
    "message": "Human-readable error message"
}
```
"""
    
    app.config.update({
        "API_TITLE": "KubeDash API",
        "API_VERSION": "v1",
        "API_DESCRIPTION": api_description,
        "OPENAPI_VERSION": "3.0.2",
        "OPENAPI_URL_PREFIX": "/api",                       # OpenAPI served under /api/
        "OPENAPI_SWAGGER_UI_PATH": "/swagger-ui",           # relative to URL_PREFIX → /api/swagger-ui
        "OPENAPI_SWAGGER_UI_URL": "/api/swagger-ui/",       # your local static files
        "OPENAPI_REDOC_PATH": "/redoc",                    # ReDoc UI path → /api/redoc
        "OPENAPI_REDOC_URL": "/api/redoc/",                # ReDoc UI URL
        "OPENAPI_JSON_PATH": "/openapi.json",               # OpenAPI JSON spec → /api/openapi.json
        "OPENAPI_RAPIDOC_PATH": "/rapidoc",                 # RapiDoc UI path → /api/rapidoc
        "OPENAPI_RAPIDOC_URL": "/api/rapidoc/",             # RapiDoc UI URL
    })
    api_doc.init_app(app)
    
    # Add additional metadata to spec after initialization
    # Access the spec's _spec dictionary to add contact and license
    if hasattr(api_doc.spec, '_spec'):
        spec_dict = api_doc.spec._spec
        if 'info' not in spec_dict:
            spec_dict['info'] = {}
        spec_dict['info']['contact'] = {
            "name": "KubeDash Support",
            "url": "https://github.com/kubedash/kubedash"
        }
        spec_dict['info']['license'] = {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        }
    
    # Add security scheme for session-based auth
    try:
        api_doc.spec.components.security_scheme("sessionAuth", {
            "type": "apiKey",
            "in": "cookie",
            "name": "session",
            "description": "Session-based authentication via Flask-Login"
        })
    except Exception as e:
        # If security scheme addition fails, log but don't crash
        app.logger.warning(f"Could not add security scheme: {e}")
    
    # Protect Swagger UI with flask-login
    # Use a before_request handler that checks authentication
    # We need to set prometheus metrics attributes to avoid middleware errors
    from flask_login import current_user
    from flask import request, redirect, url_for, Response
    import time
    
    @app.before_request
    def protect_swagger_ui():
        """Protect Swagger UI endpoints - require login"""
        # Check if the request is for the swagger-ui page (main page, not static files)
        # Static files are already protected by @login_required decorator in blueprint/api.py
        path = request.path.rstrip('/')
        if path == "/api/swagger-ui":
            if not current_user.is_authenticated:
                # Set prometheus metrics start time to avoid AttributeError in after_request
                # This ensures the flask_prometheus_metrics middleware doesn't fail
                if not hasattr(request, '_prometheus_metrics_request_start_time'):
                    request._prometheus_metrics_request_start_time = time.time()
                
                # Create a redirect response
                login_url = url_for('auth.login')
                # Add next parameter to redirect back to swagger-ui after login
                if request.url:
                    from urllib.parse import urlencode
                    login_url += '?' + urlencode({'next': request.url})
                # Return a proper Response object
                return Response(
                    status=302,
                    headers={'Location': login_url}
                )

def initialize_blueprints(app: Flask):
    """Initialize blueprints"""
    from blueprint.api_base import api_bp  # Main API blueprint (ping, health, debug)
    from blueprint.api import api_v1_bp  # API v1 blueprint (all resource endpoints)
    from blueprint.auth import auth_bp
    from blueprint.cluster import cluster_bp
    from blueprint.cluster_permission import cluster_permission_bp
    from blueprint.dashboard import dashboard_bp
    from blueprint.extension_api import extension_api_bp
    from blueprint.metrics import metrics_bp
    from blueprint.network import network_bp
    from blueprint.other_resources import other_resources_bp
    from blueprint.security import security_bp
    from blueprint.settings import settings_bp, sso_bp
    from blueprint.storage import storage_bp
    from blueprint.user import users_bp
    from blueprint.workload import workload_bp
    from blueprint.history import history_bp


    app.logger.info("Initialize blueprints")
    #app.register_blueprint(api_bp)
    api_doc.register_blueprint(api_bp)  # Main API blueprint (ping, health, debug)
    api_doc.register_blueprint(api_v1_bp)  # API v1 blueprint (all resource endpoints)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(history_bp)
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(sso_bp)
    
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(cluster_permission_bp)
    app.register_blueprint(cluster_bp)
    app.register_blueprint(workload_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(storage_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(other_resources_bp)
    app.register_blueprint(settings_bp)
    
    # Kubernetes Extension API Server blueprint
    app.logger.info("Initialize Extension API blueprint")
    api_doc.register_blueprint(extension_api_bp)
    
    # Root-level endpoints for Kubernetes API aggregation (openapi, healthz)
    from blueprint.extension_root import extension_root_bp
    app.register_blueprint(extension_root_bp)    

def initialize_commands(app: Flask):
    """Initialize commands"""
    from lib.commands import cli 
    app.register_blueprint(cli)
    
def initialize_app_tracing(app: Flask):
    """Initialize OpenTelemetry tracing
    
    Args:
        app (Flask): Flask instance

    Returns:
        jaeger_enabled (global): True if tracing is enabled
    """
    if not bool_var_test(app.config['kubedash.ini'].get('monitoring', 'jaeger_enabled')):
        return False
    
    jaeger_url = app.config['kubedash.ini'].get('monitoring', 'jaeger_http_endpoint')
    
    # 1. First setup exporter
    from lib.opentelemetry import init_opentelemetry_exporter
    if not init_opentelemetry_exporter(app, jaeger_url):
        return False
    
    # 2. Then initialize instrumentors
    initialize_instrumentors(app)
    
    # 3. Add additional span enrichment
    @app.before_request
    def enrich_spans():
        if has_request_context() and hasattr(g, 'correlation_id'):
            span = trace.get_current_span()
            if span.is_recording():
                span.set_attribute("correlation_id", g.correlation_id)
                span.set_attribute("http.url", request.url)
                span.set_attribute("http.method", request.method)
    
    return True
     
def initialize_app_caching(app: Flask):
    """Initialize caching with Redis or Redis Cluster. If Redis is not available, fallback to SimpleCache.

    Args:
        app (Flask): Flask app object
    """
    import os
    from lib.cache import cache
    from lib.cache import cached_base, cached_base2

    # Check if caching is disabled via environment variable
    disable_cache = os.getenv('KUBEDASH_DISABLE_CACHE', 'false').lower() in ('true', '1', 'yes', 'on')
    if disable_cache:
        app.logger.info("Caching disabled via KUBEDASH_DISABLE_CACHE environment variable")
        app.config['CACHE_TYPE'] = 'NullCache'
        cache.init_app(app)
        app.cache = cache
        return

    ini = app.config['kubedash.ini']
    redis_enabled = ini.get('remote_cache', 'redis_enabled', fallback='none').lower() == 'true'
    cluster_enabled = ini.get('remote_cache', 'cluster_enabled', fallback='false').lower() == 'true'

    redis_port = int(ini.get('remote_cache', 'redis_port', fallback='6379'))
    redis_password = ini.get('remote_cache', 'redis_password', fallback=None) or None
    redis_db = int(ini.get('remote_cache', 'redis_db', fallback='0'))

    cache_ready = False

    if redis_enabled:       
        if cluster_enabled:
            # Parse cluster startup nodes
            startup_nodes_raw = ini.get('remote_cache', 'cluster_startup_nodes', fallback='')
            startup_nodes = [{'host': host.strip(), 'port': redis_port} for host in startup_nodes_raw.split(',') if host.strip()]

            try:
                test_cluster = RedisCluster(startup_nodes=startup_nodes, decode_responses=True, password=redis_password, socket_timeout=2)
                test_cluster.ping()
                app.logger.info("Redis Cluster connection established.")

                app.config['CACHE_TYPE'] = 'RedisClusterCache'
                app.config['CACHE_REDIS_CLUSTER_STARTUP_NODES'] = startup_nodes
                app.config['CACHE_REDIS_PASSWORD'] = redis_password
                cache_ready = True
            except (AuthenticationError, ConnectionError, RedisError) as e:
                app.logger.error(f"Redis Cluster connection failed: {e}")
            except Exception as e:
                app.logger.exception(f"Unexpected error with Redis Cluster: {e}")

        else:
            # Standalone Redis
            redis_host = ini.get('remote_cache', 'redis_host', fallback='127.0.0.1')
            endpoint = f"{redis_host}:{redis_port}"

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((redis_host, redis_port))
                sock.close()

                if result == 0:
                    # Test Redis connection - use socket_keepalive to avoid eventlet greenio issues
                    # when running in restricted security contexts
                    test_redis = redis.StrictRedis(
                        host=redis_host,
                        port=redis_port,
                        db=redis_db,
                        password=redis_password,
                        socket_connect_timeout=2,
                        socket_keepalive=True,
                        socket_keepalive_options={}
                    )
                    test_redis.ping()
                    app.logger.info(f"Redis connection established at {endpoint}")

                    app.config['CACHE_TYPE'] = 'RedisCache'
                    app.config['CACHE_REDIS_HOST'] = redis_host
                    app.config['CACHE_REDIS_PORT'] = redis_port
                    app.config['CACHE_REDIS_DB'] = redis_db
                    app.config['CACHE_REDIS_PASSWORD'] = redis_password
                    # Configure Redis to avoid eventlet greenio issues in restricted environments
                    app.config['CACHE_REDIS_SOCKET_KEEPALIVE'] = True
                    cache_ready = True
                else:
                    app.logger.error(f"Cannot connect to Redis socket at {endpoint}")
            except (AuthenticationError, ConnectionError, RedisError) as e:
                app.logger.error(f"Redis error at {endpoint}: {e}")
            except (PermissionError, OSError) as e:
                # Handle EPERM errors when eventlet greenio can't create sockets
                # due to restricted security contexts (e.g., dropped capabilities)
                if hasattr(e, 'errno') and e.errno == 1:  # EPERM
                    app.logger.warning(f"Redis connection blocked by security context (EPERM) at {endpoint}. "
                                     f"Falling back to in-memory cache. Error: {e}")
                else:
                    app.logger.error(f"Permission/system error connecting to Redis at {endpoint}: {e}")
            except Exception as e:
                app.logger.exception(f"Unexpected Redis error at {endpoint}: {e}")

    if not cache_ready:
        app.logger.warning("Using in-memory fallback cache (SimpleCache)")
        app.config['CACHE_TYPE'] = 'SimpleCache'

    # Optional cache durations
    app.config['SHORT_CACHE_TIMEOUT'] = int(ini.get('remote_cache', 'short_cache_time', fallback='60'))
    app.config['LONG_CACHE_TIMEOUT'] = int(ini.get('remote_cache', 'long_cache_time', fallback='900'))

    # Finalize cache setup
    cache.init_app(app)
    app.cache = cache

    # Post-initialization test: Verify cache actually works (catches EPERM at runtime)
    # This is important because eventlet's greenio may fail even if initial connection test passed
    if cache_ready and app.config.get('CACHE_TYPE') in ('RedisCache', 'RedisClusterCache'):
        try:
            # Test actual cache operations which will use eventlet's greenio if available
            test_key = '__kubedash_cache_test__'
            test_value = 'test'
            cache.set(test_key, test_value, timeout=1)
            retrieved = cache.get(test_key)
            if retrieved == test_value:
                cache.delete(test_key)
                app.logger.info("Cache operations verified successfully")
            else:
                app.logger.warning("Cache test failed: value mismatch. Falling back to SimpleCache")
                cache_ready = False
                app.config['CACHE_TYPE'] = 'SimpleCache'
        except (PermissionError, OSError) as e:
            # Handle EPERM errors when eventlet greenio can't create sockets at runtime
            if hasattr(e, 'errno') and e.errno == 1:  # EPERM
                app.logger.warning(f"Cache operations blocked by security context (EPERM). "
                                 f"Falling back to in-memory cache. Error: {e}")
                cache_ready = False
                app.config['CACHE_TYPE'] = 'SimpleCache'
                # Re-initialize cache with SimpleCache
                cache.init_app(app)
            else:
                app.logger.error(f"Permission/system error during cache operations: {e}")
                cache_ready = False
                app.config['CACHE_TYPE'] = 'SimpleCache'
                cache.init_app(app)
        except Exception as e:
            app.logger.warning(f"Cache test failed with unexpected error: {e}. Falling back to SimpleCache")
            cache_ready = False
            app.config['CACHE_TYPE'] = 'SimpleCache'
            cache.init_app(app)

    # Register decorators or cache-bound setup
    cached_base(app)
    cached_base2(app)
        
def initialize_instrumentors(app: Flask):
    """Initialize OpenTelemetry instrumentors with full correlation ID support
    
    Args:
        app (Flask): Flask app object
    """
    
    def get_correlation_id():
        """Unified correlation ID source with fallbacks"""
        # 1. First try Flask's g context (this will work after before_request)
        if has_request_context() and hasattr(g, 'correlation_id'):
            return g.correlation_id
        # 2. Check request headers (standard X-Request-ID header from ingress)
        if has_request_context() and 'X-Request-ID' in request.headers:
            return request.headers['X-Request-ID']
        ## 3. Generate new if none exists
        #return str(uuid.uuid4())
        return None

    def request_hook(span, environ):
        """Set correlation ID on spans, but don't generate new ones here"""
        # Don't generate new ID here - let before_request handle it
        if has_request_context() and 'X-Request-ID' in request.headers:
            span.set_attribute("correlation_id", request.headers['X-Request-ID'])
        
        # Mirror important HTTP attributes
        span.set_attribute("http.route", environ.get('PATH_INFO'))
        span.set_attribute("http.method", environ.get('REQUEST_METHOD'))
        HTTP_USER_AGENT = environ.get('HTTP_USER_AGENT')
        if HTTP_USER_AGENT:
            span.set_attribute("http.user_agent", HTTP_USER_AGENT)
        else:
            span.set_attribute("http.user_agent", "Unknown")

    def response_hook(span, status, response_headers):
        """Ensure request ID header exists"""
        correlation_id = get_correlation_id()
        
        if correlation_id:
            # Add header if not present (standard X-Request-ID header)
            if not any(k.lower() == 'x-request-id' for k, _ in response_headers):
                response_headers.append(('X-Request-ID', correlation_id))
        
        # Record final status
        span.set_attribute("http.status_code", status.split()[0])
        span.set_attribute("http.status_text", status)

    def log_hook(span, record):
        """Inject correlation ID into all log records"""
        record.correlation_id = get_correlation_id()
        
        # Additional useful context
        if has_request_context():
            record.endpoint = request.endpoint or ''
            record.path = request.path or ''
            record.method = request.method or ''
        else:
            record.endpoint = ''
            record.path = ''
            record.method = ''

    def redis_request_hook(span, instance, args, kwargs=None):
        """Updated Redis request hook with all arguments"""
        correlation_id = get_correlation_id()
        if correlation_id:
            span.set_attribute("correlation_id", correlation_id)
        
        # Handle both args and kwargs
        command_args = list(args)
        if kwargs:
            command_args.extend(f"{k}={v}" for k, v in kwargs.items())
        
        # Sanitize and truncate arguments
        sanitized_args = [
            arg.decode('utf-8') if isinstance(arg, bytes) else str(arg)
            for arg in command_args[:3]  # Only show first 3 args
        ]
        span.set_attribute("redis.command", " ".join(sanitized_args))
        
        # Add connection context
        if hasattr(instance, 'connection_pool'):
            span.set_attributes({
                "redis.connection.host": instance.connection_pool.connection_kwargs.get('host'),
                "redis.connection.port": instance.connection_pool.connection_kwargs.get('port'),
                "redis.connection.db": instance.connection_pool.connection_kwargs.get('db')
            })

    def redis_response_hook(span, instance, response):
        """Record response metrics"""
        if response is not None:
            response_size = len(response) if isinstance(response, (bytes, str, list, dict)) else 1
            span.set_attribute("redis.response_size", response_size)
        
        # Record cache hit/miss for GET operations
        if span.is_recording() and hasattr(span, 'name') and 'get' in span.name.lower():
            span.set_attribute("redis.cache_hit", response is not None)

    app_config = app.config['kubedash.ini']
    redis_enabled = app_config.get('remote_cache', 'redis_enabled', fallback='none').lower() == 'true'
    
    # Initialize Redis instrumentation
    if redis_enabled:
        app.logger.info("\tInitializing tracing for Redis")
        RedisInstrumentor().instrument(
            tracer_provider=trace.get_tracer_provider(),
            request_hook=redis_request_hook,
            response_hook=redis_response_hook,
            # Enable these for more detailed tracing
            enable_commenter=True,  # Adds trace context to Redis commands
            suppress_instrumentation=False,
            # Custom span names
            span_name_formatter=lambda cmd: f"redis.{cmd.decode('utf-8').split()[0].lower()}"
        )

    # Instrumentation with all hooks
    app.logger.info("\tInitializing tracing for Flask")
    FlaskInstrumentor().instrument_app(
        app,
        excluded_urls="/vendor/*,/css/*,/scss/*,/js/*,/img/*,/static/*,/favicon.ico",
        request_hook=request_hook,
        response_hook=response_hook,
        tracer_provider=trace.get_tracer_provider()
    )
    
    app.logger.info("\tInitializing tracing for SQLAlchemy")
    RequestsInstrumentor().instrument(
        tracer_provider=trace.get_tracer_provider()
    )
    
    app.logger.info("\tInitializing tracing for Logging")
    LoggingInstrumentor().instrument(
        set_logging_format=True,
        log_hook=log_hook,
        tracer_provider=trace.get_tracer_provider()
    )
    
    # Ensure WSGI middleware is properly instrumented
    app.logger.info("\tInitializing OpenTelemetry WSGI Middleware")
    app.wsgi_app = OpenTelemetryMiddleware(
        app.wsgi_app,
        tracer_provider=trace.get_tracer_provider()
    )



def initialize_app_plugins(app: Flask):
    """Initialize and register plugins for the Flask application dynamically.
    
    Scans the plugins directory and checks against [plugin_settings] in kubedash.ini.
    Each plugin must have:
    - A directory under plugins/
    - An __init__.py exposing a blueprint named {plugin_name}_bp
    """
    app.logger.info("Initializing Plugins Dynamically")
    app.logger.info(separator_short)
    
    # Initialize plugin system
    app.config["plugins"] = {}
    
    # Get the plugins directory
    plugins_dir = Path(__file__).parent.parent / "plugins"
    
    # Get all plugin folders
    plugin_folders = [f.name for f in plugins_dir.iterdir() if f.is_dir() and not f.name.startswith('__')]
    
    # Get plugin configuration (empty dict if section doesn't exist)
    try:
        plugin_config = app.config['kubedash.ini']['plugin_settings']
    except KeyError:
        plugin_config = {}
    
    # Process each discovered plugin
    app.logger.info("Plugins:")
    for plugin_name in plugin_folders:
        # Determine if plugin is enabled (default to False if not in config)
        is_enabled = plugin_config.getboolean(plugin_name, fallback=False)
        app.logger.info(f"  Plugin {plugin_name}: {is_enabled}")
        
        app.config["plugins"][plugin_name] = is_enabled
        
        try:
            if is_enabled:
                # Import the plugin module
                module = importlib.import_module(f"plugins.{plugin_name}")

                # Find and register the first matching blueprint
                bp_name = f"{plugin_name}_bp"
                if hasattr(module, bp_name):
                    blueprint = getattr(module, bp_name)
                    app.register_blueprint(blueprint)

                    try:
                        importlib.import_module(f"plugins.{plugin_name}.model")
                        app.logger.info("    Import Database Models")
                    except ImportError:
                        continue
                    except Exception as e:
                        app.logger.error(f"    Error loading models for {plugin_name}: {str(e)}")

                else:
                    app.logger.info(f"    No valid blueprint found for {plugin_name}")
                
        except ImportError as e:
            app.logger.error(f"  Failed to import plugin {plugin_name}: {str(e)}")
        except Exception as e:
            app.logger.error(f"  Error loading plugin {plugin_name}: {str(e)}")


def initialize_plugin_apis(app: Flask):
    """
    Dynamically discover and register plugin API blueprints.
    
    Scans the plugins directory for api.py files and registers them
    as sub-blueprints of a parent plugins blueprint, which is then
    registered with api_doc (similar to how api_v1_bp works).
    """
    from lib.components import csrf
    
    app.logger.info("Initializing Plugin APIs Dynamically")
    app.logger.info(separator_short)
    
    # Create a parent blueprint for all plugin APIs
    plugins_api_bp = Blueprint(
        "plugins_api",
        "plugins_api",
        url_prefix="/api/v1/plugins",
        description="Plugin APIs - Gateway API, Cert Manager, External Load Balancer, etc."
    )
    csrf.exempt(plugins_api_bp)
    
    # Get the plugins directory
    plugins_dir = Path(__file__).parent.parent / "plugins"
    
    # Get all plugin folders
    plugin_folders = [f.name for f in plugins_dir.iterdir() if f.is_dir() and not f.name.startswith('__')]
    
    # Process each discovered plugin
    app.logger.info("Plugin APIs:")
    for plugin_name in plugin_folders:
        # Check if plugin has an api.py file
        api_file = plugins_dir / plugin_name / "api.py"
        if not api_file.exists():
            continue
        
        try:
            # Try to import the API module
            api_module = importlib.import_module(f"plugins.{plugin_name}.api")
            
            # Try different naming conventions for the API blueprint
            # Pattern 1: {plugin_name}_api_bp (e.g., cert_manager_api_bp)
            bp_name = f"{plugin_name}_api_bp"
            # Pattern 2: For plugins with underscores, handle gateway_api -> gateway_api_api_bp
            if plugin_name == "gateway_api":
                bp_name = "gateway_api_api_bp"
            
            if hasattr(api_module, bp_name):
                api_blueprint = getattr(api_module, bp_name)
                # Exempt from CSRF protection (like extension_api_bp)
                csrf.exempt(api_blueprint)
                # Register as sub-blueprint of plugins_api_bp
                # The blueprint's url_prefix (e.g., /gateway-api) will be combined with /api/v1/plugins
                # Final path: /api/v1/plugins/gateway-api/...
                plugins_api_bp.register_blueprint(api_blueprint)
                app.logger.info(f"  Plugin API {plugin_name} Registered")
            else:
                # Try to find any blueprint ending with _api_bp
                found = False
                for attr_name in dir(api_module):
                    attr = getattr(api_module, attr_name)
                    if attr_name.endswith('_api_bp') and isinstance(attr, Blueprint):
                        api_blueprint = attr
                        # Exempt from CSRF protection (like extension_api_bp)
                        csrf.exempt(api_blueprint)
                        # Register as sub-blueprint of plugins_api_bp
                        plugins_api_bp.register_blueprint(api_blueprint)
                        app.logger.info(f"  Plugin API {plugin_name} Registered")
                        found = True
                        break
                if not found:
                    app.logger.warning(f"  Plugin API {plugin_name}: No API blueprint found (expected {bp_name})")
                    
        except ImportError as e:
            app.logger.error(f"  Failed to import plugin API {plugin_name}: {str(e)}")
        except Exception as e:
            app.logger.error(f"  Error loading plugin API {plugin_name}: {str(e)}")
    
    # Register the parent plugins blueprint with api_doc
    api_doc.register_blueprint(plugins_api_bp)
    app.logger.info(separator_short)


def add_custom_jinja2_filters(app: Flask):
    """Add custom Jinja2 filers."""
    app.logger.info("Adding custom Jinja2 filters")

    from lib.custom_jinja2 import j2_b64decode, j2_b64encode, split_uppercase, check_url_exists

    app.add_template_filter(j2_b64decode)
    app.add_template_filter(j2_b64encode)
    app.add_template_filter(split_uppercase)
    app.add_template_filter(check_url_exists)

def initialize_app_socket(app: Flask):
    """Initialize socketIO"""
    app.logger.info("Initialize SocketIO")
    socketio.init_app(app)
    # Store app reference for use in background threads
    from lib.components import set_flask_app
    set_flask_app(app)

def initialize_app_security(app: Flask):
    """Initialize application security options:

    Configs:
    - Login Manager
    - Tell Flask it is Behind a Proxy:
    - Content Security Policy - CSP
    - Cross-site request forgery - CSRF
    - cross origin resource sharing - CORS

    Args:
        app (Flask): Flask app object
    """
    app.logger.info("Initializing app Security")

    """Init Logging managger"""
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"

    from flask_talisman import Talisman
    import secrets
    
    # Generate CSP nonce for inline scripts (XSS protection)
    # This will be set per-request in before_request handler
    @app.before_request
    def set_csp_nonce():
        """Generate CSP nonce for inline scripts to prevent XSS"""
        from flask import g
        g.csp_nonce = secrets.token_urlsafe(16)
        # Make nonce available to templates
        app.jinja_env.globals['csp_nonce'] = g.csp_nonce
    
    # Build CSP policy - nonce will be added dynamically in after_request
    # Note: 'unsafe-eval' removed for better XSS protection
    # 'unsafe-inline' can be removed after migrating all inline scripts to use nonces
    # The nonce is added dynamically in after_request handler
    # Air-gapped: no CDNs; all assets served from 'self' (local static files)
    csp = {
        'default-src': "'self'",
        'font-src': ["'self'"],
        'style-src': [
            "'self'",
            "'unsafe-inline'",  # Still needed for CSS frameworks and inline style attributes
        ],
        'script-src': [
            "'self'",
            # Nonce will be added dynamically in after_request
        ],
        'connect-src': [
            "'self'",
            'wss:',  # WebSocket connections
            'ws:',   # WebSocket connections (dev)
        ],
        'img-src': ["'self'", 'data:'],
    }

    hsts = {
        'max-age': 31536000,
        'includeSubDomains': True
    }

    app.config['SECRET_KEY'] = os.urandom(34).hex()
    # add rootCA folder # MissingImplementation
    
    """Init Talisman"""
    app.talisman = Talisman(app)

    if app.config['ENV'] == 'production':
        from werkzeug.middleware.proxy_fix import ProxyFix 
        """Tell Flask it is Behind a Proxy"""
        app.wsgi_app = ProxyFix(
          app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
        )
        """Config Talisman"""
        app.talisman.force_https = True
        app.talisman.strict_transport_security = hsts

    else:
        """Config Talisman"""
        app.talisman.force_https = False
        
        
    """Init CSRF"""
    csrf.init_app(app)

    # Disable Talisman's CSP - we'll set it manually in after_request with nonces
    # Talisman processes CSP after our after_request handler, so we need to handle it ourselves
    app.talisman.content_security_policy = None
    app.talisman.x_xss_protection = True
    app.talisman.session_cookie_secure = True
    app.talisman.session_cookie_samesite = 'Lax'

    @app.after_request
    def set_security_headers(response):
        """Add security headers for response"""
        # Get the nonce from Flask's g context (set in before_request)
        from flask import g
        nonce_value = getattr(g, 'csp_nonce', None)
        
        # Relax security headers for embedded app pages to allow iframe embedding
        is_embedded_app = (
            request.endpoint and 
            (request.endpoint.startswith('app_catalog.') or 
             request.endpoint.startswith('iframe_proxy.'))
        )
        
        # CORS
        response.headers['Access-Control-Allow-Origin'] = request.root_url.rstrip(request.root_url[-1])
        response.headers['X-Permitted-Cross-Domain-Policies'] = "none"
        
        if is_embedded_app:
            # Relaxed headers for embedded applications
            response.headers['Cross-Origin-Resource-Policy'] = "cross-origin"
            # Don't set Cross-Origin-Embedder-Policy for embedded apps
            # Don't set Cross-Origin-Opener-Policy for embedded apps
            
            # Remove Talisman's CSP header and set a relaxed one for embedded apps
            # Embedded apps need more flexibility (blob workers, external frames, etc.)
            # Remove all CSP-related headers that Talisman might have set
            response.headers.pop('Content-Security-Policy', None)
            response.headers.pop('Content-Security-Policy-Report-Only', None)
            
            # Set relaxed CSP as a string (Talisman might override dict format)
            relaxed_csp_str = (
                "default-src 'self' 'unsafe-inline' 'unsafe-eval' blob: data: *; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: data: *; "
                "style-src 'self' 'unsafe-inline' *; "
                "img-src 'self' data: blob: *; "
                "font-src 'self' data: blob: *; "
                "connect-src 'self' wss: ws: *; "
                "frame-src 'self' *; "
                "worker-src 'self' blob: *; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self' *;"
            )
            
            response.headers['Content-Security-Policy'] = relaxed_csp_str
        else:
            # Strict headers for main application
            response.headers['Cross-Origin-Resource-Policy'] = "same-origin"
            response.headers['Cross-Origin-Embedder-Policy'] = "require-corp"
            response.headers['Cross-Origin-Opener-Policy'] = "same-origin"
            
            # Build CSP string with nonce support
            # All templates now use nonces - 'unsafe-inline' removed from script-src
            # 'unsafe-eval' already removed (prevents eval() and similar functions)
            # 
            # All inline scripts in templates now have nonce="{{ csp_nonce }}"
            # 'unsafe-inline' removed from script-src for better security
            
            if nonce_value:
                csp_parts = []
                csp_parts.append("default-src 'self'")
                csp_parts.append("font-src 'self'")
                csp_parts.append("style-src 'self' 'unsafe-inline'")
                # Air-gapped: script-src only 'self' and nonce (no CDNs)
                script_src = f"'self' 'nonce-{nonce_value}'"
                csp_parts.append(f"script-src {script_src}")
                
                csp_parts.append("connect-src 'self' wss: ws:")
                csp_parts.append("img-src 'self' data:")
                
                # Set the CSP header with nonce
                response.headers['Content-Security-Policy'] = "; ".join(csp_parts)
            else:
                # Fallback if nonce not available (shouldn't happen, but safety check)
                csp_parts = []
                csp_parts.append("default-src 'self'")
                csp_parts.append("font-src 'self'")
                csp_parts.append("style-src 'self' 'unsafe-inline'")
                csp_parts.append("script-src 'self' 'unsafe-inline'")
                csp_parts.append("connect-src 'self' wss: ws:")
                csp_parts.append("img-src 'self' data:")
                response.headers['Content-Security-Policy'] = "; ".join(csp_parts)
        
        response.headers["Access-Control-Max-Age"] = "600"

        # Cache
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache" # Deprecated
        response.headers["Expires"] = "0"

        return response
    
def initialize_workloadcachers(app: Flask):
    """
    Initialize and start background tasks for caching various Kubernetes workload resources.

    This function sets up periodic tasks to fetch and cache information about pods,
    deployments, statefulsets, daemonsets, and replicasets from all namespaces in the
    Kubernetes cluster. Each task runs every 900 seconds (15 minutes).

    Args:
        app (Flask): The Flask application instance, used to provide context for
                     the caching operations.

    Returns:
        None

    Note:
        This function starts multiple ThreadedTicker instances, each responsible
        for caching a specific type of Kubernetes resource. These tickers run
        in the background and update the cache at regular intervals.
    """
    pod_ticker = ThreadedTicker(
        interval_sec=900, 
        func=fetch_and_cache_pods_all_namespaces(app)
    )
    pod_ticker.start()

    deployment_ticker = ThreadedTicker(
        interval_sec=900, 
        func=fetch_and_cache_deployments_all_namespaces(app)
    )
    deployment_ticker.start()

    statefulset_ticker = ThreadedTicker(
        interval_sec=900, 
        func=fetch_and_cache_statefulsets_all_namespaces(app)
    )
    statefulset_ticker.start()

    daemonset_ticker = ThreadedTicker(
        interval_sec=900, 
        func=fetch_and_cache_daemonsets_all_namespaces(app)
    )
    daemonset_ticker.start()

    replicasets_ticker = ThreadedTicker(
        interval_sec=900, 
        func=fetch_and_cache_replicasets_all_namespaces(app)
    )
    replicasets_ticker.start()
