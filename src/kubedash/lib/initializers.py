#!/usr/bin/env python3

import logging
import os
import sys
import socket
import redis
import importlib
from pathlib import Path
from redis.exceptions import AuthenticationError, ConnectionError, RedisError
from redis.cluster import RedisCluster
from sqlalchemy import create_engine, text

from flask import Flask, render_template, request

from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

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


separator_long = f"###################################################################################"
separator_short = f"#######################################"

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
    @app.errorhandler(404)
    def page_not_found404(e):
        app.logger.error(e.description)
        return render_template('errors/404.html.j2'), 404

    @app.errorhandler(400)
    def page_not_found400(e):
        app.logger.error(e.description)
        return render_template(
            'errors/400.html.j2',
            description = e.description,
            ), 400

    @app.errorhandler(500)
    def page_not_found500(e):
        app.logger.error(e.description)
        return render_template(
            'errors/500.html.j2',
            description = e.description,
            ), 500

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
    

    if os.path.isfile("kubedash.ini"):
        app.logger.info("Reading Config file")
        import configparser

        from lib.config import app_config

        config_ini = configparser.ConfigParser()
        config_ini.sections()
        config_ini.read('kubedash.ini')
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
    else:
        app.logger.error("Missing Local Configfile")
        return True
    

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
    from lib.prometheus import METRIC_APP_VERSION 
    METRIC_APP_VERSION.info({'version': kubedash_version})

    LOGO = f"""
{BLUE}   /$$   /$$           /$$                 /$$$$$$$                      /$$      
  | $$  /$$/          | $$                | $$__  $$                    | $$      
  | $$ /$$/  /$$   /$$| $$$$$$$   /$$$$$$ | $$  \ $$  /$$$$$$   /$$$$$$$| $$$$$$$ 
  | $$$$$/  | $$  | $$| $$__  $$ /$$__  $$| $$  | $$ |____  $$ /$$_____/| $$__  $$
  | $$  $$  | $$  | $$| $$  \ $$| $$$$$$$$| $$  | $$  /$$$$$$$|  $$$$$$ | $$  \ $$
  | $$\  $$ | $$  | $$| $$  | $$| $$_____/| $$  | $$ /$$__  $$ \____  $$| $$  | $$
  | $$ \  $$|  $$$$$$/| $$$$$$$/|  $$$$$$$| $$$$$$$/|  $$$$$$$ /$$$$$$$/| $$  | $$
  |__/  \__/ \______/ |_______/  \_______/|_______/  \_______/|_______/ |__/  |__/{RESET}
  version: {RED}{kubedash_version}{RESET}
"""

    print(separator_long)
    print(LOGO)
    print(separator_long)
    app.logger.info("Running in %s mode" % app.config['ENV'])


def initialize_app_database(app: Flask, filename: str):
    """Initialize the database

    Args:
        app (Flask): Flask app object
        filename (str): Name of the main file to find the database file
    """
    app.logger.info(separator_short)
    app.logger.info("Initialize Database:")
    
    """Get Database Configuration"""
    app.logger.info("   Get Database Configuration")    
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url(app, filename)
    database_type = app.config['kubedash.ini'].get('database', 'type', fallback=None)
    
    """Test Database Connection"""
    app.logger.info("   Test Database Connection")
    if database_type == 'postgres':
        try:
            engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception as e:
            app.logger.error(f"   Failed to connect to PostgreSQL database: {e}")
            basedir = os.path.abspath(os.path.dirname(filename))
            sqlite_url =  "sqlite:///"+basedir+"/database/"+ app.config['ENV'] +".db"
            app.config['SQLALCHEMY_DATABASE_URI'] = sqlite_url
            database_type = 'sqlite3'
            
    """Logging Database URL"""
    app.logger.info("   Database Configuration:")
    app.logger.info("   Database Type: %s" % database_type)
    app.logger.info("   Database URI: %s" % app.config['SQLALCHEMY_DATABASE_URI'])
    
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
        sess.init_app(app)
         
        """Create Tables"""
        app.logger.info("   Create Tables")
        app.logger.debug(f"Registered models: {db.metadata.tables.keys()}")  # Debugging output
        #db.create_all()
        
        if init_db_test(app):
            SQLAlchemyInstrumentor().instrument(engine=db.engine)
            db_init_roles(app.config['kubedash.ini'])
            
            """Add Contant to Tables"""
            app.logger.info("   Add Contant to Tables")
            app.logger.info(separator_short)
            
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
    app.config.update({
        "API_TITLE": "KubeDash API",
        "API_VERSION": "v1",
        "OPENAPI_VERSION": "3.0.2",
        "OPENAPI_URL_PREFIX": "/api",                       # OpenAPI served under /api/
        "OPENAPI_SWAGGER_UI_PATH": "/swagger-ui",           # relative to URL_PREFIX → /api/swagger-ui
        "OPENAPI_SWAGGER_UI_URL": "/api/swagger-ui/",  # your local static files
    })
    api_doc.init_app(app)

def initialize_blueprints(app: Flask):
    """Initialize blueprints"""
    from blueprint.api import api_bp
    from blueprint.auth import auth_bp
    from blueprint.cluster import cluster_bp
    from blueprint.cluster_permission import cluster_permission_bp
    from blueprint.dashboard import dashboard_bp
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
    api_doc.register_blueprint(api_bp)
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
    jaeger_enabled = bool_var_test(app.config['kubedash.ini'].get('monitoring', 'jaeger_enabled'))

    if jaeger_enabled:
        from lib.opentelemetry import init_opentelemetry_exporter 
        jaeger_base_url = app.config['kubedash.ini'].get('monitoring', 'jaeger_http_endpoint')
        init_opentelemetry_exporter(jaeger_base_url)
     
def initialize_app_caching(app: Flask):
    """Initialize caching with Redis or Redis Cluster. If Redis is not available, fallback to SimpleCache.

    Args:
        app (Flask): Flask app object
    """
    from lib.cache import cache
    from lib.cache import cached_base, cached_base2

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
                    test_redis = redis.StrictRedis(
                        host=redis_host,
                        port=redis_port,
                        db=redis_db,
                        password=redis_password,
                        socket_connect_timeout=2
                    )
                    test_redis.ping()
                    app.logger.info(f"Redis connection established at {endpoint}")

                    app.config['CACHE_TYPE'] = 'RedisCache'
                    app.config['CACHE_REDIS_HOST'] = redis_host
                    app.config['CACHE_REDIS_PORT'] = redis_port
                    app.config['CACHE_REDIS_DB'] = redis_db
                    app.config['CACHE_REDIS_PASSWORD'] = redis_password
                    cache_ready = True
                else:
                    app.logger.error(f"Cannot connect to Redis socket at {endpoint}")
            except (AuthenticationError, ConnectionError, RedisError) as e:
                app.logger.error(f"Redis error at {endpoint}: {e}")
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

    # Register decorators or cache-bound setup
    cached_base(app)
    cached_base2(app)
        
def inicialize_instrumentors(app: Flask):
    """Initialize OpenTelemetry instrumentors
    Args:
        app (Flask): Flask app object
    """
    FlaskInstrumentor().instrument_app(
        app,
        excluded_urls="/vendor/*,/css/*,/scss/*,/js/*,/img/*,/static/*,/favicon.ico"
    )
    RequestsInstrumentor().instrument()
    LoggingInstrumentor().instrument(set_logging_format=True)


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
    csp = {
        'font-src': [
            '\'self\'',
            '*.gstatic.com'
        ],
        'style-src': [
            '\'self\'',
            '\'unsafe-inline\'',
            '\'unsafe-eval\'',
            'fonts.googleapis.com',
            '*.cloudflare.com',
        ],
    }

    hsts = {
        'max-age': 31536000,
        'includeSubDomains': True
    }

    app.config['SECRET_KEY'] = os.urandom(12).hex()
    # add rootCA folder # MissingImplementation

    if app.config['ENV'] == 'production':
        from werkzeug.middleware.proxy_fix import ProxyFix 
        """Tell Flask it is Behind a Proxy"""
        app.wsgi_app = ProxyFix(
          app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
        )
        """Init Talisman"""
        talisman = Talisman(app)
        talisman.force_https = False
        talisman.strict_transport_security = hsts

    else:
        """Init Talisman"""
        talisman = Talisman(app)
        talisman.force_https = False
        
        
    """Init CSRF"""
    csrf.init_app(app)

    talisman.content_security_policy = csp
    talisman.x_xss_protection = True
    talisman.session_cookie_secure = True
    talisman.session_cookie_samesite = 'Lax'

    @app.after_request
    def set_security_headers(response):
        """Add security headers for response"""
        # CORS
        response.headers['Access-Control-Allow-Origin'] = request.root_url.rstrip(request.root_url[-1])
        response.headers['X-Permitted-Cross-Domain-Policies'] = "none"
        response.headers['Cross-Origin-Resource-Policy'] = "same-origin"
        response.headers['Cross-Origin-Embedder-Policy'] = "require-corp"
        response.headers['Cross-Origin-Opener-Policy']   = "same-origin"
        response.headers['Cross-Origin-Resource-Policy'] = "same-origin"
        response.headers["Access-Control-Max-Age"] = "600"
        response.headers['Clear-Site-Data'] = "*"

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