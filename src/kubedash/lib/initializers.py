#!/usr/bin/env python3

import logging
import os
import sys

from flask import Flask, render_template, request

from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

from lib.components import csrf, db, migrate, login_manager, socketio, sess, api_doc
from lib.init_functions import get_database_url
from lib.helper_functions import bool_var_test, get_logger
from lib.k8s.server import k8sGetClusterStatus

separator_long = "###################################################################################"
separator_short = "#######################################"

##############################################################
## Helper Functions
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

def initialize_app_confifuration(app: Flask, external_config_name: str) -> bool:
    """Initialize the configuration and return error if missing

    Args:
        app (Flask): Flask app object
        external_config_name (str): The name of the external configuration file

    Returns:
        error (bool): A flag used to represent if the config initialization failed
    """

    global jaeger_enable
    global redis_enable

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

        #print(app.config['kubedash.ini'].sections())
        #print(app.config['kubedash.ini'].items('monitoring'))
        jaeger_enable = bool_var_test(app.config['kubedash.ini'].get('monitoring', 'jaeger_enabled'))
        redis_enable = bool_var_test(app.config['kubedash.ini'].get('remote_cache', 'redis_enabled'))
        
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
   /$$   /$$           /$$                 /$$$$$$$                      /$$      
  | $$  /$$/          | $$                | $$__  $$                    | $$      
  | $$ /$$/  /$$   /$$| $$$$$$$   /$$$$$$ | $$  \ $$  /$$$$$$   /$$$$$$$| $$$$$$$ 
  | $$$$$/  | $$  | $$| $$__  $$ /$$__  $$| $$  | $$ |____  $$ /$$_____/| $$__  $$
  | $$  $$  | $$  | $$| $$  \ $$| $$$$$$$$| $$  | $$  /$$$$$$$|  $$$$$$ | $$  \ $$
  | $$\  $$ | $$  | $$| $$  | $$| $$_____/| $$  | $$ /$$__  $$ \____  $$| $$  | $$
  | $$ \  $$|  $$$$$$/| $$$$$$$/|  $$$$$$$| $$$$$$$/|  $$$$$$$ /$$$$$$$/| $$  | $$
  |__/  \__/ \______/ |_______/  \_______/|_______/  \_______/|_______/ |__/  |__/
   version: {kubedash_version}
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
    app.logger.info("Initialize Database:")
    
    """Get Database Configuration"""
    app.logger.info("   Get Database Configuration")
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SQLALCHEMY_DATABASE_URI'] = get_database_url(app, filename)
    
    """Initialize SQLAlchemy"""
    app.logger.info("   Initialize SQLAlchemy")
    db.init_app(app)
    migrate.init_app(app, db)
    
    """Import External Database Models"""
    app.logger.info("   Import External Database Models")
    from plugins.registry import model
    
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
        "OPENAPI_SWAGGER_UI_URL": "/api/swagger-ui-dist/",  # your local static files
    })
    api_doc.init_app(app)

def initialize_blueprints(app: Flask):
    """Initialize blueprints"""
    from blueprint.api import api
    from blueprint.auth import auth
    from blueprint.cluster import cluster
    from blueprint.cluster_permission import cluster_permission
    from blueprint.dashboard import dashboard
    from blueprint.metrics import metrics
    from blueprint.network import network
    from blueprint.other_resources import other_resources
    from blueprint.security import security
    from blueprint.settings import settings, sso
    from blueprint.storage import storage
    from blueprint.user import users
    from blueprint.workload import workload
    

    app.logger.info("Initialize blueprints")
    #app.register_blueprint(api)
    api_doc.register_blueprint(api)
    app.register_blueprint(metrics)
    
    app.register_blueprint(auth)
    app.register_blueprint(sso)
    
    app.register_blueprint(dashboard)
    app.register_blueprint(users)
    app.register_blueprint(cluster_permission)
    app.register_blueprint(cluster)
    app.register_blueprint(workload)
    app.register_blueprint(network)
    app.register_blueprint(storage)
    app.register_blueprint(security)
    app.register_blueprint(other_resources)
    app.register_blueprint(settings)
    

def initialize_commands(app: Flask):
    """Initialize commands"""
    from lib.commands import cli 
    app.register_blueprint(cli)
    
def initialize_app_tracing(app: Flask):
    """Initialize OpenTelemetry tracing
    
    Args:
        app (Flask): Flask instance

    Returns:
        jaeger_enable (global): True if tracing is enabled
    """

    if jaeger_enable:
        from lib.opentelemetry import init_opentelemetry_exporter 
        jaeger_base_url = app.config['kubedash.ini'].get('monitoring', 'jaeger_http_endpoint')
        init_opentelemetry_exporter(jaeger_base_url)
        
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
    """Initialize Plugins

    Args:
        app (Flask): Flask app object
    """
    app.logger.info("Initialize Plugins")

    app.config["plugins"] = {
            "registry":              app.config['kubedash.ini'].getboolean('plugin_settings', 'registry', fallback=False),
            "helm":                  app.config['kubedash.ini'].getboolean('plugin_settings', 'helm', fallback=True),
            "gateway_api":           app.config['kubedash.ini'].getboolean('plugin_settings', 'gateway_api', fallback=False),
            "cert_manager":          app.config['kubedash.ini'].getboolean('plugin_settings', 'cert_manager', fallback=True),
            "external_loadbalancer": app.config['kubedash.ini'].getboolean('plugin_settings', 'external_loadbalancer', fallback=True),
        }
    
    """Plugin Logging"""
    app.logger.info(separator_short)
    app.logger.info(" Starting Plugins:")
    app.logger.info("	registry:	%s" % app.config["plugins"]["registry"])
    app.logger.info("	helm:		%s" % app.config["plugins"]["helm"])
    app.logger.info("	gateway_api:	%s" % app.config["plugins"]["gateway_api"])
    app.logger.info("	cert_manager:	%s" % app.config["plugins"]["cert_manager"])
    app.logger.info("	ext_lb: 	%s" % app.config["plugins"]["external_loadbalancer"])
    app.logger.info(separator_short)

    """Register Plugin Blueprints"""
    if bool_var_test(app.config["plugins"]["helm"]):
        from plugins.helm import helm 
        app.register_blueprint(helm)
        
    if bool_var_test(app.config["plugins"]["registry"]):
        from plugins.registry import registry 
        app.register_blueprint(registry)
    
    if bool_var_test(app.config["plugins"]["gateway_api"]):
        from plugins.gateway_api import gateway_api 
        app.register_blueprint(gateway_api)

    if bool_var_test(app.config["plugins"]["cert_manager"]):
        from plugins.cert_manager import cm_routes 
        app.register_blueprint(cm_routes)

    if bool_var_test(app.config["plugins"]["external_loadbalancer"]):
        from plugins.external_loadbalancer import exlb_routes 
        app.register_blueprint(exlb_routes)


def add_custom_jinja2_filters(app: Flask):
    """Add custom Jinja2 filers."""
    app.logger.info("Adding custom Jinja2 filters")

    from lib.jinja2_decoders import j2_b64decode, j2_b64encode, split_uppercase 

    app.add_template_filter(j2_b64decode)
    app.add_template_filter(j2_b64encode)
    app.add_template_filter(split_uppercase)

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