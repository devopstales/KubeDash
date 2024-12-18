#!/usr/bin/env python3

from flask import Flask, render_template, request
import sys, logging, os

from lib_functions.components import db, sess, login_manager, csrf, socketio 
from lib_functions.helper_functions import bool_var_test, get_logger

from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor 

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
    from lib_functions.logfilters import NoMetrics, NoHealth, NoPing,  \
        NoSocketIoGet, NoSocketIoPost 
    
    logger = get_logger()

    if sys.argv[1] != 'cli' or sys.argv[1] != 'db':
        app.logger.info("Initialize logging")

    logging.getLogger("werkzeug").addFilter(NoMetrics())
    logging.getLogger("werkzeug").addFilter(NoHealth())
    logging.getLogger("werkzeug").addFilter(NoPing())
    logging.getLogger("werkzeug").addFilter(NoSocketIoGet()) 
    logging.getLogger("werkzeug").addFilter(NoSocketIoPost()) 
   
def initialize_app_confifuration(app: Flask, external_config_name: str) -> bool:
    """Initialize the configuration and return error if missing

    Args:
        app (Flask): Flask app object
        external_config_name (str): The name of the external configuration file

    Returns:
        error (bool): A flag used to represent if the config initialization failed
    """

    global jaeger_enable

    if os.path.isfile("kubedash.ini"):
        app.logger.info("Reading Config file")
        from lib_functions.config import app_config 
        import configparser

        config_ini = configparser.ConfigParser()
        config_ini.sections()
        config_ini.read('kubedash.ini')
        app.config['kubedash.ini'] = config_ini

        if external_config_name is not None:
            config_name = external_config_name
        else:
            config_name = config_ini.get('DEFAULT', 'app_mode', fallback='development')
        
        app.config.from_object(app_config[config_name])
        app.config['ENV'] = config_name

        #print(app.config['kubedash.ini'].sections())
        #print(app.config['kubedash.ini'].items('monitoring'))
        jaeger_enable = bool_var_test(app.config['kubedash.ini'].get('monitoring', 'jaeger_enabled'))
        
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
    from lib_functions.prometheus import METRIC_APP_VERSION 
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

def initialize_app_tracing(app: Flask):
    """Initialize OpenTelemetry tracing
    
    Args:
        app (Flask): Flask instance

    Returns:
        jaeger_enable (global): True if tracing is enabled
    """

    if jaeger_enable:
        from lib_functions.opentelemetry import init_opentelemetry_exporter 
        jaeger_base_url = app.config['kubedash.ini'].get('monitoring', 'jaeger_http_endpoint')
        init_opentelemetry_exporter(jaeger_base_url)

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
    if bool_var_test(app.config["plugins"]["gateway_api"]):
        from lib_plugins.gateway_api import gateway_api 
        app.register_blueprint(gateway_api)

    if bool_var_test(app.config["plugins"]["cert_manager"]):
        from lib_plugins.cert_manager import cm_routes 
        app.register_blueprint(cm_routes)

    if bool_var_test(app.config["plugins"]["external_loadbalancer"]):
        from lib_plugins.external_loadbalancer import exlb_routes 
        app.register_blueprint(exlb_routes)

def initialize_app_database(app: Flask):
    """Initialize the database

    Args:
        app (Flask): Flask app object
    """
    app.logger.info("Initialize Database")

    database_type = app.config['kubedash.ini'].get('database', 'type', fallback=None)
    if database_type == 'postgres':
        EXTERNAL_DATABASE_ENABLED = True
    else:
        EXTERNAL_DATABASE_ENABLED = False
    
    if EXTERNAL_DATABASE_ENABLED:
        SQLALCHEMY_DATABASE_HOST     = app.config['kubedash.ini'].get('database', 'host', fallback='localhost')
        SQLALCHEMY_DATABASE_DB       = app.config['kubedash.ini'].get('database', 'name', fallback='kubedash')
        SQLALCHEMY_DATABASE_USER     = app.config['kubedash.ini'].get('database', 'user', fallback='kubedash')
        SQLALCHEMY_DATABASE_PASSWORD = app.config['kubedash.ini'].get('database', 'password', fallback=None)

    app.config['SESSION_SQLALCHEMY'] = db

    # Fix: https://github.com/pallets-eco/flask-session/issues?q=is%3Aissue+%27Already+defined+in+this+MetaData+Instance%27
    db.metadata.clear()

    """Database mode"""
    if app.config['ENV'] == 'testing':
        basedir = os.path.abspath(os.path.dirname(__file__))
        SQLALCHEMY_DATABASE_URI = "sqlite:///"+basedir+"/database/"+ app.config['ENV'] +".db"
    elif EXTERNAL_DATABASE_ENABLED and SQLALCHEMY_DATABASE_USER and SQLALCHEMY_DATABASE_PASSWORD and SQLALCHEMY_DATABASE_HOST and SQLALCHEMY_DATABASE_DB:
        SQLALCHEMY_DATABASE_URI = "postgresql://%s:%s@%s/%s" % \
            (SQLALCHEMY_DATABASE_USER, SQLALCHEMY_DATABASE_PASSWORD, SQLALCHEMY_DATABASE_HOST, SQLALCHEMY_DATABASE_DB)
    else:
        basedir = os.path.abspath(os.path.dirname(__file__))
        SQLALCHEMY_DATABASE_URI = "sqlite:///"+basedir+"/database/"+ app.config['ENV'] +".db"
    
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI

    """Plugin Logging"""
    app.logger.info(separator_short)
    app.logger.info(" Starting Database:")
    app.logger.info("	Type:	%s" % database_type)
    app.logger.info(separator_short)

    """Init DB"""
    import flask_migrate 
    from sqlalchemy_utils import database_exists 
    from lib_functions.init_functions import init_db_test, db_init_roles, oidc_init, k8s_config_int, k8s_roles_init 

    migrate = flask_migrate.Migrate(app, db)
    db.init_app(app)
    if database_exists(SQLALCHEMY_DATABASE_URI):
        with app.app_context():
            if init_db_test(SQLALCHEMY_DATABASE_URI, EXTERNAL_DATABASE_ENABLED, database_type):
                SQLAlchemyInstrumentor().instrument(engine=db.engine)
                db_init_roles(app.config['kubedash.ini'])
            oidc_init(app.config['kubedash.ini'])
            k8s_config_int(app.config['kubedash.ini'])
            k8s_roles_init()

def initialize_blueprints(app: Flask):
    """Initialize blueprints"""
    from lib_routes.main import main 
    from lib_routes.accounts import accounts 
    from lib_routes.api import api 
    from lib_routes.dashboard import dashboard 
    from lib_routes.helm import helm 
    from lib_routes.limits import limits 
    from lib_routes.metrics import metrics 
    from lib_routes.namespaces import namespaces 
    from lib_routes.networks import networks 
    from lib_routes.nodes import nodes 
    from lib_routes.pods import pods 
    from lib_routes.registry import registry 
    from lib_routes.security import security 
    from lib_routes.sso import sso 
    from lib_routes.storages import storages 
    from lib_routes.workloads import workloads 

    app.logger.info("Initialize blueprints")

    app.register_blueprint(main)
    app.register_blueprint(accounts)
    app.register_blueprint(dashboard)
    app.register_blueprint(helm)
    app.register_blueprint(limits)
    app.register_blueprint(metrics)
    app.register_blueprint(namespaces)
    app.register_blueprint(networks)
    app.register_blueprint(nodes)
    app.register_blueprint(pods)
    app.register_blueprint(registry)
    app.register_blueprint(security)
    app.register_blueprint(sso)
    app.register_blueprint(storages)
    app.register_blueprint(workloads)
    app.register_blueprint(api)

    """Liveness and readiness probe"""
    from flask_healthz import healthz 
    from lib_functions.init_functions import connect_database 
    app.register_blueprint(healthz, url_prefix="/api/health")

    app.config.update(
        HEALTHZ = {
            "live":  "lib_routes.api.liveness",
            "ready": "lib_routes.api.readiness",
        }
    )

    """Swagger-UI"""
    from lib_routes.api import swaggerui_blueprint
    app.register_blueprint(swaggerui_blueprint)

def initialize_commands(app: Flask):
    """Initialize commands"""
    from lib_functions.commands import cli 
    app.register_blueprint(cli)


def add_custom_jinja2_filters(app: Flask):
    """Add custom Jinja2 filers."""
    app.logger.info("Adding custom Jinja2 filters")

    from lib_functions.jinja2_decoders import j2_b64decode, j2_b64encode, split_uppercase 

    app.add_template_filter(j2_b64decode)
    app.add_template_filter(j2_b64encode)
    app.add_template_filter(split_uppercase)

def initialize_app_session_and_socket(app: Flask):
    """Initialize session and socketIO"""
    app.logger.info("Initialize Session and SocketIO")

    sess.init_app(app)
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
    login_manager.login_view = "main.login"
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
        talisman.force_https = True
        talisman.strict_transport_security = hsts
    else:
        """Init Talisman"""
        talisman = Talisman(app)
        talisman.force_https = False

    talisman.content_security_policy = csp
    talisman.x_xss_protection = True
    talisman.session_cookie_secure = True
    talisman.session_cookie_samesite = 'Lax'

    """Init CSRF"""
    csrf.init_app(app)

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

def initialize_app_error_pages(app: Flask):
    """Initialize error pages pl 40x 50x"""

    @app.errorhandler(404)
    def page_not_found404(e):
        app.logger.error(e.description)
        return render_template('404.html.j2'), 404

    @app.errorhandler(404)
    def page_not_found404(e):
        app.logger.error(e.description)
        return render_template('404.html.j2'), 404

    @app.errorhandler(400)
    def page_not_found400(e):
        app.logger.error(e.description)
        return render_template(
            '400.html.j2',
            description = e.description,
            ), 400

    @app.errorhandler(500)
    def page_not_found500(e):
        app.logger.error(e.description)
        return render_template(
            '500.html.j2',
            description = e.description,
            ), 500
    
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
    FlaskInstrumentor().instrument_app(
        app,
        excluded_urls="/vendor/*,/css/*,/scss/*,/js/*,/img/*,/static/*,/favicon.ico"
    )
    RequestsInstrumentor().instrument()
    LoggingInstrumentor().instrument(set_logging_format=True)

    print(separator_long)
    if external_config_name is not None:
        error = initialize_app_confifuration(app, external_config_name)
    else:
        error = initialize_app_confifuration(app, None)

    initialize_app_logging(app)

    # manage cli commands
    if not error:
        if sys.argv[1] == 'cli':
            initialize_app_tracing(app)
            initialize_app_database(app)
            print(separator_long)
            initialize_commands(app)
        elif sys.argv[1] == 'db':
            initialize_app_tracing(app)
            initialize_app_database(app)
            print(separator_long)
        else:
            initialize_app_version(app)
            initialize_app_tracing(app)
            initialize_app_database(app)
            initialize_app_plugins(app)
            initialize_blueprints(app)
            initialize_app_session_and_socket(app)
            add_custom_jinja2_filters(app)
            initialize_app_security(app)
            initialize_app_error_pages(app)

            print(separator_long)

    return app

##############################################################
## Main Application variable for WSGI Like Gunicorn
##############################################################

app = create_app()