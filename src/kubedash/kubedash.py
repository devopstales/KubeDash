#!/usr/bin/env python3

import os, logging
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, render_template, request
from flask_talisman import Talisman
from flask_healthz import healthz, HealthError
from sqlalchemy_utils import database_exists
from sqlalchemy import create_engine, inspect
from flask_migrate import Migrate
from itsdangerous import base64_encode

import eventlet
import eventlet.wsgi

from functions.components import db, sess, login_manager, csrf, socketio
from functions.helper_functions import string2list, var_test
from functions.routes import routes
from functions.commands import commands
from functions.user import UserCreate, RoleCreate, UserTest, User
from functions.sso import SSOServerTest, SSOServerCreate, SSOServerUpdate
from functions.k8s import k8sServerConfigGet, k8sServerConfigCreate, k8sServerConfigUpdate, \
k8sUserRoleTemplateListGet, k8sUserClusterRoleTemplateListGet, k8sClusterRolesAdd
from config import app_config

from prometheus_client import Gauge

from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

##############################################################
## VAriables
##############################################################
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

# Roles
roles = [
    "Admin",
    "User",
]

"""App Version"""
global kubedash_version
kubedash_version = os.getenv('KUBEDASH_VERSION', "???")

##############################################################
## Promatehus Endpoint
##############################################################

METRIC_DB_CONNECTION = Gauge(
    'app_databse_connection',
    'Database Info',
    ['external', 'type']
)

METRIC_OIDC_CONFIG_UPDATE = Gauge(
    'oidc_config_update',
    "OIDC Config Update",
    ['issuer', 'client_id'],
)

METRIC_K8S_CONFIG_UPDATE = Gauge(
    'k8s_config_update',
    "K8S Config Update",
    ['cluster_name', 'api'],
)

##############################################################
## Helper Functions
##############################################################

class localFlask(Flask):
    def process_response(self, response):
        response.headers['server'] = "KubeDash " + kubedash_version

        # CORS
        response.headers['Access-Control-Allow-Origin'] = request.root_url.rstrip(request.root_url[-1])
        response.headers['X-Permitted-Cross-Domain-Policies'] = "none"
        response.headers['Cross-Origin-Resource-Policy'] = "same-origin"
        response.headers['Cross-Origin-Embedder-Policy'] = "require-corp"
        response.headers['Cross-Origin-Opener-Policy']   = "same-origin"
        response.headers['Cross-Origin-Resource-Policy'] = "same-origin"

        response.headers['Referrer-Policy'] = "no-referrer"
        response.headers['Clear-Site-Data'] = "*"

        # XSS
        response.headers['X-XSS-Protection'] = 0

        # HSTS
        if os.getenv('FLASK_CONFIG') == "production":
            response.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains; preload"

        # CSP
        response.headers['X-Frame-Options'] = "deny"
        response.headers['X-Content-Type-Options'] = "nosniff"

        # Cache
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache" # Deprecated
        response.headers["Expires"] = "0"

        super(localFlask, self).process_response(response)
        return(response)

"""Exclude requests logging"""
class NoPing(logging.Filter):
    def filter(self, record):
        return 'GET /api/ping' not in record.getMessage()
    
class NoHealth(logging.Filter):
    def filter(self, record):
        return 'GET /api/health' not in record.getMessage()

class NoMetrics(logging.Filter):
    def filter(self, record):
        return 'GET /metrics' not in record.getMessage()
   
class NoSocketIoGet(logging.Filter):
    def filter(self, record):
        return 'GET /socket.io' not in record.getMessage()
    
class NoSocketIoPost(logging.Filter):
    def filter(self, record):
        return 'POST /socket.io' not in record.getMessage()

"""Load kubedash.ini config file"""
def config_parser():
    if os.path.isfile("kubedash.ini"):
        logger.info("Reading config file")
        import configparser

        config = configparser.ConfigParser()
        config.sections()
        config.read('kubedash.ini')
        return False, config
    else:
        logger.warning("No local config file")
        return True, None

def db_init(error, config):
    for r in roles:
        RoleCreate(r)
    if error:
        UserCreate("admin", "admin", None, "Local", "Admin")
    else:
        admin_password = config.get('security', 'admin_password', fallback="admin")
        UserCreate("admin", admin_password, None, "Local", "Admin")

def connect_database():
    user = UserTest('Admin')
    if user:
        return True
    else:
        return False
    
def init_db_test(SQLALCHEMY_DATABASE_URI, EXTERNAL_DATABASE_ENABLED, database_type):
    engine = create_engine(SQLALCHEMY_DATABASE_URI)
    if inspect(engine).has_table("alembic_version"):
        METRIC_DB_CONNECTION.labels(EXTERNAL_DATABASE_ENABLED, database_type).set(1.0)
        return True
    else:
        METRIC_DB_CONNECTION.labels(EXTERNAL_DATABASE_ENABLED, database_type).set(0.0)
        return False
    
def oidc_init(error, config):
    # https://github.com/requests/requests-oauthlib/issues/387
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = "1"
    if not error:
        OIDC_ISSUER_URL   = config.get('sso_settings', 'issuer_url', fallback=None)
        OIDC_CLIENT_ID    = config.get('sso_settings', 'client_id', fallback=None)
        OIDC_SECRET       = config.get('sso_settings', 'secret', fallback=None)
        OIDC_SCOPE        = config.get('sso_settings', 'scope', fallback=None)
        OIDC_CALLBACK_URL = config.get('sso_settings', 'callback_url', fallback=None)
    else:
        OIDC_ISSUER_URL   = os.environ.get('OIDC_ISSUER_URL', None)
        OIDC_CLIENT_ID    = os.environ.get('OIDC_CLIENT_ID', None)
        OIDC_SECRET       = os.environ.get('OIDC_SECRET', None)
        OIDC_SCOPE        = os.environ.get('OIDC_SCOPE', None)
        OIDC_CALLBACK_URL = os.environ.get('OIDC_CALLBACK_URL', None)

    if OIDC_ISSUER_URL and OIDC_CLIENT_ID and OIDC_SECRET and OIDC_SCOPE and OIDC_CALLBACK_URL:
        oidc_test, OIDC_ISSUER_URL_OLD = SSOServerTest()
        if oidc_test:
            SSOServerUpdate(OIDC_ISSUER_URL_OLD, OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_SECRET, OIDC_CALLBACK_URL, string2list(OIDC_SCOPE))
            logger.info("OIDC Provider updated")
            METRIC_OIDC_CONFIG_UPDATE.labels(OIDC_ISSUER_URL, OIDC_CLIENT_ID).set(1)
        else:
            SSOServerCreate(OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_SECRET, OIDC_CALLBACK_URL, string2list(OIDC_SCOPE))
            logger.info("OIDC Provider created")
            METRIC_OIDC_CONFIG_UPDATE.labels(OIDC_ISSUER_URL, OIDC_CLIENT_ID).set(0)

def k8s_config_int(error, config):
    if not error:
        K8S_CLUSTER_NAME = config.get('k8s', 'cluster_name', fallback="k8s-main")
        K8S_API_SERVER   = config.get('k8s', 'api_server', fallback=None)
        try:
            K8S_API_CA       = config.get('k8s', 'api_ca', fallback=None)
        except Exception:
            pass
    else:
        K8S_CLUSTER_NAME = os.environ.get('K8S_CLUSTER_NAME', "k8s-main")
        K8S_API_SERVER   = os.environ.get('K8S_API_SERVER', None)
        try:
            K8S_API_CA       = os.environ.get('K8S_API_CA', None) # base64 encoded
        except Exception:
            pass

    if K8S_API_SERVER:
        try:
            K8S_API_CA
        except NameError:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", 'w') as cert_file:
                cert_file_data = cert_file.read()
                base64_encoded_data = str(base64_encode(cert_file_data), "UTF-8")
                K8S_API_CA = base64_encoded_data

        k8sConfig = k8sServerConfigGet()
        if k8sConfig is None:
            k8sServerConfigCreate(K8S_API_SERVER, K8S_CLUSTER_NAME, K8S_API_CA)
            logger.info("Kubernetes Config created")
            METRIC_K8S_CONFIG_UPDATE.labels(K8S_CLUSTER_NAME, K8S_API_SERVER).set(0)
        else:
            k8sServerConfigUpdate(k8sConfig.k8s_context, K8S_API_SERVER, K8S_CLUSTER_NAME, K8S_API_CA)
            logger.info("Kubernetes Config updated")
            METRIC_K8S_CONFIG_UPDATE.labels(K8S_CLUSTER_NAME, K8S_API_SERVER).set(1)
    else:
        logger.error("Missing Kubernetes Config: K8S_API_SERVER, K8S_API_CA")

def k8s_roles_init():
    user_role_template_list = k8sUserRoleTemplateListGet("Admin", None)
    user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet("Admin", None)

    if not bool(user_clusterRole_template_list) or not bool(user_role_template_list):
        logger.info("Kubernetes Roles created")
        k8sClusterRolesAdd()

##############################################################
## Main App creation Function
##############################################################

def create_app(config_name="development"):
    """Init App"""
    app = localFlask(__name__, static_url_path='', static_folder='static')

    if config_name == "production":
      """Tell Flask it is Behind a Proxy"""
      app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
      )

    """App Version"""
    global kubedash_version
    kubedash_version = os.getenv('KUBEDASH_VERSION')
    app.jinja_env.globals['kubedash_version'] = kubedash_version
    print("######################################################################")
    print("# KubeDash %s " % kubedash_version)
    print("######################################################################")

    """Init Logger"""
    global logger
    logger=logging.getLogger()
    logging.basicConfig(
            level="INFO",
            format='[%(asctime)s] %(name)s        %(levelname)s %(message)s'
        )
    
    """Parse Configfile"""
    error, config = config_parser()
    if not error:
        """App config"""
        config_name = config.get('DEFAULT', 'app_mode', fallback='development')
        app.config['SECRET_KEY'] = os.urandom(12).hex()

        """Database mode"""
        database_type = config.get('database', 'type', fallback='none')
        if database_type == 'postgres':
            EXTERNAL_DATABASE_ENABLED = True
        else:
            EXTERNAL_DATABASE_ENABLED = False
        
        if EXTERNAL_DATABASE_ENABLED:
            SQLALCHEMY_DATABASE_HOST     = config.get('database', 'host', fallback='localhost')
            SQLALCHEMY_DATABASE_DB       = config.get('database', 'name', fallback='kubedash')
            SQLALCHEMY_DATABASE_USER     = config.get('database', 'user', fallback='kubedash')
            SQLALCHEMY_DATABASE_PASSWORD = config.get('database', 'password', fallback=None)
    else:
        """App config"""
        if os.getenv('FLASK_CONFIG') == "production":
            config_name = "production"
            app.config['SECRET_KEY'] = os.urandom(12).hex()
        else:
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
            logging.captureWarnings(True)

        """Database mode"""
        EXTERNAL_DATABASE_ENABLED = var_test(os.getenv('EXTERNAL_DATABASE_ENABLED', "False"))
        if EXTERNAL_DATABASE_ENABLED:
            SQLALCHEMY_DATABASE_HOST     = os.environ.get('EXTERNAL_DATABASE_HOST', "localhost")
            SQLALCHEMY_DATABASE_DB       = os.environ.get('EXTERNAL_DATABASE_DB', "kubedash")
            SQLALCHEMY_DATABASE_USER     = os.environ.get('EXTERNAL_DATABASE_USER', "kubedash")
            SQLALCHEMY_DATABASE_PASSWORD = os.environ.get('EXTERNAL_DATABASE_PASSWORD', None)

    logger.info("Running in %s mode" % config_name)

    app.config.from_object(app_config[config_name])
    app.config['SESSION_SQLALCHEMY'] = db

    """Init FlaskInstrumentor"""
    # FlaskInstrumentor().instrument_app(app)

    """Database mode"""
    if EXTERNAL_DATABASE_ENABLED:
        if SQLALCHEMY_DATABASE_USER and SQLALCHEMY_DATABASE_PASSWORD and SQLALCHEMY_DATABASE_HOST and SQLALCHEMY_DATABASE_DB:
            SQLALCHEMY_DATABASE_URI = "postgresql://%s:%s@%s/%s" % (SQLALCHEMY_DATABASE_USER, SQLALCHEMY_DATABASE_PASSWORD, SQLALCHEMY_DATABASE_HOST, SQLALCHEMY_DATABASE_DB)
            app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
            database_type = 'postgres'
        else:
            basedir = os.path.abspath(os.path.dirname(__file__))
            SQLALCHEMY_DATABASE_URI = "sqlite:///"+basedir+"/database/"+config_name+".db"
            database_type = 'sqlite'
    else:
        basedir = os.path.abspath(os.path.dirname(__file__))
        SQLALCHEMY_DATABASE_URI = "sqlite:///"+basedir+"/database/"+config_name+".db"
        database_type = 'sqlite'

    """Init session"""
    sess.init_app(app)

    """Init DB"""
    migrate = Migrate(app, db)
    db.init_app(app)
    if database_exists(SQLALCHEMY_DATABASE_URI):
        with app.app_context():
            if init_db_test(SQLALCHEMY_DATABASE_URI, EXTERNAL_DATABASE_ENABLED, database_type):
                SQLAlchemyInstrumentor().instrument(engine=db.engine)
                db_init(error, config)
                oidc_init(error, config)
                k8s_config_int(error, config)
                k8s_roles_init()

    """Init Logging managger"""
    login_manager.init_app(app)
    login_manager.login_view = "routes.login"
    login_manager.session_protection = "strong"

    """Init CSRF"""
    csrf.init_app(app)

    """Init SocketIO"""
    socketio.init_app(app)

    """Init Talisman"""
    talisman = Talisman(app, content_security_policy=csp)
    ##############################################################
    ## Custom jinja2 filter
    ##############################################################
    from functions.jinja2_decoders import j2_b64decode, j2_b64encode, split_uppercase

    app.add_template_filter(j2_b64decode)
    app.add_template_filter(j2_b64encode)
    app.add_template_filter(split_uppercase)
    
    app.register_blueprint(routes)
    app.register_blueprint(commands)
    return app

app = create_app()

##############################################################
## Plugin configs
##############################################################
error, config = config_parser()
if error:
    app.config["plugins"] = {
            "registry":              var_test(os.getenv('PLUGIN_REGISTRY_ENABLED', "False")),
            "helm":                  var_test(os.getenv('PLUGIN_HELM_ENABLED', "True")),
            "gateway_api":           var_test(os.getenv('PLUGIN_GATEWAY_API_ENABLED', "False")),
            "cert_manager":          var_test(os.getenv('PLUGIN_CERT_MANAGER_ENABLED', "False")),
            "external_loadbalancer": var_test(os.getenv('PLUGIN_EXT_LOADBALANCER_ENABLED', "False")),
        }
else:
    app.config["plugins"] = {
            "registry":              config.getboolean('plugin_settings', 'registry', fallback=False),
            "helm":                  config.getboolean('plugin_settings', 'helm', fallback=True),
            "gateway_api":           config.getboolean('plugin_settings', 'gateway_api', fallback=False),
            "cert_manager":          config.getboolean('plugin_settings', 'cert_manager', fallback=True),
            "external_loadbalancer": config.getboolean('plugin_settings', 'external_loadbalancer', fallback=True),
        }

"""Plugin Logging"""
logger.info("###########################")
logger.info(" Starting Plugins:")
logger.info(" 	registry:	%s" % app.config["plugins"]["registry"])
logger.info("	helm:		%s" % app.config["plugins"]["helm"])
logger.info("	gateway_api:	%s" % app.config["plugins"]["gateway_api"])
logger.info("	cert_manager:	%s" % app.config["plugins"]["cert_manager"])
logger.info("	ext_lb: 	%s" % app.config["plugins"]["external_loadbalancer"])
logger.info("###########################")
print("######################################################################")


if app.config["plugins"]["gateway_api"]:
    from plugins.gateway_api import gateway_api
    app.register_blueprint(gateway_api)

if app.config["plugins"]["cert_manager"]:
    from plugins.cert_manager import cm_routes
    app.register_blueprint(cm_routes)

if app.config["plugins"]["external_loadbalancer"]:
    from plugins.external_loadbalancer import exlb_routes
    app.register_blueprint(exlb_routes)

##############################################################
## Liveness and redyes probe
##############################################################
app.register_blueprint(healthz, url_prefix="/api/health")

def liveness():
    pass

def readiness():
    try:
        connect_database()
    except Exception:
        raise HealthError("Can't connect to the database")

app.config.update(
    HEALTHZ = {
        "live":  app.name + ".liveness",
        "ready":  app.name + ".readiness",
    }
)

##############################################################
## Error Pages
##############################################################

@app.errorhandler(404)
def page_not_found404(e):
    logger.error(e.description)
    return render_template('404.html.j2'), 404

@app.errorhandler(404)
def page_not_found404(e):
    logger.error(e.description)
    return render_template('404.html.j2'), 404

@app.errorhandler(400)
def page_not_found400(e):
    logger.error(e.description)
    return render_template(
        '400.html.j2',
        description = e.description,
        ), 400

@app.errorhandler(500)
def page_not_found500(e):
    logger.error(e.description)
    return render_template(
        '500.html.j2',
        description = e.description,
        ), 500

##############################################################
## Error Pages
##############################################################

logging.getLogger("werkzeug").addFilter(NoMetrics())
logging.getLogger("werkzeug").addFilter(NoHealth())
logging.getLogger("werkzeug").addFilter(NoPing())
logging.getLogger("werkzeug").addFilter(NoSocketIoGet())
logging.getLogger("werkzeug").addFilter(NoSocketIoPost())

if __name__ == '__main__':
    if os.getenv('FLASK_CONFIG') == "production":
        eventlet.wsgi.server(eventlet.listen(('', 8000)), app, debug=False)
    else:
        eventlet.wsgi.server(eventlet.listen(('', 8000)), app, debug=True)

