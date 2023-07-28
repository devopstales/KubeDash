#!/usr/bin/env python3

import os, logging
from flask import Flask
from flask_talisman import Talisman
from flask_healthz import healthz, HealthError
from sqlalchemy_utils import database_exists
from flask_migrate import Migrate

import eventlet
import eventlet.wsgi

from functions.components import db, sess, login_manager, csrf, socketio
from functions.routes import routes
from functions.commands import commands
from functions.user import UserCreate, RoleCreate, UserTest
from config import app_config

from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

csp = {
    'font-src': [
        '\'self\'',
        '*.gstatic.com'
    ],
    'style-src': [
        '\'self\'',
        'fonts.googleapis.com',
        '*.cloudflare.com',
    ],
}

# Roles
roles = [
    "Admin",
    "User",
]

class NoHealth(logging.Filter):
    def filter(self, record):
        return 'GET /health' not in record.getMessage()
    
class NoSocketIoGet(logging.Filter):
    def filter(self, record):
        return 'GET /socket.io' not in record.getMessage()
    
class NoSocketIoPost(logging.Filter):
    def filter(self, record):
        return 'POST /socket.io' not in record.getMessage()

def db_init():
    for r in roles:
        RoleCreate(r)
    UserCreate("admin", "admin", None, "Local", "Admin")

def connect_database():
    user = UserTest('Admin')
    if user:
        return True
    else:
        return False

def create_app(config_name="development"):
    """Init App"""
    app = Flask(__name__, static_url_path='', static_folder='static')

    """Init Logger"""
    global logger
    logger=logging.getLogger()
    logging.basicConfig(
            level="INFO",
            format='[%(asctime)s] %(name)s        %(levelname)s %(message)s'
        )

    """App config"""
    if os.getenv('FLASK_CONFIG') == "production":
        config_name = "production"
        app.config['SECRET_KEY'] = os.urandom(12).hex()
    else:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        logging.captureWarnings(True)
    logger.info("Running in %s mode" % config_name)

    app.config.from_object(app_config[config_name])
    app.config['SESSION_SQLALCHEMY'] = db

    """Init FlaskInstrumentor"""
    # FlaskInstrumentor().instrument_app(app)

    """Init session"""
    sess.init_app(app)

    """Init DB"""
    migrate = Migrate(app, db)
    db.init_app(app)
    basedir = os.path.abspath(os.path.dirname(__file__))
    if database_exists("sqlite:///"+basedir+"/database/"+config_name+".db"):
        with app.app_context():
            SQLAlchemyInstrumentor().instrument(engine=db.engine)
            db_init()

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
## Liveness and redyes probe
##############################################################
app.register_blueprint(healthz, url_prefix="/healthz")

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

logging.getLogger("werkzeug").addFilter(NoHealth())
logging.getLogger("werkzeug").addFilter(NoSocketIoGet())
logging.getLogger("werkzeug").addFilter(NoSocketIoPost())

if __name__ == '__main__':
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
    # socketio.run(app, port=8000)
    eventlet.wsgi.server(eventlet.listen(('', 8000)), app)
