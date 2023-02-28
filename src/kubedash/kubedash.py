#!/usr/bin/env python3

from flask import Flask
from flask_talisman import Talisman
from sqlalchemy_utils import database_exists

from functions.components import db, login_manager, csrf
from functions.routes import main
from functions.user import User, UserCreate, RoleCreate

csp = {
    'font-src': [
        '\'self\'',
        '*.gstatic.com'
    ],
    'style-src': [
        '\'self\'',
        'fonts.googleapis.com',
    ],
}

# Roles
roles = [
    "Admin",
    "User",
]

import os, logging
## the cli client use http not https
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
logging.captureWarnings(True)

def db_init():
    for r in roles:
        RoleCreate(r)
    UserCreate("admin", "admin", None, "Local", "Admin")

def create_app(database_uri="sqlite:///sqlite.db"):
    app = Flask(__name__, static_url_path='', static_folder='static')
    app.config["SQLALCHEMY_DATABASE_URI"] = database_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config["SECRET_KEY"] = "FesC9cBSuxakv9yN0vBY"
    app.config.update(
        DEBUG = True,
        SESSION_COOKIE_SECURE = True,
        REMEMBER_COOKIE_SECURE = True,
        SESSION_COOKIE_HTTPONLY = True,
        REMEMBER_COOKIE_HTTPONLY = True,
        SESSION_COOKIE_SAMESITE = "Lax",
        PERMANENT_SESSION_LIFETIME = 600,
    )

    db.init_app(app)
    if not database_exists(database_uri):
        with app.app_context():
            db.create_all()
            db_init()
    else:
        db_init()


    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.session_protection = "strong"

    csrf.init_app(app)

    talisman = Talisman(app, content_security_policy=csp)

    ##############################################################
    ## Custom jinja2 filter
    ##############################################################
    from functions.jinja2_decoders import j2_b64decode, j2_b64encode, split_uppercase

    app.add_template_filter(j2_b64decode)
    app.add_template_filter(j2_b64encode)
    app.add_template_filter(split_uppercase)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(user_id)
    
    app.register_blueprint(main)
    return app