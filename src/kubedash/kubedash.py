#!/usr/bin/env python3

import os, logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

## the cli client use http not https
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
logging.captureWarnings(True)

# VARIABLES
SQL_PATH = "sqlite.db"

# FLASK
app = Flask(__name__, static_url_path='', static_folder='static')

# secure
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
talisman = Talisman(app, content_security_policy=csp)
app.config.update(
    DEBUG = True,
    SECRET_KEY = "J0vb4r7Hi5cCksCovC6GNVXPj",
    SESSION_COOKIE_SECURE = True,
    REMEMBER_COOKIE_SECURE = True,
    SESSION_COOKIE_HTTPONLY = True,
    REMEMBER_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    PERMANENT_SESSION_LIFETIME = 600,
)


# DB
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///"+SQL_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)

# LoginManager
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

# csrf
csrf = CSRFProtect()
csrf.init_app(app)

# import routes
import functions.routes

# init db
from functions.db import init_db
init_db(SQL_PATH)

if __name__== "__main__":
    app.run(port=8000,debug=True, use_reloader=False)
