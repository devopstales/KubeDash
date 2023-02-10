#!/usr/bin/env python3

import os, logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

## the cli client use http not https
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
logging.captureWarnings(True)

# VARIABLES
SQL_PATH = "sqlite.db"

# FLASK
app = Flask(__name__, static_url_path='', static_folder='static')
app.secret_key = 'development'


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

if __name__== "__main__":
    if not os.path.exists(SQL_PATH):
        from functions.db import dbCreate
        dbCreate()
    app.run(port=8000,debug=True, use_reloader=False)
