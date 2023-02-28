from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

login_manager = LoginManager()
db = SQLAlchemy()
csrf = CSRFProtect()