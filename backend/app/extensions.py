from flask_migrate import Migrate
from flask_smorest import Api
from flask_sqlalchemy import SQLAlchemy

api = Api()
db = SQLAlchemy()
migrate = Migrate()
