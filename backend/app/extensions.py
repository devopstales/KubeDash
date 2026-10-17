from flask_migrate import Migrate
from flask_redis import FlaskRedis
from flask_smorest import Api
from flask_sqlalchemy import SQLAlchemy

api = Api()
db = SQLAlchemy()
migrate = Migrate()
# App-bound redis (flask-redis): init_app creates a fresh underlying client
# per app, so multiple create_app calls (conftest builds one app per test)
# never cross-bind clients.
redis_client = FlaskRedis(config_prefix="KUBEDASH_REDIS", strict=False)
