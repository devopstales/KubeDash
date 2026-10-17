import redis as redis_lib
from flask_migrate import Migrate
from flask_smorest import Api  # type: ignore[import-untyped]
from flask_sqlalchemy import SQLAlchemy

api = Api()
db = SQLAlchemy()
migrate = Migrate()
redis_client = redis_lib.Redis(decode_responses=True)
