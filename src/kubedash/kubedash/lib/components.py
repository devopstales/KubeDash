from flask_login import LoginManager
from flask_session import Session
from flask_socketio import SocketIO
from flask_smorest import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache
from pathlib import Path

from kubedash.lib.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

logger = get_logger()

short_cache_time = 60
long_cache_time = 900

KUBEDASH_ROOT = Path(__file__).parent.parent
PROJECT_ROOT = KUBEDASH_ROOT.parent

##############################################################
## Initialize modules
##############################################################

login_manager = LoginManager()
login_manager.login_message_category = "warning"
db = SQLAlchemy()
migrate = Migrate()
sess = Session()
csrf = CSRFProtect()
socketio = SocketIO()
api_doc = Api()
cache = Cache()
