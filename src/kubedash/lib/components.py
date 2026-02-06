from flask_login import LoginManager
from flask_session import Session
from flask_socketio import SocketIO
from flask_smorest import Api
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache

from lib.helper_functions import get_logger
from lib.paths import KUBEDASH_ROOT, PROJECT_ROOT  # Re-export for backwards compatibility

##############################################################
## Helpers
##############################################################

logger = get_logger()

short_cache_time = 60
long_cache_time = 900

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

# Global reference to Flask app for use in background threads
# This will be set when socketio.init_app() is called
_flask_app = None

def set_flask_app(app):
    """Store Flask app instance for use in background threads"""
    global _flask_app
    _flask_app = app

def get_flask_app():
    """Get Flask app instance for use in background threads"""
    global _flask_app
    if _flask_app is not None:
        return _flask_app
    # Fallback: try to import from kubedash module
    try:
        from kubedash import app
        return app
    except (ImportError, AttributeError):
        raise RuntimeError("No Flask app instance available. App may not be initialized yet.")
