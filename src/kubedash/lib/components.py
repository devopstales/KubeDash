from flask_login import LoginManager
from flask_session import Session
from flask_socketio import SocketIO
from flask_smorest import Api
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from lib.helper_functions import get_logger

##############################################################
## Helpers
##############################################################

logger = get_logger()

##############################################################
## Initialize modules
##############################################################

login_manager = LoginManager()
login_manager.login_message_category = "warning"
db = SQLAlchemy()
sess = Session()
csrf = CSRFProtect()
socketio = SocketIO()
api_doc = Api()