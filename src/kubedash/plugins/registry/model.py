from flask_login import UserMixin

from lib.components import db


##############################################################
## Database Models
##############################################################
class Registry(UserMixin, db.Model):
    __tablename__ = 'registry'
    id = db.Column(db.Integer, primary_key=True)
    registry_server_url = db.Column(db.Text, unique=True, nullable=False)
    registry_server_port = db.Column(db.Text, nullable=False)
    registry_server_auth = db.Column(db.Boolean, nullable=False)
    registry_server_tls = db.Column(db.Boolean, nullable=False)
    insecure_tls = db.Column(db.Boolean, nullable=False)
    registry_server_auth_token = db.Column(db.String(80), nullable=True)

    def __repr__(self):
        return_data = {
            "registry_server_url": self.registry_server_url,
            "registry_server_port": self.registry_server_port,
            "registry_server_auth": self.registry_server_auth,
            "registry_server_tls": self.registry_server_tls,
            "insecure_tls": self.insecure_tls,
            "registry_server_auth_token": self.registry_server_auth_token,
        }
        return str(return_data)
    
class RegistryEvents(UserMixin, db.Model):
    __tablename__ = 'registry_events'
    id = db.Column(db.Integer, unique=True, primary_key=True)
    action = db.Column(db.String(4), unique=False, nullable=False)
    repository = db.Column(db.String(100), unique=False, nullable=False)
    tag = db.Column(db.String(100), unique=False, nullable=True)
    digest = db.Column(db.String(100), unique=False, nullable=False)
    ip = db.Column(db.String(15), unique=False, nullable=False)
    user = db.Column(db.String(50), unique=False, nullable=True)
    created = db.Column(db.DateTime, unique=False, nullable=False)

    def __repr__(self):
        return_data = {
            "action": self.action,
            "repository": self.repository,
            "tag": self.tag,
            "ip": self.ip,
            "user": self.user,
            "created": self.created,
        }
        return str(return_data)
