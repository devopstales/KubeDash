from flask_login import UserMixin

from lib.components import db

##############################################################
## Database Models
##############################################################
class ServiceCatalog(UserMixin, db.Model):
    __tablename__ = 'service_catalog'
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(100), unique=True, nullable=False)
    service_enabled = db.Column(db.Boolean, nullable=False, default=False)
    service_url = db.Column(db.String(200), nullable=False)
    service_icon = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return_data = {
            "service_name": self.service_name,
            "service_enabled": self.service_enabled,
            "service_url": self.service_url,
            "service_icon": self.service_icon,
        }
        return str(return_data)