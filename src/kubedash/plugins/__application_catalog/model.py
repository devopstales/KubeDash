from flask_login import UserMixin

from lib.components import db

##############################################################
## Database Models
##############################################################
class ApplicationCatalog(UserMixin, db.Model):
    __tablename__ = 'application_catalog'
    id = db.Column(db.Integer, primary_key=True)
    application_name = db.Column(db.String(100), unique=True, nullable=False)
    application_enabled = db.Column(db.Boolean, nullable=False, default=False)
    application_url = db.Column(db.String(200), nullable=False)
    application_icon = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return_data = {
            "application_name": self.application_name,
            "application_enabled": self.application_enabled,
            "application_url": self.application_url,
            "application_icon": self.application_icon,
        }
        return str(return_data)