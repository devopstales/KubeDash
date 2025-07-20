from itsdangerous import base64_decode, base64_encode
from sqlalchemy import inspect

from lib.components import db

from .model import ApplicationCatalog

##############################################################
## Registry Server
##############################################################

def ApplicationCreate(application_name, application_url, application_icon, application_enabled=False):
    """Create a new application object in database
    
    Args:
        application_name (str):  Name of application
        application_url (str): URL of the application
        application_icon (str): base64 encoded icon of the application
        application_enabled (bool): Enable or disable application
    """
    application = ApplicationCatalog.query.filter_by(application_name=application_name).first()
    if application is None:
        application = ApplicationCatalog(
            application_name = application_name,
            application_enabled = application_enabled,
            application_url = application_url,
            application_icon = application_icon,
        )
        db.session.add(application)
        db.session.commit()
        
def ApplicationUpdate(application_name, application_url_old, application_url, application_icon, application_enabled=False):
    """Update application object in database
    
    Args:
        application_name (str):  Name of application
        application_url (str): URL of the application
        application_url_old (str): Old URL of the application
        application_icon (str): base64 encoded icon of the application
        application_enabled (bool): Enable or disable application
    """
    
    application = ApplicationCatalog.query.filter_by(registry_server_url=application_url_old).first()
    if application:
        application.application_name = application_name
        application.application_url = application_url
        application.application_icon = application_icon
        db.session.commit()

def ApplicationListGet() -> list:
    """Get all Application from database
    
    Returns:
        applications (list): list of Applications objects
    """
    applications = ApplicationCatalog.query.all()
    if applications:
        return applications
    else:
        return list()

def ApplicationGet(application_name):
    """Get application object from database
    
    Args:
        application_name (str): Name of the application

    Returns:
        application (Registry): Application object or None if not found
    """
    application = ApplicationCatalog.query.filter_by(application_name=application_name).first()
    if application:
        return application
    else:
        return None

def RegistryServerDelete(application_name):
    """Delete application object from database
    
    Args:
        application_name (str):  Url of the application
    """
    application = ApplicationCatalog.query.filter_by(application_name=application_name).first()
    if application:
        db.session.delete(application)
        db.session.commit()
