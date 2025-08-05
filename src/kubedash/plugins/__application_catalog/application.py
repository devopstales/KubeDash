from itsdangerous import base64_decode, base64_encode
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from lib.components import db

from .model import ApplicationCatalog

##############################################################
## Registry Server
##############################################################

def ApplicationCreate(current_app, application_name, application_url, application_icon, application_enabled=True):
    """Create application object in database if it doesn't already exist
    
    Args:
        current_app: Flask application context
        application_name (str): Name of application
        application_url (str): URL of the application
        application_icon (str): base64 encoded icon of the application
        application_enabled (bool): Enable or disable application
    
    Returns:
        tuple: (success: bool, message: str, application: ApplicationCatalog or None)
    """
    try:
        # Use a transaction with isolation level to prevent race conditions
        db.session.begin_nested()
        
        # Check for existing application WITH LOCK
        existing_app = ApplicationCatalog.query.filter_by(application_url=application_url).with_for_update().first()
        
        if existing_app:
            db.session.rollback()  # Release the lock
            current_app.logger.info(f"\tApplication already exists: {application_name} at {application_url}")
            return True, "Application already exists", existing_app
        
        # Create new application
        new_app = ApplicationCatalog(
            application_name=application_name,
            application_url=application_url,
            application_icon=application_icon,
            application_enabled=application_enabled
        )
        db.session.add(new_app)
        db.session.commit()
        current_app.logger.info(f"\tRegistered application: {application_name} at {application_url}")
        return True, "Application created successfully", new_app
        
    except IntegrityError as e:
        db.session.rollback()
        current_app.logger.error(f"\tIntegrity error creating application {application_name}: {str(e)}")
        # Try to return the existing application if the error was due to a race condition
        existing = ApplicationCatalog.query.filter_by(application_url=application_url).first()
        if existing:
            return True, "Application exists (race condition)", existing
        return False, f"Database error: {str(e)}", None
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"\tError creating application {application_name}: {str(e)}")
        return False, f"Error creating application: {str(e)}", None
    
        
def ApplicationUpdate(current_app, application_name, application_url_old, application_url, application_icon, application_enabled=False):
    """Update application object in database
    
    Args:
        current_app: Flask application context
        application_name (str): Name of application
        application_url (str): New URL of the application
        application_url_old (str): Old URL of the application (to find the record)
        application_icon (str): base64 encoded icon of the application
        application_enabled (bool): Enable or disable application
    
    Returns:
        tuple: (success: bool, message: str)
    """
    # First find the application we want to update
    application = ApplicationCatalog.query.filter_by(application_url=application_url_old).first()
    
    if not application:
        return False, "Application not found"
    
    # Check if the new URL is different from the old one
    if application_url != application_url_old:
        # Check if another application already has this new URL
        existing_app = ApplicationCatalog.query.filter(
            ApplicationCatalog.application_url == application_url,
            ApplicationCatalog.id != application.id  # Exclude current application from check
        ).first()
        
        if existing_app:
            current_app.logger.warning(f"\tAnother application already uses URL: {application_url}")
            return False, f"Another application already uses URL: {application_url}"
    
    # Proceed with the update
    try:
        application.application_name = application_name
        application.application_url = application_url
        application.application_icon = application_icon
        application.application_enabled = application_enabled
        db.session.commit()
        current_app.logger.info(f"\tUpdate application: {application_name} at {application_url}")
        return True, "Application updated successfully"
    except Exception as e:
        db.session.rollback()
        return False, f"Error updating application: {str(e)}"

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
