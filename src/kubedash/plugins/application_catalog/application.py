"""
Application catalog helper functions for database operations.
"""

from lib.helper_functions import get_logger, ErrorHandler
from .model import ApplicationCatalog

logger = get_logger()


def ApplicationGet(application_name):
    """
    Get an application by name from the database.
    
    Args:
        application_name (str): Name of the application
        
    Returns:
        ApplicationCatalog: Application object or None if not found
    """
    try:
        application = ApplicationCatalog.query.filter_by(
            application_name=application_name
        ).first()
        return application
    except Exception as error:
        ErrorHandler(logger, error, f"Error getting application {application_name}: {error}")
        return None


def ApplicationListGet(enabled_only=False):
    """
    Get all applications from the database.
    
    Args:
        enabled_only (bool): If True, only return enabled applications. Default: False (return all)
    
    Returns:
        list: List of ApplicationCatalog objects
    """
    try:
        if enabled_only:
            applications = ApplicationCatalog.query.filter_by(
                application_enabled=True
            ).all()
        else:
            applications = ApplicationCatalog.query.all()
        return applications
    except Exception as error:
        ErrorHandler(logger, error, f"Error getting application list: {error}")
        return []


def ApplicationCreate(application_name, application_url, application_icon=None, 
                     application_enabled=True, application_embedded=False):
    """
    Create a new application in the database.
    
    Args:
        application_name (str): Name of the application
        application_url (str): URL of the application
        application_icon (str, optional): Icon URL or base64
        application_enabled (bool): Whether the application is enabled
        application_embedded (bool): Whether the application should be embedded
        
    Returns:
        ApplicationCatalog: Created application object
        
    Raises:
        Exception: If application already exists or creation fails
    """
    try:
        # Check if application already exists
        existing = ApplicationCatalog.query.filter_by(
            application_name=application_name
        ).first()
        if existing:
            raise ValueError(f"Application '{application_name}' already exists")
        
        # Check if URL already exists
        existing_url = ApplicationCatalog.query.filter_by(
            application_url=application_url
        ).first()
        if existing_url:
            raise ValueError(f"Application URL '{application_url}' already exists")
        
        application = ApplicationCatalog(
            application_name=application_name,
            application_url=application_url,
            application_icon=application_icon,
            application_enabled=application_enabled,
            application_embedded=application_embedded
        )
        
        from lib.components import db
        db.session.add(application)
        db.session.commit()
        
        return application
    except Exception as error:
        from lib.components import db
        db.session.rollback()
        ErrorHandler(logger, error, f"Error creating application {application_name}: {error}")
        raise


def ApplicationUpdate(application_name_old, application_name, application_url, 
                      application_icon=None, application_enabled=True, 
                      application_embedded=False):
    """
    Update an existing application in the database.
    
    Args:
        application_name_old (str): Current name of the application
        application_name (str): New name of the application
        application_url (str): New URL of the application
        application_icon (str, optional): Icon URL or base64
        application_enabled (bool): Whether the application is enabled
        application_embedded (bool): Whether the application should be embedded
        
    Returns:
        ApplicationCatalog: Updated application object
        
    Raises:
        Exception: If application not found or update fails
    """
    try:
        application = ApplicationCatalog.query.filter_by(
            application_name=application_name_old
        ).first()
        
        if not application:
            raise ValueError(f"Application '{application_name_old}' not found")
        
        # Check if new name conflicts with existing application
        if application_name != application_name_old:
            existing = ApplicationCatalog.query.filter_by(
                application_name=application_name
            ).first()
            if existing:
                raise ValueError(f"Application '{application_name}' already exists")
        
        # Check if new URL conflicts with existing application
        if application_url != application.application_url:
            existing_url = ApplicationCatalog.query.filter_by(
                application_url=application_url
            ).first()
            if existing_url:
                raise ValueError(f"Application URL '{application_url}' already exists")
        
        application.application_name = application_name
        application.application_url = application_url
        application.application_icon = application_icon
        application.application_enabled = application_enabled
        application.application_embedded = application_embedded
        
        from lib.components import db
        db.session.commit()
        
        return application
    except Exception as error:
        from lib.components import db
        db.session.rollback()
        ErrorHandler(logger, error, f"Error updating application {application_name_old}: {error}")
        raise


def ApplicationDelete(application_name):
    """
    Delete an application from the database.
    
    Args:
        application_name (str): Name of the application to delete
        
    Returns:
        bool: True if deletion was successful
        
    Raises:
        Exception: If application not found or deletion fails
    """
    try:
        application = ApplicationCatalog.query.filter_by(
            application_name=application_name
        ).first()
        
        if not application:
            raise ValueError(f"Application '{application_name}' not found")
        
        from lib.components import db
        db.session.delete(application)
        db.session.commit()
        
        return True
    except Exception as error:
        from lib.components import db
        db.session.rollback()
        ErrorHandler(logger, error, f"Error deleting application {application_name}: {error}")
        raise
