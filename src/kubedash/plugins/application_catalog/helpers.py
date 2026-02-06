"""
Helper functions for application catalog initialization and security policy updates.
"""

from urllib.parse import urlparse
from lib.helper_functions import get_logger, ErrorHandler
from .model import ApplicationCatalog
from .application import ApplicationCreate, ApplicationUpdate

logger = get_logger()


def application_links_init(app_config):
    """
    Initialize application catalog from kubedash.ini configuration.
    Reads [application_list] section and syncs with database.
    
    Args:
        app_config: Configuration object from kubedash.ini
    """
    try:
        if not hasattr(app_config, "has_section") or not app_config.has_section("application_list"):
            logger.info("No [application_list] section found in config")
            return
        
        section = app_config["application_list"]
        import re
        
        # Parse all application entries
        app_map = {}
        for key, value in section.items():
            match = re.match(r"app_(\d+)_(name|url|icon|embed|enable|enabled)$", key)
            if not match:
                continue
            index, field = match.groups()
            # Normalize 'enabled' to 'enable'
            if field == 'enabled':
                field = 'enable'
            app_map.setdefault(index, {})[field] = value
        
        # Sync with database
        from lib.components import db
        from sqlalchemy.exc import IntegrityError
        
        for index, data in app_map.items():
            app_name = data.get("name")
            app_url = data.get("url")
            
            if not app_name or not app_url:
                continue
            
            app_enabled = section.getboolean(f"app_{index}_enable", fallback=True)
            app_embedded = section.getboolean(f"app_{index}_embed", fallback=False)
            app_icon = data.get("icon", "")
            
            # Use no_autoflush to prevent premature flush during query
            with db.session.no_autoflush:
                # Check if application exists
                existing = ApplicationCatalog.query.filter_by(
                    application_name=app_name
                ).first()
                
                if existing:
                    # Update existing application
                    existing.application_url = app_url
                    existing.application_icon = app_icon if app_icon else None
                    existing.application_enabled = app_enabled
                    existing.application_embedded = app_embedded
                else:
                    # Create new application
                    new_app = ApplicationCatalog(
                        application_name=app_name,
                        application_url=app_url,
                        application_icon=app_icon if app_icon else None,
                        application_enabled=app_enabled,
                        application_embedded=app_embedded
                    )
                    db.session.add(new_app)
            
            # Commit each application individually to handle race conditions
            try:
                db.session.commit()
            except IntegrityError as e:
                # Handle race condition: another request might have inserted the same app
                db.session.rollback()
                # Try to update instead
                existing = ApplicationCatalog.query.filter_by(
                    application_name=app_name
                ).first()
                if existing:
                    existing.application_url = app_url
                    existing.application_icon = app_icon if app_icon else None
                    existing.application_enabled = app_enabled
                    existing.application_embedded = app_embedded
                    db.session.commit()
                else:
                    logger.warning(f"Failed to create or update application '{app_name}': {e}")
                    # Re-raise if it's not a duplicate key error
                    if "duplicate key" not in str(e).lower() and "unique constraint" not in str(e).lower():
                        raise
        
        logger.info(f"Initialized {len(app_map)} applications from config")
    except Exception as error:
        ErrorHandler(logger, error, f"Error initializing application links: {error}")


def update_security_policies(app, applications):
    """
    Update Content Security Policy (CSP) to allow embedding applications.
    
    Args:
        app: Flask application object
        applications: List of application dictionaries with 'url' and 'embed' keys
    """
    try:
        if not hasattr(app, 'talisman'):
            logger.warning("Talisman not initialized, cannot update CSP")
            return
        
        # Get embedded applications
        embedded_apps = [app_data for app_data in applications if app_data.get('embed', False)]
        
        if not embedded_apps:
            logger.info("No embedded applications found, CSP not updated")
            return
        
        # Extract domains from embedded application URLs
        domains = set()
        for app_data in embedded_apps:
            url = app_data.get('url', '')
            if url:
                try:
                    parsed = urlparse(url)
                    if parsed.scheme and parsed.netloc:
                        # Add the full origin (scheme + netloc)
                        domains.add(f"{parsed.scheme}://{parsed.netloc}")
                except Exception as e:
                    logger.warning(f"Failed to parse URL {url}: {e}")
        
        # Update CSP
        csp = app.talisman.content_security_policy.copy() if app.talisman.content_security_policy else {}
        
        # Initialize frame-src if not present
        if 'frame-src' not in csp:
            csp['frame-src'] = ["'self'"]
        elif isinstance(csp['frame-src'], str):
            csp['frame-src'] = [csp['frame-src']]
        
        # Add domains to frame-src
        if domains:
            # Ensure 'self' is included
            if "'self'" not in csp['frame-src']:
                csp['frame-src'].insert(0, "'self'")
            # Add application domains
            for domain in sorted(domains):
                if domain not in csp['frame-src']:
                    csp['frame-src'].append(domain)
        
        app.talisman.content_security_policy = csp
        logger.info(f"Updated CSP frame-src with {len(domains)} application domains")
        
    except Exception as error:
        ErrorHandler(logger, error, f"Error updating security policies: {error}")
