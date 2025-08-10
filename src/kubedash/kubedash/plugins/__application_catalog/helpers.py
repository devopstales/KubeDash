from logging import getLogger

import os
from flask import Flask, current_app
from .application import ApplicationCreate

#############################################################
## Variables
#############################################################

from kubedash.lib.initializers import (
    separator_long,
    separator_short
)

logger = getLogger(__name__)

#############################################################
## Helper Functions
##############################################################

flask_app = current_app

def init_applications(application_list=None):
    flask_app.logger.info(separator_short)
    flask_app.logger.info("Initializing application catalog with provided applications.")
    
    for application in application_list or []:
        APP_NAME = application.get('name', None)
        APP_URL = application.get('url', None)
        APP_ICON = application.get('icon', None)
        APP_ENABLED = application.get('enable', True)
        if APP_NAME and APP_URL:
            ApplicationCreate(
                flask_app,
                application_name=APP_NAME,
                application_url=APP_URL,
                application_icon=APP_ICON,
                application_enabled=APP_ENABLED,
            )
        else:
            logger.warning(f"Skipping application registration for {APP_NAME} due to missing URL or name.")
    flask_app.logger.info(separator_short)
            
def update_security_policies(app: Flask, applications: list):
    """
    Update all security headers in a coordinated way:
    - CSP (Content Security Policy)
    - COEP (Cross-Origin Embedder Policy)
    - COOP (Cross-Origin Opener Policy)
    - CORP (Cross-Origin Resource Policy)
    """
    if not hasattr(app, 'talisman'):
        logger.warning("Talisman not initialized, skipping security policy update.")
        return

    domains = set()
    for app_info in applications:
        if app_info.get('enable', False) and app_info.get('url'):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(app_info['url'])
                domains.add(app_info['url'])
                #if parsed.netloc:
                #    domain = parsed.scheme + "://" + parsed.netloc
                #    # Add without subdomain if applicable
                #    if domain.startswith('www.'):
                #        domains.add(domain[4:])
                #    else:
                #        domains.add(domain)
                #        
                #    logger.info("\n %s \n %s " % (app_info['url'],domain))

            except Exception as e:
                logger.error(f"Error parsing URL {app_info['url']}: {str(e)}")

    #new_csp = {
    #    'default-src': ["'self'"],
    #    'frame-src': ["'self'"] + list(domains),
    #    'connect-src': ["'self'"] + list(domains),
    #    'img-src': ["'self'", 'data:'] + list(domains),
    #    'script-src': ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com'],
    #    'style-src': ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
    #    'font-src': ["'self'", 'fonts.gstatic.com'],
    #    'base-uri': ["'self'"],
    #    'form-action': ["'self'"]
    #}
    
    # Get the existing CSP configuration
    existing_csp = getattr(app.talisman, 'content_security_policy', {})
    
    # Create a copy of the existing CSP to modify
    updated_csp = existing_csp.copy()
    
    # Update frame-src and child-src directives
    frame_src = ["'self'"] + sorted(list(domains))
    updated_csp['frame-src'] = frame_src
    updated_csp['child-src'] = frame_src  # For older browser support
    
    # Apply the updated CSP
    app.talisman.content_security_policy = updated_csp
    
    app.logger.info(f"Updated CSP frame-src with {len(domains)} additional domains")