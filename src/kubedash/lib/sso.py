#!/usr/bin/env python3

import json

from flask_login import UserMixin
from opentelemetry import trace
from requests_oauthlib import OAuth2Session
from sqlalchemy import PickleType, inspect
from sqlalchemy.ext.mutable import MutableList

from lib.components import db
from lib.helper_functions import get_logger
from lib.user import SSOTokenUpdate

##############################################################
## variables
##############################################################

logger = get_logger()
tracer = trace.get_tracer(__name__)

##############################################################
## functions
##############################################################

class Openid(UserMixin, db.Model):
    __tablename__ = 'openid'
    id = db.Column(db.Integer, primary_key=True)
    oauth_server_uri = db.Column(db.Text, unique=True, nullable=False)
    oauth_server_ca = db.Column(db.Text, nullable=True)
    client_id = db.Column(db.Text, nullable=False)
    client_secret = db.Column(db.Text, nullable=False)
    base_uri = db.Column(db.Text, nullable=False)
    scope = db.Column(MutableList.as_mutable(PickleType), default=[], nullable=False)


    def __repr__(self):
        return '<Server URL %r>' % self.oauth_server_uri

def SSOServerCreate(oauth_server_uri, oauth_server_ca, client_id, client_secret, base_uri, scopes):
    """Create a SSOServer instance in database
    
    Args:
        oauth_server_uri (string): URL of the oauth server
        oauth_server_ca (string): CA certificate for the oauth server
        client_id (string): Client ID for the oauth client
        client_secret (string): Client secret for the oauth client
        base_uri (string): Base URI for the oauth server redirect
        scopes (list): List of scopes for the oauth client"""
    sso = Openid.query.filter_by(oauth_server_uri=oauth_server_uri).first()
    sso_data = Openid(
        oauth_server_uri = oauth_server_uri,
        oauth_server_ca = oauth_server_ca,
        client_id = client_id,
        client_secret = client_secret,
        base_uri = base_uri,
        scope = []
    )
    sso_data.scope = scopes
    if sso is None:
        db.session.add(sso_data)
        db.session.commit()

def SSOServerTest():
    """Test SSOServer
    
    Returns:
        status (bool): True if the SSO server exists, False otherwise
        uri (string): URL of the SSO server if test is successful, None otherwise
    """
    sso = Openid.query.get(1)
    if sso:
        return True, sso.oauth_server_uri
    else:
        return False, None

def SSOServerUpdate(oauth_server_uri_old, oauth_server_uri, oauth_server_ca, client_id, client_secret, base_uri, scope):
    """Update a SSOServer instance in database
    
    Args:
        oauth_server_uri_old (string): Old URL of the oauth server
        oauth_server_uri (string): New URL of the oauth server
        oauth_server_ca (string): CA certificate for the oauth server
        client_id (string): Client ID for the oauth client
        client_secret (string): Client secret for the oauth client
        base_uri (string): Base URI for the oauth server redirect
        scope (list): List of scopes for the oauth client
    """

    sso = Openid.query.filter_by(oauth_server_uri=oauth_server_uri_old).first()
    if sso:
        sso.oauth_server_uri = oauth_server_uri
        sso.oauth_server_ca = oauth_server_ca
        sso.client_id = client_id
        sso.client_secret = client_secret
        sso.base_uri = base_uri
        sso.scope = scope
        db.session.commit()
        
@tracer.start_as_current_span("get_logger")
def SSOSererGet():
    """Get a SSOServer instance from database
    
    Returns:
        Openid: SSOServer instance or None if not found
    """
    span = trace.get_current_span()
    inspector = inspect(db.engine)
    if inspector.has_table("openid"):
        if tracer and span.is_recording():
            span.add_event("log", {
                "log.severity": "info",
                "log.message": "openid exists",
            })
        return Openid.query.get(1)
    else:
        if tracer and span.is_recording():
            span.add_event("log", {
                "log.severity": "error",
                "log.message": "openid is missing",
            })
        return None

def get_auth_server_info():
    """Get OAuth2Session and Auth Server Info
    
    Returns:
        tuple: auth_server_info (dict), oauth (OAuth2Session)
    """
    ssoServer = SSOSererGet()
    redirect_uri = ssoServer.base_uri+"/callback"
    oauth = OAuth2Session(
        ssoServer.client_id,
        redirect_uri = redirect_uri,
        scope = ssoServer.scope
    )
    try:
        auth_server_info = oauth.get(
            f"{ssoServer.oauth_server_uri}/.well-known/openid-configuration",
            withhold_token=True,
            verify=False,
            timeout=1
        ).json()
    except Exception as error:
        auth_server_info = None
        logger.error('Cannot connect to identity provider: %s ' % error)

    return auth_server_info, oauth

def get_user_token(session):
    """Get user token from session

    Args:
        session: session
    
    Returns:
        string: user token or None if not found in session
    """
    if session['user_type'] == "OpenID":
        """Refreshing an OAuth 2 token using a refresh token.
        """
        ssoServer = SSOSererGet()
        auth_server_info, oauth = get_auth_server_info()

        # Get OAuth2Session
        oauth = OAuth2Session(
            ssoServer.client_id,
            redirect_uri = ssoServer.base_uri+"/callback",
            scope = ssoServer.scope
        )

        # Use OAuth2Session to refresh tokens
        token_new = oauth.refresh_token(
            token_url = auth_server_info["token_endpoint"],
            refresh_token = session['refresh_token'],
            client_id = ssoServer.client_id,
            client_secret = ssoServer.client_secret,
            verify=False,
            timeout=60,
        )

        # Store Updated Token Data in User session
        session['oauth_token']   = token_new
        session['refresh_token'] = token_new.get("refresh_token")

        # Store Updated Token Data in DB
        SSOTokenUpdate(session['user_name'], json.dumps(token_new))

        user_token = session['oauth_token']
    else:
        user_token = None
    return user_token
