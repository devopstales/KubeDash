#!/usr/bin/env python3

import json
from functions.helper_functions import get_logger
from functions.components import db
from functions.user import SSOTokenUpdate
from flask_login import UserMixin
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy import PickleType, inspect
from requests_oauthlib import OAuth2Session

##############################################################
## functions
##############################################################

logger = get_logger(__name__)

class Openid(UserMixin, db.Model):
    __tablename__ = 'openid'
    id = db.Column(db.Integer, primary_key=True)
    oauth_server_uri = db.Column(db.Text, unique=True, nullable=False)
    client_id = db.Column(db.Text, nullable=False)
    client_secret = db.Column(db.Text, nullable=False)
    base_uri = db.Column(db.Text, nullable=False)
    scope = db.Column(MutableList.as_mutable(PickleType), default=[], nullable=False)

    def __repr__(self):
        return '<Server URL %r>' % self.oauth_server_uri

def SSOServerCreate(oauth_server_uri, client_id, client_secret, base_uri, scopes):
    sso = Openid.query.filter_by(oauth_server_uri=oauth_server_uri).first()
    sso_data = Openid(
        oauth_server_uri = oauth_server_uri,
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
    sso = Openid.query.get(1)
    if sso:
        return True, sso.oauth_server_uri
    else:
        return False, None

def SSOServerUpdate(oauth_server_uri_old, oauth_server_uri, client_id, client_secret, base_uri, scope):
    sso = Openid.query.filter_by(oauth_server_uri=oauth_server_uri_old).first()
    if sso:
        sso.oauth_server_uri = oauth_server_uri
        sso.client_id = client_id
        sso.client_secret = client_secret
        sso.base_uri = base_uri
        sso.scope = scope
        db.session.commit()

def SSOSererGet():
    inspector = inspect(db.engine)
    if inspector.has_table("openid"):
        return Openid.query.get(1)
    else:
        return None

def get_auth_server_info():
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
        SSOTokenUpdate(session['username'], json.dumps(token_new))

        user_token = session['oauth_token']
    else:
        user_token = None
    return user_token