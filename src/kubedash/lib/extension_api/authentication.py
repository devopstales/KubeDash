"""
Authentication module for Kubernetes Extension API Server.

This module handles authentication for the extension API server:
1. Front-proxy authentication (X-Remote-User headers from API server)
2. Bearer token authentication (TokenReview API)
3. Session authentication (Web UI)
"""

from contextlib import nullcontext
from typing import Optional

from flask import request
from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException
from opentelemetry.trace.status import Status, StatusCode

from . import logger, tracer
from lib.k8s.server import k8sClientConfigGet

##############################################################
## Types
##############################################################

class AuthenticatedUser:
    """Represents an authenticated user from TokenReview or front-proxy."""
    
    def __init__(self, username: str, uid: str = None, groups: list = None, extra: dict = None):
        self.username = username
        self.uid = uid or ""
        self.groups = groups or []
        self.extra = extra or {}
    
    def __repr__(self):
        return f"<AuthenticatedUser username={self.username} groups={self.groups}>"


##############################################################
## Front-Proxy Authentication (API Aggregation)
##############################################################

def authenticate_front_proxy(req: request) -> Optional[AuthenticatedUser]:
    """
    Authenticate using Kubernetes front-proxy headers.
    
    When Kubernetes API server proxies requests to extension API servers,
    it sends the authenticated user info via headers:
    - X-Remote-User: The username
    - X-Remote-Group: The user's groups (can appear multiple times)
    - X-Remote-Extra-*: Additional user info
    
    Args:
        req: Flask request object
        
    Returns:
        AuthenticatedUser: The authenticated user info, or None if headers not present
    """
    # Log all headers for debugging (only in debug mode)
    logger.debug(f"Request headers: {dict(req.headers)}")
    
    username = req.headers.get('X-Remote-User')
    
    if not username:
        logger.debug("No X-Remote-User header found")
        return None
    
    # Get all X-Remote-Group headers (can be multiple headers or comma-separated)
    raw_groups = req.headers.getlist('X-Remote-Group')
    groups = []
    for group_value in raw_groups:
        # Split comma-separated groups and strip whitespace
        for g in group_value.split(','):
            g = g.strip()
            if g and g not in groups:
                groups.append(g)
    
    # Get extra info from X-Remote-Extra-* headers
    extra = {}
    for key, value in req.headers:
        if key.lower().startswith('x-remote-extra-'):
            extra_key = key[15:]  # Remove 'X-Remote-Extra-' prefix
            if extra_key not in extra:
                extra[extra_key] = []
            extra[extra_key].append(value)
    
    logger.debug(f"Front-proxy auth: user={username}, groups={groups}")
    
    return AuthenticatedUser(
        username=username,
        uid="",  # Not provided by front-proxy
        groups=groups,
        extra=extra
    )


##############################################################
## Bearer Token Authentication (TokenReview)
##############################################################

def extract_bearer_token(req: request) -> Optional[str]:
    """
    Extract Bearer token from Authorization header.
    
    Args:
        req: Flask request object
        
    Returns:
        str: The bearer token, or None if not present
    """
    auth_header = req.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]  # Remove 'Bearer ' prefix
    return None


def authenticate_request(req: request) -> Optional[AuthenticatedUser]:
    """
    Authenticate a request by delegating to Kubernetes TokenReview API.
    
    This function extracts the bearer token from the request and validates it
    against the Kubernetes API server using TokenReview.
    
    Args:
        req: Flask request object
        
    Returns:
        AuthenticatedUser: The authenticated user info, or None if authentication failed
    """
    with tracer.start_as_current_span(
        "authenticate-request",
        attributes={
            "auth.method": "token_review",
        }
    ) if tracer else nullcontext() as span:
        
        token = extract_bearer_token(req)
        
        if not token:
            logger.debug("No bearer token found in request")
            if tracer and span and span.is_recording():
                span.set_attribute("auth.result", "no_token")
            return None
        
        try:
            # Use Admin role to perform TokenReview (requires cluster permissions)
            k8sClientConfigGet("Admin", None)
            
            # Create TokenReview request
            token_review = k8s_client.V1TokenReview(
                spec=k8s_client.V1TokenReviewSpec(token=token)
            )
            
            # Call TokenReview API
            api = k8s_client.AuthenticationV1Api()
            result = api.create_token_review(token_review, _request_timeout=5)
            
            if result.status.authenticated:
                user = AuthenticatedUser(
                    username=result.status.user.username,
                    uid=result.status.user.uid,
                    groups=result.status.user.groups or [],
                    extra=result.status.user.extra or {}
                )
                
                logger.debug(f"User authenticated: {user.username}")
                if tracer and span and span.is_recording():
                    span.set_attribute("auth.result", "success")
                    span.set_attribute("auth.user", user.username)
                    span.set_attribute("auth.groups", ",".join(user.groups))
                
                return user
            else:
                logger.debug(f"Token authentication failed: {result.status.error}")
                if tracer and span and span.is_recording():
                    span.set_attribute("auth.result", "failed")
                    span.set_attribute("auth.error", result.status.error or "unknown")
                return None
                
        except ApiException as e:
            logger.error(f"TokenReview API error: {e.status} - {e.reason}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, f"TokenReview failed: {e.reason}"))
            return None
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            if tracer and span and span.is_recording():
                span.set_status(Status(StatusCode.ERROR, f"Authentication error: {e}"))
            return None


def get_user_from_session_or_token(req: request, session: dict = None) -> Optional[AuthenticatedUser]:
    """
    Get authenticated user from front-proxy headers, Bearer token, or session.
    
    This allows the Extension API to work with:
    1. Front-proxy headers (from Kubernetes API server via aggregation)
    2. Direct API calls with Bearer tokens (kubectl, API clients)
    3. Web UI requests with session authentication
    
    Args:
        req: Flask request object
        session: Flask session dict (optional)
        
    Returns:
        AuthenticatedUser: The authenticated user, or None
    """
    # First try front-proxy authentication (Kubernetes API aggregation)
    user = authenticate_front_proxy(req)
    if user:
        logger.debug(f"Authenticated via front-proxy: {user.username}")
        return user
    
    # Try Bearer token (direct API clients like kubectl)
    user = authenticate_request(req)
    if user:
        logger.debug(f"Authenticated via Bearer token: {user.username}")
        return user
    
    # Fall back to session authentication (Web UI)
    if session and 'username' in session:
        logger.debug(f"Authenticated via session: {session.get('username')}")
        return AuthenticatedUser(
            username=session.get('username'),
            uid=str(session.get('user_id', '')),
            groups=[session.get('user_role', 'User')]
        )
    
    logger.warning("No authentication method succeeded (no front-proxy, no token, no session)")
    return None
