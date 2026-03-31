#!/usr/bin/env python3
"""Swagger/OpenAPI documentation initialization for KubeDash."""

import time
from flask import Flask, request, redirect, url_for, Response
from flask_login import current_user
from urllib.parse import urlencode


def initialize_app_swagger(app: Flask):
    """Initialize Swagger UI

    Args:
        app (Flask): Flask app object
    """
    from lib.components import api_doc

    app.logger.info("Initialize Swagger UI")
    api_description = """
KubeDash REST API Documentation

This API provides programmatic access to KubeDash functionality including:
- Kubernetes resource management (pods, deployments, services, etc.)
- Cluster metrics and monitoring
- User and role management
- Application settings and configuration
- Plugin resources (Flux, Gateway API, Cert Manager, etc.)

## Authentication

Most endpoints require authentication via Flask-Login session cookies.
Some endpoints may support Bearer token authentication.

## Base URL

All API endpoints are prefixed with `/api/v1/`

## Response Format

All responses follow a consistent format:
```json
{
    "data": {...},
    "metadata": {
        "count": 10,
        "namespace": "default"
    }
}
```

## Error Format

Errors follow this format:
```json
{
    "error": "Error type",
    "message": "Human-readable error message"
}
```
"""

    app.config.update({
        "API_TITLE": "KubeDash API",
        "API_VERSION": "v1",
        "API_DESCRIPTION": api_description,
        "OPENAPI_VERSION": "3.0.2",
        "OPENAPI_URL_PREFIX": "/api",                       # OpenAPI served under /api/
        "OPENAPI_SWAGGER_UI_PATH": "/swagger-ui",           # relative to URL_PREFIX → /api/swagger-ui
        "OPENAPI_SWAGGER_UI_URL": "/api/swagger-ui/",       # your local static files
        "OPENAPI_REDOC_PATH": "/redoc",                    # ReDoc UI path → /api/redoc
        "OPENAPI_REDOC_URL": "/api/redoc/",                # ReDoc UI URL
        "OPENAPI_JSON_PATH": "/openapi.json",               # OpenAPI JSON spec → /api/openapi.json
        "OPENAPI_RAPIDOC_PATH": "/rapidoc",                 # RapiDoc UI path → /api/rapidoc
        "OPENAPI_RAPIDOC_URL": "/api/rapidoc/",             # RapiDoc UI URL
    })
    api_doc.init_app(app)

    # Add additional metadata to spec after initialization
    # Access the spec's _spec dictionary to add contact and license
    if hasattr(api_doc.spec, '_spec'):
        spec_dict = api_doc.spec._spec
        if 'info' not in spec_dict:
            spec_dict['info'] = {}
        spec_dict['info']['contact'] = {
            "name": "KubeDash Support",
            "url": "https://github.com/kubedash/kubedash"
        }
        spec_dict['info']['license'] = {
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT"
        }

    # Add security scheme for session-based auth
    try:
        api_doc.spec.components.security_scheme("sessionAuth", {
            "type": "apiKey",
            "in": "cookie",
            "name": "session",
            "description": "Session-based authentication via Flask-Login"
        })
    except Exception as e:
        # If security scheme addition fails, log but don't crash
        app.logger.warning(f"Could not add security scheme: {e}")

    # Protect Swagger UI with flask-login
    # Use a before_request handler that checks authentication
    # We need to set prometheus metrics attributes to avoid middleware errors

    @app.before_request
    def protect_swagger_ui():
        """Protect Swagger UI endpoints - require login"""
        # Check if the request is for the swagger-ui page (main page, not static files)
        # Static files are already protected by @login_required decorator in blueprint/api.py
        path = request.path.rstrip('/')
        if path == "/api/swagger-ui":
            if not current_user.is_authenticated:
                # Set prometheus metrics start time to avoid AttributeError in after_request
                # This ensures the flask_prometheus_metrics middleware doesn't fail
                if not hasattr(request, '_prometheus_metrics_request_start_time'):
                    request._prometheus_metrics_request_start_time = time.time()

                # Create a redirect response
                login_url = url_for('auth.login')
                # Add next parameter to redirect back to swagger-ui after login
                if request.url:
                    login_url += '?' + urlencode({'next': request.url})
                # Return a proper Response object
                return Response(
                    status=302,
                    headers={'Location': login_url}
                )
