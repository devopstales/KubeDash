#!/usr/bin/env python3
"""Security initialization for KubeDash (login, CSRF, CSP, CORS, Talisman)."""

import os
import secrets
from flask import Flask, request, g


def initialize_app_security(app: Flask):
    """Initialize application security options:

    Configs:
    - Login Manager
    - Tell Flask it is Behind a Proxy:
    - Content Security Policy - CSP
    - Cross-site request forgery - CSRF
    - cross origin resource sharing - CORS

    Args:
        app (Flask): Flask app object
    """
    from lib.components import login_manager, csrf
    from flask_talisman import Talisman

    app.logger.info("Initializing app Security")

    """Init Logging managger"""
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"

    # Generate CSP nonce for inline scripts (XSS protection)
    # This will be set per-request in before_request handler
    @app.before_request
    def set_csp_nonce():
        """Generate CSP nonce for inline scripts to prevent XSS"""
        g.csp_nonce = secrets.token_urlsafe(16)

    # Make nonce available to all templates via context processor
    @app.context_processor
    def inject_csp_nonce():
        """Inject CSP nonce into template context for each request"""
        return {'csp_nonce': getattr(g, 'csp_nonce', '')}

    # Build CSP policy - nonce will be added dynamically in after_request
    # Note: 'unsafe-eval' removed for better XSS protection
    # 'unsafe-inline' can be removed after migrating all inline scripts to use nonces
    # The nonce is added dynamically in after_request handler
    # Air-gapped: no CDNs; all assets served from 'self' (local static files)
    csp = {
        'default-src': "'self'",
        'font-src': ["'self'"],
        'style-src': [
            "'self'",
            "'unsafe-inline'",  # Still needed for CSS frameworks and inline style attributes
        ],
        'script-src': [
            "'self'",
            # Nonce will be added dynamically in after_request
        ],
        'connect-src': [
            "'self'",
            'wss:',  # WebSocket connections
            'ws:',   # WebSocket connections (dev)
        ],
        'img-src': ["'self'", 'data:'],
    }

    hsts = {
        'max-age': 31536000,
        'includeSubDomains': True
    }

    app.config['SECRET_KEY'] = os.urandom(34).hex()
    # add rootCA folder # MissingImplementation

    """Init Talisman"""
    app.talisman = Talisman(app)

    if app.config['ENV'] == 'production':
        from werkzeug.middleware.proxy_fix import ProxyFix
        """Tell Flask it is Behind a Proxy"""
        app.wsgi_app = ProxyFix(
          app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
        )
        """Config Talisman"""
        app.talisman.force_https = True
        app.talisman.strict_transport_security = hsts

    else:
        """Config Talisman"""
        app.talisman.force_https = False


    """Init CSRF"""
    csrf.init_app(app)

    # Disable Talisman's CSP - we'll set it manually in after_request with nonces
    # Talisman processes CSP after our after_request handler, so we need to handle it ourselves
    app.talisman.content_security_policy = None
    app.talisman.x_xss_protection = True
    app.talisman.session_cookie_secure = True
    app.talisman.session_cookie_samesite = 'Lax'

    @app.after_request
    def set_security_headers(response):
        """Add security headers for response"""
        # Get the nonce from Flask's g context (set in before_request)
        nonce_value = getattr(g, 'csp_nonce', None)

        # Relax security headers for embedded app pages to allow iframe embedding
        is_embedded_app = (
            request.endpoint and
            (request.endpoint.startswith('app_catalog.') or
             request.endpoint.startswith('iframe_proxy.'))
        )

        # CORS
        response.headers['Access-Control-Allow-Origin'] = request.root_url.rstrip(request.root_url[-1])
        response.headers['X-Permitted-Cross-Domain-Policies'] = "none"

        if is_embedded_app:
            # Relaxed headers for embedded applications
            response.headers['Cross-Origin-Resource-Policy'] = "cross-origin"
            # Don't set Cross-Origin-Embedder-Policy for embedded apps
            # Don't set Cross-Origin-Opener-Policy for embedded apps

            # Remove Talisman's CSP header and set a relaxed one for embedded apps
            # Embedded apps need more flexibility (blob workers, external frames, etc.)
            # Remove all CSP-related headers that Talisman might have set
            response.headers.pop('Content-Security-Policy', None)
            response.headers.pop('Content-Security-Policy-Report-Only', None)

            # Set relaxed CSP as a string (Talisman might override dict format)
            relaxed_csp_str = (
                "default-src 'self' 'unsafe-inline' 'unsafe-eval' blob: data: *; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: data: *; "
                "style-src 'self' 'unsafe-inline' *; "
                "img-src 'self' data: blob: *; "
                "font-src 'self' data: blob: *; "
                "connect-src 'self' wss: ws: *; "
                "frame-src 'self' *; "
                "worker-src 'self' blob: *; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self' *;"
            )

            response.headers['Content-Security-Policy'] = relaxed_csp_str
        else:
            # Strict headers for main application
            response.headers['Cross-Origin-Resource-Policy'] = "same-origin"
            response.headers['Cross-Origin-Embedder-Policy'] = "require-corp"
            response.headers['Cross-Origin-Opener-Policy'] = "same-origin"

            # Build CSP string with nonce support
            # All templates now use nonces - 'unsafe-inline' removed from script-src
            # 'unsafe-eval' already removed (prevents eval() and similar functions)
            #
            # All inline scripts in templates now use nonce="{{ csp_nonce }}"
            # 'unsafe-inline' removed from script-src for better security

            if nonce_value:
                csp_parts = []
                csp_parts.append("default-src 'self'")
                csp_parts.append("font-src 'self'")
                csp_parts.append("style-src 'self' 'unsafe-inline'")
                # Air-gapped: script-src only 'self' and nonce (no CDNs)
                script_src = f"'self' 'nonce-{nonce_value}'"
                csp_parts.append(f"script-src {script_src}")

                csp_parts.append("connect-src 'self' wss: ws:")
                csp_parts.append("img-src 'self' data:")

                # Set the CSP header with nonce
                response.headers['Content-Security-Policy'] = "; ".join(csp_parts)
            else:
                # Fallback if nonce not available (shouldn't happen, but safety check)
                csp_parts = []
                csp_parts.append("default-src 'self'")
                csp_parts.append("font-src 'self'")
                csp_parts.append("style-src 'self' 'unsafe-inline'")
                csp_parts.append("script-src 'self' 'unsafe-inline'")
                csp_parts.append("connect-src 'self' wss: ws:")
                csp_parts.append("img-src 'self' data:")
                response.headers['Content-Security-Policy'] = "; ".join(csp_parts)

        response.headers["Access-Control-Max-Age"] = "600"

        # Cache
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache" # Deprecated
        response.headers["Expires"] = "0"

        return response
