#!/usr/bin/env python3
"""Error page handlers for KubeDash."""

from flask import Flask, request, render_template


def initialize_error_page(app: Flask):
    """Initialize error pages

    Args:
        app (Flask): Flask app object
    """
    @app.errorhandler(400)
    def page_not_found400(e):
        # Check if this is a CSRF error from a security scanner (ZAP)
        is_security_scanner = False
        if hasattr(request, 'user_agent'):
            user_agent = str(request.user_agent)
            # ZAP uses specific User-Agent patterns
            if any(pattern in user_agent.lower() for pattern in ['zap', 'owasp', 'scanner', 'security']):
                is_security_scanner = True
        # Also check if request is from localhost (common for ZAP in Docker)
        if request.remote_addr in ['127.0.0.1', '::1', 'localhost']:
            # Check if it's a CSRF error (expected during security scanning)
            if 'csrf' in str(e.description).lower():
                is_security_scanner = True

        # Log security scanner CSRF errors at DEBUG level (expected behavior)
        # Log real CSRF errors at ERROR level
        if is_security_scanner and 'csrf' in str(e.description).lower():
            app.logger.debug(f"400 Error (Security Scanner): {e.description} - This is expected during security scanning")
        else:
            app.logger.error(f"400 Error: {e.description}")
        return render_template(
            'errors/400.html.j2',
            description=e.description,
            ), 400

    @app.errorhandler(403)
    def page_not_found403(e):
        app.logger.error(f"403 Error: {e.description}")
        return render_template(
            'errors/403.html.j2',
            description=e.description,
            ), 403

    @app.errorhandler(404)
    def page_not_found404(e):
        app.logger.error(f"404 Error: {e.description} {request.url}")
        return render_template('errors/404.html.j2'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        # Handle cases where description might not exist
        description = getattr(e, 'description', 'Internal Server Error')
        app.logger.error(f"500 Error: {description}")
        return render_template(
            'errors/500.html.j2',
            description=description,
            ), 500

    # Also handle generic exceptions
    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        app.logger.error(f"Unexpected error: {str(e)}")
        description = "An unexpected error occurred"
        return render_template(
            'errors/500.html.j2',
            description=description,
            ), 500

    @app.errorhandler(502)
    def bad_gateway(e):
        return render_template('errors/502.html.j2', description=e.description), 502

    @app.errorhandler(504)
    def gateway_timeout(e):
        return render_template('errors/504.html.j2', description=e.description), 504
