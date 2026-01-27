#!/usr/bin/env python3

from flask import Blueprint, request, Response, current_app, url_for
from flask_login import login_required
import requests
from urllib.parse import urljoin, urlparse, quote
import re

from lib.helper_functions import get_logger
from lib.components import csrf
from plugins.application_catalog.application import ApplicationGet

##############################################################
## variables
##############################################################

iframe_proxy_bp = Blueprint(
    "iframe_proxy",
    __name__,
    url_prefix="/plugins/iframe-proxy"
)

# Exempt from CSRF protection - embedded apps can't provide CSRF tokens
csrf.exempt(iframe_proxy_bp)

logger = get_logger()

##############################################################
## Proxy Routes
##############################################################

@iframe_proxy_bp.route('/<app_name>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@iframe_proxy_bp.route('/<app_name>/', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@iframe_proxy_bp.route('/<app_name>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@login_required
def proxy_app(app_name, path=''):
    """
    Proxy requests to embedded applications.
    This allows HTTPS dashboard to embed HTTP applications by proxying through HTTPS.
    
    Args:
        app_name: Name of the application from database
        path: Path to proxy (e.g., /api/data, /static/js/app.js)
    
    Returns:
        Response: Proxied response from the application
    """
    try:
        # Handle OPTIONS (CORS preflight) - after authentication
        if request.method == 'OPTIONS':
            response_headers = {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Max-Age': '3600'
            }
            return Response('', status=200, headers=response_headers)
        
        # Get application from database
        application = ApplicationGet(app_name)
        
        if not application:
            return Response(
                f"Application '{app_name}' not found",
                status=404,
                mimetype='text/plain'
            )
        
        if not application.application_enabled:
            return Response(
                f"Application '{app_name}' is not enabled",
                status=403,
                mimetype='text/plain'
            )
        
        if not application.application_embedded:
            return Response(
                f"Application '{app_name}' is not configured for embedding",
                status=403,
                mimetype='text/plain'
            )
        
        # Build target URL
        base_url = application.application_url.rstrip('/')
        target_path = path.lstrip('/') if path else ''
        target_url = urljoin(base_url + '/', target_path)
        
        # Add query string if present
        if request.query_string:
            separator = '&' if '?' in target_url else '?'
            target_url = f"{target_url}{separator}{request.query_string.decode('utf-8')}"
        
        logger.debug(f"Proxying request to {target_url}")
        
        # Prepare headers for the proxied request
        headers = {}
        
        # Forward some headers that might be needed
        forward_headers = ['Accept', 'Accept-Language', 'Accept-Encoding', 'User-Agent', 'Content-Type', 'Referer']
        for header_name in forward_headers:
            if header_name in request.headers:
                headers[header_name] = request.headers[header_name]
        
        # Handle cookies if needed (forward from request)
        cookies = {}
        if request.cookies:
            # Optionally forward cookies - be careful with security
            # For now, we'll not forward cookies unless needed
            pass
        
        # Make the proxied request
        verify_ssl = True  # Set to False only for development with self-signed certs
        timeout = 30  # 30 second timeout
        
        try:
            if request.method == 'GET':
                response = requests.get(
                    target_url,
                    headers=headers,
                    cookies=cookies,
                    verify=verify_ssl,
                    timeout=timeout,
                    allow_redirects=True
                )
            elif request.method == 'POST':
                # Handle both form data and JSON/raw data
                if request.is_json:
                    # JSON request - use json parameter
                    response = requests.post(
                        target_url,
                        headers=headers,
                        cookies=cookies,
                        json=request.get_json(),
                        verify=verify_ssl,
                        timeout=timeout,
                        allow_redirects=True
                    )
                elif request.form:
                    # Form data request
                    response = requests.post(
                        target_url,
                        headers=headers,
                        cookies=cookies,
                        data=request.form.to_dict(),
                        verify=verify_ssl,
                        timeout=timeout,
                        allow_redirects=True
                    )
                else:
                    # Raw data request
                    response = requests.post(
                        target_url,
                        headers=headers,
                        cookies=cookies,
                        data=request.get_data(),
                        verify=verify_ssl,
                        timeout=timeout,
                        allow_redirects=True
                    )
            elif request.method == 'PUT':
                response = requests.put(
                    target_url,
                    headers=headers,
                    cookies=cookies,
                    data=request.get_data(),
                    verify=verify_ssl,
                    timeout=timeout,
                    allow_redirects=True
                )
            elif request.method == 'DELETE':
                response = requests.delete(
                    target_url,
                    headers=headers,
                    cookies=cookies,
                    verify=verify_ssl,
                    timeout=timeout,
                    allow_redirects=True
                )
            elif request.method == 'PATCH':
                response = requests.patch(
                    target_url,
                    headers=headers,
                    cookies=cookies,
                    data=request.get_data(),
                    verify=verify_ssl,
                    timeout=timeout,
                    allow_redirects=True
                )
            else:
                return Response(
                    f"Method {request.method} not supported",
                    status=405,
                    mimetype='text/plain'
                )
        except requests.exceptions.Timeout:
            return Response(
                "Request to application timed out",
                status=504,
                mimetype='text/plain'
            )
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error proxying to {target_url}: {e}")
            return Response(
                f"Cannot connect to application: {str(e)}",
                status=502,
                mimetype='text/plain'
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Error proxying to {target_url}: {e}")
            return Response(
                f"Error proxying request: {str(e)}",
                status=500,
                mimetype='text/plain'
            )
        
        # Prepare response headers
        response_headers = {}
        
        # Copy relevant headers from proxied response
        copy_headers = [
            'Content-Type', 'Content-Length', 'Content-Encoding',
            'Cache-Control', 'Expires', 'Last-Modified', 'ETag',
            'Content-Disposition'
        ]
        
        for header_name in copy_headers:
            if header_name in response.headers:
                response_headers[header_name] = response.headers[header_name]
        
        # Remove headers that would prevent embedding
        # X-Frame-Options is removed to allow embedding
        # Remove any CSP from the proxied response - we'll set our own relaxed one
        if 'Content-Security-Policy' in response.headers:
            del response.headers['Content-Security-Policy']
        
        # Set relaxed CSP for embedded apps - they need flexibility for workers, frames, etc.
        relaxed_csp = (
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
        response_headers['Content-Security-Policy'] = relaxed_csp
        
        # Set CORS headers to allow embedding
        response_headers['X-Frame-Options'] = 'ALLOWALL'
        response_headers['Access-Control-Allow-Origin'] = '*'
        response_headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        response_headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        
        # Get response content
        content = response.content
        
        # If response is HTML, rewrite relative URLs to go through proxy
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' in content_type:
            try:
                content_str = content.decode('utf-8', errors='ignore')
                
                # Generate proxy base URL - use the app's base path, not the current request path
                # This ensures we always use the same base for rewriting
                from flask import url_for
                proxy_base = url_for('iframe_proxy.proxy_app', app_name=app_name, path='', _external=False).rstrip('/')
                
                # Update or add <base> tag - some apps (like Jaeger, AngularJS apps) require it
                # Replace existing <base> tags with our proxy base
                base_pattern = r'<base\s+[^>]*href\s*=\s*["\']([^"\']*)["\'][^>]*>'
                def rewrite_base(match):
                    return f'<base href="{proxy_base}/">'
                content_str = re.sub(base_pattern, rewrite_base, content_str, flags=re.IGNORECASE)
                
                # If no base tag exists, add one after <head>
                # Some apps (Jaeger, AngularJS) require a base tag
                if '<base' not in content_str.lower() and '<head' in content_str.lower():
                    head_pattern = r'(<head[^>]*>)'
                    content_str = re.sub(head_pattern, r'\1\n<base href="' + proxy_base + '/">', content_str, count=1, flags=re.IGNORECASE)
                
                # Rewrite relative URLs (starting with /) to go through proxy
                # Match: href="/path", src="/path", action="/path", etc.
                def rewrite_url(match):
                    attr_name = match.group(1)   # href, src, action, etc.
                    quote_char = match.group(2)  # " or '
                    url = match.group(3)         # The URL
                    
                    # Skip if URL already goes through proxy (prevent double-rewriting)
                    # Check if URL starts with proxy path or contains the app name in the proxy path
                    if (url.startswith(proxy_base) or 
                        (url.startswith('/plugins/iframe-proxy/') and f'/{app_name}/' in url) or
                        (url.startswith('/plugins/iframe-proxy/') and url.count('/plugins/iframe-proxy/') > 1)):
                        return match.group(0)
                    
                    # Only rewrite if it's a relative URL starting with /
                    # Skip if it's protocol-relative (//) or already absolute (http://, https://)
                    if url.startswith('/') and not url.startswith('//') and not url.startswith('/http'):
                        # Build new URL through proxy
                        new_url = f"{proxy_base}{url}"
                        return f'{attr_name}={quote_char}{new_url}{quote_char}'
                    # For absolute URLs or protocol-relative URLs, leave as-is
                    return match.group(0)
                
                # Pattern to match common HTML attributes with URLs
                # Matches: href="/path", src="/path", action="/path", etc.
                url_pattern = r'(href|src|action|data-src|data-href|data-url|content|cite)\s*=\s*(["\'])([^"\']+)\2'
                content_str = re.sub(url_pattern, rewrite_url, content_str, flags=re.IGNORECASE)
                
                # Also handle URLs in CSS (url(...))
                def rewrite_css_url(match):
                    quote_char = match.group(1)  # " or ' or nothing
                    url = match.group(2)          # The URL
                    
                    # Skip if URL already goes through proxy (prevent double-rewriting)
                    # Check if URL starts with proxy path or contains the app name in the proxy path
                    if (url.startswith(proxy_base) or 
                        (url.startswith('/plugins/iframe-proxy/') and f'/{app_name}/' in url) or
                        (url.startswith('/plugins/iframe-proxy/') and url.count('/plugins/iframe-proxy/') > 1)):
                        return match.group(0)
                    
                    # Only rewrite if it's a relative URL starting with /
                    if url.startswith('/') and not url.startswith('//') and not url.startswith('/http'):
                        new_url = f"{proxy_base}{url}"
                        return f'url({quote_char}{new_url}{quote_char})'
                    return match.group(0)
                
                # Pattern for CSS url() functions
                css_url_pattern = r'url\((["\']?)([^"\')]+)\1\)'
                content_str = re.sub(css_url_pattern, rewrite_css_url, content_str, flags=re.IGNORECASE)
                
                # Update content
                content = content_str.encode('utf-8')
                
                # Update Content-Length header
                response_headers['Content-Length'] = str(len(content))
                
            except Exception as e:
                logger.warning(f"Error rewriting URLs in HTML response: {e}")
                # Continue with original content if rewriting fails
        
        # Create Flask response
        flask_response = Response(
            content,
            status=response.status_code,
            headers=response_headers
        )
        
        return flask_response
        
    except Exception as e:
        logger.error(f"Unexpected error in proxy: {e}")
        return Response(
            f"Internal server error: {str(e)}",
            status=500,
            mimetype='text/plain'
        )
