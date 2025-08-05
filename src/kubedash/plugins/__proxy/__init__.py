from flask import request, Response, Blueprint, session, current_app
from flask_wtf.csrf import generate_csrf, validate_csrf
from werkzeug.datastructures import Headers
import requests
from urllib.parse import urljoin

proxy_bp = Blueprint(
    "app_catalog_proxy", 
    __name__, 
    url_prefix="/plugins/app-catalog-proxy"
)

APP_CONFIG = {
    'app1': {'base_url': 'http://127.0.0.1:8001/'},
    'app2': {'base_url': 'http://127.0.0.1:8002/'},
    'app3': {'base_url': 'http://127.0.0.1:8003/'},
    'app4': {'base_url': 'http://127.0.0.1:8004/'}
}

@proxy_bp.before_app_request
def check_csrf_for_proxy():
    """Verify CSRF token for POST requests to the proxy"""
    if request.method == 'POST' and request.blueprint == 'app_catalog_proxy':
        try:
            # Check for token in form data or headers
            validate_csrf(request.form.get('csrf_token') or 
                        request.headers.get('X-CSRF-Token'))
        except:
            current_app.logger.warning("CSRF validation failed for proxy request")
            return Response("CSRF token missing or invalid", 400)

@proxy_bp.route('/<app_name>/', defaults={'path': ''})
@proxy_bp.route('/<app_name>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy_app(app_name, path):
    """Enhanced proxy with complete CSRF handling"""
    if app_name not in APP_CONFIG:
        return "Application not found", 404
    
    app_cfg = APP_CONFIG[app_name]
    target_url = urljoin(app_cfg['base_url'], path)
    if request.query_string:
        target_url += f"?{request.query_string.decode('utf-8')}"
    
    # Generate new CSRF token for our proxy
    proxy_csrf_token = generate_csrf()
    
    # Prepare headers with both proxy and backend CSRF tokens
    headers = Headers()
    for key, value in request.headers:
        if key.lower() not in ['host', 'connection', 'content-length']:
            headers.add(key, value)
    
    # Add CSRF tokens
    headers.add('X-CSRF-Token', proxy_csrf_token)
    headers.add('X-Proxy-CSRF', proxy_csrf_token)
    
    # For form submissions, inject CSRF token
    data = request.get_data()
    if request.method in ['POST', 'PUT', 'PATCH']:
        if request.content_type == 'application/x-www-form-urlencoded':
            try:
                form_data = request.form.to_dict()
                form_data['csrf_token'] = proxy_csrf_token
                data = form_data
            except:
                pass
    
    # Forward the request
    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=data,
            cookies=request.cookies,
            allow_redirects=False,
            timeout=30
        )
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Proxy error: {str(e)}")
        return f"Proxy error: {str(e)}", 502
    
    # Handle response
    response_headers = Headers()
    for key, value in resp.raw.headers.items():
        if key.lower() not in ['content-encoding', 'transfer-encoding', 'connection']:
            response_headers.add(key, value)
    
    # Set CSRF cookie for the proxy
    response = Response(
        resp.content,
        resp.status_code,
        response_headers
    )
    response.set_cookie(
        'csrf_token',
        proxy_csrf_token,
        secure=True,
        httponly=True,
        samesite='Lax'
    )
    
    return response