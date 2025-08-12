from flask import request, Response, Blueprint, abort, stream_with_context
import requests
from urllib.parse import urljoin

proxy_bp = Blueprint(
    "app_catalog_proxy",
    __name__,
    url_prefix="/plugins/app-catalog-proxy"
)

APP_CONFIG = {
    'app1': 'http://127.0.0.1:8001/',  # [X] pgweb - Dark Mode
    'app2': 'http://127.0.0.1:8002/',  # [-] p3x
    'app3': 'http://127.0.0.1:8003/',  # [X] kube view
    'app4': 'http://127.0.0.1:8004/',  # [?] redis commander
    'app5': 'http://127.0.0.1:8005/'   # [-] redis INSIGHT

}

@proxy_bp.route('/<app_name>/', defaults={'path': ''})
@proxy_bp.route('/<app_name>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy_app(app_name, path):
    target_base = APP_CONFIG.get(app_name)
    if not target_base:
        abort(404, description=f"No target configured for app: {app_name}")

    url = f"{target_base.rstrip('/')}/{path.lstrip('/')}" if path else target_base.rstrip('/')

    headers = {k: v for k, v in request.headers if k.lower() != 'host'}

    # Forward cookies from client to backend
    csrf_token = request.cookies.get('csrf_token')
    if csrf_token:
        headers['X-CSRFToken'] = csrf_token

    resp = requests.request(
        method=request.method,
        url=url,
        headers=headers,
        params=request.args,
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        stream=True
    )
    
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']

    # Build headers for client response, including Set-Cookie(s)
    response_headers = [(name, value) for name, value in resp.headers.items() if name.lower() not in excluded_headers]

    # Add all Set-Cookie headers explicitly to support multiple cookies
    set_cookies = resp.raw.headers.getlist('Set-Cookie')
    for cookie in set_cookies:
        response_headers.append(('Set-Cookie', cookie))

    return Response(
        stream_with_context(resp.iter_content(chunk_size=8192)),
        status=resp.status_code,
        headers=response_headers
    )
