"""Lightweight OIDC provider for the KubeDash dev-stack.

Provides a minimal OAuth2/OIDC authorization-code flow for local SSO
testing. Pre-configured users (from the SSO_USERS env var) get a login
page; the backend's OIDC callback receives the id_token + userinfo.

Env:
  SSO_ISSUER     — public issuer URL (default http://localhost:8888)
  SSO_CLIENT_ID  — the client_id the KubeDash backend is registered with
  SSO_USERS      — comma-separated "email:name:role" pre-created users
  SSO_SECRET     — HMAC secret for signing JWT id_tokens (default dev)

Endpoints:
  GET  /.well-known/openid-configuration  — OIDC discovery
  GET  /authorize                         — redirect to /login or issue code
  GET  /login                             — HTML form (pick a user)
  POST /login                             — issue code + redirect to callback
  GET  /token                             — code → access_token + id_token
  GET  /userinfo                          — access_token → claims
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlencode

from flask import Flask, Response, abort, redirect, request, jsonify
import jwt  # PyJWT

ISSUER = os.environ.get("SSO_ISSUER", "http://localhost:8888")
CLIENT_ID = os.environ.get("SSO_CLIENT_ID", "kubedash-dev")
SSO_SECRET = os.environ.get("SSO_SECRET", "dev-sso-secret-32-bytes!!!!!01")

# Parse SSO_USERS: "email:name:role,email2:name2:role2"
SSO_USERS: list[dict] = []
for _entry in os.environ.get("SSO_USERS", "").split(","):
    _entry = _entry.strip()
    if not _entry:
        continue
    parts = _entry.split(":")
    if len(parts) >= 2:
        SSO_USERS.append({
            "sub": parts[0].strip(),
            "email": parts[0].strip(),
            "name": parts[1].strip(),
            "role": parts[2].strip() if len(parts) > 2 else "user",
        })
    elif parts:
        SSO_USERS.append({
            "sub": parts[0].strip(),
            "email": parts[0].strip(),
            "name": parts[0].strip().split("@")[0],
            "role": "user",
        })

# In-memory code store: {code: (user, redirect_uri, state, expires)}
_codes: dict[str, tuple[dict, str, str, float]] = {}

app = Flask(__name__)


def _now() -> int:
    return int(time.time())


def _make_id_token(user: dict) -> str:
    """Sign a JWT id_token with HS256 (dev only — no verification by client)."""
    now = _now()
    payload = {
        "iss": ISSUER,
        "sub": user["sub"],
        "aud": CLIENT_ID,
        "exp": now + 300,
        "iat": now,
        "email": user["email"],
        "name": user["name"],
        "groups": [f"kubedash-{user['role']}"],
    }
    return jwt.encode(payload, SSO_SECRET, algorithm="HS256")


def _make_access_token(user: dict) -> str:
    now = _now()
    payload = {
        "iss": ISSUER,
        "sub": user["sub"],
        "aud": CLIENT_ID,
        "exp": now + 300,
        "iat": now,
        "token_type": "Bearer",
    }
    return jwt.encode(payload, SSO_SECRET, algorithm="HS256")


@app.get("/.well-known/openid-configuration")
def discovery():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "email", "profile", "groups"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    })


@app.get("/jwks")
def jwks():
    # HS256 has no JWKS — return empty keys (Authlib handles HS256 via secret).
    return jsonify({"keys": []})


_LOGIN_PAGE = """<!doctype html>
<html><head><title>KubeDash SSO</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 32em; margin: 4em auto; padding: 0 1em; }
  h1 { font-size: 1.3em; }
  button { display: block; width: 100%%; padding: 0.7em; margin: 0.5em 0; font-size: 1em;
           border: 1px solid #ccc; border-radius: 6px; cursor: pointer; background: #fff; }
  button:hover { background: #f0f0f0; }
  .role { font-size: 0.8em; color: #666; }
</style></head>
<body>
<h1>KubeDash Dev SSO</h1>
<p>Pick a user to log in as:</p>
<form method="POST" action="/login">
  <input type="hidden" name="redirect_uri" value="{{redirect_uri}}">
  <input type="hidden" name="state" value="{{state}}">
  {% for u in users %}
  <button type="submit" name="sub" value="{{u.sub}}">
    {{u.name}} <span class="role">({{u.role}})</span>
  </button>
  {% endfor %}
</form>
</body></html>"""


@app.get("/authorize")
def authorize():
    redirect_uri = request.args.get("redirect_uri", "")
    state = request.args.get("state", "")
    # If no SSO users configured, auto-approve with a default user
    if not SSO_USERS:
        user = {"sub": "dev@local", "email": "dev@local", "name": "Dev", "role": "user"}
        code = secrets.token_urlsafe(32)
        _codes[code] = (user, redirect_uri, state, time.time() + 300)
        params = {"code": code, "state": state}
        return redirect(f"{redirect_uri}?{urlencode(params)}")
    # Render the login page
    from jinja2 import Template
    html = Template(_LOGIN_PAGE).render(
        users=SSO_USERS, redirect_uri=redirect_uri, state=state
    )
    return Response(html, content_type="text/html")


@app.post("/login")
def login():
    sub = request.form.get("sub", "")
    redirect_uri = request.form.get("redirect_uri", "")
    state = request.form.get("state", "")
    user = next((u for u in SSO_USERS if u["sub"] == sub), None)
    if user is None:
        abort(401, description="unknown user")
    code = secrets.token_urlsafe(32)
    _codes[code] = (user, redirect_uri, state, time.time() + 300)
    params = {"code": code, "state": state}
    return redirect(f"{redirect_uri}?{urlencode(params)}")


@app.get("/token")
def token():
    # Accept both GET (for simplicity in dev) and POST
    code = request.args.get("code") or request.form.get("code", "")
    entry = _codes.pop(code, None)
    if entry is None:
        abort(400, description="invalid or expired code")
    user, _, _, expires = entry
    if time.time() > expires:
        abort(400, description="code expired")
    return jsonify({
        "access_token": _make_access_token(user),
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": _make_id_token(user),
        "scope": "openid email profile groups",
    })


@app.get("/userinfo")
def userinfo():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401)
    token = auth[7:]
    try:
        payload = jwt.decode(token, SSO_SECRET, algorithms=["HS256"], audience=CLIENT_ID)
    except jwt.InvalidTokenError:
        abort(401)
    # The access token only carries sub — look up the full user by sub.
    user = next((u for u in SSO_USERS if u["sub"] == payload["sub"]), None)
    if user is None:
        abort(404)
    return jsonify({
        "sub": user["sub"],
        "email": user["email"],
        "name": user["name"],
        "groups": [f"kubedash-{user['role']}"],
    })


@app.get("/healthz")
def healthz():
    return jsonify(status="ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)
