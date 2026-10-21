#!/usr/bin/env python3
"""Network-reachable OIDC mock for e2e (CI service container, port 9096).

Same contract as Task 3's ``MockOIDC`` in backend/tests/api/conftest.py, but
served over HTTP so the real Authlib adapter runs in e2e (the unit tier
monkeypatches ``oidc_authorize_url`` / ``oidc_exchange``; e2e exercises the
real bodies).

Endpoints (per the OpenID Connect discovery contract the Authlib client uses):
  GET  /.well-known/openid-configuration  → discovery document
  GET  /authorize?client_id=..&redirect_uri=..&state=..&code=..
       → 302 back to redirect_uri with ?code=fixed&state=<echoed>
  POST /token                              → static id_token (+ refresh)

Run:  python tests/e2e/oidc-mock.py   (listens on 0.0.0.0:9096)
"""
import json
import os

from flask import Flask, redirect, request

ISSUER = os.environ.get("OIDC_MOCK_ISSUER", "http://localhost:9096")
CODE = "fixed"
ID_TOKEN = {
    "iss": ISSUER,
    "sub": "sub-oidc-1",
    "email": "jdoe@example.com",
    "name": "J Doe",
    "groups": ["devs"],
    "aud": "kubedash",
    "exp": 9999999999,
    "iat": 0,
}

app = Flask(__name__)


@app.get("/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "email", "profile", "groups"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }


@app.get("/authorize")
def authorize():
    # 302 back to the client with a fixed code + our echoed state.
    return redirect(
        f"{request.args['redirect_uri']}"
        f"?code={CODE}&state={request.args['state']}"
    )


@app.post("/token")
def token():
    return {
        "token_type": "Bearer",
        "access_token": "fixed-access",
        "refresh_token": "fixed-refresh",
        "id_token": _encode_jwt(ID_TOKEN),
    }


def _encode_jwt(claims: dict) -> str:
    """Minimal unverified JWT (HS256) — e2e only checks claims, not the
    signature (the mock is a stand-in IdP, not a signing authority)."""
    import base64
    import hashlib
    import hmac

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = b64(hmac.new(b"kubedash-mock-key", signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9096)
