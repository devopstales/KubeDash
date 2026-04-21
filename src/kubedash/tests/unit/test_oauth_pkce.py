"""PKCE verifier/challenge generation for OIDC."""

import base64
import hashlib

from lib.oauth_pkce import generate_pkce_pair


def test_generate_pkce_pair_s256_roundtrip():
    verifier, challenge = generate_pkce_pair()
    assert len(verifier) >= 40
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    assert challenge == expected
