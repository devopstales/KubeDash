"""OD-2 — encrypted-kubeconfig registry: AES-256-GCM stored form.

Frozen form (one-way door — see ADR-0002):
    0x01 (version byte) || 12-byte nonce || AES-GCM(nonce, key, plaintext)
key = sha256(KUBEDASH_SECRET_KEY).

These tests are PURE: no DB, no Docker — the cipher is unit-testable in
isolation from the registry.
"""
import base64

import pytest

from app.services.k8s_client import decrypt_kubeconfig, encrypt_kubeconfig


def test_roundtrip_and_at_rest_not_plaintext() -> None:
    plain = base64.b64encode(b"apiVersion: v1\nkind: Config\nclusters: []")
    enc = encrypt_kubeconfig(plain)
    # At-rest form must hide the plaintext.
    assert b"apiVersion" not in enc
    # The OD-2 frozen form: version byte first, then 12-byte nonce, then
    # AES-GCM(nonce, key, plaintext).
    assert enc[0] == 0x01
    assert len(enc) >= 13 + 16  # version + nonce + 16-byte GCM tag
    assert decrypt_kubeconfig(enc) == plain


def test_wrong_key_fails() -> None:
    import app.services.k8s_client as kc

    enc = encrypt_kubeconfig(b"data")
    old = kc._key
    kc._key = b"x" * 32
    try:
        with pytest.raises(ValueError, match="kubeconfig decryption failed"):
            kc.decrypt_kubeconfig(enc)
    finally:
        kc._key = old


def test_wrong_version_byte_fails() -> None:
    enc = encrypt_kubeconfig(b"data")
    # Swap the version byte 0x01 -> 0x02: unknown cipher/key generation.
    with pytest.raises(ValueError, match="unknown kubeconfig version"):
        decrypt_kubeconfig(b"\x02" + enc[1:])


def test_tampered_ciphertext_fails() -> None:
    enc = encrypt_kubeconfig(b"data")
    # Tamper the last ciphertext byte (the GCM tag) — the version byte and
    # nonce are intact, so the failure must come out of the GCM layer, not
    # the version check.
    flipped = enc[:-1] + bytes([enc[-1] ^ 0x01])
    with pytest.raises(ValueError, match="kubeconfig decryption failed"):
        decrypt_kubeconfig(flipped)
