"""Tests des primitives crypto utilisées par les modules 7 (signature) et
8 (HMAC fédération, anti-replay)."""
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bot.crypto_utils import (
    sign_bytes, verify_signature, federation_signature, verify_federation_signature,
    hash_federation_id,
)


def test_ed25519_sign_and_verify_roundtrip():
    key = Ed25519PrivateKey.generate()
    data = b"contenu du rapport forensique"
    sig = sign_bytes(key, data)
    assert verify_signature(key.public_key(), data, sig) is True


def test_ed25519_verify_fails_on_tampered_data():
    key = Ed25519PrivateKey.generate()
    sig = sign_bytes(key, b"original")
    assert verify_signature(key.public_key(), b"altere", sig) is False


def test_ed25519_verify_fails_with_wrong_key():
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    sig = sign_bytes(key_a, b"data")
    assert verify_signature(key_b.public_key(), b"data", sig) is False


def test_federation_hmac_roundtrip_valid():
    secret = "secret-partage"
    ts = str(int(time.time()))
    body = b'{"hashed_user_id": "abc"}'
    sig = federation_signature(secret, "POST", "/v1/reports", ts, body)

    ok, reason = verify_federation_signature(secret, "POST", "/v1/reports", ts, body, sig)
    assert ok is True, reason


def test_federation_hmac_rejects_wrong_secret():
    ts = str(int(time.time()))
    body = b"{}"
    sig = federation_signature("secret-a", "POST", "/v1/reports", ts, body)
    ok, _ = verify_federation_signature("secret-b", "POST", "/v1/reports", ts, body, sig)
    assert ok is False


def test_federation_hmac_rejects_tampered_body():
    secret = "secret"
    ts = str(int(time.time()))
    sig = federation_signature(secret, "POST", "/v1/reports", ts, b'{"a":1}')
    ok, _ = verify_federation_signature(secret, "POST", "/v1/reports", ts, b'{"a":2}', sig)
    assert ok is False


def test_federation_hmac_rejects_old_timestamp_replay():
    secret = "secret"
    old_ts = str(int(time.time()) - 999)  # bien au-delà du skew autorisé
    body = b"{}"
    sig = federation_signature(secret, "GET", "/v1/check/abc", old_ts, body)
    ok, reason = verify_federation_signature(secret, "GET", "/v1/check/abc", old_ts, body, sig, max_skew_seconds=120)
    assert ok is False
    assert "hors fenêtre" in reason


def test_federation_hmac_rejects_wrong_path_replay():
    """Un attaquant qui intercepte une requête signée pour /v1/check/x ne
    doit pas pouvoir la réutiliser sur /v1/reports."""
    secret = "secret"
    ts = str(int(time.time()))
    body = b"{}"
    sig = federation_signature(secret, "GET", "/v1/check/x", ts, body)
    ok, _ = verify_federation_signature(secret, "GET", "/v1/reports", ts, body, sig)
    assert ok is False


def test_hash_federation_id_not_reversible():
    h = hash_federation_id(123456789012345, "pepper")
    assert "123456789012345" not in h
    assert len(h) == 64  # sha256 hexdigest
