"""
Primitives cryptographiques de SENTINEL.

- Chaîne de hash SHA-256 (module 7, forensique) : chaque preuve référence le
  hash de la précédente -> toute altération a posteriori casse la chaîne.
- Signature Ed25519 du rapport final : prouve que le rapport a bien été
  généré par CE bot (clé privée jamais partagée).
- HMAC-SHA256 pour l'authentification inter-serveurs (module 8, fédération) :
  chaque partenaire a un secret partagé, chaque requête est signée avec un
  timestamp + nonce pour empêcher le replay.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ── Chaîne de hash (module 7) ────────────────────────────────────────────

def canonical_json(data: dict) -> bytes:
    """Sérialisation déterministe : mêmes données -> mêmes octets, toujours.
    Condition nécessaire pour que le hash soit reproductible et vérifiable."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode()


def compute_chain_hash(prev_hash: str | None, event_type: str, data: dict, ts: str) -> str:
    payload = canonical_json({"prev": prev_hash, "type": event_type, "data": data, "ts": ts})
    return hashlib.sha256(payload).hexdigest()


def hash_ip(ip: str, pepper: str) -> str:
    """Une IP n'est JAMAIS stockée en clair (RGPD) : toujours HMAC-SHA256
    avec un pepper propre au déploiement, pour permettre les corrélations
    (même IP revient deux fois) sans exposer l'IP elle-même."""
    return hmac.new(pepper.encode(), ip.encode(), hashlib.sha256).hexdigest()


# ── Signature Ed25519 du bot (module 7) ──────────────────────────────────

def load_or_create_signing_key(path: str) -> Ed25519PrivateKey:
    p = Path(path)
    if p.exists():
        return serialization.load_pem_private_key(p.read_bytes(), password=None)

    p.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # 0600 : seul le process du bot doit pouvoir lire la clé privée
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


def sign_bytes(key: Ed25519PrivateKey, data: bytes) -> str:
    return key.sign(data).hex()


def verify_signature(public_key: Ed25519PublicKey, data: bytes, signature_hex: str) -> bool:
    try:
        public_key.verify(bytes.fromhex(signature_hex), data)
        return True
    except Exception:
        return False


# ── HMAC fédération (module 8) ───────────────────────────────────────────

def federation_signature(secret: str, method: str, path: str, timestamp: str, body: bytes) -> str:
    """Signe method+path+timestamp+body — empêche qu'une requête interceptée
    soit rejouée sur un autre endpoint ou avec un corps modifié."""
    msg = f"{method.upper()}\n{path}\n{timestamp}\n".encode() + body
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify_federation_signature(
    secret: str, method: str, path: str, timestamp: str, body: bytes,
    signature: str, max_skew_seconds: int = 120,
) -> tuple[bool, str]:
    try:
        ts = int(timestamp)
    except ValueError:
        return False, "timestamp invalide"

    if abs(time.time() - ts) > max_skew_seconds:
        return False, "timestamp hors fenêtre (possible replay)"

    expected = federation_signature(secret, method, path, timestamp, body)
    if not hmac.compare_digest(expected, signature):
        return False, "signature invalide"

    return True, "ok"


def hash_federation_id(discord_id: int, pepper: str) -> str:
    """Jamais l'ID Discord en clair vers l'extérieur : HMAC salé, stable pour
    un même pepper (permet la corrélation) mais non réversible."""
    return hmac.new(pepper.encode(), str(discord_id).encode(), hashlib.sha256).hexdigest()
