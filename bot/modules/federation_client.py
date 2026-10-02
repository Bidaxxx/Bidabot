"""
Module 8 — Fédération de réputation inter-serveurs (côté client, appelé
depuis le bot). Le serveur qui reçoit ces requêtes est federation_api/app.py.

Garanties RGPD posées par l'architecture, appliquées ici :
- Jamais l'ID Discord en clair : hash_federation_id() le transforme via
  HMAC-SHA256 salé (pepper propre au déploiement), non réversible.
- Consentement explicite : ce module ne doit être appelé QUE si le serveur
  a un accord de fédération actif (federation_partners.active), configuré
  manuellement par un admin — jamais automatique/opt-out.
- Chaque requête sortante est signée HMAC (méthode+chemin+timestamp+corps)
  pour empêcher qu'un tiers usurpe l'identité d'un serveur partenaire.
"""
from __future__ import annotations

import json
import logging
import time

import httpx

from bot.crypto_utils import federation_signature, hash_federation_id

logger = logging.getLogger("sentinel.federation")


class FederationClient:
    def __init__(self, base_url: str, partner_name: str, hmac_secret: str, pepper: str):
        self.base_url = base_url.rstrip("/")
        self.partner_name = partner_name
        self.hmac_secret = hmac_secret
        self.pepper = pepper

    def _headers(self, method: str, path: str, body: bytes) -> dict:
        ts = str(int(time.time()))
        sig = federation_signature(self.hmac_secret, method, path, ts, body)
        return {
            "X-Sentinel-Partner": self.partner_name,
            "X-Sentinel-Timestamp": ts,
            "X-Sentinel-Signature": sig,
            "Content-Type": "application/json",
        }

    async def report(self, discord_id: int, risk_score: float, evidence_link: str, reason: str) -> bool:
        path = "/v1/reports"
        body = json.dumps({
            "hashed_user_id": hash_federation_id(discord_id, self.pepper),
            "risk_score": risk_score,
            "evidence_link": evidence_link,
            "reason": reason,
        }).encode()

        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.post(
                    self.base_url + path, content=body, headers=self._headers("POST", path, body),
                )
                resp.raise_for_status()
                return True
            except httpx.HTTPError as e:
                logger.warning("Échec de signalement fédération : %s", e)
                return False

    async def check(self, discord_id: int) -> list[dict]:
        hashed = hash_federation_id(discord_id, self.pepper)
        path = f"/v1/check/{hashed}"

        async with httpx.AsyncClient(timeout=10) as client:
            try:
                resp = await client.get(
                    self.base_url + path, headers=self._headers("GET", path, b""),
                )
                resp.raise_for_status()
                return resp.json().get("reports", [])
            except httpx.HTTPError as e:
                logger.warning("Échec de consultation fédération : %s", e)
                return []
