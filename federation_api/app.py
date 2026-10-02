"""
SENTINEL — API de fédération (module 8) + endpoint honeytoken (module 5).

Service séparé du bot Discord, déployé indépendamment (voir docker-compose.yml).
Deux familles d'endpoints :

- /v1/reports, /v1/check/{hashed_id} : échange de signalements entre serveurs
  partenaires, authentifié par HMAC (voir bot/crypto_utils.py). Réplique
  côté serveur des rappels RGPD déjà présents côté client : seul un
  identifiant hashé et salé circule, jamais un ID Discord brut.

- /t/{token} : cible des liens honeytoken générés par /sentinel canary link.
  Ne logue QUE ip (hashée), ASN, user-agent, timestamp — rien de plus.
  Redirige ensuite vers une page neutre pour ne pas éveiller les soupçons.

Lancer avec : uvicorn federation_api.app:app --host 0.0.0.0 --port 8001
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel

from bot.config import settings
from bot.crypto_utils import hash_ip, verify_federation_signature
from bot.db import Database

logger = logging.getLogger("sentinel.federation_api")

app = FastAPI(title="SENTINEL Federation API")
db = Database(settings.database_url)


@app.on_event("startup")
async def startup():
    await db.connect()


@app.on_event("shutdown")
async def shutdown():
    await db.close()


class ReportIn(BaseModel):
    hashed_user_id: str
    risk_score: float
    evidence_link: str
    reason: str


async def _authenticate(request: Request, partner_name: str | None, timestamp: str | None, signature: str | None):
    if not (partner_name and timestamp and signature):
        raise HTTPException(401, "En-têtes d'authentification manquants")

    partner = await db.get_partner_by_name(partner_name)
    if not partner:
        raise HTTPException(401, "Partenaire inconnu ou inactif")

    body = await request.body()
    ok, reason = verify_federation_signature(
        partner["hmac_secret"], request.method, request.url.path, timestamp, body,
        signature, settings.federation_hmac_max_skew_seconds,
    )
    if not ok:
        raise HTTPException(401, f"Authentification refusée : {reason}")

    # Anti-replay : un nonce = timestamp+signature ne doit être vu qu'une fois
    nonce = f"{timestamp}:{signature}"
    if await db.nonce_seen(nonce):
        raise HTTPException(401, "Requête rejouée (nonce déjà vu)")
    await db.store_nonce(nonce, partner["id"])

    return partner


@app.post("/v1/reports")
async def post_report(
    report: ReportIn, request: Request,
    x_sentinel_partner: str | None = Header(default=None),
    x_sentinel_timestamp: str | None = Header(default=None),
    x_sentinel_signature: str | None = Header(default=None),
):
    partner = await _authenticate(request, x_sentinel_partner, x_sentinel_timestamp, x_sentinel_signature)
    await db.insert_federation_report(
        report.hashed_user_id, partner["id"], report.risk_score, report.evidence_link, report.reason,
    )
    return {"status": "ok"}


@app.get("/v1/check/{hashed_user_id}")
async def get_check(
    hashed_user_id: str, request: Request,
    x_sentinel_partner: str | None = Header(default=None),
    x_sentinel_timestamp: str | None = Header(default=None),
    x_sentinel_signature: str | None = Header(default=None),
):
    await _authenticate(request, x_sentinel_partner, x_sentinel_timestamp, x_sentinel_signature)
    rows = await db.check_federation(hashed_user_id)
    reports = [
        {
            "risk_score": r["risk_score"], "reason": r["reason"],
            "partner": r["partner_name"], "reliability_weight": r["reliability_weight"],
            "received_at": r["received_at"].isoformat(),
        }
        for r in rows
    ]
    return {"reports": reports}


# ── Honeytoken (module 5) ─────────────────────────────────────────────

@app.get("/t/{token}")
async def honeytoken_hit(token: str, request: Request):
    entry = await db.get_canary_token(token)
    if not entry:
        # Ne jamais révéler qu'un token honeytoken existe ou pas via le code
        # de retour -> même comportement qu'une 404 générique.
        raise HTTPException(404)

    client_ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")

    await db.insert_canary_hit(
        guild_id=entry["guild_id"], channel_id=entry["channel_id"], user_id=None,
        ip_hash=hash_ip(client_ip, settings.hash_pepper),
        asn=None,  # brancher un lookup IPinfo/MaxMind ici si une clé API est configurée
        user_agent=ua, kind="link_click",
    )
    logger.warning("Honeytoken déclenché : token=%s guild=%s label=%s", token, entry["guild_id"], entry["label"])

    # Redirige vers une page neutre : ne pas alerter la personne que son clic a été détecté
    return RedirectResponse(url="https://http.cat/404", status_code=302)


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok"})
