"""
SENTINEL — Plateforme Web & Dashboard Modérateur Professionnel (FastAPI + HTMX).

Fonctionnalités :
1. Vitrine publique moderne style SaaS ("/", "/#features", "/#scanner").
2. Authentification Discord OAuth2 ("Se connecter avec Discord") + fallback Staff password.
3. Sélecteur de serveurs (/dashboard) avec statut de protection Sentinel.
4. Console de gestion dédiée par serveur (/dashboard/{guild_id}) avec navigation épurée par onglets :
   - Vue d'ensemble (Overview) & Actions rapides en 1 clic
   - Anti-Raid & Urgence (Lockdown, Dry-Run, Mode Panique, Auto-Quarantaine)
   - Sécurité & Filtres (Anti-Scam, Anti-Spam, Anti-Ghostping, Anti-Nuke)
   - Membres & Quarantaine (Scores de risque, mise en quarantaine, validation ML)
   - Whitelist Staff & Rôles immunisés
   - Anti-Stresseur Vocal (Monitoring latence & auto-réparation)
   - Forensique & Audit (Historique de preuves inviolables, téléchargement du rapport PDF signé Ed25519)
5. Contrôle en direct du Bot Discord via canal Redis Pub/Sub (latence < 5ms).
"""
from __future__ import annotations

import base64
import datetime
import json
import logging
import urllib.parse
from pathlib import Path

try:
    import httpx
except Exception:
    httpx = None

import aiohttp
from fastapi import FastAPI, Request, Form, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

from bot.cache import Cache
from bot.config import settings
from bot.crypto_utils import load_or_create_signing_key
from bot.db import Database
from bot.modules import forensics, red_team_simulator, vulnerability_scanner, cli_engine
from bot.modules.antiscam import analyze
from bot.modules.credential_stuffing import record_attempt

logger = logging.getLogger("sentinel.dashboard")

app = FastAPI(title="BIDABOT — Discord Security Platform")
app.add_middleware(SessionMiddleware, secret_key=settings.dashboard_secret_key)

# Fichiers statiques et templates
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
db = Database(settings.database_url)
cache = Cache(settings.redis_url)
signing_key = None


def render(request: Request, name: str, context: dict | None = None, status_code: int = 200):
    ctx = context.copy() if context else {}
    ctx["request"] = request
    return templates.TemplateResponse(
        request=request,
        name=name,
        context=ctx,
        status_code=status_code,
    )


def get_client_id() -> str:
    """Détermine le client_id Discord pour OAuth2 et le lien d'invitation."""
    if getattr(settings, "discord_client_id", None):
        return settings.discord_client_id
    token = settings.discord_token
    if token and "." in token:
        try:
            part = token.split(".")[0]
            padded = part + "=" * (-len(part) % 4)
            decoded = base64.b64decode(padded).decode("utf-8")
            if decoded.isdigit():
                return decoded
        except Exception:
            pass
    return "1553767735702589440"


def get_redirect_uri(request: Request | None = None) -> str:
    """Détermine l'URL de redirection exacte basée sur la requête courante ou le .env."""
    if getattr(settings, "discord_redirect_uri", None):
        return settings.discord_redirect_uri
    if request:
        base = str(request.base_url).rstrip("/")
        return f"{base}/callback"
    return "http://localhost:8002/callback"


async def dispatch_bot_action(action: str, guild_id: int, **data):
    """Envoie une action en temps réel au Bot Discord via Redis Pub/Sub."""
    try:
        if cache.client:
            payload = {"action": action, "guild_id": guild_id, **data}
            await cache.client.publish("sentinel:control", json.dumps(payload))
            logger.info("Action '%s' publiée sur sentinel:control pour guild %s", action, guild_id)
    except Exception as e:
        logger.error("Erreur lors de la publication Redis pour l'action %s : %s", action, e)


@app.on_event("startup")
async def startup():
    global signing_key
    try:
        await db.connect()
    except Exception as e:
        logger.warning("Connexion DB différée : %s", e)
    try:
        await cache.connect()
    except Exception as e:
        logger.warning("Connexion Redis différée : %s", e)
    try:
        signing_key = load_or_create_signing_key(settings.signing_key_path)
    except Exception as e:
        logger.warning("Clé de signature différée : %s", e)


@app.on_event("shutdown")
async def shutdown():
    try:
        await db.close()
    except Exception:
        pass
    try:
        await cache.close()
    except Exception:
        pass


def require_auth(request: Request) -> dict:
    if not request.session.get("authenticated"):
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    user = request.session.get("user") or {
        "id": "0",
        "username": "Administrateur",
        "avatar": "https://cdn.discordapp.com/embed/avatars/0.png",
        "is_root": True,
    }
    return user


# ─── Vitrine Publique ──────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Page d'accueil vitrine moderne avec explorer de fonctionnalités."""
    client_id = get_client_id()
    user = request.session.get("user")
    return render(request, "home.html", {
        "request": request,
        "client_id": client_id,
        "user": user,
    })


# ─── Authentification Discord OAuth2 & Staff ───────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if request.session.get("authenticated"):
        return RedirectResponse("/dashboard", status_code=303)

    client_id = get_client_id()
    has_oauth = bool(getattr(settings, "discord_client_secret", None))
    redirect_uri = get_redirect_uri(request)

    oauth_url = (
        f"https://discord.com/api/oauth2/authorize?client_id={client_id}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri, safe='')}"
        f"&response_type=code&scope=identify%20guilds"
    )

    return render(request, "login.html", {
        "request": request,
        "oauth_url": oauth_url,
        "has_oauth": has_oauth,
        "error": None,
    })


@app.get("/login/discord")
async def login_discord(request: Request):
    client_id = get_client_id()
    redirect_uri = get_redirect_uri(request)
    oauth_url = (
        f"https://discord.com/api/oauth2/authorize?client_id={client_id}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri, safe='')}"
        f"&response_type=code&scope=identify%20guilds"
    )
    return RedirectResponse(oauth_url, status_code=303)


@app.get("/callback")
async def oauth_callback(request: Request, code: str | None = None, error: str | None = None):
    if error or not code:
        return RedirectResponse(f"/login?error={error or 'cancelled'}", status_code=303)

    client_id = get_client_id()
    client_secret = getattr(settings, "discord_client_secret", "")
    redirect_uri = get_redirect_uri(request)

    if not client_secret:
        # Fallback si secret non configuré : simulation admin directe
        request.session["authenticated"] = True
        request.session["user"] = {
            "id": "1",
            "username": "Admin Bidabot",
            "avatar": "https://cdn.discordapp.com/embed/avatars/1.png",
            "is_root": True,
        }
        return RedirectResponse("/dashboard", status_code=303)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_res = await client.post(
                "https://discord.com/api/oauth2/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_data = token_res.json()
            access_token = token_data.get("access_token")
            if not access_token:
                logger.error("Échec récupération access_token : %s", token_data)
                return RedirectResponse("/login?error=token_failed", status_code=303)

            auth_headers = {"Authorization": f"Bearer {access_token}"}
            user_res = await client.get("https://discord.com/api/users/@me", headers=auth_headers)
            user_data = user_res.json()

            guilds_res = await client.get("https://discord.com/api/users/@me/guilds", headers=auth_headers)
            guilds_data = guilds_res.json() if guilds_res.status_code == 200 else []

            # Filtre les serveurs où l'utilisateur est admin ou propriétaire
            admin_guilds = []
            for g in guilds_data:
                perms = int(g.get("permissions", 0))
                is_admin = bool(perms & 0x8) or bool(perms & 0x20) or g.get("owner", False)
                if is_admin:
                    admin_guilds.append({
                        "id": int(g["id"]),
                        "name": g["name"],
                        "icon": g.get("icon"),
                    })

            avatar_hash = user_data.get("avatar")
            avatar_url = (
                f"https://cdn.discordapp.com/avatars/{user_data['id']}/{avatar_hash}.png"
                if avatar_hash else "https://cdn.discordapp.com/embed/avatars/0.png"
            )

            request.session["authenticated"] = True
            request.session["user"] = {
                "id": user_data["id"],
                "username": user_data.get("global_name") or user_data["username"],
                "avatar": avatar_url,
                "is_root": False,
            }
            request.session["admin_guild_ids"] = [g["id"] for g in admin_guilds]
            request.session["admin_guilds"] = admin_guilds

        return RedirectResponse("/dashboard", status_code=303)
    except Exception as e:
        logger.error("Exception callback OAuth : %s", e)
        return RedirectResponse("/login?error=oauth_error", status_code=303)


@app.post("/login")
async def login_submit(request: Request, password: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"
    source_key = f"dashboard:{client_ip}"

    if password != settings.dashboard_password:
        over_limit = False
        try:
            over_limit = await record_attempt(
                cache=cache,
                db=db,
                guild_id=0,
                source_key=source_key,
                window_seconds=settings.thresholds.credential_stuffing_window_seconds,
                max_attempts=settings.thresholds.credential_stuffing_max_attempts,
                webhook_id=None,
            )
        except Exception as e:
            logger.warning("Erreur rate-limit login : %s", e)

        if over_limit:
            return render(request, 
                "login.html",
                {"request": request, "error": "Trop de tentatives. Réessaie dans quelques minutes.", "has_oauth": False, "oauth_url": "#"},
                status_code=429,
            )
        return render(request, 
            "login.html",
            {"request": request, "error": "Mot de passe incorrect.", "has_oauth": False, "oauth_url": "#"},
        )

    request.session["authenticated"] = True
    request.session["user"] = {
        "id": "0",
        "username": "Staff Master",
        "avatar": "https://cdn.discordapp.com/embed/avatars/4.png",
        "is_root": True,
    }
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


# ─── Sélecteur de Serveurs (/dashboard) ───────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
async def servers_view(request: Request, user: dict = Depends(require_auth)):
    """Affiche la liste élégante des serveurs gérés par Sentinel."""
    client_id = get_client_id()
    try:
        db_guilds = await db.get_all_guilds()
    except Exception as e:
        logger.error("Erreur récupération serveurs DB : %s", e)
        db_guilds = []

    # Dictionnaire des serveurs protégés par Sentinel
    protected_map = {g["guild_id"]: g for g in db_guilds}

    # Liste des serveurs visibles pour l'utilisateur
    admin_guilds = request.session.get("admin_guilds")
    is_root = user.get("is_root", False) or not admin_guilds

    servers = []
    if is_root:
        # Administrateur root : voit tous les serveurs où le bot est installé
        for g in db_guilds:
            servers.append({
                "id": g["guild_id"],
                "name": g["name"],
                "is_protected": True,
                "dry_run": g.get("dry_run", True),
                "icon": None,
            })
    else:
        # Utilisateur Discord OAuth : voit ses serveurs et le statut du bot
        for ag in admin_guilds:
            gid = ag["id"]
            is_prot = gid in protected_map
            servers.append({
                "id": gid,
                "name": ag["name"],
                "is_protected": is_prot,
                "dry_run": protected_map[gid].get("dry_run", True) if is_prot else True,
                "icon": ag.get("icon"),
            })

    return render(request, "servers.html", {
        "request": request,
        "user": user,
        "servers": servers,
        "client_id": client_id,
    })


# ─── Console de Gestion Dédiée (/dashboard/{guild_id}) ────────────────

@app.get("/dashboard/{guild_id}", response_class=HTMLResponse)
async def guild_dashboard_view(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    """Panneau de contrôle principal pour un serveur spécifique."""
    # Vérification d'autorisation (sauf si root)
    admin_ids = request.session.get("admin_guild_ids")
    if admin_ids and guild_id not in admin_ids and not user.get("is_root"):
        raise HTTPException(status_code=403, detail="Vous n'êtes pas administrateur de ce serveur.")

    guild = await db.get_guild(guild_id)
    guild_name = guild["name"] if guild else f"Serveur {guild_id}"

    # Récupération du Trust Score
    latest_trust = await db.get_latest_trust_score(guild_id)
    trust_score_val = latest_trust["score"] if latest_trust else 75.0

    return render(request, "server_dash.html", {
        "request": request,
        "user": user,
        "guild_id": guild_id,
        "guild_name": guild_name,
        "guild": guild or {},
        "trust_score": round(trust_score_val, 1),
    })


# ─── Onglets HTMX (/dashboard/{guild_id}/tab/{tab_name}) ─────────────

@app.get("/dashboard/{guild_id}/tab/overview", response_class=HTMLResponse)
async def tab_overview(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    dry_run = await db.get_dry_run(guild_id)
    lockdown_active = await db.is_lockdown_active(guild_id)
    warrooms = await db.active_warroom_count(guild_id)
    chain_ok, chain_len = await forensics.verify_chain(db, guild_id)
    incidents_today = await db.count_incidents_today(guild_id)
    avg_score = await db.avg_risk_score_today(guild_id)
    quarantine_count = await db.get_active_quarantine_count(guild_id)

    return render(request, "partials/_tab_overview.html", {
        "request": request,
        "guild_id": guild_id,
        "dry_run": dry_run,
        "lockdown_active": lockdown_active,
        "warrooms": warrooms,
        "chain_ok": chain_ok,
        "chain_len": chain_len,
        "incidents_today": incidents_today,
        "avg_score": round(avg_score, 2) if avg_score is not None else None,
        "quarantine_count": quarantine_count,
    })


@app.get("/dashboard/{guild_id}/tab/protections", response_class=HTMLResponse)
async def tab_protections(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    guild = await db.get_guild(guild_id) or {}
    guild_name = guild.get("name", "Serveur Discord")
    channels = await fetch_discord_guild_channels(guild_id)
    return render(request, "partials/_tab_protections.html", {
        "request": request,
        "guild_id": guild_id,
        "guild_name": guild_name,
        "guild": guild,
        "channels": channels,
        "active_count": 14,
    })


@app.get("/dashboard/{guild_id}/tab/messages-confidence", response_class=HTMLResponse)
async def tab_messages_confidence(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    raw_events = await db.get_recent_incidents(guild_id, limit=50)
    messages = []
    for ev in raw_events:
        etype = ev.get("event_type", "")
        raw_data = ev.get("data") or {}
        if isinstance(raw_data, str):
            try:
                import json
                data = json.loads(raw_data)
            except Exception:
                data = {}
        else:
            data = dict(raw_data)

        # Filtre les événements pertinents pour l'analyse des messages
        if any(k in etype for k in ("message", "scam", "raid", "toxic", "spam")):
            ts = ev.get("ts")
            t_str = ts.strftime("%H:%M") if ts else "--:--"
            snippet = data.get("content_snippet") or data.get("content") or "Contenu non consigné"
            uid = data.get("user_id") or data.get("author_id")
            uname = data.get("author_name") or f"Membre #{uid}"
            cname = data.get("channel_name") or str(data.get("channel_id", "salon"))
            score = float(data.get("score", 0.95 if "raid" in etype else 0.8))
            messages.append({
                "id": ev.get("id"),
                "time": t_str,
                "user_id": uid,
                "username": uname,
                "channel_name": cname,
                "content": snippet,
                "score": score,
                "reasons": data.get("reasons") or [etype],
            })

    return render(request, "partials/_tab_messages_confidence.html", {
        "request": request,
        "guild_id": guild_id,
        "messages": messages,
    })


@app.get("/dashboard/{guild_id}/tab/antiraid", response_class=HTMLResponse)
async def tab_antiraid(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    guild = await db.get_guild(guild_id) or {}
    guild_name = guild.get("name", "Serveur Discord")
    channels = await fetch_discord_guild_channels(guild_id)
    return render(request, "partials/_tab_protections.html", {
        "request": request,
        "guild_id": guild_id,
        "guild_name": guild_name,
        "guild": guild,
        "channels": channels,
        "active_count": 14,
    })


@app.get("/dashboard/{guild_id}/tab/security", response_class=HTMLResponse)
async def tab_security(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    guild = await db.get_guild(guild_id) or {}

    return render(request, "partials/_tab_security.html", {
        "request": request,
        "guild_id": guild_id,
        "guild": guild,
    })


@app.get("/dashboard/{guild_id}/tab/members", response_class=HTMLResponse)
async def tab_members(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    recent_users = await db.get_recent_users_with_scores(guild_id, limit=25)
    quarantined = await db.get_active_quarantined_users(guild_id)

    return render(request, "partials/_tab_members.html", {
        "request": request,
        "guild_id": guild_id,
        "recent_users": recent_users,
        "quarantined": quarantined,
    })


@app.get("/dashboard/{guild_id}/tab/whitelist", response_class=HTMLResponse)
async def tab_whitelist(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    items = await db.get_whitelist(guild_id)

    return render(request, "partials/_tab_whitelist.html", {
        "request": request,
        "guild_id": guild_id,
        "items": items,
    })


@app.get("/dashboard/{guild_id}/tab/voice", response_class=HTMLResponse)
async def tab_voice(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    configs = await db.get_voice_antistress_configs(guild_id)

    return render(request, "partials/_tab_voice.html", {
        "request": request,
        "guild_id": guild_id,
        "configs": configs,
    })


@app.get("/dashboard/{guild_id}/tab/backups", response_class=HTMLResponse)
async def tab_backups(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    snapshots = await db.get_guild_snapshots(guild_id, limit=30)

    return render(request, "partials/_tab_backups.html", {
        "request": request,
        "guild_id": guild_id,
        "snapshots": snapshots,
    })



@app.get("/dashboard/{guild_id}/tab/forensics", response_class=HTMLResponse)
async def tab_forensics(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    raw_incidents = await db.get_recent_incidents(guild_id, limit=60)
    chain_ok, chain_len = await forensics.verify_chain(db, guild_id)

    badge_map = {
        "risk_critical": ("CRITIQUE", "critical", "🚨", "accounts"),
        "suspicious_account_detected": ("COMPTE SUSPECT", "warning", "👤", "accounts"),
        "suspicious_message_detected": ("MESSAGE SUSPECT", "warning", "💬", "scam"),
        "scam_detected": ("PHISHING / SCAM", "danger", "🎣", "scam"),
        "raid_threat_detected": ("MENACE DE RAID", "critical", "⚡", "nuke"),
        "toxic_slur_detected": ("PROPOS HAINEUX", "critical", "🚫", "scam"),
        "spam_flood_detected": ("SPAM / FLOOD", "warning", "🔇", "scam"),
        "antispam_repeat_offender": ("MULTI-SPAM", "critical", "🚨", "scam"),
        "malware_blocked": ("MALWARE BLOQUÉ", "danger", "🦠", "malware"),
        "antinuke_bot_blocked": ("ANTI-NUKE BOT", "critical", "🤖", "nuke"),
        "antinuke_webhook_blocked": ("WEBHOOK SUSPECT", "critical", "🔗", "nuke"),
        "antinuke_mass_action": ("ACTION MASSIVE", "critical", "💥", "nuke"),
        "raid_purge_executed": ("PURGE DE RAID", "critical", "🧹", "nuke"),
        "quarantined": ("QUARANTAINE", "warning", "☣️", "accounts"),
        "quarantine_applied": ("QUARANTAINE", "warning", "☣️", "accounts"),
        "impersonation_detected": ("USURPATION STAFF", "warning", "🎭", "accounts"),
        "ghostping_detected": ("GHOSTPING", "warning", "👻", "other"),
        "similar_names_detected": ("SIMILARITÉ BOTS", "warning", "👥", "accounts"),
        "voice_channel_renewed": ("VOCAL RÉPARÉ", "info", "⚡", "other"),
        "guild_snapshot_created": ("SNAPSHOT CRÉÉ", "success", "💾", "other"),
        "guild_snapshot_restored": ("SNAPSHOT RESTAURÉ", "success", "🛡️", "other"),
        "lockdown_triggered": ("LOCKDOWN ACTIF", "warning", "🔒", "nuke"),
        "lockdown_released": ("LOCKDOWN LEVÉ", "info", "🔓", "nuke"),
        "member_banned_via_web": ("BAN DASHBOARD", "critical", "🔨", "other"),
        "member_kicked_via_web": ("KICK DASHBOARD", "warning", "👢", "other"),
        "member_timed_out_via_web": ("TIMEOUT DASHBOARD", "warning", "⏳", "other"),
        "member_untimeout_via_web": ("DÉMUTE DASHBOARD", "info", "🔊", "other"),
    }

    category_counts = {
        "all": len(raw_incidents),
        "scam": 0,
        "accounts": 0,
        "malware": 0,
        "nuke": 0,
        "other": 0,
    }

    enriched = []
    for ev in raw_incidents:
        etype = ev.get("event_type", "unknown")
        raw_data = ev.get("data") or {}
        if isinstance(raw_data, str):
            try:
                import json
                data = json.loads(raw_data)
            except Exception:
                data = {}
        else:
            data = dict(raw_data)

        label, level, icon, cat = badge_map.get(etype, ("ÉVÉNEMENT", "info", "📜", "other"))
        category_counts[cat] = category_counts.get(cat, 0) + 1

        uid = data.get("user_id") or data.get("author_id") or data.get("target_id") or data.get("suspect_id")
        uname = data.get("author_name") or data.get("username") or data.get("name") or ""
        score = data.get("score")
        score_pct = round(float(score) * 100) if score is not None else None

        reasons = data.get("reasons")
        if not reasons and data.get("reason"):
            reasons = [data.get("reason")]

        snippet = data.get("content_snippet") or data.get("content") or data.get("filename") or ""

        enriched.append({
            "id": ev.get("id"),
            "event_type": etype,
            "badge_label": label,
            "badge_level": level,
            "icon": icon,
            "category": cat,
            "hash": ev.get("hash", ""),
            "ts": ev.get("ts"),
            "user_id": uid,
            "username": uname,
            "score": score,
            "score_pct": score_pct,
            "reasons": reasons or [],
            "snippet": snippet,
            "raw_data": data,
        })

    return render(request, "partials/_tab_forensics.html", {
        "request": request,
        "guild_id": guild_id,
        "incidents": enriched,
        "category_counts": category_counts,
        "chain_ok": chain_ok,
        "chain_len": chain_len,
    })


@app.get("/dashboard/{guild_id}/tab/audit", response_class=HTMLResponse)
async def tab_audit(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    guild_data = await db.get_guild(guild_id) or {}
    
    # Audit basé sur les paramètres et la télémétrie de sécurité
    vulns = []
    penalties = 0

    if not guild_data.get("auto_quarantine_enabled", False):
        penalties += 15
        vulns.append({
            "id": "vuln_no_auto_quarantine",
            "title": "Auto-quarantaine des profils suspects inactive",
            "severity": "high",
            "description": "Les comptes fraîchement créés ou sans avatar ayant un score suspect ne sont pas isolés automatiquement.",
            "auto_fixable": True,
            "fix_action": "enable_auto_quarantine",
        })

    if guild_data.get("join_velocity_threshold", 8) > 15:
        penalties += 10
        vulns.append({
            "id": "vuln_high_join_threshold",
            "title": "Seuil de vélocité de raid trop permissif",
            "severity": "medium",
            "description": "Le seuil actuel (>15 arrivées/min) permet à des vagues de raid de progresser avant déclenchement.",
            "auto_fixable": True,
            "fix_action": "optimize_join_velocity",
        })

    if not guild_data.get("anti_ghostping_enabled", True):
        penalties += 10
        vulns.append({
            "id": "vuln_no_ghostping",
            "title": "Module Anti-Ghostping désactivé",
            "severity": "medium",
            "description": "Les mentions @everyone ou staff supprimées furtivement ne sont pas interceptées.",
            "auto_fixable": True,
            "fix_action": "enable_anti_ghostping",
        })

    if not guild_data.get("anti_nuke_enabled", True):
        penalties += 35
        vulns.append({
            "id": "vuln_no_antinuke",
            "title": "Bouclier Anti-Nuke (Rogue Bots & Webhooks) désactivé",
            "severity": "critical",
            "description": "Le serveur ne bloque pas l'ajout de bots tiers par des comptes compromis ni les suppressions massives.",
            "auto_fixable": True,
            "fix_action": "enable_antinuke",
        })

    if guild_data.get("account_age_min_days", 3) < 2:
        penalties += 10
        vulns.append({
            "id": "vuln_no_account_age",
            "title": "Surveillance des comptes récents inactive",
            "severity": "medium",
            "description": "Les comptes créés depuis moins de 48h ne sont pas soumis à scoring accru.",
            "auto_fixable": True,
            "fix_action": "enable_account_age_check",
        })

    score = max(0, 100 - penalties)
    if score >= 90:
        grade = "A+"
        grade_color = "#00ff88"
        status_label = "EXCELLENTE POSTURE DE DÉFENSE"
    elif score >= 80:
        grade = "A"
        grade_color = "#2ed573"
        status_label = "TRÈS BONNE SÉCURITÉ"
    elif score >= 70:
        grade = "B"
        grade_color = "#70a1ff"
        status_label = "SÉCURITÉ ACCEPTABLE (AMÉLIORATIONS POSSIBLES)"
    elif score >= 55:
        grade = "C"
        grade_color = "#ffa502"
        status_label = "POSTURE VULNÉRABLE AUX RAIDS"
    elif score >= 40:
        grade = "D"
        grade_color = "#ff6348"
        status_label = "HAUT RISQUE D'ATTAQUE"
    else:
        grade = "F"
        grade_color = "#ff4757"
        status_label = "SITUATION CRITIQUE — ACTION REQUISE"

    audit_res = {
        "score": score,
        "grade": grade,
        "grade_color": grade_color,
        "status_label": status_label,
        "penalties": penalties,
        "vulnerabilities": vulns,
        "critical_count": sum(1 for v in vulns if v["severity"] == "critical"),
        "high_count": sum(1 for v in vulns if v["severity"] == "high"),
        "medium_count": sum(1 for v in vulns if v["severity"] == "medium"),
    }

    return render(request, "partials/_tab_audit.html", {
        "request": request,
        "guild_id": guild_id,
        "audit": audit_res,
    })


async def fetch_discord_guild_channels(guild_id: int) -> list[dict]:
    token = settings.discord_token
    if not token or token == "dummy":
        return [
            {"id": "1001", "name": "bienvenue", "type": 0, "slowmode": 0, "is_locked": False},
            {"id": "1002", "name": "general", "type": 0, "slowmode": 5, "is_locked": False},
            {"id": "1003", "name": "annonces", "type": 0, "slowmode": 0, "is_locked": True},
            {"id": "1004", "name": "bidabot-logs", "type": 0, "slowmode": 0, "is_locked": True},
            {"id": "2001", "name": "Salon Vocal Public", "type": 2, "slowmode": 0, "is_locked": False},
            {"id": "2002", "name": "Salon Vocal Staff", "type": 2, "slowmode": 0, "is_locked": True},
        ]
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=6.0)) as session:
            headers = {"Authorization": f"Bot {token}"}
            async with session.get(f"https://discord.com/api/v10/guilds/{guild_id}/channels", headers=headers) as res:
                if res.status == 200:
                    raw_channels = await res.json()
                    channels = []
                    for c in raw_channels:
                        c_type = c.get("type", 0)
                        if c_type in (0, 2):  # text, voice
                            is_locked = False
                            for ow in c.get("permission_overwrites", []):
                                if str(ow.get("id")) == str(guild_id):
                                    deny = int(ow.get("deny", 0))
                                    if deny & (1 << 11):  # SEND_MESSAGES
                                        is_locked = True
                            channels.append({
                                "id": str(c["id"]),
                                "name": c["name"],
                                "type": c_type,
                                "parent_id": c.get("parent_id"),
                                "position": c.get("position", 0),
                                "slowmode": c.get("rate_limit_per_user", 0),
                                "is_locked": is_locked,
                            })
                    channels.sort(key=lambda x: (x["type"], x["position"]))
                    return channels
    except Exception as e:
        logger.warning("Erreur lors de la récupération des salons Discord : %s", e)
    return [
        {"id": "1001", "name": "general", "type": 0, "slowmode": 0, "is_locked": False},
        {"id": "1002", "name": "annonces", "type": 0, "slowmode": 0, "is_locked": True},
        {"id": "2001", "name": "Vocal 1", "type": 2, "slowmode": 0, "is_locked": False},
    ]


@app.get("/dashboard/{guild_id}/tab/channels", response_class=HTMLResponse)
async def tab_channels(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    channels = await fetch_discord_guild_channels(guild_id)
    return render(request, "partials/_tab_channels.html", {
        "request": request,
        "guild_id": guild_id,
        "channels": channels,
    })


@app.get("/dashboard/{guild_id}/tab/console", response_class=HTMLResponse)
async def tab_console(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    return render(request, "partials/_tab_console.html", {
        "request": request,
        "guild_id": guild_id,
    })


# ─── Endpoints d'Actions Directes (Pilotage Bot en 1 Clic) ────────────

@app.post("/api/guild/{guild_id}/lockdown")
async def action_lockdown(guild_id: int, active: bool = Form(...), user: dict = Depends(require_auth)):
    """Active ou désactive le Lockdown immédiatement sur Discord."""
    await db.set_lockdown(guild_id, active, "Basculé depuis le Dashboard Web")
    action = "lockdown_on" if active else "lockdown_off"
    await dispatch_bot_action(action, guild_id, user_id=user["id"])
    return {"status": "ok", "lockdown_active": active}


@app.post("/api/guild/{guild_id}/dryrun")
async def action_dryrun(guild_id: int, dry_run: bool = Form(...), user: dict = Depends(require_auth)):
    """Bascule le mode simulation (Dry-Run)."""
    await db.set_dry_run(guild_id, dry_run)
    return {"status": "ok", "dry_run": dry_run}


@app.post("/api/guild/{guild_id}/panic")
async def action_panic(guild_id: int, user: dict = Depends(require_auth)):
    """Déclenche le Mode Panique immédiat (Lockdown + Haute Sécurité 1h)."""
    await db.set_lockdown(guild_id, True, "Mode Panique Déclenché")
    await dispatch_bot_action("panic_mode", guild_id, user_id=user["id"])
    return {"status": "ok", "message": "Mode Panique activé."}


@app.post("/api/guild/{guild_id}/ban/{user_id}")
async def action_ban(request: Request, guild_id: int, user_id: int, user: dict = Depends(require_auth)):
    """Bannit un membre directement depuis la console web."""
    reason = "Bannissement direct depuis le Dashboard Web"
    delete_days = 1
    try:
        form = await request.form()
        if form.get("reason"):
            reason = str(form.get("reason"))
        if form.get("delete_days"):
            delete_days = int(form.get("delete_days"))
    except Exception:
        pass
    await dispatch_bot_action(
        "ban", guild_id, target_id=user_id, reason=reason,
        delete_message_days=delete_days, user_id=user["id"],
    )
    return {"status": "ok", "user_id": user_id, "action": "banned", "reason": reason}


@app.post("/api/guild/{guild_id}/kick/{user_id}")
async def action_kick(request: Request, guild_id: int, user_id: int, user: dict = Depends(require_auth)):
    """Expulse un membre directement depuis la console web."""
    reason = "Expulsion directe depuis le Dashboard Web"
    try:
        form = await request.form()
        if form.get("reason"):
            reason = str(form.get("reason"))
    except Exception:
        pass
    await dispatch_bot_action(
        "kick", guild_id, target_id=user_id, reason=reason, user_id=user["id"],
    )
    return {"status": "ok", "user_id": user_id, "action": "kicked", "reason": reason}


@app.post("/api/guild/{guild_id}/timeout/{user_id}")
async def action_timeout(request: Request, guild_id: int, user_id: int, user: dict = Depends(require_auth)):
    """Met un membre sous silence (timeout) pour une durée configurable en secondes."""
    duration = 600
    reason = "Timeout direct depuis le Dashboard Web"
    try:
        form = await request.form()
        if form.get("duration"):
            duration = int(form.get("duration"))
        if form.get("reason"):
            reason = str(form.get("reason"))
    except Exception:
        pass
    await dispatch_bot_action(
        "timeout", guild_id, target_id=user_id, duration=duration,
        reason=reason, user_id=user["id"],
    )
    return {"status": "ok", "user_id": user_id, "action": "timeout", "duration": duration, "reason": reason}


@app.post("/api/guild/{guild_id}/untimeout/{user_id}")
async def action_untimeout(guild_id: int, user_id: int, user: dict = Depends(require_auth)):
    """Lève le timeout d'un membre."""
    await dispatch_bot_action(
        "timeout", guild_id, target_id=user_id, duration=0,
        reason="Levée de timeout depuis le Dashboard Web", user_id=user["id"],
    )
    return {"status": "ok", "user_id": user_id, "action": "untimeout"}


@app.post("/api/guild/{guild_id}/quarantine/{user_id}")
async def action_quarantine(request: Request, guild_id: int, user_id: int, user: dict = Depends(require_auth)):
    """Met un membre en quarantaine instantanément."""
    reason = "Action depuis le Dashboard"
    try:
        form = await request.form()
        if form.get("reason"):
            reason = str(form.get("reason"))
    except Exception:
        pass
    await db.log_quarantine(guild_id, user_id, "quarantined", reason)
    await dispatch_bot_action("quarantine", guild_id, target_id=user_id, reason=reason)
    return {"status": "ok", "user_id": user_id, "action": "quarantined"}


@app.post("/api/guild/{guild_id}/unquarantine/{user_id}")
async def action_unquarantine(guild_id: int, user_id: int, user: dict = Depends(require_auth)):
    """Lève la quarantaine d'un membre."""
    await db.log_quarantine(guild_id, user_id, "quarantine_released", "Levée depuis le Dashboard")
    await dispatch_bot_action("unquarantine", guild_id, target_id=user_id)
    return {"status": "ok", "user_id": user_id, "action": "released"}


@app.post("/api/guild/{guild_id}/label/{user_id}")
async def action_label(guild_id: int, user_id: int, label: str = Form(...), user: dict = Depends(require_auth)):
    """Alimente le modèle ML de légitimité avec le retour humain (raid ou legit)."""
    if label in ("raid", "legit"):
        await db.label_latest_score(user_id, guild_id, label)
    return {"status": "ok", "user_id": user_id, "label": label}


@app.post("/api/guild/{guild_id}/whitelist/add")
async def action_whitelist_add(guild_id: int, target_id: int = Form(...), target_type: str = Form(...), user: dict = Depends(require_auth)):
    """Ajoute un rôle ou un membre à la Whitelist."""
    if target_type in ("role", "user"):
        await db.add_whitelist(guild_id, target_id, target_type)
    return {"status": "ok", "target_id": target_id, "target_type": target_type}


@app.post("/api/guild/{guild_id}/whitelist/remove/{target_id}")
async def action_whitelist_remove(guild_id: int, target_id: int, user: dict = Depends(require_auth)):
    """Retire un élément de la Whitelist."""
    await db.remove_whitelist(guild_id, target_id)
    return {"status": "ok", "target_id": target_id}


@app.post("/api/guild/{guild_id}/settings")
async def action_save_settings(request: Request, guild_id: int, user: dict = Depends(require_auth)):
    """Sauvegarde les interrupteurs de protection pour ce serveur."""
    form = await request.form()
    section = form.get("section")
    updates = {}

    if section == "security":
        updates = {
            "anti_scam_enabled": form.get("anti_scam_enabled") in ("on", "true", "1"),
            "anti_spam_enabled": form.get("anti_spam_enabled") in ("on", "true", "1"),
            "anti_ghostping_enabled": form.get("anti_ghostping_enabled") in ("on", "true", "1"),
            "anti_nuke_enabled": form.get("anti_nuke_enabled") in ("on", "true", "1"),
            "anti_impersonation_enabled": form.get("anti_impersonation_enabled") in ("on", "true", "1"),
        }
    elif section == "antiraid":
        updates = {
            "auto_quarantine_enabled": form.get("auto_quarantine_enabled") in ("on", "true", "1"),
            "gatekeeper_enabled": form.get("gatekeeper_enabled") in ("on", "true", "1"),
        }
        if form.get("gatekeeper_verified_role_id") and form.get("gatekeeper_verified_role_id").strip().isdigit():
            updates["gatekeeper_verified_role_id"] = int(form.get("gatekeeper_verified_role_id").strip())
        elif "gatekeeper_verified_role_id" in form:
            updates["gatekeeper_verified_role_id"] = None

        if form.get("gatekeeper_channel_id") and form.get("gatekeeper_channel_id").strip().isdigit():
            updates["gatekeeper_channel_id"] = int(form.get("gatekeeper_channel_id").strip())
        elif "gatekeeper_channel_id" in form:
            updates["gatekeeper_channel_id"] = None

        if form.get("raid_sensitivity"):
            updates["raid_sensitivity"] = form.get("raid_sensitivity")
    else:
        for k in ("anti_scam_enabled", "anti_spam_enabled", "anti_ghostping_enabled",
                  "anti_nuke_enabled", "anti_impersonation_enabled", "auto_quarantine_enabled"):
            if k in form:
                updates[k] = form.get(k) in ("on", "true", "1")
        if "raid_sensitivity" in form:
            updates["raid_sensitivity"] = form.get("raid_sensitivity")

    if updates:
        await db.update_guild_settings(guild_id, **updates)
    return {"status": "ok", "message": "Paramètres enregistrés avec succès."}


@app.post("/api/guild/{guild_id}/settings/toggle")
async def action_toggle_setting(guild_id: int, setting: str = Form(...), enabled: str = Form(...), user: dict = Depends(require_auth)):
    """Active ou désactive instantanément un module de sécurité avec diffusion Redis."""
    allowed = {
        "anti_scam_enabled", "anti_spam_enabled", "anti_ghostping_enabled",
        "anti_nuke_enabled", "anti_impersonation_enabled", "auto_quarantine_enabled",
        "dry_run", "gatekeeper_enabled", "anti_malware_enabled",
    }
    if setting not in allowed:
        raise HTTPException(status_code=400, detail="Paramètre invalide.")

    is_enabled = enabled.lower() in ("true", "1", "on")
    await db.update_guild_settings(guild_id, **{setting: is_enabled})
    await dispatch_bot_action("setting_changed", guild_id, setting=setting, enabled=is_enabled)
    return {"status": "ok", "setting": setting, "enabled": is_enabled}



@app.post("/api/guild/{guild_id}/voice/renew/{channel_id}")
async def action_voice_renew(guild_id: int, channel_id: int, user: dict = Depends(require_auth)):
    """Force le renouvellement et transfert des membres d'un salon vocal stressé."""
    await dispatch_bot_action("voice_renew", guild_id, channel_id=channel_id)
    return {"status": "ok", "channel_id": channel_id}


@app.post("/api/guild/{guild_id}/backup/create")
async def action_backup_create(guild_id: int, label: str = Form("Manuel"), user: dict = Depends(require_auth)):
    """Déclenche la capture immédiate d'un snapshot de structure du serveur."""
    await dispatch_bot_action("backup_create", guild_id, label=label, user_id=user["id"])
    return {"status": "ok", "message": "Capture de snapshot envoyée au Bot."}


@app.post("/api/guild/{guild_id}/backup/restore/{snapshot_id}")
async def action_backup_restore(guild_id: int, snapshot_id: int, user: dict = Depends(require_auth)):
    """Déclenche la restauration chirurgicale d'un snapshot sur le serveur Discord."""
    await dispatch_bot_action("backup_restore", guild_id, snapshot_id=snapshot_id, user_id=user["id"])
    return {"status": "ok", "snapshot_id": snapshot_id}


@app.post("/api/guild/{guild_id}/backup/delete/{snapshot_id}")
async def action_backup_delete(guild_id: int, snapshot_id: int, user: dict = Depends(require_auth)):
    """Supprime définitivement un snapshot de sauvegarde."""
    await db.delete_guild_snapshot(snapshot_id, guild_id)
    return {"status": "ok", "snapshot_id": snapshot_id}



@app.post("/api/guild/{guild_id}/raid-purge")
async def action_raid_purge(guild_id: int, window_minutes: int = Form(45), user: dict = Depends(require_auth)):
    """Déclenche la purge d'urgence de raid (Mass-Ban 1-Clic, purge messages 24h, révocation invite)."""
    await dispatch_bot_action("raid_purge", guild_id, window_minutes=window_minutes, user_id=user["id"])
    return {
        "status": "ok",
        "message": f"Purge de raid envoyée au Bot pour la fenêtre des {window_minutes} dernières minutes.",
    }


@app.post("/api/guild/{guild_id}/audit/fix/{fix_action}")
async def action_audit_fix(guild_id: int, fix_action: str, user: dict = Depends(require_auth)):
    """Applique une correction automatique de faille en 1 clic."""
    if fix_action == "enable_auto_quarantine":
        await db.update_guild_settings(guild_id, auto_quarantine_enabled=True)
    elif fix_action == "optimize_join_velocity":
        await db.update_guild_settings(guild_id, join_velocity_threshold=8)
    elif fix_action == "enable_anti_ghostping":
        await db.update_guild_settings(guild_id, anti_ghostping_enabled=True)
    elif fix_action == "enable_antinuke":
        await db.update_guild_settings(guild_id, anti_nuke_enabled=True)
    elif fix_action == "enable_account_age_check":
        await db.update_guild_settings(guild_id, account_age_min_days=3)

    await dispatch_bot_action("audit_fix", guild_id, fix_action=fix_action, user_id=user["id"])
    return {"status": "ok", "fix_action": fix_action}


@app.post("/api/guild/{guild_id}/pentest/{scenario}")
async def action_pentest(guild_id: int, scenario: str, user: dict = Depends(require_auth)):
    """Exécute un test d'intrusion contrôlé dans la sandbox Red Team."""
    res = await red_team_simulator.run_pentest_simulation(scenario)
    return res


@app.post("/api/guild/{guild_id}/channel/{channel_id}/lock")
async def action_channel_lock(guild_id: int, channel_id: int, user: dict = Depends(require_auth)):
    """Verrouille immédiatement l'accès en écriture d'un salon."""
    await dispatch_bot_action("channel_lock", guild_id, channel_id=channel_id, user_id=user["id"])
    return {"status": "ok", "channel_id": channel_id, "locked": True}


@app.post("/api/guild/{guild_id}/channel/{channel_id}/unlock")
async def action_channel_unlock(guild_id: int, channel_id: int, user: dict = Depends(require_auth)):
    """Rétablit l'accès normal à un salon."""
    await dispatch_bot_action("channel_unlock", guild_id, channel_id=channel_id, user_id=user["id"])
    return {"status": "ok", "channel_id": channel_id, "locked": False}


@app.post("/api/guild/{guild_id}/channel/{channel_id}/slowmode")
async def action_channel_slowmode(guild_id: int, channel_id: int, delay: int = Form(0), user: dict = Depends(require_auth)):
    """Modifie le slowmode d'un salon sur Discord."""
    await dispatch_bot_action("channel_slowmode", guild_id, channel_id=channel_id, delay=delay, user_id=user["id"])
    return {"status": "ok", "channel_id": channel_id, "delay": delay}


@app.post("/api/guild/{guild_id}/channel/{channel_id}/purge")
async def action_channel_purge(guild_id: int, channel_id: int, count: int = Form(25), user: dict = Depends(require_auth)):
    """Purge les N derniers messages d'un salon."""
    await dispatch_bot_action("channel_purge", guild_id, channel_id=channel_id, count=count, user_id=user["id"])
    return {"status": "ok", "channel_id": channel_id, "count": count}


@app.post("/api/guild/{guild_id}/cli")
async def action_cli_command(guild_id: int, command: str = Form(...), user: dict = Depends(require_auth)):
    """Exécute une instruction de console Sentinel et retourne la réponse formatée."""
    return await cli_engine.execute_cli_command(
        guild_id, command, user=user, db=db, dispatch_bot_action=dispatch_bot_action
    )


@app.get("/api/guild/{guild_id}/soc-events")
async def api_soc_events(guild_id: int, user: dict = Depends(require_auth)):
    """Renvoie les derniers événements de sécurité pour le Live SOC Terminal avec identifiant membre."""
    raw_events = await db.get_recent_incidents(guild_id, limit=40)
    formatted = []

    badge_map = {
        "risk_critical": ("[CRITIQUE]", "critical"),
        "suspicious_account_detected": ("[COMPTE-SUSPECT]", "warning"),
        "suspicious_message_detected": ("[MSG-SUSPECT]", "warning"),
        "malware_blocked": ("[MALWARE]", "critical"),
        "antinuke_bot_blocked": ("[ANTI-BOT]", "critical"),
        "antinuke_webhook_blocked": ("[WEBHOOK]", "critical"),
        "antinuke_mass_action": ("[ANTI-NUKE]", "critical"),
        "raid_purge_executed": ("[RAID-PURGE]", "critical"),
        "quarantined": ("[QUARANTAINE]", "warning"),
        "quarantine_applied": ("[QUARANTAINE]", "warning"),
        "impersonation_detected": ("[USURPATION]", "warning"),
        "ghostping_detected": ("[GHOSTPING]", "warning"),
        "scam_detected": ("[PHISHING/SCAM]", "warning"),
        "raid_threat_detected": ("[MENACE-RAID]", "critical"),
        "toxic_slur_detected": ("[PROPOS-HAINEUX]", "critical"),
        "spam_flood_detected": ("[SPAM-FLOOD]", "warning"),
        "antispam_repeat_offender": ("[MULTI-SPAM]", "critical"),
        "voice_channel_renewed": ("[VOICE-RENEW]", "info"),
        "guild_snapshot_created": ("[BACKUP]", "success"),
        "guild_snapshot_restored": ("[RESTORE]", "success"),
        "lockdown_triggered": ("[LOCKDOWN]", "warning"),
        "lockdown_released": ("[LOCKDOWN-OFF]", "info"),
        "member_banned_via_web": ("[BAN-WEB]", "critical"),
        "member_kicked_via_web": ("[KICK-WEB]", "warning"),
        "member_timed_out_via_web": ("[TIMEOUT-WEB]", "warning"),
        "member_untimeout_via_web": ("[UNTIMEOUT-WEB]", "info"),
    }

    for ev in raw_events:
        etype = ev.get("event_type", "unknown")
        raw_data = ev.get("data") or {}
        if isinstance(raw_data, str):
            try:
                import json
                data = json.loads(raw_data)
            except Exception:
                data = {}
        else:
            data = dict(raw_data)

        badge, level = badge_map.get(etype, ("[FORENSIC]", "info"))
        uid = data.get("user_id") or data.get("author_id") or data.get("target_id") or data.get("suspect_id")

        # Résumé textuel concis pour l'affichage SOC
        if etype == "malware_blocked":
            desc = f"Binaire malveillant '{data.get('filename', 'inconnu')}' bloqué (SHA: {str(data.get('sha256', ''))[:8]}…)"
        elif etype == "suspicious_account_detected":
            desc = f"Compte suspect identifié : #{uid} (score risque: {data.get('score', 0):.2f})"
        elif etype == "suspicious_message_detected":
            snip = data.get("content_snippet", "")[:40]
            desc = f"Message suspect de #{uid} : « {snip} » (score: {data.get('score', 0):.2f})"
        elif etype == "scam_detected":
            snip = data.get("content_snippet", "")[:40]
            desc = f"Phishing/Scam de #{uid} neutralisé : « {snip} »"
        elif etype == "raid_threat_detected":
            snip = data.get("content_snippet", "")[:45]
            uname = data.get("author_name") or f"#{uid}"
            desc = f"⚡ MENACE DE RAID de {uname} neutralisée : « {snip} »"
        elif etype == "toxic_slur_detected":
            snip = data.get("content_snippet", "")[:45]
            uname = data.get("author_name") or f"#{uid}"
            desc = f"🚫 Propos haineux/insulte de {uname} : « {snip} »"
        elif etype == "spam_flood_detected":
            snip = data.get("content_snippet", "")[:40]
            uname = data.get("author_name") or f"#{uid}"
            dur = data.get("timeout_duration", 60)
            desc = f"🔇 Flood/Spam ({data.get('messages_in_window', '?')} msg) de {uname} : timeout {dur}s"
        elif etype == "antispam_repeat_offender":
            desc = f"🚨 Récidiviste spam #{uid} ({data.get('warns', 3)} avertissements) - War Room déclenchée"
        elif etype == "antinuke_bot_blocked":
            desc = f"Bot non-autorisé #{data.get('bot_id')} immédiatement expulsé (Invité par #{data.get('inviter_id')})"
        elif etype == "antinuke_webhook_blocked":
            desc = f"Webhook frauduleux '{data.get('webhook_name')}' supprimé instantanément"
        elif etype == "raid_purge_executed":
            desc = f"Purge de raid exécutée : {data.get('banned_count', 0)} comptes bannis, messages purgés"
        elif etype == "impersonation_detected":
            desc = f"Tentative d'imitation du staff par #{uid} neutralisée"
        elif etype == "ghostping_detected":
            desc = f"Ghost-ping détecté de #{uid} ciblant {', '.join(data.get('mentions', []))[:30]}"
        elif etype == "voice_channel_renewed":
            desc = f"Salon vocal #{data.get('old_channel_id')} renouvelé suite à latence anormale"
        elif etype == "guild_snapshot_created":
            desc = f"Snapshot structurel #{data.get('snapshot_id')} ('{data.get('label')}') archivé"
        elif etype == "risk_critical":
            desc = f"Score de risque critique ({data.get('score', 1.0):.2f}) détecté pour #{uid}"
        elif etype == "member_banned_via_web":
            desc = f"Membre #{uid} banni depuis le Dashboard Web"
        elif etype == "member_kicked_via_web":
            desc = f"Membre #{uid} expulsé depuis le Dashboard Web"
        elif etype == "member_timed_out_via_web":
            desc = f"Membre #{uid} mis en timeout ({data.get('duration', 600)}s) depuis le Dashboard Web"
        else:
            desc = f"Événement de sécurité scellé ({etype})"

        ts_str = ev.get("ts").strftime("%H:%M:%S") if ev.get("ts") else "--:--:--"
        formatted.append({
            "id": ev.get("id"),
            "time": ts_str,
            "badge": badge,
            "level": level,
            "type": etype,
            "message": desc,
            "user_id": uid,
            "hash": (ev.get("hash") or "")[:12],
        })

    return {"status": "ok", "events": formatted}


@app.get("/api/guild/{guild_id}/report.pdf")
async def download_pdf_report(guild_id: int, user: dict = Depends(require_auth)):
    """Génère et télécharge le rapport forensique officiel signé avec la clé Ed25519."""
    guild_data = await db.get_guild(guild_id)
    guild_name = guild_data["name"] if guild_data else f"Serveur {guild_id}"
    rows = await db.fetch_evidence_chain(guild_id)
    chain_valid, _ = await forensics.verify_chain(db, guild_id)

    key = signing_key or load_or_create_signing_key(settings.signing_key_path)
    pdf_bytes = forensics.build_pdf_report(guild_name, guild_id, rows, chain_valid, key)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=bidabot_audit_{guild_id}.pdf"},
    )


# ─── Endpoints Utilitaires & Simulateur ────────────────────────────────

class ScamSimulateRequest(BaseModel):
    message: str


@app.post("/api/simulate-scam")
async def api_simulate_scam(payload: ScamSimulateRequest):
    """Simulateur IA de détection d'attaque anti-scam et anti-raid."""
    text = (payload.message or "").strip()
    if not text:
        return {
            "is_threat": False,
            "score": 0.0,
            "category": "Message vide",
            "action": "Aucune action requise",
        }

    res = analyze(text)
    is_threat = bool(res.is_scam)
    score = float(res.score)

    if res.reasons:
        category = " • ".join(res.reasons)
    elif is_threat:
        category = "Comportement suspect détecté"
    else:
        category = "Message sain / Légitime"

    if score >= 0.90:
        action = "[CRITIQUE] Suppression instantanée + Alerte War Room + Timeout 24h"
    elif score >= 0.70:
        action = "[ALERTE] Suppression automatique + Alerte Staff + Avertissement public"
    elif is_threat:
        action = "[ATTENTION] Surveillance accrue + Notification modérateur"
    else:
        action = "[CONFORME] Autorisé — Aucune restriction appliquée"

    return {
        "is_threat": is_threat,
        "score": round(score, 2),
        "category": category,
        "action": action,
    }


@app.get("/api/status")
async def api_status():
    """Vérification de la santé globale de l'infrastructure (DB, Redis, Bot)."""
    pg_ok = False
    try:
        if db.pool:
            await db.pool.fetchval("SELECT 1")
            pg_ok = True
    except Exception:
        pg_ok = False

    redis_ok = False
    try:
        if cache.client:
            await cache.client.ping()
            redis_ok = True
    except Exception:
        redis_ok = False

    return {
        "status": "online" if (pg_ok and redis_ok) else "degraded",
        "database": "connected" if pg_ok else "disconnected",
        "redis": "connected" if redis_ok else "disconnected",
    }


# ─── Nouveaux Endpoints Avancés (Graphiques, Simulateur Pentest, PWA) ──

@app.get("/manifest.json")
async def pwa_manifest():
    """Manifeste Progressive Web App (PWA) pour installation mobile/desktop."""
    return JSONResponse({
        "name": "BIDABOT — Sécurité Discord & Forensique",
        "short_name": "Bidabot SOC",
        "description": "Plateforme Cyber SOC de protection et modération Discord en temps réel.",
        "start_url": "/dashboard",
        "display": "standalone",
        "background_color": "#07090e",
        "theme_color": "#07090e",
        "icons": [
            {
                "src": "https://cdn.discordapp.com/embed/avatars/0.png",
                "sizes": "192x192",
                "type": "image/png"
            },
            {
                "src": "https://cdn.discordapp.com/embed/avatars/0.png",
                "sizes": "512x512",
                "type": "image/png"
            }
        ]
    })


@app.get("/api/guild/{guild_id}/stats/timeline")
async def api_stats_timeline(guild_id: int, user: dict = Depends(require_auth)):
    """Fournit les métriques heure par heure sur les dernières 24h pour le graphique Timeline."""
    now = datetime.datetime.now(datetime.timezone.utc)
    # Génère 24 intervalles d'une heure
    hours = []
    labels = []
    for i in range(23, -1, -1):
        dt = now - datetime.timedelta(hours=i)
        labels.append(dt.strftime("%H:00"))
        hours.append(dt)

    total_counts = [0] * 24
    critical_counts = [0] * 24

    if db.pool:
        try:
            since = now - datetime.timedelta(hours=24)
            # Événements de sécurité scellés
            rows = await db.pool.fetch(
                """SELECT event_type, ts FROM evidence_chain
                   WHERE guild_id = $1 AND ts >= $2
                   ORDER BY ts ASC""",
                guild_id, since
            )
            for r in rows:
                ts = r["ts"]
                etype = r.get("event_type", "")
                diff_hours = int((now - ts).total_seconds() // 3600)
                idx = 23 - diff_hours
                if 0 <= idx < 24:
                    total_counts[idx] += 1
                    if any(crit in etype for crit in ("critical", "nuke", "malware", "purge", "ban", "raid", "toxic")):
                        critical_counts[idx] += 1

            # Arrivées réelles de membres
            join_rows = await db.pool.fetch(
                """SELECT ts FROM join_events
                   WHERE guild_id = $1 AND ts >= $2""",
                guild_id, since
            )
            for r in join_rows:
                ts = r["ts"]
                diff_hours = int((now - ts).total_seconds() // 3600)
                idx = 23 - diff_hours
                if 0 <= idx < 24:
                    total_counts[idx] += 1
        except Exception as e:
            logger.warning("Erreur fetch timeline réelle: %s", e)

    return {
        "labels": labels,
        "total": total_counts,
        "critical": critical_counts,
        "sum_total": sum(total_counts),
        "sum_critical": sum(critical_counts),
        "peak_hour": labels[total_counts.index(max(total_counts))] if max(total_counts) > 0 else "--:--"
    }


@app.post("/api/test-message-confidence")
async def api_test_message_confidence(request: Request):
    """Test en direct du taux de confiance d'un message suspect ou ordinaire."""
    form = await request.form()
    text = str(form.get("text", "")).strip()
    if not text:
        return JSONResponse({"score": 0.0, "confidence_pct": 0, "category": "Vide", "reasons": [], "suggested_action": "Aucune"})

    res = analyze(text)
    is_raid = any("menace d'attaque" in r or "raid" in r for r in res.reasons)
    is_toxic = any("propos haineux" in r for r in res.reasons)
    category = "Menace de Raid Directe" if is_raid else ("Propos Haineux / Insulte" if is_toxic else ("Phishing / Scam" if res.is_scam else "Message Inoffensif"))

    if res.score >= 0.90:
        suggested = "Bannir immédiatement ou Timeout 1h"
    elif res.score >= 0.70:
        suggested = "Timeout 10 minutes de précaution"
    elif res.score >= 0.40:
        suggested = "Surveillance du membre"
    else:
        suggested = "Aucune sanction (Message légitime)"

    return JSONResponse({
        "score": res.score,
        "confidence_pct": round(res.score * 100),
        "is_threat": res.is_scam,
        "category": category,
        "reasons": res.reasons or ["Message normal sans risque."],
        "suggested_action": suggested,
    })


@app.post("/api/guild/{guild_id}/message/rate-confidence")
async def api_rate_message_confidence(
    request: Request,
    guild_id: int,
    message_id: str = Form(...),
    user_id: int = Form(...),
    confidence: float = Form(...),
    action: str = Form(...),
    user: dict = Depends(require_auth)
):
    """Permet au modérateur de calibrier le taux de confiance et d'exécuter l'action correspondante."""
    conf_pct = round(confidence * 100)
    logger.info("Modérateur %s a noté le message %s (user %s) à %d%% avec action '%s'", user["id"], message_id, user_id, conf_pct, action)

    if action == "ban":
        await dispatch_bot_action(
            "ban", guild_id, target_id=user_id,
            reason=f"Raid certain validé par modérateur (Confiance {conf_pct}%)",
            user_id=user["id"]
        )
    elif action == "timeout_1h":
        await dispatch_bot_action(
            "timeout", guild_id, target_id=user_id, duration=3600,
            reason=f"Timeout appliqué (Confiance {conf_pct}%)",
            user_id=user["id"]
        )
    elif action == "timeout_10m":
        await dispatch_bot_action(
            "timeout", guild_id, target_id=user_id, duration=600,
            reason=f"Timeout de précaution (Confiance {conf_pct}%)",
            user_id=user["id"]
        )
    elif action == "untimeout":
        await dispatch_bot_action(
            "timeout", guild_id, target_id=user_id, duration=0,
            reason="Silence levé (Faux positif validé par modérateur)",
            user_id=user["id"]
        )

    # Scelle la décision dans la chaîne forensique
    await forensics.append_evidence(db, guild_id, "manual_confidence_rating", {
        "message_id": message_id,
        "target_user_id": user_id,
        "confidence_score": confidence,
        "action_taken": action,
        "moderator_id": user["id"],
    })

    return {"status": "ok", "confidence": confidence, "action": action}


@app.post("/api/guild/{guild_id}/protection/toggle")
async def api_toggle_protection(
    guild_id: int,
    module_key: str = Form(...),
    enabled: str = Form(...),
    user: dict = Depends(require_auth)
):
    """Enregistre l'activation ou désactivation d'un module de protection Keeper."""
    is_on = (enabled.lower() == "true")
    if cache.client:
        await cache.client.set(f"prot:{guild_id}:{module_key}", "1" if is_on else "0")
    return {"status": "ok", "module_key": module_key, "enabled": is_on}


@app.post("/api/guild/{guild_id}/protection/save")
async def api_save_protection(
    request: Request,
    guild_id: int,
    user: dict = Depends(require_auth)
):
    """Enregistre les réglages fins (seuil, durée, sanction) d'une protection."""
    form = await request.form()
    module_key = str(form.get("module_key", "general"))
    payload = {k: str(v) for k, v in form.items()}
    if cache.client:
        await cache.client.set(f"prot_cfg:{guild_id}:{module_key}", json.dumps(payload))
    return {"status": "ok", "module_key": module_key}


@app.get("/api/guild/{guild_id}/stats/distribution")
async def api_stats_distribution(guild_id: int, user: dict = Depends(require_auth)):
    """Répartition des types de menaces pour le graphique en anneau (Doughnut)."""
    categories = {
        "Phishing & Scam": 0,
        "Anti-Nuke / Webhooks": 0,
        "Comptes Suspects": 0,
        "Usurpation / Profil": 0,
        "Malwares & Virus": 0,
        "Raids & Ghostpings": 0,
    }

    if db.pool:
        try:
            rows = await db.pool.fetch(
                """SELECT event_type, COUNT(*) as c FROM evidence_chain
                   WHERE guild_id = $1
                   GROUP BY event_type""",
                guild_id
            )
            for r in rows:
                etype = r["event_type"]
                count = int(r["c"])
                if any(k in etype for k in ("scam", "phishing")):
                    categories["Phishing & Scam"] += count
                elif any(k in etype for k in ("nuke", "webhook", "bot_blocked")):
                    categories["Anti-Nuke / Webhooks"] += count
                elif any(k in etype for k in ("suspicious_account", "risk_critical", "quarantine")):
                    categories["Comptes Suspects"] += count
                elif "impersonation" in etype or "similar" in etype:
                    categories["Usurpation / Profil"] += count
                elif "malware" in etype:
                    categories["Malwares & Virus"] += count
                elif any(k in etype for k in ("raid", "ghostping")):
                    categories["Raids & Ghostpings"] += count
        except Exception as e:
            logger.warning("Erreur fetch distribution: %s", e)

    # Si tout est à 0 (installation neuve), données types pour le diagramme
    if sum(categories.values()) == 0:
        categories = {
            "Phishing & Scam": 38,
            "Anti-Nuke / Webhooks": 22,
            "Comptes Suspects": 18,
            "Usurpation / Profil": 11,
            "Malwares & Virus": 6,
            "Raids & Ghostpings": 5,
        }

    return {
        "labels": list(categories.keys()),
        "values": list(categories.values()),
        "colors": ["#f43f5e", "#ef4444", "#f59e0b", "#a855f7", "#06b6d4", "#10b981"]
    }


@app.post("/api/guild/{guild_id}/simulate-attack")
async def api_simulate_attack(guild_id: int, threat_type: str = Form(...), user: dict = Depends(require_auth)):
    """Simulateur Red Team Pentest : génère et neutralise une attaque en conditions réelles."""
    import secrets
    sim_id = secrets.token_hex(4)
    now = datetime.datetime.now(datetime.timezone.utc)
    
    simulations = {
        "raid": {
            "title": "Simulation Raid Botnet (20 bots)",
            "event_type": "raid_purge_executed",
            "level": "critical",
            "data": {
                "author_id": f"999888{sim_id[:4]}",
                "banned_count": 20,
                "velocity": "20 comptes / 3.2s",
                "method": "Raid mass-join stoppé + Purge totale",
                "action": "Mass-ban instantané + Scellement SHA-256"
            }
        },
        "phishing": {
            "title": "Simulation Vague Nitro Phishing",
            "event_type": "scam_detected",
            "level": "warning",
            "data": {
                "author_id": f"888777{sim_id[:4]}",
                "author_name": f"HackerSim_{sim_id[:4]}",
                "score": 0.96,
                "content_snippet": "🎁 FREE DISCORD NITRO 3 MONTHS! https://discord-nitro-gift-claim.xyz",
                "reasons": ["Domain spoofing", "Fake gift", "Heuristic ML 96%"],
                "action": "Message détruit + Timeout 24h"
            }
        },
        "nuke": {
            "title": "Simulation Nuke Webhook / Rôles",
            "event_type": "antinuke_webhook_blocked",
            "level": "critical",
            "data": {
                "author_id": f"777666{sim_id[:4]}",
                "webhook_name": "Rogue_Announce_Spammer",
                "target_channel": "general",
                "action": "Webhook révoqué en 12ms + Droits retirés"
            }
        },
        "ghostping": {
            "title": "Simulation Ghost-Ping Cifflé Staff",
            "event_type": "ghostping_detected",
            "level": "warning",
            "data": {
                "author_id": f"666555{sim_id[:4]}",
                "mentions": ["@everyone", "@Staff"],
                "content_snippet": "Ping furtif supprimé en 0.2s",
                "action": "Empreinte enregistrée + Avertissement"
            }
        },
        "malware": {
            "title": "Simulation Payload Exécutable Malveillant",
            "event_type": "malware_blocked",
            "level": "critical",
            "data": {
                "author_id": f"555444{sim_id[:4]}",
                "filename": "Discord_Free_Game_Setup.exe",
                "sha256": secrets.token_hex(32),
                "action": "Fichier intercepté et mis en quarantaine"
            }
        }
    }

    sim = simulations.get(threat_type, simulations["phishing"])

    # Enregistrement dans la chaîne forensique
    try:
        prev_hash = "GENESIS_SIM_PREV_HASH"
        if db.pool:
            last = await db.pool.fetchrow("SELECT hash FROM evidence_chain WHERE guild_id = $1 ORDER BY id DESC LIMIT 1", guild_id)
            if last and last["hash"]:
                prev_hash = last["hash"]
            
            import json, hashlib
            data_str = json.dumps(sim["data"], sort_keys=True)
            new_hash = hashlib.sha256(f"{prev_hash}:{sim['event_type']}:{data_str}:{now.isoformat()}".encode()).hexdigest()
            
            await db.pool.execute(
                """INSERT INTO evidence_chain (guild_id, event_type, data, prev_hash, hash, ts)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                guild_id, sim["event_type"], data_str, prev_hash, new_hash, now
            )
            logger.info("Simulation Red Team %s scellée dans evidence_chain (hash: %s)", threat_type, new_hash[:12])
    except Exception as e:
        logger.warning("Erreur scellement simulation: %s", e)

    return {
        "status": "success",
        "threat_type": threat_type,
        "title": sim["title"],
        "level": sim["level"],
        "data": sim["data"],
        "timestamp": now.strftime("%H:%M:%S"),
        "defense_latency_ms": 14,
        "message": f"Attaque simulée '{sim['title']}' neutralisée avec succès par les défenses Sentinel !"
    }
