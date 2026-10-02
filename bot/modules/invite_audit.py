"""
Module 17 — Audit d'invitations.

Mécanisme : à chaque join, compare la liste des invitations AVANT/APRÈS
pour identifier laquelle a été utilisée (la seule dont le uses a augmenté
d'exactement 1, ou dont le nombre d'utilisations a changé).

Raison du pattern snapshot : Discord n'expose pas directement "quel lien a
été utilisé" dans l'événement on_member_join. La seule façon fiable est de
différer la snapshot post-join de ~500ms (délai réseau Discord) et de
comparer avec la snapshot pré-join maintenue en cache Redis.

Détection de lien vérolé :
- Si X% des joiners dans une fenêtre glissante utilisent le même lien → alerte
- Si ce ratio dépasse le seuil critique → révocation automatique du lien +
  chaîne forensique + bus "risk_critical"
- Le bot a besoin de la permission MANAGE_GUILD pour lire et révoquer les
  invitations.

Limites connues :
- Les liens d'invitation à usage unique (max_uses=1) sont visibles 0 fois
  après usage → non différenciables de liens expirés normalement.
- Les liens créés par des bots tiers (Mee6, etc.) apparaissent quand même
  dans la liste, ce qui peut créer de faux positifs → filtrage par créateur.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

import discord

logger = logging.getLogger("sentinel.invite_audit")

# Cache mémoire des snapshots d'invitations : guild_id → {code: uses}
# Aussi persisté en Redis (clé sentinel:invsnap:{guild_id}) pour survivre aux restarts.
_invite_cache: dict[int, dict[str, int]] = {}
_REDIS_SNAP_KEY = "sentinel:invsnap:{guild_id}"
_REDIS_SNAP_TTL = 3600  # 1h (les invitations évoluent, on ne veut pas de snapshot trop vieux)


async def snapshot(guild: discord.Guild, redis_client=None) -> dict[str, int]:
    """Prend un snapshot des invitations courantes. Retourne {} si pas de
    permission MANAGE_GUILD.
    Si redis_client est fourni, persiste le snapshot en Redis (survit aux restarts)."""
    try:
        invites = await guild.invites()
        snap = {inv.code: inv.uses or 0 for inv in invites}
        _invite_cache[guild.id] = snap
        # Persistance Redis
        if redis_client:
            import json as _json
            key = _REDIS_SNAP_KEY.format(guild_id=guild.id)
            await redis_client.set(key, _json.dumps(snap), ex=_REDIS_SNAP_TTL)
        return snap
    except discord.Forbidden:
        logger.debug("Pas de permission MANAGE_GUILD sur %s → audit d'invitations désactivé", guild.name)
        return {}


async def detect_used_invite(guild: discord.Guild, redis_client=None) -> discord.Invite | None:
    """
    Appelé ~500ms après on_member_join.
    Compare le snapshot actuel avec le cache précédent pour identifier
    l'invitation utilisée.
    Si le cache mémoire est vide (restart), tente de le restaurer depuis Redis.
    Retourne l'objet discord.Invite ou None si indétectable.
    """
    await asyncio.sleep(0.5)  # attend la propagation côté Discord API

    # Restauration depuis Redis si cache mémoire vide (après restart)
    if guild.id not in _invite_cache and redis_client:
        import json as _json
        key = _REDIS_SNAP_KEY.format(guild_id=guild.id)
        raw = await redis_client.get(key)
        if raw:
            _invite_cache[guild.id] = _json.loads(raw)
            logger.debug("Snapshot d'invitations restauré depuis Redis pour %s", guild.name)

    old = _invite_cache.get(guild.id, {})
    try:
        new_invites = await guild.invites()
    except discord.Forbidden:
        return None

    new_snap = {inv.code: (inv.uses or 0, inv) for inv in new_invites}
    snap_to_store = {code: data[0] for code, data in new_snap.items()}
    _invite_cache[guild.id] = snap_to_store
    if redis_client:
        import json as _json
        key = _REDIS_SNAP_KEY.format(guild_id=guild.id)
        await redis_client.set(key, _json.dumps(snap_to_store), ex=_REDIS_SNAP_TTL)

    for code, (new_uses, inv_obj) in new_snap.items():
        old_uses = old.get(code, 0)
        if new_uses > old_uses:
            return inv_obj

    # Lien à usage unique (disparu de la liste après usage) → cherche les disparus
    for code in old:
        if code not in new_snap:
            logger.debug("Lien %s disparu après le join (probablement usage unique)", code)
    return None


async def record_join(guild_id: int, user_id: int, invite: discord.Invite | None, db) -> None:
    """Enregistre l'invitation utilisée dans invite_usage."""
    if invite:
        await db.record_invite_usage(
            guild_id=guild_id, user_id=user_id,
            invite_code=invite.code,
            inviter_id=invite.inviter.id if invite.inviter else None,
        )


async def check_raid_via_invite(guild: discord.Guild, db, bus, append_evidence, *,
                                  dashboard_module=None,
                                  window_seconds: int = 120,
                                  raid_ratio_threshold: float = 0.70,
                                  min_joiners: int = 5) -> dict | None:
    """
    Vérifie si un lien d'invitation est utilisé par une proportion anormale
    des joiners récents (signal de lien de raid diffusé en masse).

    Processus :
    1. Récupère les invitations utilisées dans la fenêtre glissante depuis la DB
    2. Calcule la distribution d'usage par code
    3. Si un code représente >raid_ratio_threshold des joins ET qu'il y a
       au moins min_joiners → c'est suspect
    4. Si le lien est encore actif ET que le ratio > 0.85 → révocation auto
    """
    rows = await db.get_invite_usage_window(guild.id, window_seconds)
    if len(rows) < min_joiners:
        return None

    counts: dict[str, int] = defaultdict(int)
    for r in rows:
        if r["invite_code"]:
            counts[r["invite_code"]] += 1

    if not counts:
        return None

    top_code = max(counts, key=counts.__getitem__)
    top_count = counts[top_code]
    ratio = top_count / len(rows)

    if ratio < raid_ratio_threshold:
        return None

    # Cherche l'objet Invite pour obtenir les métadonnées et éventuellement révoquer
    invite_obj: discord.Invite | None = None
    try:
        invite_obj = await guild.fetch_invite(top_code)
    except (discord.NotFound, discord.Forbidden):
        pass

    if not invite_obj:
        try:
            for inv in await guild.invites():
                if inv.code == top_code:
                    invite_obj = inv
                    break
        except (discord.Forbidden, discord.HTTPException):
            pass

    inviter_id = invite_obj.inviter.id if invite_obj and invite_obj.inviter else None
    auto_revoked = False

    # Révocation automatique dès que le lien concentre 70% ou plus des arrivées suspectes
    if ratio >= 0.70 and invite_obj:
        try:
            await invite_obj.delete(reason="SENTINEL — lien de raid révoqué automatiquement (module 17)")
            auto_revoked = True
            logger.warning("Lien %s révoqué automatiquement sur %s (ratio=%.0f%%)",
                           top_code, guild.name, ratio * 100)
        except (discord.Forbidden, discord.HTTPException) as e:
            logger.warning("Impossible de révoquer %s sur %s : %s", top_code, guild.name, e)

    payload = {
        "guild_id": guild.id,
        "invite_code": top_code,
        "inviter_id": inviter_id,
        "joiners_via_link": top_count,
        "total_recent_joiners": len(rows),
        "ratio": round(ratio, 3),
        "auto_revoked": auto_revoked,
        "reason": "lien_raid_detecte",
        "score": min(1.0, ratio + 0.1),
        "signals": {
            "invite_code": top_code,
            "ratio": ratio,
            "auto_revoked": auto_revoked,
        },
    }

    entry = await append_evidence(guild.id, "invite_raid_detected", payload)
    payload["evidence_hash"] = entry["hash"]

    await db.flag_invite(guild.id, top_code, ratio, auto_revoked)
    await bus.emit("risk_critical", payload)

    if dashboard_module:
        await dashboard_module.send_alert(
            guild,
            title="🚫 Invitation de raid détectée",
            description=(
                f"**Code d'invitation :** `discord.gg/{top_code}`\n"
                f"**Utilisation :** `{top_count}/{len(rows)}` membres récents (`{ratio*100:.0f}%`)\n"
                f"**Statut :** {'Lien révoqué automatiquement 🛡️' if auto_revoked else '⚠️ Révocation manuelle requise (permissions manquantes)'}"
            ),
            color=0xFF0000 if auto_revoked else 0xFFAA00,
        )

    logger.warning(
        "Lien de raid détecté sur %s : %s utilisé par %.0f%% des joiners récents (%d/%d)%s",
        guild.name, top_code, ratio * 100, top_count, len(rows),
        " — révoqué" if auto_revoked else " — révocation manuelle nécessaire",
    )
    return payload
