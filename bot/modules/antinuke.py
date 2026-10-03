"""
Module 18 — Anti-Nuke & Protection contre un Staff/Bot compromis (Rogue Admin).

Surveille en temps réel les actions administratives critiques via les Audit Logs Discord :
- Suppression massive de salons (CHANNEL_DELETE)
- Suppression massive de rôles (ROLE_DELETE)
- Bannissements en rafale (MEMBER_BAN)
- Expulsions en rafale (MEMBER_KICK)
- Création abusive de webhooks (WEBHOOK_CREATE)
- Création massive de salons (CHANNEL_CREATE)

Si un compte dépasse le seuil configuré dans une fenêtre temporelle étroite :
1. Neutralisation immédiate : révocation de tous ses rôles à permissions sensibles + timeout 28j
2. Déclenchement du Lockdown d'urgence sur le serveur
3. Inscription dans la chaîne forensique immuable
4. Alerte critique War Room, Dashboard et DM au propriétaire du serveur
"""
from __future__ import annotations

import datetime
import inspect
import logging
import time
from collections import defaultdict
from typing import Any

import discord

logger = logging.getLogger("sentinel.antinuke")

# Seuils par défaut (action: (max_allowed, window_seconds))
DEFAULT_THRESHOLDS: dict[str, tuple[int, int]] = {
    "channel_delete": (3, 10),
    "role_delete": (3, 10),
    "member_ban": (4, 10),
    "member_kick": (4, 10),
    "webhook_create": (3, 15),
    "channel_create": (3, 10),
    "role_create": (3, 10),
}

# Mémoire de secours si Redis indisponible
_mem_windows: dict[str, list[float]] = defaultdict(list)


def _mem_sliding_window(key: str, window_seconds: int) -> int:
    now = time.time()
    cutoff = now - window_seconds
    timestamps = [t for t in _mem_windows[key] if t > cutoff]
    timestamps.append(now)
    _mem_windows[key] = timestamps
    return len(timestamps)


async def _count_action(cache: Any, key: str, window_seconds: int) -> int:
    if cache and hasattr(cache, "sliding_window_add_and_count"):
        try:
            return await cache.sliding_window_add_and_count(key, window_seconds)
        except Exception:
            pass
    return _mem_sliding_window(key, window_seconds)


DANGEROUS_PERMISSIONS = {
    "administrator", "manage_guild", "manage_channels", "manage_roles",
    "ban_members", "kick_members", "manage_messages", "mention_everyone",
    "manage_webhooks",
}


def get_dangerous_roles(member: discord.Member) -> list[discord.Role]:
    """Retourne les rôles possédant des permissions sensibles (hors @everyone)."""
    roles = []
    for r in member.roles:
        if r.is_default():
            continue
        perms = r.permissions
        if any(getattr(perms, p, False) for p in DANGEROUS_PERMISSIONS):
            roles.append(r)
    return roles


async def neutralize_actor(guild: discord.Guild, actor_id: int, reason: str) -> dict[str, Any]:
    """
    Dépouille l'acteur de tous ses rôles à pouvoirs et lui applique un timeout.
    """
    member = guild.get_member(actor_id)
    if not member:
        try:
            member = await guild.fetch_member(actor_id)
        except (discord.NotFound, discord.HTTPException):
            return {"success": False, "reason": "Membre introuvable"}

    roles_to_remove = get_dangerous_roles(member)
    removed_names = [r.name for r in roles_to_remove]
    
    # 1. Retrait des rôles sensibles
    if roles_to_remove and guild.me.guild_permissions.manage_roles:
        try:
            # Ne peut retirer que les rôles inférieurs au rôle le plus haut du bot
            manageable = []
            for r in roles_to_remove:
                can_manage = True
                try:
                    if hasattr(guild.me, "top_role") and r >= guild.me.top_role:
                        can_manage = False
                except TypeError:
                    can_manage = True
                if can_manage:
                    manageable.append(r)
            if manageable:
                await member.remove_roles(*manageable, reason=f"SENTINEL Anti-Nuke: {reason}")
        except discord.Forbidden:
            logger.warning("Permissions insuffisantes pour retirer les rôles de %s sur %s", member, guild.name)

    # 2. Timeout 28 jours (durée max Discord)
    timed_out = False
    if guild.me.guild_permissions.moderate_members:
        try:
            await member.timeout(datetime.timedelta(days=28), reason=f"SENTINEL Anti-Nuke: {reason}")
            timed_out = True
        except discord.Forbidden:
            logger.warning("Impossible de timeout %s sur %s", member, guild.name)

    return {
        "success": True,
        "member_id": actor_id,
        "removed_roles": removed_names,
        "timed_out": timed_out,
    }


async def check_action(
    guild: discord.Guild,
    action_name: str,
    target_id: int | None,
    *,
    cache: Any,
    db: Any,
    bus: Any,
    append_evidence: Any,
    lockdown_module: Any,
    dashboard_module: Any = None,
    custom_thresholds: dict[str, tuple[int, int]] | None = None,
) -> dict[str, Any] | None:
    """
    Point d'entrée principal appelé lors d'un événement sensible.
    Vérifie l'audit log pour trouver l'auteur, incrémente le compteur glissant
    et déclenche la neutralisation si le seuil est franchi.
    """
    if not guild.me.guild_permissions.view_audit_log:
        logger.debug("Pas de permission VIEW_AUDIT_LOG sur %s", guild.name)
        return None

    # Mappage des actions Discord
    action_map = {
        "channel_delete": discord.AuditLogAction.channel_delete,
        "role_delete": discord.AuditLogAction.role_delete,
        "member_ban": discord.AuditLogAction.ban,
        "member_kick": discord.AuditLogAction.kick,
        "webhook_create": discord.AuditLogAction.webhook_create,
        "channel_create": discord.AuditLogAction.channel_create,
        "role_create": discord.AuditLogAction.role_create,
    }
    audit_action = action_map.get(action_name)
    if not audit_action:
        return None

    actor: discord.User | discord.Member | None = None
    try:
        async for entry in guild.audit_logs(limit=5, action=audit_action):
            age = (discord.utils.utcnow() - entry.created_at).total_seconds()
            if age <= 12:
                if target_id is None or (entry.target and getattr(entry.target, "id", None) == target_id):
                    actor = entry.user
                    break
                elif target_id is not None and not actor:
                    # En cas de légère désynchronisation d'ID de cible
                    actor = entry.user
    except (discord.Forbidden, discord.HTTPException) as e:
        logger.debug("Audit log inaccessible sur %s : %s", guild.name, e)
        return None

    if not actor:
        return None

    # ── Exceptions et exemptions ───────────────────────────────────────
    # 1. Le bot lui-même (actions de modération légitimes de Sentinel)
    if actor.id == guild.me.id:
        return None

    # 2. Le Propriétaire du serveur (propriété absolue du serveur)
    if actor.id == guild.owner_id:
        return None

    # 3. Whitelist dynamique
    if db and hasattr(db, "is_whitelisted"):
        member = guild.get_member(actor.id)
        role_ids = [r.id for r in member.roles] if member else []
        if await db.is_whitelisted(guild.id, actor.id, role_ids):
            logger.debug("Acteur %s immunisé par la whitelist", actor)
            return None

    # ── Comptage dans la fenêtre glissante ──────────────────────────────
    thresholds = custom_thresholds or DEFAULT_THRESHOLDS
    limit, window_seconds = thresholds.get(action_name, (3, 10))

    key = f"sentinel:antinuke:{guild.id}:{actor.id}:{action_name}"
    count = await _count_action(cache, key, window_seconds)

    # ── Détection des Heures d'Anomalie (Raid Nocturne Staff Compromis) ──
    # Entre minuit et 6h du matin, la sensibilité est doublée (seuil abaissé)
    now_utc = discord.utils.utcnow()
    is_night_anomaly = (now_utc.hour in (0, 1, 2, 3, 4, 5)) and (custom_thresholds is None)
    effective_limit = max(1, limit - 1) if is_night_anomaly else limit

    logger.info(
        "Action anti-nuke [%s] par %s sur %s : %d/%d (fenêtre %ds)%s",
        action_name, actor, guild.name, count, effective_limit, window_seconds,
        " [ALERTE NOCTURNE]" if is_night_anomaly else "",
    )

    if count < effective_limit:
        return None

    # ── SEUIL DÉPASSÉ : NEUTRALISATION D'URGENCE ───────────────────────
    logger.critical(
        "🚨 SEUIL ANTI-NUKE DÉPASSÉ sur %s par %s (%d) pour l'action %s (%d/%d en %ds)%s !",
        guild.name, actor, actor.id, action_name, count, effective_limit, window_seconds,
        " [HORAIRE NOCTURNE ANORMAL]" if is_night_anomaly else "",
    )

    neutralize_res = await neutralize_actor(
        guild, actor.id,
        reason=f"Seuil anti-nuke dépassé ({count} {action_name} en {window_seconds}s)",
    )

    # Nettoyage automatique des salons et rôles créés par le raider
    cleaned_items: list[str] = []
    if action_name in ("channel_create", "role_create"):
        # 1. Nettoyage des salons créés par l'attaquant dans la rafale
        if guild.me.guild_permissions.manage_channels:
            try:
                async for entry in guild.audit_logs(limit=50, action=discord.AuditLogAction.channel_create):
                    if entry.user and entry.user.id == actor.id and entry.target:
                        age = (discord.utils.utcnow() - entry.created_at).total_seconds()
                        if age <= 60:
                            ch = guild.get_channel(entry.target.id)
                            if ch:
                                try:
                                    res = ch.delete(reason="SENTINEL Anti-Nuke: Suppression immédiate de salon de raid")
                                    if inspect.isawaitable(res):
                                        await res
                                    cleaned_items.append(f"#{getattr(ch, 'name', 'salon')}")
                                except (discord.Forbidden, discord.HTTPException):
                                    pass
            except (discord.Forbidden, discord.HTTPException):
                pass

        # 2. Nettoyage des rôles créés par l'attaquant dans la rafale
        if guild.me.guild_permissions.manage_roles:
            try:
                async for entry in guild.audit_logs(limit=50, action=discord.AuditLogAction.role_create):
                    if entry.user and entry.user.id == actor.id and entry.target:
                        age = (discord.utils.utcnow() - entry.created_at).total_seconds()
                        if age <= 60:
                            r = guild.get_role(entry.target.id)
                            if r:
                                can_delete = True
                                try:
                                    if hasattr(guild.me, "top_role") and r >= guild.me.top_role:
                                        can_delete = False
                                except TypeError:
                                    can_delete = True
                                if can_delete:
                                    try:
                                        res = r.delete(reason="SENTINEL Anti-Nuke: Suppression immédiate de rôle de raid")
                                        if inspect.isawaitable(res):
                                            await res
                                        cleaned_items.append(f"@{getattr(r, 'name', 'role')}")
                                    except (discord.Forbidden, discord.HTTPException):
                                        pass
            except (discord.Forbidden, discord.HTTPException):
                pass

    payload = {
        "guild_id": guild.id,
        "user_id": actor.id,
        "action": action_name,
        "count": count,
        "limit": limit,
        "window_seconds": window_seconds,
        "neutralization": neutralize_res,
        "cleaned_items": cleaned_items,
        "reason": "antinuke_threshold_exceeded",
        "score": 1.0,
    }

    # Preuve forensique immuable
    if append_evidence:
        entry = await append_evidence(guild.id, "antinuke_triggered", payload)
        payload["evidence_hash"] = entry.get("hash")

    # Déclenchement du Lockdown d'urgence
    if lockdown_module:
        await lockdown_module.trigger(
            guild, payload, dry_run=False,
            auto_release_seconds=1800, # 30 min par défaut
            append_evidence=append_evidence, db=db,
        )

    # Émission d'événement critique vers la War Room
    if bus:
        await bus.emit("risk_critical", payload)

    # Alertes Dashboard et DM Propriétaire
    if dashboard_module:
        roles_str = ", ".join(neutralize_res.get("removed_roles", [])) or "Aucun rôle gérable"
        clean_str = f"\n**Objets de raid supprimés ({len(cleaned_items)}) :** " + ", ".join(cleaned_items) if cleaned_items else ""
        night_badge = " 🌙 [ALERTE NOCTURNE — COMPTE COMPROMIS ?]" if is_night_anomaly else ""
        await dashboard_module.send_alert(
            guild,
            title=f"🚨 ANTI-NUKE DÉCLENCHÉ — Compte staff neutralisé !{night_badge}",
            description=(
                f"**Auteur :** <@{actor.id}> (`{actor.name}`)\n"
                f"**Action destructrice :** `{action_name}` ({count} en {window_seconds}s)\n"
                f"**Rôles retirés :** {roles_str}\n"
                f"**Timeout appliqué :** {'Oui (28 jours)' if neutralize_res.get('timed_out') else 'Non'}\n"
                f"**Serveur :** Placé en **Lockdown d'urgence**.{clean_str}"
            ),
            color=0xFF0000,
        )
        if guild.owner:
            try:
                await guild.owner.send(
                    f"🚨 **ALERTE CRITIQUE ANTI-NUKE sur {guild.name}{night_badge}**\n\n"
                    f"Le compte <@{actor.id}> (`{actor.name}`) a déclenché l'anti-nuke "
                    f"(`{action_name}`: {count} fois en {window_seconds}s à {now_utc.strftime('%H:%M')} UTC).\n"
                    f"Ses permissions ont été immédiatement révoquées et le serveur a été verrouillé en urgence."
                )
            except discord.HTTPException:
                pass

    return payload


async def check_bot_add(
    guild: discord.Guild,
    bot_member: discord.Member,
    *,
    db: Any,
    bus: Any,
    append_evidence: Any,
    dashboard_module: Any = None,
) -> dict[str, Any] | None:
    """
    Détecte l'ajout d'un bot (potentiel rogue bot / bot nuker).
    Si l'inviteur n'est pas le propriétaire ni whitelisted, le bot est immédiatement exclu/banni
    et l'inviteur est neutralisé.
    """
    if not bot_member.bot:
        return None
    if not guild.me.guild_permissions.view_audit_log:
        return None

    inviter: discord.User | discord.Member | None = None
    try:
        async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.bot_add):
            age = (discord.utils.utcnow() - entry.created_at).total_seconds()
            if age <= 20 and entry.target and entry.target.id == bot_member.id:
                inviter = entry.user
                break
    except (discord.Forbidden, discord.HTTPException) as e:
        logger.debug("Audit log inaccessible pour bot_add sur %s : %s", guild.name, e)
        return None

    if not inviter or inviter.id == guild.me.id or inviter.id == guild.owner_id:
        return None

    # Vérification whitelist de l'inviteur
    if db and hasattr(db, "is_whitelisted"):
        member = guild.get_member(inviter.id)
        role_ids = [r.id for r in member.roles] if member else []
        if await db.is_whitelisted(guild.id, inviter.id, role_ids):
            return None

    # Inviteur non autorisé : ROUGE ! Bot suspect ajouté !
    logger.critical(
        "🚨 ROGUE BOT DÉTECTÉ sur %s : Bot %s (%d) ajouté par l'utilisateur non autorisé %s (%d) !",
        guild.name, bot_member, bot_member.id, inviter, inviter.id,
    )

    # 1. Bannir ou expulser immédiatement le bot suspect
    kicked = False
    try:
        if guild.me.guild_permissions.ban_members:
            await guild.ban(bot_member, reason=f"SENTINEL Anti-Nuke: Rogue Bot ajouté par {inviter.name}")
            kicked = True
        elif guild.me.guild_permissions.kick_members:
            await guild.kick(bot_member, reason=f"SENTINEL Anti-Nuke: Rogue Bot ajouté par {inviter.name}")
            kicked = True
    except (discord.Forbidden, discord.HTTPException) as e:
        logger.error("Impossible d'exclure le bot suspect %s : %s", bot_member, e)

    # 2. Neutraliser l'inviteur (retrait rôles + timeout)
    neutralize_res = await neutralize_actor(
        guild, inviter.id,
        reason=f"Ajout frauduleux d'un bot non autorisé ({bot_member.name})",
    )

    payload = {
        "guild_id": guild.id,
        "bot_id": bot_member.id,
        "bot_name": bot_member.name,
        "inviter_id": inviter.id,
        "inviter_name": inviter.name,
        "action": "rogue_bot_neutralized",
        "bot_removed": kicked,
        "neutralization": neutralize_res,
        "score": 1.0,
    }

    if append_evidence:
        await append_evidence(guild.id, "rogue_bot_blocked", payload)

    if bus:
        await bus.emit("risk_critical", payload)

    if dashboard_module:
        await dashboard_module.send_alert(
            guild,
            title="🚨 ROGUE BOT NEUTRALISÉ D'URGENCE",
            description=(
                f"**Bot suspect :** {bot_member.mention} (`{bot_member.name}`)\n"
                f"**Invité par :** {inviter.mention} (`{inviter.name}`) — *Non autorisé*\n"
                f"**Action prise :** Bot {'banni' if kicked else 'non banni (perms manquantes)'} & permissions de l'inviteur révoquées d'urgence."
            ),
            color=0xFF0000,
        )

    return payload


async def check_unauthorized_webhook(
    guild: discord.Guild,
    channel: discord.abc.GuildChannel,
    *,
    db: Any,
    append_evidence: Any,
    dashboard_module: Any = None,
) -> bool:
    """
    Inspecte les webhooks créés sur un salon. Si créé par un utilisateur non autorisé,
    le webhook est immédiatement détruit pour prévenir les attaques de spam webhook.
    """
    if not guild.me.guild_permissions.view_audit_log or not guild.me.guild_permissions.manage_webhooks:
        return False

    try:
        async for entry in guild.audit_logs(limit=3, action=discord.AuditLogAction.webhook_create):
            age = (discord.utils.utcnow() - entry.created_at).total_seconds()
            if age <= 15 and entry.user:
                actor = entry.user
                if actor.id == guild.me.id or actor.id == guild.owner_id:
                    continue

                if db and hasattr(db, "is_whitelisted"):
                    member = guild.get_member(actor.id)
                    role_ids = [r.id for r in member.roles] if member else []
                    if await db.is_whitelisted(guild.id, actor.id, role_ids):
                        continue

                # Webhook non autorisé : le supprimer immédiatement
                if hasattr(channel, "webhooks"):
                    whs = await channel.webhooks()
                    for wh in whs:
                        if entry.target and wh.id == entry.target.id:
                            await wh.delete(reason="SENTINEL Anti-Nuke: Webhook non autorisé détruit")
                            logger.warning("Webhook frauduleux %s supprimé sur #%s", wh.name, channel.name)
                            if append_evidence:
                                await append_evidence(guild.id, "unauthorized_webhook_destroyed", {
                                    "webhook_id": wh.id, "author_id": actor.id, "channel_id": channel.id,
                                })
                            if dashboard_module:
                                await dashboard_module.send_alert(
                                    guild,
                                    title="🛡️ WEBHOOK NON AUTORISÉ DÉTRUIT",
                                    description=f"Un webhook créé par {actor.mention} dans {channel.mention} a été supprimé instantanément.",
                                    color=0xFFAA00,
                                )
                            return True
    except Exception as e:
        logger.debug("Erreur inspection webhooks sur %s : %s", guild.name, e)
    return False

