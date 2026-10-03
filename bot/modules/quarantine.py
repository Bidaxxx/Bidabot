"""
Module 14 — Quarantaine automatique.

Alternative moins brutale au lockdown total et au ban immédiat :
- Ajoute le rôle @sentinel-quarantine au membre suspect
- Ce rôle retire le droit de voir/parler PARTOUT sauf dans #sentinel-quarantine
- Dans #sentinel-quarantine, le membre reçoit un message explicatif et peut
  s'expliquer auprès d'un modérateur
- Un admin peut lever la quarantaine (/sentinel unquarantine) ou la convertir
  en ban (/sentinel quarantine ban)
- Toutes les actions sont chaînées dans le module forensique (module 7)

Différence avec le lockdown :
- Le lockdown affecte TOUT LE SERVEUR (tous les membres ne peuvent plus écrire)
- La quarantaine affecte UN SEUL COMPTE, de façon ciblée et réversible

Cas d'usage typique : score de légitimité entre 0.4 et 0.7 (suspect mais pas
encore critique) → quarantaine au lieu d'attendre qu'il fasse quelque chose
de définitif pour déclencher le lockdown.
"""
from __future__ import annotations

import logging

import discord

logger = logging.getLogger("sentinel.quarantine")

QUARANTINE_ROLE_NAME = "bidabot-quarantine"
LEGACY_QUARANTINE_ROLE_NAME = "sentinel-quarantine"
QUARANTINE_CHANNEL_NAME = "bidabot-quarantine"
LEGACY_QUARANTINE_CHANNEL_NAME = "sentinel-quarantine"
QUARANTINE_CATEGORY_NAME = "bidabot-admin"
LEGACY_QUARANTINE_CATEGORY_NAME = "sentinel-admin"


async def _get_or_create_role(guild: discord.Guild) -> discord.Role:
    """Récupère ou crée le rôle de quarantaine avec les bonnes permissions."""
    role = discord.utils.get(guild.roles, name=QUARANTINE_ROLE_NAME) or discord.utils.get(guild.roles, name=LEGACY_QUARANTINE_ROLE_NAME)
    if not role:
        try:
            role = await guild.create_role(
                name=QUARANTINE_ROLE_NAME,
                color=discord.Color.from_str("#FF6600"),
                reason="BIDABOT — rôle de quarantaine automatique (module 14)",
            )
            logger.info("Rôle @%s créé sur %s", QUARANTINE_ROLE_NAME, guild.name)
        except discord.Forbidden:
            logger.warning("Permissions insuffisantes pour créer le rôle quarantaine sur %s", guild.name)
            raise
    return role


async def _get_or_create_channel(guild: discord.Guild,
                                  role: discord.Role,
                                  staff_role: discord.Role | None = None) -> discord.TextChannel | None:
    """Récupère ou crée #sentinel-quarantine dans la catégorie admin."""
    ch = discord.utils.get(guild.text_channels, name=QUARANTINE_CHANNEL_NAME) or discord.utils.get(guild.text_channels, name=LEGACY_QUARANTINE_CHANNEL_NAME)
    category = discord.utils.get(guild.categories, name=QUARANTINE_CATEGORY_NAME) or discord.utils.get(guild.categories, name=LEGACY_QUARANTINE_CATEGORY_NAME)

    # Permissions : seul le rôle quarantaine + les admins + le rôle staff peuvent voir ce salon
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        role: discord.PermissionOverwrite(
            view_channel=True, send_messages=True, read_message_history=True,
        ),
    }
    if guild.me:
        overwrites[guild.me] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, manage_messages=True, embed_links=True, read_message_history=True,
        )

    for r in guild.roles:
        if r == guild.default_role:
            continue
        if r.permissions.administrator or r.permissions.manage_guild:
            overwrites[r] = discord.PermissionOverwrite(
                view_channel=True, send_messages=True, manage_messages=True, read_message_history=True,
            )
    roles_list: list[discord.Role] = []
    if staff_role:
        if isinstance(staff_role, (list, tuple, set)):
            roles_list = [r for r in staff_role if r]
        else:
            roles_list = [staff_role]

    for r in roles_list:
        overwrites[r] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, manage_messages=True, read_message_history=True,
        )

    if ch:
        # Met à jour les permissions si le salon existait déjà
        try:
            await ch.set_permissions(guild.default_role, view_channel=False)
            await ch.set_permissions(role, view_channel=True, send_messages=True, read_message_history=True)
            if guild.me:
                await ch.set_permissions(guild.me, view_channel=True, send_messages=True, manage_messages=True, embed_links=True)
            for r in roles_list:
                await ch.set_permissions(r, view_channel=True, send_messages=True, manage_messages=True, read_message_history=True)
        except (discord.Forbidden, discord.HTTPException):
            pass
        return ch

    try:
        ch = await guild.create_text_channel(
            QUARANTINE_CHANNEL_NAME, category=category, overwrites=overwrites,
            topic="🔒 Salon de quarantaine SENTINEL — Explique ta situation à un modérateur.",
            reason="BIDABOT — salon de quarantaine (module 14)",
        )
        logger.info("Salon #%s créé sur %s", QUARANTINE_CHANNEL_NAME, guild.name)
        return ch
    except discord.Forbidden:
        logger.warning("Permissions insuffisantes pour créer #%s sur %s", QUARANTINE_CHANNEL_NAME, guild.name)
        return None


async def setup_quarantine(guild: discord.Guild, db=None, staff_role: discord.Role | list[discord.Role] | None = None) -> tuple[discord.Role | None, discord.TextChannel | None]:
    """
    Configure la quarantaine manuellement (via /sentinel setup ou /sentinel setup_quarantine) :
    1. Crée ou récupère le rôle @sentinel-quarantine
    2. Crée ou récupère le salon #sentinel-quarantine (invisible à @everyone, visible pour le rôle staff et le rôle quarantaine)
    3. Isole tous les autres salons du serveur pour le rôle @sentinel-quarantine
    """
    try:
        role = await _get_or_create_role(guild)
    except discord.Forbidden:
        logger.warning("Permissions insuffisantes pour créer le rôle quarantaine sur %s", guild.name)
        return None, None

    channel = await _get_or_create_channel(guild, role, staff_role=staff_role)
    await _apply_channel_denials(guild, role)

    roles_list: list[discord.Role] = []
    if staff_role:
        if isinstance(staff_role, (list, tuple, set)):
            roles_list = [r for r in staff_role if r]
        else:
            roles_list = [staff_role]

    if roles_list and db and hasattr(db, "set_staff_role"):
        await db.set_staff_role(guild.id, roles_list[0].id)

    role_desc = ", ".join(r.name for r in roles_list) if roles_list else "défaut"
    logger.info("Quarantaine configurée sur %s (rôle: @%s, salon: #%s, staff: %s)",
                guild.name, role.name, channel.name if channel else "None", role_desc)
    return role, channel


async def _apply_channel_denials(guild: discord.Guild, role: discord.Role) -> None:
    """Applique une permission deny(view_channel=False) pour le rôle quarantaine
    sur tous les salons du serveur, sauf #sentinel-quarantine lui-même et les
    salons de la catégorie sentinel-admin (war rooms, canary, dashboard)."""
    sentinel_categories = {QUARANTINE_CATEGORY_NAME, LEGACY_QUARANTINE_CATEGORY_NAME, "bidabot-warrooms", "sentinel-warrooms", "bidabot-canary", "sentinel-canary"}
    for ch in guild.text_channels + list(guild.voice_channels) + list(guild.stage_channels):
        if ch.name == QUARANTINE_CHANNEL_NAME:
            continue
        if ch.category and ch.category.name in sentinel_categories:
            continue
        try:
            await ch.set_permissions(
                role,
                view_channel=False, send_messages=False,
                reason="SENTINEL — restriction de quarantaine (module 14)",
            )
        except (discord.Forbidden, discord.HTTPException):
            pass


async def quarantine(member: discord.Member, reason: str,
                      db, append_evidence) -> discord.TextChannel | None:
    """
    Met un membre en quarantaine :
    1. Crée (ou récupère) le rôle + salon
    2. Applique les deny permissions sur tous les salons
    3. Ajoute le rôle au membre
    4. Envoie un message d'explication dans #sentinel-quarantine
    5. Chaîne l'événement en forensique

    Retourne le salon #sentinel-quarantine (pour que le modérateur puisse y
    répondre) ou None si une permission Discord manque.
    """
    guild = member.guild
    try:
        role = await _get_or_create_role(guild)
    except discord.Forbidden:
        return None

    channel = await _get_or_create_channel(guild, role)

    # Applique les deny sur tous les salons (uniquement si le rôle est nouveau
    # ou si les permissions ont pu être réinitialisées)
    await _apply_channel_denials(guild, role)

    try:
        await member.add_roles(role, reason=f"SENTINEL quarantaine : {reason}")
    except (discord.Forbidden, discord.HTTPException) as e:
        logger.warning("Impossible d'ajouter le rôle quarantaine à %s : %s", member, e)
        return channel

    await db.log_quarantine(member.guild.id, member.id, "quarantined", reason)
    await append_evidence(guild.id, "quarantine_applied", {
        "user_id": member.id,
        "reason": reason,
    })

    if channel:
        embed = discord.Embed(
            title="🔒 Accès temporairement restreint",
            description=(
                f"Bonjour <@{member.id}>,\n\n"
                "Suite à une détection automatique du système de sécurité SENTINEL, "
                "ton accès au serveur a été temporairement restreint.\n\n"
                f"**Raison détectée :** `{reason}`\n\n"
                "Un modérateur va examiner ton cas rapidement. "
                "Tu peux écrire un message ici pour t'expliquer.\n\n"
                "*Si tu es un vrai membre, ta quarantaine sera levée sous peu.*"
            ),
            color=0xFF6600,
        )
        embed.set_footer(text="Ce message a été généré automatiquement par SENTINEL.")
        try:
            await channel.send(embed=embed)
        except discord.HTTPException:
            pass

    logger.info("Membre %s mis en quarantaine sur %s (raison: %s)", member, guild.name, reason)
    return channel


async def release(member: discord.Member, *, db, append_evidence, banned: bool = False) -> bool:
    """
    Lève la quarantaine d'un membre :
    - Si banned=False : retire le rôle, accès normal restauré
    - Si banned=True  : ban direct depuis la quarantaine

    Retourne True si la quarantaine était bien active.
    """
    guild = member.guild
    role = discord.utils.get(guild.roles, name=QUARANTINE_ROLE_NAME)
    if not role or role not in member.roles:
        return False

    if banned:
        try:
            await member.ban(reason="SENTINEL — banni depuis la quarantaine par un modérateur")
        except (discord.Forbidden, discord.HTTPException) as e:
            logger.warning("Permissions insuffisantes ou erreur pour bannir %s : %s", member, e)
            return False
        action = "banned_from_quarantine"
    else:
        try:
            await member.remove_roles(role, reason="SENTINEL — quarantaine levée par un modérateur")
        except (discord.Forbidden, discord.HTTPException) as e:
            logger.warning("Permissions insuffisantes ou erreur pour lever la quarantaine de %s : %s", member, e)
            return False
        action = "quarantine_released"

    await db.log_quarantine(guild.id, member.id, action, "")
    await append_evidence(guild.id, action, {"user_id": member.id})
    logger.info("%s appliqué à %s sur %s", action, member, guild.name)
    return True


async def restore_from_db(guild: discord.Guild, db) -> None:
    """Appelé dans on_ready : recrée les permissions si le rôle existe mais
    que ses deny ont été remis à zéro (ex: suppression manuelle des perms)."""
    role = discord.utils.get(guild.roles, name=QUARANTINE_ROLE_NAME) or discord.utils.get(guild.roles, name=LEGACY_QUARANTINE_ROLE_NAME)
    if not role:
        return
    # Vérifie qu'il y a des membres en quarantaine active
    count = await db.get_active_quarantine_count(guild.id)
    if count > 0:
        await _apply_channel_denials(guild, role)
        logger.info("Permissions de quarantaine restaurées sur %s (%d membre(s) actif(s))",
                     guild.name, count)


async def quarantine_member(guild: discord.Guild, member: discord.Member, reason: str, db=None, append_evidence=None) -> bool:
    """Fonction wrapper de compatibilité pour isoler un membre."""
    async def _dummy_append(*args, **kwargs):
        pass
    ev_callback = append_evidence or _dummy_append
    ch = await quarantine(member, reason, db=db, append_evidence=ev_callback)
    return bool(ch)
