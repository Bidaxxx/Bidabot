"""
Module 5 — Canary channels invisibles.

⚠️ Rappel légal (repris du rapport d'architecture, à ne jamais retirer) :
la capture d'IP via lien honeytoken n'est légale que si elle est annoncée
dans le règlement/CGU du serveur (transparence RGPD). Ne jamais activer
`generate_honeytoken_link` sans que le règlement du serveur mentionne
explicitement l'usage de liens de détection d'intrusion. Aucune IP n'est
jamais stockée en clair : toujours hashée (voir crypto_utils.hash_ip).

Deux mécanismes :
1. Canaux texte invisibles pour @everyone, visibles seulement pour les
   rôles jugés suspects (ex: "nouveau membre non vérifié") -> tout message
   posté dedans = alerte immédiate (personne de légitime ne devrait
   pouvoir/vouloir y écrire).
2. Liens honeytoken : URL opaque pointant vers l'endpoint /t/{token} de
   federation_api/app.py, qui logue IP (hashée) + ASN + user-agent du
   visiteur sans jamais exposer le token lui-même à un humain autrement
   que via le canal caché.
"""
from __future__ import annotations

import logging
import secrets

import discord

logger = logging.getLogger("sentinel.canary")

CATEGORY_NAME = "bidabot-canary"
LEGACY_CATEGORY_NAME = "sentinel-canary"
CHANNEL_COUNT = 3


async def setup_canaries(guild: discord.Guild, db,
                         staff_role: discord.Role | list[discord.Role] | None = None,
                         suspect_role: discord.Role | None = None) -> set[int]:
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
    }
    if guild.me:
        overwrites[guild.me] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, read_message_history=True, manage_messages=True,
        )

    roles_list: list[discord.Role] = []
    if staff_role:
        if isinstance(staff_role, (list, tuple, set)):
            roles_list = [r for r in staff_role if r]
        else:
            roles_list = [staff_role]

    for r in roles_list:
        overwrites[r] = discord.PermissionOverwrite(
            view_channel=True, send_messages=False, read_message_history=True,
        )
    if suspect_role:
        overwrites[suspect_role] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, read_message_history=True,
        )

    category = discord.utils.get(guild.categories, name=CATEGORY_NAME) or discord.utils.get(guild.categories, name=LEGACY_CATEGORY_NAME)
    if not category:
        try:
            category = await guild.create_category(
                CATEGORY_NAME,
                overwrites=overwrites,
                reason="BIDABOT — mise en place des canaux pièges (module 5)",
            )
        except discord.Forbidden:
            logger.warning("Permissions insuffisantes pour créer la catégorie canary sur %s", guild.name)
            return set()
    else:
        try:
            await category.set_permissions(guild.default_role, view_channel=False)
            if guild.me:
                await category.set_permissions(guild.me, view_channel=True, send_messages=True, read_message_history=True)
            for r in roles_list:
                await category.set_permissions(r, view_channel=True, send_messages=False, read_message_history=True)
            if suspect_role:
                await category.set_permissions(suspect_role, view_channel=True, send_messages=True, read_message_history=True)
        except (discord.Forbidden, discord.HTTPException):
            pass

    ids: set[int] = set()
    for i in range(CHANNEL_COUNT):
        name = f"canary-{i + 1}"
        ch = discord.utils.get(guild.text_channels, name=name)
        if not ch:
            try:
                ch = await guild.create_text_channel(
                    name, category=category,
                    overwrites=overwrites,
                    topic="🚨 Salon piège BIDABOT — invisible en usage normal. Tout accès génère une alerte.",
                )
            except (discord.Forbidden, discord.HTTPException):
                continue
        else:
            try:
                await ch.set_permissions(guild.default_role, view_channel=False)
                if guild.me:
                    await ch.set_permissions(guild.me, view_channel=True, send_messages=True, read_message_history=True)
                for r in roles_list:
                    await ch.set_permissions(r, view_channel=True, send_messages=False, read_message_history=True)
                if suspect_role:
                    await ch.set_permissions(suspect_role, view_channel=True, send_messages=True, read_message_history=True)
            except (discord.Forbidden, discord.HTTPException):
                pass
        if ch:
            ids.add(ch.id)

    logger.info("%d canaux pièges actifs sur %s (staff: %d rôles)", len(ids), guild.name, len(roles_list))
    return ids


async def handle_message(message: discord.Message, canary_ids: set[int], db, bus, append_evidence) -> bool:
    """Retourne True si le message provenait d'un canal piège (déjà traité,
    ne pas continuer le pipeline normal dessus)."""
    if message.channel.id not in canary_ids:
        return False

    await db.insert_canary_hit(
        guild_id=message.guild.id, channel_id=message.channel.id, user_id=message.author.id,
        ip_hash=None, asn=None, user_agent=None, kind="channel_access",
    )
    entry = await append_evidence(message.guild.id, "canary_hit", {
        "user_id": message.author.id,
        "channel_id": message.channel.id,
        "channel_name": message.channel.name,
        "content_preview": message.content[:100],
    })

    await bus.emit("canary_hit", {
        "guild_id": message.guild.id,
        "user_id": message.author.id,
        "channel_id": message.channel.id,
        "score": 0.99,
        "reason": "canary_channel_triggered",
        "evidence_hash": entry["hash"],
        "signals": {},
    })
    return True


async def generate_honeytoken_link(guild: discord.Guild, channel: discord.TextChannel,
                                    label: str, db, public_base_url: str) -> str:
    """Génère un lien opaque à poster UNIQUEMENT dans un canal piège déjà
    invisible pour @everyone. Le clic (par un raider qui a exfiltré l'accès
    au canal, ou un bot de scraping) est logué par federation_api (route
    /t/{token}), jamais par le bot Discord lui-même."""
    token = secrets.token_urlsafe(24)
    await db.create_canary_token(token, guild.id, channel.id, label)
    return f"{public_base_url.rstrip('/')}/t/{token}"
