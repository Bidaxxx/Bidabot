"""
Module de Snapshot et Restauration d'Arborescence Discord (Anti-Nuke Ultime).
Capture l'état complet des salons, catégories, rôles et permissions,
et permet une reconstruction chirurgicale en un clic.
"""
from __future__ import annotations

import logging
from typing import Any
import discord

logger = logging.getLogger("sentinel.snapshot")


async def capture_guild_snapshot(guild: discord.Guild, label: str = "Automatique") -> dict[str, Any]:
    """Capture l'état structurel complet d'un serveur Discord."""
    roles_data = []
    # Ignorer @everyone (role[0]) dans la création, mais capturer ses permissions
    for role in guild.roles:
        if role.is_default():
            continue
        roles_data.append({
            "name": role.name,
            "permissions": role.permissions.value,
            "color": role.color.value,
            "hoist": role.hoist,
            "mentionable": role.mentionable,
            "position": role.position,
        })

    categories_data = []
    for cat in guild.categories:
        categories_data.append({
            "name": cat.name,
            "position": cat.position,
        })

    text_channels_data = []
    for ch in guild.text_channels:
        # Ne pas sauvegarder les salons temporaires de war rooms
        if "warroom-" in ch.name:
            continue
        text_channels_data.append({
            "name": ch.name,
            "category": ch.category.name if ch.category else None,
            "topic": ch.topic,
            "slowmode_delay": ch.slowmode_delay,
            "nsfw": ch.nsfw,
            "position": ch.position,
        })

    voice_channels_data = []
    for vch in guild.voice_channels:
        voice_channels_data.append({
            "name": vch.name,
            "category": vch.category.name if vch.category else None,
            "bitrate": vch.bitrate,
            "user_limit": vch.user_limit,
            "position": vch.position,
        })

    snapshot = {
        "guild_id": guild.id,
        "guild_name": guild.name,
        "label": label,
        "roles": roles_data,
        "categories": categories_data,
        "text_channels": text_channels_data,
        "voice_channels": voice_channels_data,
        "summary": {
            "roles_count": len(roles_data),
            "categories_count": len(categories_data),
            "text_channels_count": len(text_channels_data),
            "voice_channels_count": len(voice_channels_data),
        },
    }
    return snapshot


async def restore_guild_snapshot(guild: discord.Guild, snapshot: dict[str, Any]) -> dict[str, int]:
    """Restaure les éléments manquants à partir d'un snapshot sans écraser l'existant."""
    stats = {
        "roles_restored": 0,
        "categories_restored": 0,
        "channels_restored": 0,
    }

    existing_roles = {r.name: r for r in guild.roles}
    existing_categories = {c.name: c for c in guild.categories}
    existing_text = {tc.name: tc for tc in guild.text_channels}
    existing_voice = {vc.name: vc for vc in guild.voice_channels}

    # 1. Restauration des rôles manquants
    for r_data in snapshot.get("roles", []):
        name = r_data["name"]
        if name not in existing_roles:
            try:
                new_role = await guild.create_role(
                    name=name,
                    permissions=discord.Permissions(r_data.get("permissions", 0)),
                    color=discord.Color(r_data.get("color", 0)),
                    hoist=r_data.get("hoist", False),
                    mentionable=r_data.get("mentionable", False),
                    reason="Sentinel Anti-Nuke: Restauration de rôle supprimé",
                )
                existing_roles[name] = new_role
                stats["roles_restored"] += 1
                logger.info("Rôle '%s' restauré sur %s", name, guild.id)
            except discord.HTTPException as e:
                logger.error("Échec restauration rôle %s: %s", name, e)

    # 2. Restauration des catégories manquantes
    for cat_data in snapshot.get("categories", []):
        cat_name = cat_data["name"]
        if cat_name not in existing_categories:
            try:
                new_cat = await guild.create_category(
                    name=cat_name,
                    position=cat_data.get("position", 0),
                    reason="Sentinel Anti-Nuke: Restauration de catégorie",
                )
                existing_categories[cat_name] = new_cat
                stats["categories_restored"] += 1
                logger.info("Catégorie '%s' restaurée sur %s", cat_name, guild.id)
            except discord.HTTPException as e:
                logger.error("Échec restauration catégorie %s: %s", cat_name, e)

    # 3. Restauration des salons textuels
    for tch_data in snapshot.get("text_channels", []):
        ch_name = tch_data["name"]
        if ch_name not in existing_text:
            cat = existing_categories.get(tch_data.get("category"))
            try:
                new_ch = await guild.create_text_channel(
                    name=ch_name,
                    category=cat,
                    topic=tch_data.get("topic"),
                    slowmode_delay=tch_data.get("slowmode_delay", 0),
                    nsfw=tch_data.get("nsfw", False),
                    position=tch_data.get("position", 0),
                    reason="Sentinel Anti-Nuke: Restauration de salon textuel",
                )
                existing_text[ch_name] = new_ch
                stats["channels_restored"] += 1
                logger.info("Salon textuel '#%s' restauré sur %s", ch_name, guild.id)
            except discord.HTTPException as e:
                logger.error("Échec restauration salon textuel %s: %s", ch_name, e)

    # 4. Restauration des salons vocaux
    for vch_data in snapshot.get("voice_channels", []):
        vch_name = vch_data["name"]
        if vch_name not in existing_voice:
            cat = existing_categories.get(vch_data.get("category"))
            try:
                new_vch = await guild.create_voice_channel(
                    name=vch_name,
                    category=cat,
                    bitrate=vch_data.get("bitrate", 64000),
                    user_limit=vch_data.get("user_limit", 0),
                    position=vch_data.get("position", 0),
                    reason="Sentinel Anti-Nuke: Restauration de salon vocal",
                )
                existing_voice[vch_name] = new_vch
                stats["channels_restored"] += 1
                logger.info("Salon vocal '%s' restauré sur %s", vch_name, guild.id)
            except discord.HTTPException as e:
                logger.error("Échec restauration salon vocal %s: %s", vch_name, e)

    return stats
