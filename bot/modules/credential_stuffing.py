"""
Module 6 — Détection de credential stuffing sur webhook.

Limite connue et documentée : Discord ne transmet pas l'IP de l'appelant à
un bot classique (seul un reverse-proxy placé devant vos propres webhooks
sortants le pourrait). Ce module surveille donc, à défaut, la fréquence
d'échecs d'authentification applicative (ex: tentatives de commandes admin
avec un token/secret invalide côté dashboard ou fédération — voir
dashboard/app.py et federation_api/app.py qui appellent record_attempt) :
c'est la même logique de rate-limit, appliquée à ce que le bot peut
réellement observer.

Si une source dépasse le seuil, rotation en cascade de tous les webhooks
du salon concerné (révocation immédiate des identifiants potentiellement
compromis).
"""
from __future__ import annotations

import logging

import discord

logger = logging.getLogger("sentinel.credential_stuffing")


async def record_attempt(cache, db, guild_id: int, source_key: str,
                          window_seconds: int, max_attempts: int,
                          webhook_id: int | None = None) -> bool:
    """Retourne True si le seuil est dépassé (source à traiter comme
    compromise/attaquante)."""
    key = f"sentinel:credstuff:{guild_id}:{source_key}"
    count = await cache.incr_with_ttl(key, window_seconds)
    await db.insert_credential_stuffing_event(guild_id, source_key, webhook_id)

    if count > max_attempts:
        logger.warning("Seuil credential-stuffing dépassé pour %s sur guild %s (%d tentatives)",
                        source_key, guild_id, count)
        return True
    return False


async def rotate_channel_webhooks(channel: discord.TextChannel, reason: str) -> list[str]:
    """Révoque et recrée tous les webhooks d'un salon. Retourne les nouvelles
    URLs (à distribuer aux intégrations légitimes via un canal sécurisé,
    jamais en clair dans Discord)."""
    new_urls = []
    try:
        existing = await channel.webhooks()
    except discord.Forbidden:
        logger.warning("Permission manage_webhooks manquante sur #%s", channel.name)
        return new_urls

    for wh in existing:
        try:
            await wh.delete(reason=f"SENTINEL rotation (module 6): {reason}")
        except discord.HTTPException:
            continue

    try:
        new_wh = await channel.create_webhook(name="sentinel-rotated", reason=reason)
        new_urls.append(new_wh.url)
    except (discord.Forbidden, discord.HTTPException):
        pass

    return new_urls
