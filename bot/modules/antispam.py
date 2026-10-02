"""
Module 10 — Anti-spam / flood par salon.

Détecte les rafales de messages d'un même utilisateur dans un salon donné
via une fenêtre glissante Redis (même mécanique que join_velocity).

Seuils (configurables via Thresholds) :
  antispam_messages_per_window   : nombre de messages max dans la fenêtre
  antispam_window_seconds        : durée de la fenêtre (défaut 10s)
  antispam_delete_messages        : supprime les messages en excès

Système de warns progressifs :
  1 warn → timeout 5 min
  2 warns → timeout 1 heure
  3 warns → timeout 24h + alerte war room
Les warns sont stockés en Redis avec TTL de 7 jours.

N.B. : Utilise le timeout natif Discord (Member.timeout) — aucun rôle
"Muted" nécessaire. Disponible sur Discord depuis fin 2021.
"""
from __future__ import annotations

import datetime
import logging

import discord

logger = logging.getLogger("sentinel.antispam")

# Clés Redis
_KEY_RATE  = "sentinel:antispam:rate:{guild}:{channel}:{user}"
_KEY_WARN  = "sentinel:antispam:warn:{guild}:{user}"

WARN_TTL_SECONDS = 7 * 24 * 3600   # les warns expirent après 7 jours

# Durée de mute selon le nombre de warns
MUTE_DURATIONS = {
    1: 5 * 60,       # 1er warn  → 5 minutes
    2: 60 * 60,      # 2e warn   → 1 heure
    3: 24 * 60 * 60, # 3e warn+  → 24 heures
}


async def check_message(
    message: discord.Message,
    cache,
    *,
    max_messages: int = 5,
    window_seconds: int = 10,
    delete_excess: bool = True,
    mute_seconds: int = 0,         # 0 = désactivé, sinon durée mute fixe
    progressive_mute: bool = True,  # active les mutes progressifs par warns
    bus=None,
    append_evidence=None,
) -> bool:
    """
    Vérifie si l'auteur du message spam dans ce salon.

    Retourne True si l'action est prise (message supprimé / mute appliqué),
    False si tout est normal.

    À appeler depuis on_message AVANT le traitement fingerprint/stylométrie.
    """
    guild = message.guild
    author = message.author
    channel = message.channel

    key = _KEY_RATE.format(guild=guild.id, channel=channel.id, user=author.id)
    count = await cache.sliding_window_add_and_count(key, window_seconds)

    if count <= max_messages:
        return False  # pas de spam

    # ── Suppression du message en excès ────────────────────────────────
    if delete_excess:
        try:
            await message.delete()
            logger.info("Message spam supprimé : %s dans #%s (%s)", author, channel.name, guild.name)
        except (discord.Forbidden, discord.HTTPException):
            pass

    # ── Timeout natif Discord (pas besoin de rôle "Muted") ─────────────
    if progressive_mute:
        warn_key = _KEY_WARN.format(guild=guild.id, user=author.id)
        warns = await cache.incr_with_ttl(warn_key, WARN_TTL_SECONDS)
        duration = MUTE_DURATIONS.get(warns, MUTE_DURATIONS[3])  # 3+ warns → max

        if isinstance(author, discord.Member):
            try:
                await author.timeout(
                    discord.utils.utcnow() + datetime.timedelta(seconds=duration),
                    reason=f"SENTINEL anti-spam : {warns} warn(s) — {count} messages en {window_seconds}s",
                )
                logger.warning(
                    "Timeout %ds appliqué à %s (%d warn(s)) sur %s", duration, author, warns, guild.name
                )
            except (discord.Forbidden, discord.HTTPException) as e:
                logger.warning("Impossible de timeout %s : %s", author, e)

        # Enregistrement SYSTÉMATIQUE dans la chaîne de preuves forensiques (Dashboard)
        if append_evidence:
            entry = await append_evidence(guild.id, "spam_flood_detected", {
                "user_id": author.id,
                "author_name": str(author),
                "channel_id": channel.id,
                "channel_name": getattr(channel, "name", str(channel.id)),
                "warns": warns,
                "messages_in_window": count,
                "window_seconds": window_seconds,
                "timeout_duration": duration,
                "content_snippet": message.content[:200],
            })

        # War room si 3+ warns
        if warns >= 3 and bus and append_evidence:
            await append_evidence(guild.id, "antispam_repeat_offender", {
                "user_id": author.id,
                "channel_id": channel.id,
                "warns": warns,
                "messages_in_window": count,
            })
            await bus.emit("risk_critical", {
                "guild_id": guild.id,
                "user_id": author.id,
                "score": 0.9,
                "reason": "spam_repetitif",
                "signals": {"warns": warns, "messages_in_window": count},
                "evidence_hash": entry["hash"] if entry else "unhashed",
            })

    elif mute_seconds > 0 and isinstance(author, discord.Member):
        try:
            await author.timeout(
                discord.utils.utcnow() + datetime.timedelta(seconds=mute_seconds),
                reason=f"SENTINEL anti-spam : {count} messages en {window_seconds}s",
            )
        except (discord.Forbidden, discord.HTTPException) as e:
            logger.warning("Impossible de timeout %s : %s", author, e)

    return True


async def get_warn_count(user_id: int, guild_id: int, cache) -> int:
    """Retourne le nombre de warns actifs d'un utilisateur (pour /sentinel warns)."""
    key = _KEY_WARN.format(guild=guild_id, user=user_id)
    if hasattr(cache, "get"):
        val = await cache.get(key)
    elif hasattr(cache, "client") and cache.client:
        val = await cache.client.get(key)
    else:
        val = None
    return int(val) if val else 0


async def reset_warns(user_id: int, guild_id: int, cache) -> None:
    """Remet les warns à 0 (commande admin /sentinel warns reset)."""
    key = _KEY_WARN.format(guild=guild_id, user=user_id)
    if hasattr(cache, "delete"):
        await cache.delete(key)
    elif hasattr(cache, "client") and cache.client:
        await cache.client.delete(key)
