"""
Module 3bis — Lockdown automatique.

Garde-fous ajoutés par rapport au prototype initial (point légal explicite
de l'architecture : "prévoir un mécanisme d'override humain immédiat") :

1. Mode dry-run par serveur (guilds.dry_run, activé par défaut) : le module
   calcule tout, log tout, ouvre la war room — mais N'APPLIQUE AUCUNE
   permission tant qu'un admin n'a pas fait /sentinel dry-run off. Le temps
   de calibrer les seuils sans risquer de locker un afflux légitime.
2. /sentinel lockdown off répond toujours immédiatement, même si
   l'auto-release est encore en attente (pas de fenêtre où l'admin est
   bloqué par le bot lui-même).
3. Chaque déclenchement ET chaque levée sont chaînés dans le module
   forensique (module 7), y compris en dry-run (avec data.dry_run=true).

Fix #1 : restore_from_db() permet à on_ready de repeupler _active depuis la
base après un restart, évitant l'état "lockdown fantôme" où la DB indique un
lockdown actif mais _active est vide → release() ne faisait rien.

Fix #10 : _apply_permissions exclut désormais les channels de la catégorie
"sentinel-warrooms" (et "sentinel-canary") pour que les modérateurs puissent
continuer à écrire dans la war room pendant un lockdown réel.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import discord

logger = logging.getLogger("sentinel.lockdown")

_active: dict[int, bool] = {}
_release_tasks: dict[int, asyncio.Task] = {}

# Noms de catégories que SENTINEL gère lui-même — exclus du lockdown
SENTINEL_CATEGORY_NAMES = {"bidabot-warrooms", "bidabot-canary", "bidabot-admin", "bidabot-quarantine", "sentinel-warrooms", "sentinel-canary", "sentinel-admin", "sentinel-quarantine"}


def is_active(guild_id: int) -> bool:
    return _active.get(guild_id, False)


async def restore_from_db(guild: discord.Guild, db) -> None:
    """Appelé dans on_ready pour chaque guild : relit l'état depuis la base
    et repeuple _active. Évite le lockdown 'fantôme' post-restart où la DB
    indique active=True mais _active est vide → release() ne faisait rien."""
    active = await db.is_lockdown_active(guild.id)
    _active[guild.id] = active
    if active:
        logger.warning(
            "Lockdown toujours actif sur %s après restart (repris depuis la DB).",
            guild.name,
        )


async def _apply_permissions(guild: discord.Guild, locked: bool, slowmode: int):
    overwrite = discord.PermissionOverwrite(send_messages=False) if locked else None
    for ch in guild.text_channels:
        # Fix #10 : ne jamais locker les salons gérés par SENTINEL lui-même
        # (war rooms, canary) — les modérateurs doivent y rester opérationnels.
        if ch.category and ch.category.name in SENTINEL_CATEGORY_NAMES:
            continue
        try:
            await ch.set_permissions(guild.default_role, overwrite=overwrite,
                                      reason="SENTINEL lockdown auto (module 3bis)")
            await ch.edit(slowmode_delay=slowmode)
        except (discord.Forbidden, discord.HTTPException) as e:
            logger.warning("Impossible de modifier #%s : %s", ch.name, e)


async def trigger(guild: discord.Guild, payload: dict[str, Any], *, dry_run: bool,
                   auto_release_seconds: int, append_evidence, db, notify_callback=None) -> None:
    if _active.get(guild.id):
        return  # déjà actif, on ne réapplique pas

    _active[guild.id] = True
    await db.set_lockdown(guild.id, True, payload.get("reason", "inconnu"))

    if dry_run:
        logger.info("[DRY-RUN] Lockdown aurait été déclenché sur %s (raison: %s)",
                     guild.name, payload.get("reason"))
    else:
        await _apply_permissions(guild, locked=True, slowmode=30)
        try:
            await guild.edit(verification_level=discord.VerificationLevel.high)
        except (discord.Forbidden, discord.HTTPException):
            pass
        logger.warning("Lockdown ACTIF sur %s (raison: %s)", guild.name, payload.get("reason"))

    await append_evidence(guild.id, "lockdown_triggered", {
        "dry_run": dry_run,
        "reason": payload.get("reason", "inconnu"),
        "trigger_user_id": payload.get("user_id"),
        "score": payload.get("score"),
        "signals": payload.get("signals"),
    })

    task = asyncio.create_task(_auto_release(guild, auto_release_seconds, dry_run, append_evidence, db, notify_callback))
    _release_tasks[guild.id] = task


async def _auto_release(guild: discord.Guild, delay: int, dry_run: bool, append_evidence, db, notify_callback=None):
    await asyncio.sleep(delay)
    await release(guild, dry_run=dry_run, append_evidence=append_evidence, db=db, manual=False, notify_callback=notify_callback)


async def release(guild: discord.Guild, *, dry_run: bool, append_evidence, db, manual: bool, notify_callback=None) -> bool:
    if not _active.get(guild.id):
        return False

    task = _release_tasks.pop(guild.id, None)
    if task and manual:
        task.cancel()

    if not dry_run:
        await _apply_permissions(guild, locked=False, slowmode=0)

    _active[guild.id] = False
    await db.set_lockdown(guild.id, False)
    await append_evidence(guild.id, "lockdown_released", {"dry_run": dry_run, "manual": manual})
    logger.info("Lockdown levé sur %s (manuel=%s)", guild.name, manual)

    # Notifie le caller (main.py) pour envoyer l'alerte dashboard + DM admins
    if notify_callback:
        try:
            await notify_callback(guild, manual)
        except Exception:
            logger.exception("Erreur dans le callback de fin de lockdown sur %s", guild.name)

    return True
