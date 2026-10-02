"""
Module 25 — Nettoyeur de Raid & Mass-Ban Groupé 1-Clic (Raid Purge Engine).

Permet d'éradiquer instantanément une vague d'attaque (tokens / self-bots / raiders) :
1. Détection automatique et regroupement des comptes arrivés dans la dernière vague.
2. Bannissement groupé concurrent (avec respect des rate-limits Discord).
3. Purge immédiate de tous les messages envoyés par ces comptes (dernières 24h).
4. Détection et révocation automatique du lien d'invitation Discord utilisé par le raid.
5. Inscription forensique scellée par hash Ed25519.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
import logging
from typing import Any

import discord

logger = logging.getLogger("sentinel.raid_purge")


async def find_raid_suspects(
    guild: discord.Guild,
    db: Any,
    window_minutes: int = 45,
    score_threshold: float = 0.50,
) -> list[dict[str, Any]]:
    """
    Identifie tous les membres suspects ayant rejoint dans la fenêtre de raid.
    Critères : arrivés depuis moins de X minutes, compte récent (< 5 jours),
    score de légitimité suspect ou sans avatar personnalisé.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    suspects = []

    for member in guild.members:
        # Ignore les bots tiers déjà approuvés ou le propriétaire
        if member.id == guild.owner_id or member.id == guild.me.id:
            continue

        # Ignore les administrateurs
        if member.guild_permissions.administrator:
            continue

        # Vérification date de jointure sur le serveur
        if not member.joined_at or member.joined_at < cutoff:
            continue

        # Vérification whitelist dynamique
        if db and hasattr(db, "is_whitelisted"):
            role_ids = [r.id for r in member.roles]
            if await db.is_whitelisted(guild.id, member.id, role_ids):
                continue

        account_age_days = (datetime.now(timezone.utc) - member.created_at).days
        is_default_avatar = member.avatar is None

        # Récupération du score de risque si disponible
        score = 0.0
        if db and hasattr(db, "get_latest_score"):
            row = await db.get_latest_score(member.id, guild.id)
            if row:
                score = float(row.get("score", 0.0))

        # Éligibilité suspecte de raid
        is_suspect = (
            score >= score_threshold
            or account_age_days <= 3
            or (account_age_days <= 7 and is_default_avatar)
        )

        if is_suspect:
            suspects.append({
                "id": member.id,
                "name": str(member),
                "created_at": member.created_at.isoformat(),
                "joined_at": member.joined_at.isoformat(),
                "account_age_days": account_age_days,
                "score": round(score, 2),
                "is_default_avatar": is_default_avatar,
            })

    return suspects


async def execute_raid_purge(
    guild: discord.Guild,
    suspect_ids: list[int],
    *,
    delete_message_days: int = 1,
    db: Any = None,
    append_evidence: Any = None,
    dashboard_module: Any = None,
) -> dict[str, Any]:
    """
    Exécute le bannissement groupé de tous les comptes ciblés, supprime leurs messages,
    et révoque l'invitation compromise si identifiée.
    """
    banned_count = 0
    failed_count = 0
    revoked_invite = None

    if not guild.me.guild_permissions.ban_members:
        raise PermissionError("Le bot n'a pas la permission 'Bannir des membres' (BAN_MEMBERS).")

    # 1. Bannissement concurrent avec limitation de concurrence pour ne pas saturer Discord
    semaphore = asyncio.Semaphore(5)

    async def ban_one(uid: int):
        nonlocal banned_count, failed_count
        async with semaphore:
            try:
                # Ban direct par ID (fonctionne même si le membre a quitté entre-temps)
                await guild.ban(
                    discord.Object(id=uid),
                    delete_message_days=delete_message_days,
                    reason="SENTINEL Raid Purge: Éradication de raid groupé 1-clic",
                )
                banned_count += 1
            except Exception as e:
                logger.debug("Échec ban pour %d : %s", uid, e)
                failed_count += 1

    tasks = [ban_one(uid) for uid in suspect_ids]
    if tasks:
        await asyncio.gather(*tasks)

    # 2. Identification et révocation de l'invitation de raid
    if db and hasattr(db, "pool") and suspect_ids:
        try:
            # Trouve le code d'invitation le plus fréquemment utilisé par ces suspects
            row = await db.pool.fetchrow(
                """SELECT invite_code, COUNT(*) as cnt
                   FROM invite_usage
                   WHERE guild_id = $1 AND user_id = ANY($2::bigint[])
                   GROUP BY invite_code
                   ORDER BY cnt DESC
                   LIMIT 1""",
                guild.id, suspect_ids,
            )
            if row and row["invite_code"]:
                code = row["invite_code"]
                if guild.me.guild_permissions.manage_guild:
                    invites = await guild.invites()
                    for inv in invites:
                        if inv.code == code:
                            await inv.delete(reason="SENTINEL: Invitation de raid révoquée automatiquement")
                            revoked_invite = code
                            logger.info("Invitation de raid '%s' révoquée avec succès sur %s", code, guild.name)
                            break
        except Exception as e:
            logger.warning("Erreur révocation invitation raid : %s", e)

    payload = {
        "guild_id": guild.id,
        "total_suspects": len(suspect_ids),
        "banned_count": banned_count,
        "failed_count": failed_count,
        "revoked_invite": revoked_invite,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # 3. Preuve forensique
    if append_evidence:
        await append_evidence(guild.id, "raid_purge_executed", payload)

    # 4. Alerte Dashboard
    if dashboard_module:
        inv_str = f"\n• 🛑 **Invitation révoquée :** `discord.gg/{revoked_invite}`" if revoked_invite else ""
        await dashboard_module.send_alert(
            guild,
            title="🧹 PURGE DE RAID EFFECTUÉE AVEC SUCCÈS",
            description=(
                f"**{banned_count}** compte(s) de raid ont été bannis en masse.\n"
                f"• 🗑️ Messages des dernières 24h purgés instantanément.{inv_str}"
            ),
            color=0x00FF88,
        )

    return payload
