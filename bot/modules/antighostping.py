"""
Module 20 — Anti-Ghostping (Détection et traçage des pings supprimés).

Intercepte la suppression rapide de messages contenant des mentions :
- @everyone ou @here
- Rôles mentionnés
- Utilisateurs ciblés

Quand un utilisateur mentionne des membres ou le staff puis supprime son message
dans un court délai (par défaut < 90 secondes) pour harceler ou perturber sans trace :
1. Capture et trace immédiate dans #sentinel-logs (avec contenu, auteur, cibles et délai)
2. Alerte prioritaire dans #sentinel-alerts si @everyone / @here ou staff a été ciblé
3. Inscription dans la chaîne forensique immuable
"""
from __future__ import annotations

import logging
from typing import Any

import discord

logger = logging.getLogger("sentinel.antighostping")


async def handle_deleted_message(
    message: discord.Message,
    *,
    db: Any = None,
    append_evidence: Any = None,
    dashboard_module: Any = None,
    log_channel_id: int | None = None,
    max_age_seconds: int = 90,
) -> dict[str, Any] | None:
    """
    Analyse un message supprimé et déclenche l'alerte ghost-ping si nécessaire.
    """
    if not message.guild or message.author.bot:
        return None

    # Calcul du temps écoulé entre l'envoi et la suppression
    now = discord.utils.utcnow()
    age_seconds = (now - message.created_at).total_seconds()
    if age_seconds > max_age_seconds:
        return None  # Message ancien supprimé normalement, pas un ghost-ping d'attaque

    # Extraction des cibles mentionnées
    mentions_summary: list[str] = []
    is_critical = False

    if message.mention_everyone:
        mentions_summary.append("@everyone / @here")
        is_critical = True

    for r in message.role_mentions:
        mentions_summary.append(f"@{r.name}")
        if r.permissions.administrator or r.permissions.manage_guild or r.permissions.moderate_members:
            is_critical = True

    target_users = [u for u in message.mentions if u.id != message.author.id]
    for u in target_users[:5]:  # limite l'affichage
        mentions_summary.append(f"<@{u.id}>")
    if len(target_users) > 5:
        mentions_summary.append(f"+{len(target_users) - 5} autres")

    if not mentions_summary:
        return None  # Aucun ping dans le message supprimé

    guild = message.guild
    channel = message.channel
    content_preview = message.content[:500] if message.content else "*(Contenu vide ou médias)*"

    logger.warning(
        "👻 Ghost-ping détecté sur %s : %s a mentionné %s dans #%s puis supprimé après %ds",
        guild.name, message.author, mentions_summary, getattr(channel, "name", "inconnu"), int(age_seconds),
    )

    payload = {
        "guild_id": guild.id,
        "channel_id": channel.id,
        "author_id": message.author.id,
        "author_name": str(message.author),
        "content": message.content,
        "mentions": mentions_summary,
        "age_seconds": round(age_seconds, 1),
        "is_critical": is_critical,
        "reason": "ghostping_detected",
    }

    # Preuve forensique
    if append_evidence:
        entry = await append_evidence(guild.id, "ghostping_detected", payload)
        payload["evidence_hash"] = entry.get("hash")

    # Alerte dans #sentinel-alerts si ping @everyone ou rôle staff
    if dashboard_module and is_critical:
        await dashboard_module.send_alert(
            guild,
            title="👻 Ghost-ping critique détecté !",
            description=(
                f"**Auteur :** <@{message.author.id}> (`{message.author}`)\n"
                f"**Salon :** <#{channel.id}>\n"
                f"**Cibles mentionnées :** {', '.join(mentions_summary)}\n"
                f"**Supprimé après :** `{int(age_seconds)}s`\n\n"
                f"**Contenu effacé :**\n> {content_preview}"
            ),
            color=0xFFAA00,
        )

    # Journalisation dans le salon de logs configuré
    target_log_channel = None
    if log_channel_id:
        target_log_channel = guild.get_channel(log_channel_id)
    
    if not target_log_channel:
        # Tente de trouver un salon #bidabot-logs ou #sentinel-logs
        for ch in guild.text_channels:
            if any(k in ch.name for k in ("bidabot-logs", "sentinel-logs")):
                target_log_channel = ch
                break

    if target_log_channel and target_log_channel.permissions_for(guild.me).send_messages:
        embed = discord.Embed(
            title="👻 Notification de Ghost-Ping",
            description=f"Un message mentionnant des membres a été supprimé après `{int(age_seconds)}s`.",
            color=0xFF9900 if is_critical else 0x5865F2,
            timestamp=now,
        )
        embed.add_field(name="Auteur", value=f"<@{message.author.id}> (`{message.author}`)", inline=True)
        embed.add_field(name="Salon", value=f"<#{channel.id}>", inline=True)
        embed.add_field(name="Mentions", value=", ".join(mentions_summary) or "Aucune", inline=False)
        clean_preview = content_preview.replace("```", "'''")
        embed.add_field(name="Contenu supprimé", value=f"```{clean_preview}```", inline=False)
        embed.set_footer(text="BIDABOT Ghost-Ping Shield")
        try:
            await target_log_channel.send(embed=embed)
        except discord.HTTPException:
            pass

    return payload
