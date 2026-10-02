"""
Module 22 — Anti-Stresseur Vocal & Auto-Réparation de Salons Vocaux.

Protège les salons vocaux contre :
1. Les stresseurs WebRTC / attaques de lag provoquant des pics de latence (ping élevé, voix robotique, coupures).
2. Les attaques de flooding d'états vocaux (tokens rejoignant/quittant ou spammant mute/deaf à haute fréquence).
3. Les pannes ou dégradations régionales des passerelles vocales Discord.

Actions du module :
- /sentinel voice renew : Clone instantanément le salon vocal avec les MÊMES permissions,
  catégorie, bitrate et position, déplace automatiquement tous les membres connectés,
  et supprime l'ancien salon lagué/compromis (ce qui invalide l'ID ciblé par le stresseur).
- /sentinel voice ping : Mesure la latence WebRTC réelle de la passerelle vocale du salon.
- /sentinel voice region : Fait pivoter la région WebRTC Discord (ex: rotterdam -> frankfurt)
  pour changer instantanément de serveur physique sans recréer le salon.
- /sentinel voice autoprotect : Active la surveillance automatique en tâche de fond. Si un ping
  excessif (> seuil) ou un flood de paquets est détecté, Sentinel répare le salon de façon autonome.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from typing import Any, Optional

import discord

logger = logging.getLogger("sentinel.voice_antistress")

# Régions Discord RTC supportées
DISCORD_REGIONS = [
    "auto",
    "rotterdam",
    "frankfurt",
    "madrid",
    "milan",
    "london",
    "stockholm",
    "us-central",
    "us-east",
    "us-south",
    "us-west",
]


class VoiceVelocityTracker:
    """
    Suit la vélocité des événements d'état vocal par salon pour détecter
    les stresseurs floodant les connexions/déconnexions ou mute/deafen.
    """

    def __init__(self, window_seconds: int = 6, flood_threshold: int = 12):
        self.window_seconds = window_seconds
        self.flood_threshold = flood_threshold
        # channel_id -> list of timestamps
        self._history: dict[int, list[float]] = defaultdict(list)
        # channel_id -> last mitigation timestamp
        self._last_mitigation: dict[int, float] = {}

    def record_event(self, channel_id: int) -> tuple[int, bool]:
        """
        Enregistre un événement vocal sur un salon.
        Retourne (nombre_events_fenetre, est_un_flood).
        """
        now = time.time()
        events = self._history[channel_id]
        events.append(now)

        cutoff = now - self.window_seconds
        self._history[channel_id] = [t for t in events if t > cutoff]
        count = len(self._history[channel_id])

        # Cooldown de 30s après une mitigation pour éviter les boucles
        last_mit = self._last_mitigation.get(channel_id, 0)
        is_flood = (count >= self.flood_threshold) and (now - last_mit > 30)

        if is_flood:
            self._last_mitigation[channel_id] = now

        return count, is_flood


# Instance globale du traqueur de vélocité
velocity_tracker = VoiceVelocityTracker()


async def renew_voice_channel(
    channel: discord.VoiceChannel,
    *,
    reason: str = "Anti-stresseur vocal : recréation automatique",
    new_region: str | None = None,
    append_evidence: Any = None,
    db: Any = None,
) -> tuple[discord.VoiceChannel, int]:
    """
    Recrée un salon vocal à l'identique :
    1. Clone le salon avec toutes ses permissions, son bitrate, sa position et catégorie.
    2. Déplace immédiatement tous les membres connectés vers le nouveau salon.
    3. Supprime l'ancien salon compromis/stressé.
    4. Met à jour la configuration en DB si le salon était surveillé.
    5. Enregistre une preuve dans la chaîne forensique.

    Retourne : (nouveau_salon, nombre_de_membres_deplaces)
    """
    guild = channel.guild
    me = guild.me

    # Vérification des permissions du bot
    bot_perms = channel.permissions_for(me)
    if not bot_perms.manage_channels:
        raise PermissionError("Le bot n'a pas la permission 'Gérer les salons' sur ce salon vocal.")
    if not bot_perms.move_members:
        raise PermissionError("Le bot n'a pas la permission 'Déplacer les membres' sur ce serveur.")

    # 1. Capture des membres connectés avant toute modification
    connected_members = list(channel.members)
    member_count = len(connected_members)
    old_id = channel.id
    old_name = channel.name
    old_position = channel.position
    old_category = channel.category

    logger.info(
        "Début du renouvellement anti-stresseur pour le vocal '%s' (ID %s) avec %d membres connectés",
        old_name, old_id, member_count,
    )

    # 2. Clonage du salon avec l'intégralité des overwrites de permissions
    rtc_reg = None if new_region in (None, "auto") else new_region
    new_channel = await channel.clone(
        name=old_name,
        reason=f"SENTINEL — {reason}",
    )

    # Ajustement de la région et de la position si nécessaire
    try:
        kwargs: dict[str, Any] = {"position": old_position}
        if rtc_reg is not None:
            kwargs["rtc_region"] = rtc_reg
        await new_channel.edit(**kwargs)
    except discord.HTTPException as e:
        logger.warning("Ajustement des propriétés du nouveau salon vocal : %s", e)

    # 3. Déplacement des membres connectés vers le nouveau salon
    moved_count = 0
    for member in connected_members:
        # Vérifie si le membre est toujours en vocal dans l'ancien salon
        if member.voice and member.voice.channel and member.voice.channel.id == old_id:
            try:
                await member.move_to(new_channel, reason=f"SENTINEL — {reason}")
                moved_count += 1
            except discord.HTTPException as e:
                logger.warning("Échec déplacement du membre %s (%s) : %s", member.display_name, member.id, e)

    # 4. Suppression de l'ancien salon lagué/stressé
    try:
        await channel.delete(reason=f"SENTINEL — {reason} (remplacé par #{new_channel.name})")
    except discord.HTTPException as e:
        logger.error("Impossible de supprimer l'ancien salon vocal %s : %s", old_id, e)

    # 5. Mise à jour de la configuration en base de données si surveillé
    if db and hasattr(db, "update_voice_antistress_channel"):
        try:
            await db.update_voice_antistress_channel(guild.id, old_id, new_channel.id)
        except Exception as e:
            logger.warning("Erreur mise à jour config vocal en DB : %s", e)

    # 6. Journalisation forensique immuable
    if append_evidence:
        try:
            await append_evidence(
                guild.id,
                "voice_antistress_renew",
                {
                    "old_channel_id": old_id,
                    "new_channel_id": new_channel.id,
                    "channel_name": old_name,
                    "members_moved": moved_count,
                    "total_connected": member_count,
                    "reason": reason,
                    "region": str(new_channel.rtc_region or "auto"),
                },
            )
        except Exception as e:
            logger.warning("Erreur journalisation forensique renouvellement vocal : %s", e)

    logger.info(
        "Renouvellement anti-stresseur terminé : nouveau salon %s (ID %s), %d/%d membres déplacés",
        new_channel.name, new_channel.id, moved_count, member_count,
    )
    return new_channel, moved_count


async def measure_voice_latency(
    bot: discord.Client,
    channel: discord.VoiceChannel,
    *,
    timeout: float = 4.5,
) -> dict[str, Any]:
    """
    Mesure la latence WebRTC d'un salon vocal :
    1. Si PyNaCl est installé et que le bot peut se connecter, ouvre une connexion
       éphémère silencieuse à la passerelle vocale pour lire la latence WebRTC en ms.
    2. Si indisponible ou en cas d'erreur réseau, utilise la latence de la passerelle Discord.
    """
    guild = channel.guild
    me = guild.me
    perms = channel.permissions_for(me)

    if not perms.connect:
        return {
            "ping_ms": None,
            "status": "error",
            "error": "Le bot n'a pas la permission de se connecter à ce salon pour sonder la latence.",
            "source": "permission_denied",
            "region": str(channel.rtc_region or "auto"),
        }

    # Tentative de sonde WebRTC active
    has_nacl = True
    try:
        import nacl  # type: ignore # noqa: F401
    except ImportError:
        has_nacl = False

    if has_nacl:
        vc = None
        try:
            # Connexion éphémère (timeout court pour détecter le lag)
            vc = await asyncio.wait_for(channel.connect(timeout=timeout, reconnect=False), timeout=timeout + 0.5)
            # Attente légère de négociation du protocole
            await asyncio.sleep(0.3)
            # vc.latency est en secondes (ex: 0.035 s = 35 ms)
            raw_lat = getattr(vc, "latency", None)
            avg_lat = getattr(vc, "average_latency", None)

            measured = raw_lat if raw_lat is not None else avg_lat
            if measured is not None and measured > 0:
                ping_ms = round(measured * 1000.0, 1)
            else:
                ping_ms = round(bot.latency * 1000.0, 1)

            await vc.disconnect(force=True)
            vc = None

            status = "stressed" if ping_ms >= 250.0 else "warning" if ping_ms >= 140.0 else "optimal"
            return {
                "ping_ms": ping_ms,
                "status": status,
                "source": "webrtc_probe",
                "region": str(channel.rtc_region or "auto"),
                "member_count": len(channel.members),
            }
        except asyncio.TimeoutError:
            if vc:
                try:
                    await vc.disconnect(force=True)
                except Exception:
                    pass
            return {
                "ping_ms": 999.0,
                "status": "stressed",
                "source": "timeout",
                "reason": "Délai de connexion dépassé (passerelle vocale saturée ou sous attaque)",
                "region": str(channel.rtc_region or "auto"),
                "member_count": len(channel.members),
            }
        except Exception as e:
            if vc:
                try:
                    await vc.disconnect(force=True)
                except Exception:
                    pass
            logger.debug("Sonde WebRTC voix échouée (%s), repli sur latence passerelle", e)

    # Repli sur latence passerelle Discord
    ws_ping = round(bot.latency * 1000.0, 1) if bot.latency else 50.0
    status = "stressed" if ws_ping >= 300.0 else "warning" if ws_ping >= 160.0 else "optimal"
    return {
        "ping_ms": ws_ping,
        "status": status,
        "source": "gateway_ws",
        "region": str(channel.rtc_region or "auto"),
        "member_count": len(channel.members),
    }


async def switch_voice_region(
    channel: discord.VoiceChannel,
    region: str | None,
    *,
    reason: str = "Anti-stresseur vocal : rotation de région",
) -> tuple[bool, str]:
    """
    Bascule la région WebRTC d'un salon vocal pour contourner les stresseurs
    sans recréer le salon.
    """
    guild = channel.guild
    if not channel.permissions_for(guild.me).manage_channels:
        return False, "Le bot n'a pas la permission 'Gérer les salons'."

    rtc_reg = None if region in (None, "auto") else region
    try:
        await channel.edit(rtc_region=rtc_reg, reason=f"SENTINEL — {reason}")
        return True, f"Région basculée avec succès sur : **{region or 'auto'}**"
    except discord.HTTPException as e:
        return False, f"Erreur Discord : {e}"
