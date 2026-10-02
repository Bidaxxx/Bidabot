"""
SENTINEL — point d'entrée.

Câble tous les modules ensemble et implémente le flux anti-raid documenté :

  join détecté (3) -> vélocité + légitimité
    -> si suspect  : rien (juste loggé, en dessous du seuil critique)
    -> si critique : lockdown (3bis) + war room (9), en une seule émission
                     d'événement "risk_critical" traité SÉQUENTIELLEMENT
                     (voir bus.py) pour garantir que le lockdown est acté
                     avant que la war room ne lise le contexte.

  message dans un canary (5) -> hit -> "canary_hit" -> war room directe.

  message normal -> fingerprint (1) + stylométrie (2) + comptage burst (fix #8),
  et vérification périodique de coordination (4) après chaque rafale de joins.

Corrections appliquées dans ce fichier :
  Fix #1  : on_ready restaure l'état de lockdown depuis la DB (lockdown.restore_from_db).
  Fix #3  : on_ready restaure les war rooms actives depuis la DB (warroom.restore_from_db).
  Fix #6  : _canary_ids passé par référence au cog → canary setup les met à jour en live.
  Fix #7  : on_member_remove — nettoyage des buffers mémoire des membres qui partent.
  Fix #8  : message_burst_score alimenté via cache.message_burst_count dans on_message
            et cache.get_message_burst lors du scoring on_member_join.
  Fix #12 : on_guild_remove — purge des données du serveur en DB.
"""
from __future__ import annotations

import asyncio
import datetime
import logging

import discord
from discord.ext import commands, tasks

from bot.bus import EventBus
from bot.cache import Cache
from bot.config import settings
from bot.crypto_utils import load_or_create_signing_key
from bot.db import Database
from bot.modules import canary, coordination, credential_stuffing, fingerprint, stylometry
from bot.modules import forensics, lockdown, warroom
from bot.modules import antispam, antiscam, guild_dashboard
from bot.modules import similar_names as similar_names_mod
from bot.modules import quarantine, trust_score, ban_fingerprint, invite_audit
from bot.modules import antinuke, anti_impersonation, antighostping, voice_antistress, snapshot, antimalware, raid_purge, vulnerability_scanner, red_team_simulator, gatekeeper
from bot.modules.legitimacy import LegitimacyScorer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.main")

intents = discord.Intents.default()
intents.members = True          # requis pour on_member_join (à activer aussi sur le portail dev Discord)
intents.message_content = True  # requis pour le fingerprint/stylométrie/canaries
intents.voice_states = True     # requis pour l'anti-stresseur et surveillance des salons vocaux

bot = commands.Bot(command_prefix="!", intents=intents)

db = Database(settings.database_url)
cache = Cache(settings.redis_url)
bus = EventBus()
scorer = LegitimacyScorer(
    settings.legitimacy_model_path, settings.legitimacy_min_training_samples,
    settings.thresholds.account_age_min_days, settings.thresholds.join_velocity_per_minute,
)
signing_key = None  # chargé dans setup_hook (I/O)

# Fix #6 : dict mutable passé par référence au cog — les mises à jour
# faites dans admin.py (canary setup) sont immédiatement visibles ici.
_canary_ids: dict[int, set[int]] = {}


async def _append_evidence(guild_id: int, event_type: str, data: dict) -> dict:
    return await forensics.append_evidence(db, guild_id, event_type, data)


async def _log_to_channel(guild_id: int, message: str) -> None:
    """Journal d'activité léger, indépendant des war rooms — utile pour un
    admin qui veut un historique sans salon dédié à chaque détection.
    N'envoie rien si aucun log_channel_id n'a été configuré (/sentinel setup)."""
    _, log_channel_id = await db.get_guild_config(guild_id)
    if not log_channel_id:
        return
    channel = bot.get_channel(log_channel_id)
    if channel:
        try:
            await channel.send(message)
        except discord.HTTPException:
            pass


# ── Handlers du bus ───────────────────────────────────────────────

async def _on_risk_critical(payload: dict):
    guild = bot.get_guild(payload["guild_id"])
    if not guild:
        return
    dry_run = await db.get_dry_run(guild.id)

    await lockdown.trigger(
        guild, payload, dry_run=dry_run,
        auto_release_seconds=settings.thresholds.lockdown_auto_release_seconds,
        append_evidence=_append_evidence, db=db,
        notify_callback=_notify_lockdown_released,
    )
    await _log_to_channel(
        guild.id,
        f"🚨 Score critique détecté (raison: `{payload.get('reason')}`, score: `{payload.get('score')}`) "
        f"— lockdown {'simulé (dry-run)' if dry_run else 'appliqué'}.",
    )
    await warroom.open_warroom(
        payload, bot=bot, db=db, cache=cache, bus=bus, append_evidence=_append_evidence,
        lockdown_module=lockdown, forensics_module=forensics, signing_key=signing_key,
        dry_run=dry_run, auto_release_seconds=settings.thresholds.lockdown_auto_release_seconds,
    )
    # Alerte dashboard + DM admins
    reason = payload.get('reason', 'risque critique')
    score = payload.get('score', '?')
    await guild_dashboard.send_alert(
        guild,
        title=f"🚨 Incident critique — {reason}",
        description=f"Score : `{score}` — War room ouverte.",
        color=0xFF0000,
        fields={"Utilisateur": f"<@{payload.get('user_id', 0)}>"},
        target_user_id=payload.get("user_id"),
        score_data=payload,
        db=db,
        append_evidence=_append_evidence,
        quarantine_module=quarantine,
    )
    await guild_dashboard.dm_admins(
        guild,
        title="Incident critique détecté",
        description=(
            f"**Raison :** {reason}\n"
            f"**Score :** {score}\n"
            f"**Utilisateur :** <@{payload.get('user_id', 0)}>\n"
            "Une war room a été ouverte sur le serveur."
        ),
    )
    await guild_dashboard.update_status(guild, db, lockdown, scorer)


async def _on_canary_hit(payload: dict):
    guild_id = payload["guild_id"]
    guild = bot.get_guild(guild_id)
    await _log_to_channel(guild_id, "🚨 Canal piège déclenché — war room ouverte.")
    await warroom.open_warroom(
        payload, bot=bot, db=db, cache=cache, bus=bus, append_evidence=_append_evidence,
        lockdown_module=lockdown, forensics_module=forensics, signing_key=signing_key,
        dry_run=await db.get_dry_run(guild_id),
        auto_release_seconds=settings.thresholds.lockdown_auto_release_seconds,
    )
    if guild:
        await guild_dashboard.send_alert(
            guild, title="🪤 Canal piège déclenché",
            description=f"Utilisateur <@{payload.get('user_id', 0)}> a déclenché un canary.",
            color=0xFF6600,
            target_user_id=payload.get("user_id"),
            score_data=payload,
            db=db,
            append_evidence=_append_evidence,
            quarantine_module=quarantine,
        )
        await guild_dashboard.dm_admins(
            guild,
            title="Canal piège déclenché",
            description=(
                f"Utilisateur <@{payload.get('user_id', 0)}> a accédé à un canal piège.\n"
                "Une war room a été ouverte."
            ),
        )


bus.on("risk_critical", _on_risk_critical)
bus.on("canary_hit", _on_canary_hit)


# ── Écouteur d'Actions en direct du Dashboard Web (Redis PubSub) ─────

async def _handle_web_action(payload: dict):
    action = payload.get("action")
    guild_id = payload.get("guild_id")
    if not guild_id:
        return
    guild = bot.get_guild(int(guild_id))
    if not guild:
        return

    logger.info("📡 Action Dashboard reçue : '%s' pour %s (%d)", action, guild.name, guild.id)

    if action == "lockdown_on":
        await lockdown.trigger(
            guild, {"reason": "Déclenché depuis le Dashboard Web", "user_id": payload.get("user_id")},
            dry_run=False,
            auto_release_seconds=settings.thresholds.lockdown_auto_release_seconds,
            append_evidence=_append_evidence, db=db,
            notify_callback=_notify_lockdown_released,
        )
    elif action == "lockdown_off":
        await lockdown.release(
            guild, db, append_evidence=_append_evidence,
            notify_callback=_notify_lockdown_released,
        )
    elif action == "panic_mode":
        await lockdown.trigger(
            guild, {"reason": "Mode Panique activé depuis la console web", "user_id": payload.get("user_id")},
            dry_run=False,
            auto_release_seconds=3600,
            append_evidence=_append_evidence, db=db,
            notify_callback=_notify_lockdown_released,
        )
        try:
            await guild.edit(verification_level=discord.VerificationLevel.highest)
        except Exception:
            pass
        await guild_dashboard.send_alert(
            guild, title="🚨 ALERTE : MODE PANIQUE ACTIVÉ",
            description="Le mode panique a été activé depuis la console web. Le serveur est verrouillé pendant 1 heure.",
            color=0xFF0000,
        )
    elif action == "ban":
        target_id = payload.get("target_id")
        reason = payload.get("reason", "Bannissement depuis le Dashboard Web")
        delete_days = int(payload.get("delete_message_days", 1))
        if target_id and guild:
            try:
                await guild.ban(
                    discord.Object(id=int(target_id)),
                    delete_message_days=delete_days,
                    reason=reason,
                )
                await _append_evidence(guild.id, "member_banned_via_web", {
                    "user_id": int(target_id),
                    "reason": reason,
                    "admin_id": payload.get("user_id"),
                    "delete_days": delete_days,
                })
                await guild_dashboard.send_alert(
                    guild,
                    title="🔨 Membre Banni depuis la Console Web",
                    description=f"L'utilisateur <@{target_id}> (`{target_id}`) a été banni du serveur.\n• Motif : **{reason}**\n• Messages purgés : **{delete_days}j**",
                    color=0xFF0000,
                )
                logger.info("Membre %s banni depuis le Dashboard Web sur %s", target_id, guild.name)
            except Exception as e:
                logger.error("Erreur ban web pour %s : %s", target_id, e)
    elif action == "kick":
        target_id = payload.get("target_id")
        reason = payload.get("reason", "Expulsion depuis le Dashboard Web")
        if target_id and guild:
            try:
                member = guild.get_member(int(target_id))
                if member:
                    await member.kick(reason=reason)
                else:
                    await guild.kick(discord.Object(id=int(target_id)), reason=reason)
                await _append_evidence(guild.id, "member_kicked_via_web", {
                    "user_id": int(target_id),
                    "reason": reason,
                    "admin_id": payload.get("user_id"),
                })
                await guild_dashboard.send_alert(
                    guild,
                    title="👢 Membre Expulsé depuis la Console Web",
                    description=f"L'utilisateur <@{target_id}> (`{target_id}`) a été expulsé.\n• Motif : **{reason}**",
                    color=0xFFAA00,
                )
                logger.info("Membre %s expulsé depuis le Dashboard Web sur %s", target_id, guild.name)
            except Exception as e:
                logger.error("Erreur kick web pour %s : %s", target_id, e)
    elif action == "timeout":
        target_id = payload.get("target_id")
        duration_seconds = int(payload.get("duration", 600))
        reason = payload.get("reason", "Mise sous silence depuis le Dashboard Web")
        if target_id and guild:
            try:
                member = guild.get_member(int(target_id))
                if member:
                    until = (
                        discord.utils.utcnow() + datetime.timedelta(seconds=duration_seconds)
                        if duration_seconds > 0 else None
                    )
                    await member.timeout(until, reason=reason)
                    action_name = "member_timed_out_via_web" if duration_seconds > 0 else "member_untimeout_via_web"
                    await _append_evidence(guild.id, action_name, {
                        "user_id": int(target_id),
                        "duration": duration_seconds,
                        "reason": reason,
                        "admin_id": payload.get("user_id"),
                    })
                    dur_text = f"{duration_seconds // 60}m" if duration_seconds < 3600 else f"{duration_seconds // 3600}h"
                    title = "⏳ Membre Réduit au Silence" if duration_seconds > 0 else "🔊 Silence Levé"
                    desc = (
                        f"L'utilisateur <@{target_id}> a été mis en timeout pour **{dur_text}**.\n• Motif : **{reason}**"
                        if duration_seconds > 0 else f"Le silence de <@{target_id}> a été levé."
                    )
                    await guild_dashboard.send_alert(
                        guild,
                        title=title,
                        description=desc,
                        color=0xFF9900 if duration_seconds > 0 else 0x00FF88,
                    )
                    logger.info("Membre %s timeout=%ds sur %s", target_id, duration_seconds, guild.name)
            except Exception as e:
                logger.error("Erreur timeout web pour %s : %s", target_id, e)
    elif action == "quarantine":
        target_id = payload.get("target_id")
        member = guild.get_member(int(target_id)) if target_id else None
        if member:
            reason = payload.get("reason", "Quarantaine appliquée depuis le Dashboard Web")
            await quarantine.quarantine(
                member, reason=reason, db=db, append_evidence=_append_evidence,
            )
    elif action == "unquarantine":
        target_id = payload.get("target_id")
        member = guild.get_member(int(target_id)) if target_id else None
        if member:
            await quarantine.release(
                member, db=db, append_evidence=_append_evidence,
            )
    elif action == "voice_renew":
        ch_id = payload.get("channel_id")
        channel = guild.get_channel(int(ch_id)) if ch_id else None
        if channel and isinstance(channel, discord.VoiceChannel):
            await voice_antistress.renew_voice_channel(
                channel, reason="Renouvellement forcé depuis le Dashboard Web",
                append_evidence=_append_evidence, db=db,
            )
    elif action == "backup_create":
        label = payload.get("label", "Dashboard Web")
        snap = await snapshot.capture_guild_snapshot(guild, label=label)
        total_channels = snap["summary"]["text_channels_count"] + snap["summary"]["voice_channels_count"]
        total_roles = snap["summary"]["roles_count"]
        snap_id = await db.save_guild_snapshot(
            guild.id, label, snap,
            channels_count=total_channels,
            roles_count=total_roles,
        )
        await _append_evidence(guild.id, "guild_snapshot_created", {
            "snapshot_id": snap_id, "label": label, "summary": snap["summary"],
            "triggered_by": "dashboard_web",
        })
        await guild_dashboard.send_alert(
            guild, title="💾 SNAPSHOT DE SÉCURITÉ CRÉÉ",
            description=f"Un snapshot de la structure du serveur (ID `#{snap_id}`, '{label}') a été enregistré avec succès depuis la console web.",
            color=0x00FF88,
        )
    elif action == "backup_restore":
        snapshot_id = payload.get("snapshot_id")
        if snapshot_id:
            row = await db.get_guild_snapshot_by_id(int(snapshot_id), guild.id)
            if row:
                stats = await snapshot.restore_guild_snapshot(guild, row["snapshot_data"])
                await _append_evidence(guild.id, "guild_snapshot_restored", {
                    "snapshot_id": int(snapshot_id), "stats": stats,
                    "triggered_by": "dashboard_web",
                })
                await guild_dashboard.send_alert(
                    guild, title="🛡️ RESTAURATION D'URGENCE EFFECTUÉE",
                    description=(
                        f"Restauration du snapshot `#{snapshot_id}` ('{row['label']}') terminée :\n"
                        f"• Rôles recréés : **{stats['roles_restored']}**\n"
                        f"• Catégories recréées : **{stats['categories_restored']}**\n"
                        f"• Salons recréés : **{stats['channels_restored']}**"
                    ),
                    color=0x00FF88,
                )
    elif action == "raid_purge":
        window = int(payload.get("window_minutes", 45))
        suspects = await raid_purge.find_raid_suspects(guild, db, window_minutes=window)
        suspect_ids = [s["id"] for s in suspects]
        if suspect_ids:
            res = await raid_purge.execute_raid_purge(
                guild, suspect_ids,
                delete_message_days=1,
                db=db, append_evidence=_append_evidence,
                dashboard_module=guild_dashboard,
            )
            logger.info("Purge de raid exécutée sur %s : %d bannis", guild.name, res.get("banned_count", 0))
    elif action == "audit_fix":
        fix_action = payload.get("fix_action")
        if fix_action:
            res = await vulnerability_scanner.auto_fix_vulnerability(
                guild, fix_action, db=db, append_evidence=_append_evidence,
            )
            logger.info("Auto-fix exécuté sur %s : %s", guild.name, res.get("action_performed"))
    elif action == "channel_lock":
        ch_id = payload.get("channel_id")
        ch = guild.get_channel(int(ch_id)) if ch_id else None
        if ch and hasattr(ch, "set_permissions"):
            await ch.set_permissions(guild.default_role, send_messages=False, reason="Verrouillage depuis Dashboard Web")
            await _append_evidence(guild.id, "channel_locked", {"channel_id": ch.id, "name": ch.name})
            logger.info("Salon #%s verrouillé depuis le Dashboard Web", ch.name)
    elif action == "channel_unlock":
        ch_id = payload.get("channel_id")
        ch = guild.get_channel(int(ch_id)) if ch_id else None
        if ch and hasattr(ch, "set_permissions"):
            await ch.set_permissions(guild.default_role, send_messages=None, reason="Déverrouillage depuis Dashboard Web")
            await _append_evidence(guild.id, "channel_unlocked", {"channel_id": ch.id, "name": ch.name})
            logger.info("Salon #%s déverrouillé depuis le Dashboard Web", ch.name)
    elif action == "channel_slowmode":
        ch_id = payload.get("channel_id")
        delay = int(payload.get("delay", 0))
        ch = guild.get_channel(int(ch_id)) if ch_id else None
        if ch and hasattr(ch, "edit"):
            await ch.edit(slowmode_delay=delay, reason="Slowmode configuré depuis Dashboard Web")
            await _append_evidence(guild.id, "channel_slowmode_changed", {"channel_id": ch.id, "delay": delay})
            logger.info("Slowmode de #%s réglé sur %ds depuis le Dashboard Web", ch.name, delay)
    elif action == "channel_purge":
        ch_id = payload.get("channel_id")
        count = min(int(payload.get("count", 25)), 100)
        ch = guild.get_channel(int(ch_id)) if ch_id else None
        if ch and hasattr(ch, "purge"):
            deleted = await ch.purge(limit=count)
            await _append_evidence(guild.id, "channel_purged", {"channel_id": ch.id, "deleted": len(deleted)})
            logger.info("Purge de %d messages sur #%s depuis le Dashboard Web", len(deleted), ch.name)




async def _listen_redis_actions():
    """Écoute en temps réel les actions publiées par le Dashboard Web sur Redis."""
    try:
        while not cache.client:
            await asyncio.sleep(0.5)
        pubsub = cache.client.pubsub()
        await pubsub.subscribe("bidabot:control", "sentinel:control")
        logger.info("📡 Écouteur d'actions Web connecté sur les canaux Redis 'bidabot:control' et 'sentinel:control'.")
        async for message in pubsub.listen():
            if message and message.get("type") == "message":
                try:
                    import json
                    data = message.get("data")
                    if isinstance(data, (str, bytes)):
                        payload = json.loads(data)
                        await _handle_web_action(payload)
                except Exception as e:
                    logger.error("Erreur traitement action web : %s", e)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.warning("Écouteur Redis interrompu : %s", e)


# ── Événements Discord ────────────────────────────────────────────

@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    cmd_name = interaction.command.name if interaction.command else "inconnue"
    logger.error("Erreur commande slash '%s' : %s", cmd_name, error)
    msg = "❌ Une erreur est survenue lors de l'exécution de la commande."
    if isinstance(error, app_commands.MissingPermissions):
        msg = "❌ Vous devez être administrateur du serveur pour exécuter cette commande."
    elif isinstance(error, app_commands.BotMissingPermissions):
        msg = f"❌ Le bot n'a pas les permissions requises sur le serveur : {', '.join(error.missing_permissions)}."
    elif isinstance(error, app_commands.CommandOnCooldown):
        msg = f"⏳ Cette commande est en rechargement. Réessayez dans {error.retry_after:.1f}s."

    try:
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)
    except Exception:
        pass


@bot.event
async def setup_hook():
    global signing_key
    await db.connect()
    await cache.connect()
    signing_key = load_or_create_signing_key(settings.signing_key_path)
    logger.info("SENTINEL prêt : DB + Redis connectés, clé de signature chargée.")

    # Lance l'écouteur d'actions Web en arrière-plan
    asyncio.create_task(_listen_redis_actions())

    from bot.cogs.admin import SentinelAdmin
    # Fix #6 : on passe _canary_ids (dict mutable) par référence pour que
    # le cog admin puisse le mettre à jour lors d'un /sentinel canary setup.
    await bot.add_cog(SentinelAdmin(bot, db, cache, bus, scorer, _append_evidence, _canary_ids))

    # IMPORTANT : on ne synchronise JAMAIS bot.tree.sync() sans guild -> ça
    # publierait les commandes globalement (jusqu'à 1h de propagation, ET
    # doublon avec la copie guild-scoped synchronisée dans on_ready/
    # on_guild_join ci-dessous). On veut UNIQUEMENT nettoyer un éventuel
    # ancien enregistrement global côté Discord (d'un précédent déploiement),
    # sans toucher à l'arbre LOCAL de commandes : on_ready en a besoin pour
    # les copier vers chaque serveur (copy_global_to). D'où l'appel HTTP
    # direct ci-dessous plutôt que bot.tree.clear_commands() + sync().
    try:
        await bot.http.bulk_upsert_global_commands(bot.application_id, payload=[])
        logger.info("Ancien registre de commandes globales Discord vidé (les commandes restent 100%% guild-scoped).")
    except discord.HTTPException as e:
        logger.warning("Impossible de vider le registre global (pas bloquant) : %s", e)


@bot.event
async def on_ready():
    logger.info("🛡️ SENTINEL en ligne : %s", bot.user)
    for guild in bot.guilds:
        await db.ensure_guild(guild.id, guild.name)
        _canary_ids[guild.id] = await canary.setup_canaries(guild, db)

        # Fix #1 : restaure l'état de lockdown depuis la DB — évite le
        # lockdown "fantôme" où _active est vide après restart mais la DB
        # indique toujours active=True → release() ne faisait rien.
        await lockdown.restore_from_db(guild, db)

        # Sync guild-scoped pour CE serveur uniquement — voir la note dans
        # setup_hook sur pourquoi on évite tout sync global.
        bot.tree.copy_global_to(guild=guild)
        await bot.tree.sync(guild=guild)

    # Fix #3 : restaure les war rooms ouvertes
    await warroom.restore_from_db(bot, db)

    # Module 12 : restaure les salons dashboard depuis la DB
    await guild_dashboard.restore_from_db(bot, db)

    # Module 14 : restaure les permissions de quarantaine si des membres sont encore en quarantaine
    for guild in bot.guilds:
        await quarantine.restore_from_db(guild, db)

    # Module 17 : prend un snapshot initial des invitations sur tous les serveurs
    # + persistance Redis pour survivre aux futurs restarts
    for guild in bot.guilds:
        await invite_audit.snapshot(guild, redis_client=cache.client)

    # Lance les tâches périodiques
    if not _update_dashboard_task.is_running():
        _update_dashboard_task.start()
    if not _auto_label_legit_task.is_running():
        _auto_label_legit_task.start()
    if not _update_trust_score_task.is_running():
        _update_trust_score_task.start()
    if not _purge_ban_fingerprints_task.is_running():
        _purge_ban_fingerprints_task.start()
    if not _voice_watchdog_task.is_running():
        _voice_watchdog_task.start()

    logger.info("%d commande(s) slash synchronisée(s) sur %d serveur(s).", len(bot.tree.get_commands()), len(bot.guilds))


@tasks.loop(minutes=5)
async def _update_dashboard_task():
    """Met à jour l'embed de statut dans #sentinel-status de chaque serveur."""
    for guild in bot.guilds:
        await guild_dashboard.update_status(guild, db, lockdown, scorer)


@tasks.loop(hours=6)
async def _auto_label_legit_task():
    """Auto-labellise comme 'legit' les membres non-labellisés présents depuis
    plus de 7 jours — ils ont prouvé leur légitimité par leur durée de présence.
    Alimente le modèle ML sans action manuelle de l'admin."""
    for guild in bot.guilds:
        user_ids = await db.get_long_standing_members(guild.id, days=7)
        count = 0
        for uid in user_ids:
            if await db.auto_label_user(uid, guild.id, "legit"):
                count += 1
        if count:
            logger.info("Auto-label 'legit' : %d membre(s) sur %s", count, guild.name)

    # Réentraînement automatique du modèle ML si de nouveaux labels sont disponibles
    try:
        report = await legitimacy.auto_train_job(db, scorer, _append_evidence)
        if report:
            logger.info("🧠 Auto-entraînement ML complété avec succès (%s)", scorer.model_version)
    except Exception as e:
        logger.warning("Erreur auto-train ML périodique : %s", e)


@tasks.loop(hours=1)
async def _update_trust_score_task():
    """Recalcule le trust score de chaque serveur toutes les heures et met à jour
    le dashboard. Aussi appelé manuellement après chaque incident majeur."""
    for guild in bot.guilds:
        await trust_score.compute(guild.id, db, lockdown, forensics, guild=guild)


@tasks.loop(hours=24)
async def _purge_ban_fingerprints_task():
    """Supprime quotidiennement les fingerprints de bannis expirés (rétention 90j)."""
    count = await db.purge_expired_banned_fingerprints()
    if count:
        logger.info("Fingerprints de bannis expirés supprimés : %d", count)


_last_voice_check: dict[tuple[int, int], float] = {}

@tasks.loop(seconds=5)
async def _voice_watchdog_task():
    """Surveillance continue de latence et auto-réparation des salons vocaux selon l'intervalle configuré."""
    import time
    try:
        configs = await db.get_all_voice_antistress_configs()
        now = time.time()
        for cfg in configs:
            interval = int(cfg.get("check_interval_seconds") or 30)
            key = (cfg["guild_id"], cfg["channel_id"])
            if (now - _last_voice_check.get(key, 0)) < interval:
                continue

            _last_voice_check[key] = now

            guild = bot.get_guild(cfg["guild_id"])
            if not guild:
                continue
            channel = guild.get_channel(cfg["channel_id"])
            if not channel or not isinstance(channel, discord.VoiceChannel):
                continue
            # Ne sonde que s'il y a des membres connectés
            if not channel.members:
                continue

            lat_info = await voice_antistress.measure_voice_latency(bot, channel, timeout=3.5)
            ping = lat_info.get("ping_ms")
            status = lat_info.get("status")

            if status == "stressed" or (ping is not None and ping >= cfg["max_ping_ms"]):
                logger.warning(
                    "Anti-stresseur vocal : pic de lag critique sur %s (%s ms >= seuil %s ms)",
                    channel.name, ping, cfg["max_ping_ms"],
                )
                try:
                    new_ch, moved = await voice_antistress.renew_voice_channel(
                        channel,
                        reason=f"Latence critique ({ping} ms >= seuil {cfg['max_ping_ms']} ms)",
                        append_evidence=_append_evidence,
                        db=db,
                    )
                    alert_msg = (
                        f"⚡ **BIDABOT Anti-Stresseur Vocal :** Intervention automatique sur **#{channel.name}** !\n"
                        f"• Latence critique mesurée : **{ping} ms** (seuil : {cfg['max_ping_ms']} ms)\n"
                        f"• 🔊 Nouveau salon recréé : {new_ch.mention}\n"
                        f"• 👥 **{moved}** membre(s) déplacés automatiquement sans coupure.\n"
                        f"• 🛡️ L'ancien salon a été détruit et les stresseurs neutralisés."
                    )
                    await _log_to_channel(guild.id, alert_msg)
                    await guild_dashboard.send_alert(
                        guild,
                        title="⚡ Anti-Stresseur Vocal : Salon auto-réparé",
                        description=f"Le salon **#{channel.name}** a été recréé suite à un pic de latence ({ping} ms).\n{moved} membre(s) transférés dans {new_ch.mention}.",
                        color=0x00FF88,
                    )
                except Exception as e:
                    logger.error("Erreur renouvellement auto vocal : %s", e)
    except Exception as e:
        logger.debug("Erreur watchdog vocal : %s", e)


@bot.event
async def on_guild_join(guild: discord.Guild):
    # Petit délai pour laisser Discord propager les permissions du bot
    # avant d'essayer de créer des salons (évite les Forbidden intempestifs
    # les premières secondes après une invitation).
    await asyncio.sleep(3)

    await db.ensure_guild(guild.id, guild.name)

    # setup_canaries peut échouer si le bot n'a pas Manage Channels —
    # on l'attrape ici pour ne pas bloquer le sync des commandes.
    try:
        _canary_ids[guild.id] = await canary.setup_canaries(guild, db)
    except Exception:
        logger.warning("Impossible de créer les canaux canary sur %s — lance /bidabot setup manuellement.", guild.name)
        _canary_ids[guild.id] = set()

    # Sync ciblé pour que /bidabot soit utilisable IMMÉDIATEMENT sur le
    # nouveau serveur, sans attendre la propagation du sync global (~1h).
    try:
        bot.tree.copy_global_to(guild=guild)
        synced = await bot.tree.sync(guild=guild)
        logger.info("%d commande(s) synchronisée(s) sur le nouveau serveur %s.", len(synced), guild.name)
    except discord.HTTPException as e:
        logger.warning("Échec du sync de commandes sur %s : %s", guild.name, e)

    logger.info("Rejoint un nouveau serveur : %s (%d). Lance /bidabot setup pour finaliser la config.", guild.name, guild.id)


@bot.event
async def on_guild_remove(guild: discord.Guild):
    """Fix #12 — Purge toutes les données du serveur quand le bot en est
    retiré. Les tables enfants (users, risk_scores, etc.) sont supprimées
    automatiquement par les contraintes FK ON DELETE CASCADE."""
    _canary_ids.pop(guild.id, None)
    try:
        await db.purge_guild_data(guild.id)
        logger.info("Données du serveur %s (%d) purgées après retrait.", guild.name, guild.id)
    except Exception:
        logger.exception("Erreur lors de la purge des données du serveur %s (%d).", guild.name, guild.id)


@bot.event
async def on_member_join(member: discord.Member):
    # Interception immédiate des rogue bots (anti-nuke)
    if member.bot:
        rogue_res = await antinuke.check_bot_add(
            member.guild, member,
            db=db, bus=bus, append_evidence=_append_evidence,
            dashboard_module=guild_dashboard,
        )
        if rogue_res:
            logger.info("Bot suspect intercepté et neutralisé : %s sur %s", member, member.guild.name)
            return

    guild_id = member.guild.id
    await db.record_join(guild_id, member.id)

    velocity = await cache.sliding_window_add_and_count(
        f"sentinel:joinvel:{guild_id}", window_seconds=60,
    )
    await db.upsert_user(
        member.id, guild_id,
        account_age_days=(discord.utils.utcnow() - member.created_at).days,
        join_date=member.joined_at, avatar_hash=str(member.avatar) if member.avatar else None,
        is_default_avatar=member.avatar is None,
    )

    # Fix #8 : récupère les messages envoyés dans la dernière minute par ce
    # compte (possible sur les gros serveurs où un compte rejoignait après
    # avoir été vu dans un autre salon, ou pour du re-scoring) sans ajouter
    # d'événement dans la fenêtre join.
    messages_last_minute = await cache.get_message_burst(member.id, guild_id, window_seconds=60)

    # Extraction des badges Discord officiels
    flags = member.public_flags
    active_flags = [
        f for f in [
            getattr(flags, "hypesquad", False),
            getattr(flags, "hypesquad_bravery", False),
            getattr(flags, "hypesquad_brilliance", False),
            getattr(flags, "hypesquad_balance", False),
            getattr(flags, "early_supporter", False),
            getattr(flags, "partner", False),
            getattr(flags, "staff", False),
            getattr(flags, "bug_hunter", False),
            getattr(flags, "bug_hunter_level_2", False),
            getattr(flags, "active_developer", False),
            getattr(flags, "verified_bot_developer", False),
        ] if f
    ] if flags else []
    badge_count = len(active_flags)
    has_badges = badge_count > 0

    # Extraction bio / statut personnalisé
    bio_texts = []
    if hasattr(member, "bio") and member.bio:
        bio_texts.append(str(member.bio))
    if member.activities:
        for act in member.activities:
            if getattr(act, "name", None):
                bio_texts.append(str(act.name))
            if getattr(act, "state", None):
                bio_texts.append(str(act.state))
    bio_status_combined = " ".join(bio_texts) if bio_texts else None

    score, signals, model_version = scorer.score(
        account_age_days=(discord.utils.utcnow() - member.created_at).days,
        is_default_avatar=member.avatar is None,
        join_velocity=velocity,
        messages_last_minute=messages_last_minute,
        has_badges=has_badges,
        badge_count=badge_count,
        bio_or_status=bio_status_combined,
        username=member.name,
    )
    await db.insert_risk_score(member.id, guild_id, score, signals, model_version)

    # Module 25 — Smart Gatekeeper (Onboarding progressif : passage direct / sas interactif / quarantaine)
    await gatekeeper.handle_new_member_gate(
        member, score,
        db=db, append_evidence=_append_evidence,
        dashboard_module=guild_dashboard, quarantine_module=quarantine,
    )

    payload = {
        "guild_id": guild_id, "user_id": member.id, "score": score,
        "signals": signals, "velocity": velocity,
    }

    t = settings.thresholds
    payload["author_name"] = str(member)
    payload["username"] = str(member)

    if score >= t.legitimacy_score_critical:
        payload["reason"] = "score_de_legitimite_critique"
        entry = await _append_evidence(guild_id, "risk_critical", payload)
        payload["evidence_hash"] = entry["hash"]
        await bus.emit("risk_critical", payload)
    elif score >= t.legitimacy_score_suspect:
        logger.info("Compte suspect (score=%.2f) : %s sur %s", score, member, member.guild.name)
        payload["reason"] = f"Compte suspect identifié (score risque: {score:.2f})"
        entry = await _append_evidence(guild_id, "suspicious_account_detected", payload)
        payload["evidence_hash"] = entry["hash"]
        guild_cfg = await db.get_guild(guild_id)
        if guild_cfg and guild_cfg.get("auto_quarantine_enabled", False):
            await quarantine.quarantine(
                member, reason=f"Auto-quarantaine : score suspect ({score:.2f})",
                db=db, append_evidence=_append_evidence,
            )

    # Vérifie la coordination après chaque rafale de joins récents
    if velocity >= 3:
        await coordination.check_recent_joiners(
            guild_id, db, bus, _append_evidence,
            window_seconds=t.coordination_window_seconds,
            min_accounts=t.coordination_min_accounts,
            similarity_threshold=t.fingerprint_similarity_threshold,
        )

    # Module 13 — noms similaires (bots de raid avec pseudos quasi-identiques)
    recent_names = [
        m.display_name for m in member.guild.members
        if m.id != member.id
        and m.joined_at
        and (discord.utils.utcnow() - m.joined_at).total_seconds() < 90
    ]
    asyncio.create_task(similar_names_mod.check_new_member(
        member, recent_names, bus=bus, append_evidence=_append_evidence,
    ))

    # Module 16 — vérifie si ce nouveau membre ressemble à un banni
    asyncio.create_task(ban_fingerprint.check_new_member(
        guild_id, member.id, db, bus, _append_evidence,
    ))

    # Module 17 — identifie l'invitation utilisée et vérifie les ratios de raid
    asyncio.create_task(_handle_invite_audit(member))

    # Module 19 — vérifie si ce nouveau membre tente d'usurper le staff ou le bot
    asyncio.create_task(anti_impersonation.handle_impersonation(
        member, db=db, bus=bus, append_evidence=_append_evidence,
        quarantine_module=quarantine, dashboard_module=guild_dashboard,
    ))


async def _handle_invite_audit(member: discord.Member):
    """Identifie l'invitation utilisée (snapshot diff), l'enregistre, puis
    vérifie si un lien est utilisé par une proportion anormale de joiners."""
    invite = await invite_audit.detect_used_invite(member.guild, redis_client=cache.client)
    await invite_audit.record_join(member.guild.id, member.id, invite, db)
    await invite_audit.check_raid_via_invite(
        member.guild, db, bus, _append_evidence,
        dashboard_module=guild_dashboard,
        window_seconds=120,
        raid_ratio_threshold=0.70,
        min_joiners=5,
    )


@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    """Auto-labellise comme 'raid' les membres bannis, conserve leur fingerprint,
    et surveille l'audit log pour contrer les bannissements abusifs d'un modérateur piraté (Anti-Nuke)."""
    labelled = await db.auto_label_user(user.id, guild.id, "raid")
    if labelled:
        logger.info("Auto-label 'raid' après ban de %s sur %s", user, guild.name)

    # Module 16 — conserve le fingerprint du banni pour détecter un retour
    await ban_fingerprint.on_member_ban(guild.id, user.id, db)

    # Module 18 — Anti-Nuke (surveille si un modérateur bannie en rafale)
    asyncio.create_task(antinuke.check_action(
        guild, "member_ban", user.id,
        cache=cache, db=db, bus=bus, append_evidence=_append_evidence,
        lockdown_module=lockdown, dashboard_module=guild_dashboard,
    ))


@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    """Détecte les changements de pseudo et vérifie l'usurpation du staff (module 19)
    ainsi que la similarité avec d'autres membres récents (module 13)."""
    if before.display_name == after.display_name:
        return

    # Module 19 — Anti-Impersonation sur renommage
    asyncio.create_task(anti_impersonation.handle_impersonation(
        after, db=db, bus=bus, append_evidence=_append_evidence,
        quarantine_module=quarantine, dashboard_module=guild_dashboard,
    ))

    recent_names = [
        m.display_name for m in after.guild.members
        if m.id != after.id
        and m.joined_at
        and (discord.utils.utcnow() - m.joined_at).total_seconds() < 300
    ]
    matches = similar_names_mod.find_similar_names(after.display_name, recent_names, threshold=0.80)
    if matches:
        await _append_evidence(after.guild.id, "similar_names_detected", {
            "user_id": after.id,
            "username": after.display_name,
            "previous_name": before.display_name,
            "trigger": "name_change",
            "similar_to": [{"name": n, "score": s} for n, s in matches],
        })
        logger.info(
            "Changement de pseudo suspect sur %s : %s → %s (similaire à %s)",
            after.guild.name, before.display_name, after.display_name,
            [n for n, _ in matches],
        )


@bot.event
async def on_member_remove(member: discord.Member):
    """Fix #7 — Nettoie les buffers mémoire, et surveille les kicks massifs (Anti-Nuke)."""
    key = (member.id, member.guild.id)
    fingerprint._buffers.pop(key, None)
    stylometry._buffers.pop(key, None)

    # Module 18 — Anti-Nuke (vérifie si le départ est une expulsion abusive par un modérateur)
    asyncio.create_task(antinuke.check_action(
        member.guild, "member_kick", member.id,
        cache=cache, db=db, bus=bus, append_evidence=_append_evidence,
        lockdown_module=lockdown, dashboard_module=guild_dashboard,
    ))


# ── Événements Anti-Nuke (Salons, Rôles, Webhooks) ───────────────────

@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    """Module 18 — Anti-Nuke : neutralise un compte staff qui supprime des salons en rafale."""
    await antinuke.check_action(
        channel.guild, "channel_delete", channel.id,
        cache=cache, db=db, bus=bus, append_evidence=_append_evidence,
        lockdown_module=lockdown, dashboard_module=guild_dashboard,
    )


@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    """Module 18 — Anti-Nuke : neutralise un compte staff qui crée des salons en rafale (spam nuke)."""
    await antinuke.check_action(
        channel.guild, "channel_create", channel.id,
        cache=cache, db=db, bus=bus, append_evidence=_append_evidence,
        lockdown_module=lockdown, dashboard_module=guild_dashboard,
    )


@bot.event
async def on_guild_role_delete(role: discord.Role):
    """Module 18 — Anti-Nuke : neutralise un compte staff qui supprime des rôles."""
    await antinuke.check_action(
        role.guild, "role_delete", role.id,
        cache=cache, db=db, bus=bus, append_evidence=_append_evidence,
        lockdown_module=lockdown, dashboard_module=guild_dashboard,
    )


@bot.event
async def on_guild_role_create(role: discord.Role):
    """Module 18 — Anti-Nuke : neutralise un compte staff qui crée des rôles en rafale (spam nuke)."""
    await antinuke.check_action(
        role.guild, "role_create", role.id,
        cache=cache, db=db, bus=bus, append_evidence=_append_evidence,
        lockdown_module=lockdown, dashboard_module=guild_dashboard,
    )


@bot.event
async def on_webhooks_update(channel: discord.abc.GuildChannel):
    """Module 18 — Anti-Nuke : neutralise la création abusive ou non autorisée de webhooks."""
    # 1. Vérification et suppression instantanée si le webhook est non autorisé
    await antinuke.check_unauthorized_webhook(
        channel.guild, channel,
        db=db, append_evidence=_append_evidence,
        dashboard_module=guild_dashboard,
    )
    # 2. Vérification de rafale anti-nuke
    await antinuke.check_action(
        channel.guild, "webhook_create", None,
        cache=cache, db=db, bus=bus, append_evidence=_append_evidence,
        lockdown_module=lockdown, dashboard_module=guild_dashboard,
    )


# ── Événement Anti-Ghostping ──────────────────────────────────────────

@bot.event
async def on_message_delete(message: discord.Message):
    """Module 20 — Anti-Ghostping : journalise et alerte sur les messages supprimés avec mentions."""
    if not message.guild or message.author.bot:
        return
    _, log_channel_id = await db.get_guild_config(message.guild.id)
    await antighostping.handle_deleted_message(
        message, db=db, append_evidence=_append_evidence,
        dashboard_module=guild_dashboard, log_channel_id=log_channel_id,
    )


# ── Événement Surveillance d'édition de messages ─────────────────────

@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    """Analyse les messages modifiés pour bloquer les arnaques différées."""
    if after.author.bot or not after.guild:
        return
    if before.content == after.content:
        return

    # Bypass administrateurs
    if getattr(after.author, "guild_permissions", None) and after.author.guild_permissions.administrator:
        return

    # Bypass whitelist dynamique
    if hasattr(db, "is_whitelisted"):
        role_ids = [r.id for r in getattr(after.author, "roles", [])]
        if await db.is_whitelisted(after.guild.id, after.author.id, role_ids):
            return

    scam_result = await antiscam.handle_message(
        after,
        allow_invites=False,
        delete_message=True,
        warn_in_channel=True,
        bus=bus,
        append_evidence=_append_evidence,
    )
    if scam_result.is_scam:
        await guild_dashboard.send_alert(
            after.guild,
            title="⚠️ Contenu suspect détecté (Message édité)",
            description=f"<@{after.author.id}> dans <#{after.channel.id}>\n"
                        + "\n".join(f"• {r}" for r in scam_result.reasons),
            color=0xFF0000 if scam_result.score >= 0.80 else 0xFF6600,
        )


# ── Callback de fin de lockdown auto (fix #9) ────────────────────────

async def _notify_lockdown_released(guild: discord.Guild, manual: bool) -> None:
    """Envoie une alerte dashboard + DM admins quand le lockdown se lève,
    que ce soit automatiquement ou manuellement."""
    mode = "manuellement" if manual else "automatiquement (timer expiré)"
    await guild_dashboard.send_alert(
        guild,
        title="🔓 Lockdown levé",
        description=f"Le lockdown a été levé **{mode}**.",
        color=0x00CC66,
    )
    await guild_dashboard.dm_admins(
        guild,
        title="Lockdown levé",
        description=f"Le lockdown sur **{guild.name}** a été levé {mode}.",
    )


@bot.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
    """Détecte les attaques par flood d'états vocaux (tokens spammant join/leave/mute/deaf)."""
    channel = after.channel or before.channel
    if not channel or not isinstance(channel, discord.VoiceChannel):
        return

    count, is_flood = voice_antistress.velocity_tracker.record_event(channel.id)
    if is_flood:
        logger.warning("Flood d'états vocaux sur le salon %s (ID %s, %d événements/6s)", channel.name, channel.id, count)
        guild = channel.guild
        configs = await db.get_voice_antistress_configs(guild.id)
        is_protected = any(c["channel_id"] == channel.id and c["auto_renew"] for c in configs)

        if is_protected:
            try:
                new_ch, moved = await voice_antistress.renew_voice_channel(
                    channel,
                    reason=f"Attaque par saturation d'états vocaux ({count} événements en 6s)",
                    append_evidence=_append_evidence,
                    db=db,
                )
                msg = (
                    f"🚨 **BIDABOT Anti-Stresseur :** Attaque par flood détectée sur **#{channel.name}** !\n"
                    f"• {count} changements d'état vocaux en 6 secondes (spam tokens/stresseur).\n"
                    f"• 🔊 Salon recréé automatiquement : {new_ch.mention}\n"
                    f"• 👥 **{moved}** membre(s) mis à l'abri immédiatement sans coupure."
                )
                await _log_to_channel(guild.id, msg)
                await guild_dashboard.send_alert(
                    guild,
                    title="🚨 Anti-Stresseur Vocal : Attaque Flood Bloquée",
                    description=msg,
                    color=0xFF0000,
                )
            except Exception as e:
                logger.error("Erreur auto-réparation flood vocal : %s", e)


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    # 1. Bypass analyse pour les administrateurs du serveur
    if getattr(message.author, "guild_permissions", None) and message.author.guild_permissions.administrator:
        await bot.process_commands(message)
        return

    # 2. Bypass analyse pour les rôles de confiance configurés (.env)
    trusted_roles = getattr(settings, "trusted_role_ids", [])
    if trusted_roles and any(r.id in trusted_roles for r in getattr(message.author, "roles", [])):
        await bot.process_commands(message)
        return

    # 3. Bypass pour la whitelist dynamique (DB — rôles ou membres immunisés)
    if hasattr(db, "is_whitelisted"):
        role_ids = [r.id for r in getattr(message.author, "roles", [])]
        if await db.is_whitelisted(message.guild.id, message.author.id, role_ids):
            await bot.process_commands(message)
            return

    guild = message.guild

    # ── Canary (piège) — priorité maximale ───────────────────────────
    canary_ids = _canary_ids.get(guild.id, set())
    handled = await canary.handle_message(message, canary_ids, db, bus, _append_evidence)
    if handled:
        return

    # ── Paramètres dynamiques par serveur (depuis le Dashboard Web) ──
    guild_cfg = await db.get_guild(guild.id)
    anti_scam_on = guild_cfg.get("anti_scam_enabled", True) if guild_cfg else True
    anti_spam_on = guild_cfg.get("anti_spam_enabled", True) if guild_cfg else True

    # ── Module 24 — Bouclier Anti-Fichiers Malveillants & Trojans (.exe, .scr, stealers) ──
    if message.attachments or ("http://" in message.content or "https://" in message.content):
        vt_key = getattr(settings, "virustotal_api_key", None)
        malware_res = await antimalware.handle_message_attachments(
            message,
            virustotal_key=vt_key,
            cache=cache,
            db=db,
            bus=bus,
            append_evidence=_append_evidence,
            dashboard_module=guild_dashboard,
        )
        if malware_res:
            return

    # ── Anti-scam / anti-liens ────────────────────────────────────────
    if anti_scam_on:
        scam_result = await antiscam.handle_message(
            message,
            allow_invites=False,
            delete_message=True,
            warn_in_channel=True,
            bus=bus,
            append_evidence=_append_evidence,
        )
        if scam_result.is_scam:
            is_raid = any("raid" in r or "menace d'attaque" in r for r in scam_result.reasons)
            is_toxic = any("propos haineux" in r for r in scam_result.reasons)
            title = "⚡ Menace de Raid détectée" if is_raid else ("🚫 Propos haineux détectés" if is_toxic else "⚠️ Contenu suspect détecté")
            await guild_dashboard.send_alert(
                guild,
                title=title,
                description=f"<@{message.author.id}> dans <#{message.channel.id}>\n"
                            + "\n".join(f"• {r}" for r in scam_result.reasons),
                color=0xFF0033 if (is_raid or is_toxic) else (0xFF6600 if scam_result.score < 0.80 else 0xFF0000),
            )
            return
        elif scam_result.score >= 0.40:
            # Score de confiance intermédiaire : consigné dans les logs pour surveillance
            await _append_evidence(guild.id, "suspicious_message_detected", {
                "user_id": message.author.id,
                "author_name": str(message.author),
                "channel_id": message.channel.id,
                "score": scam_result.score,
                "reasons": scam_result.reasons or ["Contenu suspect ou ambigu"],
                "content_snippet": message.content[:200],
            })

    # ── Anti-spam / flood ─────────────────────────────────────────────
    if anti_spam_on:
        t = settings.thresholds
        spam_handled = await antispam.check_message(
            message,
            cache,
            max_messages=t.antispam_messages_per_window,
            window_seconds=t.antispam_window_seconds,
            delete_excess=True,
            progressive_mute=True,
            bus=bus,
            append_evidence=_append_evidence,
        )
        if spam_handled:
            await guild_dashboard.send_alert(
                guild,
                title="🔇 Spam détecté",
                description=f"<@{message.author.id}> dans <#{message.channel.id}> — message supprimé.",
                color=0xFFAA00,
            )
            return

    # ── Fingerprint + stylométrie + burst (messages normaux) ──────────
    ts = message.created_at.timestamp()
    await fingerprint.record_message(db, message.author.id, guild.id, message.content, ts)
    await stylometry.record_message(db, message.author.id, guild.id, message.content)

    # Fix #8 : incrémente la fenêtre burst pour que le signal soit disponible
    # lors du prochain score (join d'un autre compte, ou re-score manuel).
    await cache.message_burst_count(message.author.id, guild.id, window_seconds=60)

    await bot.process_commands(message)


def run():
    if settings.discord_token in ("", "COLLE_TON_TOKEN_ICI"):
        raise SystemExit("❌ DISCORD_TOKEN manquant — configure ton .env (voir .env.example).")
    bot.run(settings.discord_token, log_handler=None)


if __name__ == "__main__":
    run()
