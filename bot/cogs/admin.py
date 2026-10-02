"""
Commandes slash d'administration de BIDABOT.

/bidabot setup              — configuration initiale (à lancer une fois)
/bidabot status             — vue d'ensemble
/bidabot verify             — vérifie l'intégrité de la chaîne forensique
/bidabot report             — génère et envoie le PDF forensique signé
/bidabot dry-run <on|off>   — bascule le mode simulation (garde-fou légal)
/bidabot lockdown <on|off>  — lockdown manuel / override humain immédiat
/bidabot canary setup       — (re)crée les canaux pièges
/bidabot canary link        — génère un lien honeytoken pour un canary
/bidabot similar <user>     — comptes comportementalement/stylométriquement proches
/bidabot label <user> <raid|legit> — feedback pour le ré-entraînement ML
/bidabot train              — réentraîne le modèle scikit-learn sur les labels
/bidabot federation check <user>   — interroge les signalements fédérés (fix #11)
"""
from __future__ import annotations

import io
import logging

import discord
from discord import app_commands
from discord.ext import commands

from bot.config import settings
from bot.crypto_utils import hash_federation_id, load_or_create_signing_key
from bot.modules import canary as canary_module
from bot.modules import forensics, lockdown, warroom
from bot.modules import quarantine as quarantine_module
from bot.modules import trust_score as trust_score_module
from bot.modules import guild_dashboard as guild_dashboard_module
from bot.modules import antiscam, antimalware
from bot.modules.federation_client import FederationClient

logger = logging.getLogger("bidabot.admin")


class BidabotAdmin(commands.Cog):
    def __init__(self, bot, db, cache, bus, scorer, append_evidence,
                 canary_ids: dict[int, set[int]]):
        self.bot = bot
        self.db = db
        self.cache = cache
        self.bus = bus
        self.scorer = scorer
        self.append_evidence = append_evidence
        # Fix #6 : référence au dict mutable de main.py — les mises à jour
        # faites ici (canary setup) sont immédiatement visibles dans on_message.
        self._canary_ids = canary_ids

        # Menu contextuel : Clic droit sur un message -> Apps -> 🛡️ Signaler à Bidabot
        self.report_menu = app_commands.ContextMenu(
            name="🛡️ Signaler à Bidabot",
            callback=self.report_threat_context_menu,
        )
        self.bot.tree.add_command(self.report_menu)

    async def cog_unload(self):
        try:
            self.bot.tree.remove_command(self.report_menu.name, type=self.report_menu.type)
        except Exception:
            pass

    async def report_threat_context_menu(self, interaction: discord.Interaction, message: discord.Message):
        """Menu contextuel déclenché via clic droit sur un message -> Apps -> 🛡️ Signaler à Sentinel."""
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        if not guild:
            await interaction.followup.send("❌ Cette action ne peut être exécutée que sur un serveur.", ephemeral=True)
            return

        # 1. Analyse textuelle anti-scam
        scam_res = antiscam.analyze(message.content) if message.content else None

        # 2. Analyse pièces jointes anti-malware
        malware_found = False
        malware_reasons = []
        if message.attachments:
            for att in message.attachments:
                is_dang, reason = antimalware.is_dangerous_filename(att.filename)
                if is_dang:
                    malware_found = True
                    malware_reasons.append(f"{att.filename} : {reason}")

        # 3. Calcul du diagnostic
        is_threat = (scam_res and scam_res.is_scam) or malware_found
        score = scam_res.score if scam_res else (0.85 if malware_found else 0.10)

        payload = {
            "guild_id": guild.id,
            "reporter_id": interaction.user.id,
            "author_id": message.author.id,
            "channel_id": message.channel.id,
            "message_id": message.id,
            "content": message.content[:500] if message.content else "*(vide ou médias)*",
            "attachments": [a.filename for a in message.attachments],
            "scam_detected": bool(scam_res and scam_res.is_scam),
            "malware_detected": malware_found,
            "reasons": (scam_res.reasons if scam_res else []) + malware_reasons,
        }

        # 4. Enregistrement dans la chaîne de preuves forensiques
        entry = await self.append_evidence(guild.id, "user_reported_threat", payload)
        payload["evidence_hash"] = entry.get("hash")

        # 5. Envoi d'une alerte immédiate avec boutons interactifs dans #sentinel-alerts
        fields = {
            "Auteur du message": f"<@{message.author.id}> (`{message.author}`)",
            "Signalé par": f"<@{interaction.user.id}> (`{interaction.user}`)",
            "Salon": f"<#{message.channel.id}>",
            "Lien du message": f"[Aller au message]({message.jump_url})",
            "Contenu": f"```{message.content[:300].replace('```', '')}```" if message.content else "*(Médias ou vide)*",
            "Diagnostic BIDABOT": (
                f"🚨 **Menace confirmée** (Score: `{score:.2f}`)" if is_threat
                else f"ℹ️ Analyse automatique : Aucun pattern évident détecté (Score: `{score:.2f}`) — Révision staff requise"
            ),
        }
        if payload["reasons"]:
            fields["Motifs détectés"] = "\n".join([f"• {r}" for r in payload["reasons"][:5]])

        await guild_dashboard_module.send_alert(
            guild,
            title="🛡️ Signalement Communautaire — Menace Suspectée",
            description=f"Un membre a signalé un message potentiellement dangereux dans <#{message.channel.id}>.",
            color=0xFF0000 if is_threat else 0xFFAA00,
            fields=fields,
            target_user_id=message.author.id,
            score_data={"score": score, "signals": {"scam_score": score}, "reason": "Signalement utilisateur"},
            db=self.db,
            append_evidence=self.append_evidence,
            quarantine_module=quarantine_module,
        )

        # 6. Réponse éphémère au signalant
        if is_threat:
            reply_msg = (
                "🛡️ **Signalement reçu et menace confirmée !**\n\n"
                f"Nos algorithmes ont immédiatement identifié ce contenu comme suspect (`score: {score:.2f}`).\n"
                "Le message et son auteur ont été transmis aux modérateurs avec les preuves forensiques scellées."
            )
        else:
            reply_msg = (
                "🛡️ **Signalement bien reçu.**\n\n"
                "Le message a été archivé et transmis à l'équipe de modération dans le fil d'alertes sécurisé pour examen."
            )
        await interaction.followup.send(reply_msg, ephemeral=True)

    group = app_commands.Group(name="bidabot", description="Commandes BIDABOT")

    def _admin_only(self, interaction: discord.Interaction) -> bool:
        return interaction.user.guild_permissions.administrator

    @group.command(name="setup", description="Configuration complète de TOUS les salons et rôles BIDABOT (à lancer une fois)")
    @app_commands.describe(
        role="Rôle modérateur/staff principal (invisible pour les autres)",
        role2="Deuxième rôle staff autorisé (optionnel)",
        role3="Troisième rôle staff autorisé (optionnel)",
        log_channel="Salon de journal d'activité existant (optionnel — sinon créé dans sentinel-admin)",
    )
    async def setup_cmd(self, interaction: discord.Interaction,
                        role: discord.Role | None = None,
                        role2: discord.Role | None = None,
                        role3: discord.Role | None = None,
                        log_channel: discord.TextChannel | None = None):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild

        await self.db.ensure_guild(guild.id, guild.name)
        roles_list = [r for r in (role, role2, role3) if r is not None]
        if roles_list and hasattr(self.db, "set_staff_role"):
            await self.db.set_staff_role(guild.id, roles_list[0].id)

        # 1. Catégorie sentinel-admin + #sentinel-status + #sentinel-alerts
        status_ch, alerts_ch = await guild_dashboard_module.setup_dashboard(guild, self.db, staff_role=roles_list)

        # 2. Catégorie sentinel-admin -> #sentinel-quarantine + rôle @sentinel-quarantine
        q_role, q_ch = await quarantine_module.setup_quarantine(guild, self.db, staff_role=roles_list)

        # 3. Catégorie sentinel-warrooms + salon War Room initial
        war_cat = await warroom.get_or_create_warroom_category(guild, self.db, staff_role=roles_list)
        initial_warroom_ch = None
        if war_cat:
            from bot.modules import lockdown as ld_mod, forensics as fr_mod
            from bot.crypto_utils import load_or_create_signing_key
            init_payload = {
                "guild_id": guild.id,
                "user_id": interaction.user.id,
                "reason": "Initialisation du système BIDABOT",
                "score": 0.0,
                "signals": {"status": "pret", "admin": interaction.user.name},
            }
            signing_key = load_or_create_signing_key(settings.signing_key_path)
            initial_warroom_ch = await warroom.open_warroom(
                init_payload,
                bot=self.bot,
                db=self.db,
                cache=self.cache,
                bus=self.bus,
                append_evidence=self.append_evidence,
                lockdown_module=ld_mod,
                forensics_module=fr_mod,
                signing_key=signing_key,
                dry_run=await self.db.get_dry_run(guild.id),
                auto_release_seconds=settings.thresholds.lockdown_auto_release_seconds,
            )

        # 4. Catégorie sentinel-canary + canary-1..3
        canary_ids = await canary_module.setup_canaries(guild, self.db, staff_role=roles_list)
        self._canary_ids[guild.id] = canary_ids

        # 5. Salon de logs (existant ou créé dans sentinel-admin)
        final_log_ch = None
        if log_channel:
            try:
                await log_channel.set_permissions(guild.default_role, view_channel=False)
                for r in roles_list:
                    await log_channel.set_permissions(r, view_channel=True, read_message_history=True, send_messages=False)
                if guild.me:
                    await log_channel.set_permissions(guild.me, view_channel=True, send_messages=True, embed_links=True)
            except (discord.Forbidden, discord.HTTPException):
                pass
            await self.db.set_log_channel(guild.id, log_channel.id)
            final_log_ch = log_channel
        else:
            admin_cat = discord.utils.get(guild.categories, name="bidabot-admin") or discord.utils.get(guild.categories, name="sentinel-admin")
            final_log_ch = discord.utils.get(guild.text_channels, name="bidabot-logs", category=admin_cat) or discord.utils.get(guild.text_channels, name="sentinel-logs", category=admin_cat)
            if not final_log_ch and admin_cat:
                ow = {guild.default_role: discord.PermissionOverwrite(view_channel=False)}
                if guild.me:
                    ow[guild.me] = discord.PermissionOverwrite(view_channel=True, send_messages=True, embed_links=True)
                for r in roles_list:
                    ow[r] = discord.PermissionOverwrite(view_channel=True, read_message_history=True, send_messages=False)
                try:
                    final_log_ch = await guild.create_text_channel(
                        "bidabot-logs", category=admin_cat, overwrites=ow,
                        topic="📜 Journal d'activité BIDABOT.",
                        reason="BIDABOT — salon logs (setup complet)",
                    )
                except (discord.Forbidden, discord.HTTPException):
                    pass
            elif final_log_ch:
                for r in roles_list:
                    try:
                        await final_log_ch.set_permissions(r, view_channel=True, read_message_history=True, send_messages=False)
                    except (discord.Forbidden, discord.HTTPException):
                        pass
            if final_log_ch:
                await self.db.set_log_channel(guild.id, final_log_ch.id)

        # Initialise / rafraîchit l'embed dans #sentinel-status
        try:
            await guild_dashboard_module.update_status(guild, self.db, lockdown, self.scorer)
        except Exception as e:
            logger.warning("Échec mise à jour embed statut initial : %s", e)

        if roles_list:
            role_str = "🛡️ **Rôles staff autorisés :** " + ", ".join(r.mention for r in roles_list)
        else:
            role_str = "🛡️ **Rôle staff :** Administrateurs uniquement (aucun rôle spécifié)"

        lines = [
            f"📊 **Tableau de bord :** {status_ch.mention if status_ch else '⚠️ Erreur'} & {alerts_ch.mention if alerts_ch else '⚠️ Erreur'} (`sentinel-admin`)",
            f"🔒 **Quarantaine :** {q_ch.mention if q_ch else '⚠️ Erreur'} (Rôle @{q_role.name if q_role else 'sentinel-quarantine'})",
            f"🚨 **War Room de crise :** {initial_warroom_ch.mention if initial_warroom_ch else war_cat.name if war_cat else '⚠️ Erreur'} (`sentinel-warrooms`)",
            f"🪤 **Canaux pièges :** {len(canary_ids)} canaux pièges actifs (`sentinel-canary`)",
            f"📜 **Journal d'activité :** {final_log_ch.mention if final_log_ch else 'Non configuré'}",
            "",
            role_str,
            "👁️ **Visibilité :** **Totalement invisible pour @everyone** (les membres normaux ne voient aucun de ces salons).",
            "🟡 Mode dry-run actif par défaut — fais `/bidabot dry-run off` pour armer les sanctions réelles.",
        ]
        await interaction.followup.send("**🛡️ Configuration Complète BIDABOT terminée :**\n\n" + "\n".join(lines), ephemeral=True)

    channel_group = app_commands.Group(name="channel", parent=group, description="Configuration individuelle des salons Bidabot")

    @channel_group.command(name="dashboard", description="Crée/configure les salons #sentinel-status et #sentinel-alerts")
    @app_commands.describe(
        role="Rôle modérateur/staff principal (lecture seule)",
        role2="Deuxième rôle staff autorisé (optionnel)",
        role3="Troisième rôle staff autorisé (optionnel)",
    )
    async def channel_dashboard(self, interaction: discord.Interaction,
                                role: discord.Role | None = None,
                                role2: discord.Role | None = None,
                                role3: discord.Role | None = None):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        await self.db.ensure_guild(guild.id, guild.name)
        roles_list = [r for r in (role, role2, role3) if r is not None]

        status_ch, alerts_ch = await guild_dashboard_module.setup_dashboard(guild, self.db, staff_role=roles_list)
        if not status_ch or not alerts_ch:
            return await interaction.followup.send("❌ Impossible de créer les salons (vérifie les permissions 'Gérer les salons' du bot).", ephemeral=True)

        try:
            await guild_dashboard_module.update_status(guild, self.db, lockdown, self.scorer)
        except Exception:
            pass

        role_desc = ", ".join(r.mention for r in roles_list) if roles_list else "réservé aux Administrateurs"
        await interaction.followup.send(
            f"✅ **Dashboard configuré avec succès !**\n"
            f"• 📊 Statut live : {status_ch.mention}\n"
            f"• 🚨 Alertes live : {alerts_ch.mention}\n"
            f"• 👁️ **Invisible pour @everyone**, accessible à : {role_desc} (en lecture seule).",
            ephemeral=True,
        )

    @channel_group.command(name="quarantine", description="Crée/configure le salon #sentinel-quarantine et le rôle d'isolation")
    @app_commands.describe(
        role="Rôle modérateur/staff principal pour gérer les cas suspects",
        role2="Deuxième rôle staff autorisé (optionnel)",
        role3="Troisième rôle staff autorisé (optionnel)",
    )
    async def channel_quarantine(self, interaction: discord.Interaction,
                                 role: discord.Role | None = None,
                                 role2: discord.Role | None = None,
                                 role3: discord.Role | None = None):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        await self.db.ensure_guild(guild.id, guild.name)
        roles_list = [r for r in (role, role2, role3) if r is not None]

        q_role, q_ch = await quarantine_module.setup_quarantine(guild, self.db, staff_role=roles_list)
        if not q_role or not q_ch:
            return await interaction.followup.send("❌ Impossible de créer le système de quarantaine (vérifie les permissions du bot).", ephemeral=True)

        role_desc = ", ".join(r.mention for r in roles_list) if roles_list else "réservé aux Administrateurs"
        await interaction.followup.send(
            f"✅ **Système de quarantaine configuré avec succès !**\n"
            f"• 🔒 Salon d'isolement : {q_ch.mention}\n"
            f"• 🏷️ Rôle d'isolement : {q_role.mention}\n"
            f"• 👁️ **Invisible pour @everyone**, accessible à : {role_desc} et au membre suspect placé en quarantaine.\n"
            f"• 🛡️ Les autres salons du serveur sont automatiquement verrouillés pour le rôle de quarantaine.",
            ephemeral=True,
        )

    @channel_group.command(name="warroom", description="Configure la catégorie ou ouvre une War Room d'urgence")
    @app_commands.describe(
        role="Rôle modérateur/staff principal pour les war rooms d'urgence",
        role2="Deuxième rôle staff autorisé (optionnel)",
        role3="Troisième rôle staff autorisé (optionnel)",
        open_test="Ouvrir immédiatement un salon War Room de test (True/False)",
    )
    async def channel_warroom(self, interaction: discord.Interaction,
                               role: discord.Role | None = None,
                               role2: discord.Role | None = None,
                               role3: discord.Role | None = None,
                               open_test: bool = True):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        await self.db.ensure_guild(guild.id, guild.name)
        roles_list = [r for r in (role, role2, role3) if r is not None]

        cat = await warroom.get_or_create_warroom_category(guild, self.db, staff_role=roles_list)
        if not cat:
            return await interaction.followup.send("❌ Impossible de créer la catégorie war room (permissions `Manage Channels` manquantes).", ephemeral=True)

        role_desc = ", ".join(r.mention for r in roles_list) if roles_list else "réservée aux Administrateurs"
        cat_mention = cat.mention if hasattr(cat, "mention") else f"`{cat.name}`"

        war_ch_msg = ""
        if open_test:
            from bot.modules import lockdown, forensics
            from bot.crypto_utils import load_or_create_signing_key
            test_payload = {
                "guild_id": guild.id,
                "user_id": interaction.user.id,
                "reason": "Test de configuration de War Room",
                "score": 0.99,
                "signals": {"test": True, "lance_par": interaction.user.name},
            }
            signing_key = load_or_create_signing_key(settings.signing_key_path)
            war_ch = await warroom.open_warroom(
                test_payload,
                bot=self.bot,
                db=self.db,
                cache=self.cache,
                bus=self.bus,
                append_evidence=self.append_evidence,
                lockdown_module=lockdown,
                forensics_module=forensics,
                signing_key=signing_key,
                dry_run=await self.db.get_dry_run(guild.id),
                auto_release_seconds=settings.thresholds.lockdown_auto_release_seconds,
            )
            if war_ch:
                war_ch_msg = f"\n\n🚨 **Salon War Room de test ouvert avec succès :** {war_ch.mention}\n*(Tu peux le tester avec ses boutons interactifs, puis le fermer en cliquant sur 'Clôturer')*"

        await interaction.followup.send(
            f"✅ **Catégorie War Room configurée avec succès !**\n"
            f"• 🚨 Catégorie : {cat_mention}\n"
            f"• 👁️ **Totalement invisible pour @everyone**, accessible à : {role_desc}.\n"
            f"• Lors d'une alerte critique ou d'un raid, les salons de crise y seront automatiquement créés.{war_ch_msg}",
            ephemeral=True,
        )

    @channel_group.command(name="canary", description="Crée/configure les 3 canaux pièges invisibles (canary-1..3)")
    @app_commands.describe(
        role="Rôle staff autorisé à voir les pièges (optionnel — par défaut invisible pour tous)",
        role2="Deuxième rôle staff autorisé (optionnel)",
    )
    async def channel_canary(self, interaction: discord.Interaction,
                             role: discord.Role | None = None,
                             role2: discord.Role | None = None):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        await self.db.ensure_guild(guild.id, guild.name)
        roles_list = [r for r in (role, role2) if r is not None]

        ids = await canary_module.setup_canaries(guild, self.db, staff_role=roles_list)
        self._canary_ids[guild.id] = ids

        role_desc = ", ".join(r.mention for r in roles_list) if roles_list else "invisible pour TOUT LE MONDE"
        await interaction.followup.send(
            f"✅ **Canaux pièges configurés avec succès !**\n"
            f"• 🪤 {len(ids)} canaux pièges créés dans la catégorie `sentinel-canary`.\n"
            f"• 👁️ **Totalement invisible pour @everyone**, visible pour : {role_desc}.\n"
            f"• Tout intrus ou bot qui accède à un canal piège déclenche une alerte critique immédiate.",
            ephemeral=True,
        )

    @channel_group.command(name="logs", description="Configure le salon de logs d'activité SENTINEL")
    @app_commands.describe(
        role="Rôle modérateur/staff qui aura accès aux logs",
        role2="Deuxième rôle staff autorisé (optionnel)",
        channel="Salon existant à utiliser (si omis, #sentinel-logs sera créé dans sentinel-admin)",
    )
    async def channel_logs(self, interaction: discord.Interaction,
                           role: discord.Role | None = None,
                           role2: discord.Role | None = None,
                           channel: discord.TextChannel | None = None):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        await self.db.ensure_guild(guild.id, guild.name)
        roles_list = [r for r in (role, role2) if r is not None]

        if channel:
            target_ch = channel
            try:
                await target_ch.set_permissions(guild.default_role, view_channel=False)
                for r in roles_list:
                    await target_ch.set_permissions(r, view_channel=True, read_message_history=True, send_messages=False)
                if guild.me:
                    await target_ch.set_permissions(guild.me, view_channel=True, send_messages=True, embed_links=True)
            except (discord.Forbidden, discord.HTTPException):
                pass
        else:
            cat = discord.utils.get(guild.categories, name="bidabot-admin") or discord.utils.get(guild.categories, name="sentinel-admin")
            if not cat:
                cat = await guild.create_category("bidabot-admin", overwrites={guild.default_role: discord.PermissionOverwrite(view_channel=False)})
            target_ch = discord.utils.get(guild.text_channels, name="bidabot-logs", category=cat) or discord.utils.get(guild.text_channels, name="sentinel-logs", category=cat)
            if not target_ch:
                ow = {guild.default_role: discord.PermissionOverwrite(view_channel=False)}
                if guild.me:
                    ow[guild.me] = discord.PermissionOverwrite(view_channel=True, send_messages=True, embed_links=True)
                for r in roles_list:
                    ow[r] = discord.PermissionOverwrite(view_channel=True, read_message_history=True, send_messages=False)
                try:
                    target_ch = await guild.create_text_channel(
                        "bidabot-logs", category=cat, overwrites=ow,
                        topic="📜 Journal d'activité BIDABOT.",
                        reason="BIDABOT — salon logs",
                    )
                except (discord.Forbidden, discord.HTTPException):
                    pass
            else:
                try:
                    await target_ch.set_permissions(guild.default_role, view_channel=False)
                    for r in roles_list:
                        await target_ch.set_permissions(r, view_channel=True, read_message_history=True, send_messages=False)
                except (discord.Forbidden, discord.HTTPException):
                    pass

        if not target_ch:
            return await interaction.followup.send("❌ Impossible de configurer le salon de logs.", ephemeral=True)

        await self.db.set_log_channel(guild.id, target_ch.id)
        role_desc = ", ".join(r.mention for r in roles_list) if roles_list else "réservé aux Administrateurs"
        await interaction.followup.send(
            f"✅ **Journal d'activité BIDABOT configuré !**\n"
            f"• 📜 Salon : {target_ch.mention}\n"
            f"• 👁️ **Invisible pour @everyone**, accessible à : {role_desc}.",
            ephemeral=True,
        )

    @channel_group.command(name="add_role", description="Donne accès à un rôle supplémentaire sur les salons Sentinel")
    @app_commands.describe(
        role="Rôle à autoriser",
        target="Cible des salons à débloquer pour ce rôle",
    )
    @app_commands.choices(target=[
        app_commands.Choice(name="Tous les salons Sentinel (recommandé)", value="all"),
        app_commands.Choice(name="Dashboard (#sentinel-status et #sentinel-alerts)", value="dashboard"),
        app_commands.Choice(name="Quarantaine (#sentinel-quarantine)", value="quarantine"),
        app_commands.Choice(name="War Rooms (sentinel-warrooms)", value="warroom"),
        app_commands.Choice(name="Canaries (canary-1..3)", value="canary"),
        app_commands.Choice(name="Logs (#sentinel-logs)", value="logs"),
    ])
    async def channel_add_role(self, interaction: discord.Interaction, role: discord.Role, target: app_commands.Choice[str]):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        updated = []

        if target.value in ("all", "dashboard"):
            cat = discord.utils.get(guild.categories, name="bidabot-admin") or discord.utils.get(guild.categories, name="sentinel-admin")
            if cat:
                try:
                    await cat.set_permissions(role, view_channel=True, read_message_history=True)
                except (discord.Forbidden, discord.HTTPException):
                    pass
            for name in ("bidabot-status", "bidabot-alerts", "sentinel-status", "sentinel-alerts"):
                ch = discord.utils.get(guild.text_channels, name=name)
                if ch:
                    try:
                        await ch.set_permissions(role, view_channel=True, read_message_history=True, send_messages=False)
                        updated.append(ch.mention)
                    except (discord.Forbidden, discord.HTTPException):
                        pass

        if target.value in ("all", "quarantine"):
            ch = discord.utils.get(guild.text_channels, name="bidabot-quarantine") or discord.utils.get(guild.text_channels, name="sentinel-quarantine")
            if ch:
                try:
                    await ch.set_permissions(role, view_channel=True, send_messages=True, manage_messages=True, read_message_history=True)
                    updated.append(ch.mention)
                except (discord.Forbidden, discord.HTTPException):
                    pass

        if target.value in ("all", "warroom"):
            cat = discord.utils.get(guild.categories, name="bidabot-warrooms") or discord.utils.get(guild.categories, name="sentinel-warrooms")
            if cat:
                try:
                    await cat.set_permissions(role, view_channel=True, send_messages=True, manage_messages=True, read_message_history=True)
                    updated.append(cat.mention if hasattr(cat, "mention") else cat.name)
                except (discord.Forbidden, discord.HTTPException):
                    pass

        if target.value in ("all", "canary"):
            cat = discord.utils.get(guild.categories, name="bidabot-canary") or discord.utils.get(guild.categories, name="sentinel-canary")
            if cat:
                try:
                    await cat.set_permissions(role, view_channel=True, send_messages=False, read_message_history=True)
                except (discord.Forbidden, discord.HTTPException):
                    pass
            for ch in guild.text_channels:
                if "canary" in ch.name:
                    try:
                        await ch.set_permissions(role, view_channel=True, send_messages=False, read_message_history=True)
                        updated.append(ch.mention)
                    except (discord.Forbidden, discord.HTTPException):
                        pass

        if target.value in ("all", "logs"):
            _, log_id = await self.db.get_guild_config(guild.id)
            ch = guild.get_channel(log_id) if log_id else (discord.utils.get(guild.text_channels, name="bidabot-logs") or discord.utils.get(guild.text_channels, name="sentinel-logs"))
            if ch and isinstance(ch, discord.TextChannel):
                try:
                    await ch.set_permissions(role, view_channel=True, read_message_history=True, send_messages=False)
                    updated.append(ch.mention)
                except (discord.Forbidden, discord.HTTPException):
                    pass

        await interaction.followup.send(
            f"✅ **Rôle {role.mention} autorisé avec succès !**\n"
            f"• Salons mis à jour ({len(updated)}) : {', '.join(updated) if updated else 'aucun'}\n"
            f"• Reste invisible pour @everyone.",
            ephemeral=True,
        )

    @group.command(name="set_role", description="Attribue un ou plusieurs rôles staff à TOUS les salons Sentinel et masque tout à @everyone")
    @app_commands.describe(
        role="Rôle staff principal à autoriser",
        role2="Deuxième rôle staff autorisé (optionnel)",
        role3="Troisième rôle staff autorisé (optionnel)",
    )
    async def set_role_cmd(self, interaction: discord.Interaction,
                           role: discord.Role,
                           role2: discord.Role | None = None,
                           role3: discord.Role | None = None):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        await self.db.ensure_guild(guild.id, guild.name)
        roles_list = [r for r in (role, role2, role3) if r is not None]
        if hasattr(self.db, "set_staff_role"):
            await self.db.set_staff_role(guild.id, roles_list[0].id)

        updated_channels = []
        sentinel_category_names = {"bidabot-admin", "bidabot-warrooms", "bidabot-canary", "sentinel-admin", "sentinel-warrooms", "sentinel-canary"}

        for cat in guild.categories:
            if cat.name in sentinel_category_names:
                try:
                    await cat.set_permissions(guild.default_role, view_channel=False)
                    for r in roles_list:
                        await cat.set_permissions(r, view_channel=True, read_message_history=True)
                    if guild.me:
                        await cat.set_permissions(guild.me, view_channel=True, send_messages=True, manage_channels=True, manage_messages=True)
                except (discord.Forbidden, discord.HTTPException):
                    pass

                for ch in cat.text_channels:
                    try:
                        await ch.set_permissions(guild.default_role, view_channel=False)
                        for r in roles_list:
                            if ch.name in {"sentinel-status", "sentinel-alerts", "sentinel-logs"}:
                                await ch.set_permissions(r, view_channel=True, read_message_history=True, send_messages=False)
                            elif ch.name == "sentinel-quarantine" or "warroom" in ch.name:
                                await ch.set_permissions(r, view_channel=True, read_message_history=True, send_messages=True, manage_messages=True)
                            elif "canary" in ch.name:
                                await ch.set_permissions(r, view_channel=True, read_message_history=True, send_messages=False)
                        if guild.me:
                            await ch.set_permissions(guild.me, view_channel=True, send_messages=True, embed_links=True, manage_messages=True)
                        updated_channels.append(ch.mention)
                    except (discord.Forbidden, discord.HTTPException):
                        pass

        # Vérifie aussi le salon de logs configuré
        _, log_ch_id = await self.db.get_guild_config(guild.id)
        if log_ch_id:
            ext_ch = guild.get_channel(log_ch_id)
            if ext_ch and isinstance(ext_ch, discord.TextChannel) and ext_ch.mention not in updated_channels:
                try:
                    await ext_ch.set_permissions(guild.default_role, view_channel=False)
                    for r in roles_list:
                        await ext_ch.set_permissions(r, view_channel=True, read_message_history=True, send_messages=False)
                    updated_channels.append(ext_ch.mention)
                except (discord.Forbidden, discord.HTTPException):
                    pass

        channels_text = ", ".join(updated_channels) if updated_channels else "aucun salon existant"
        roles_text = ", ".join(r.mention for r in roles_list)
        await interaction.followup.send(
            f"✅ **Permissions mises à jour pour {roles_text} !**\n\n"
            f"• 🔒 **Salons configurés ({len(updated_channels)}) :** {channels_text}\n"
            f"• 👁️ **Visibilité :** Totalement masqués pour `@everyone`.\n"
            f"• 🛡️ Les rôles ont maintenant les accès appropriés.",
            ephemeral=True,
        )

    # ── Whitelist dynamique (rôles et membres immunisés) ───────────────

    whitelist_group = app_commands.Group(name="whitelist", parent=group, description="Gestion de la liste blanche (exemptions de sanctions)")

    @whitelist_group.command(name="add_role", description="Immunise un rôle contre les sanctions (anti-spam, scam, lockdown, etc.)")
    @app_commands.describe(role="Rôle à immuniser")
    async def whitelist_add_role(self, interaction: discord.Interaction, role: discord.Role):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)
        await self.db.add_whitelist(interaction.guild_id, role.id, "role")
        await interaction.response.send_message(
            f"✅ Rôle {role.mention} ajouté à la **whitelist**. Tous les membres ayant ce rôle sont immunisés contre l'anti-spam, l'anti-scam et les sanctions automatiques.",
            ephemeral=True,
        )

    @whitelist_group.command(name="add_user", description="Immunise un membre ou bot spécifique contre les sanctions")
    @app_commands.describe(member="Membre ou bot à immuniser")
    async def whitelist_add_user(self, interaction: discord.Interaction, member: discord.Member):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)
        await self.db.add_whitelist(interaction.guild_id, member.id, "user")
        await interaction.response.send_message(
            f"✅ Membre {member.mention} ajouté à la **whitelist**.", ephemeral=True,
        )

    @whitelist_group.command(name="remove", description="Retire un rôle ou un membre de la liste blanche")
    @app_commands.describe(role="Rôle à retirer de la whitelist", member="Membre à retirer de la whitelist")
    async def whitelist_remove(self, interaction: discord.Interaction,
                               role: discord.Role | None = None,
                               member: discord.Member | None = None):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)
        target = role or member
        if not target:
            return await interaction.response.send_message("❌ Spécifie un rôle ou un membre à retirer.", ephemeral=True)
        ok = await self.db.remove_whitelist(interaction.guild_id, target.id)
        if ok:
            await interaction.response.send_message(f"✅ {target.mention} retiré de la whitelist.", ephemeral=True)
        else:
            await interaction.response.send_message(f"⚠️ {target.mention} n'était pas présent dans la whitelist.", ephemeral=True)

    @whitelist_group.command(name="list", description="Affiche la liste des rôles et membres immunisés")
    async def whitelist_list(self, interaction: discord.Interaction):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)
        rows = await self.db.get_whitelist(interaction.guild_id)
        embed = discord.Embed(title="🛡️ Liste Blanche BIDABOT", color=0x00CC66)
        roles = []
        users = []
        for r in rows:
            if r["target_type"] == "role":
                role = interaction.guild.get_role(r["target_id"])
                roles.append(role.mention if role else f"<@&{r['target_id']}>")
            else:
                user = interaction.guild.get_member(r["target_id"])
                users.append(user.mention if user else f"<@{r['target_id']}>")

        embed.add_field(name="🏷️ Rôles immunisés", value=", ".join(roles) if roles else "Aucun (ajoute avec `/bidabot whitelist add_role`)", inline=False)
        embed.add_field(name="👤 Membres immunisés", value=", ".join(users) if users else "Aucun (ajoute avec `/bidabot whitelist add_user`)", inline=False)
        embed.set_footer(text="Note : Les administrateurs du serveur sont également immunisés par défaut.")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @group.command(name="status", description="Vue d'ensemble de SENTINEL sur ce serveur")
    async def status(self, interaction: discord.Interaction):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        guild_id = interaction.guild_id
        dry_run = await self.db.get_dry_run(guild_id)
        lockdown_active = await self.db.is_lockdown_active(guild_id)
        warrooms = await self.db.active_warroom_count(guild_id)
        chain_ok, chain_len = await forensics.verify_chain(self.db, guild_id)

        embed = discord.Embed(title="🛡️ BIDABOT — Statut", color=0x5865F2)
        embed.add_field(name="Mode dry-run", value="🟡 Actif (aucune action réelle)" if dry_run else "🔴 Désactivé (actions réelles)")
        embed.add_field(name="Lockdown actif", value="🔒 Oui" if lockdown_active else "🔓 Non")
        embed.add_field(name="War rooms ouvertes", value=str(warrooms))
        embed.add_field(name="Chaîne forensique", value=f"{'✅' if chain_ok else '❌ CORROMPUE'} ({chain_len} entrées)")
        embed.add_field(name="Modèle de légitimité", value=self.scorer.model_version)
        await interaction.response.send_message(embed=embed)

    @group.command(name="verify", description="Vérifie l'intégrité de la chaîne de preuves forensiques")
    async def verify(self, interaction: discord.Interaction):
        ok, count = await forensics.verify_chain(self.db, interaction.guild_id)
        msg = f"{'✅ Chaîne intègre' if ok else '❌ CHAÎNE CORROMPUE — investiguer immédiatement'} ({count} entrées vérifiées)."
        await interaction.response.send_message(msg)

    @group.command(name="report", description="Génère le rapport forensique PDF signé")
    async def report(self, interaction: discord.Interaction):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer()
        rows = await self.db.fetch_evidence_chain(interaction.guild_id)
        chain_ok, _ = await forensics.verify_chain(self.db, interaction.guild_id)
        signing_key = load_or_create_signing_key(settings.signing_key_path)

        pdf_bytes = forensics.build_pdf_report(
            interaction.guild.name, interaction.guild_id,
            [dict(r) for r in rows], chain_ok, signing_key,
        )
        file = discord.File(io.BytesIO(pdf_bytes), filename=f"bidabot_rapport_{interaction.guild_id}.pdf")
        await interaction.followup.send("📄 Rapport forensique signé :", file=file)

    @group.command(name="dry-run", description="Active/désactive le mode simulation (aucune action réelle)")
    @app_commands.describe(mode="on = simulation seulement, off = actions réelles")
    @app_commands.choices(mode=[app_commands.Choice(name="on", value="on"), app_commands.Choice(name="off", value="off")])
    async def dry_run(self, interaction: discord.Interaction, mode: app_commands.Choice[str]):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await self.db.set_dry_run(interaction.guild_id, mode.value == "on")
        await self.append_evidence(interaction.guild_id, "dry_run_changed", {"by": interaction.user.id, "mode": mode.value})
        await interaction.response.send_message(
            f"{'🟡 Mode dry-run activé' if mode.value == 'on' else '🔴 Mode dry-run désactivé — le lockdown appliquera de vraies permissions'}."
        )

    @group.command(name="lockdown", description="Déclenche ou lève le lockdown manuellement (override humain)")
    @app_commands.choices(mode=[app_commands.Choice(name="on", value="on"), app_commands.Choice(name="off", value="off")])
    async def lockdown_cmd(self, interaction: discord.Interaction, mode: app_commands.Choice[str]):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        dry_run = await self.db.get_dry_run(interaction.guild_id)
        if mode.value == "on":
            await lockdown.trigger(
                interaction.guild, {"reason": "manuel", "user_id": interaction.user.id, "score": 1.0, "signals": {}},
                dry_run=dry_run, auto_release_seconds=settings.thresholds.lockdown_auto_release_seconds,
                append_evidence=self.append_evidence, db=self.db,
            )
            await interaction.response.send_message("🔒 Lockdown déclenché manuellement.")
        else:
            released = await lockdown.release(
                interaction.guild, dry_run=dry_run, append_evidence=self.append_evidence, db=self.db, manual=True,
            )
            await interaction.response.send_message("🔓 Lockdown levé." if released else "Aucun lockdown actif.")

    canary_group = app_commands.Group(name="canary", parent=group, description="Gestion des canaux pièges")

    @canary_group.command(name="setup", description="(Re)crée les canaux pièges invisibles")
    @app_commands.describe(role="Rôle staff autorisé à voir les pièges (optionnel)")
    async def canary_setup(self, interaction: discord.Interaction, role: discord.Role | None = None):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)
        await interaction.response.defer(ephemeral=True)
        ids = await canary_module.setup_canaries(interaction.guild, self.db, staff_role=role)
        # Fix #6 : met à jour le dict partagé avec on_message dans main.py
        self._canary_ids[interaction.guild_id] = ids
        await interaction.followup.send(f"✅ {len(ids)} canaux pièges actifs (invisibles à @everyone).", ephemeral=True)

    @canary_group.command(name="link", description="Génère un lien honeytoken (RGPD : doit être annoncé au règlement)")
    @app_commands.describe(label="Étiquette descriptive du leurre, ex: 'leak-database-2024'")
    async def canary_link(self, interaction: discord.Interaction, label: str):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        url = await canary_module.generate_honeytoken_link(
            interaction.guild, interaction.channel, label, self.db, settings.federation_api_url,
        )
        await interaction.response.send_message(
            f"🔗 Lien honeytoken généré : ||{url}||\n"
            "⚠️ Ne poster QUE dans un canal piège invisible. Vérifie que le règlement du "
            "serveur mentionne l'usage de liens de détection d'intrusion avant de l'utiliser.",
            ephemeral=True,
        )

    @group.command(name="similar", description="Comptes comportementalement/stylométriquement proches d'un membre")
    async def similar(self, interaction: discord.Interaction, member: discord.Member):
        behavior = await self.db.find_similar_behavior(member.id, interaction.guild_id, threshold=0.7)
        style = await self.db.find_similar_style(member.id, interaction.guild_id, threshold=0.7)

        embed = discord.Embed(title=f"🧬 Profils proches de {member.display_name}")
        embed.add_field(
            name="Comportement (module 1)",
            value="\n".join(f"<@{r['user_id']}> — {r['similarity']:.2f}" for r in behavior) or "Aucun",
            inline=False,
        )
        embed.add_field(
            name="Style d'écriture (module 2)",
            value="\n".join(f"<@{r['user_id']}> — {r['similarity']:.2f}" for r in style) or "Aucun",
            inline=False,
        )
    ai_group = app_commands.Group(name="ai", parent=group, description="Commandes d'apprentissage et détection IA")

    @ai_group.command(name="label", description="Étiquette le dernier score d'un membre pour ré-entraîner le modèle ML")
    @app_commands.choices(label=[app_commands.Choice(name="raid", value="raid"), app_commands.Choice(name="legit", value="legit")])
    async def label_cmd(self, interaction: discord.Interaction, member: discord.Member, label: app_commands.Choice[str]):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        ok = await self.db.label_latest_score(member.id, interaction.guild_id, label.value)
        await interaction.response.send_message(
            f"✅ Étiqueté `{label.value}`." if ok else "❌ Aucun score trouvé pour ce membre.", ephemeral=True,
        )

    @ai_group.command(name="train", description="Réentraîne le modèle scikit-learn sur les labels collectés")
    @app_commands.checks.cooldown(1, 300.0, key=lambda i: i.guild_id)  # 1 fois / 5 min par serveur
    async def train(self, interaction: discord.Interaction):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer()
        X, y = await self.db.fetch_training_data()
        report = self.scorer.retrain(X, y)
        if report is None:
            return await interaction.followup.send(
                f"❌ Pas assez de labels ({len(y)}/{settings.legitimacy_min_training_samples} minimum, "
                "ou une seule classe représentée). Utilise /bidabot label pour en ajouter."
            )
        precision = report.get("1", {}).get("precision", 0)
        recall = report.get("1", {}).get("recall", 0)
        await interaction.followup.send(
            f"✅ Modèle réentraîné sur {len(y)} échantillons — précision={precision:.2f}, rappel={recall:.2f} "
            f"(classe 'raid'). Nouvelle version : `{self.scorer.model_version}`."
        )

    # ── Fédération ────────────────────────────────────────────────────

    federation_group = app_commands.Group(name="federation", parent=group, description="Fédération inter-serveurs")

    @federation_group.command(name="check", description="Consulte les signalements fédérés pour un membre")
    async def federation_check(self, interaction: discord.Interaction, member: discord.Member):
        """Fix #11 — Commande absente du code malgré sa présence dans la
        docstring. Interroge tous les partenaires fédérés (via la DB locale
        qui centralise les rapports reçus) pour un membre donné."""
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        hashed = hash_federation_id(member.id, settings.federation_pepper)
        rows = await self.db.check_federation(hashed)

        if not rows:
            return await interaction.followup.send(
                f"✅ Aucun signalement fédéré pour <@{member.id}> (hash: `{hashed[:16]}…`).",
                ephemeral=True,
            )

        embed = discord.Embed(
            title=f"🌐 Signalements fédérés — {member.display_name}",
            color=0xFF6600,
        )
        embed.set_footer(text=f"ID hashé (HMAC, non réversible) : {hashed[:24]}…")
        for r in rows:
            embed.add_field(
                name=f"Partenaire : {r['partner_name']} (fiabilité {r['reliability_weight']:.1f})",
                value=(
                    f"Score : `{r['risk_score']:.2f}` — {r['reason']}\n"
                    f"Reçu le : {r['received_at'].strftime('%Y-%m-%d %H:%M UTC')}"
                ),
                inline=False,
            )
        await interaction.followup.send(embed=embed, ephemeral=True)

    @federation_group.command(name="report", description="Signale un membre aux serveurs partenaires fédérés")
    @app_commands.describe(
        member="Membre à signaler",
        partner="Nom du partenaire de fédération (doit être configuré en DB)",
        reason="Raison du signalement",
    )
    async def federation_report(self, interaction: discord.Interaction, member: discord.Member,
                                 partner: str, reason: str):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        partner_row = await self.db.get_partner_by_name(partner)
        if not partner_row:
            return await interaction.followup.send(
                f"❌ Partenaire `{partner}` inconnu ou inactif. Vérifie la table `federation_partners`.",
                ephemeral=True,
            )

        client = FederationClient(
            base_url=settings.federation_api_url,
            partner_name=partner,
            hmac_secret=partner_row["hmac_secret"],
            pepper=settings.federation_pepper,
        )
        # Récupère le dernier hash forensique du serveur comme lien de preuve
        last_hash = await self.db.last_evidence_hash(interaction.guild_id)
        evidence_link = f"{settings.federation_api_url}/evidence/{last_hash}" if last_hash else ""

        ok = await client.report(
            discord_id=member.id,
            risk_score=1.0,
            evidence_link=evidence_link,
            reason=reason,
        )
        if ok:
            await self.append_evidence(interaction.guild_id, "federation_reported", {
                "user_id": member.id, "partner": partner, "reason": reason,
            })
            await interaction.followup.send(
                f"✅ Membre <@{member.id}> signalé au partenaire `{partner}`.", ephemeral=True,
            )
        else:
            await interaction.followup.send(
                "❌ Échec du signalement (voir les logs du bot).", ephemeral=True,
            )
    # ── Warns anti-spam (module 10) ────────────────────────────────────

    warns_group = app_commands.Group(name="warns", parent=group, description="Gestion des avertissements anti-spam")

    @warns_group.command(name="check", description="Voir le nombre de warns d'un membre")
    async def warns_check(self, interaction: discord.Interaction, member: discord.Member):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)
        from bot.modules.antispam import get_warn_count
        count = await get_warn_count(member.id, interaction.guild_id, self.cache)
        await interaction.response.send_message(
            f"⚠️ {member.mention} a **{count}** warn(s) actif(s) (TTL : 7 jours).", ephemeral=True
        )

    @warns_group.command(name="reset", description="Remet les warns d'un membre à 0")
    async def warns_reset(self, interaction: discord.Interaction, member: discord.Member):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)
        from bot.modules.antispam import reset_warns
        await reset_warns(member.id, interaction.guild_id, self.cache)
        await interaction.response.send_message(
            f"✅ Warns de {member.mention} remis à 0.", ephemeral=True
        )

    # ── Test anti-scam (module 11) ─────────────────────────────────────

    @ai_group.command(name="test", description="Teste le détecteur anti-scam sur un texte")
    @app_commands.describe(text="Texte à analyser")
    async def scam_test(self, interaction: discord.Interaction, text: str):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)
        from bot.modules.antiscam import analyze
        result = analyze(text)
        if result.is_scam:
            reasons = "\n".join(f"• {r}" for r in result.reasons)
            await interaction.response.send_message(
                f"🚨 **Scam détecté** (score `{result.score:.2f}`) :\n{reasons}", ephemeral=True
            )
        else:
            await interaction.response.send_message(
                f"✅ Texte considéré comme sûr (score `{result.score:.2f}`).", ephemeral=True
            )

    # ── /bidabot whois ────────────────────────────────────────────────

    @group.command(
        name="whois",
        description="Rapport complet sur un membre (accessible à soi-même ou aux admins)",
    )
    @app_commands.describe(member="Membre à analyser (laisser vide = toi-même)")
    async def whois(self, interaction: discord.Interaction, member: discord.Member | None = None):
        target = member or interaction.user

        # Un membre peut consulter son propre profil ; seul un admin peut consulter celui d'un autre.
        if target.id != interaction.user.id and not self._admin_only(interaction):
            return await interaction.response.send_message(
                "❌ Tu peux uniquement consulter ton propre profil. "
                "Seuls les administrateurs peuvent consulter celui d'autres membres.",
                ephemeral=True,
            )

        await interaction.response.defer(ephemeral=(target.id == interaction.user.id))

        guild_id = interaction.guild_id
        profile = await self.db.get_member_profile(target.id, guild_id)
        evidence = await self.db.fetch_evidence_by_user(target.id, guild_id, limit=10)

        embed = discord.Embed(
            title=f"🔍 Rapport BIDABOT — {target.display_name}",
            color=0x5865F2,
            timestamp=discord.utils.utcnow(),
        )
        embed.set_thumbnail(url=target.display_avatar.url)

        if profile is None:
            embed.description = "⚠️ Ce membre n'est pas encore enregistré dans la base de données BIDABOT."
        else:
            u = profile["user"]
            embed.add_field(
                name="👤 Profil",
                value=(
                    f"Compte créé il y a **{u.get('account_age_days', '?')} jours**\n"
                    f"A rejoint le : {u['join_date'].strftime('%d/%m/%Y') if u.get('join_date') else '?'}\n"
                    f"Avatar par défaut : {'Oui ⚠️' if u.get('is_default_avatar') else 'Non ✅'}"
                ),
                inline=True,
            )

            s = profile["latest_score"]
            if s:
                score_val = s["score"]
                score_emoji = "🔴" if score_val >= 0.7 else ("🟡" if score_val >= 0.4 else "🟢")
                embed.add_field(
                    name="🎯 Dernier score de risque",
                    value=(
                        f"{score_emoji} **{score_val:.2f}** (modèle `{s['model_version']}`)\n"
                        f"Label : `{s['label'] or 'non étiqueté'}`\n"
                        f"Évalué le : {s['created_at'].strftime('%d/%m/%Y %H:%M')}"
                    ),
                    inline=True,
                )
                embed.add_field(
                    name="📊 Historique",
                    value=f"{profile['score_count']} évaluation(s) au total",
                    inline=True,
                )
            else:
                embed.add_field(name="🎯 Score", value="Pas encore évalué", inline=True)

        # Chaîne forensique liée à ce membre
        if evidence:
            lines = []
            for e in evidence:
                ts = e["ts"].strftime("%d/%m %H:%M") if e.get("ts") else "?"
                lines.append(f"`{ts}` — `{e['event_type']}` (hash: `{e['hash'][:10]}…`)")
            embed.add_field(
                name=f"🔗 Événements forensiques ({len(evidence)} derniers)",
                value="\n".join(lines),
                inline=False,
            )
        else:
            embed.add_field(name="🔗 Événements forensiques", value="Aucun enregistrement.", inline=False)

        embed.set_footer(text=f"ID Discord : {target.id}")

        # PDF forensique complet uniquement pour les admins, en fichier joint
        if self._admin_only(interaction) and evidence:
            from bot.modules.forensics import build_pdf_report
            from bot.crypto_utils import load_or_create_signing_key
            signing_key = load_or_create_signing_key(settings.signing_key_path)
            chain_ok, _ = await self.db.fetch_evidence_chain(guild_id), True
            pdf_rows = [dict(e) for e in evidence]
            # Reconstruit les champs attendus par build_pdf_report
            for r in pdf_rows:
                r.setdefault("hash", "")
                r.setdefault("ts", "")
            pdf_bytes = build_pdf_report(
                interaction.guild.name, guild_id, pdf_rows, True, signing_key,
            )
            file = discord.File(
                io.BytesIO(pdf_bytes),
                filename=f"bidabot_whois_{target.id}.pdf",
            )
            await interaction.followup.send(embed=embed, file=file)
        else:
            await interaction.followup.send(embed=embed)

    # ── /bidabot logs ─────────────────────────────────────────────────

    @group.command(
        name="logs",
        description="Historique forensique d'un salon (ou du salon courant par défaut)",
    )
    @app_commands.describe(
        channel="Salon dont tu veux voir les logs (défaut : salon courant)",
        filter="Filtrer par type d'événement",
        limit="Nombre max d'entrées à afficher (max 50, défaut 20)",
    )
    @app_commands.choices(filter=[
        app_commands.Choice(name="Tous", value="all"),
        app_commands.Choice(name="Risques critiques", value="risk_critical"),
        app_commands.Choice(name="Canary hits", value="canary_hit"),
        app_commands.Choice(name="Coordination", value="coordination_detected"),
        app_commands.Choice(name="Scams", value="scam_detected"),
        app_commands.Choice(name="Anti-spam", value="antispam_repeat_offender"),
        app_commands.Choice(name="Lockdown", value="lockdown_triggered"),
    ])
    async def logs_cmd(
        self,
        interaction: discord.Interaction,
        channel: discord.TextChannel | None = None,
        filter: app_commands.Choice[str] | None = None,
        limit: int = 20,
    ):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        limit = max(1, min(limit, 50))
        target_channel = channel or interaction.channel
        guild_id = interaction.guild_id

        await interaction.response.defer(ephemeral=True)

        event_types = None
        if filter and filter.value != "all":
            event_types = [filter.value]

        rows = await self.db.fetch_evidence_by_channel(
            target_channel.id, guild_id, limit=limit, event_types=event_types,
        )

        embed = discord.Embed(
            title=f"📋 Logs forensiques — #{target_channel.name}",
            color=0x2F3136,
            timestamp=discord.utils.utcnow(),
        )

        if not rows:
            filter_label = f" (filtre : `{filter.value}`)" if filter and filter.value != "all" else ""
            embed.description = f"Aucun événement trouvé dans ce salon{filter_label}."
        else:
            lines = []
            for r in rows:
                import json as _json
                ts = r["ts"].strftime("%d/%m/%Y %H:%M") if r.get("ts") else "?"
                data = r.get("data") or {}
                if isinstance(data, str):
                    try:
                        data = _json.loads(data)
                    except Exception:
                        data = {}

                # Informations contextuelles selon le type d'événement
                extra = ""
                if data.get("user_id"):
                    extra = f" → <@{data['user_id']}>"
                elif data.get("user_ids"):
                    ids = data["user_ids"][:3]
                    extra = f" → {', '.join(f'<@{u}>' for u in ids)}"
                    if len(data["user_ids"]) > 3:
                        extra += f" (+{len(data['user_ids'])-3})"

                lines.append(
                    f"`{ts}` **{r['event_type']}**{extra}\n"
                    f"  ↳ hash `{r['hash'][:12]}…`"
                )

            embed.description = "\n".join(lines)
            embed.set_footer(
                text=f"{len(rows)} entrée(s) affichée(s) "
                     f"{'sur ' + str(limit) + ' demandées' if len(rows) == limit else '(toutes)'}"
                     f" | /bidabot logs channel:#salon filter:... limit:N"
            )

        await interaction.followup.send(embed=embed, ephemeral=True)

    @group.command(name="unmute", description="Lève le timeout (mute) d'un membre")
    @app_commands.describe(member="Membre à libérer du timeout")
    async def unmute_cmd(self, interaction: discord.Interaction, member: discord.Member):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        try:
            await member.timeout(None, reason=f"BIDABOT — timeout levé par {interaction.user} via /bidabot unmute")
            await self.append_evidence(interaction.guild_id, "timeout_removed", {
                "user_id": member.id,
                "by": interaction.user.id,
            })
            await interaction.followup.send(f"✅ Timeout de {member.mention} levé.", ephemeral=True)
        except discord.Forbidden:
            await interaction.followup.send("❌ Permissions insuffisantes pour lever le timeout.", ephemeral=True)
        except discord.HTTPException as e:
            await interaction.followup.send(f"❌ Erreur Discord : {e}", ephemeral=True)

    @group.command(name="ban", description="Bannit un membre avec enregistrement forensique")
    @app_commands.describe(
        member="Membre à bannir",
        reason="Raison du ban",
        delete_days="Nombre de jours de messages à supprimer (0–7, défaut 1)",
    )
    async def ban_cmd(self, interaction: discord.Interaction, member: discord.Member,
                       reason: str = "Ban manuel via BIDABOT",
                       delete_days: int = 1):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        delete_days = max(0, min(7, delete_days))
        try:
            await member.ban(
                reason=f"BIDABOT — {reason} (par {interaction.user})",
                delete_message_days=delete_days,
            )
            await self.append_evidence(interaction.guild_id, "manual_ban", {
                "user_id": member.id,
                "by": interaction.user.id,
                "reason": reason,
                "delete_days": delete_days,
            })
            await interaction.followup.send(
                f"✅ {member.mention} banni. Raison : `{reason}`. "
                f"Messages des {delete_days} dernier(s) jour(s) supprimés.",
                ephemeral=True,
            )
        except discord.Forbidden:
            await interaction.followup.send("❌ Permissions insuffisantes pour bannir ce membre.", ephemeral=True)
        except discord.HTTPException as e:
            await interaction.followup.send(f"❌ Erreur Discord : {e}", ephemeral=True)

    # ── /bidabot quarantine ───────────────────────────────────────────

    @group.command(name="quarantine", description="Met un membre en quarantaine (accès restreint au salon #sentinel-quarantine)")
    @app_commands.describe(
        member="Membre à mettre en quarantaine",
        reason="Raison de la quarantaine",
    )
    async def quarantine_cmd(self, interaction: discord.Interaction,
                              member: discord.Member, reason: str = "Comportement suspect détecté"):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        channel = await quarantine_module.quarantine(
            member, reason, db=self.db, append_evidence=self.append_evidence,
        )
        if channel:
            await interaction.followup.send(
                f"✅ <@{member.id}> mis en quarantaine. Salon : {channel.mention}", ephemeral=True
            )
        else:
            await interaction.followup.send(
                "⚠️ Quarantaine appliquée partiellement — vérifier les permissions du bot (Manage Roles + Manage Channels).",
                ephemeral=True,
            )

    @group.command(name="unquarantine", description="Lève la quarantaine d'un membre")
    @app_commands.describe(
        member="Membre à libérer",
        ban="Bannir le membre au lieu de le libérer",
    )
    async def unquarantine_cmd(self, interaction: discord.Interaction,
                                member: discord.Member, ban: bool = False):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        ok = await quarantine_module.release(
            member, db=self.db, append_evidence=self.append_evidence, banned=ban,
        )
        if ok:
            action = "banni" if ban else "libéré de la quarantaine"
            await interaction.followup.send(f"✅ <@{member.id}> {action}.", ephemeral=True)
        else:
            await interaction.followup.send(
                f"⚠️ <@{member.id}> n'était pas en quarantaine active.", ephemeral=True
            )

    # ── /bidabot audit (trustscore & invites) ──────────────────────────

    audit_group = app_commands.Group(name="audit", parent=group, description="Audits de configuration et réputation")

    @audit_group.command(name="trustscore", description="Score de confiance global du serveur (0-100)")
    @app_commands.describe(recalculate="Forcer un recalcul immédiat (sinon affiche le dernier score)")
    async def trustscore_cmd(self, interaction: discord.Interaction, recalculate: bool = False):
        await interaction.response.defer()
        guild_id = interaction.guild_id

        if recalculate or self._admin_only(interaction):
            result = await trust_score_module.compute(guild_id, self.db, lockdown, forensics)
        else:
            result = await self.db.get_latest_trust_score(guild_id)
            if not result:
                result = await trust_score_module.compute(guild_id, self.db, lockdown, forensics)

        params = trust_score_module.build_embed(result, interaction.guild.name)
        embed = discord.Embed(
            title=params["title"],
            description=params["description"],
            color=params["color"],
        )
        for name, value in params["fields"]:
            embed.add_field(name=name, value=value, inline=False)
        embed.set_footer(text=params["footer"])

        # Historique en mini-sparkline (dernières 5 valeurs)
        history = await self.db.get_trust_score_history(guild_id, limit=5)
        if len(history) >= 2:
            trend = history[0]["score"] - history[-1]["score"]
            trend_str = f"{'📈' if trend > 0 else '📉' if trend < 0 else '➡️'} {abs(trend):.1f} pts sur {len(history)} mesures"
            embed.add_field(name="Tendance", value=trend_str, inline=False)

        await interaction.followup.send(embed=embed)

    @audit_group.command(name="invites", description="Statistiques d'utilisation des invitations")
    async def invites_cmd(self, interaction: discord.Interaction):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        stats = await self.db.get_invite_stats(interaction.guild_id, limit=10)
        flagged = await self.db.pool.fetch(
            "SELECT invite_code, raid_ratio, auto_revoked, flagged_at "
            "FROM flagged_invites WHERE guild_id=$1 ORDER BY flagged_at DESC LIMIT 5",
            interaction.guild_id,
        )

        embed = discord.Embed(
            title="📨 Audit d'invitations — BIDABOT",
            color=0x5865F2,
        )

        if stats:
            lines = []
            for r in stats:
                inviter = f"<@{r['inviter_id']}> — " if r.get("inviter_id") else ""
                lines.append(
                    f"`{r['invite_code']}` — {inviter}**{r['uses']}** utilisation(s) "
                    f"(dernier : {r['last_use'].strftime('%d/%m %H:%M')})"
                )
            embed.add_field(name="Top invitations", value="\n".join(lines), inline=False)
        else:
            embed.add_field(name="Top invitations", value="Aucune donnée (module 17 actif depuis le dernier restart)", inline=False)

        if flagged:
            fl_lines = []
            for r in flagged:
                status = "🔴 révoqué" if r["auto_revoked"] else "⚠️ non révoqué"
                fl_lines.append(
                    f"`{r['invite_code']}` — ratio raid {r['raid_ratio']*100:.0f}% — {status} ({r['flagged_at'].strftime('%d/%m %H:%M')})"
                )
            embed.add_field(name="🚨 Invitations flagguées", value="\n".join(fl_lines), inline=False)

        await interaction.followup.send(embed=embed, ephemeral=True)

    # ── /bidabot voice (Anti-Stresseur Vocal) ─────────────────────────

    voice_group = app_commands.Group(name="voice", parent=group, description="Système Anti-Stresseur et protection des salons vocaux")

    @voice_group.command(name="renew", description="Recrée un salon vocal lagué/stressé avec les mêmes perms et déplace tous les membres")
    @app_commands.describe(
        channel="Salon vocal à réparer (par défaut : le salon dans lequel vous êtes connecté)",
        region="Région WebRTC cible (optionnel, 'auto' ou ex: rotterdam, frankfurt, madrid)",
    )
    async def voice_renew_cmd(self, interaction: discord.Interaction,
                              channel: discord.VoiceChannel | None = None,
                              region: str | None = None):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        target_ch = channel
        if not target_ch and isinstance(interaction.user, discord.Member) and interaction.user.voice:
            target_ch = interaction.user.voice.channel

        if not target_ch or not isinstance(target_ch, discord.VoiceChannel):
            return await interaction.response.send_message(
                "❌ Veuillez spécifier un salon vocal ou vous connecter au salon vocal à réparer.",
                ephemeral=True,
            )

        await interaction.response.defer(ephemeral=True)
        try:
            from bot.modules import voice_antistress as va_mod
            new_ch, moved = await va_mod.renew_voice_channel(
                target_ch,
                reason=f"Déclenché manuellement par {interaction.user.name}",
                new_region=region,
                append_evidence=self.append_evidence,
                db=self.db,
            )
            reg_text = f" (Région : `{region}`)" if region else ""
            await interaction.followup.send(
                f"⚡ **Salon vocal réparé avec succès !**\n"
                f"• 🔊 Nouveau salon : {new_ch.mention}{reg_text}\n"
                f"• 👥 **{moved}** membre(s) déplacés automatiquement sans coupure.\n"
                f"• 🛡️ L'ancien salon lagué a été détruit — attaques de stresseurs neutralisées.",
                ephemeral=True,
            )
        except PermissionError as e:
            await interaction.followup.send(f"❌ {e}", ephemeral=True)
        except Exception as e:
            logger.error("Erreur commande voice renew : %s", e)
            await interaction.followup.send(f"❌ Erreur lors du renouvellement vocal : {e}", ephemeral=True)

    @voice_group.command(name="ping", description="Mesure le ping WebRTC et la santé de la passerelle d'un salon vocal")
    @app_commands.describe(channel="Salon vocal à analyser")
    async def voice_ping_cmd(self, interaction: discord.Interaction, channel: discord.VoiceChannel | None = None):
        target_ch = channel
        if not target_ch and isinstance(interaction.user, discord.Member) and interaction.user.voice:
            target_ch = interaction.user.voice.channel

        if not target_ch or not isinstance(target_ch, discord.VoiceChannel):
            return await interaction.response.send_message("❌ Veuillez spécifier un salon vocal ou être connecté en vocal.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        from bot.modules import voice_antistress as va_mod
        lat_info = await va_mod.measure_voice_latency(self.bot, target_ch)

        ping = lat_info.get("ping_ms")
        status = lat_info.get("status", "unknown")
        region = lat_info.get("region", "auto")
        source = lat_info.get("source", "unknown")

        if status == "stressed":
            icon = "🚨"
            color = 0xFF0000
            diag = "Saturé / Lag critique (recommandation : lancer `/bidabot voice renew`)"
        elif status == "warning":
            icon = "⚠️"
            color = 0xFFAA00
            diag = "Latence élevée détectée"
        else:
            icon = "🟢"
            color = 0x00FF88
            diag = "Passerelle fluide et optimale"

        embed = discord.Embed(
            title=f"{icon} Diagnostic Vocal — #{target_ch.name}",
            color=color,
        )
        embed.add_field(name="Ping Passerelle", value=f"**{ping} ms**" if ping else "Indisponible", inline=True)
        embed.add_field(name="Région WebRTC", value=f"`{region}`", inline=True)
        embed.add_field(name="Diagnostic", value=diag, inline=False)
        embed.add_field(name="Membres connectés", value=str(len(target_ch.members)), inline=True)
        embed.add_field(name="Source mesure", value=f"`{source}`", inline=True)

        await interaction.followup.send(embed=embed, ephemeral=True)

    @voice_group.command(name="region", description="Bascule la région WebRTC d'un salon pour réinitialiser la connexion")
    @app_commands.describe(
        channel="Salon vocal",
        region="Région cible (rotterdam, frankfurt, madrid, london, auto...)",
    )
    async def voice_region_cmd(self, interaction: discord.Interaction,
                               channel: discord.VoiceChannel,
                               region: str):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        from bot.modules import voice_antistress as va_mod
        ok, msg = await va_mod.switch_voice_region(channel, region)
        if ok:
            await interaction.response.send_message(f"✅ {msg} sur {channel.mention}", ephemeral=True)
        else:
            await interaction.response.send_message(f"❌ {msg}", ephemeral=True)

    @voice_group.command(name="autoprotect", description="Active ou désactive la surveillance automatique anti-stresseur")
    @app_commands.describe(
        channel="Salon vocal à surveiller",
        enable="Activer ou désactiver l'auto-réparation",
        max_ping="Seuil de ping en ms déclenchant la recréation automatique (défaut: 250)",
    )
    async def voice_autoprotect_cmd(self, interaction: discord.Interaction,
                                    channel: discord.VoiceChannel,
                                    enable: bool = True,
                                    max_ping: int = 250):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        if enable:
            await self.db.set_voice_antistress_config(interaction.guild_id, channel.id, max_ping_ms=max_ping, auto_renew=True)
            await interaction.response.send_message(
                f"🛡️ **Surveillance Anti-Stresseur activée sur {channel.mention} !**\n"
                f"• Seuil d'intervention : **{max_ping} ms**\n"
                f"• Auto-réparation : **Activée** (recréation automatique & transfert des membres en cas de lag ou flood).",
                ephemeral=True,
            )
        else:
            await self.db.remove_voice_antistress_config(interaction.guild_id, channel.id)
            await interaction.response.send_message(
                f"⚪ Surveillance Anti-Stresseur désactivée sur {channel.mention}.",
                ephemeral=True,
            )

    # ── /bidabot backup (Sauvegardes et Restauration d'urgence) ────────

    backup_group = app_commands.Group(name="backup", parent=group, description="Système de Sauvegarde et Restauration d'urgence")

    @backup_group.command(name="create", description="Capture un snapshot complet de la structure du serveur (salons, rôles, catégories)")
    @app_commands.describe(label="Nom ou description de la sauvegarde (ex: Avant-Event, Pre-Update)")
    async def backup_create_cmd(self, interaction: discord.Interaction, label: str = "Manuel"):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        try:
            from bot.modules import snapshot as snap_mod
            snap_data = await snap_mod.capture_guild_snapshot(interaction.guild, label=label)
            total_channels = snap_data["summary"]["text_channels_count"] + snap_data["summary"]["voice_channels_count"]
            total_roles = snap_data["summary"]["roles_count"]
            total_cats = snap_data["summary"]["categories_count"]

            snap_id = await self.db.save_guild_snapshot(
                interaction.guild_id, label, snap_data,
                channels_count=total_channels,
                roles_count=total_roles,
            )

            if self.append_evidence:
                await self.append_evidence(interaction.guild_id, "guild_snapshot_created", {
                    "snapshot_id": snap_id,
                    "label": label,
                    "author_id": interaction.user.id,
                    "summary": snap_data["summary"],
                })

            embed = discord.Embed(
                title="💾 Snapshot de Sauvegarde Enregistré",
                description=(
                    f"La structure actuelle du serveur a été sauvegardée avec succès.\n"
                    f"En cas de raid ou de nuke, restaurez tout avec `/bidabot backup restore {snap_id}`."
                ),
                color=0x00FF88,
            )
            embed.add_field(name="ID Snapshot", value=f"`#{snap_id}`", inline=True)
            embed.add_field(name="Label", value=f"**{label}**", inline=True)
            embed.add_field(name="Catégories", value=str(total_cats), inline=True)
            embed.add_field(name="Salons Textuels", value=str(snap_data["summary"]["text_channels_count"]), inline=True)
            embed.add_field(name="Salons Vocaux", value=str(snap_data["summary"]["voice_channels_count"]), inline=True)
            embed.add_field(name="Rôles Sauvegardés", value=str(total_roles), inline=True)

            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            logger.error("Erreur création snapshot : %s", e)
            await interaction.followup.send(f"❌ Erreur lors de la création de la sauvegarde : {e}", ephemeral=True)

    @backup_group.command(name="list", description="Liste les snapshots de sauvegarde disponibles pour ce serveur")
    async def backup_list_cmd(self, interaction: discord.Interaction):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        snaps = await self.db.get_guild_snapshots(interaction.guild_id, limit=10)
        if not snaps:
            return await interaction.followup.send(
                "📂 Aucun snapshot enregistré pour ce serveur. Créez-en un avec `/bidabot backup create`.",
                ephemeral=True,
            )

        embed = discord.Embed(
            title="📂 Sauvegardes Disponibles — BIDABOT",
            description="Liste des 10 derniers snapshots de structure enregistrés :",
            color=0x5865F2,
        )
        for s in snaps:
            created = s.get("created_at")
            time_str = created.strftime("%d/%m/%Y %H:%M") if hasattr(created, "strftime") else str(created)[:16]
            embed.add_field(
                name=f"#{s['id']} — {s['label']}",
                value=f"📅 {time_str} • 💬 {s['channels_count']} salons • 🎭 {s['roles_count']} rôles\n`Commande : /bidabot backup restore {s['id']}`",
                inline=False,
            )

        await interaction.followup.send(embed=embed, ephemeral=True)

    @backup_group.command(name="restore", description="Restaure chirurgicalement les salons, catégories et rôles manquants")
    @app_commands.describe(snapshot_id="Identifiant numérique du snapshot à restaurer")
    async def backup_restore_cmd(self, interaction: discord.Interaction, snapshot_id: int):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        await interaction.response.defer(ephemeral=True)
        snap = await self.db.get_guild_snapshot_by_id(snapshot_id, interaction.guild_id)
        if not snap:
            return await interaction.followup.send(f"❌ Aucun snapshot trouvé avec l'identifiant `#{snapshot_id}`.", ephemeral=True)

        try:
            from bot.modules import snapshot as snap_mod
            stats = await snap_mod.restore_guild_snapshot(interaction.guild, snap["snapshot_data"])

            if self.append_evidence:
                await self.append_evidence(interaction.guild_id, "guild_snapshot_restored", {
                    "snapshot_id": snapshot_id,
                    "author_id": interaction.user.id,
                    "stats": stats,
                })

            embed = discord.Embed(
                title="🛡️ Restauration de Sauvegarde Terminée",
                description=f"La structure du snapshot `#{snapshot_id}` ({snap['label']}) a été restaurée sans écraser les éléments existants.",
                color=0x00FF88,
            )
            embed.add_field(name="Rôles recréés", value=str(stats["roles_restored"]), inline=True)
            embed.add_field(name="Catégories recréées", value=str(stats["categories_restored"]), inline=True)
            embed.add_field(name="Salons recréés", value=str(stats["channels_restored"]), inline=True)

            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            logger.error("Erreur restauration snapshot : %s", e)
            await interaction.followup.send(f"❌ Erreur lors de la restauration : {e}", ephemeral=True)

    @backup_group.command(name="delete", description="Supprime définitivement un snapshot de sauvegarde")
    @app_commands.describe(snapshot_id="Identifiant numérique du snapshot à supprimer")
    async def backup_delete_cmd(self, interaction: discord.Interaction, snapshot_id: int):
        if not self._admin_only(interaction):
            return await interaction.response.send_message("❌ Réservé aux administrateurs.", ephemeral=True)

        deleted = await self.db.delete_guild_snapshot(snapshot_id, interaction.guild_id)
        if deleted:
            await interaction.response.send_message(f"🗑️ Snapshot `#{snapshot_id}` supprimé avec succès.", ephemeral=True)
        else:
            await interaction.response.send_message(f"❌ Impossible de supprimer le snapshot `#{snapshot_id}` (introuvable).", ephemeral=True)


async def setup(bot):
    pass  # ajouté explicitement via bot.add_cog dans bot/main.py (besoin d'injecter db/cache/bus)


# Alias pour compatibilité descendante
SentinelAdmin = BidabotAdmin
