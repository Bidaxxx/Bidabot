"""
Module 12 — Dashboard Discord (salon stats live + salon alertes).

Deux salons dans une catégorie privée réservée aux admins :
  #sentinel-status   : embed de stats mis à jour toutes les 5 min
                       (lockdown, war rooms, incidents du jour, score moyen)
  #sentinel-alerts   : fil d'alertes textuelles en temps réel
                       (chaque incident déclenche un message ici)

Alertes DM : quand un incident critique se produit, le bot envoie aussi
un DM aux membres ayant le rôle "admin" (ou qui ont la permission
`administrator`) — configurable via /sentinel admin-alerts on|off.

Les DM sont envoyés de façon non-bloquante et ignorés si l'utilisateur
a désactivé ses DM (discord.Forbidden silencieux).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import discord

logger = logging.getLogger("sentinel.guild_dashboard")

CATEGORY_NAME = "bidabot-admin"
STATUS_CHANNEL_NAME = "bidabot-status"
ALERTS_CHANNEL_NAME = "bidabot-alerts"

# Garde en mémoire les IDs des salons par guild pour éviter une requête DB à
# chaque alerte — repopulé dans on_ready et quand le dashboard est (re)créé.
_status_channels: dict[int, discord.TextChannel] = {}
_alerts_channels: dict[int, discord.TextChannel] = {}
_status_messages: dict[int, discord.Message] = {}   # message d'embed qu'on édite


# ── Création / restauration ────────────────────────────────────────────

async def setup_dashboard(guild: discord.Guild, db, staff_role: discord.Role | None = None) -> tuple[discord.TextChannel, discord.TextChannel] | tuple[None, None]:
    """
    Crée (ou retrouve) la catégorie admin et les deux salons (#sentinel-status et #sentinel-alerts).
    Appelé depuis /sentinel setup ou /sentinel setup_dashboard.
    Le rôle @everyone a view_channel=False (totalement invisible pour les membres normaux).
    Le rôle staff_role (si fourni) a accès en lecture seule.
    Retourne (status_channel, alerts_channel) ou (None, None) si Forbidden.
    """
    # Permissions : invisible pour @everyone, visible pour le bot et le staff
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
    }
    if guild.me:
        overwrites[guild.me] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, embed_links=True,
            attach_files=True, read_message_history=True, manage_messages=True,
        )

    for role in guild.roles:
        if role == guild.default_role:
            continue
        if role.permissions.administrator or role.permissions.manage_guild:
            overwrites[role] = discord.PermissionOverwrite(
                view_channel=True, send_messages=False, read_message_history=True,
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

    # Catégorie (cherche bidabot-admin ou ancien sentinel-admin)
    category = discord.utils.get(guild.categories, name=CATEGORY_NAME) or discord.utils.get(guild.categories, name="sentinel-admin")
    if not category:
        try:
            category = await guild.create_category(
                CATEGORY_NAME, overwrites=overwrites,
                reason="BIDABOT — catégorie dashboard admin",
            )
        except discord.Forbidden:
            logger.warning("Permissions insuffisantes pour créer la catégorie dashboard sur %s", guild.name)
            return None, None
    else:
        try:
            await category.set_permissions(guild.default_role, view_channel=False)
            if guild.me:
                await category.set_permissions(guild.me, view_channel=True, send_messages=True, manage_messages=True)
            for r in roles_list:
                await category.set_permissions(r, view_channel=True, send_messages=False, read_message_history=True)
        except (discord.Forbidden, discord.HTTPException):
            pass

    # Salon status (cherche bidabot-status ou ancien sentinel-status)
    status_ch = discord.utils.get(guild.text_channels, name=STATUS_CHANNEL_NAME, category=category) or discord.utils.get(guild.text_channels, name="sentinel-status", category=category)
    if not status_ch:
        try:
            status_ch = await guild.create_text_channel(
                STATUS_CHANNEL_NAME, category=category, overwrites=overwrites,
                topic="📊 Tableau de bord BIDABOT — mis à jour automatiquement.",
                reason="BIDABOT — salon status",
            )
        except discord.Forbidden:
            return None, None
    else:
        try:
            await status_ch.set_permissions(guild.default_role, view_channel=False)
            if guild.me:
                await status_ch.set_permissions(guild.me, view_channel=True, send_messages=True, embed_links=True, manage_messages=True)
            for r in roles_list:
                await status_ch.set_permissions(r, view_channel=True, send_messages=False, read_message_history=True)
        except (discord.Forbidden, discord.HTTPException):
            pass

    # Salon alerts (cherche bidabot-alerts ou ancien sentinel-alerts)
    alerts_ow = dict(overwrites)
    alerts_ch = discord.utils.get(guild.text_channels, name=ALERTS_CHANNEL_NAME, category=category) or discord.utils.get(guild.text_channels, name="sentinel-alerts", category=category)
    if not alerts_ch:
        try:
            alerts_ch = await guild.create_text_channel(
                ALERTS_CHANNEL_NAME, category=category, overwrites=alerts_ow,
                topic="🚨 Fil d'alertes BIDABOT en temps réel.",
                reason="BIDABOT — salon alertes",
            )
        except discord.Forbidden:
            return None, None
    else:
        try:
            await alerts_ch.set_permissions(guild.default_role, view_channel=False)
            if guild.me:
                await alerts_ch.set_permissions(guild.me, view_channel=True, send_messages=True, embed_links=True, manage_messages=True)
            for r in roles_list:
                await alerts_ch.set_permissions(r, view_channel=True, send_messages=False, read_message_history=True)
        except (discord.Forbidden, discord.HTTPException):
            pass

    _status_channels[guild.id] = status_ch
    _alerts_channels[guild.id] = alerts_ch

    if hasattr(db, "set_dashboard_channels"):
        await db.set_dashboard_channels(guild.id, status_ch.id, alerts_ch.id)
    roles_list: list[discord.Role] = []
    if staff_role:
        if isinstance(staff_role, (list, tuple, set)):
            roles_list = [r for r in staff_role if r]
        else:
            roles_list = [staff_role]

    if roles_list and hasattr(db, "set_staff_role"):
        await db.set_staff_role(guild.id, roles_list[0].id)

    role_desc = ", ".join(r.name for r in roles_list) if roles_list else "défaut"
    logger.info("Dashboard admin configuré sur %s — #%s / #%s (rôle staff: %s)",
                guild.name, STATUS_CHANNEL_NAME, ALERTS_CHANNEL_NAME, role_desc)
    return status_ch, alerts_ch


async def restore_from_db(bot: discord.Client, db) -> None:
    """Appelé dans on_ready pour repeupler _status_channels / _alerts_channels."""
    rows = await db.get_dashboard_channels()
    for row in rows:
        guild = bot.get_guild(row["guild_id"])
        if not guild:
            continue
        status_ch = guild.get_channel(row["status_channel_id"])
        alerts_ch = guild.get_channel(row["alerts_channel_id"])
        if isinstance(status_ch, discord.TextChannel):
            _status_channels[guild.id] = status_ch
        if isinstance(alerts_ch, discord.TextChannel):
            _alerts_channels[guild.id] = alerts_ch


# ── Mise à jour du status ─────────────────────────────────────────────

async def update_status(guild: discord.Guild, db, lockdown_module, scorer) -> None:
    """
    Édite (ou crée) l'embed de statut dans #sentinel-status.
    Appelé périodiquement (toutes les 5 min via discord.ext.tasks dans main.py)
    et après chaque incident majeur.
    """
    ch = _status_channels.get(guild.id)
    if not ch:
        ch = discord.utils.get(guild.text_channels, name=STATUS_CHANNEL_NAME)
        if ch:
            _status_channels[guild.id] = ch
        else:
            return

    dry_run = await db.get_dry_run(guild.id)
    lockdown_active = lockdown_module.is_active(guild.id)
    warrooms = await db.active_warroom_count(guild.id)
    incidents_today = await db.count_incidents_today(guild.id)
    avg_score = await db.avg_risk_score_today(guild.id)

    color = 0xFF0000 if lockdown_active else (0xFF6600 if warrooms > 0 else 0x00CC66)
    embed = discord.Embed(
        title="🛡️ BIDABOT — Tableau de bord",
        color=color,
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(
        name="🔒 Lockdown",
        value="🔴 **ACTIF**" if lockdown_active else "🟢 Inactif",
    )
    embed.add_field(
        name="🚨 War rooms ouvertes",
        value=f"**{warrooms}**" if warrooms > 0 else "0",
    )
    embed.add_field(
        name="📅 Incidents aujourd'hui",
        value=str(incidents_today),
    )
    embed.add_field(
        name="📊 Score de risque moyen (24h)",
        value=f"{avg_score:.2f}" if avg_score is not None else "N/A",
    )
    embed.add_field(
        name="🤖 Modèle ML",
        value=scorer.model_version,
    )
    embed.add_field(
        name="⚙️ Mode",
        value="🟡 Dry-run (simulation)" if dry_run else "🔴 Actions réelles",
    )
    embed.set_footer(text="Mis à jour automatiquement toutes les 5 minutes")

    existing = _status_messages.get(guild.id)
    try:
        if existing:
            await existing.edit(embed=embed)
        else:
            # Cherche un embed existant dans les 10 derniers messages
            async for msg in ch.history(limit=10):
                if msg.author == ch.guild.me and msg.embeds:
                    _status_messages[guild.id] = msg
                    await msg.edit(embed=embed)
                    return
            # Aucun trouvé → on en crée un
            msg = await ch.send(embed=embed)
            _status_messages[guild.id] = msg
    except (discord.Forbidden, discord.HTTPException):
        pass


# ── Composants d'Action Interactive (Boutons & Modals) ────────────────

class BanReasonModal(discord.ui.Modal, title="Confirmer le Bannissement"):
    reason = discord.ui.TextInput(
        label="Raison du bannissement",
        default="Raid / Activité malveillante détectée par SENTINEL",
        placeholder="Indiquez le motif de la sanction...",
        max_length=200,
        required=True,
    )
    purge_days = discord.ui.TextInput(
        label="Jours de messages à purger (0 à 7)",
        default="1",
        max_length=1,
        required=True,
    )

    def __init__(self, guild_id: int, target_user_id: int, db=None, append_evidence=None):
        super().__init__()
        self.guild_id = guild_id
        self.target_user_id = target_user_id
        self.db = db
        self.append_evidence = append_evidence

    async def on_submit(self, interaction: discord.Interaction):
        p = interaction.user.guild_permissions
        if not (p.ban_members or p.administrator):
            await interaction.response.send_message("❌ Vous n'avez pas la permission de bannir des membres.", ephemeral=True)
            return

        guild = interaction.guild
        if not guild:
            await interaction.response.send_message("❌ Serveur Discord introuvable.", ephemeral=True)
            return

        try:
            days = int(self.purge_days.value.strip())
            days = max(0, min(7, days))
        except ValueError:
            days = 1

        try:
            await guild.ban(
                discord.Object(id=self.target_user_id),
                reason=f"[Modérateur: {interaction.user}] {self.reason.value}",
                delete_message_days=days,
            )
            if self.append_evidence:
                await self.append_evidence(guild.id, "alert_action_ban", {
                    "moderator_id": interaction.user.id,
                    "target_user_id": self.target_user_id,
                    "reason": self.reason.value,
                    "purge_days": days,
                })
            await interaction.response.send_message(
                f"✅ **Sanction appliquée** : <@{self.target_user_id}> a été banni avec succès par {interaction.user.mention} (purge: {days}j).",
                ephemeral=False,
            )
        except discord.Forbidden:
            await interaction.response.send_message("❌ Permissions insuffisantes : le bot ne peut pas bannir ce membre (hiérarchie des rôles).", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ Erreur lors du bannissement : {e}", ephemeral=True)


class AlertActionView(discord.ui.View):
    def __init__(
        self,
        guild_id: int,
        target_user_id: int,
        *,
        score_data: dict | None = None,
        db=None,
        append_evidence=None,
        quarantine_module=None,
    ):
        super().__init__(timeout=None)
        self.guild_id = guild_id
        self.target_user_id = target_user_id
        self.score_data = score_data or {}
        self.db = db
        self.append_evidence = append_evidence
        self.quarantine_module = quarantine_module

    def _has_mod_perms(self, interaction: discord.Interaction) -> bool:
        p = interaction.user.guild_permissions
        return p.administrator or p.ban_members or p.moderate_members or p.manage_guild

    @discord.ui.button(label="Bannir & Purger", style=discord.ButtonStyle.danger, emoji="🔴", custom_id="sentinel_alert_ban")
    async def ban_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._has_mod_perms(interaction):
            await interaction.response.send_message("❌ Action réservée aux modérateurs / administrateurs.", ephemeral=True)
            return
        await interaction.response.send_modal(
            BanReasonModal(self.guild_id, self.target_user_id, db=self.db, append_evidence=self.append_evidence)
        )

    @discord.ui.button(label="Isoler en Quarantaine", style=discord.ButtonStyle.secondary, emoji="🟡", custom_id="sentinel_alert_quarantine")
    async def quarantine_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._has_mod_perms(interaction):
            await interaction.response.send_message("❌ Action réservée aux modérateurs / administrateurs.", ephemeral=True)
            return
        guild = interaction.guild
        member = guild.get_member(self.target_user_id) if guild else None
        if not member:
            await interaction.response.send_message("❌ Membre introuvable sur le serveur (déjà parti ou expulsé).", ephemeral=True)
            return

        if self.quarantine_module:
            res = await self.quarantine_module.quarantine(
                member,
                reason=f"Quarantaine déclenchée depuis l'alerte par {interaction.user}",
                db=self.db,
                append_evidence=self.append_evidence,
            )
            if res.get("status") == "quarantined":
                await interaction.response.send_message(
                    f"🟡 **Quarantaine appliquée** : <@{self.target_user_id}> a été isolé dans le salon de quarantaine par {interaction.user.mention}.",
                    ephemeral=False,
                )
            else:
                err_msg = res.get("reason") or "Impossible d'isoler le membre"
                await interaction.response.send_message(f"⚠️ Quarantaine : {err_msg}", ephemeral=True)
        else:
            await interaction.response.send_message("❌ Module de quarantaine non initialisé.", ephemeral=True)

    @discord.ui.button(label="Faux Positif (Whitelist)", style=discord.ButtonStyle.success, emoji="🟢", custom_id="sentinel_alert_whitelist")
    async def whitelist_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._has_mod_perms(interaction):
            await interaction.response.send_message("❌ Action réservée aux modérateurs / administrateurs.", ephemeral=True)
            return
        if self.db:
            await self.db.add_whitelist(self.guild_id, self.target_user_id, "user")
        guild = interaction.guild
        member = guild.get_member(self.target_user_id) if guild else None
        if member and self.quarantine_module:
            await self.quarantine_module.release(member, db=self.db, append_evidence=self.append_evidence)
        if self.append_evidence:
            await self.append_evidence(self.guild_id, "alert_action_whitelist", {
                "moderator_id": interaction.user.id,
                "target_user_id": self.target_user_id,
            })
        await interaction.response.send_message(
            f"🟢 **Faux Positif** : <@{self.target_user_id}> a été ajouté à la Whitelist de confiance par {interaction.user.mention} (sanctions levées).",
            ephemeral=False,
        )

    @discord.ui.button(label="Inspecter Profil", style=discord.ButtonStyle.primary, emoji="🔍", custom_id="sentinel_alert_inspect")
    async def inspect_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        guild = interaction.guild
        member = guild.get_member(self.target_user_id) if guild else None

        embed = discord.Embed(
            title=f"🔍 Dossier de Sécurité Forensique — ID: {self.target_user_id}",
            color=0x5865F2,
            timestamp=datetime.now(timezone.utc),
        )
        if member:
            embed.set_author(name=str(member), icon_url=member.display_avatar.url)
            created_days = (discord.utils.utcnow() - member.created_at).days
            embed.add_field(name="📅 Ancienneté", value=f"{created_days} jours (créé le {member.created_at.strftime('%d/%m/%Y')})", inline=True)
            embed.add_field(name="🖼️ Avatar", value="Défaut" if member.avatar is None else "Personnalisé", inline=True)
            badges_list = [f.name for f in member.public_flags.all()] if member.public_flags else []
            embed.add_field(name="🎖️ Badges", value=", ".join(badges_list) or "Aucun", inline=True)
        else:
            embed.description = "*(Membre non présent actuellement sur le serveur)*"

        if self.score_data:
            score_val = self.score_data.get("score", "N/A")
            embed.add_field(name="🎯 Score de Risque Global", value=f"**{score_val}**", inline=False)
            signals = self.score_data.get("signals", {})
            if signals:
                details = "\n".join([f"• `{k}` : `{v:.2f}`" if isinstance(v, (int, float)) else f"• `{k}` : `{v}`" for k, v in signals.items()])
                embed.add_field(name="📊 Signaux d'évaluation ML", value=details, inline=False)
            if "reason" in self.score_data:
                embed.add_field(name="🚨 Motif déclencheur", value=f"`{self.score_data['reason']}`", inline=False)

        embed.set_footer(text="BIDABOT Intelligence Forensique — Consultation Staff Privée")
        await interaction.response.send_message(embed=embed, ephemeral=True)


# ── Envoi d'alerte ────────────────────────────────────────────────────

async def send_alert(
    guild: discord.Guild,
    title: str,
    description: str,
    color: int = 0xFF6600,
    fields: dict | None = None,
    target_user_id: int | None = None,
    score_data: dict | None = None,
    view: discord.ui.View | None = None,
    db=None,
    append_evidence=None,
    quarantine_module=None,
) -> None:
    """
    Poste un embed d'alerte dans #sentinel-alerts avec boutons d'action rapide.
    Appelé depuis warroom.py, antispam.py, antiscam.py, main.py, etc.
    """
    ch = _alerts_channels.get(guild.id)
    if not ch:
        ch = discord.utils.get(guild.text_channels, name=ALERTS_CHANNEL_NAME)
        if ch:
            _alerts_channels[guild.id] = ch
        else:
            return

    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=datetime.now(timezone.utc),
    )
    if fields:
        for name, value in fields.items():
            embed.add_field(name=name, value=str(value)[:1024], inline=False)

    action_view = view
    if action_view is None and target_user_id is not None:
        action_view = AlertActionView(
            guild.id,
            target_user_id,
            score_data=score_data,
            db=db,
            append_evidence=append_evidence,
            quarantine_module=quarantine_module,
        )

    try:
        if action_view is not None:
            await ch.send(embed=embed, view=action_view)
        else:
            await ch.send(embed=embed)
    except (discord.Forbidden, discord.HTTPException):
        pass


# ── Alertes DM ────────────────────────────────────────────────────────

async def dm_admins(guild: discord.Guild, title: str, description: str) -> None:
    """
    Envoie un DM à tous les membres avec la permission `administrator`.
    Silencieux si l'utilisateur a ses DM fermés (discord.Forbidden ignoré).
    """
    embed = discord.Embed(
        title=f"🛡️ BIDABOT — {title}",
        description=description,
        color=0xFF0000,
        timestamp=datetime.now(timezone.utc),
    )
    embed.set_footer(text=f"Serveur : {guild.name}")

    for member in guild.members:
        if member.bot:
            continue
        if not member.guild_permissions.administrator:
            continue
        try:
            await member.send(embed=embed)
            logger.debug("DM alerte envoyé à %s (%s)", member, guild.name)
        except (discord.Forbidden, discord.HTTPException):
            pass  # DM désactivés ou autre erreur → on ignore silencieusement
