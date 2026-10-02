"""
Module 9 — War room auto-assemblée.

Réagit aux événements "risk_critical" et "canary_hit" émis par les modules
3, 4 et 5. Rassemble en un seul embed tout le contexte déjà calculé par les
autres modules (score de légitimité, comptes comportementalement proches,
correspondances stylométriques) — la war room ne recalcule rien, elle
consomme ce que le pipeline anti-raid a déjà produit.

Timeline live : chaque nouvel événement forensique du même serveur pendant
que la war room est ouverte édite le message-timeline plutôt que d'en
poster un nouveau, pour garder le salon lisible.

Fix #3 : restore_from_db() permet à on_ready de repeupler _active_channels
et _timeline_messages depuis la base après un restart, évitant que la
timeline et les boutons soient silencieusement morts après un redémarrage.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import discord

logger = logging.getLogger("sentinel.warroom")

_active_channels: dict[int, discord.TextChannel] = {}
_timeline_messages: dict[int, discord.Message] = {}


async def restore_from_db(bot, db) -> None:
    """Appelé dans on_ready : relit les war rooms ouvertes depuis la base et
    re-peuple _active_channels / _timeline_messages pour que la timeline et
    les boutons restent fonctionnels après un restart."""
    rows = await db.get_open_warrooms()
    for row in rows:
        guild = bot.get_guild(row["guild_id"])
        if not guild:
            continue
        channel = guild.get_channel(row["channel_id"])
        if not isinstance(channel, discord.TextChannel):
            continue
        _active_channels[guild.id] = channel
        # Récupère le dernier message "Timeline live" pour reprendre l'édition
        try:
            async for msg in channel.history(limit=20, oldest_first=True):
                if msg.author == bot.user and "Timeline live" in msg.content:
                    _timeline_messages[guild.id] = msg
                    break
        except discord.HTTPException:
            pass
        logger.info("War room restaurée sur %s → #%s", guild.name, channel.name)


class WarRoomView(discord.ui.View):
    def __init__(self, guild: discord.Guild, db, cache, bus, append_evidence,
                 lockdown_module, dry_run: bool, auto_release_seconds: int,
                 signing_key, forensics_module):
        super().__init__(timeout=None)
        self.guild = guild
        self.db = db
        self.cache = cache
        self.bus = bus
        self.append_evidence = append_evidence
        self.lockdown_module = lockdown_module
        self.dry_run = dry_run
        self.auto_release_seconds = auto_release_seconds
        self.signing_key = signing_key
        self.forensics_module = forensics_module

    @discord.ui.button(label="🔒 Lockdown total", style=discord.ButtonStyle.danger)
    async def lockdown_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.lockdown_module.trigger(
            self.guild, {"reason": "manuel (war room)", "user_id": interaction.user.id},
            dry_run=self.dry_run, auto_release_seconds=self.auto_release_seconds,
            append_evidence=self.append_evidence, db=self.db,
        )
        msg = "✅ Lockdown appliqué." if not self.dry_run else "✅ Lockdown simulé (dry-run actif — voir /sentinel dry-run off)."
        await interaction.response.send_message(msg, ephemeral=True)

    @discord.ui.button(label="📄 Vérifier la chaîne", style=discord.ButtonStyle.secondary)
    async def verify_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        ok, count = await self.forensics_module.verify_chain(self.db, self.guild.id)
        await interaction.response.send_message(
            f"{'✅' if ok else '❌'} Chaîne forensique ({count} entrées) : {'intègre' if ok else 'CORROMPUE — investiguer immédiatement'}",
            ephemeral=True,
        )

    @discord.ui.button(label="💾 Snapshot d'urgence", style=discord.ButtonStyle.primary)
    async def snapshot_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer(ephemeral=True)
        try:
            from bot.modules import snapshot as snap_mod
            snap_data = await snap_mod.capture_guild_snapshot(self.guild, label="War Room Urgence")
            total_channels = snap_data["summary"]["text_channels_count"] + snap_data["summary"]["voice_channels_count"]
            total_roles = snap_data["summary"]["roles_count"]
            snap_id = await self.db.save_guild_snapshot(
                self.guild.id, "War Room Urgence", snap_data,
                channels_count=total_channels,
                roles_count=total_roles,
            )
            await self.append_evidence(self.guild.id, "guild_snapshot_created", {
                "snapshot_id": snap_id, "label": "War Room Urgence",
                "triggered_by": interaction.user.id,
            })
            await interaction.followup.send(
                f"💾 **Snapshot de sécurité créé avec succès !** (ID `#{snap_id}`)\n"
                f"• {total_channels} salons & {total_roles} rôles sauvegardés.\n"
                f"• En cas de dégâts, restaurez tout avec `/sentinel backup restore {snap_id}`.",
                ephemeral=True,
            )
        except Exception as e:
            logger.error("Erreur snapshot war room : %s", e)
            await interaction.followup.send(f"❌ Erreur lors du snapshot d'urgence : {e}", ephemeral=True)

    @discord.ui.button(label="📜 Rapport PDF", style=discord.ButtonStyle.secondary)
    async def report_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer(ephemeral=True)
        try:
            import io
            rows = await self.db.fetch_evidence_chain(self.guild.id)
            chain_valid, _ = await self.forensics_module.verify_chain(self.db, self.guild.id)
            pdf_bytes = self.forensics_module.build_pdf_report(
                self.guild.name, self.guild.id, rows, chain_valid, self.signing_key,
            )
            file = discord.File(io.BytesIO(pdf_bytes), filename=f"sentinel_forensic_{self.guild.id}.pdf")
            await interaction.followup.send(
                "📜 **Rapport forensique officiel généré et signé Ed25519 :**",
                file=file, ephemeral=True,
            )
        except Exception as e:
            logger.error("Erreur génération PDF war room : %s", e)
            await interaction.followup.send(f"❌ Erreur lors de la génération du rapport PDF : {e}", ephemeral=True)

    @discord.ui.button(label="✅ Clore l'incident", style=discord.ButtonStyle.success)
    async def close_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.append_evidence(self.guild.id, "warroom_closed", {"by": interaction.user.id})
        await self.db.close_warroom(interaction.channel.id)
        _active_channels.pop(self.guild.id, None)
        _timeline_messages.pop(self.guild.id, None)
        await interaction.response.send_message("War room clôturée. Le salon sera archivé dans 10s.")
        await interaction.channel.edit(name=f"closed-{interaction.channel.name}")



def _build_context_embed(payload: dict, similar_behavior, similar_style) -> discord.Embed:
    embed = discord.Embed(
        title="🚨 War Room activée — SENTINEL",
        description=(
            f"**Déclencheur** : `{payload.get('reason', 'risque critique')}`\n"
            f"**Utilisateur** : <@{payload.get('user_id', 0)}>\n"
            f"**Score** : `{payload.get('score', '?')}`"
        ),
        color=0xFF0000,
        timestamp=datetime.now(timezone.utc),
    )
    signals = payload.get("signals") or {}
    if signals:
        embed.add_field(name="Signaux (module 3)", value=f"```{json.dumps(signals, indent=2)[:900]}```", inline=False)

    if similar_behavior:
        embed.add_field(
            name="🧬 Comptes comportementalement proches (module 1)",
            value="\n".join(f"<@{r['user_id']}> — similarité {r['similarity']:.2f}" for r in similar_behavior),
            inline=False,
        )
    if similar_style:
        embed.add_field(
            name="✍️ Comptes stylométriquement proches (module 2)",
            value="\n".join(f"<@{r['user_id']}> — similarité {r['similarity']:.2f}" for r in similar_style),
            inline=False,
        )
    if "user_ids" in payload:
        embed.add_field(
            name="👥 Cluster de coordination (module 4)",
            value=", ".join(f"<@{u}>" for u in payload["user_ids"][:15]),
            inline=False,
        )

    embed.set_footer(text=f"evidence_hash={payload.get('evidence_hash', '?')[:24]}…")
    return embed


async def get_or_create_warroom_category(guild: discord.Guild, db, staff_role: discord.Role | None = None) -> discord.CategoryChannel | None:
    """Récupère la catégorie war room configurée pour CE serveur, ou en crée
    une par défaut si aucune n'a encore été choisie (première utilisation,
    sans passer par /sentinel setup) — c'est ce qui permet au bot de
    fonctionner correctement dès qu'il est invité sur un nouveau serveur,
    sans dépendre d'un ID de catégorie codé en dur dans .env."""
    category_id, _ = await db.get_guild_config(guild.id)
    cat = None
    if category_id:
        c = guild.get_channel(category_id)
        if isinstance(c, discord.CategoryChannel):
            cat = c
    if not cat:
        cat = discord.utils.get(guild.categories, name="bidabot-warrooms") or discord.utils.get(guild.categories, name="sentinel-warrooms")

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
    }
    if guild.me:
        overwrites[guild.me] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, manage_channels=True,
            manage_messages=True, read_message_history=True,
        )
    for role in guild.roles:
        if role == guild.default_role:
            continue
        if role.permissions.manage_messages or role.permissions.ban_members or role.permissions.administrator:
            overwrites[role] = discord.PermissionOverwrite(
                view_channel=True, send_messages=True, manage_messages=True, read_message_history=True,
            )
    roles_list: list[discord.Role] = []
    if staff_role:
        if isinstance(staff_role, (list, tuple, set)):
            roles_list = [r for r in staff_role if r]
        else:
            roles_list = [staff_role]

    for r in roles_list:
        overwrites[r] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, manage_messages=True, read_message_history=True,
        )

    if cat:
        # Met à jour les permissions pour masquer à @everyone et autoriser le rôle staff
        try:
            await cat.set_permissions(guild.default_role, view_channel=False)
            if guild.me:
                await cat.set_permissions(guild.me, view_channel=True, send_messages=True, manage_channels=True, manage_messages=True)
            for r in roles_list:
                await cat.set_permissions(r, view_channel=True, send_messages=True, manage_messages=True, read_message_history=True)
        except (discord.Forbidden, discord.HTTPException):
            pass
        if roles_list and hasattr(db, "set_staff_role"):
            await db.set_staff_role(guild.id, roles_list[0].id)
        return cat

    try:
        cat = await guild.create_category(
            "bidabot-warrooms", overwrites=overwrites,
            reason="BIDABOT — création automatique de la catégorie war room (module 9)",
        )
    except discord.Forbidden:
        logger.warning("Permissions insuffisantes pour créer la catégorie war room sur %s", guild.name)
        return None

    await db.set_warroom_category(guild.id, cat.id)
    if roles_list and hasattr(db, "set_staff_role"):
        await db.set_staff_role(guild.id, roles_list[0].id)
    return cat


async def open_warroom(payload: dict, *, bot, db, cache, bus, append_evidence,
                        lockdown_module, forensics_module, signing_key,
                        dry_run: bool, auto_release_seconds: int) -> discord.TextChannel | None:
    guild = bot.get_guild(payload["guild_id"])
    if not guild:
        return None

    # Vérifie si la war room en mémoire existe encore réellement sur Discord
    active_ch = _active_channels.get(guild.id)
    if active_ch:
        if guild.get_channel(active_ch.id):
            logger.info("War room déjà active sur %s : #%s", guild.name, active_ch.name)
            return active_ch
        _active_channels.pop(guild.id, None)

    # Nettoyage des salons fantômes enregistrés en base mais détruits sur Discord
    if hasattr(db, "get_open_warrooms"):
        try:
            open_rows = await db.get_open_warrooms()
            for r in open_rows:
                if r["guild_id"] == guild.id:
                    if not guild.get_channel(r["channel_id"]):
                        await db.close_warroom(r["channel_id"])
        except Exception as e:
            logger.debug("Erreur vérification war rooms DB : %s", e)

    if await db.active_warroom_count(guild.id) > 0:
        return _active_channels.get(guild.id)

    staff_role = None
    if hasattr(db, "get_staff_role"):
        staff_role_id = await db.get_staff_role(guild.id)
        if staff_role_id:
            staff_role = guild.get_role(staff_role_id)

    category = await get_or_create_warroom_category(guild, db, staff_role=staff_role)
    overwrites = {guild.default_role: discord.PermissionOverwrite(view_channel=False)}
    if guild.me:
        overwrites[guild.me] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, manage_channels=True,
            manage_messages=True, read_message_history=True,
        )
    for role in guild.roles:
        if role.permissions.manage_messages or role.permissions.ban_members or role.permissions.administrator:
            overwrites[role] = discord.PermissionOverwrite(
                view_channel=True, send_messages=True, manage_messages=True, read_message_history=True,
            )
    if staff_role:
        overwrites[staff_role] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, manage_messages=True, read_message_history=True,
        )

    try:
        channel = await guild.create_text_channel(
            f"🚨-warroom-{datetime.now(timezone.utc).strftime('%H%M%S')}",
            category=category, overwrites=overwrites,
            topic="War room auto-assemblée par SENTINEL — contexte complet en haut du salon.",
        )
    except discord.Forbidden:
        logger.warning("Permissions insuffisantes pour créer la war room sur %s", guild.name)
        return None

    _active_channels[guild.id] = channel
    await db.open_warroom(guild.id, channel.id, payload.get("reason", ""), payload.get("user_id"))

    similar_behavior = await db.find_similar_behavior(
        payload.get("user_id", 0), guild.id, threshold=0.85,
    ) if payload.get("user_id") else []
    similar_style = await db.find_similar_style(
        payload.get("user_id", 0), guild.id, threshold=0.90,
    ) if payload.get("user_id") else []

    embed = _build_context_embed(payload, similar_behavior, similar_style)
    view = WarRoomView(guild, db, cache, bus, append_evidence, lockdown_module,
                        dry_run, auto_release_seconds, signing_key, forensics_module)
    await channel.send(embed=embed, view=view)

    timeline_msg = await channel.send("📜 **Timeline live** — les nouveaux événements apparaîtront ici.")
    _timeline_messages[guild.id] = timeline_msg

    await append_evidence(guild.id, "warroom_opened", payload)
    logger.info("War room ouverte sur %s → #%s", guild.name, channel.name)
    return channel


async def append_timeline(guild_id: int, line: str) -> None:
    msg = _timeline_messages.get(guild_id)
    if not msg:
        return
    try:
        lines = msg.content.split("\n")
        lines.append(f"• {line}")
        # Préserve l'en-tête (ligne 0) et purge les plus anciens événements si dépassement de la limite Discord
        while len("\n".join(lines)) > 1900 and len(lines) > 2:
            lines.pop(1)
        await msg.edit(content="\n".join(lines))
    except (discord.NotFound, discord.HTTPException):
        pass
