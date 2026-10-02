"""
Module 25 — Smart Gatekeeper (Sas d'Entrée Dynamique & Onboarding Intelligent).

Évalue le score de légitimité lors de l'arrivée d'un nouveau membre (on_member_join)
et applique un protocole d'onboarding adaptatif et progressif :

1. Score < 0.30 (Légitime / Confiance Élevée) :
   - Passage direct, zéro friction.
   - Attribution immédiate du rôle vérifié (gatekeeper_verified_role_id) si configuré.
   - Enregistrement de la preuve forensique "gatekeeper_pass_direct".

2. 0.30 <= Score < 0.70 (Suspect / Douteux) :
   - Sas de vérification interactif obligatoire.
   - Le membre ne reçoit pas le rôle vérifié immédiatement.
   - Déploiement d'un challenge interactif anti-script dans le salon de sas dédié
     ou par message direct sécurisé (GatekeeperChallengeView).
   - Cooldown anti-bot (minimum 2.5 secondes de temporisation avant clic).
   - Validation manuelle possible en 1 clic par le staff via #sentinel-alerts.

3. Score >= 0.70 (Critique / Attaque Avérée) :
   - Quarantaine automatique immédiate.
   - Révocation de tout accès public au serveur.
   - Alerte critique prioritaire dans #sentinel-alerts avec boutons d'action rapide
     (Bannir & Purger, Isoler, Inspecter profil).
"""
from __future__ import annotations

import logging
import time
from typing import Any

import discord

logger = logging.getLogger("sentinel.gatekeeper")


class GatekeeperChallengeView(discord.ui.View):
    """Bouton de challenge anti-bot pour les membres au profil suspect."""

    def __init__(
        self,
        target_user_id: int,
        verified_role_id: int | None,
        *,
        db: Any = None,
        append_evidence: Any = None,
        timeout: float = 600.0,
    ):
        super().__init__(timeout=timeout)
        self.target_user_id = target_user_id
        self.verified_role_id = verified_role_id
        self.db = db
        self.append_evidence = append_evidence
        self.created_at = time.time()

    @discord.ui.button(
        label="🛡️ Confirmer l'accès au serveur (Je suis humain)",
        style=discord.ButtonStyle.success,
        custom_id="gatekeeper_verify_action",
    )
    async def verify_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.target_user_id:
            await interaction.response.send_message(
                "❌ Ce défi de vérification est réservé au nouvel arrivant désigné.",
                ephemeral=True,
            )
            return

        elapsed = time.time() - self.created_at
        if elapsed < 2.5:
            # Réaction quasi-instantanée typique des scripts automatisés de raid
            await interaction.response.send_message(
                "⏱️ Veuillez patienter 2 secondes avant de cliquer (protection anti-script automatisé).",
                ephemeral=True,
            )
            return

        guild = interaction.guild
        if not guild:
            return

        if self.verified_role_id:
            role = guild.get_role(int(self.verified_role_id))
            if role:
                try:
                    await interaction.user.add_roles(
                        role,
                        reason="Smart Gatekeeper : Défi de vérification anti-bot validé avec succès",
                    )
                except discord.Forbidden:
                    logger.warning("Permissions insuffisantes pour attribuer le rôle vérifié sur %s", guild.name)
                    await interaction.response.send_message(
                        "⚠️ Le bot n'a pas la permission requise pour vous attribuer le rôle (hiérarchie des rôles). Contactez un modérateur.",
                        ephemeral=True,
                    )
                    return

        if self.append_evidence:
            await self.append_evidence(guild.id, "gatekeeper_challenge_completed", {
                "user_id": interaction.user.id,
                "elapsed_seconds": round(elapsed, 1),
            })

        button.disabled = True
        button.label = "Accès validé ✓"
        button.style = discord.ButtonStyle.secondary

        await interaction.response.edit_message(
            content=f"✅ Bienvenue {interaction.user.mention} ! Votre accès au serveur a été déverrouillé avec succès.",
            view=self,
        )


async def handle_new_member_gate(
    member: discord.Member,
    legitimacy_score: float,
    *,
    db: Any,
    append_evidence: Any,
    dashboard_module: Any = None,
    quarantine_module: Any = None,
) -> dict[str, Any]:
    """
    Point d'entrée du Smart Gatekeeper exécuté dans on_member_join.
    """
    guild = member.guild
    guild_cfg = await db.get_guild(guild.id)
    if not guild_cfg or not guild_cfg.get("gatekeeper_enabled", False):
        return {"status": "disabled", "score": legitimacy_score}

    verified_role_id = guild_cfg.get("gatekeeper_verified_role_id")
    channel_id = guild_cfg.get("gatekeeper_channel_id")

    # ── Tier 1 : Score < 0.30 -> Passage direct (Zéro friction) ────────
    if legitimacy_score < 0.30:
        if verified_role_id:
            role = guild.get_role(int(verified_role_id))
            if role:
                try:
                    await member.add_roles(
                        role,
                        reason=f"Smart Gatekeeper : Passage direct accordé (Score légitime: {legitimacy_score:.2f})",
                    )
                except discord.Forbidden:
                    logger.warning("Permissions insuffisantes pour attribuer le rôle vérifié sur %s", guild.name)

        if append_evidence:
            await append_evidence(guild.id, "gatekeeper_pass_direct", {
                "user_id": member.id,
                "user_name": str(member),
                "score": legitimacy_score,
            })

        logger.info(
            "🛡️ Smart Gatekeeper : Passage direct accordé à %s sur %s (score=%.2f)",
            member, guild.name, legitimacy_score,
        )
        return {"status": "passed_direct", "tier": "clean", "score": legitimacy_score}

    # ── Tier 2 : 0.30 <= Score < 0.70 -> Sas de vérification interactif ─
    if legitimacy_score < 0.70:
        logger.info(
            "🟡 Smart Gatekeeper : Sas de vérification activé pour %s sur %s (score=%.2f)",
            member, guild.name, legitimacy_score,
        )

        target_ch = None
        if channel_id:
            target_ch = guild.get_channel(int(channel_id))
        if not target_ch:
            for ch in guild.text_channels:
                if any(k in ch.name.lower() for k in ("verification", "sas", "bienvenue", "gatekeeper", "accueil")):
                    target_ch = ch
                    break

        challenge_view = GatekeeperChallengeView(
            target_user_id=member.id,
            verified_role_id=verified_role_id,
            db=db,
            append_evidence=append_evidence,
        )

        challenge_embed = discord.Embed(
            title="🛡️ Sas de Vérification de Sécurité — BIDABOT",
            description=(
                f"Bonjour {member.mention},\n\n"
                f"Pour assurer la sécurité du serveur, nos systèmes ont détecté un profil nécessitant une confirmation d'humanité "
                f"(`indice de risque: {legitimacy_score:.2f}`).\n\n"
                f"Cliquez sur le bouton ci-dessous pour déverrouiller votre accès au serveur :"
            ),
            color=0xFFAA00,
            timestamp=discord.utils.utcnow(),
        )
        challenge_embed.set_footer(text="BIDABOT Smart Gatekeeper — Protection anti-bot adaptative")

        msg_sent = False
        if target_ch and target_ch.permissions_for(guild.me).send_messages:
            try:
                await target_ch.send(
                    content=member.mention,
                    embed=challenge_embed,
                    view=challenge_view,
                )
                msg_sent = True
            except discord.HTTPException:
                pass

        if not msg_sent:
            try:
                await member.send(embed=challenge_embed, view=challenge_view)
                msg_sent = True
            except (discord.Forbidden, discord.HTTPException):
                pass

        if append_evidence:
            await append_evidence(guild.id, "gatekeeper_challenge_issued", {
                "user_id": member.id,
                "score": legitimacy_score,
                "channel_id": getattr(target_ch, "id", None),
                "delivered": msg_sent,
            })

        if dashboard_module:
            await dashboard_module.send_alert(
                guild,
                title="🟡 Sas de Vérification Déclenché",
                description=f"<@{member.id}> (`{member}`) a été orienté vers le sas de vérification automatique.",
                color=0xFFAA00,
                fields={
                    "Score de risque": f"`{legitimacy_score:.2f}` (Suspect)",
                    "Salon de sas": f"<#{target_ch.id}>" if target_ch else "DM Membre",
                },
                target_user_id=member.id,
                score_data={"score": legitimacy_score, "reason": "Smart Gatekeeper — Sas de vérification"},
                db=db,
                append_evidence=append_evidence,
                quarantine_module=quarantine_module,
            )

        return {"status": "challenge_sent", "tier": "suspect", "score": legitimacy_score, "delivered": msg_sent}

    # ── Tier 3 : Score >= 0.70 -> Quarantaine ou Rejet Immédiat ────────
    logger.warning(
        "🚨 Smart Gatekeeper : Score critique (%.2f) pour %s sur %s — Quarantaine immédiate",
        legitimacy_score, member, guild.name,
    )

    if quarantine_module:
        await quarantine_module.quarantine(
            member,
            reason=f"Smart Gatekeeper : Profil hautement suspect / raid (Score: {legitimacy_score:.2f})",
            db=db,
            append_evidence=append_evidence,
        )

    if append_evidence:
        await append_evidence(guild.id, "gatekeeper_quarantine_triggered", {
            "user_id": member.id,
            "score": legitimacy_score,
            "action": "quarantine",
        })

    if dashboard_module:
        await dashboard_module.send_alert(
            guild,
            title="🚨 Accès Refusé — Profil Critique Détecté",
            description=f"<@{member.id}> (`{member}`) a été intercepté par le Smart Gatekeeper et placé en quarantaine immédiate.",
            color=0xFF0000,
            fields={
                "Score de risque": f"`{legitimacy_score:.2f}` (Critique)",
                "Action appliquée": "**Quarantaine Automatique & Blocage des accès**",
            },
            target_user_id=member.id,
            score_data={"score": legitimacy_score, "reason": "Smart Gatekeeper — Score critique"},
            db=db,
            append_evidence=append_evidence,
            quarantine_module=quarantine_module,
        )

    return {"status": "quarantined", "tier": "critical", "score": legitimacy_score}
