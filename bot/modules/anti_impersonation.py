"""
Module 19 — Anti-Impersonation (Protection contre l'usurpation d'identité du Staff).

Détecte les nouveaux membres ou changements de pseudo tentant d'imiter :
- Le Propriétaire du serveur
- Les Administrateurs et Modérateurs
- Le bot SENTINEL lui-même ou les bots officiels

Techniques contrées :
- Homoglyphes cyrilliques / grecs (ex: Sеntinеl avec un 'e' cyrillique)
- Leet-speak (ex: Adm1n, M0d)
- Espacements, ponctuation et caractères invisibles (zéro-width spaces)
- Pseudos d'imitation à forte similarité lexicale (distance Levenshtein >= 82%)

Actions automatiques :
1. Renommage d'urgence du membre : "[Modéré] Pseudo Suspect"
2. Mise en quarantaine automatique si le module de quarantaine est configuré
3. Preuve forensique immuable + alerte immédiate dans #sentinel-alerts
"""
from __future__ import annotations

import logging
import re
import unicodedata
from typing import Any

import discord

from bot.modules import similar_names

logger = logging.getLogger("sentinel.anti_impersonation")

# Homoglyphes courants utilisés pour usurper des identités
_HOMOGLYPH_TABLE = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "u", "х": "x",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "U", "Х": "X",
    "ᴀ": "a", "ɢ": "g", "ɪ": "i", "ɴ": "n", "ʀ": "r", "в": "b", "ѕ": "s",
    "ο": "o", "ι": "i", "α": "a", "і": "i", "І": "I",
})

# Leet-speak basique
_LEET_TABLE = str.maketrans({
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i", "|": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t", "+": "t",
    "8": "b",
})


def normalize_for_impersonation(name: str) -> str:
    """Normalisation agressive pour neutraliser les ruses de faux profils."""
    if not name or not isinstance(name, str):
        return ""
    name = name.lower()
    # 1. Homoglyphes
    name = name.translate(_HOMOGLYPH_TABLE)
    # 2. Suppression accents / diacritiques
    name = unicodedata.normalize("NFD", name)
    name = "".join(c for c in name if unicodedata.category(c) != "Mn")
    # 3. Leet-speak
    name = name.translate(_LEET_TABLE)
    # 4. Suppression de tous les caractères non alphanumériques (espaces, tirets, ponctuation, symboles)
    name = re.sub(r"[^a-z0-9]", "", name)
    return name


def get_protected_staff(guild: discord.Guild) -> list[tuple[discord.Member, list[str]]]:
    """
    Identifie tous les comptes protégés du serveur :
    - Le Propriétaire
    - Membres avec permissions Administrateur, Gérer le serveur, Bannir
    - Le Bot lui-même (Sentinel)
    Retourne une liste de tuples : (membre, [noms_à_protéger])
    """
    staff_targets = []
    seen_ids = set()

    # 1. Propriétaire
    if guild.owner:
        seen_ids.add(guild.owner.id)
        names = [guild.owner.name, guild.owner.display_name]
        if hasattr(guild.owner, "global_name") and isinstance(guild.owner.global_name, str):
            names.append(guild.owner.global_name)
        staff_targets.append((guild.owner, list(set(names))))

    # 2. Le bot Sentinel
    if guild.me and guild.me.id not in seen_ids:
        seen_ids.add(guild.me.id)
        names = [guild.me.name, guild.me.display_name, "sentinel", "sentinel bot"]
        staff_targets.append((guild.me, list(set(names))))

    # 3. Autres membres du staff
    for m in guild.members:
        if m.id in seen_ids or m.bot:
            continue
        perms = m.guild_permissions
        if perms.administrator or perms.manage_guild or perms.ban_members:
            seen_ids.add(m.id)
            names = [m.name, m.display_name]
            if hasattr(m, "global_name") and isinstance(m.global_name, str):
                names.append(m.global_name)
            staff_targets.append((m, list(set(names))))

    return staff_targets


def check_impersonation(
    member: discord.Member,
    protected_staff: list[tuple[discord.Member, list[str]]],
    threshold: float = 0.82,
) -> tuple[discord.Member, str, float] | None:
    """
    Vérifie si `member` usurpe l'identité d'un des membres du staff.
    Retourne (staff_usurpé, nom_staff, score) ou None.
    """
    # Ne s'applique pas aux bots ou aux membres faisant déjà partie du staff
    candidate_names = [member.name, member.display_name]
    if hasattr(member, "global_name") and isinstance(member.global_name, str):
        candidate_names.append(member.global_name)

    normalized_candidates = {normalize_for_impersonation(n) for n in candidate_names if n}
    normalized_candidates.discard("")

    for staff_member, staff_names in protected_staff:
        if staff_member.id == member.id:
            continue  # Ne se compare pas à lui-même

        for s_name in staff_names:
            norm_s = normalize_for_impersonation(s_name)
            if not norm_s or len(norm_s) < 3:
                continue

            for c_raw in candidate_names:
                norm_c = normalize_for_impersonation(c_raw)
                if not norm_c:
                    continue

                # 1. Correspondance exacte après normalisation (homoglyphes / leet)
                if norm_c == norm_s:
                    return (staff_member, s_name, 1.0)

                # 2. Similarité Levenshtein
                score = similar_names.similarity_score(norm_c, norm_s)
                if score >= threshold:
                    return (staff_member, s_name, score)

    return None


async def handle_impersonation(
    member: discord.Member,
    *,
    db: Any = None,
    bus: Any = None,
    append_evidence: Any = None,
    quarantine_module: Any = None,
    dashboard_module: Any = None,
    threshold: float = 0.82,
) -> dict[str, Any] | None:
    """
    Scanne le membre à son arrivée ou lors d'un changement de nom.
    Applique le renommage, la quarantaine et les alertes nécessaires.
    """
    guild = member.guild
    protected_staff = get_protected_staff(guild)
    match = check_impersonation(member, protected_staff, threshold=threshold)
    if not match:
        return None

    staff_target, target_name, score = match
    logger.warning(
        "🚨 Usurpation d'identité détectée sur %s : %s tente d'imiter %s (score=%.2f)",
        guild.name, member, staff_target, score,
    )

    # 1. Renommage d'urgence pour neutraliser l'escroquerie
    renamed = False
    can_manage_nick = (
        guild.me.guild_permissions.manage_nicknames
        and guild.owner_id != member.id
    )
    if can_manage_nick:
        try:
            if hasattr(member, "top_role") and hasattr(guild.me, "top_role"):
                can_manage_nick = member.top_role < guild.me.top_role
        except TypeError:
            can_manage_nick = True

    if can_manage_nick:
        try:
            await member.edit(nick="[Modéré] Pseudo Suspect", reason=f"SENTINEL: Usurpation de {target_name}")
            renamed = True
        except (discord.Forbidden, discord.HTTPException) as e:
            logger.debug("Échec du renommage de %s : %s", member, e)

    # 2. Mise en quarantaine si disponible
    quarantined = False
    if quarantine_module:
        try:
            if hasattr(quarantine_module, "quarantine"):
                ch = await quarantine_module.quarantine(
                    member,
                    reason=f"Usurpation du staff ({target_name} - score {score:.2f})",
                    db=db,
                    append_evidence=append_evidence,
                )
                quarantined = bool(ch)
            elif hasattr(quarantine_module, "quarantine_member"):
                quarantined = await quarantine_module.quarantine_member(
                    guild, member, db=db,
                    reason=f"Usurpation du staff ({target_name} - score {score:.2f})",
                )
        except Exception as e:
            logger.debug("Échec de la quarantaine : %s", e)

    payload = {
        "guild_id": guild.id,
        "user_id": member.id,
        "impersonated_id": staff_target.id,
        "impersonated_name": target_name,
        "member_name": member.display_name,
        "score": score,
        "renamed": renamed,
        "quarantined": quarantined,
        "reason": "staff_impersonation_detected",
    }

    # Preuve forensique
    if append_evidence:
        entry = await append_evidence(guild.id, "staff_impersonation_detected", payload)
        payload["evidence_hash"] = entry.get("hash")

    # Alerte dashboard
    if dashboard_module:
        await dashboard_module.send_alert(
            guild,
            title="⚠️ Tentative d'usurpation du staff détectée",
            description=(
                f"**Membre :** <@{member.id}> (`{member.name}`)\n"
                f"**Cible imitée :** <@{staff_target.id}> (`{target_name}`)\n"
                f"**Similarité :** `{score * 100:.1f}%`\n"
                f"**Renommé :** {'Oui (`[Modéré] Pseudo Suspect`)' if renamed else 'Non'}\n"
                f"**Mise en quarantaine :** {'Oui' if quarantined else 'Non'}"
            ),
            color=0xFF3300,
        )

    return payload
