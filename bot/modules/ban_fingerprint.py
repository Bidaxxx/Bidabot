"""
Module 16 — Reconnaissance de bannis qui reviennent.

Quand un membre est banni, SENTINEL copie ses vecteurs comportementaux
(fingerprint module 1) et stylométriques (module 2) dans une table dédiée
`banned_fingerprints`. Ces vecteurs survivent à la suppression du compte
dans `behavior_vectors`.

À chaque nouveau join, le module compare les vecteurs du nouvel arrivant
avec tous les fingerprints de bannis du serveur. Si la similarité dépasse
le seuil (défaut 0.88 comportemental ET 0.85 stylo), c'est un signal fort
qu'un banni revient avec un nouveau compte.

⚠️ Garanties RGPD :
- Les vecteurs stockés sont des représentations mathématiques non réversibles :
  on ne peut pas reconstruire le contenu des messages à partir d'un vecteur.
- La rétention maximale est configurable (settings.ban_fingerprint_retention_days,
  défaut 90 jours) — au-delà, les vecteurs sont supprimés automatiquement.
- Seuls les bannis (décision humaine explicite) ont leur fingerprint conservé,
  jamais les membres qui partent volontairement.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("sentinel.ban_fingerprint")

# Seuils de similarité : les deux doivent être dépassés pour un match confirmé.
# Un seul suffit pour un match "possible" (level WARNING vs CRITICAL).
BEHAVIOR_THRESHOLD_CONFIRMED = 0.88
STYLE_THRESHOLD_CONFIRMED    = 0.85
BEHAVIOR_THRESHOLD_POSSIBLE  = 0.80


async def on_member_ban(guild_id: int, user_id: int, db) -> bool:
    """
    Appelé dans on_member_ban (main.py).
    Copie behavior_vector + stylometry_profile du banni dans banned_fingerprints.
    Retourne True si au moins un vecteur a pu être copié.
    """
    behavior = await db.get_behavior_vector(user_id, guild_id)
    style = await db.get_stylometry_vector(user_id, guild_id)

    if not behavior and not style:
        logger.debug("Pas de vecteur à conserver pour le banni %s sur %s", user_id, guild_id)
        return False

    await db.store_banned_fingerprint(
        guild_id=guild_id,
        banned_user_id=user_id,
        behavior_vector=behavior,
        style_vector=style,
    )
    logger.info("Fingerprint du banni %s conservé sur %s", user_id, guild_id)
    return True


async def check_new_member(guild_id: int, user_id: int, db, bus, append_evidence) -> dict | None:
    """
    Appelé dans on_member_join, après que le behavior_vector du nouveau membre
    a été (potentiellement) initialisé.

    Retourne un dict de match si un banni probable est détecté, None sinon.
    """
    behavior = await db.get_behavior_vector(user_id, guild_id)
    style = await db.get_stylometry_vector(user_id, guild_id)

    # Pas encore assez de données pour ce membre (tout juste arrivé) → skip
    if not behavior and not style:
        return None

    matches = await db.find_banned_fingerprint_matches(
        guild_id=guild_id,
        behavior_vector=behavior,
        style_vector=style,
        behavior_threshold=BEHAVIOR_THRESHOLD_POSSIBLE,
        style_threshold=0.75,
        limit=3,
    )
    if not matches:
        return None

    best = matches[0]
    behavior_sim = float(best.get("behavior_similarity") or 0)
    style_sim = float(best.get("style_similarity") or 0)
    confirmed = (behavior_sim >= BEHAVIOR_THRESHOLD_CONFIRMED
                 and style_sim >= STYLE_THRESHOLD_CONFIRMED)

    result = {
        "guild_id": guild_id,
        "new_user_id": user_id,
        "banned_user_id": best["banned_user_id"],
        "behavior_similarity": round(behavior_sim, 3),
        "style_similarity": round(style_sim, 3),
        "confirmed": confirmed,
        "score": round(max(behavior_sim, style_sim), 3),
        "reason": "banni_similaire_confirme" if confirmed else "banni_similaire_possible",
        "signals": {
            "behavior_similarity": behavior_sim,
            "style_similarity": style_sim,
            "banned_user_id": best["banned_user_id"],
        },
    }

    entry = await append_evidence(guild_id, "ban_fingerprint_match", result)
    result["evidence_hash"] = entry["hash"]

    logger.warning(
        "[%s] Nouveau membre %s ressemble au banni %s — behavior=%.2f style=%.2f (%s)",
        guild_id, user_id, best["banned_user_id"], behavior_sim, style_sim,
        "CONFIRMÉ" if confirmed else "possible",
    )

    if confirmed:
        await bus.emit("risk_critical", result)
    else:
        await bus.emit("risk_suspect", result)

    return result
