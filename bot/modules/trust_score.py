"""
Module 15 — Score de confiance du serveur.

Score global de 0 à 100 calculé périodiquement (toutes les heures par défaut,
et immédiatement après chaque incident majeur). Visible dans le dashboard
Discord (#bidabot-status) et via /bidabot trustscore.

Formule en 5 composantes (100 points au total) :

┌─────────────────────────────────────────────────────┬────────┐
│ Composante                                          │ Max    │
├─────────────────────────────────────────────────────┼────────┤
│ Ancienneté du serveur (>6 mois = plein score)       │  15 pts│
│ Ratio membres légitimes vs suspects (labels DB)     │  30 pts│
│ Incidents des 30 derniers jours (0 = plein score)   │  25 pts│
│ Absence de lockdown actif ou récent (<7j)           │  20 pts│
│ Santé forensique (chaîne non corrompue, dry-run off)│  10 pts│
└─────────────────────────────────────────────────────┴────────┘

Un serveur sain neuf sans incidents démarre autour de 55/100 (ancienneté
faible). Il monte à mesure que les membres sont labellisés "legit" et que le
temps passe sans incident.

L'historique est stocké en DB pour pouvoir tracer la courbe dans le dashboard.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger("sentinel.trust_score")

MAX_SCORE = 100


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


async def compute(guild_id: int, db, lockdown_module, forensics_module, guild=None) -> dict:
    """
    Calcule le score de confiance pour le serveur donné.
    `guild` (discord.Guild optionnel) permet de calculer la composante activité.
    Retourne un dict avec le score total et le détail par composante.
    """
    breakdown: dict[str, float] = {}

    # ── 1. Ancienneté du serveur (15 pts) ────────────────────────────
    age_days = await db.get_guild_age_days(guild_id)
    # Progression linéaire : 0 pt à 0 jours, 15 pts à 180+ jours
    age_score = _clamp(age_days / 180) * 15
    breakdown["age"] = round(age_score, 2)

    # ── 2. Ratio légitimes / suspects (30 pts) ────────────────────────
    label_stats = await db.get_label_stats(guild_id)
    legit = label_stats.get("legit", 0)
    raid = label_stats.get("raid", 0)
    unlabeled = label_stats.get("unlabeled", 0)
    total_scored = legit + raid + unlabeled

    if total_scored == 0:
        ratio_score = 15.0  # neutre si aucune donnée
    else:
        # Chaque label "raid" pénalise, "legit" booste, "unlabeled" est neutre
        ratio = (legit * 1.0 + unlabeled * 0.5 - raid * 2.0) / max(total_scored, 1)
        ratio_score = _clamp((ratio + 1) / 2) * 30
    breakdown["member_ratio"] = round(ratio_score, 2)

    # ── 3. Incidents des 30 derniers jours (25 pts) ───────────────────
    incidents_30d = await db.count_incidents_period(guild_id, days=30)
    # 0 incident → 25 pts, 10+ → 0 pt (décroissance exponentielle)
    incident_score = _clamp(1 - incidents_30d / 10) * 25
    breakdown["incidents_30d"] = round(incident_score, 2)
    breakdown["incidents_count"] = incidents_30d

    # ── 4. Absence de lockdown (20 pts) ──────────────────────────────
    lockdown_active = lockdown_module.is_active(guild_id)
    days_since_lockdown = await db.days_since_last_lockdown(guild_id)

    if lockdown_active:
        lockdown_score = 0.0
    elif days_since_lockdown is None:
        lockdown_score = 20.0  # jamais eu de lockdown
    else:
        # Remonte progressivement : 0 pt le jour même, 20 pts après 30 jours
        lockdown_score = _clamp(days_since_lockdown / 30) * 20
    breakdown["lockdown"] = round(lockdown_score, 2)

    # ── 5. Santé forensique (10 pts) ─────────────────────────────────
    chain_ok, _ = await forensics_module.verify_chain(db, guild_id)
    dry_run = await db.get_dry_run(guild_id)
    # Chaîne corrompue → 0. Dry-run actif → -2 (configuration incomplète).
    forensic_score = (8.0 if chain_ok else 0.0) + (0.0 if dry_run else 2.0)
    breakdown["forensic_health"] = round(forensic_score, 2)

    # ── 6. Activité saine (5 pts) ─────────────────────────────────────
    # Ancienneté moyenne des membres → communauté stable.
    # Ratio bots vs humains : trop de bots = serveur artificiel.
    if guild is not None:
        member_count = max(guild.member_count or 1, 1)
        now = datetime.now(timezone.utc)
        ages = [(now - m.joined_at).days for m in guild.members if m.joined_at]
        avg_age = sum(ages) / len(ages) if ages else 0
        age_pts = _clamp(avg_age / 30) * 2.5  # plein score si ancienneté moy > 30j
        bot_count = sum(1 for m in guild.members if m.bot)
        bot_ratio = bot_count / member_count
        bot_pts = _clamp(1 - bot_ratio * 5) * 2.5  # pénalité si > 20% bots
        activity_score = round(age_pts + bot_pts, 2)
    else:
        activity_score = 2.5  # neutre si guild non disponible
    breakdown["activity_health"] = activity_score

    total = sum(v for k, v in breakdown.items() if k != "incidents_count")
    total = round(_clamp(total, 0, MAX_SCORE), 1)

    result = {
        "score": total,
        "breakdown": breakdown,
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "grade": _grade(total),
    }

    await db.save_trust_score(guild_id, total, breakdown)
    logger.info("Score de confiance %s → %.1f/100 (%s)", guild_id, total, result["grade"])
    return result


def _grade(score: float) -> str:
    if score >= 85:  return "A — Excellent"
    if score >= 70:  return "B — Bon"
    if score >= 55:  return "C — Moyen"
    if score >= 40:  return "D — Faible"
    return "F — Critique"


def build_embed(result: dict, guild_name: str) -> dict:
    """Construit les paramètres d'un discord.Embed depuis le résultat de compute()."""
    score = result["score"]
    grade = result["grade"]
    b = result["breakdown"]

    color = (
        0x00CC66 if score >= 70 else
        0xFF9900 if score >= 40 else
        0xFF0000
    )

    def bar(value: float, max_val: float) -> str:
        filled = max(0, min(10, round(value / max(0.001, max_val) * 10)))
        return "█" * filled + "░" * (10 - filled)

    fields = [
        ("🏛️ Ancienneté (15 pts)",      f"{bar(b['age'], 15)} {b['age']:.1f}/15"),
        ("👥 Membres légitimes (30 pts)", f"{bar(b['member_ratio'], 30)} {b['member_ratio']:.1f}/30"),
        (f"🚨 Incidents 30j (25 pts) — {b['incidents_count']} incident(s)",
                                           f"{bar(b['incidents_30d'], 25)} {b['incidents_30d']:.1f}/25"),
        ("🔒 Historique lockdown (20 pts)", f"{bar(b['lockdown'], 20)} {b['lockdown']:.1f}/20"),
        ("🔗 Santé forensique (10 pts)",    f"{bar(b['forensic_health'], 10)} {b['forensic_health']:.1f}/10"),
        ("📊 Activité saine (5 pts)",       f"{bar(b.get('activity_health', 2.5), 5)} {b.get('activity_health', 2.5):.1f}/5"),
    ]

    return {
        "title": f"🛡️ Score de confiance — {guild_name}",
        "description": f"## **{score}/100** — {grade}",
        "color": color,
        "fields": fields,
        "footer": f"Calculé le {result['computed_at'][:19].replace('T', ' ')} UTC",
    }
