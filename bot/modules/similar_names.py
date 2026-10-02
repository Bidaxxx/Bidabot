"""
Module 13 — Détection de noms similaires à l'arrivée.

Quand un nouveau membre rejoint, compare son pseudo aux pseudos des
membres ayant rejoint dans la même fenêtre (ex: 90 secondes).

Technique utilisée : distance de Levenshtein normalisée + comparaison
des formes "leet-speak" (a→@, e→3, i→1, o→0, s→5, etc.).

Exemples de noms détectés comme similaires :
  Alexis / Al3xis / Alexi5 / @lexis / Alexx
  RaidBot / Ra1dBot / RaidB0t

Si plusieurs comptes ont des noms très proches, c'est un signal fort de
raid coordonné — émis comme "risk_suspect" (pas critical immédiatement,
mais ça alimente le score global).
"""
from __future__ import annotations

import logging
import re
import unicodedata

logger = logging.getLogger("sentinel.similar_names")

# Table de normalisation leet-speak
_LEET_TABLE = str.maketrans({
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t",
    "+": "t",
    "8": "b",
    "6": "g",
})


def _normalize(name: str) -> str:
    """
    Normalise un pseudo pour comparaison :
    - minuscules
    - accents supprimés (é→e, ü→u, etc.)
    - leet-speak remplacé (3→e, 0→o, etc.)
    - caractères non-alphanumériques supprimés
    """
    name = name.lower()
    # Supprime les accents
    name = unicodedata.normalize("NFD", name)
    name = "".join(c for c in name if unicodedata.category(c) != "Mn")
    # Leet-speak
    name = name.translate(_LEET_TABLE)
    # Garde seulement les lettres et chiffres
    name = re.sub(r"[^a-z0-9]", "", name)
    return name


def _levenshtein(a: str, b: str) -> int:
    """Distance de Levenshtein entre deux chaînes."""
    if not a:
        return len(b)
    if not b:
        return len(a)
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]


def similarity_score(name_a: str, name_b: str) -> float:
    """
    Retourne un score de similarité entre 0.0 (complètement différent)
    et 1.0 (identique), après normalisation des deux noms.
    """
    a = _normalize(name_a)
    b = _normalize(name_b)
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    max_len = max(len(a), len(b))
    dist = _levenshtein(a, b)
    return round(1.0 - dist / max_len, 3)


def find_similar_names(
    new_name: str,
    existing_names: list[str],
    threshold: float = 0.75,
) -> list[tuple[str, float]]:
    """
    Compare `new_name` à une liste de noms existants.
    Retourne les noms dont la similarité >= threshold, triés par score desc.
    """
    results = []
    for name in existing_names:
        score = similarity_score(new_name, name)
        if score >= threshold:
            results.append((name, score))
    return sorted(results, key=lambda x: x[1], reverse=True)


async def check_new_member(
    member,  # discord.Member
    recent_names: list[str],
    *,
    threshold: float = 0.78,
    bus=None,
    append_evidence=None,
) -> list[tuple[str, float]]:
    """
    Appelé depuis on_member_join avec la liste des pseudos des membres
    ayant rejoint dans la même fenêtre temporelle.

    Si des similarités sont trouvées, émet un signal suspect sur le bus.
    """
    matches = find_similar_names(member.display_name, recent_names, threshold)
    if not matches:
        return []

    logger.info(
        "Noms similaires détectés pour %s sur %s : %s",
        member.display_name, member.guild.name,
        [(n, f"{s:.2f}") for n, s in matches],
    )

    if append_evidence:
        await append_evidence(member.guild.id, "similar_names_detected", {
            "user_id": member.id,
            "username": member.display_name,
            "similar_to": [{"name": n, "score": s} for n, s in matches],
        })

    return matches
