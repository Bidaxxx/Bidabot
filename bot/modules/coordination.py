"""
Module 4 — Détection de coordination inauthentique.

Combine deux signaux déjà calculés par les modules 1 et 2 : si N comptes
rejoignent dans une même fenêtre courte ET que leurs vecteurs de
fingerprint/stylométrie sont anormalement proches entre eux (pas juste
proches d'un profil individuel), c'est le signal d'un raid orchestré
(scripts identiques, comptes créés en masse par le même opérateur) plutôt
que d'un pic de popularité organique.

Contrairement au prototype initial qui ne faisait que compter les joins,
ceci exploite pgvector pour chercher, PARMI les joiners récents, des
paires dont la similarité dépasse le seuil — un pic de joins légitime
(un post Reddit qui explose) n'aura pas cette cohérence comportementale.

Fix #4 : l'ancienne implémentation faisait N requêtes pgvector (une par
joiner), soit O(N²) requêtes sur un raid de 50 comptes. La nouvelle version
utilise une seule requête SQL avec auto-jointure sur behavior_vectors,
limitant la détection à une seule aller-retour DB quel que soit le nombre
de joiners.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("sentinel.coordination")


async def check_recent_joiners(guild_id: int, db, bus, append_evidence, *,
                                window_seconds: int, min_accounts: int,
                                similarity_threshold: float) -> dict | None:
    joiners = await db.recent_joiners(guild_id, window_seconds)
    if len(joiners) < min_accounts:
        return None

    joiner_ids = [r["user_id"] for r in joiners]

    # Fix #4 : une seule requête SQL au lieu de N requêtes pgvector.
    # find_correlated_pairs retourne toutes les paires (a, b) parmi les
    # joiners dont la similarité cosinus dépasse le seuil.
    correlated_pairs = await db.find_correlated_pairs(
        guild_id, joiner_ids, similarity_threshold
    )

    if not correlated_pairs:
        return None

    # Regroupe en un seul cluster (union des paires corrélées)
    involved = sorted({uid for pair in correlated_pairs for uid in pair["pair"]})
    if len(involved) < min_accounts:
        return None

    avg_similarity = sum(p["similarity"] for p in correlated_pairs) / len(correlated_pairs)

    await db.insert_coordination_flag(
        guild_id, involved, avg_similarity,
        f"{len(involved)} comptes joints en {window_seconds}s avec similarité comportementale moyenne {avg_similarity:.2f}",
    )
    entry = await append_evidence(guild_id, "coordination_detected", {
        "user_ids": involved, "avg_similarity": avg_similarity, "window_seconds": window_seconds,
    })

    payload = {
        "guild_id": guild_id,
        "user_id": involved[0],  # compte "représentatif" pour la war room
        "user_ids": involved,
        "score": min(1.0, avg_similarity + 0.1),
        "reason": "coordination_inauthentique",
        "signals": {"avg_similarity": avg_similarity, "cluster_size": len(involved)},
        "evidence_hash": entry["hash"],
    }
    await bus.emit("risk_critical", payload)
    return payload
