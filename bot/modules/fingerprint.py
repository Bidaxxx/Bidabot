"""
Module 1 — Fingerprint comportemental.

Construit un vecteur 16D par utilisateur à partir d'une fenêtre glissante de
ses derniers messages (intervalles entre messages, heures d'activité,
longueur, ratio ponctuation/majuscules/emoji/liens...). Le stockage et la
comparaison se font via pgvector (opérateur `<=>`, distance cosinus) plutôt
qu'en boucle Python — voir bot/db.py pour le pourquoi.
"""
from __future__ import annotations

import statistics
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

DIM = 16
REBUILD_EVERY = 10       # reconstruit le profil tous les N messages
BUFFER_SIZE = 50         # fenêtre glissante de messages pris en compte

_buffers: dict[tuple[int, int], deque] = defaultdict(lambda: deque(maxlen=BUFFER_SIZE))


def _safe_stat(fn, seq, default: float = 0.0) -> float:
    try:
        return float(fn(seq))
    except Exception:
        return default


def build_vector(events: list[dict[str, Any]]) -> list[float]:
    if not events:
        return [0.0] * DIM

    times = [e["ts"] for e in events]
    intervals = [b - a for a, b in zip(times, times[1:])] or [0.0]
    hours = [datetime.fromtimestamp(t, tz=timezone.utc).hour for t in times]
    lengths = [len(e.get("content", "")) for e in events]
    sorted_hours = sorted(hours)

    return [
        _safe_stat(statistics.mean, intervals),
        _safe_stat(statistics.pstdev, intervals),
        _safe_stat(statistics.mean, hours),
        _safe_stat(statistics.pstdev, hours),
        _safe_stat(statistics.mean, lengths),
        _safe_stat(statistics.pstdev, lengths),
        _safe_stat(statistics.mean, [e.get("typing_ms", 0) for e in events]),
        _safe_stat(statistics.pstdev, [e.get("typing_ms", 0) for e in events]),
        _safe_stat(statistics.mean, [e.get("punct_ratio", 0) for e in events]),
        _safe_stat(statistics.mean, [e.get("caps_ratio", 0) for e in events]),
        _safe_stat(statistics.mean, [e.get("emoji_count", 0) for e in events]),
        _safe_stat(statistics.mean, [e.get("link_count", 0) for e in events]),
        float(len(events)),
        _safe_stat(statistics.median, intervals),
        float(sorted_hours[len(sorted_hours) // 4]) if sorted_hours else 0.0,
        float(sorted_hours[3 * len(sorted_hours) // 4]) if sorted_hours else 0.0,
    ]


def event_from_message(content: str, created_at_ts: float) -> dict[str, Any]:
    L = max(1, len(content))
    return {
        "ts": created_at_ts,
        "content": content,
        "typing_ms": 0,  # discord.py n'expose pas la durée de frappe côté bot ; branché à 0 sauf si un gateway custom la fournit
        "punct_ratio": sum(c in ".,;!?" for c in content) / L,
        "caps_ratio": sum(c.isupper() for c in content) / L,
        "emoji_count": sum((not c.isalnum()) and (not c.isspace()) for c in content),
        "link_count": content.count("http"),
    }


async def record_message(db, user_id: int, guild_id: int, content: str, created_at_ts: float) -> None:
    key = (user_id, guild_id)
    buf = _buffers[key]
    buf.append(event_from_message(content, created_at_ts))

    if len(buf) >= REBUILD_EVERY and len(buf) % REBUILD_EVERY == 0:
        vector = build_vector(list(buf))
        await db.upsert_behavior_vector(user_id, guild_id, vector, len(buf))
