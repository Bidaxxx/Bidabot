"""
Module 2 — Stylométrie.

Signature de style réduite à 64 dimensions par feature hashing
(HashingVectorizer de scikit-learn, n-grammes de caractères 2-3, word
boundaries) : taille fixe indépendante du vocabulaire, stockable en
pgvector(64) et comparable par distance cosinus, comme module 1.

Complète le fingerprint comportemental (module 1) : deux comptes peuvent
avoir des horaires/rythmes différents (fingerprint) mais un style
d'écriture identique (stylométrie) -> signal fort de multi-compte ou
d'opérateur unique derrière plusieurs identités.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from sklearn.feature_extraction.text import HashingVectorizer

SIG_DIM = 64
REBUILD_EVERY = 8
BUFFER_SIZE = 40
MIN_CHARS_TOTAL = 120  # sous ce seuil, la signature est trop bruitée pour être fiable

_vectorizer = HashingVectorizer(
    n_features=SIG_DIM,
    analyzer="char_wb",
    ngram_range=(2, 3),
    norm="l2",
    alternate_sign=False,
)

_buffers: dict[tuple[int, int], deque] = defaultdict(lambda: deque(maxlen=BUFFER_SIZE))


def lexical_richness(texts: list[str]) -> float:
    words = " ".join(texts).lower().split()
    if not words:
        return 0.0
    return len(set(words)) / len(words)


def avg_sentence_length(texts: list[str]) -> float:
    sentences = []
    for t in texts:
        for part in t.replace("!", ".").replace("?", ".").split("."):
            part = part.strip()
            if part:
                sentences.append(part)
    if not sentences:
        return 0.0
    return sum(len(s.split()) for s in sentences) / len(sentences)


def build_signature(texts: list[str]) -> list[float] | None:
    joined_len = sum(len(t) for t in texts)
    if joined_len < MIN_CHARS_TOTAL:
        return None
    vec = _vectorizer.transform([" ".join(texts)]).toarray()[0]
    return vec.tolist()


async def record_message(db, user_id: int, guild_id: int, content: str) -> None:
    if not content or content.startswith(("!", "/")):  # ignore les commandes
        return

    key = (user_id, guild_id)
    buf = _buffers[key]
    buf.append(content)

    if len(buf) >= REBUILD_EVERY and len(buf) % REBUILD_EVERY == 0:
        texts = list(buf)
        sig = build_signature(texts)
        if sig is None:
            return
        await db.upsert_stylometry(
            user_id, guild_id, sig,
            lexical_richness(texts), avg_sentence_length(texts), len(texts),
        )
