"""Tests de la chaîne de hash SHA-256 (module 7) — pas de DB nécessaire,
on teste directement compute_chain_hash."""
from bot.crypto_utils import compute_chain_hash, hash_ip


def test_chain_is_deterministic():
    h1 = compute_chain_hash(None, "join", {"user_id": 42}, "2026-01-01T00:00:00+00:00")
    h2 = compute_chain_hash(None, "join", {"user_id": 42}, "2026-01-01T00:00:00+00:00")
    assert h1 == h2


def test_chain_changes_if_data_tampered():
    h1 = compute_chain_hash(None, "join", {"user_id": 42}, "2026-01-01T00:00:00+00:00")
    h2 = compute_chain_hash(None, "join", {"user_id": 43}, "2026-01-01T00:00:00+00:00")
    assert h1 != h2


def test_chain_links_to_previous_hash():
    h1 = compute_chain_hash(None, "join", {"user_id": 1}, "t0")
    h2 = compute_chain_hash(h1, "message", {"user_id": 1}, "t1")
    h2_bis = compute_chain_hash("some_other_hash", "message", {"user_id": 1}, "t1")
    assert h2 != h2_bis  # même data mais prev_hash différent -> hash différent


def test_full_chain_verification_detects_tampering():
    """Simule 3 preuves chaînées, puis un altération de la 2e -> la
    vérification doit détecter la rupture à partir de cette entrée."""
    events = [
        ("join", {"user_id": 1}, "t0"),
        ("message", {"user_id": 1, "content": "salut"}, "t1"),
        ("lockdown_triggered", {"reason": "raid"}, "t2"),
    ]

    chain = []
    prev = None
    for event_type, data, ts in events:
        h = compute_chain_hash(prev, event_type, data, ts)
        chain.append({"event_type": event_type, "data": data, "ts": ts, "hash": h, "prev_hash": prev})
        prev = h

    # Vérification normale : tout doit être valide
    prev = None
    for entry in chain:
        expected = compute_chain_hash(prev, entry["event_type"], entry["data"], entry["ts"])
        assert expected == entry["hash"]
        prev = entry["hash"]

    # On altère la donnée de la 2e entrée SANS recalculer son hash (= altération a posteriori)
    chain[1]["data"] = {"user_id": 1, "content": "message modifié"}

    prev = None
    broken_at = None
    for i, entry in enumerate(chain):
        expected = compute_chain_hash(prev, entry["event_type"], entry["data"], entry["ts"])
        if expected != entry["hash"]:
            broken_at = i
            break
        prev = entry["hash"]

    assert broken_at == 1


def test_hash_ip_never_reversible_and_stable():
    h1 = hash_ip("203.0.113.42", "pepper-a")
    h2 = hash_ip("203.0.113.42", "pepper-a")
    h3 = hash_ip("203.0.113.42", "pepper-b")
    assert h1 == h2               # même IP + même pepper -> même hash (permet la corrélation)
    assert h1 != h3                # pepper différent -> hash différent (pas de rainbow table cross-déploiement)
    assert "203.0.113.42" not in h1  # jamais l'IP en clair dans le résultat
