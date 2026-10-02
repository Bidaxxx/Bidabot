"""Tests des modules 1 (fingerprint) et 2 (stylométrie) — construction de
vecteurs et similarité, sans DB."""
import numpy as np

from bot.modules.fingerprint import build_vector, event_from_message, DIM
from bot.modules.stylometry import build_signature, lexical_richness, avg_sentence_length, SIG_DIM


def _cosine(a, b):
    a, b = np.array(a), np.array(b)
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    return float(np.dot(a, b) / (na * nb)) if na and nb else 0.0


def test_build_vector_empty_returns_zeros():
    assert build_vector([]) == [0.0] * DIM


def test_build_vector_has_correct_dimension():
    events = [event_from_message(f"message {i}", 1000.0 + i * 5) for i in range(20)]
    vec = build_vector(events)
    assert len(vec) == DIM
    assert all(isinstance(x, float) for x in vec)


def test_similar_rhythms_produce_similar_vectors():
    """Deux comptes qui postent au même rythme (toutes les 5s, même heure,
    messages courts) doivent avoir des vecteurs proches — c'est la base de
    la détection de coordination (module 4)."""
    events_a = [event_from_message("hey", 1_700_000_000.0 + i * 5) for i in range(20)]
    events_b = [event_from_message("yo", 1_700_000_100.0 + i * 5) for i in range(20)]  # décalé de 100s, même cadence
    vec_a, vec_b = build_vector(events_a), build_vector(events_b)

    events_c = [event_from_message(
        "un message beaucoup plus long avec plein de mots différents pour changer le profil",
        1_700_000_000.0 + i * 600) for i in range(20)]  # rythme très différent (toutes les 10 min)
    vec_c = build_vector(events_c)

    sim_ab = _cosine(vec_a, vec_b)
    sim_ac = _cosine(vec_a, vec_c)
    assert sim_ab > sim_ac  # A et B (même cadence) plus proches que A et C (cadence différente)


def test_stylometry_signature_requires_minimum_text():
    assert build_signature(["salut"]) is None  # trop court (< MIN_CHARS_TOTAL)


def test_stylometry_signature_has_correct_dimension():
    texts = ["Ceci est un message de test assez long pour dépasser le seuil minimum."] * 3
    sig = build_signature(texts)
    assert sig is not None
    assert len(sig) == SIG_DIM


def test_stylometry_same_author_style_is_more_similar_than_different_style():
    author_a_texts = [
        "Salut tout le monde, comment ça va aujourd'hui ? J'espère que vous allez bien !!",
        "Franchement je pense que c'est une super idée, on devrait essayer ça rapidement !!",
        "Hey, quelqu'un sait comment configurer ce truc ? J'ai un souci bizarre là...",
    ]
    author_a_texts_2 = [
        "Coucou la team, ça va aujourd'hui ? J'espère que tout roule bien pour vous !!",
        "Sérieusement je trouve que c'est une excellente idée, testons ça vite fait !!",
        "Yo, qqn sait comment paramétrer ce machin ? J'ai un problème étrange ici...",
    ]
    author_b_texts = [
        "Conformément à l'article 3 du règlement, la présente clause s'applique sans exception.",
        "Le rapport financier du troisième trimestre indique une croissance de douze pour cent.",
        "Veuillez trouver ci-joint le document requis pour la validation administrative.",
    ]

    sig_a1 = build_signature(author_a_texts)
    sig_a2 = build_signature(author_a_texts_2)
    sig_b = build_signature(author_b_texts)

    sim_same_author = _cosine(sig_a1, sig_a2)
    sim_diff_author = _cosine(sig_a1, sig_b)
    assert sim_same_author > sim_diff_author


def test_lexical_richness_bounds():
    assert 0.0 <= lexical_richness(["le chat le chat le chat"]) <= 1.0
    assert lexical_richness([]) == 0.0


def test_avg_sentence_length_positive():
    assert avg_sentence_length(["Ceci est une phrase. Et une autre encore ici."]) > 0
    assert avg_sentence_length([]) == 0.0
