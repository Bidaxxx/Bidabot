"""Tests du module 3 — combinaison bayésienne et bascule vers scikit-learn."""
import random

from bot.modules.legitimacy import (
    LegitimacyScorer, bayes_combine, score_account_age, score_avatar, score_velocity,
)


def test_score_account_age_monotonic_with_age():
    # Plus le compte est vieux, plus le score de risque doit être BAS
    assert score_account_age(0, min_days=3) > score_account_age(1, min_days=3)
    assert score_account_age(1, min_days=3) > score_account_age(3, min_days=3)
    assert score_account_age(3, min_days=3) > score_account_age(30, min_days=3)


def test_score_avatar_default_is_riskier():
    assert score_avatar(is_default=True) > score_avatar(is_default=False)


def test_score_velocity_saturates_at_one():
    assert score_velocity(velocity=1000, threshold=8) == 1.0
    assert 0.0 <= score_velocity(velocity=4, threshold=8) <= 1.0


def test_bayes_combine_all_low_signals_gives_low_score():
    signals = {"a": 0.05, "b": 0.0, "c": 0.05, "d": 0.0}
    score = bayes_combine(signals, prior=0.1)
    assert score < 0.1


def test_bayes_combine_all_high_signals_gives_high_score():
    signals = {"a": 0.9, "b": 0.9, "c": 0.9, "d": 0.9}
    score = bayes_combine(signals, prior=0.1)
    assert score > 0.9


def test_scorer_cold_start_uses_bayes(tmp_path):
    scorer = LegitimacyScorer(
        model_path=str(tmp_path / "does_not_exist.joblib"),
        min_training_samples=40, account_age_min_days=3, join_velocity_threshold=8,
    )
    score, signals, version = scorer.score(
        account_age_days=0, is_default_avatar=True, join_velocity=20, messages_last_minute=15,
        has_badges=False, bio_or_status=None, username="normaluser",
    )
    assert version == "cold-start-bayes"
    assert score > 0.5  # compte tout neuf, avatar par défaut, vélocité et rafale élevées -> suspect
    assert set(signals.keys()) == {
        "account_age_score", "default_avatar_score", "join_velocity_score",
        "message_burst_score", "badge_score", "bio_score", "username_entropy_score",
    }


def test_scorer_badges_reduces_risk():
    from bot.modules.legitimacy import score_badges
    assert score_badges(has_badges=True) == 0.05
    assert score_badges(has_badges=False) == 0.0


def test_scorer_bio_phishing():
    from bot.modules.legitimacy import score_bio
    assert score_bio("Claim free nitro at bit.ly/test") == 0.85
    assert score_bio("Just a normal gamer bio") == 0.0


def test_scorer_username_entropy():
    from bot.modules.legitimacy import score_username_entropy
    assert score_username_entropy("bcdfgh123") == 0.70
    assert score_username_entropy("alexandre") == 0.0


def test_scorer_refuses_to_train_below_minimum(tmp_path):
    scorer = LegitimacyScorer(str(tmp_path / "m.joblib"), min_training_samples=40)
    report = scorer.retrain(X=[[0.1] * 7] * 10, y=[0] * 5 + [1] * 5)
    assert report is None  # 10 < 40


def test_scorer_refuses_to_train_on_single_class(tmp_path):
    scorer = LegitimacyScorer(str(tmp_path / "m.joblib"), min_training_samples=10)
    report = scorer.retrain(X=[[0.1] * 7] * 20, y=[0] * 20)
    assert report is None  # une seule classe représentée


def test_scorer_trains_and_switches_model(tmp_path):
    random.seed(42)
    scorer = LegitimacyScorer(str(tmp_path / "m.joblib"), min_training_samples=40)

    X, y = [], []
    for _ in range(60):
        # profil "légitime" : signaux bas
        X.append([random.uniform(0, 0.2) for _ in range(7)])
        y.append(0)
    for _ in range(60):
        # profil "raid" : signaux hauts
        X.append([random.uniform(0.7, 1.0) for _ in range(7)])
        y.append(1)

    report = scorer.retrain(X, y)
    assert report is not None
    assert scorer.model is not None
    assert scorer.model_version.startswith("logreg-")

    # Une fois entraîné, .score() doit utiliser le modèle, pas le fallback bayésien
    score, _, version = scorer.score(
        account_age_days=0, is_default_avatar=True, join_velocity=100, messages_last_minute=50,
        has_badges=False, bio_or_status=None, username="bot12345",
    )
    assert version == scorer.model_version
    assert score > 0.5  # profil clairement "raid" doit être détecté comme tel
