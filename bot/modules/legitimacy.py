"""
Module 3 — Score de légitimité de compte.

Deux régimes, avec bascule automatique :
- Cold start (< legitimacy_min_training_samples labels) : combinaison
  bayésienne naïve des signaux, déterministe et explicable dès le jour 1.
- Modèle entraîné : régression logistique scikit-learn sur l'historique
  labellisé via /sentinel label raid|legit, rechargée à chaud après
  chaque ré-entraînement (bot/cogs/admin.py -> /sentinel train).

Le score reste toujours accompagné de son `breakdown` (les 4 signaux bruts)
et de son `model_version`, stockés en base -> traçabilité totale de pourquoi
un compte a été flaggé, exigée par les points RGPD de l'architecture.
"""
from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

logger = logging.getLogger("sentinel.legitimacy")

FEATURE_NAMES = [
    "account_age_score",
    "default_avatar_score",
    "join_velocity_score",
    "message_burst_score",
    "badge_score",
    "bio_score",
    "username_entropy_score",
]


def score_account_age(age_days: int, min_days: int) -> float:
    if age_days >= 30:
        return 0.05
    if age_days >= min_days:
        return 0.25
    if age_days >= 1:
        return 0.55
    return 0.85


def score_avatar(is_default: bool) -> float:
    return 0.7 if is_default else 0.0


def score_velocity(velocity: int, threshold: int) -> float:
    return min(1.0, velocity / max(1, threshold * 2))


def score_message_burst(messages_last_minute: int) -> float:
    return min(1.0, messages_last_minute / 10)


def score_badges(has_badges: bool, badge_count: int = 0) -> float:
    """Si l'utilisateur a des badges officiels Discord, le risque de bot jetable est quasi-nul."""
    if has_badges or badge_count > 0:
        return 0.05
    return 0.0  # neutre, ne pénalise pas un nouveau compte sans badge


_PHISHING_BIO_REGEX = re.compile(
    r"(free[\s_-]*nitro|nitro[\s_-]*free|gift[\s_-]*card|airdrop|crypto[\s_-]*claim|steam[\s_-]*gift|claim.*nitro|t\.me/|bit\.ly/|tinyurl|discord-nitro|discorcl|dlscord)",
    re.IGNORECASE,
)


def score_bio(bio_or_status: str | None) -> float:
    """Analyse la bio ou le statut personnalisé pour y détecter des URLs ou du phishing Nitro/crypto."""
    if not bio_or_status or not isinstance(bio_or_status, str):
        return 0.0
    if _PHISHING_BIO_REGEX.search(bio_or_status):
        return 0.85
    return 0.0


def calculate_shannon_entropy(text: str) -> float:
    """Calcule l'entropie de Shannon sur une chaîne."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def score_username_entropy(username: str) -> float:
    """Détecte les pseudos générés de façon pseudo-aléatoire (générateurs de tokens de raid)."""
    if not username or not isinstance(username, str):
        return 0.0
    u = username.lower()

    # 1. Longue suite de consonnes sans voyelle (ex: "bcdfgh", "zrkptw")
    consonant_streak = re.findall(r"[bcdfghjklmnpqrstvwxyz]{5,}", u)
    if consonant_streak and len(u) >= 6:
        return 0.70

    # 2. Entropie élevée + faible ratio de voyelles sur un nom moyen/long
    if len(u) >= 7:
        entropy = calculate_shannon_entropy(u)
        vowels = len(re.findall(r"[aeiouy]", u))
        vowel_ratio = vowels / len(u)
        if entropy >= 3.2 and vowel_ratio < 0.15:
            return 0.70

    return 0.0


def bayes_combine(signals: dict[str, float], prior: float = 0.1) -> float:
    """Combinaison bayésienne naïve : chaque signal met à jour un prior
    commun comme une vraisemblance indépendante. Simple, transparent,
    suffisant tant qu'on n'a pas assez de labels pour entraîner un modèle.

    Les signaux à 0.0 sont ignorés (non-informatifs) : un signal absent
    ne doit pas être interprété comme une preuve de légitimité. Par exemple,
    0 message burst = données insuffisantes, pas = compte légitime.
    """
    p = prior
    for s in signals.values():
        if s == 0.0:
            continue  # signal absent → neutre, n'influence pas le score
        s = min(max(s, 1e-6), 1 - 1e-6)
        p = (p * s) / (p * s + (1 - p) * (1 - s))
    return round(p, 4)


class LegitimacyScorer:
    def __init__(self, model_path: str, min_training_samples: int = 40,
                 account_age_min_days: int = 3, join_velocity_threshold: int = 8):
        self.model_path = Path(model_path)
        self.min_training_samples = min_training_samples
        self.account_age_min_days = account_age_min_days
        self.join_velocity_threshold = join_velocity_threshold
        self.model: Optional[LogisticRegression] = None
        self.model_version = "cold-start-bayes"
        self.model_features = FEATURE_NAMES
        self._try_load()

    def _try_load(self):
        if self.model_path.exists():
            try:
                data = joblib.load(self.model_path)
                self.model = data["model"]
                self.model_version = data["version"]
                self.model_features = data.get("features", [
                    "account_age_score", "default_avatar_score", "join_velocity_score", "message_burst_score"
                ])
                logger.info("Modèle de légitimité chargé (%s)", self.model_version)
            except Exception as e:
                logger.warning("Impossible de charger le modèle existant : %s", e)
                self.model = None

    def raw_signals(
        self,
        *,
        account_age_days: int,
        is_default_avatar: bool,
        join_velocity: int,
        messages_last_minute: int = 0,
        has_badges: bool = False,
        badge_count: int = 0,
        bio_or_status: Optional[str] = None,
        username: Optional[str] = None,
    ) -> dict:
        return {
            "account_age_score": score_account_age(account_age_days, self.account_age_min_days),
            "default_avatar_score": score_avatar(is_default_avatar),
            "join_velocity_score": score_velocity(join_velocity, self.join_velocity_threshold),
            "message_burst_score": score_message_burst(messages_last_minute),
            "badge_score": score_badges(has_badges, badge_count),
            "bio_score": score_bio(bio_or_status),
            "username_entropy_score": score_username_entropy(username or ""),
        }

    def score(self, **kwargs) -> tuple[float, dict, str]:
        signals = self.raw_signals(**kwargs)

        if self.model is not None:
            model_feats = getattr(self, "model_features", FEATURE_NAMES)
            vector = np.array([[signals.get(f, 0.0) for f in model_feats]])
            try:
                proba = float(self.model.predict_proba(vector)[0][1])
                return round(proba, 4), signals, self.model_version
            except Exception as e:
                logger.warning("Erreur d'inférence du modèle, fallback bayésien : %s", e)

        return bayes_combine(signals), signals, "cold-start-bayes"

    def retrain(self, X: list[list[float]], y: list[int]) -> Optional[dict]:
        if len(y) < self.min_training_samples:
            return None
        if len(set(y)) < 2:
            return None  # scikit-learn ne peut pas entraîner sur une seule classe

        X_arr, y_arr = np.array(X), np.array(y)
        X_train, X_test, y_train, y_test = train_test_split(
            X_arr, y_arr, test_size=0.2, random_state=42, stratify=y_arr
        )
        model = LogisticRegression(class_weight="balanced", max_iter=1000)
        model.fit(X_train, y_train)
        report = classification_report(y_test, model.predict(X_test), output_dict=True, zero_division=0)

        version = f"logreg-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": model, "version": version, "features": FEATURE_NAMES}, self.model_path)

        self.model = model
        self.model_version = version
        self.model_features = FEATURE_NAMES
        logger.info("Modèle réentraîné : %s (%d échantillons)", version, len(y))
        return report


async def auto_train_job(db, scorer: LegitimacyScorer, append_evidence=None) -> Optional[dict]:
    """
    Tâche automatique d'auto-apprentissage ML (Module 3 - Auto-Training) :
    1. Auto-labellise les membres bannis comme 'raid' s'ils avaient un score non labellisé.
    2. Auto-labellise les membres fiables et anciens comme 'legit'.
    3. Réentraîne le modèle Scikit-Learn et recharge à chaud sans redémarrer le bot.
    """
    try:
        if not hasattr(db, "pool") or not db.pool:
            return None

        # Auto-labellisation des comptes bannis confirmés
        await db.pool.execute(
            """UPDATE risk_scores r
               SET label = 'raid'
               FROM banned_fingerprints b
               WHERE r.user_id = b.banned_user_id AND r.guild_id = b.guild_id AND r.label IS NULL"""
        )
        # Auto-labellisation des membres anciens et sains
        await db.pool.execute(
            """UPDATE risk_scores r
               SET label = 'legit'
               FROM users u
               WHERE r.user_id = u.discord_id AND r.guild_id = u.guild_id
                 AND u.account_age_days >= 30 AND r.score < 0.25 AND r.label IS NULL"""
        )

        X, y = await db.fetch_training_data()
        if len(y) < scorer.min_training_samples:
            logger.info("Auto-apprentissage ML : échantillons insuffisants (%d/%d)", len(y), scorer.min_training_samples)
            return None

        report = scorer.retrain(X, y)
        if report:
            logger.info("🧠 Auto-apprentissage ML réussi ! Nouvelle version : %s (Échantillons : %d)", scorer.model_version, len(y))
        return report
    except Exception as e:
        logger.warning("Erreur lors de l'auto-apprentissage ML : %s", e)
        return None
