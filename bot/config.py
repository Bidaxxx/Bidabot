"""
Configuration centralisée de SENTINEL, chargée depuis les variables
d'environnement (voir .env.example). Tout ce qui est un secret (token,
pepper, clé de signature) passe par l'environnement, jamais en dur dans le code.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Thresholds(BaseSettings):
    account_age_min_days: int = 3
    join_velocity_per_minute: int = 8
    join_velocity_lockdown: int = 15
    legitimacy_score_suspect: float = 0.55
    legitimacy_score_critical: float = 0.80
    fingerprint_similarity_threshold: float = 0.85
    stylometry_similarity_threshold: float = 0.90
    coordination_window_seconds: int = 90
    coordination_min_accounts: int = 3
    lockdown_auto_release_seconds: int = 300
    credential_stuffing_window_seconds: int = 60
    credential_stuffing_max_attempts: int = 5
    # Module 10 — anti-spam
    antispam_messages_per_window: int = 5   # max messages dans la fenêtre
    antispam_window_seconds: int = 10       # durée de la fenêtre (secondes)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_nested_delimiter="__", extra="ignore")

    # Discord
    discord_token: str = "COLLE_TON_TOKEN_ICI"
    discord_client_id: str = ""
    discord_client_secret: str = ""
    discord_redirect_uri: str = ""

    # PostgreSQL
    database_url: str = "postgresql://sentinel:sentinel@localhost:5432/sentinel"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Sécurité / crypto
    hash_pepper: str = "change-moi-en-prod"        # pour les IP hashées (canary, credential stuffing)
    federation_pepper: str = "change-moi-aussi"     # pour hasher les discord_id envoyés en fédération
    signing_key_path: str = "models/sentinel_ed25519.pem"

    # Fédération (API HTTP séparée, voir federation_api/)
    federation_api_url: str = "http://localhost:8001"
    federation_hmac_max_skew_seconds: int = 120

    # Dashboard
    dashboard_password: str = "change-moi"
    dashboard_secret_key: str = "change-moi-aussi-stp"
    default_guild_id: int = 0  # guild affiché par défaut dans le dashboard (0 = non configuré)

    # ML
    legitimacy_model_path: str = "models/legitimacy_model.joblib"
    legitimacy_min_training_samples: int = 40

    # Whitelist — rôles de confiance qui bypassent l'analyse anti-spam/scam
    # Format : liste d'IDs séparés par des virgules dans le .env
    # Ex: TRUSTED_ROLE_IDS=123456789,987654321
    trusted_role_ids: list[int] = []

    # Intégrations Cyber-Défense Tiers
    virustotal_api_key: str = ""

    thresholds: Thresholds = Thresholds()


settings = Settings()
