-- ═══════════════════════════════════════════════════════════════════════
-- SENTINEL — Schéma PostgreSQL (pgvector requis)
-- ═══════════════════════════════════════════════════════════════════════
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS guilds (
    guild_id            BIGINT PRIMARY KEY,
    name                TEXT,
    dry_run             BOOLEAN NOT NULL DEFAULT TRUE,  -- lockdown en mode "log only" par défaut
    joined_at           TIMESTAMPTZ DEFAULT now(),
    -- Fix : colonnes manquantes dans le schéma original, utilisées par db.py
    warroom_category_id             BIGINT,   -- catégorie Discord pour les war rooms
    log_channel_id                  BIGINT,   -- salon de journal d'activité (optionnel)
    -- Module 12 — dashboard admin (sentinel-status / sentinel-alerts)
    dashboard_status_channel_id     BIGINT,   -- salon #sentinel-status
    dashboard_alerts_channel_id     BIGINT,   -- salon #sentinel-alerts
    admin_alerts_dm                 BOOLEAN NOT NULL DEFAULT TRUE,
    joined_bot_at                   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    discord_id          BIGINT NOT NULL,
    guild_id            BIGINT NOT NULL REFERENCES guilds(guild_id) ON DELETE CASCADE,
    account_age_days    INT,
    join_date           TIMESTAMPTZ,
    avatar_hash         TEXT,
    is_default_avatar   BOOLEAN,
    first_seen          TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (discord_id, guild_id)
);

-- Module 1 — fingerprint comportemental (vecteur 16D)
CREATE TABLE IF NOT EXISTS behavior_vectors (
    user_id         BIGINT NOT NULL,
    guild_id        BIGINT NOT NULL,
    vector          vector(16) NOT NULL,
    sample_count    INT NOT NULL DEFAULT 0,
    last_updated    TIMESTAMPTZ,
    PRIMARY KEY (user_id, guild_id)
);
CREATE INDEX IF NOT EXISTS behavior_vectors_ivfflat
    ON behavior_vectors USING ivfflat (vector vector_cosine_ops) WITH (lists = 100);

-- Module 2 — stylométrie (signature n-gram hashée 64D)
CREATE TABLE IF NOT EXISTS stylometry_profiles (
    user_id             BIGINT NOT NULL,
    guild_id            BIGINT NOT NULL,
    ngram_signature     vector(64) NOT NULL,
    lexical_richness    REAL,
    avg_sentence_len    REAL,
    sample_count        INT NOT NULL DEFAULT 0,
    last_updated        TIMESTAMPTZ,
    PRIMARY KEY (user_id, guild_id)
);
CREATE INDEX IF NOT EXISTS stylometry_ivfflat
    ON stylometry_profiles USING ivfflat (ngram_signature vector_cosine_ops) WITH (lists = 100);

-- Module 3 — scores de légitimité (+ labels pour ré-entraînement scikit-learn)
CREATE TABLE IF NOT EXISTS risk_scores (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL,
    guild_id        BIGINT NOT NULL,
    score           REAL NOT NULL,
    breakdown       JSONB NOT NULL,
    model_version   TEXT NOT NULL,
    label           TEXT CHECK (label IN ('raid', 'legit')),  -- NULL = non labellisé
    created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS risk_scores_user_idx ON risk_scores(user_id, guild_id);
CREATE INDEX IF NOT EXISTS risk_scores_label_idx ON risk_scores(label) WHERE label IS NOT NULL;

-- Historique des joins (vélocité persistée, indépendante de Redis)
CREATE TABLE IF NOT EXISTS join_events (
    id          BIGSERIAL PRIMARY KEY,
    guild_id    BIGINT NOT NULL,
    user_id     BIGINT NOT NULL,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS join_events_guild_ts_idx ON join_events(guild_id, ts DESC);
-- Index par user_id utile pour les requêtes de nettoyage (on_member_remove)
CREATE INDEX IF NOT EXISTS join_events_user_idx ON join_events(user_id, guild_id);

-- Module 5 — canary channels
CREATE TABLE IF NOT EXISTS canary_tokens (
    token           TEXT PRIMARY KEY,      -- identifiant opaque inséré dans le lien honeytoken
    guild_id        BIGINT NOT NULL,
    channel_id      BIGINT NOT NULL,
    label           TEXT,                  -- ex: "lien-leak-database-2024"
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS canary_hits (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT NOT NULL,
    channel_id      BIGINT NOT NULL,
    user_id         BIGINT,    -- NULL pour un clic sur lien honeytoken (visiteur non authentifié Discord)
    ip_hash         TEXT,      -- jamais l'IP en clair, toujours hashée+salée
    asn             TEXT,
    user_agent      TEXT,
    kind            TEXT NOT NULL DEFAULT 'channel_access', -- 'channel_access' | 'link_click'
    ts              TIMESTAMPTZ DEFAULT now()
);

-- Module 4 — coordination inauthentique
CREATE TABLE IF NOT EXISTS coordination_flags (
    id                  BIGSERIAL PRIMARY KEY,
    guild_id            BIGINT NOT NULL,
    user_ids            BIGINT[] NOT NULL,
    correlation_score   REAL,
    reason              TEXT,
    ts                  TIMESTAMPTZ DEFAULT now()
);

-- Module 6 — credential stuffing webhooks
CREATE TABLE IF NOT EXISTS credential_stuffing_events (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT NOT NULL,
    source_key      TEXT NOT NULL,   -- IP hashée si dispo, sinon "unknown"
    webhook_id      BIGINT,
    attempts        INT NOT NULL DEFAULT 1,
    window_start    TIMESTAMPTZ DEFAULT now()
);

-- Module 7 — chaîne de preuves forensiques
CREATE TABLE IF NOT EXISTS evidence_chain (
    id          BIGSERIAL PRIMARY KEY,
    guild_id    BIGINT NOT NULL,
    event_type  TEXT NOT NULL,
    data        JSONB NOT NULL,
    hash        TEXT NOT NULL,
    prev_hash   TEXT,
    signature   TEXT,             -- signature Ed25519 (clé privée du bot)
    ts_iso      TEXT NOT NULL,    -- chaîne EXACTE utilisée dans le calcul du hash (ne jamais reformater)
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()  -- même instant, pour le tri/l'affichage uniquement
);
CREATE INDEX IF NOT EXISTS evidence_chain_guild_idx ON evidence_chain(guild_id, id);

-- Module 8 — fédération inter-serveurs
CREATE TABLE IF NOT EXISTS federation_partners (
    id                  BIGSERIAL PRIMARY KEY,
    name                TEXT UNIQUE NOT NULL,
    guild_id            BIGINT,
    hmac_secret         TEXT NOT NULL,
    reliability_weight  REAL NOT NULL DEFAULT 0.5,
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS federation_reports (
    id                  BIGSERIAL PRIMARY KEY,
    hashed_user_id      TEXT NOT NULL,        -- HMAC(discord_id, pepper) — jamais l'ID brut
    source_partner_id   BIGINT REFERENCES federation_partners(id),
    risk_score          REAL,
    evidence_link       TEXT,
    reason              TEXT,
    received_at         TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS federation_reports_hash_idx ON federation_reports(hashed_user_id);

CREATE TABLE IF NOT EXISTS federation_nonces (
    nonce       TEXT PRIMARY KEY,
    partner_id  BIGINT NOT NULL,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Nettoyage automatique des nonces expirés (> 10 minutes) — évite une
-- croissance indéfinie de la table sur un déploiement très actif.
CREATE INDEX IF NOT EXISTS federation_nonces_ts_idx ON federation_nonces(ts);

-- Module 9 — war rooms
CREATE TABLE IF NOT EXISTS warrooms (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT NOT NULL,
    channel_id      BIGINT NOT NULL,
    trigger_reason  TEXT,
    trigger_user_id BIGINT,
    status          TEXT NOT NULL DEFAULT 'open',  -- open | closed
    opened_at       TIMESTAMPTZ DEFAULT now(),
    closed_at       TIMESTAMPTZ
);
-- Index pour get_open_warrooms() (fix #3)
CREATE INDEX IF NOT EXISTS warrooms_status_idx ON warrooms(status) WHERE status = 'open';

-- Module 3bis — état de lockdown persistant (survit à un restart du bot)
CREATE TABLE IF NOT EXISTS lockdown_state (
    guild_id        BIGINT PRIMARY KEY,
    active          BOOLEAN NOT NULL DEFAULT FALSE,
    triggered_at    TIMESTAMPTZ,
    reason          TEXT
);

-- Module Whitelist — rôles et membres de confiance immunisés
CREATE TABLE IF NOT EXISTS whitelist (
    guild_id        BIGINT NOT NULL,
    target_id       BIGINT NOT NULL,
    target_type     TEXT NOT NULL CHECK (target_type IN ('role', 'user')),
    created_at      TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (guild_id, target_id)
);
CREATE INDEX IF NOT EXISTS whitelist_guild_idx ON whitelist(guild_id);

-- Index pour count_incidents_today (utilisé par le dashboard status)
CREATE INDEX IF NOT EXISTS evidence_chain_guild_ts_idx ON evidence_chain(guild_id, ts DESC);

-- Index pour join_events
CREATE INDEX IF NOT EXISTS join_events_user_idx ON join_events(user_id, guild_id);

-- Module 14 — Quarantaine
CREATE TABLE IF NOT EXISTS quarantine_log (
    id          BIGSERIAL PRIMARY KEY,
    guild_id    BIGINT NOT NULL,
    user_id     BIGINT NOT NULL,
    action      TEXT NOT NULL,   -- 'quarantined' | 'quarantine_released' | 'banned_from_quarantine'
    reason      TEXT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS quarantine_log_guild_user_idx ON quarantine_log(guild_id, user_id, ts DESC);

-- Module 15 — Score de confiance
CREATE TABLE IF NOT EXISTS guild_trust_scores (
    id          BIGSERIAL PRIMARY KEY,
    guild_id    BIGINT NOT NULL,
    score       REAL NOT NULL,
    breakdown   JSONB NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS trust_scores_guild_idx ON guild_trust_scores(guild_id, computed_at DESC);

-- Module 16 — Fingerprints de bannis
CREATE TABLE IF NOT EXISTS banned_fingerprints (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT NOT NULL,
    banned_user_id  BIGINT NOT NULL,
    behavior_vector vector(16),
    style_vector    vector(64),
    banned_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS banned_fingerprints_guild_idx ON banned_fingerprints(guild_id, banned_at DESC);
CREATE INDEX IF NOT EXISTS banned_fingerprints_behavior_ivfflat
    ON banned_fingerprints USING ivfflat (behavior_vector vector_cosine_ops)
    WITH (lists = 50)
    WHERE behavior_vector IS NOT NULL;
CREATE INDEX IF NOT EXISTS banned_fingerprints_style_ivfflat
    ON banned_fingerprints USING ivfflat (style_vector vector_cosine_ops)
    WITH (lists = 50)
    WHERE style_vector IS NOT NULL;

-- Module 17 — Audit d'invitations
CREATE TABLE IF NOT EXISTS invite_usage (
    id          BIGSERIAL PRIMARY KEY,
    guild_id    BIGINT NOT NULL,
    user_id     BIGINT NOT NULL,
    invite_code TEXT,
    inviter_id  BIGINT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS invite_usage_guild_ts_idx ON invite_usage(guild_id, ts DESC);
CREATE INDEX IF NOT EXISTS invite_usage_code_idx ON invite_usage(invite_code, guild_id);

CREATE TABLE IF NOT EXISTS flagged_invites (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT NOT NULL,
    invite_code     TEXT NOT NULL,
    raid_ratio      REAL NOT NULL,
    auto_revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    flagged_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Module 22 — Anti-Stresseur Vocal
CREATE TABLE IF NOT EXISTS voice_antistress_config (
    guild_id    BIGINT NOT NULL,
    channel_id  BIGINT NOT NULL,
    max_ping_ms INT NOT NULL DEFAULT 250,
    auto_renew  BOOLEAN NOT NULL DEFAULT TRUE,
    check_interval_seconds INT NOT NULL DEFAULT 30,
    created_at  TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (guild_id, channel_id)
);

-- Module Snapshots & Disaster Recovery
CREATE TABLE IF NOT EXISTS guild_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT NOT NULL,
    label           TEXT NOT NULL DEFAULT 'Automatique',
    snapshot_data   JSONB NOT NULL,
    channels_count  INT NOT NULL DEFAULT 0,
    roles_count     INT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS guild_snapshots_guild_idx ON guild_snapshots(guild_id, created_at DESC);



