-- ═══════════════════════════════════════════════════════════════════════
-- SENTINEL — Migration 003
-- Modules 14 (quarantaine), 15 (trust score), 16 (ban fingerprints),
-- 17 (audit d'invitations)
-- Idempotente : tous les CREATE sont IF NOT EXISTS / ADD COLUMN IF NOT EXISTS
-- ═══════════════════════════════════════════════════════════════════════

-- ── Module 14 — Quarantaine ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS quarantine_log (
    id          BIGSERIAL PRIMARY KEY,
    guild_id    BIGINT NOT NULL,
    user_id     BIGINT NOT NULL,
    action      TEXT NOT NULL,   -- 'quarantined' | 'quarantine_released' | 'banned_from_quarantine'
    reason      TEXT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS quarantine_log_guild_user_idx
    ON quarantine_log(guild_id, user_id, ts DESC);

-- ── Module 15 — Score de confiance ───────────────────────────────────

CREATE TABLE IF NOT EXISTS guild_trust_scores (
    id          BIGSERIAL PRIMARY KEY,
    guild_id    BIGINT NOT NULL,
    score       REAL NOT NULL,
    breakdown   JSONB NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS trust_scores_guild_idx
    ON guild_trust_scores(guild_id, computed_at DESC);

-- Colonne de date de join pour calculer l'ancienneté
ALTER TABLE guilds
    ADD COLUMN IF NOT EXISTS joined_bot_at TIMESTAMPTZ DEFAULT now();

-- ── Module 16 — Fingerprints de bannis ───────────────────────────────

CREATE TABLE IF NOT EXISTS banned_fingerprints (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT NOT NULL,
    banned_user_id  BIGINT NOT NULL,
    behavior_vector vector(16),     -- peut être NULL si pas encore calculé au moment du ban
    style_vector    vector(64),     -- idem
    banned_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ     -- NULL = rétention indéfinie, sinon nettoyage automatique
);
CREATE INDEX IF NOT EXISTS banned_fingerprints_guild_idx
    ON banned_fingerprints(guild_id, banned_at DESC);
CREATE INDEX IF NOT EXISTS banned_fingerprints_behavior_ivfflat
    ON banned_fingerprints USING ivfflat (behavior_vector vector_cosine_ops)
    WITH (lists = 50)
    WHERE behavior_vector IS NOT NULL;
CREATE INDEX IF NOT EXISTS banned_fingerprints_style_ivfflat
    ON banned_fingerprints USING ivfflat (style_vector vector_cosine_ops)
    WITH (lists = 50)
    WHERE style_vector IS NOT NULL;

-- ── Module 17 — Audit d'invitations ──────────────────────────────────

CREATE TABLE IF NOT EXISTS invite_usage (
    id          BIGSERIAL PRIMARY KEY,
    guild_id    BIGINT NOT NULL,
    user_id     BIGINT NOT NULL,
    invite_code TEXT,
    inviter_id  BIGINT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS invite_usage_guild_ts_idx
    ON invite_usage(guild_id, ts DESC);
CREATE INDEX IF NOT EXISTS invite_usage_code_idx
    ON invite_usage(invite_code, guild_id);

CREATE TABLE IF NOT EXISTS flagged_invites (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT NOT NULL,
    invite_code     TEXT NOT NULL,
    raid_ratio      REAL NOT NULL,
    auto_revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    flagged_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
