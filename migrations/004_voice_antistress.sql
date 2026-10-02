-- ═══════════════════════════════════════════════════════════════════════
-- SENTINEL — Migration 004 : Anti-Stresseur Vocal & Surveillance WebRTC
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS voice_antistress_config (
    guild_id    BIGINT NOT NULL,
    channel_id  BIGINT NOT NULL,
    max_ping_ms INT NOT NULL DEFAULT 250,
    auto_renew  BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (guild_id, channel_id)
);
