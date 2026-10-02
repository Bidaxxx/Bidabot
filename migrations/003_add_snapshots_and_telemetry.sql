-- ═══════════════════════════════════════════════════════════════════════
-- SENTINEL — Migration 003 : Instantanés et Restauration Anti-Nuke
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS guild_snapshots (
    id                  BIGSERIAL PRIMARY KEY,
    guild_id            BIGINT NOT NULL REFERENCES guilds(guild_id) ON DELETE CASCADE,
    label               TEXT,
    snapshot_data       JSONB NOT NULL,
    channels_count      INT NOT NULL DEFAULT 0,
    roles_count         INT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS guild_snapshots_guild_idx ON guild_snapshots(guild_id, created_at DESC);
