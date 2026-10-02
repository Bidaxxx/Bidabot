-- ═══════════════════════════════════════════════════════════════════════
-- SENTINEL — Migration 001
-- À appliquer sur une base existante (créée avec le schema.sql original).
-- Pour une nouvelle installation, schema.sql suffit — ne pas jouer cette
-- migration en double (les ADD COLUMN IF NOT EXISTS sont idempotents).
-- ═══════════════════════════════════════════════════════════════════════

-- Fix : colonnes warroom_category_id et log_channel_id absentes du schema.sql
-- original, mais attendues par db.get_guild_config() et db.set_log_channel().
ALTER TABLE guilds
    ADD COLUMN IF NOT EXISTS warroom_category_id BIGINT,
    ADD COLUMN IF NOT EXISTS log_channel_id BIGINT;

-- Fix #3 : index sur warrooms(status) pour get_open_warrooms() appelé à chaque restart.
CREATE INDEX IF NOT EXISTS warrooms_status_idx ON warrooms(status) WHERE status = 'open';

-- Fix #4 : index sur join_events(user_id, guild_id) pour les requêtes de
-- nettoyage et la future suppression de données au départ d'un membre.
CREATE INDEX IF NOT EXISTS join_events_user_idx ON join_events(user_id, guild_id);

-- Fix : index TTL sur federation_nonces pour faciliter le nettoyage périodique.
CREATE INDEX IF NOT EXISTS federation_nonces_ts_idx ON federation_nonces(ts);
