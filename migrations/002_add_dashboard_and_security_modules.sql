-- ═══════════════════════════════════════════════════════════════════════
-- SENTINEL — Migration 002
-- Ajout des colonnes et tables pour :
--   • Module 10 (anti-spam) : rien en DB, géré 100% Redis
--   • Module 11 (anti-scam) : rien en DB, les hits vont dans evidence_chain
--   • Module 12 (dashboard) : colonnes IDs des salons dans guilds
-- ═══════════════════════════════════════════════════════════════════════

-- Colonnes dashboard dans la table guilds
ALTER TABLE guilds
    ADD COLUMN IF NOT EXISTS dashboard_status_channel_id  BIGINT,
    ADD COLUMN IF NOT EXISTS dashboard_alerts_channel_id  BIGINT,
    ADD COLUMN IF NOT EXISTS admin_alerts_dm              BOOLEAN NOT NULL DEFAULT TRUE;

-- Index pour count_incidents_today (utilisé par le dashboard status)
-- Compte les entrées evidence_chain du jour dont event_type est un incident
CREATE INDEX IF NOT EXISTS evidence_chain_guild_ts_idx
    ON evidence_chain(guild_id, ts DESC);
