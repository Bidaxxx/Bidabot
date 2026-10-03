"""
Couche d'accès PostgreSQL, asyncpg + pgvector.

Pourquoi pgvector plutôt qu'une boucle Python de similarité cosinus (comme
dans le prototype initial) : l'opérateur `<=>` de pgvector calcule la
distance cosinus DANS la base, avec un index ivfflat -> passe à l'échelle
sur des dizaines de milliers de profils sans rapatrier tous les vecteurs
en mémoire à chaque comparaison.

Fix #5 : remplacement du pattern dangereux `$n || ' seconds'` par
`$n * interval '1 second'` dans toutes les requêtes SQL temporelles.

Fix #4 : ajout de find_correlated_pairs() — une seule requête SQL avec
auto-jointure sur behavior_vectors au lieu de N requêtes pgvector.

Fix #1/#3 : ajout de get_active_lockdowns() et get_open_warrooms() pour
permettre la restauration d'état après restart.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import asyncpg
from pgvector.asyncpg import register_vector

logger = logging.getLogger("sentinel.db")


class Database:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self):
        async def init_conn(conn):
            await register_vector(conn)

        try:
            self.pool = await asyncpg.create_pool(self.dsn, init=init_conn, min_size=2, max_size=10)
        except Exception:
            if "@postgres:" in self.dsn:
                fallback_dsn = self.dsn.replace("@postgres:", "@127.0.0.1:")
                self.pool = await asyncpg.create_pool(fallback_dsn, init=init_conn, min_size=2, max_size=10)
            else:
                raise
        try:
            async with self.pool.acquire() as conn:
                await conn.execute("""
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS staff_role_id BIGINT;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS dashboard_status_channel_id BIGINT;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS dashboard_alerts_channel_id BIGINT;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS anti_scam_enabled BOOLEAN NOT NULL DEFAULT TRUE;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS anti_spam_enabled BOOLEAN NOT NULL DEFAULT TRUE;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS anti_ghostping_enabled BOOLEAN NOT NULL DEFAULT TRUE;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS anti_nuke_enabled BOOLEAN NOT NULL DEFAULT TRUE;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS anti_impersonation_enabled BOOLEAN NOT NULL DEFAULT TRUE;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS auto_quarantine_enabled BOOLEAN NOT NULL DEFAULT FALSE;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS raid_sensitivity TEXT NOT NULL DEFAULT 'medium';
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS gatekeeper_enabled BOOLEAN NOT NULL DEFAULT FALSE;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS gatekeeper_verified_role_id BIGINT;
                    ALTER TABLE guilds ADD COLUMN IF NOT EXISTS gatekeeper_channel_id BIGINT;
                    CREATE TABLE IF NOT EXISTS whitelist (
                        guild_id BIGINT NOT NULL,
                        target_id BIGINT NOT NULL,
                        target_type TEXT NOT NULL,
                        created_at TIMESTAMPTZ DEFAULT now(),
                        PRIMARY KEY (guild_id, target_id)
                    );
                    CREATE TABLE IF NOT EXISTS voice_antistress_config (
                        guild_id BIGINT NOT NULL,
                        channel_id BIGINT NOT NULL,
                        max_ping_ms INT NOT NULL DEFAULT 250,
                        auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
                        check_interval_seconds INT NOT NULL DEFAULT 30,
                        created_at TIMESTAMPTZ DEFAULT now(),
                        PRIMARY KEY (guild_id, channel_id)
                    );
                    ALTER TABLE voice_antistress_config ADD COLUMN IF NOT EXISTS check_interval_seconds INT NOT NULL DEFAULT 30;
                    CREATE TABLE IF NOT EXISTS guild_snapshots (
                        id BIGSERIAL PRIMARY KEY,
                        guild_id BIGINT NOT NULL,
                        label TEXT NOT NULL DEFAULT 'Automatique',
                        snapshot_data JSONB NOT NULL,
                        channels_count INT NOT NULL DEFAULT 0,
                        roles_count INT NOT NULL DEFAULT 0,
                        created_at TIMESTAMPTZ DEFAULT now()
                    );
                    CREATE INDEX IF NOT EXISTS guild_snapshots_guild_idx ON guild_snapshots(guild_id, created_at DESC);
                """)
        except Exception as e:
            logger.warning("Migration des colonnes/tables ignorée ou échouée : %s", e)

    async def close(self):
        if self.pool:
            await self.pool.close()

    # ── Whitelist (rôles & membres immunisés) ──────────────────────────

    async def add_whitelist(self, guild_id: int, target_id: int, target_type: str):
        await self.pool.execute(
            """INSERT INTO whitelist (guild_id, target_id, target_type)
               VALUES ($1, $2, $3)
               ON CONFLICT (guild_id, target_id) DO NOTHING""",
            guild_id, target_id, target_type,
        )

    async def remove_whitelist(self, guild_id: int, target_id: int) -> bool:
        res = await self.pool.execute(
            "DELETE FROM whitelist WHERE guild_id = $1 AND target_id = $2",
            guild_id, target_id,
        )
        return res.endswith("1")

    async def get_whitelist(self, guild_id: int) -> list[dict]:
        rows = await self.pool.fetch(
            "SELECT target_id, target_type, created_at FROM whitelist WHERE guild_id = $1 ORDER BY created_at ASC",
            guild_id,
        )
        return [dict(r) for r in rows]

    async def is_whitelisted(self, guild_id: int, user_id: int, role_ids: list[int] | None = None) -> bool:
        targets = [user_id]
        if role_ids:
            targets.extend(role_ids)
        row = await self.pool.fetchrow(
            "SELECT 1 FROM whitelist WHERE guild_id = $1 AND target_id = ANY($2::bigint[]) LIMIT 1",
            guild_id, targets,
        )
        return row is not None

    # ── Guilds / users ────────────────────────────────────────────────

    async def ensure_guild(self, guild_id: int, name: str):
        await self.pool.execute(
            "INSERT INTO guilds (guild_id, name) VALUES ($1, $2) "
            "ON CONFLICT (guild_id) DO UPDATE SET name = EXCLUDED.name",
            guild_id, name,
        )

    async def get_dry_run(self, guild_id: int) -> bool:
        row = await self.pool.fetchrow("SELECT dry_run FROM guilds WHERE guild_id = $1", guild_id)
        return bool(row["dry_run"]) if row else True

    async def set_dry_run(self, guild_id: int, dry_run: bool):
        await self.pool.execute("UPDATE guilds SET dry_run = $1 WHERE guild_id = $2", dry_run, guild_id)

    async def get_guild_config(self, guild_id: int):
        """Retourne (warroom_category_id, log_channel_id), chacun potentiellement
        NULL si pas encore configuré (voir /sentinel setup)."""
        row = await self.pool.fetchrow(
            "SELECT warroom_category_id, log_channel_id FROM guilds WHERE guild_id = $1", guild_id
        )
        if not row:
            return None, None
        return row["warroom_category_id"], row["log_channel_id"]

    async def set_warroom_category(self, guild_id: int, channel_id: int):
        await self.pool.execute(
            "UPDATE guilds SET warroom_category_id = $1 WHERE guild_id = $2", channel_id, guild_id
        )

    async def set_log_channel(self, guild_id: int, channel_id: int):
        await self.pool.execute(
            "UPDATE guilds SET log_channel_id = $1 WHERE guild_id = $2", channel_id, guild_id
        )

    async def set_dashboard_channels(self, guild_id: int, status_channel_id: int, alerts_channel_id: int):
        await self.pool.execute(
            """UPDATE guilds SET dashboard_status_channel_id = $1, dashboard_alerts_channel_id = $2
               WHERE guild_id = $3""",
            status_channel_id, alerts_channel_id, guild_id,
        )

    async def get_dashboard_channels(self) -> list[dict]:
        rows = await self.pool.fetch(
            """SELECT guild_id, dashboard_status_channel_id AS status_channel_id,
                      dashboard_alerts_channel_id AS alerts_channel_id
               FROM guilds
               WHERE dashboard_status_channel_id IS NOT NULL AND dashboard_alerts_channel_id IS NOT NULL"""
        )
        return [dict(r) for r in rows]

    async def set_staff_role(self, guild_id: int, role_id: int | None):
        await self.pool.execute(
            "UPDATE guilds SET staff_role_id = $1 WHERE guild_id = $2", role_id, guild_id
        )

    async def get_staff_role(self, guild_id: int) -> int | None:
        row = await self.pool.fetchrow(
            "SELECT staff_role_id FROM guilds WHERE guild_id = $1", guild_id
        )
        return int(row["staff_role_id"]) if row and row["staff_role_id"] else None

    async def get_all_guilds(self) -> list[dict]:
        rows = await self.pool.fetch(
            """SELECT guild_id, name, dry_run, joined_at,
                      anti_scam_enabled, anti_spam_enabled, anti_ghostping_enabled,
                      anti_nuke_enabled, anti_impersonation_enabled, auto_quarantine_enabled,
                      raid_sensitivity
               FROM guilds ORDER BY name ASC"""
        )
        return [dict(r) for r in rows]

    async def get_guild(self, guild_id: int) -> dict | None:
        row = await self.pool.fetchrow(
            "SELECT * FROM guilds WHERE guild_id = $1", guild_id
        )
        return dict(row) if row else None

    async def update_guild_settings(self, guild_id: int, **kwargs):
        allowed = {
            "dry_run", "anti_scam_enabled", "anti_spam_enabled",
            "anti_ghostping_enabled", "anti_nuke_enabled",
            "anti_impersonation_enabled", "auto_quarantine_enabled",
            "raid_sensitivity", "log_channel_id", "staff_role_id",
            "gatekeeper_enabled", "gatekeeper_verified_role_id", "gatekeeper_channel_id",
        }
        updates = []
        values = [guild_id]
        idx = 2
        for k, v in kwargs.items():
            if k in allowed:
                updates.append(f"{k} = ${idx}")
                values.append(v)
                idx += 1
        if updates:
            sql = f"UPDATE guilds SET {', '.join(updates)} WHERE guild_id = $1"
            await self.pool.execute(sql, *values)

    async def get_recent_users_with_scores(self, guild_id: int, limit: int = 30) -> list[dict]:
        rows = await self.pool.fetch(
            """SELECT u.discord_id, u.account_age_days, u.join_date, u.is_default_avatar,
                      r.score, r.breakdown, r.label, r.created_at
               FROM users u
               LEFT JOIN LATERAL (
                   SELECT score, breakdown, label, created_at
                   FROM risk_scores
                   WHERE user_id = u.discord_id AND guild_id = u.guild_id
                   ORDER BY created_at DESC LIMIT 1
               ) r ON true
               WHERE u.guild_id = $1
               ORDER BY COALESCE(r.created_at, u.join_date, u.first_seen) DESC
               LIMIT $2""",
            guild_id, limit,
        )
        return [dict(r) for r in rows]

    async def get_active_quarantined_users(self, guild_id: int) -> list[dict]:
        rows = await self.pool.fetch(
            """SELECT q1.user_id, q1.reason, q1.ts
               FROM quarantine_log q1
               WHERE q1.guild_id = $1
                 AND q1.action = 'quarantined'
                 AND NOT EXISTS (
                     SELECT 1 FROM quarantine_log q2
                     WHERE q2.guild_id = q1.guild_id
                       AND q2.user_id = q1.user_id
                       AND q2.ts > q1.ts
                       AND q2.action IN ('quarantine_released', 'banned_from_quarantine')
                 )
               ORDER BY q1.ts DESC""",
            guild_id,
        )
        return [dict(r) for r in rows]

    async def get_recent_incidents(self, guild_id: int, limit: int = 25) -> list[dict]:
        rows = await self.pool.fetch(
            """SELECT id, event_type, data, hash, ts
               FROM evidence_chain
               WHERE guild_id = $1
               ORDER BY ts DESC
               LIMIT $2""",
            guild_id, limit,
        )
        return [dict(r) for r in rows]

    async def count_incidents_today(self, guild_id: int) -> int:
        row = await self.pool.fetchrow(
            """SELECT COUNT(*) AS c FROM evidence_chain
               WHERE guild_id = $1 AND ts >= CURRENT_DATE""",
            guild_id,
        )
        return int(row["c"]) if row else 0

    async def avg_risk_score_today(self, guild_id: int) -> float | None:
        row = await self.pool.fetchrow(
            """SELECT AVG(score) AS a FROM risk_scores
               WHERE guild_id = $1 AND created_at >= CURRENT_DATE""",
            guild_id,
        )
        return float(row["a"]) if row and row["a"] is not None else None

    async def upsert_user(self, discord_id: int, guild_id: int, account_age_days: int,
                           join_date: datetime, avatar_hash: str | None, is_default_avatar: bool):
        await self.pool.execute(
            """INSERT INTO users (discord_id, guild_id, account_age_days, join_date, avatar_hash, is_default_avatar)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT (discord_id, guild_id) DO UPDATE SET
                   account_age_days = EXCLUDED.account_age_days,
                   avatar_hash = EXCLUDED.avatar_hash,
                   is_default_avatar = EXCLUDED.is_default_avatar""",
            discord_id, guild_id, account_age_days, join_date, avatar_hash, is_default_avatar,
        )

    async def record_join(self, guild_id: int, user_id: int):
        await self.pool.execute(
            "INSERT INTO join_events (guild_id, user_id) VALUES ($1, $2)", guild_id, user_id
        )

    async def join_count_since(self, guild_id: int, seconds: int) -> int:
        # Fix #5 : utilise $n * interval '1 second' au lieu de $n || ' seconds'
        row = await self.pool.fetchrow(
            "SELECT COUNT(*) AS c FROM join_events WHERE guild_id = $1 AND ts > now() - $2 * interval '1 second'",
            guild_id, seconds,
        )
        return int(row["c"])

    # ── Module 3 — risk scores ───────────────────────────────────────

    async def insert_risk_score(self, user_id: int, guild_id: int, score: float,
                                 breakdown: dict, model_version: str) -> int:
        row = await self.pool.fetchrow(
            """INSERT INTO risk_scores (user_id, guild_id, score, breakdown, model_version)
               VALUES ($1, $2, $3, $4::jsonb, $5) RETURNING id""",
            user_id, guild_id, score, json.dumps(breakdown), model_version,
        )
        return int(row["id"])

    async def label_latest_score(self, user_id: int, guild_id: int, label: str) -> bool:
        row = await self.pool.fetchrow(
            """UPDATE risk_scores SET label = $3
               WHERE id = (SELECT id FROM risk_scores WHERE user_id=$1 AND guild_id=$2
                           ORDER BY created_at DESC LIMIT 1)
               RETURNING id""",
            user_id, guild_id, label,
        )
        return row is not None

    async def fetch_training_data(self) -> tuple[list[list[float]], list[int]]:
        rows = await self.pool.fetch(
            "SELECT breakdown, label FROM risk_scores WHERE label IS NOT NULL"
        )
        from bot.modules.legitimacy import FEATURE_NAMES  # import local pour éviter un cycle
        X, y = [], []
        for r in rows:
            breakdown = json.loads(r["breakdown"])
            try:
                X.append([breakdown[f] for f in FEATURE_NAMES])
                y.append(1 if r["label"] == "raid" else 0)
            except KeyError:
                continue
        return X, y

    # ── Module 1 — fingerprint comportemental ────────────────────────

    async def upsert_behavior_vector(self, user_id: int, guild_id: int, vector: list[float], sample_count: int):
        await self.pool.execute(
            """INSERT INTO behavior_vectors (user_id, guild_id, vector, sample_count, last_updated)
               VALUES ($1, $2, $3, $4, now())
               ON CONFLICT (user_id, guild_id) DO UPDATE SET
                   vector = EXCLUDED.vector, sample_count = EXCLUDED.sample_count, last_updated = now()""",
            user_id, guild_id, vector, sample_count,
        )

    async def find_similar_behavior(self, user_id: int, guild_id: int, threshold: float, limit: int = 5):
        row = await self.pool.fetchrow(
            "SELECT vector FROM behavior_vectors WHERE user_id=$1 AND guild_id=$2", user_id, guild_id
        )
        if not row:
            return []
        return await self.pool.fetch(
            """SELECT user_id, 1 - (vector <=> $1) AS similarity
               FROM behavior_vectors
               WHERE guild_id = $2 AND user_id != $3
               AND 1 - (vector <=> $1) >= $4
               ORDER BY vector <=> $1 LIMIT $5""",
            row["vector"], guild_id, user_id, threshold, limit,
        )

    async def find_correlated_pairs(self, guild_id: int, user_ids: list[int],
                                     similarity_threshold: float) -> list[dict]:
        """Fix #4 — une seule requête SQL qui compare tous les joiners entre
        eux via une auto-jointure sur behavior_vectors, plutôt que N requêtes
        pgvector en boucle Python. Retourne la liste des paires corrélées avec
        leur similarité."""
        if len(user_ids) < 2:
            return []
        rows = await self.pool.fetch(
            """SELECT a.user_id AS uid_a, b.user_id AS uid_b,
                      1 - (a.vector <=> b.vector) AS similarity
               FROM behavior_vectors a
               JOIN behavior_vectors b ON b.guild_id = a.guild_id
                   AND b.user_id > a.user_id   -- évite les doublons (a,b) et (b,a)
               WHERE a.guild_id = $1
                 AND a.user_id = ANY($2::bigint[])
                 AND b.user_id = ANY($2::bigint[])
                 AND 1 - (a.vector <=> b.vector) >= $3""",
            guild_id, user_ids, similarity_threshold,
        )
        return [{"pair": (r["uid_a"], r["uid_b"]), "similarity": float(r["similarity"])} for r in rows]

    # ── Module 2 — stylométrie ────────────────────────────────────────

    async def upsert_stylometry(self, user_id: int, guild_id: int, signature: list[float],
                                 lexical_richness: float, avg_sentence_len: float, sample_count: int):
        await self.pool.execute(
            """INSERT INTO stylometry_profiles
                   (user_id, guild_id, ngram_signature, lexical_richness, avg_sentence_len, sample_count, last_updated)
               VALUES ($1, $2, $3, $4, $5, $6, now())
               ON CONFLICT (user_id, guild_id) DO UPDATE SET
                   ngram_signature = EXCLUDED.ngram_signature,
                   lexical_richness = EXCLUDED.lexical_richness,
                   avg_sentence_len = EXCLUDED.avg_sentence_len,
                   sample_count = EXCLUDED.sample_count, last_updated = now()""",
            user_id, guild_id, signature, lexical_richness, avg_sentence_len, sample_count,
        )

    async def find_similar_style(self, user_id: int, guild_id: int, threshold: float, limit: int = 5):
        row = await self.pool.fetchrow(
            "SELECT ngram_signature FROM stylometry_profiles WHERE user_id=$1 AND guild_id=$2", user_id, guild_id
        )
        if not row:
            return []
        return await self.pool.fetch(
            """SELECT user_id, 1 - (ngram_signature <=> $1) AS similarity
               FROM stylometry_profiles
               WHERE guild_id = $2 AND user_id != $3
               AND 1 - (ngram_signature <=> $1) >= $4
               ORDER BY ngram_signature <=> $1 LIMIT $5""",
            row["ngram_signature"], guild_id, user_id, threshold, limit,
        )

    # ── Module 4 — coordination ───────────────────────────────────────

    async def recent_joiners(self, guild_id: int, window_seconds: int):
        # Fix #5 : intervalle paramétré sans concaténation de chaîne
        return await self.pool.fetch(
            "SELECT DISTINCT user_id FROM join_events WHERE guild_id=$1 AND ts > now() - $2 * interval '1 second'",
            guild_id, window_seconds,
        )

    async def insert_coordination_flag(self, guild_id: int, user_ids: list[int], score: float, reason: str):
        await self.pool.execute(
            "INSERT INTO coordination_flags (guild_id, user_ids, correlation_score, reason) VALUES ($1, $2, $3, $4)",
            guild_id, user_ids, score, reason,
        )

    # ── Module 5 — canaries ───────────────────────────────────────────

    async def create_canary_token(self, token: str, guild_id: int, channel_id: int, label: str):
        await self.pool.execute(
            "INSERT INTO canary_tokens (token, guild_id, channel_id, label) VALUES ($1,$2,$3,$4)",
            token, guild_id, channel_id, label,
        )

    async def get_canary_token(self, token: str):
        return await self.pool.fetchrow("SELECT * FROM canary_tokens WHERE token=$1", token)

    async def insert_canary_hit(self, guild_id: int, channel_id: int, user_id: int | None,
                                 ip_hash: str | None, asn: str | None, user_agent: str | None, kind: str):
        await self.pool.execute(
            """INSERT INTO canary_hits (guild_id, channel_id, user_id, ip_hash, asn, user_agent, kind)
               VALUES ($1,$2,$3,$4,$5,$6,$7)""",
            guild_id, channel_id, user_id, ip_hash, asn, user_agent, kind,
        )

    # ── Module 6 — credential stuffing ────────────────────────────────

    async def insert_credential_stuffing_event(self, guild_id: int, source_key: str, webhook_id: int | None):
        await self.pool.execute(
            "INSERT INTO credential_stuffing_events (guild_id, source_key, webhook_id) VALUES ($1,$2,$3)",
            guild_id, source_key, webhook_id,
        )

    # ── Module 7 — chaîne de preuves ─────────────────────────────────

    async def last_evidence_hash(self, guild_id: int) -> str | None:
        row = await self.pool.fetchrow(
            "SELECT hash FROM evidence_chain WHERE guild_id=$1 ORDER BY id DESC LIMIT 1", guild_id
        )
        return row["hash"] if row else None

    async def insert_evidence(self, guild_id: int, event_type: str, data: dict,
                               hash_: str, prev_hash: str | None, signature: str, ts: str):
        ts_str = str(ts)
        if isinstance(ts, datetime.datetime):
            dt_val = ts
        else:
            try:
                dt_val = datetime.datetime.fromisoformat(ts_str)
            except Exception:
                dt_val = datetime.datetime.now(datetime.timezone.utc)

        row = await self.pool.fetchrow(
            """INSERT INTO evidence_chain (guild_id, event_type, data, hash, prev_hash, signature, ts_iso, ts)
               VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7,$8) RETURNING id""",
            guild_id, event_type, json.dumps(data, default=str), hash_, prev_hash, signature, ts_str, dt_val,
        )
        return int(row["id"])

    async def fetch_evidence_chain(self, guild_id: int):
        return await self.pool.fetch(
            "SELECT * FROM evidence_chain WHERE guild_id=$1 ORDER BY id ASC", guild_id
        )

    # ── Module 8 — fédération ─────────────────────────────────────────

    async def get_partner_by_name(self, name: str):
        return await self.pool.fetchrow("SELECT * FROM federation_partners WHERE name=$1 AND active", name)

    async def nonce_seen(self, nonce: str) -> bool:
        row = await self.pool.fetchrow("SELECT 1 FROM federation_nonces WHERE nonce=$1", nonce)
        return row is not None

    async def store_nonce(self, nonce: str, partner_id: int):
        await self.pool.execute(
            "INSERT INTO federation_nonces (nonce, partner_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
            nonce, partner_id,
        )

    async def insert_federation_report(self, hashed_user_id: str, partner_id: int,
                                        risk_score: float, evidence_link: str, reason: str):
        await self.pool.execute(
            """INSERT INTO federation_reports (hashed_user_id, source_partner_id, risk_score, evidence_link, reason)
               VALUES ($1,$2,$3,$4,$5)""",
            hashed_user_id, partner_id, risk_score, evidence_link, reason,
        )

    async def check_federation(self, hashed_user_id: str):
        return await self.pool.fetch(
            """SELECT fr.risk_score, fr.reason, fr.received_at, fp.name AS partner_name, fp.reliability_weight
               FROM federation_reports fr JOIN federation_partners fp ON fp.id = fr.source_partner_id
               WHERE fr.hashed_user_id = $1 ORDER BY fr.received_at DESC LIMIT 20""",
            hashed_user_id,
        )

    # ── Module 9 — war rooms ──────────────────────────────────────────

    async def open_warroom(self, guild_id: int, channel_id: int, reason: str, trigger_user_id: int | None) -> int:
        row = await self.pool.fetchrow(
            """INSERT INTO warrooms (guild_id, channel_id, trigger_reason, trigger_user_id)
               VALUES ($1,$2,$3,$4) RETURNING id""",
            guild_id, channel_id, reason, trigger_user_id,
        )
        return int(row["id"])

    async def close_warroom(self, channel_id: int):
        await self.pool.execute(
            "UPDATE warrooms SET status='closed', closed_at=now() WHERE channel_id=$1", channel_id
        )

    async def active_warroom_count(self, guild_id: int) -> int:
        row = await self.pool.fetchrow(
            "SELECT COUNT(*) AS c FROM warrooms WHERE guild_id=$1 AND status='open'", guild_id
        )
        return int(row["c"])

    async def get_open_warrooms(self):
        """Fix #3 — Retourne toutes les war rooms ouvertes (tous guilds) pour
        permettre la restauration de _active_channels après un restart."""
        return await self.pool.fetch(
            "SELECT guild_id, channel_id FROM warrooms WHERE status='open'"
        )

    # ── Module 3bis — lockdown ────────────────────────────────────────

    async def set_lockdown(self, guild_id: int, active: bool, reason: str = ""):
        await self.pool.execute(
            """INSERT INTO lockdown_state (guild_id, active, triggered_at, reason)
               VALUES ($1, $2, CASE WHEN $2 THEN now() ELSE NULL END, $3)
               ON CONFLICT (guild_id) DO UPDATE SET
                   active = EXCLUDED.active,
                   triggered_at = CASE WHEN EXCLUDED.active THEN now() ELSE lockdown_state.triggered_at END,
                   reason = EXCLUDED.reason""",
            guild_id, active, reason,
        )

    async def is_lockdown_active(self, guild_id: int) -> bool:
        row = await self.pool.fetchrow("SELECT active FROM lockdown_state WHERE guild_id=$1", guild_id)
        return bool(row["active"]) if row else False

    async def get_active_lockdowns(self) -> list[int]:
        """Fix #1 — Retourne les guild_ids dont le lockdown est actif en base
        pour permettre la restauration de _active après un restart."""
        rows = await self.pool.fetch(
            "SELECT guild_id FROM lockdown_state WHERE active = TRUE"
        )
        return [r["guild_id"] for r in rows]

    # ── Nettoyage (fix #12) ───────────────────────────────────────────

    async def purge_guild_data(self, guild_id: int) -> None:
        """Appelé dans on_guild_remove : supprime toutes les données du serveur.
        Les tables en CASCADE (users, risk_scores, etc.) sont nettoyées
        automatiquement par la contrainte FK ON DELETE CASCADE de guilds."""
        await self.pool.execute("DELETE FROM guilds WHERE guild_id = $1", guild_id)

    # ── Module 12 — dashboard Discord ────────────────────────────────

    async def set_dashboard_channels(self, guild_id: int, status_channel_id: int, alerts_channel_id: int):
        await self.pool.execute(
            """UPDATE guilds
               SET dashboard_status_channel_id = $2, dashboard_alerts_channel_id = $3
               WHERE guild_id = $1""",
            guild_id, status_channel_id, alerts_channel_id,
        )

    async def get_dashboard_channels(self) -> list:
        """Retourne tous les guilds ayant un dashboard configuré (pour restore_from_db)."""
        return await self.pool.fetch(
            """SELECT guild_id, dashboard_status_channel_id AS status_channel_id,
                      dashboard_alerts_channel_id AS alerts_channel_id
               FROM guilds
               WHERE dashboard_status_channel_id IS NOT NULL
                 AND dashboard_alerts_channel_id IS NOT NULL"""
        )

    async def count_incidents_today(self, guild_id: int) -> int:
        """Nombre d'événements critiques dans les dernières 24h (pour le dashboard)."""
        INCIDENT_TYPES = ("risk_critical", "canary_hit", "coordination_detected",
                          "scam_detected", "antispam_repeat_offender", "lockdown_triggered")
        row = await self.pool.fetchrow(
            """SELECT COUNT(*) AS c FROM evidence_chain
               WHERE guild_id = $1
                 AND ts > now() - interval '24 hours'
                 AND event_type = ANY($2::text[])""",
            guild_id, list(INCIDENT_TYPES),
        )
        return int(row["c"]) if row else 0

    async def avg_risk_score_today(self, guild_id: int) -> float | None:
        """Score de risque moyen des 24 dernières heures (pour le dashboard)."""
        row = await self.pool.fetchrow(
            """SELECT AVG(score) AS avg FROM risk_scores
               WHERE guild_id = $1 AND created_at > now() - interval '24 hours'""",
            guild_id,
        )
        return float(row["avg"]) if row and row["avg"] is not None else None

    # ── Module 14 — Quarantaine ───────────────────────────────────────

    async def log_quarantine(self, guild_id: int, user_id: int, action: str, reason: str) -> None:
        await self.pool.execute(
            "INSERT INTO quarantine_log (guild_id, user_id, action, reason) VALUES ($1,$2,$3,$4)",
            guild_id, user_id, action, reason,
        )

    async def get_active_quarantine_count(self, guild_id: int) -> int:
        """Nombre de membres actuellement en quarantaine (dernier action = 'quarantined')."""
        row = await self.pool.fetchrow(
            """SELECT COUNT(DISTINCT user_id) AS c
               FROM quarantine_log q1
               WHERE guild_id = $1
                 AND action = 'quarantined'
                 AND NOT EXISTS (
                     SELECT 1 FROM quarantine_log q2
                     WHERE q2.guild_id = q1.guild_id
                       AND q2.user_id = q1.user_id
                       AND q2.ts > q1.ts
                       AND q2.action IN ('quarantine_released', 'banned_from_quarantine')
                 )""",
            guild_id,
        )
        return int(row["c"]) if row else 0

    async def is_quarantined(self, guild_id: int, user_id: int) -> bool:
        row = await self.pool.fetchrow(
            """SELECT action FROM quarantine_log
               WHERE guild_id = $1 AND user_id = $2
               ORDER BY ts DESC LIMIT 1""",
            guild_id, user_id,
        )
        return row is not None and row["action"] == "quarantined"

    # ── Module 15 — Trust score ───────────────────────────────────────

    async def save_trust_score(self, guild_id: int, score: float, breakdown: dict) -> None:
        import json as _json
        await self.pool.execute(
            "INSERT INTO guild_trust_scores (guild_id, score, breakdown) VALUES ($1,$2,$3::jsonb)",
            guild_id, score, _json.dumps(breakdown),
        )

    async def get_latest_trust_score(self, guild_id: int) -> dict | None:
        row = await self.pool.fetchrow(
            """SELECT score, breakdown, computed_at
               FROM guild_trust_scores WHERE guild_id = $1
               ORDER BY computed_at DESC LIMIT 1""",
            guild_id,
        )
        if not row:
            return None
        import json as _json
        return {
            "score": float(row["score"]),
            "breakdown": _json.loads(row["breakdown"]) if isinstance(row["breakdown"], str) else row["breakdown"],
            "computed_at": row["computed_at"].isoformat(),
        }

    async def get_trust_score_history(self, guild_id: int, limit: int = 24) -> list:
        """Historique du trust score (pour tracer la courbe dans le dashboard)."""
        return await self.pool.fetch(
            """SELECT score, computed_at FROM guild_trust_scores
               WHERE guild_id = $1 ORDER BY computed_at DESC LIMIT $2""",
            guild_id, limit,
        )

    async def get_guild_age_days(self, guild_id: int) -> int:
        """Nombre de jours depuis que le bot a rejoint le serveur."""
        row = await self.pool.fetchrow(
            "SELECT joined_bot_at FROM guilds WHERE guild_id = $1", guild_id
        )
        if not row or not row["joined_bot_at"]:
            return 0
        from datetime import datetime, timezone
        delta = datetime.now(timezone.utc) - row["joined_bot_at"].replace(tzinfo=timezone.utc)
        return max(0, delta.days)

    async def get_label_stats(self, guild_id: int) -> dict:
        """Retourne {legit: N, raid: N, unlabeled: N} pour le trust score."""
        rows = await self.pool.fetch(
            """SELECT
                 COUNT(*) FILTER (WHERE label = 'legit')   AS legit,
                 COUNT(*) FILTER (WHERE label = 'raid')    AS raid,
                 COUNT(*) FILTER (WHERE label IS NULL)     AS unlabeled
               FROM risk_scores WHERE guild_id = $1""",
            guild_id,
        )
        if not rows:
            return {"legit": 0, "raid": 0, "unlabeled": 0}
        r = rows[0]
        return {"legit": int(r["legit"]), "raid": int(r["raid"]), "unlabeled": int(r["unlabeled"])}

    async def count_incidents_period(self, guild_id: int, days: int = 30) -> int:
        INCIDENT_TYPES = ("risk_critical", "canary_hit", "coordination_detected",
                          "scam_detected", "antispam_repeat_offender", "lockdown_triggered",
                          "ban_fingerprint_match", "invite_raid_detected")
        row = await self.pool.fetchrow(
            """SELECT COUNT(*) AS c FROM evidence_chain
               WHERE guild_id = $1
                 AND ts > now() - $2 * interval '1 day'
                 AND event_type = ANY($3::text[])""",
            guild_id, days, list(INCIDENT_TYPES),
        )
        return int(row["c"]) if row else 0

    async def days_since_last_lockdown(self, guild_id: int) -> int | None:
        """Retourne le nombre de jours depuis le dernier lockdown levé, ou None si jamais."""
        row = await self.pool.fetchrow(
            """SELECT ts FROM evidence_chain
               WHERE guild_id = $1 AND event_type = 'lockdown_released'
               ORDER BY ts DESC LIMIT 1""",
            guild_id,
        )
        if not row:
            return None
        from datetime import datetime, timezone
        delta = datetime.now(timezone.utc) - row["ts"].replace(tzinfo=timezone.utc)
        return max(0, delta.days)

    # ── Module 16 — Ban fingerprints ──────────────────────────────────

    async def get_behavior_vector(self, user_id: int, guild_id: int) -> list | None:
        row = await self.pool.fetchrow(
            "SELECT vector FROM behavior_vectors WHERE user_id=$1 AND guild_id=$2",
            user_id, guild_id,
        )
        return list(row["vector"]) if row and row["vector"] is not None else None

    async def get_stylometry_vector(self, user_id: int, guild_id: int) -> list | None:
        row = await self.pool.fetchrow(
            "SELECT ngram_signature FROM stylometry_profiles WHERE user_id=$1 AND guild_id=$2",
            user_id, guild_id,
        )
        return list(row["ngram_signature"]) if row and row["ngram_signature"] is not None else None

    async def store_banned_fingerprint(self, guild_id: int, banned_user_id: int,
                                        behavior_vector: list | None,
                                        style_vector: list | None,
                                        retention_days: int = 90) -> None:
        from datetime import datetime, timezone, timedelta
        expires = datetime.now(timezone.utc) + timedelta(days=retention_days)
        await self.pool.execute(
            """INSERT INTO banned_fingerprints
                   (guild_id, banned_user_id, behavior_vector, style_vector, expires_at)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT DO NOTHING""",
            guild_id, banned_user_id, behavior_vector, style_vector, expires,
        )

    async def find_banned_fingerprint_matches(self, guild_id: int,
                                               behavior_vector: list | None,
                                               style_vector: list | None,
                                               behavior_threshold: float = 0.80,
                                               style_threshold: float = 0.75,
                                               limit: int = 3) -> list[dict]:
        """Cherche les fingerprints de bannis similaires au vecteur donné.
        Utilise le vecteur comportemental comme filtre principal (index ivfflat),
        puis affine avec la stylométrie si disponible."""
        if not behavior_vector and not style_vector:
            return []

        if behavior_vector:
            rows = await self.pool.fetch(
                """SELECT banned_user_id,
                          1 - (behavior_vector <=> $1) AS behavior_similarity,
                          CASE WHEN style_vector IS NOT NULL AND $5::vector IS NOT NULL
                               THEN 1 - (style_vector <=> $5::vector)
                               ELSE NULL END AS style_similarity
                   FROM banned_fingerprints
                   WHERE guild_id = $2
                     AND behavior_vector IS NOT NULL
                     AND (expires_at IS NULL OR expires_at > now())
                     AND 1 - (behavior_vector <=> $1) >= $3
                   ORDER BY behavior_vector <=> $1
                   LIMIT $4""",
                behavior_vector, guild_id, behavior_threshold, limit,
                style_vector,
            )
        else:
            # Fallback : comparaison uniquement stylométrique
            rows = await self.pool.fetch(
                """SELECT banned_user_id,
                          NULL AS behavior_similarity,
                          1 - (style_vector <=> $1) AS style_similarity
                   FROM banned_fingerprints
                   WHERE guild_id = $2
                     AND style_vector IS NOT NULL
                     AND (expires_at IS NULL OR expires_at > now())
                     AND 1 - (style_vector <=> $1) >= $3
                   ORDER BY style_vector <=> $1
                   LIMIT $4""",
                style_vector, guild_id, style_threshold, limit,
            )

        return [dict(r) for r in rows]

    async def purge_expired_banned_fingerprints(self) -> int:
        """Supprime les fingerprints expirés (appelé périodiquement). Retourne le nombre supprimé."""
        result = await self.pool.execute(
            "DELETE FROM banned_fingerprints WHERE expires_at IS NOT NULL AND expires_at < now()"
        )
        count = int(result.split()[-1]) if result else 0
        return count

    # ── Module 17 — Audit d'invitations ──────────────────────────────

    async def record_invite_usage(self, guild_id: int, user_id: int,
                                   invite_code: str | None, inviter_id: int | None) -> None:
        await self.pool.execute(
            "INSERT INTO invite_usage (guild_id, user_id, invite_code, inviter_id) VALUES ($1,$2,$3,$4)",
            guild_id, user_id, invite_code, inviter_id,
        )

    async def get_invite_usage_window(self, guild_id: int, window_seconds: int) -> list:
        return await self.pool.fetch(
            """SELECT invite_code, inviter_id, user_id FROM invite_usage
               WHERE guild_id = $1 AND ts > now() - $2 * interval '1 second'""",
            guild_id, window_seconds,
        )

    async def flag_invite(self, guild_id: int, invite_code: str,
                           raid_ratio: float, auto_revoked: bool) -> None:
        await self.pool.execute(
            """INSERT INTO flagged_invites (guild_id, invite_code, raid_ratio, auto_revoked)
               VALUES ($1,$2,$3,$4)""",
            guild_id, invite_code, raid_ratio, auto_revoked,
        )

    async def get_invite_stats(self, guild_id: int, limit: int = 10) -> list:
        """Top N des invitations les plus utilisées pour ce serveur."""
        return await self.pool.fetch(
            """SELECT invite_code, inviter_id,
                      COUNT(*) AS uses,
                      MIN(ts) AS first_use, MAX(ts) AS last_use
               FROM invite_usage
               WHERE guild_id = $1 AND invite_code IS NOT NULL
               GROUP BY invite_code, inviter_id
               ORDER BY uses DESC
               LIMIT $2""",
            guild_id, limit,
        )



    async def get_recent_joiner_names(self, guild_id: int, window_seconds: int = 90) -> list[str]:
        """Retourne les display_names des membres ayant rejoint dans la fenêtre.
        Utilisé par similar_names.check_new_member dans on_member_join."""
        rows = await self.pool.fetch(
            """SELECT DISTINCT u.discord_id
               FROM join_events j
               JOIN users u ON u.discord_id = j.user_id AND u.guild_id = j.guild_id
               WHERE j.guild_id = $1
                 AND j.ts > now() - $2 * interval '1 second'""",
            guild_id, window_seconds,
        )
        # On retourne les discord_ids — le nom sera résolu côté bot depuis le cache Discord
        return [str(r["discord_id"]) for r in rows]

    # ── Auto-labellisation ────────────────────────────────────────────

    async def auto_label_user(self, user_id: int, guild_id: int, label: str) -> bool:
        """Labellise automatiquement le dernier score non-labellisé d'un utilisateur.
        Utilisé dans on_member_ban (→ 'raid') et tâche périodique (→ 'legit').
        Retourne True si un score a été trouvé et labellisé."""
        row = await self.pool.fetchrow(
            """UPDATE risk_scores SET label = $3
               WHERE id = (
                   SELECT id FROM risk_scores
                   WHERE user_id = $1 AND guild_id = $2 AND label IS NULL
                   ORDER BY created_at DESC LIMIT 1
               )
               RETURNING id""",
            user_id, guild_id, label,
        )
        return row is not None

    async def get_long_standing_members(self, guild_id: int, days: int = 7) -> list[int]:
        """Retourne les user_ids présents depuis plus de X jours sans label.
        Utilisé pour l'auto-labellisation 'legit' des membres actifs."""
        rows = await self.pool.fetch(
            """SELECT DISTINCT rs.user_id
               FROM risk_scores rs
               JOIN users u ON u.discord_id = rs.user_id AND u.guild_id = rs.guild_id
               WHERE rs.guild_id = $1
                 AND rs.label IS NULL
                 AND u.join_date < now() - $2 * interval '1 day'""",
            guild_id, days,
        )
        return [r["user_id"] for r in rows]

    # ── /sentinel whois ───────────────────────────────────────────────

    async def get_member_profile(self, user_id: int, guild_id: int) -> dict | None:
        """Agrège toutes les données connues sur un membre pour /sentinel whois.
        Utilise asyncio.gather pour exécuter les 3 requêtes en parallèle (au lieu
        de 4 allers-retours séquentiels)."""
        import asyncio

        user, (latest_score, score_count, incidents) = await asyncio.gather(
            self.pool.fetchrow(
                "SELECT discord_id, guild_id, account_age_days, join_date, avatar_hash, "
                "is_default_avatar, first_seen FROM users WHERE discord_id = $1 AND guild_id = $2",
                user_id, guild_id,
            ),
            asyncio.gather(
                self.pool.fetchrow(
                    """SELECT score, breakdown, model_version, label, created_at
                       FROM risk_scores WHERE user_id = $1 AND guild_id = $2
                       ORDER BY created_at DESC LIMIT 1""",
                    user_id, guild_id,
                ),
                self.pool.fetchrow(
                    "SELECT COUNT(*) AS c FROM risk_scores WHERE user_id = $1 AND guild_id = $2",
                    user_id, guild_id,
                ),
                self.pool.fetch(
                    """SELECT event_type, ts FROM evidence_chain
                       WHERE guild_id = $1 AND data->>'user_id' = $2
                       ORDER BY ts DESC LIMIT 5""",
                    guild_id, str(user_id),
                ),
            ),
        )
        if not user:
            return None

        return {
            "user": dict(user),
            "latest_score": dict(latest_score) if latest_score else None,
            "score_count": int(score_count["c"]) if score_count else 0,
            "recent_incidents": [dict(r) for r in incidents],
        }

    async def fetch_evidence_by_user(self, user_id: int, guild_id: int,
                                      limit: int = 30) -> list:
        """Retourne les entrées forensiques liées à un utilisateur spécifique,
        triées de la plus récente à la plus ancienne — pour /sentinel whois."""
        return await self.pool.fetch(
            """SELECT event_type, data, hash, ts
               FROM evidence_chain
               WHERE guild_id = $1
                 AND (
                     data->>'user_id' = $2
                     OR $2 = ANY(
                         SELECT jsonb_array_elements_text(data->'user_ids')
                     )
                 )
               ORDER BY ts DESC
               LIMIT $3""",
            guild_id, str(user_id), limit,
        )

    async def fetch_evidence_by_channel(self, channel_id: int, guild_id: int,
                                         limit: int = 50, event_types: list[str] | None = None) -> list:
        """Retourne l'historique forensique d'un salon donné — pour /sentinel logs.
        Filtre optionnel par type d'événement (risk_critical, canary_hit, etc.)."""
        if event_types:
            return await self.pool.fetch(
                """SELECT event_type, data, hash, ts
                   FROM evidence_chain
                   WHERE guild_id = $1
                     AND data->>'channel_id' = $2
                     AND event_type = ANY($3::text[])
                   ORDER BY ts DESC
                   LIMIT $4""",
                guild_id, str(channel_id), event_types, limit,
            )
        return await self.pool.fetch(
            """SELECT event_type, data, hash, ts
               FROM evidence_chain
               WHERE guild_id = $1
                 AND data->>'channel_id' = $2
               ORDER BY ts DESC
               LIMIT $3""",
            guild_id, str(channel_id), limit,
        )

    # ── Anti-Stresseur Vocal ──────────────────────────────────────────

    async def set_voice_antistress_config(
        self, guild_id: int, channel_id: int, max_ping_ms: int = 250, auto_renew: bool = True, check_interval_seconds: int = 30
    ) -> None:
        """Enregistre ou met à jour la configuration anti-stresseur d'un salon vocal avec intervalle de ping."""
        await self.pool.execute(
            """INSERT INTO voice_antistress_config (guild_id, channel_id, max_ping_ms, auto_renew, check_interval_seconds)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (guild_id, channel_id)
               DO UPDATE SET max_ping_ms = EXCLUDED.max_ping_ms,
                             auto_renew = EXCLUDED.auto_renew,
                             check_interval_seconds = EXCLUDED.check_interval_seconds""",
            guild_id, channel_id, max_ping_ms, auto_renew, check_interval_seconds,
        )

    async def set_guild_voice_interval(self, guild_id: int, check_interval_seconds: int) -> None:
        """Met à jour l'intervalle de vérification de ping pour tous les salons vocaux du serveur."""
        await self.pool.execute(
            "UPDATE voice_antistress_config SET check_interval_seconds = $2 WHERE guild_id = $1",
            guild_id, check_interval_seconds,
        )

    async def remove_voice_antistress_config(self, guild_id: int, channel_id: int) -> bool:
        """Retire un salon vocal de la surveillance anti-stresseur."""
        res = await self.pool.execute(
            "DELETE FROM voice_antistress_config WHERE guild_id = $1 AND channel_id = $2",
            guild_id, channel_id,
        )
        return "DELETE 1" in res

    async def get_voice_antistress_configs(self, guild_id: int) -> list[dict]:
        """Retourne la liste des salons vocaux sous surveillance pour un serveur."""
        rows = await self.pool.fetch(
            "SELECT guild_id, channel_id, max_ping_ms, auto_renew, check_interval_seconds, created_at FROM voice_antistress_config WHERE guild_id = $1 ORDER BY created_at ASC",
            guild_id,
        )
        return [dict(r) for r in rows]

    async def get_all_voice_antistress_configs(self) -> list[dict]:
        """Retourne toutes les configurations anti-stresseur actives."""
        rows = await self.pool.fetch(
            "SELECT guild_id, channel_id, max_ping_ms, auto_renew, check_interval_seconds FROM voice_antistress_config WHERE auto_renew = TRUE",
        )
        return [dict(r) for r in rows]

    async def update_voice_antistress_channel(self, guild_id: int, old_channel_id: int, new_channel_id: int) -> None:
        """Met à jour l'ID du salon suite à une recréation/renouvellement automatique."""
        await self.pool.execute(
            "UPDATE voice_antistress_config SET channel_id = $3 WHERE guild_id = $1 AND channel_id = $2",
            guild_id, old_channel_id, new_channel_id,
        )

    # ── Sauvegardes & Restauration (Anti-Nuke) ──────────────────────────

    async def save_guild_snapshot(
        self, guild_id: int, label: str, snapshot_data: dict, channels_count: int, roles_count: int
    ) -> int:
        """Enregistre un snapshot complet de l'arborescence et des rôles d'un serveur."""
        row = await self.pool.fetchrow(
            """INSERT INTO guild_snapshots (guild_id, label, snapshot_data, channels_count, roles_count)
               VALUES ($1, $2, $3::jsonb, $4, $5)
               RETURNING id""",
            guild_id, label, json.dumps(snapshot_data), channels_count, roles_count,
        )
        return int(row["id"])

    async def get_guild_snapshots(self, guild_id: int, limit: int = 20) -> list[dict]:
        """Retourne l'historique des snapshots d'un serveur."""
        rows = await self.pool.fetch(
            """SELECT id, guild_id, label, channels_count, roles_count, created_at
               FROM guild_snapshots
               WHERE guild_id = $1
               ORDER BY created_at DESC
               LIMIT $2""",
            guild_id, limit,
        )
        return [dict(r) for r in rows]

    async def get_guild_snapshot_by_id(self, snapshot_id: int) -> dict | None:
        """Récupère les données complètes d'un snapshot spécifique."""
        row = await self.pool.fetchrow(
            """SELECT id, guild_id, label, snapshot_data, channels_count, roles_count, created_at
               FROM guild_snapshots
               WHERE id = $1""",
            snapshot_id,
        )
        if not row:
            return None
        d = dict(row)
        if isinstance(d["snapshot_data"], str):
            d["snapshot_data"] = json.loads(d["snapshot_data"])
        return d

    async def delete_guild_snapshot(self, snapshot_id: int, guild_id: int) -> bool:
        """Supprime un snapshot."""
        res = await self.pool.execute(
            "DELETE FROM guild_snapshots WHERE id = $1 AND guild_id = $2",
            snapshot_id, guild_id,
        )
        return "DELETE 1" in res

    # ── Enquête & Forensique Membre Approfondie ────────────────────────

    async def get_user_invite_info(self, guild_id: int, user_id: int) -> dict | None:
        """Retourne les informations d'invitation d'un utilisateur."""
        row = await self.pool.fetchrow(
            """SELECT invite_code, inviter_id, ts
               FROM invite_usage
               WHERE guild_id = $1 AND user_id = $2
               ORDER BY ts DESC
               LIMIT 1""",
            guild_id, user_id,
        )
        return dict(row) if row else None

    async def get_invite_traffic(self, guild_id: int, invite_code: str, window_minutes: int = 15) -> int:
        """Compte le nombre de jointures utilisant ce code d'invitation dans la fenêtre."""
        row = await self.pool.fetchrow(
            """SELECT COUNT(*) as cnt
               FROM invite_usage
               WHERE guild_id = $1 AND invite_code = $2
                 AND ts > now() - (interval '1 minute' * $3)""",
            guild_id, invite_code, window_minutes,
        )
        return int(row["cnt"]) if row else 0

    async def get_similar_stylometry_users(
        self, guild_id: int, user_id: int, threshold: float = 0.80, limit: int = 5
    ) -> list[dict]:
        """Trouve les comptes du serveur ayant une stylométrie textuelle similaire (pgvector)."""
        try:
            rows = await self.pool.fetch(
                """SELECT s2.user_id, 1 - (s1.ngram_signature <=> s2.ngram_signature) AS similarity
                   FROM stylometry_profiles s1
                   JOIN stylometry_profiles s2 ON s1.guild_id = s2.guild_id AND s1.user_id != s2.user_id
                   WHERE s1.guild_id = $1 AND s1.user_id = $2
                     AND 1 - (s1.ngram_signature <=> s2.ngram_signature) >= $3
                   ORDER BY s1.ngram_signature <=> s2.ngram_signature ASC
                   LIMIT $4""",
                guild_id, user_id, threshold, limit,
            )
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning("Erreur similarité stylométrique pgvector : %s", e)
            return []

    async def get_user_evidence_events(self, guild_id: int, user_id: int, limit: int = 10) -> list[dict]:
        """Retourne les derniers événements de la chaîne forensique liés à un utilisateur."""
        rows = await self.pool.fetch(
            """SELECT event_type, data, hash, ts
               FROM evidence_chain
               WHERE guild_id = $1
                 AND (data->>'user_id' = $2 OR data->>'target_id' = $2)
               ORDER BY ts DESC
               LIMIT $3""",
            guild_id, str(user_id), limit,
        )
        return [dict(r) for r in rows]

    # ── Snapshots & Backups ───────────────────────────────────────────

    async def save_guild_snapshot(
        self, guild_id: int, label: str, snapshot_data: dict, channels_count: int = 0, roles_count: int = 0
    ) -> int:
        """Enregistre un snapshot d'état structurel du serveur et retourne son ID."""
        import json
        snap_json = json.dumps(snapshot_data) if isinstance(snapshot_data, dict) else snapshot_data
        row = await self.pool.fetchrow(
            """INSERT INTO guild_snapshots (guild_id, label, snapshot_data, channels_count, roles_count)
               VALUES ($1, $2, $3::jsonb, $4, $5)
               RETURNING id""",
            guild_id, label, snap_json, channels_count, roles_count,
        )
        return int(row["id"]) if row else 0

    async def get_guild_snapshots(self, guild_id: int, limit: int = 20) -> list[dict]:
        """Retourne la liste des snapshots d'un serveur (sans les données volumineuses)."""
        rows = await self.pool.fetch(
            """SELECT id, guild_id, label, channels_count, roles_count, created_at
               FROM guild_snapshots
               WHERE guild_id = $1
               ORDER BY created_at DESC
               LIMIT $2""",
            guild_id, limit,
        )
        return [dict(r) for r in rows]

    async def get_guild_snapshot_by_id(self, snapshot_id: int, guild_id: int | None = None) -> dict | None:
        """Récupère un snapshot complet avec ses données JSON par son identifiant."""
        if guild_id is not None:
            row = await self.pool.fetchrow(
                """SELECT id, guild_id, label, snapshot_data, channels_count, roles_count, created_at
                   FROM guild_snapshots
                   WHERE id = $1 AND guild_id = $2""",
                snapshot_id, guild_id,
            )
        else:
            row = await self.pool.fetchrow(
                """SELECT id, guild_id, label, snapshot_data, channels_count, roles_count, created_at
                   FROM guild_snapshots
                   WHERE id = $1""",
                snapshot_id,
            )
        if not row:
            return None
        res = dict(row)
        import json
        if isinstance(res.get("snapshot_data"), str):
            res["snapshot_data"] = json.loads(res["snapshot_data"])
        return res

    async def delete_guild_snapshot(self, snapshot_id: int, guild_id: int) -> bool:
        """Supprime un snapshot."""
        res = await self.pool.execute(
            "DELETE FROM guild_snapshots WHERE id = $1 AND guild_id = $2",
            snapshot_id, guild_id,
        )
        return res.endswith("1")




