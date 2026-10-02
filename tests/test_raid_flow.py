"""
Tests d'intégration du flow anti-raid.

Simule le cycle complet join → score → risk_critical → lockdown → warroom,
avec toutes les dépendances externes (DB, Redis, Discord) mockées, pour
vérifier que les modules s'enchaînent correctement sans régression.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bot.bus import EventBus
from bot.modules import lockdown as lockdown_module
from bot.modules.legitimacy import LegitimacyScorer, score_account_age, score_velocity


# ── Helpers ────────────────────────────────────────────────────────────

def _make_guild(guild_id: int = 42):
    guild = MagicMock()
    guild.id = guild_id
    guild.name = "TestGuild"
    guild.text_channels = []
    guild.roles = []
    guild.default_role = MagicMock()
    return guild


def _make_db(dry_run=True, lockdown_active=False):
    db = MagicMock()
    db.get_dry_run = AsyncMock(return_value=dry_run)
    db.is_lockdown_active = AsyncMock(return_value=lockdown_active)
    db.set_lockdown = AsyncMock()
    db.insert_evidence = AsyncMock(return_value=1)
    db.last_evidence_hash = AsyncMock(return_value=None)
    db.open_warroom = AsyncMock(return_value=1)
    db.active_warroom_count = AsyncMock(return_value=0)
    db.get_guild_config = AsyncMock(return_value=(None, None))
    db.find_similar_behavior = AsyncMock(return_value=[])
    db.find_similar_style = AsyncMock(return_value=[])
    return db


# ── Tests scorer ───────────────────────────────────────────────────────

def test_score_account_age_fresh_account():
    """Un compte de moins d'1 jour est très suspect."""
    assert score_account_age(0, min_days=3) == 0.85


def test_score_account_age_old_account():
    """Un compte de plus de 30 jours est considéré légitime."""
    assert score_account_age(365, min_days=3) == 0.05


def test_score_velocity_high():
    """Une vélocité de join élevée augmente le score de risque."""
    score = score_velocity(velocity=20, threshold=8)
    assert score > 0.9


def test_scorer_cold_start_new_account(tmp_path):
    """Cold-start : un compte frais avec avatar par défaut et raid en cours → score critique."""
    scorer = LegitimacyScorer(
        model_path=str(tmp_path / "model.joblib"),
        min_training_samples=40,
        account_age_min_days=3,
        join_velocity_threshold=8,
    )
    score, signals, version = scorer.score(
        account_age_days=0,
        is_default_avatar=True,
        join_velocity=15,
        messages_last_minute=0,
    )
    assert version == "cold-start-bayes"
    assert score > 0.7, f"Score attendu > 0.7 pour un compte frais en raid, obtenu : {score}"


def test_scorer_cold_start_legit_account(tmp_path):
    """Cold-start : un compte ancien, avatar personnalisé, join calme → score faible."""
    scorer = LegitimacyScorer(
        model_path=str(tmp_path / "model.joblib"),
        min_training_samples=40,
        account_age_min_days=3,
        join_velocity_threshold=8,
    )
    score, signals, version = scorer.score(
        account_age_days=365,
        is_default_avatar=False,
        join_velocity=1,
        messages_last_minute=0,
    )
    assert version == "cold-start-bayes"
    assert score < 0.3, f"Score attendu < 0.3 pour un compte légitime, obtenu : {score}"


# ── Tests flow anti-raid ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_lockdown_triggered_on_risk_critical():
    """risk_critical → lockdown.trigger() est appelé en dry-run."""
    bus = EventBus()
    guild = _make_guild()
    db = _make_db(dry_run=True)

    evidence_calls = []

    async def mock_append(guild_id, event_type, data):
        evidence_calls.append(event_type)
        return {"hash": "abc123", "prev_hash": None, "timestamp": "now", "event_type": event_type, "data": data}

    trigger_calls = []
    original_trigger = lockdown_module.trigger

    async def mock_trigger(g, payload, *, dry_run, auto_release_seconds, append_evidence, **kw):
        trigger_calls.append({"dry_run": dry_run, "reason": payload.get("reason")})

    async def on_risk_critical(payload):
        dr = await db.get_dry_run(payload["guild_id"])
        await mock_trigger(
            guild, payload, dry_run=dr, auto_release_seconds=300,
            append_evidence=mock_append, db=db,
        )

    bus.on("risk_critical", on_risk_critical)

    payload = {
        "guild_id": guild.id,
        "user_id": 999,
        "score": 0.95,
        "reason": "score_de_legitimite_critique",
        "signals": {},
    }
    await bus.emit("risk_critical", payload)

    assert len(trigger_calls) == 1
    assert trigger_calls[0]["dry_run"] is True


@pytest.mark.asyncio
async def test_lockdown_restore_from_db():
    """restore_from_db() remet _active à True quand la DB indique lockdown actif."""
    guild = _make_guild(guild_id=77)
    db = _make_db(lockdown_active=True)

    # Assure que _active est vide avant restauration
    lockdown_module._active.pop(guild.id, None)
    assert not lockdown_module.is_active(guild.id)

    await lockdown_module.restore_from_db(guild, db)
    assert lockdown_module.is_active(guild.id)

    # Nettoyage
    lockdown_module._active.pop(guild.id, None)


@pytest.mark.asyncio
async def test_lockdown_release_after_restore():
    """Après restore_from_db, release() fonctionne correctement."""
    guild = _make_guild(guild_id=88)
    db = _make_db(lockdown_active=True, dry_run=True)

    lockdown_module._active.pop(guild.id, None)
    await lockdown_module.restore_from_db(guild, db)
    assert lockdown_module.is_active(guild.id)

    evidence_calls = []

    async def mock_append(guild_id, event_type, data):
        evidence_calls.append(event_type)
        return {"hash": "x", "prev_hash": None, "timestamp": "t", "event_type": event_type, "data": data}

    released = await lockdown_module.release(
        guild, dry_run=True, append_evidence=mock_append, db=db, manual=True
    )
    assert released is True
    assert not lockdown_module.is_active(guild.id)
    assert "lockdown_released" in evidence_calls

    # Nettoyage
    lockdown_module._active.pop(guild.id, None)
