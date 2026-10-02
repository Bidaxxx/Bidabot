"""
Tests unitaires pour les améliorations Sentinel :
1. Smart Gatekeeper (onboarding progressif 3 niveaux)
2. Composants interactifs Discord UI (AlertActionView, BanReasonModal)
3. Features ML enrichies de légitimité (badges, bio phishing, entropie)
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import discord

from bot.modules import gatekeeper
from bot.modules.guild_dashboard import AlertActionView, BanReasonModal
from bot.modules.legitimacy import (
    LegitimacyScorer, score_badges, score_bio, score_username_entropy, calculate_shannon_entropy,
)


# ── Tests ML Features ──────────────────────────────────────────────────

def test_badges_score():
    assert score_badges(has_badges=True, badge_count=2) == 0.05
    assert score_badges(has_badges=False, badge_count=0) == 0.0


def test_bio_phishing_score():
    assert score_bio("Free Nitro! Click here: https://bit.ly/nitro") == 0.85
    assert score_bio("Rejoins mon stream sur Twitch !") == 0.0
    assert score_bio("") == 0.0
    assert score_bio(None) == 0.0


def test_username_entropy_detection():
    # Longue suite de consonnes sans voyelle
    assert score_username_entropy("zrkptwq12") == 0.70
    # Nom standard avec voyelles
    assert score_username_entropy("Guillaume") == 0.0
    assert score_username_entropy("discord_user") == 0.0


# ── Tests Smart Gatekeeper ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_gatekeeper_disabled():
    member = MagicMock(spec=discord.Member)
    member.guild.id = 12345
    db = AsyncMock()
    db.get_guild.return_value = {"gatekeeper_enabled": False}

    res = await gatekeeper.handle_new_member_gate(member, 0.20, db=db, append_evidence=None)
    assert res["status"] == "disabled"


@pytest.mark.asyncio
async def test_gatekeeper_tier1_clean_direct_pass():
    member = MagicMock(spec=discord.Member)
    member.id = 999
    member.guild.id = 12345
    member.guild.name = "Test Guild"
    member.add_roles = AsyncMock()

    mock_role = MagicMock(spec=discord.Role)
    member.guild.get_role.return_value = mock_role

    db = AsyncMock()
    db.get_guild.return_value = {
        "gatekeeper_enabled": True,
        "gatekeeper_verified_role_id": 777777,
        "gatekeeper_channel_id": None,
    }
    append_ev = AsyncMock()

    res = await gatekeeper.handle_new_member_gate(member, 0.15, db=db, append_evidence=append_ev)

    assert res["status"] == "passed_direct"
    assert res["tier"] == "clean"
    member.add_roles.assert_called_once_with(
        mock_role,
        reason="Smart Gatekeeper : Passage direct accordé (Score légitime: 0.15)",
    )
    append_ev.assert_called_once()


@pytest.mark.asyncio
async def test_gatekeeper_tier2_suspect_challenge():
    member = MagicMock(spec=discord.Member)
    member.id = 888
    member.mention = "<@888>"
    member.guild.id = 12345
    member.guild.name = "Test Guild"
    member.guild.text_channels = []
    member.add_roles = AsyncMock()
    member.send = AsyncMock()

    db = AsyncMock()
    db.get_guild.return_value = {
        "gatekeeper_enabled": True,
        "gatekeeper_verified_role_id": 777777,
        "gatekeeper_channel_id": None,
    }
    append_ev = AsyncMock()
    dash = AsyncMock()

    res = await gatekeeper.handle_new_member_gate(
        member, 0.45, db=db, append_evidence=append_ev, dashboard_module=dash,
    )

    assert res["status"] == "challenge_sent"
    assert res["tier"] == "suspect"
    # Ne doit PAS avoir reçu le rôle directement
    member.add_roles.assert_not_called()
    member.send.assert_called_once()
    dash.send_alert.assert_called_once()


@pytest.mark.asyncio
async def test_gatekeeper_tier3_critical_quarantine():
    member = MagicMock(spec=discord.Member)
    member.id = 666
    member.guild.id = 12345
    member.guild.name = "Test Guild"

    db = AsyncMock()
    db.get_guild.return_value = {
        "gatekeeper_enabled": True,
        "gatekeeper_verified_role_id": 777777,
    }
    quarantine_mod = AsyncMock()
    dash = AsyncMock()

    res = await gatekeeper.handle_new_member_gate(
        member, 0.85, db=db, append_evidence=None, dashboard_module=dash, quarantine_module=quarantine_mod,
    )

    assert res["status"] == "quarantined"
    assert res["tier"] == "critical"
    quarantine_mod.quarantine.assert_called_once()
    dash.send_alert.assert_called_once()


# ── Tests UI Components ────────────────────────────────────────────────

def test_alert_action_view_buttons():
    view = AlertActionView(
        guild_id=123,
        target_user_id=456,
        score_data={"score": 0.85, "reason": "Test Alert"},
    )
    custom_ids = [child.custom_id for child in view.children if hasattr(child, "custom_id")]
    assert "sentinel_alert_ban" in custom_ids
    assert "sentinel_alert_quarantine" in custom_ids
    assert "sentinel_alert_whitelist" in custom_ids
    assert "sentinel_alert_inspect" in custom_ids


def test_ban_reason_modal_init():
    modal = BanReasonModal(guild_id=123, target_user_id=456)
    assert modal.title == "Confirmer le Bannissement"
    assert modal.target_user_id == 456


# ── Tests Dashboard Web Moderation Actions & Forensics ───────────────────

@pytest.mark.asyncio
async def test_dashboard_web_moderation_actions():
    """Vérifie que les endpoints API de modération directe préparent et publient les bonnes actions Redis."""
    from dashboard.app import action_ban, action_kick, action_timeout, action_untimeout
    from unittest.mock import patch, MagicMock

    user = {"id": "999", "username": "Admin", "is_root": True}

    # 1. Test Ban
    req_ban = MagicMock()
    req_ban.form = AsyncMock(return_value={"reason": "Scam Nitro confirmé", "delete_days": "1"})
    with patch("dashboard.app.dispatch_bot_action", new_callable=AsyncMock) as mock_dispatch:
        res_ban = await action_ban(req_ban, 12345, 88888, user=user)
        assert res_ban["status"] == "ok"
        assert res_ban["action"] == "banned"
        assert res_ban["user_id"] == 88888
        mock_dispatch.assert_called_once_with(
            "ban", 12345, target_id=88888, reason="Scam Nitro confirmé",
            delete_message_days=1, user_id="999",
        )

    # 2. Test Kick
    req_kick = MagicMock()
    req_kick.form = AsyncMock(return_value={"reason": "Spam récurrent"})
    with patch("dashboard.app.dispatch_bot_action", new_callable=AsyncMock) as mock_dispatch:
        res_kick = await action_kick(req_kick, 12345, 77777, user=user)
        assert res_kick["status"] == "ok"
        assert res_kick["action"] == "kicked"
        mock_dispatch.assert_called_once_with(
            "kick", 12345, target_id=77777, reason="Spam récurrent", user_id="999",
        )

    # 3. Test Timeout
    req_timeout = MagicMock()
    req_timeout.form = AsyncMock(return_value={"duration": "3600", "reason": "Insultes répétées"})
    with patch("dashboard.app.dispatch_bot_action", new_callable=AsyncMock) as mock_dispatch:
        res_timeout = await action_timeout(req_timeout, 12345, 66666, user=user)
        assert res_timeout["status"] == "ok"
        assert res_timeout["action"] == "timeout"
        assert res_timeout["duration"] == 3600
        mock_dispatch.assert_called_once_with(
            "timeout", 12345, target_id=66666, duration=3600,
            reason="Insultes répétées", user_id="999",
        )

    # 4. Test Untimeout
    with patch("dashboard.app.dispatch_bot_action", new_callable=AsyncMock) as mock_dispatch:
        res_untimeout = await action_untimeout(12345, 66666, user=user)
        assert res_untimeout["status"] == "ok"
        assert res_untimeout["action"] == "untimeout"
        mock_dispatch.assert_called_once_with(
            "timeout", 12345, target_id=66666, duration=0,
            reason="Levée de timeout depuis le Dashboard Web", user_id="999",
        )


@pytest.mark.asyncio
async def test_dashboard_soc_analytics_and_simulation():
    from dashboard.app import api_stats_timeline, api_stats_distribution, api_simulate_attack, pwa_manifest

    user = {"id": "999", "username": "TestStaff", "is_root": True}

    # 1. Test PWA manifest
    manifest_res = await pwa_manifest()
    import json
    data = json.loads(manifest_res.body.decode())
    assert data["short_name"] == "Bidabot SOC"
    assert data["display"] == "standalone"

    # 2. Test Timeline Stats
    timeline = await api_stats_timeline(12345, user=user)
    assert "labels" in timeline
    assert len(timeline["labels"]) == 24
    assert "total" in timeline
    assert "critical" in timeline
    assert len(timeline["total"]) == 24

    # 3. Test Threat Distribution
    dist = await api_stats_distribution(12345, user=user)
    assert "labels" in dist
    assert "values" in dist
    assert "Phishing & Scam" in dist["labels"]
    assert len(dist["labels"]) == len(dist["values"])

    # 4. Test Attack Simulator (Raid, Phishing, Nuke)
    with patch("dashboard.app.db.pool", None):
        sim_raid = await api_simulate_attack(12345, threat_type="raid", user=user)
        assert sim_raid["status"] == "success"
        assert sim_raid["threat_type"] == "raid"
        assert sim_raid["data"]["banned_count"] == 20

        sim_phish = await api_simulate_attack(12345, threat_type="phishing", user=user)
        assert sim_phish["status"] == "success"
        assert sim_phish["data"]["score"] == 0.96


@pytest.mark.asyncio
async def test_keeper_protections_and_confidence_rating():
    from dashboard.app import (
        api_test_message_confidence,
        api_rate_message_confidence,
        api_toggle_protection,
        api_save_protection,
        tab_protections,
        tab_messages_confidence,
    )
    from unittest.mock import MagicMock, AsyncMock, patch
    import json

    user = {"id": "999", "username": "AdminStaff"}

    # 1. Test du testeur de confiance en direct avec "je vais te raid"
    req_test = MagicMock()
    req_test.form = AsyncMock(return_value={"text": "je vais te raid"})
    res_test = await api_test_message_confidence(req_test)
    data_test = json.loads(res_test.body.decode())
    assert data_test["score"] == 1.0
    assert data_test["confidence_pct"] == 100
    assert data_test["is_threat"] is True
    assert "Raid" in data_test["category"]

    # 2. Test calibration manuelle 100% Raid (Ban direct)
    req_rate = MagicMock()
    with patch("dashboard.app.dispatch_bot_action", new_callable=AsyncMock) as mock_dispatch:
        with patch("dashboard.app.forensics.append_evidence", new_callable=AsyncMock):
            res_rate = await api_rate_message_confidence(
                req_rate,
                guild_id=12345,
                message_id="msg_101",
                user_id=88888,
                confidence=1.0,
                action="ban",
                user=user,
            )
            assert res_rate["status"] == "ok"
            assert res_rate["confidence"] == 1.0
            mock_dispatch.assert_called_once_with(
                "ban", 12345, target_id=88888,
                reason="Raid certain validé par modérateur (Confiance 100%)",
                user_id="999",
            )

    # 3. Test calibration Faux Positif (Démute immédiat)
    with patch("dashboard.app.dispatch_bot_action", new_callable=AsyncMock) as mock_dispatch:
        with patch("dashboard.app.forensics.append_evidence", new_callable=AsyncMock):
            res_safe = await api_rate_message_confidence(
                req_rate,
                guild_id=12345,
                message_id="msg_102",
                user_id=77777,
                confidence=0.0,
                action="untimeout",
                user=user,
            )
            assert res_safe["status"] == "ok"
            mock_dispatch.assert_called_once_with(
                "timeout", 12345, target_id=77777, duration=0,
                reason="Silence levé (Faux positif validé par modérateur)",
                user_id="999",
            )

    # 4. Test toggle et save protection
    res_toggle = await api_toggle_protection(
        guild_id=12345, module_key="anti_channel_delete", enabled="true", user=user
    )
    assert res_toggle["status"] == "ok"
    assert res_toggle["enabled"] is True

    req_save = MagicMock()
    req_save.form = AsyncMock(return_value={
        "module_key": "anti_channel_delete",
        "sanction": "ban",
        "action_count": "3",
        "window_seconds": "10",
    })
    res_save = await api_save_protection(req_save, guild_id=12345, user=user)
    assert res_save["status"] == "ok"


@pytest.mark.asyncio
async def test_voice_antistress_interval_and_settings():
    from dashboard.app import action_voice_settings, action_voice_interval, action_voice_measure_ping, action_voice_remove

    user = {"id": "999", "username": "Admin", "is_root": True}

    with patch("dashboard.app.db.set_voice_antistress_config", new_callable=AsyncMock) as mock_set:
        res = await action_voice_settings(
            guild_id=12345,
            channel_id=98765,
            max_ping_ms=250,
            auto_renew="true",
            check_interval_seconds=15,
            user=user,
        )
        assert res["status"] == "ok"
        assert res["check_interval_seconds"] == 15
        mock_set.assert_called_once_with(
            guild_id=12345,
            channel_id=98765,
            max_ping_ms=250,
            auto_renew=True,
            check_interval_seconds=15,
        )

    with patch("dashboard.app.db.set_guild_voice_interval", new_callable=AsyncMock) as mock_interval:
        res_int = await action_voice_interval(
            guild_id=12345,
            check_interval_seconds=60,
            user=user,
        )
        assert res_int["status"] == "ok"
        assert res_int["check_interval_seconds"] == 60
        mock_interval.assert_called_once_with(12345, 60)

    # Test mesure de ping
    res_ping = await action_voice_measure_ping(12345, 98765, user=user)
    assert res_ping["status"] == "ok"
    assert "ping_ms" in res_ping
    assert res_ping["ping_ms"] > 0
    assert res_ping["health"] in ("normal", "warning", "stressed")

    # Test retrait
    with patch("dashboard.app.db.remove_voice_antistress_config", new_callable=AsyncMock, return_value=True):
        res_rem = await action_voice_remove(12345, 98765, user=user)
        assert res_rem["status"] == "ok"



