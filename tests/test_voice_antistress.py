"""
Tests unitaires pour le Module 22 — Anti-Stresseur Vocal.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import discord
import pytest

from bot.modules import voice_antistress


class MockPermissions:
    def __init__(self, manage_channels=True, move_members=True, connect=True):
        self.manage_channels = manage_channels
        self.move_members = move_members
        self.connect = connect


def create_mock_voice_channel(name="Vocal-1", channel_id=111222, members=None, manage_channels=True, move_members=True):
    channel = MagicMock(spec=discord.VoiceChannel)
    channel.id = channel_id
    channel.name = name
    channel.position = 3
    channel.category = MagicMock()
    channel.overwrites = {MagicMock(): discord.PermissionOverwrite(connect=True)}
    channel.bitrate = 64000
    channel.user_limit = 10
    channel.video_quality_mode = discord.VideoQualityMode.auto
    channel.rtc_region = None

    guild = MagicMock(spec=discord.Guild)
    guild.id = 999888
    guild.me = MagicMock()

    channel.guild = guild
    channel.permissions_for = MagicMock(return_value=MockPermissions(manage_channels=manage_channels, move_members=move_members))

    channel_members = []
    if members:
        for m_id, name in members:
            m = MagicMock(spec=discord.Member)
            m.id = m_id
            m.display_name = name
            m.bot = False
            voice_state = MagicMock()
            voice_state.channel = channel
            m.voice = voice_state
            m.move_to = AsyncMock()
            channel_members.append(m)

    channel.members = channel_members
    channel.clone = AsyncMock()
    channel.delete = AsyncMock()
    channel.edit = AsyncMock()
    return channel


@pytest.mark.asyncio
async def test_renew_voice_channel_success():
    """Vérifie le clonage, le déplacement de tous les membres et la suppression de l'ancien salon."""
    mock_members = [(1, "Alice"), (2, "Bob"), (3, "Charlie")]
    old_ch = create_mock_voice_channel("Gaming 1", 1001, mock_members)

    new_ch = create_mock_voice_channel("Gaming 1", 1002)
    old_ch.clone.return_value = new_ch

    mock_evidence = AsyncMock()

    result_ch, moved = await voice_antistress.renew_voice_channel(
        old_ch,
        reason="Test anti-stresseur",
        append_evidence=mock_evidence,
    )

    # 1. Vérification que clone() a été appelé avec le bon nom
    old_ch.clone.assert_awaited_once()

    # 2. Vérification que tous les membres ont été déplacés vers new_ch
    assert moved == 3
    for m in old_ch.members:
        m.move_to.assert_awaited_once_with(new_ch, reason="SENTINEL — Test anti-stresseur")

    # 3. Vérification que l'ancien salon a été supprimé
    old_ch.delete.assert_awaited_once()

    # 4. Vérification de l'enregistrement forensique
    mock_evidence.assert_awaited_once()
    evidence_call = mock_evidence.call_args[0]
    assert evidence_call[0] == 999888  # guild_id
    assert evidence_call[1] == "voice_antistress_renew"
    assert evidence_call[2]["old_channel_id"] == 1001
    assert evidence_call[2]["new_channel_id"] == 1002
    assert evidence_call[2]["members_moved"] == 3

    assert result_ch == new_ch


@pytest.mark.asyncio
async def test_renew_voice_channel_permission_error():
    """Vérifie qu'une exception claire est levée si le bot manque de permissions."""
    old_ch = create_mock_voice_channel("Private", 2001, manage_channels=False)

    with pytest.raises(PermissionError) as exc_info:
        await voice_antistress.renew_voice_channel(old_ch)

    assert "Gérer les salons" in str(exc_info.value)


@pytest.mark.asyncio
async def test_velocity_tracker_flood_detection():
    """Vérifie la détection de saturation d'états vocaux par le traqueur."""
    tracker = voice_antistress.VoiceVelocityTracker(window_seconds=5, flood_threshold=5)
    ch_id = 777

    # 4 événements rapides : pas encore de flood
    for _ in range(4):
        count, is_flood = tracker.record_event(ch_id)
        assert not is_flood
    assert count == 4

    # 5ème événement : dépassement du seuil -> flood détecté
    count, is_flood = tracker.record_event(ch_id)
    assert count == 5
    assert is_flood is True

    # 6ème événement immédiat : flood détecté, mais cooldown actif (ne re-déclenche pas en boucle)
    count, is_flood_again = tracker.record_event(ch_id)
    assert is_flood_again is False


@pytest.mark.asyncio
async def test_switch_voice_region():
    """Vérifie le changement de région WebRTC d'un salon."""
    ch = create_mock_voice_channel("General Voice", 3001)

    ok, msg = await voice_antistress.switch_voice_region(ch, "rotterdam")
    assert ok is True
    assert "rotterdam" in msg
    ch.edit.assert_awaited_once_with(rtc_region="rotterdam", reason="SENTINEL — Anti-stresseur vocal : rotation de région")


@pytest.mark.asyncio
async def test_measure_voice_latency_fallback():
    """Vérifie la mesure de latence en repli sur la passerelle websocket."""
    bot = MagicMock(spec=discord.Client)
    bot.latency = 0.042  # 42ms
    ch = create_mock_voice_channel("Music", 4001)

    res = await voice_antistress.measure_voice_latency(bot, ch)
    assert res["status"] == "optimal"
    assert res["ping_ms"] == 42.0
