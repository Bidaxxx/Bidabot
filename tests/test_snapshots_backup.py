"""
Tests pour le système de Snapshots et Disaster Recovery (Module Snapshot & DB).
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
import discord

from bot.modules import snapshot


@pytest.mark.asyncio
async def test_capture_guild_snapshot():
    guild = MagicMock(spec=discord.Guild)
    guild.id = 123456789
    guild.name = "Serveur Test Securite"

    # Simulation de rôles
    r_everyone = MagicMock(spec=discord.Role)
    r_everyone.is_default.return_value = True

    r_admin = MagicMock(spec=discord.Role)
    r_admin.is_default.return_value = False
    r_admin.name = "Staff"
    r_admin.permissions.value = 8
    r_admin.color.value = 0xFF0000
    r_admin.hoist = True
    r_admin.mentionable = True
    r_admin.position = 5

    guild.roles = [r_everyone, r_admin]

    # Simulation de catégories
    cat = MagicMock(spec=discord.CategoryChannel)
    cat.name = "ADMINISTRATION"
    cat.position = 1
    guild.categories = [cat]

    # Simulation de salons textuels
    tc = MagicMock(spec=discord.TextChannel)
    tc.name = "general"
    tc.category = None
    tc.topic = "Bienvenue"
    tc.slowmode_delay = 0
    tc.nsfw = False
    tc.position = 0
    guild.text_channels = [tc]

    # Simulation de salons vocaux
    vc = MagicMock(spec=discord.VoiceChannel)
    vc.name = "General Vocal"
    vc.category = cat
    vc.bitrate = 64000
    vc.user_limit = 10
    vc.position = 1
    guild.voice_channels = [vc]

    snap = await snapshot.capture_guild_snapshot(guild, label="Test-Unit")

    assert snap["guild_id"] == 123456789
    assert snap["label"] == "Test-Unit"
    assert snap["summary"]["roles_count"] == 1
    assert snap["summary"]["categories_count"] == 1
    assert snap["summary"]["text_channels_count"] == 1
    assert snap["summary"]["voice_channels_count"] == 1
    assert snap["roles"][0]["name"] == "Staff"
    assert snap["text_channels"][0]["name"] == "general"


@pytest.mark.asyncio
async def test_restore_guild_snapshot_missing_items():
    guild = MagicMock(spec=discord.Guild)
    guild.id = 999888777
    guild.roles = []
    guild.categories = []
    guild.text_channels = []
    guild.voice_channels = []

    guild.create_role = AsyncMock()
    guild.create_category = AsyncMock()
    guild.create_text_channel = AsyncMock()
    guild.create_voice_channel = AsyncMock()

    snap_data = {
        "roles": [{"name": "Modo", "permissions": 8, "color": 12345, "hoist": True, "mentionable": False}],
        "categories": [{"name": "COMMUNAUTÉ", "position": 1}],
        "text_channels": [{"name": "annonces", "category": "COMMUNAUTÉ", "topic": "News", "slowmode_delay": 0, "nsfw": False, "position": 0}],
        "voice_channels": [{"name": "Vocal 1", "category": "COMMUNAUTÉ", "bitrate": 96000, "user_limit": 5, "position": 1}],
    }

    stats = await snapshot.restore_guild_snapshot(guild, snap_data)

    assert stats["roles_restored"] == 1
    assert stats["categories_restored"] == 1
    assert stats["channels_restored"] == 2
    guild.create_role.assert_awaited_once()
    guild.create_category.assert_awaited_once()
    guild.create_text_channel.assert_awaited_once()
    guild.create_voice_channel.assert_awaited_once()
