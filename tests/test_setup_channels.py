"""
Tests unitaires pour la configuration des salons et rôles Sentinel :
- guild_dashboard : #sentinel-status et #sentinel-alerts masqués pour @everyone, visibles pour le staff
- quarantine : #sentinel-quarantine + rôle d'isolement, invisible pour @everyone
- warroom : catégorie sentinel-warrooms invisible pour @everyone, visible pour le staff
- canary : 3 canaux pièges invisibles pour @everyone
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
import pytest
import discord

from bot.modules import guild_dashboard, quarantine, warroom, canary


@pytest.fixture
def mock_guild():
    guild = MagicMock(spec=discord.Guild)
    guild.id = 12345
    guild.name = "Test Security Guild"
    guild.default_role = MagicMock(spec=discord.Role, name="@everyone")
    guild.roles = [guild.default_role]
    guild.categories = []
    guild.text_channels = []
    guild.voice_channels = []
    guild.stage_channels = []
    guild.me = MagicMock(spec=discord.Member)

    async def fake_create_category(name, overwrites=None, reason=None):
        cat = MagicMock(spec=discord.CategoryChannel)
        cat.id = 9901
        cat.name = name
        cat.overwrites = overwrites or {}
        cat.set_permissions = AsyncMock()
        guild.categories.append(cat)
        return cat

    async def fake_create_text_channel(name, category=None, overwrites=None, topic=None, reason=None):
        ch = MagicMock(spec=discord.TextChannel)
        ch.id = 1000 + len(guild.text_channels)
        ch.name = name
        ch.category = category
        ch.overwrites = overwrites or {}
        ch.set_permissions = AsyncMock()
        ch.send = AsyncMock()
        guild.text_channels.append(ch)
        return ch

    async def fake_create_role(name, color=None, reason=None):
        role = MagicMock(spec=discord.Role)
        role.id = 8801
        role.name = name
        guild.roles.append(role)
        return role

    guild.create_category = AsyncMock(side_effect=fake_create_category)
    guild.create_text_channel = AsyncMock(side_effect=fake_create_text_channel)
    guild.create_role = AsyncMock(side_effect=fake_create_role)
    return guild


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.set_dashboard_channels = AsyncMock()
    db.set_staff_role = AsyncMock()
    db.get_staff_role = AsyncMock(return_value=None)
    db.get_guild_config = AsyncMock(return_value=(None, None))
    db.set_warroom_category = AsyncMock()
    db.set_log_channel = AsyncMock()
    db.insert_canary_hit = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_setup_dashboard_with_staff_role(mock_guild, mock_db):
    staff_role = MagicMock(spec=discord.Role)
    staff_role.id = 777
    staff_role.name = "Staff"
    mock_guild.roles.append(staff_role)

    status_ch, alerts_ch = await guild_dashboard.setup_dashboard(mock_guild, mock_db, staff_role=staff_role)

    assert status_ch is not None
    assert alerts_ch is not None
    assert status_ch.name == "bidabot-status"
    assert alerts_ch.name == "bidabot-alerts"

    # Vérifie que la catégorie a bien été créée avec @everyone masqué et staff autorisé
    cat = mock_guild.categories[0]
    assert cat.name == "bidabot-admin"
    assert cat.overwrites[mock_guild.default_role].view_channel is False
    assert cat.overwrites[staff_role].view_channel is True
    assert cat.overwrites[staff_role].send_messages is False
    assert cat.overwrites[mock_guild.me].view_channel is True

    # Vérifie que la DB a été mise à jour
    mock_db.set_dashboard_channels.assert_called_once_with(mock_guild.id, status_ch.id, alerts_ch.id)
    mock_db.set_staff_role.assert_called_once_with(mock_guild.id, staff_role.id)


@pytest.mark.asyncio
async def test_setup_quarantine_with_staff_role(mock_guild, mock_db):
    staff_role = MagicMock(spec=discord.Role)
    staff_role.id = 777
    staff_role.name = "Staff"
    mock_guild.roles.append(staff_role)

    role, ch = await quarantine.setup_quarantine(mock_guild, mock_db, staff_role=staff_role)

    assert role is not None
    assert ch is not None
    assert role.name == "bidabot-quarantine"
    assert ch.name == "bidabot-quarantine"

    # Vérifie que le salon a @everyone masqué et le staff + rôle quarantaine autorisés
    assert ch.overwrites[mock_guild.default_role].view_channel is False
    assert ch.overwrites[role].view_channel is True
    assert ch.overwrites[staff_role].view_channel is True
    assert ch.overwrites[staff_role].manage_messages is True
    assert mock_db.set_staff_role.called


@pytest.mark.asyncio
async def test_setup_warroom_category(mock_guild, mock_db):
    staff_role = MagicMock(spec=discord.Role)
    staff_role.id = 777
    staff_role.name = "Staff"
    mock_guild.roles.append(staff_role)

    cat = await warroom.get_or_create_warroom_category(mock_guild, mock_db, staff_role=staff_role)

    assert cat is not None
    assert cat.name == "bidabot-warrooms"
    assert cat.overwrites[mock_guild.default_role].view_channel is False
    assert cat.overwrites[staff_role].view_channel is True
    assert cat.overwrites[staff_role].send_messages is True
    assert cat.overwrites[mock_guild.me].manage_channels is True
    mock_db.set_warroom_category.assert_called_once_with(mock_guild.id, cat.id)


@pytest.mark.asyncio
async def test_setup_canaries(mock_guild, mock_db):
    staff_role = MagicMock(spec=discord.Role)
    staff_role.id = 777
    staff_role.name = "Staff"
    mock_guild.roles.append(staff_role)

    canary_ids = await canary.setup_canaries(mock_guild, mock_db, staff_role=staff_role)

    assert len(canary_ids) == 3
    canary_channels = [c for c in mock_guild.text_channels if "canary" in c.name]
    assert len(canary_channels) == 3
    for c in canary_channels:
        assert c.overwrites[mock_guild.default_role].view_channel is False
        assert c.overwrites[staff_role].view_channel is True
