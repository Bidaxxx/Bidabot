"""
Tests unitaires pour les fonctionnalités de pilotage total depuis le Web Dashboard :
- Module 28 : Moteur de Commandes Web CLI Sentinel
- Gestion des salons Discord
"""
from unittest.mock import AsyncMock, MagicMock
import pytest

from bot.modules import cli_engine


@pytest.mark.asyncio
async def test_cli_help_command():
    """Vérifie que la commande 'help' renvoie le guide des commandes CLI."""
    user = {"id": 1, "username": "Admin"}
    res = await cli_engine.execute_cli_command(123456, "help", user=user)
    assert res["status"] == "ok"
    assert "BIDABOT WEB CLI" in res["output"]
    assert "lockdown" in res["output"]
    assert "raid purge" in res["output"]


@pytest.mark.asyncio
async def test_cli_lockdown_command():
    """Vérifie le déclenchement du lockdown via la CLI web."""
    user = {"id": 1, "username": "Admin"}
    mock_db = MagicMock()
    mock_db.set_lockdown = AsyncMock()
    mock_dispatch = AsyncMock()

    res = await cli_engine.execute_cli_command(
        123456, "lockdown on", user=user, db=mock_db, dispatch_bot_action=mock_dispatch
    )
    assert res["status"] == "ok"
    assert "activé" in res["output"]
    mock_db.set_lockdown.assert_called_once()
    mock_dispatch.assert_called_once_with("lockdown_on", 123456, user_id=1)


@pytest.mark.asyncio
async def test_cli_quarantine_command():
    """Vérifie la mise en quarantaine via la CLI web."""
    user = {"id": 1, "username": "Admin"}
    mock_db = MagicMock()
    mock_db.log_quarantine = AsyncMock()
    mock_dispatch = AsyncMock()

    res = await cli_engine.execute_cli_command(
        123456, "quarantine 987654 bot suspect", user=user, db=mock_db, dispatch_bot_action=mock_dispatch
    )
    assert res["status"] == "ok"
    assert "987654" in res["output"]
    mock_db.log_quarantine.assert_called_once()
    mock_dispatch.assert_called_once()


@pytest.mark.asyncio
async def test_cli_raid_purge_command():
    """Vérifie l'ordre de raid purge via la CLI web."""
    user = {"id": 1, "username": "Admin"}
    mock_dispatch = AsyncMock()

    res = await cli_engine.execute_cli_command(
        123456, "raid purge 30", user=user, dispatch_bot_action=mock_dispatch
    )
    assert res["status"] == "ok"
    assert "30" in res["output"]
    mock_dispatch.assert_called_once_with("raid_purge", 123456, window_minutes=30, user_id=1)


@pytest.mark.asyncio
async def test_cli_backup_command():
    """Vérifie la commande de création de backup via CLI."""
    user = {"id": 1, "username": "Admin"}
    mock_dispatch = AsyncMock()

    res = await cli_engine.execute_cli_command(
        123456, "backup create Pre-Event", user=user, dispatch_bot_action=mock_dispatch
    )
    assert res["status"] == "ok"
    assert "Pre-Event" in res["output"]
    mock_dispatch.assert_called_once_with("backup_create", 123456, label="Pre-Event", user_id=1)
