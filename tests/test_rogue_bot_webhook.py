"""
Tests pour l'Anti-Nuke : Protection Anti-Rogue Bot et Anti-Webhook Frauduleux.
"""
from datetime import datetime, timezone
import pytest
from unittest.mock import AsyncMock, MagicMock
import discord

from bot.modules import antinuke


@pytest.mark.asyncio
async def test_rogue_bot_blocked_when_unauthorized():
    guild = MagicMock(spec=discord.Guild)
    guild.id = 555666777
    guild.name = "Serveur Protege"
    guild.owner_id = 111111111
    guild.me = MagicMock(spec=discord.Member)
    guild.me.id = 999999999
    guild.me.guild_permissions.view_audit_log = True
    guild.me.guild_permissions.ban_members = True
    guild.me.guild_permissions.manage_roles = True
    guild.me.guild_permissions.moderate_members = True
    guild.ban = AsyncMock()

    bot_member = MagicMock(spec=discord.Member)
    bot_member.id = 777777777
    bot_member.name = "NukerBot"
    bot_member.bot = True

    inviter_user = MagicMock(spec=discord.User)
    inviter_user.id = 222222222
    inviter_user.name = "HackedAdmin"

    inviter_member = MagicMock(spec=discord.Member)
    inviter_member.id = inviter_user.id
    inviter_member.roles = []
    inviter_member.remove_roles = AsyncMock()
    inviter_member.timeout = AsyncMock()
    guild.get_member = MagicMock(return_value=inviter_member)

    # Simulation d'entrée audit log pour bot_add
    entry = MagicMock()
    entry.created_at = datetime.now(timezone.utc)
    entry.target = bot_member
    entry.user = inviter_user

    async def fake_audit_logs(*args, **kwargs):
        yield entry

    guild.audit_logs = fake_audit_logs

    db = MagicMock()
    db.is_whitelisted = AsyncMock(return_value=False)

    bus = MagicMock()
    bus.emit = AsyncMock()

    append_evidence = AsyncMock()
    dashboard = MagicMock()
    dashboard.send_alert = AsyncMock()

    res = await antinuke.check_bot_add(
        guild, bot_member,
        db=db, bus=bus, append_evidence=append_evidence,
        dashboard_module=dashboard,
    )

    assert res is not None
    assert res["action"] == "rogue_bot_neutralized"
    assert res["bot_removed"] is True
    guild.ban.assert_awaited_once_with(bot_member, reason="SENTINEL Anti-Nuke: Rogue Bot ajouté par HackedAdmin")
    bus.emit.assert_awaited_once()
    append_evidence.assert_awaited_once()


@pytest.mark.asyncio
async def test_rogue_bot_allowed_when_invited_by_owner():
    guild = MagicMock(spec=discord.Guild)
    guild.owner_id = 111111111
    guild.me = MagicMock(spec=discord.Member)
    guild.me.id = 999999999
    guild.me.guild_permissions.view_audit_log = True

    bot_member = MagicMock(spec=discord.Member)
    bot_member.id = 888888888
    bot_member.bot = True

    owner_user = MagicMock(spec=discord.User)
    owner_user.id = 111111111

    entry = MagicMock()
    entry.created_at = datetime.now(timezone.utc)
    entry.target = bot_member
    entry.user = owner_user

    async def fake_audit_logs(*args, **kwargs):
        yield entry

    guild.audit_logs = fake_audit_logs

    db = MagicMock()
    bus = MagicMock()
    append_evidence = AsyncMock()

    res = await antinuke.check_bot_add(
        guild, bot_member,
        db=db, bus=bus, append_evidence=append_evidence,
    )

    assert res is None


@pytest.mark.asyncio
async def test_unauthorized_webhook_destroyed():
    guild = MagicMock(spec=discord.Guild)
    guild.id = 444333222
    guild.owner_id = 111111111
    guild.me = MagicMock(spec=discord.Member)
    guild.me.id = 999999999
    guild.me.guild_permissions.view_audit_log = True
    guild.me.guild_permissions.manage_webhooks = True

    channel = MagicMock(spec=discord.TextChannel)
    channel.id = 666555444
    channel.name = "general"

    wh = MagicMock(spec=discord.Webhook)
    wh.id = 12345
    wh.name = "SpamHook"
    wh.delete = AsyncMock()
    channel.webhooks = AsyncMock(return_value=[wh])

    actor = MagicMock(spec=discord.User)
    actor.id = 333333333

    entry = MagicMock()
    entry.created_at = datetime.now(timezone.utc)
    entry.user = actor
    entry.target = MagicMock()
    entry.target.id = 12345

    async def fake_audit_logs(*args, **kwargs):
        yield entry

    guild.audit_logs = fake_audit_logs

    db = MagicMock()
    db.is_whitelisted = AsyncMock(return_value=False)
    append_evidence = AsyncMock()
    dashboard = MagicMock()
    dashboard.send_alert = AsyncMock()

    destroyed = await antinuke.check_unauthorized_webhook(
        guild, channel,
        db=db, append_evidence=append_evidence,
        dashboard_module=dashboard,
    )

    assert destroyed is True
    wh.delete.assert_awaited_once()
    append_evidence.assert_awaited_once()
