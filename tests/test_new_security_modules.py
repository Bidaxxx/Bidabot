"""
Tests unitaires pour les nouveaux modules de sécurité :
- Module 18 : Anti-Nuke (neutralisation de modérateur compromis)
- Module 19 : Anti-Impersonation (usurpation d'identité du staff)
- Module 20 : Anti-Ghostping (traçage des mentions supprimées)
- Module 17 : Révocation automatique d'invitations compromises
"""
import asyncio
import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import discord
import pytest

from bot.modules import antinuke, anti_impersonation, antighostping, invite_audit, antiscam


# ── Tests Module 18 : Anti-Nuke ──────────────────────────────────────

@pytest.mark.asyncio
async def test_antinuke_neutralize_actor():
    """Vérifie que la neutralisation retire les rôles dangereux et applique le timeout."""
    guild = MagicMock(spec=discord.Guild)
    guild.name = "TestGuild"
    guild.me = MagicMock()
    guild.me.top_role = MagicMock()
    guild.me.top_role.__gt__ = lambda self, other: True
    guild.me.guild_permissions.manage_roles = True
    guild.me.guild_permissions.moderate_members = True

    member = MagicMock(spec=discord.Member)
    member.id = 12345
    member.__lt__ = lambda self, other: True

    # Rôle normal vs rôle admin
    role_normal = MagicMock(spec=discord.Role)
    role_normal.name = "Membre"
    role_normal.is_default.return_value = False
    role_normal.permissions = discord.Permissions.none()

    role_admin = MagicMock(spec=discord.Role)
    role_admin.name = "Modérateur"
    role_admin.is_default.return_value = False
    role_admin.permissions = discord.Permissions(administrator=True, manage_channels=True)

    member.roles = [role_normal, role_admin]
    member.remove_roles = AsyncMock()
    member.timeout = AsyncMock()

    guild.get_member.return_value = member

    result = await antinuke.neutralize_actor(guild, 12345, "Test neutralisation")
    assert result["success"] is True
    assert "Modérateur" in result["removed_roles"]
    assert result["timed_out"] is True
    member.remove_roles.assert_called_once()
    member.timeout.assert_called_once()


@pytest.mark.asyncio
async def test_antinuke_threshold_trigger():
    """Vérifie que franchir le seuil d'actions destructrices déclenche la neutralisation et le lockdown."""
    guild = MagicMock(spec=discord.Guild)
    guild.id = 999
    guild.owner_id = 11111  # Le propriétaire est différent de l'attaquant
    guild.me = MagicMock()
    guild.me.id = 99999
    guild.me.guild_permissions.view_audit_log = True
    guild.owner = MagicMock()
    guild.owner.send = AsyncMock()

    # Création d'une entrée audit log récente
    entry = MagicMock()
    entry.created_at = discord.utils.utcnow()
    entry.user = MagicMock()
    entry.user.id = 55555  # Modérateur pirate
    entry.user.name = "RogueMod"
    entry.target = MagicMock()
    entry.target.id = 42

    async def fake_audit_logs(*args, **kwargs):
        yield entry

    guild.audit_logs = fake_audit_logs

    member = MagicMock(spec=discord.Member)
    member.id = 55555
    member.roles = []
    guild.get_member.return_value = member

    bus = MagicMock()
    bus.emit = AsyncMock()
    append_evidence = AsyncMock(return_value={"hash": "test_hash"})
    lockdown_mod = MagicMock()
    lockdown_mod.trigger = AsyncMock()
    dashboard_mod = MagicMock()
    dashboard_mod.send_alert = AsyncMock()

    # Seuil fixé à 2 suppressions en 10 secondes
    custom_thresholds = {"channel_delete": (2, 10)}

    # 1ère suppression -> en dessous du seuil
    res1 = await antinuke.check_action(
        guild, "channel_delete", 42,
        cache=None, db=None, bus=bus, append_evidence=append_evidence,
        lockdown_module=lockdown_mod, dashboard_module=dashboard_mod,
        custom_thresholds=custom_thresholds,
    )
    assert res1 is None
    lockdown_mod.trigger.assert_not_called()

    # 2ème suppression -> seuil atteint (2/2) !
    res2 = await antinuke.check_action(
        guild, "channel_delete", 43,
        cache=None, db=None, bus=bus, append_evidence=append_evidence,
        lockdown_module=lockdown_mod, dashboard_module=dashboard_mod,
        custom_thresholds=custom_thresholds,
    )
    assert res2 is not None
    assert res2["action"] == "channel_delete"
    assert res2["count"] >= 2
    lockdown_mod.trigger.assert_called_once()
    bus.emit.assert_called_with("risk_critical", res2)
    dashboard_mod.send_alert.assert_called_once()


@pytest.mark.asyncio
async def test_antinuke_mass_channel_and_role_creation():
    """Vérifie que la création massive de salons ou de rôles est bloquée et que les objets sont nettoyés."""
    guild = MagicMock(spec=discord.Guild)
    guild.id = 888
    guild.owner_id = 1111
    guild.me = MagicMock()
    guild.me.id = 99999
    guild.me.guild_permissions.view_audit_log = True
    guild.me.guild_permissions.manage_channels = True
    guild.me.guild_permissions.manage_roles = True
    guild.owner = MagicMock()
    guild.owner.send = AsyncMock()

    spam_channel = MagicMock(spec=discord.TextChannel)
    spam_channel.id = 701
    spam_channel.name = "raid-spam-channel"
    spam_channel.delete = AsyncMock()

    guild.get_channel.return_value = spam_channel

    entry = MagicMock()
    entry.created_at = discord.utils.utcnow()
    entry.user = MagicMock()
    entry.user.id = 44444
    entry.user.name = "RaidAttacker"
    entry.target = spam_channel

    async def fake_audit_logs(*args, **kwargs):
        yield entry

    guild.audit_logs = fake_audit_logs

    member = MagicMock(spec=discord.Member)
    member.id = 44444
    member.roles = []
    guild.get_member.return_value = member

    bus = MagicMock()
    bus.emit = AsyncMock()
    append_evidence = AsyncMock(return_value={"hash": "test_hash"})
    lockdown_mod = MagicMock()
    lockdown_mod.trigger = AsyncMock()
    dashboard_mod = MagicMock()
    dashboard_mod.send_alert = AsyncMock()

    custom_thresholds = {"channel_create": (3, 10)}

    await antinuke.check_action(guild, "channel_create", 701, cache=None, db=None, bus=bus, append_evidence=append_evidence, lockdown_module=lockdown_mod, dashboard_module=dashboard_mod, custom_thresholds=custom_thresholds)
    await antinuke.check_action(guild, "channel_create", 702, cache=None, db=None, bus=bus, append_evidence=append_evidence, lockdown_module=lockdown_mod, dashboard_module=dashboard_mod, custom_thresholds=custom_thresholds)

    res = await antinuke.check_action(guild, "channel_create", 703, cache=None, db=None, bus=bus, append_evidence=append_evidence, lockdown_module=lockdown_mod, dashboard_module=dashboard_mod, custom_thresholds=custom_thresholds)

    assert res is not None
    assert res["action"] == "channel_create"
    assert res["count"] >= 3
    lockdown_mod.trigger.assert_called_once()
    spam_channel.delete.assert_called()


# ── Tests Module 19 : Anti-Impersonation ──────────────────────────────

def test_impersonation_detection_homoglyphs():
    """Vérifie la détection d'impersonation par homoglyphes cyrilliques et leet-speak."""
    staff_member = MagicMock(spec=discord.Member)
    staff_member.id = 100
    staff_member.name = "Administrator"
    staff_member.display_name = "Administrator"

    protected_staff = [(staff_member, ["Administrator"])]

    # 1. Attaquant avec 'a' et 'o' cyrilliques
    impostor = MagicMock(spec=discord.Member)
    impostor.id = 200
    impostor.name = "Аdministratоr"  # Cyrillique
    impostor.display_name = "Аdministratоr"

    match = anti_impersonation.check_impersonation(impostor, protected_staff, threshold=0.82)
    assert match is not None
    assert match[0] == staff_member
    assert match[2] == 1.0  # Exact match après normalisation

    # 2. Attaquant avec leet-speak "4dm1n1str4t0r"
    impostor_leet = MagicMock(spec=discord.Member)
    impostor_leet.id = 201
    impostor_leet.name = "4dm1n1str4t0r"
    impostor_leet.display_name = "4dm1n1str4t0r"

    match_leet = anti_impersonation.check_impersonation(impostor_leet, protected_staff, threshold=0.82)
    assert match_leet is not None
    assert match_leet[0] == staff_member


@pytest.mark.asyncio
async def test_impersonation_handle_renaming():
    """Vérifie que l'usurpateur est renommé et alerté."""
    guild = MagicMock(spec=discord.Guild)
    guild.name = "TestGuild"
    guild.me = MagicMock()
    guild.me.id = 999
    guild.me.top_role = MagicMock()
    guild.me.guild_permissions.manage_nicknames = True
    guild.owner = MagicMock()
    guild.owner.id = 1
    guild.owner.name = "BossOwner"
    guild.owner.display_name = "BossOwner"
    guild.members = []

    impostor = MagicMock(spec=discord.Member)
    impostor.id = 666
    impostor.name = "Boss0wner"  # faux BossOwner avec zéro
    impostor.display_name = "Boss0wner"
    impostor.guild = guild
    impostor.__lt__ = lambda self, other: True
    impostor.edit = AsyncMock()

    dashboard_mod = MagicMock()
    dashboard_mod.send_alert = AsyncMock()
    append_evidence = AsyncMock(return_value={"hash": "evi_hash"})

    res = await anti_impersonation.handle_impersonation(
        impostor,
        db=None, bus=None, append_evidence=append_evidence,
        dashboard_module=dashboard_mod,
    )
    assert res is not None
    assert res["renamed"] is True
    impostor.edit.assert_called_once_with(nick="[Modéré] Pseudo Suspect", reason="SENTINEL: Usurpation de BossOwner")
    dashboard_mod.send_alert.assert_called_once()


# ── Tests Module 20 : Anti-Ghostping ──────────────────────────────────

@pytest.mark.asyncio
async def test_antighostping_detection():
    """Vérifie que la suppression d'un message avec mentions génère une alerte ghost-ping."""
    guild = MagicMock(spec=discord.Guild)
    guild.id = 111
    guild.name = "TestGuild"
    guild.text_channels = []

    channel = MagicMock(spec=discord.TextChannel)
    channel.id = 222
    channel.name = "general"

    msg = MagicMock(spec=discord.Message)
    msg.guild = guild
    msg.channel = channel
    msg.content = "Salut @everyone venez voir !"
    msg.author = MagicMock()
    msg.author.id = 333
    msg.author.bot = False
    msg.author.__str__ = lambda self: "GhostAttacker#1234"
    msg.created_at = discord.utils.utcnow() - datetime.timedelta(seconds=5)  # 5 secondes
    msg.mention_everyone = True
    msg.mentions = []
    msg.role_mentions = []

    dashboard_mod = MagicMock()
    dashboard_mod.send_alert = AsyncMock()
    append_evidence = AsyncMock(return_value={"hash": "ghost_hash"})

    res = await antighostping.handle_deleted_message(
        msg, db=None, append_evidence=append_evidence,
        dashboard_module=dashboard_mod, max_age_seconds=90,
    )

    assert res is not None
    assert res["is_critical"] is True
    assert "@everyone / @here" in res["mentions"]
    dashboard_mod.send_alert.assert_called_once()
    append_evidence.assert_called_once()


# ── Tests Module 17 : Révocation automatique des invitations ──────────

@pytest.mark.asyncio
async def test_invite_auto_revocation_at_70_percent():
    """Vérifie que si une invitation représente 75% des joiners récents, elle est révoquée."""
    guild = MagicMock(spec=discord.Guild)
    guild.id = 777
    guild.name = "RaidTarget"
    guild.me = MagicMock()
    guild.me.guild_permissions.manage_guild = True

    # 4 joiners via "badlink", 1 via "otherlink" -> 80% (>= 70%)
    db = MagicMock()
    db.get_invite_usage_window = AsyncMock(return_value=[
        {"invite_code": "badlink"},
        {"invite_code": "badlink"},
        {"invite_code": "badlink"},
        {"invite_code": "badlink"},
        {"invite_code": "otherlink"},
    ])
    db.flag_invite = AsyncMock()

    invite_obj = MagicMock(spec=discord.Invite)
    invite_obj.code = "badlink"
    invite_obj.delete = AsyncMock()
    invite_obj.inviter = MagicMock()
    invite_obj.inviter.id = 888

    guild.fetch_invite = AsyncMock(return_value=invite_obj)

    bus = MagicMock()
    bus.emit = AsyncMock()
    append_evidence = AsyncMock(return_value={"hash": "invite_hash"})
    dashboard_mod = MagicMock()
    dashboard_mod.send_alert = AsyncMock()

    payload = await invite_audit.check_raid_via_invite(
        guild, db, bus, append_evidence,
        dashboard_module=dashboard_mod,
        raid_ratio_threshold=0.70,
        min_joiners=5,
    )

    assert payload is not None
    assert payload["invite_code"] == "badlink"
    assert payload["auto_revoked"] is True
    invite_obj.delete.assert_called_once()
    dashboard_mod.send_alert.assert_called_once()
