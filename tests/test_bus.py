"""
Tests d'intégration du bus d'événements.

Ces tests ne nécessitent ni Postgres, ni Redis, ni Discord — ils mockent
toutes les dépendances externes pour tester la logique d'orchestration du bus
(ordre d'exécution, timeout, continuité en cas d'erreur d'un handler).
"""
from __future__ import annotations

import asyncio
import pytest

from bot.bus import EventBus, HANDLER_TIMEOUT_S


@pytest.mark.asyncio
async def test_handlers_called_in_order():
    """Les handlers d'un même événement sont appelés dans l'ordre d'enregistrement."""
    bus = EventBus()
    order = []

    async def h1(p): order.append(1)
    async def h2(p): order.append(2)
    async def h3(p): order.append(3)

    bus.on("test", h1)
    bus.on("test", h2)
    bus.on("test", h3)

    await bus.emit("test", {})
    assert order == [1, 2, 3]


@pytest.mark.asyncio
async def test_handler_error_does_not_block_next():
    """Une exception dans un handler ne bloque pas les suivants."""
    bus = EventBus()
    called = []

    async def failing(p): raise ValueError("intentionnel")
    async def ok(p): called.append("ok")

    bus.on("test", failing)
    bus.on("test", ok)

    await bus.emit("test", {})
    assert "ok" in called


@pytest.mark.asyncio
async def test_handler_timeout_does_not_block_next():
    """Un handler qui timeout (asyncio.sleep trop long) ne bloque pas les suivants."""
    bus = EventBus()
    called = []

    async def blocking(p):
        # Dort bien plus longtemps que le timeout configuré
        await asyncio.sleep(HANDLER_TIMEOUT_S + 5)

    async def fast(p):
        called.append("fast")

    bus.on("test", blocking)
    bus.on("test", fast)

    # Le timeout du bus est HANDLER_TIMEOUT_S, donc ce test doit terminer
    # en ~HANDLER_TIMEOUT_S secondes, pas en HANDLER_TIMEOUT_S + 5.
    await asyncio.wait_for(bus.emit("test", {}), timeout=HANDLER_TIMEOUT_S + 2)
    assert "fast" in called


@pytest.mark.asyncio
async def test_payload_passed_to_handlers():
    """Le payload est transmis intact à chaque handler."""
    bus = EventBus()
    received = []

    async def capture(p): received.append(p)

    bus.on("ev", capture)
    payload = {"guild_id": 123, "score": 0.9}
    await bus.emit("ev", payload)

    assert received == [payload]


@pytest.mark.asyncio
async def test_unknown_event_does_not_raise():
    """Émettre un événement sans handler enregistré ne lève pas d'exception."""
    bus = EventBus()
    await bus.emit("event_sans_handler", {"x": 1})  # ne doit pas lever
