"""
Bus d'événements interne.

Différence volontaire avec le prototype initial : celui-ci utilisait une
file asyncio.Queue consommée par une seule tâche de fond, ce qui NE
garantit PAS que "risk_critical" soit traité avant que la war room ne
lise le score en base — deux handlers d'un même événement pouvaient
s'exécuter en parallèle avec le reste de la boucle événementielle, créant
des conditions de course silencieuses.

Ici, `emit()` attend la fin de CHAQUE handler avant de passer au suivant,
dans l'ordre d'enregistrement. Le flux anti-raid documenté
(légitimité -> lockdown -> canary -> fingerprint -> war room -> forensique)
dépend de cet ordre : chaque étape doit avoir fini d'écrire en base avant
que la suivante ne lise le contexte.

Chaque handler est enveloppé dans un asyncio.wait_for (timeout HANDLER_TIMEOUT_S)
pour éviter qu'un await bloquant (DB injoignable, HTTP timeout) gèle tous
les handlers suivants — un lockdown ne doit jamais attendre la war room.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Any, Awaitable, Callable

logger = logging.getLogger("sentinel.bus")

Handler = Callable[[dict[str, Any]], Awaitable[None]]
HANDLER_TIMEOUT_S = 15  # secondes max par handler avant d'abandonner et continuer


class EventBus:
    def __init__(self):
        self._subs: dict[str, list[Handler]] = defaultdict(list)

    def on(self, event: str, handler: Handler) -> None:
        self._subs[event].append(handler)

    async def emit(self, event: str, payload: dict[str, Any]) -> None:
        for handler in self._subs.get(event, []):
            try:
                await asyncio.wait_for(handler(payload), timeout=HANDLER_TIMEOUT_S)
            except asyncio.TimeoutError:
                logger.error(
                    "Handler de '%s' (%s) dépassé (%ds) — abandonné, la chaîne continue.",
                    event, handler, HANDLER_TIMEOUT_S,
                )
            except Exception:
                logger.exception("Erreur dans le handler de '%s' (%s)", event, handler)
                # On continue avec les handlers suivants : un module en panne
                # ne doit jamais bloquer les autres (ex : si le PDF forensique
                # plante, le lockdown doit quand même avoir eu lieu).
