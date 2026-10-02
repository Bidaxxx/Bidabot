"""
Ré-entraîne le modèle de légitimité (module 3) hors-ligne, à partir de
l'historique labellisé (via /sentinel label en production). Fait la même
chose que /sentinel train, mais depuis la ligne de commande — utile pour
un cron nocturne ou un pipeline CI séparé du bot lui-même.

Usage : python -m ml.train_legitimacy
"""
from __future__ import annotations

import asyncio
import logging

from bot.config import settings
from bot.db import Database
from bot.modules.legitimacy import LegitimacyScorer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.train")


async def main():
    db = Database(settings.database_url)
    await db.connect()

    X, y = await db.fetch_training_data()
    logger.info("%d échantillons labellisés trouvés (%d 'raid', %d 'legit')",
                len(y), sum(y), len(y) - sum(y))

    scorer = LegitimacyScorer(
        settings.legitimacy_model_path, settings.legitimacy_min_training_samples,
        settings.thresholds.account_age_min_days, settings.thresholds.join_velocity_per_minute,
    )
    report = scorer.retrain(X, y)

    if report is None:
        logger.warning(
            "Pas assez de données pour entraîner (minimum %d, classes distinctes requises).",
            settings.legitimacy_min_training_samples,
        )
    else:
        logger.info("Modèle sauvegardé : %s", scorer.model_version)
        logger.info("Rapport de classification :\n%s", report)

    await db.close()


if __name__ == "__main__":
    asyncio.run(main())
