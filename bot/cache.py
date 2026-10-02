"""
Couche Redis : fenêtres glissantes pour la vélocité de join et le
rate-limiting du module 6 (credential stuffing webhook).

Pourquoi Redis plutôt qu'un `deque` en mémoire (comme le prototype initial) :
- Survit à un restart du bot (pas de perte de contexte pendant un raid).
- Fonctionne si le bot tourne un jour en plusieurs process/shards.
- ZSET avec score = timestamp -> ZREMRANGEBYSCORE purge automatiquement la
  fenêtre, ZCARD donne le compte en O(log n).

Fix #8 : ajout de message_burst_count() — fenêtre glissante par utilisateur
pour alimenter le message_burst_score du module 3 (qui était toujours à 0
faute de tracking côté cache).
"""
from __future__ import annotations

import time

import redis.asyncio as redis


class Cache:
    def __init__(self, url: str):
        self.url = url
        self.client: redis.Redis | None = None

    async def connect(self):
        try:
            self.client = redis.from_url(self.url, decode_responses=True)
            await self.client.ping()
        except Exception:
            if "@redis:" in self.url or "redis://redis" in self.url:
                fallback_url = self.url.replace("@redis:", "@127.0.0.1:").replace("redis://redis:", "redis://127.0.0.1:")
                self.client = redis.from_url(fallback_url, decode_responses=True)
                await self.client.ping()
            else:
                raise

    async def close(self):
        if self.client:
            await self.client.aclose()

    async def sliding_window_add_and_count(self, key: str, window_seconds: int) -> int:
        """Ajoute un événement 'maintenant' dans la fenêtre glissante `key`,
        purge ce qui est sorti de la fenêtre, retourne le nouveau compte."""
        now = time.time()
        pipe = self.client.pipeline()
        pipe.zadd(key, {f"{now}:{id(now)}": now})
        pipe.zremrangebyscore(key, 0, now - window_seconds)
        pipe.zcard(key)
        pipe.expire(key, window_seconds * 2)
        _, _, count, _ = await pipe.execute()
        return int(count)

    async def sliding_window_count(self, key: str, window_seconds: int) -> int:
        now = time.time()
        await self.client.zremrangebyscore(key, 0, now - window_seconds)
        return int(await self.client.zcard(key))

    async def incr_with_ttl(self, key: str, ttl_seconds: int) -> int:
        """Compteur simple avec expiration — utilisé pour le rate-limit du
        module 6 (tentatives de webhook invalides par source)."""
        pipe = self.client.pipeline()
        pipe.incr(key)
        pipe.expire(key, ttl_seconds, nx=True)
        count, _ = await pipe.execute()
        return int(count)

    async def set_nx_ttl(self, key: str, value: str, ttl_seconds: int) -> bool:
        """SET NX avec TTL : utilisé pour le dédoublonnage de nonce côté
        fédération (défense supplémentaire en plus de la table Postgres)."""
        if not self.client:
            return False
        return bool(await self.client.set(key, value, nx=True, ex=ttl_seconds))

    async def get(self, key: str) -> str | None:
        """Récupère une valeur de clé string."""
        if not self.client:
            return None
        return await self.client.get(key)

    async def delete(self, key: str) -> int:
        """Supprime une clé."""
        if not self.client:
            return 0
        return await self.client.delete(key)

    async def message_burst_count(self, user_id: int, guild_id: int,
                                   window_seconds: int = 60) -> int:
        """Fix #8 — Fenêtre glissante de messages par utilisateur, pour
        alimenter le message_burst_score du module 3.
        Appelé dans on_message (incrémente + retourne) ET dans on_member_join
        (lecture seule via sliding_window_count pour scorer sans ajouter)."""
        key = f"sentinel:msgburst:{guild_id}:{user_id}"
        return await self.sliding_window_add_and_count(key, window_seconds)

    async def get_message_burst(self, user_id: int, guild_id: int,
                                 window_seconds: int = 60) -> int:
        """Lecture seule de la fenêtre glissante de messages — utilisé lors
        du scoring en on_member_join pour ne pas polluer la fenêtre d'un
        événement join."""
        key = f"sentinel:msgburst:{guild_id}:{user_id}"
        return await self.sliding_window_count(key, window_seconds)
