from __future__ import annotations
import logging
from typing import Any, Callable, Dict, Tuple
from django.core.cache import cache
from django.db import connection

logger = logging.getLogger("lazarus.api")

CACHE_VERSION_KEY = "lazarus:state_version"
EXPIRING_KEYS_TTL = 5     # 1 Stellar ledger (~5 seconds)
HEATMAP_CACHE_TTL = 15    # 3 Stellar ledgers (~15 seconds)
HEALTH_CACHE_TTL = 5


class LazarusCacheManager:
    """
    Redis-backed cache coordinator for Lazarus Protocol.
    Uses an atomic namespace version key (`lazarus:state_version`) so any mutation to
    `MonitoredContract`, `StorageKeyIndex`, or `VoucherLog` invalidates stale ledger caches
    in O(1) time without requiring expensive Redis wildcard `KEYS` scans.
    """

    @classmethod
    def get_state_version(cls) -> int:
        try:
            version = cache.get(CACHE_VERSION_KEY)
            if version is None:
                cache.set(CACHE_VERSION_KEY, 1, timeout=None)
                return 1
            return int(version)
        except Exception as exc:
            logger.warning("Redis cache get_state_version fallback: %s", exc)
            return 1

    @classmethod
    def invalidate_state_caches(cls, reason: str = "state_mutation") -> int:
        try:
            try:
                new_ver = cache.incr(CACHE_VERSION_KEY)
            except ValueError:
                cache.set(CACHE_VERSION_KEY, 2, timeout=None)
                new_ver = 2
            logger.debug(
                "Invalidated Lazarus Redis state caches (new_version=%d reason=%s)",
                new_ver,
                reason,
            )
            return int(new_ver)
        except Exception as exc:
            logger.warning("Redis cache invalidation error: %s", exc)
            return 1

    @classmethod
    def get_or_set_expiring_keys(
        cls,
        current_ledger: int,
        builder_fn: Callable[[], Dict[str, Any]],
        ttl: int = EXPIRING_KEYS_TTL,
    ) -> Tuple[Dict[str, Any], str]:
        version = cls.get_state_version()
        key = f"lazarus:expiring:v{version}:ledger:{current_ledger}"
        try:
            cached = cache.get(key)
            if cached is not None:
                return cached, "HIT"
            payload = builder_fn()
            cache.set(key, payload, timeout=ttl)
            return payload, "MISS"
        except Exception as exc:
            logger.warning("Redis cache error on expiring_keys (%s); querying DB directly", exc)
            return builder_fn(), "BYPASS"

    @classmethod
    def get_or_set_heatmap(
        cls,
        current_ledger: int,
        contract_id: str | None,
        builder_fn: Callable[[], Dict[str, Any]],
        ttl: int = HEATMAP_CACHE_TTL,
    ) -> Tuple[Dict[str, Any], str]:
        version = cls.get_state_version()
        cid_tag = contract_id or "ALL"
        key = f"lazarus:heatmap:v{version}:cid:{cid_tag}:ledger:{current_ledger}"
        try:
            cached = cache.get(key)
            if cached is not None:
                return cached, "HIT"
            payload = builder_fn()
            cache.set(key, payload, timeout=ttl)
            return payload, "MISS"
        except Exception as exc:
            logger.warning("Redis cache error on heatmap (%s); querying DB directly", exc)
            return builder_fn(), "BYPASS"

    @classmethod
    def check_infrastructure_health(cls) -> Dict[str, str]:
        db_status = "ok"
        db_engine = connection.vendor
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1;")
                cursor.fetchone()
        except Exception as exc:
            logger.error("Database health check failed: %s", exc)
            db_status = "error"

        cache_status = "ok"
        try:
            probe_key = "lazarus:health:probe"
            cache.set(probe_key, "1", timeout=5)
            if cache.get(probe_key) != "1":
                cache_status = "degraded"
        except Exception as exc:
            logger.error("Redis cache health check failed: %s", exc)
            cache_status = "error"

        return {
            "database": db_status,
            "database_vendor": db_engine,
            "redis_cache": cache_status,
        }
