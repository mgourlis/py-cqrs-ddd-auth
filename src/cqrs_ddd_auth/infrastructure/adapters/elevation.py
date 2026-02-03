import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

from cqrs_ddd_auth.infrastructure.ports.elevation import ElevationStore

logger = logging.getLogger("cqrs_ddd_auth.infrastructure.adapters.elevation")


class InMemoryElevationStore(ElevationStore):
    """In-memory implementation of ElevationStore for development and testing."""

    def __init__(self):
        # Key: (user_id, action) -> expiry_time
        self._grants: Dict[tuple[str, str], datetime] = {}

    async def grant(self, user_id: str, action: str, ttl_seconds: int = 300) -> None:
        expiry = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        self._grants[(user_id, action)] = expiry
        logger.debug(f"Granted elevation to {user_id} for {action} until {expiry}")

    async def is_elevated(self, user_id: str, action: str) -> bool:
        expiry = self._grants.get((user_id, action))
        if not expiry:
            return False

        if expiry > datetime.now(timezone.utc):
            return True

        # Cleanup lazily
        del self._grants[(user_id, action)]
        return False

    async def revoke(self, user_id: str, action: Optional[str] = None) -> None:
        if action:
            self._grants.pop((user_id, action), None)
            logger.debug(f"Revoked elevation for {user_id} for action {action}")
        else:
            to_remove = [k for k in self._grants.keys() if k[0] == user_id]
            for k in to_remove:
                del self._grants[k]
            logger.debug(f"Revoked all elevations for {user_id}")

    async def cleanup_expired(self) -> int:
        now = datetime.now(timezone.utc)
        expired = [k for k, expiry in self._grants.items() if expiry <= now]
        for k in expired:
            del self._grants[k]
        return len(expired)


class RedisElevationStore(ElevationStore):
    """Redis implementation of ElevationStore using TTLs for automatic expiration."""

    def __init__(
        self,
        redis_client: Any,
        prefix: str = "auth:elevation:",
    ):
        self._redis = redis_client
        self._prefix = prefix

    def _key(self, user_id: str, action: str) -> str:
        return f"{self._prefix}{user_id}:{action}"

    async def grant(self, user_id: str, action: str, ttl_seconds: int = 300) -> None:
        try:
            key = self._key(user_id, action)
            await self._redis.setex(key, ttl_seconds, "1")
            logger.debug(
                f"Granted Redis elevation to {user_id} for {action} (TTL: {ttl_seconds}s)"
            )
        except Exception as e:
            logger.error(f"Failed to grant Redis elevation for {user_id}: {e}")
            raise

    async def is_elevated(self, user_id: str, action: str) -> bool:
        try:
            key = self._key(user_id, action)
            exists = await self._redis.exists(key)
            return bool(exists)
        except Exception as e:
            logger.error(f"Failed to check Redis elevation for {user_id}: {e}")
            return False

    async def revoke(self, user_id: str, action: Optional[str] = None) -> None:
        try:
            if action:
                await self._redis.delete(self._key(user_id, action))
            else:
                # Match all actions for this user
                pattern = f"{self._prefix}{user_id}:*"
                keys = await self._redis.keys(pattern)
                if keys:
                    await self._redis.delete(*keys)
            logger.debug(f"Revoked elevation in Redis for {user_id}")
        except Exception as e:
            logger.error(f"Failed to revoke Redis elevation for {user_id}: {e}")
            # Best effort - suppress error
            pass

    async def cleanup_expired(self) -> int:
        # Redis handles expiration automatically via TTL
        return 0
