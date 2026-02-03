"""
OTP Adapter Implementations.

Provides backends for OTP challenge and TOTP secret storage:
- InMemoryOTPAdapter: For development/testing
- RedisOTPAdapter: For production (fast, distributed)
- SQLAlchemyOTPAdapter: For production (persistent)
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from cqrs_ddd_auth.domain.aggregates import OTPChallenge, OTPChallengeStatus
from cqrs_ddd_auth.domain.value_objects import TOTPSecret
from cqrs_ddd_auth.infrastructure.ports.otp import (
    OTPChallengeRepository,
    TOTPSecretRepository,
)


logger = logging.getLogger("cqrs_ddd_auth.infrastructure.adapters.otp")


# ═══════════════════════════════════════════════════════════════
# IN-MEMORY OTP CHALLENGE ADAPTER (Development/Testing)
# ═══════════════════════════════════════════════════════════════


class InMemoryOTPChallengeAdapter(OTPChallengeRepository):
    """
    In-memory implementation of OTPChallengeRepository.

    Suitable for development and testing.

    Usage:
        adapter = InMemoryOTPChallengeAdapter()
        challenge_id = await adapter.save_challenge(
            user_id="user-123",
            method="email",
            secret="JBSWY3DPEHPK3PXP",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
    """

    def __init__(self):
        # Key: (user_id, method) -> OTPChallenge
        self._challenges: Dict[tuple[str, str], OTPChallenge] = {}

    async def save_challenge(
        self, user_id: str, method: str, secret: str, expires_at: datetime
    ) -> str:
        challenge_id = str(uuid.uuid4())
        challenge = OTPChallenge(
            entity_id=challenge_id,
            user_id=user_id,
            method=method,
            secret=secret,
            expires_at=expires_at,
            attempts=0,
            status=OTPChallengeStatus.PENDING,
        )
        self._challenges[(user_id, method)] = challenge
        logger.debug(f"Created OTP challenge: {challenge_id} for {user_id}/{method}")
        return challenge_id

    async def get_challenge(self, user_id: str, method: str) -> Optional[OTPChallenge]:
        challenge = self._challenges.get((user_id, method))
        if challenge is None:
            return None
        if challenge.is_expired():
            # Don't delete, just mark expired
            challenge.status = OTPChallengeStatus.EXPIRED
        return challenge

    async def mark_used(self, user_id: str, method: str) -> None:
        challenge = self._challenges.get((user_id, method))
        if challenge:
            challenge.mark_used()
            logger.debug(f"Marked OTP challenge used: {user_id}/{method}")

    async def increment_attempts(self, user_id: str, method: str) -> None:
        challenge = self._challenges.get((user_id, method))
        if challenge:
            challenge.increment_attempts()
            logger.debug(
                f"Incremented OTP attempts: {user_id}/{method} -> {challenge.attempts}"
            )

    async def delete_expired(self) -> int:
        expired = [key for key, c in self._challenges.items() if c.is_expired()]
        for key in expired:
            del self._challenges[key]
        return len(expired)

    def clear(self) -> None:
        """Clear all challenges (for testing)."""
        self._challenges.clear()


# ═══════════════════════════════════════════════════════════════
# IN-MEMORY TOTP SECRET ADAPTER (Development/Testing)
# ═══════════════════════════════════════════════════════════════


class InMemoryTOTPSecretAdapter(TOTPSecretRepository):
    """
    In-memory implementation of TOTPSecretRepository.

    Suitable for development and testing. For production,
    TOTP secrets should be stored in a persistent database
    with encryption at rest.

    Usage:
        adapter = InMemoryTOTPSecretAdapter()
        await adapter.save("user-123", totp_secret)
    """

    def __init__(self):
        self._secrets: Dict[str, TOTPSecret] = {}

    async def get_by_user_id(self, user_id: str) -> Optional[TOTPSecret]:
        return self._secrets.get(user_id)

    async def save(self, user_id: str, secret: TOTPSecret) -> None:
        self._secrets[user_id] = secret
        logger.debug(f"Saved TOTP secret for user: {user_id}")

    async def delete(self, user_id: str) -> None:
        self._secrets.pop(user_id, None)
        logger.debug(f"Deleted TOTP secret for user: {user_id}")

    def clear(self) -> None:
        """Clear all secrets (for testing)."""
        self._secrets.clear()


# ═══════════════════════════════════════════════════════════════
# REDIS OTP CHALLENGE ADAPTER (Production)
# ═══════════════════════════════════════════════════════════════


class RedisOTPChallengeAdapter(OTPChallengeRepository):
    """
    Redis implementation of OTPChallengeRepository.

    Production-ready with automatic expiration via Redis TTL.

    Requires: redis[hiredis]

    Usage:
        import redis.asyncio as redis

        client = redis.Redis.from_url("redis://localhost:6379")
        adapter = RedisOTPChallengeAdapter(client)
    """

    def __init__(
        self,
        redis_client: Any,
        prefix: str = "auth:otp_challenge:",
    ):
        self._redis = redis_client
        self._prefix = prefix

    def _key(self, user_id: str, method: str) -> str:
        return f"{self._prefix}{user_id}:{method}"

    async def save_challenge(
        self, user_id: str, method: str, secret: str, expires_at: datetime
    ) -> str:
        import json

        challenge_id = str(uuid.uuid4())
        ttl = max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))

        data = {
            "challenge_id": challenge_id,
            "user_id": user_id,
            "method": method,
            "secret": secret,
            "expires_at": expires_at.isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "attempts": 0,
            "status": OTPChallengeStatus.PENDING.value,
        }

        await self._redis.setex(
            self._key(user_id, method),
            ttl,
            json.dumps(data),
        )

        logger.debug(f"Created Redis OTP challenge: {challenge_id}")
        return challenge_id

    async def get_challenge(self, user_id: str, method: str) -> Optional[OTPChallenge]:
        import json

        data = await self._redis.get(self._key(user_id, method))
        if data is None:
            return None

        parsed = json.loads(data)
        return OTPChallenge(
            entity_id=parsed["challenge_id"],
            user_id=parsed["user_id"],
            method=parsed["method"],
            secret=parsed["secret"],
            expires_at=datetime.fromisoformat(parsed["expires_at"]),
            attempts=parsed.get("attempts", 0),
            status=OTPChallengeStatus(parsed.get("status", "pending")),
        )

    async def mark_used(self, user_id: str, method: str) -> None:
        import json

        data = await self._redis.get(self._key(user_id, method))
        if data:
            parsed = json.loads(data)
            parsed["status"] = OTPChallengeStatus.USED.value
            # Keep for a short time for audit, then expire
            await self._redis.setex(
                self._key(user_id, method),
                60,  # Keep for 1 minute
                json.dumps(parsed),
            )

    async def increment_attempts(self, user_id: str, method: str) -> None:
        import json

        key = self._key(user_id, method)
        data = await self._redis.get(key)
        if data:
            parsed = json.loads(data)
            parsed["attempts"] = parsed.get("attempts", 0) + 1

            # Check if max attempts reached
            if parsed["attempts"] >= 5:  # OTPChallenge.MAX_ATTEMPTS
                parsed["status"] = OTPChallengeStatus.MAX_ATTEMPTS.value

            # Get remaining TTL
            ttl = await self._redis.ttl(key)
            if ttl and ttl > 0:
                await self._redis.setex(key, ttl, json.dumps(parsed))

    async def delete_expired(self) -> int:
        # Redis handles expiration via TTL
        return 0


# ═══════════════════════════════════════════════════════════════
# REDIS TOTP SECRET ADAPTER (Production)
# ═══════════════════════════════════════════════════════════════


class RedisTOTPSecretAdapter(TOTPSecretRepository):
    """
    Redis implementation of TOTPSecretRepository.

    For production, consider using SQLAlchemy with encrypted
    columns instead, as TOTP secrets are long-lived and
    should be persisted to disk.

    This adapter is suitable when:
    - You have Redis persistence enabled (RDB/AOF)
    - You want fast lookups for high-traffic scenarios

    Usage:
        client = redis.Redis.from_url("redis://localhost:6379")
        adapter = RedisTOTPSecretAdapter(client)
    """

    def __init__(
        self,
        redis_client: Any,
        prefix: str = "auth:totp_secret:",
    ):
        self._redis = redis_client
        self._prefix = prefix

    def _key(self, user_id: str) -> str:
        return f"{self._prefix}{user_id}"

    async def get_by_user_id(self, user_id: str) -> Optional[TOTPSecret]:
        import json

        data = await self._redis.get(self._key(user_id))
        if data is None:
            return None

        parsed = json.loads(data)
        return TOTPSecret(
            secret=parsed["secret"],
        )

    async def save(self, user_id: str, secret: TOTPSecret) -> None:
        import json

        data = {
            "secret": secret.secret,
        }

        # No TTL - TOTP secrets are permanent until deleted
        await self._redis.set(self._key(user_id), json.dumps(data))
        logger.debug(f"Saved TOTP secret for user: {user_id}")

    async def delete(self, user_id: str) -> None:
        await self._redis.delete(self._key(user_id))
        logger.debug(f"Deleted TOTP secret for user: {user_id}")


__all__ = [
    # OTP Challenge
    "InMemoryOTPChallengeAdapter",
    "RedisOTPChallengeAdapter",
    # TOTP Secret
    "InMemoryTOTPSecretAdapter",
    "RedisTOTPSecretAdapter",
]
