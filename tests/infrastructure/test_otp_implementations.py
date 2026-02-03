"""
Tests for OTP Storage Implementations (InMemory & Redis).
"""

import pytest
import json
from unittest.mock import AsyncMock
from datetime import datetime, timezone, timedelta

from cqrs_ddd_auth.infrastructure.adapters.otp_storage import (
    InMemoryOTPChallengeAdapter,
    RedisOTPChallengeAdapter,
    InMemoryTOTPSecretAdapter,
    RedisTOTPSecretAdapter,
)
from cqrs_ddd_auth.domain.value_objects import TOTPSecret

# ═══════════════════════════════════════════════════════════════
# In-Memory Tests
# ═══════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_inmemory_challenge_flow():
    repo = InMemoryOTPChallengeAdapter()

    # Save
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    cid = await repo.save_challenge("u1", "email", "secret", expires)
    assert cid

    # Get
    c = await repo.get_challenge("u1", "email")
    assert c is not None
    assert c.id == cid
    assert c.secret == "secret"

    # Increment attempts
    await repo.increment_attempts("u1", "email")
    c = await repo.get_challenge("u1", "email")
    assert c.attempts == 1

    # Mark used
    await repo.mark_used("u1", "email")
    assert c.status.value == "used"

    # Delete expired
    repo._challenges[("u1", "email")].expires_at = datetime.now(
        timezone.utc
    ) - timedelta(hours=1)

    deleted = await repo.delete_expired()
    assert deleted == 1


@pytest.mark.asyncio
async def test_inmemory_totp_flow():
    repo = InMemoryTOTPSecretAdapter()

    secret = TOTPSecret(secret="S")
    await repo.save("u1", secret)

    s = await repo.get_by_user_id("u1")
    assert s.secret == "S"

    await repo.delete("u1")
    s = await repo.get_by_user_id("u1")
    assert s is None


# ═══════════════════════════════════════════════════════════════
# Redis Tests
# ═══════════════════════════════════════════════════════════════


@pytest.fixture
def mock_redis():
    mock = AsyncMock()
    mock.get = AsyncMock(return_value=None)
    mock.set = AsyncMock()
    mock.setex = AsyncMock()
    mock.delete = AsyncMock()
    mock.ttl = AsyncMock(return_value=100)
    return mock


@pytest.mark.asyncio
async def test_redis_challenge_save(mock_redis):
    repo = RedisOTPChallengeAdapter(mock_redis)
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)

    cid = await repo.save_challenge("u1", "email", "secret", expires)

    assert mock_redis.setex.called
    args = mock_redis.setex.call_args
    assert args[0][0] == "auth:otp_challenge:u1:email"  # Key
    # ttl check
    assert args[0][1] > 0
    # content check
    data = json.loads(args[0][2])
    assert data["challenge_id"] == cid
    assert data["secret"] == "secret"


@pytest.mark.asyncio
async def test_redis_challenge_get(mock_redis):
    repo = RedisOTPChallengeAdapter(mock_redis)

    mock_data = {
        "challenge_id": "c1",
        "user_id": "u1",
        "method": "email",
        "secret": "secret",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        "attempts": 0,
        "status": "pending",
    }
    mock_redis.get.return_value = json.dumps(mock_data).encode()

    c = await repo.get_challenge("u1", "email")
    assert c is not None
    assert c.id == "c1"


@pytest.mark.asyncio
async def test_redis_challenge_mark_used(mock_redis):
    repo = RedisOTPChallengeAdapter(mock_redis)

    mock_data = {"status": "pending"}
    mock_redis.get.return_value = json.dumps(mock_data).encode()

    await repo.mark_used("u1", "email")

    assert mock_redis.setex.called
    data = json.loads(mock_redis.setex.call_args[0][2])
    assert data["status"] == "used"


@pytest.mark.asyncio
async def test_redis_totp_save(mock_redis):
    repo = RedisTOTPSecretAdapter(mock_redis)
    secret = TOTPSecret(secret="S")

    await repo.save("u1", secret)

    assert mock_redis.set.called
    data = json.loads(mock_redis.set.call_args[0][1])
    assert data["secret"] == "S"


@pytest.mark.asyncio
async def test_redis_totp_get(mock_redis):
    repo = RedisTOTPSecretAdapter(mock_redis)

    mock_data = {"secret": "S"}
    mock_redis.get.return_value = json.dumps(mock_data).encode()

    s = await repo.get_by_user_id("u1")
    assert s.secret == "S"
