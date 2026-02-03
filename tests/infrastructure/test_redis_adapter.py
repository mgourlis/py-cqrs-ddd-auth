"""
Tests for Redis Session Adapter.
"""

import pytest
import json
from unittest.mock import AsyncMock
from datetime import datetime, timezone, timedelta

from cqrs_ddd_auth.infrastructure.adapters.session import RedisSessionAdapter
from cqrs_ddd_auth.domain.aggregates import AuthSession, AuthSessionStatus


@pytest.fixture
def mock_redis():
    mock = AsyncMock()
    # Mock pipeline context manager
    pipeline = AsyncMock()
    pipeline.__aenter__.return_value = pipeline
    pipeline.__aexit__.return_value = None
    mock.pipeline.return_value = pipeline
    return mock


@pytest.mark.asyncio
async def test_save_new_session(mock_redis):
    # Adapter takes redis_client as first arg
    adapter = RedisSessionAdapter(redis_client=mock_redis)

    session = AuthSession(
        entity_id="s1",
        status=AuthSessionStatus.AUTHENTICATED,
        ip_address="127.0.0.1",
        user_agent="test",
        subject_id="u1",  # Fixed param name
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=300),
    )

    await adapter.save(session)

    # Validation: set calls
    # Redis adapter likely uses .set() with ex=ttl or separate expire
    # Logic: if ttl, uses setex. 300s TTL -> setex
    assert mock_redis.setex.called

    # Verify serialization
    call_args = mock_redis.setex.call_args
    key = call_args[0][0]
    value = call_args[0][2]  # setex(key, ttl, value)

    assert key.endswith("s1")
    data = json.loads(value)
    assert data["session_id"] == "s1"
    assert data["subject_id"] == "u1"


@pytest.mark.asyncio
async def test_get_session_hit(mock_redis):
    adapter = RedisSessionAdapter(mock_redis)

    # Mock data
    data = {
        "session_id": "s1",  # Fixed key
        "status": "authenticated",
        "ip_address": "127.0.0.1",
        "user_agent": "test",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=300)).isoformat(),
        "subject_id": "u1",  # Fixed key
        "otp_required": False,
    }
    mock_redis.get.return_value = json.dumps(data)

    session = await adapter.get("s1")

    assert session is not None
    assert session.id == "s1"
    assert session.subject_id == "u1"
    assert session.status == AuthSessionStatus.AUTHENTICATED


@pytest.mark.asyncio
async def test_get_session_miss(mock_redis):
    adapter = RedisSessionAdapter(mock_redis)
    mock_redis.get.return_value = None

    session = await adapter.get("s1")
    assert session is None


@pytest.mark.asyncio
async def test_revoke_all(mock_redis):
    adapter = RedisSessionAdapter(mock_redis)

    # Mock scanning for user sessions
    # Logic uses smembers("auth:user_sessions:u1")
    mock_redis.smembers.return_value = [b"s1", b"s2"]

    # Need to return sessions for get calls
    async def side_effect(key):
        if key.startswith("auth:session:"):
            return json.dumps(
                {
                    "session_id": key.split(":")[-1],
                    "status": "authenticated",
                    "subject_id": "u1",
                    "ip_address": "127.0.0.1",
                    "user_agent": "test",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            )
        return None

    mock_redis.get.side_effect = side_effect

    await adapter.revoke_all_for_user("u1")

    # Should update sessions to REVOKED -> calls save -> calls set/setex
    assert mock_redis.set.called or mock_redis.setex.called


@pytest.mark.asyncio
async def test_redis_delete(mock_redis):
    adapter = RedisSessionAdapter(mock_redis)

    # Needs a session to delete from user set
    mock_redis.get.return_value = json.dumps(
        {
            "session_id": "s1",
            "subject_id": "u1",
            "status": "authenticated",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    await adapter.delete("s1")

    mock_redis.srem.assert_called_with("auth:user_sessions:u1", "s1")
    mock_redis.delete.assert_called_with("auth:session:s1")


@pytest.mark.asyncio
async def test_redis_cleanup(mock_redis):
    adapter = RedisSessionAdapter(mock_redis)
    count = await adapter.cleanup_expired()
    assert count == 0


@pytest.mark.asyncio
async def test_redis_revoke_redundant(mock_redis):
    adapter = RedisSessionAdapter(mock_redis)

    # 2 sessions, s1 (new), s2 (old)
    mock_redis.smembers.return_value = [b"s1", b"s2"]

    def side_effect(key):
        sid = key.split(":")[-1]
        t = datetime.now(timezone.utc)
        if sid == "s2":
            t -= timedelta(hours=1)

        return json.dumps(
            {
                "session_id": sid,
                "subject_id": "u1",
                "ip_address": "1.1.1.1",
                "status": "authenticated",
                "created_at": t.isoformat(),
            }
        )

    mock_redis.get.side_effect = side_effect

    count = await adapter.revoke_redundant_for_user("u1", "1.1.1.1")

    assert count == 1
    # s2 should be revoked
    # Check if save was called with revoked s2
    # mock_redis.setex called multiple times?
    # We just ensure it ran.
