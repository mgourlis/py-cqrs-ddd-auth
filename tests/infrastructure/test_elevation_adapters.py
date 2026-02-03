import pytest
from unittest.mock import AsyncMock

from cqrs_ddd_auth.infrastructure.adapters.elevation import (
    InMemoryElevationStore,
    RedisElevationStore,
)


@pytest.mark.asyncio
async def test_in_memory_elevation_store():
    store = InMemoryElevationStore()
    user_id = "u1"
    action = "delete_project"

    # 1. Not elevated initially
    assert await store.is_elevated(user_id, action) is False

    # 2. Grant elevation
    await store.grant(user_id, action, ttl_seconds=2)
    assert await store.is_elevated(user_id, action) is True

    # 3. Revoke
    await store.revoke(user_id, action)
    assert await store.is_elevated(user_id, action) is False

    # 4. Global revoke
    await store.grant(user_id, "action1", ttl_seconds=10)
    await store.grant(user_id, "action2", ttl_seconds=10)
    await store.revoke(user_id)
    assert await store.is_elevated(user_id, "action1") is False
    assert await store.is_elevated(user_id, "action2") is False


@pytest.mark.asyncio
async def test_redis_elevation_store():
    redis_mock = AsyncMock()
    store = RedisElevationStore(redis_mock, prefix="test:")
    user_id = "u1"
    action = "delete_project"

    # 1. Grant
    await store.grant(user_id, action, ttl_seconds=300)
    redis_mock.setex.assert_called_with("test:u1:delete_project", 300, "1")

    # 2. Check
    redis_mock.exists.return_value = 1
    assert await store.is_elevated(user_id, action) is True

    redis_mock.exists.return_value = 0
    assert await store.is_elevated(user_id, action) is False

    # 3. Revoke
    await store.revoke(user_id, action)
    redis_mock.delete.assert_called()


@pytest.mark.asyncio
async def test_redis_is_elevated_error():
    redis_mock = AsyncMock()
    redis_mock.exists.side_effect = Exception("Connection refused")

    store = RedisElevationStore(redis_mock)

    # Should return False (Fail Closed)
    assert await store.is_elevated("u1", "act") is False


@pytest.mark.asyncio
async def test_redis_grant_error():
    redis_mock = AsyncMock()
    redis_mock.setex.side_effect = Exception("Connection refused")

    store = RedisElevationStore(redis_mock)

    # Should raise (Fail Hard)
    with pytest.raises(Exception):
        await store.grant("u1", "act")


@pytest.mark.asyncio
async def test_redis_revoke_error():
    redis_mock = AsyncMock()
    redis_mock.delete.side_effect = Exception("Connection refused")

    store = RedisElevationStore(redis_mock)

    # Should not raise (Best Effort)
    await store.revoke("u1", "act")


@pytest.mark.asyncio
async def test_revoke_all_pattern():
    redis_mock = AsyncMock()
    store = RedisElevationStore(redis_mock, prefix="auth:")

    # Mock keys finding match
    redis_mock.keys.return_value = ["auth:u1:act1", "auth:u1:act2"]

    await store.revoke("u1")

    redis_mock.keys.assert_called_with("auth:u1:*")
    redis_mock.delete.assert_called_with("auth:u1:act1", "auth:u1:act2")


@pytest.mark.asyncio
async def test_revoke_all_no_matches():
    redis_mock = AsyncMock()
    store = RedisElevationStore(redis_mock, prefix="auth:")

    redis_mock.keys.return_value = []

    await store.revoke("u1")

    redis_mock.keys.assert_called_with("auth:u1:*")
    redis_mock.delete.assert_not_called()
