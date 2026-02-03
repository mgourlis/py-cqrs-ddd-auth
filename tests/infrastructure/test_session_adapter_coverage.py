import pytest
from unittest.mock import AsyncMock
from cqrs_ddd_auth.infrastructure.adapters.session import (
    InMemorySessionAdapter,
    RedisSessionAdapter,
    KeycloakSessionAdapter,
)
from cqrs_ddd_auth.domain.aggregates import AuthSessionStatus, AuthSession


@pytest.mark.asyncio
async def test_in_memory_revoke_redundant():
    adapter = InMemorySessionAdapter()

    # Create 3 sessions for same user/IP
    mod1 = await adapter.create(ip_address="1.1.1.1")
    mod2 = await adapter.create(ip_address="1.1.1.1")
    mod3 = await adapter.create(ip_address="1.1.1.1")

    s1, s2, s3 = mod1.session, mod2.session, mod3.session
    s1.credentials_validated(subject_id="u1", username="user", requires_otp=False)
    s2.credentials_validated(subject_id="u1", username="user", requires_otp=False)
    s3.credentials_validated(subject_id="u1", username="user", requires_otp=False)

    await adapter.save(s1)
    await adapter.save(s2)
    await adapter.save(s3)

    # Revoke redundant (should keep s3, revoke s1 and s2)
    count = await adapter.revoke_redundant_for_user("u1", "1.1.1.1")
    assert count == 2

    assert (await adapter.get(s1.id)).status == AuthSessionStatus.REVOKED
    assert (await adapter.get(s2.id)).status == AuthSessionStatus.REVOKED
    assert (await adapter.get(s3.id)).status == AuthSessionStatus.AUTHENTICATED


@pytest.mark.asyncio
async def test_redis_save_no_ttl():
    mock_redis = AsyncMock()
    adapter = RedisSessionAdapter(mock_redis)
    session = AuthSession.create().session
    session.expires_at = None  # No TTL

    await adapter.save(session)
    assert mock_redis.set.called


@pytest.mark.asyncio
async def test_redis_revoke_all():
    mock_redis = AsyncMock()
    adapter = RedisSessionAdapter(mock_redis)
    mock_redis.smembers.return_value = [b"s1"]

    # Mock get(s1)
    session = AuthSession.create().session
    session.credentials_validated(subject_id="u1", username="user", requires_otp=False)
    import json

    mock_redis.get.return_value = json.dumps(session.to_dict())

    count = await adapter.revoke_all_for_user("u1")
    assert count == 1
    assert mock_redis.setex.called  # Saved as revoked


@pytest.mark.asyncio
async def test_keycloak_session_adapter_crud():
    mock_idp = AsyncMock()
    mock_pending = InMemorySessionAdapter()
    mock_admin = AsyncMock()
    adapter = KeycloakSessionAdapter(mock_idp, mock_pending, mock_admin)

    # Create
    mod = await adapter.create()
    assert mod.session.id

    # Save
    session = mod.session
    session.credentials_validated(subject_id="u1", username="user", requires_otp=False)
    await adapter.save(session)
    # Check if saved in pending
    assert await mock_pending.get(session.id)

    # Get
    mock_admin.get_realm_settings.return_value = {}
    mock_admin.get_user_sessions.return_value = [
        {"id": session.id, "username": "u", "start": 0}
    ]
    fetched = await adapter.get(session.id)
    assert fetched.subject_id == "u1"

    # Delete
    await adapter.delete(session.id)
    assert not await mock_pending.get(session.id)


@pytest.mark.asyncio
async def test_keycloak_session_revoke_all():
    mock_idp = AsyncMock()
    mock_pending = AsyncMock()
    mock_admin = AsyncMock()
    adapter = KeycloakSessionAdapter(mock_idp, mock_pending, mock_admin)

    mock_pending.revoke_all_for_user.return_value = 1
    count = await adapter.revoke_all_for_user("u1")
    assert count == 1
    assert mock_admin.logout_user.called


@pytest.mark.asyncio
async def test_in_memory_get_expired():
    adapter = InMemorySessionAdapter()
    mod = await adapter.create(expires_in_seconds=-10)  # already expired
    s = mod.session
    await adapter.save(s)

    fetched = await adapter.get(s.id)
    assert fetched is None
    # Check it was deleted
    assert (await adapter.get(s.id)) is None


@pytest.mark.asyncio
async def test_in_memory_get_by_user_inactive():
    adapter = InMemorySessionAdapter()
    mod = await adapter.create()
    s = mod.session
    s.credentials_validated(subject_id="u1", username="u", requires_otp=False)
    s.status = AuthSessionStatus.REVOKED
    await adapter.save(s)

    # Active only
    assert len(await adapter.get_by_user("u1", active_only=True)) == 0
    # Include inactive
    assert len(await adapter.get_by_user("u1", active_only=False)) == 1


@pytest.mark.asyncio
async def test_redis_delete():
    mock_redis = AsyncMock()
    adapter = RedisSessionAdapter(mock_redis)
    mock_redis.get.return_value = None
    await adapter.delete("s1")
    assert mock_redis.delete.called


@pytest.mark.asyncio
async def test_redis_get_none():
    mock_redis = AsyncMock()
    adapter = RedisSessionAdapter(mock_redis)
    mock_redis.get.return_value = None
    assert await adapter.get("s1") is None


@pytest.mark.asyncio
async def test_keycloak_get_by_user_combined():
    mock_idp = AsyncMock()
    mock_pending = AsyncMock()
    mock_admin = AsyncMock()
    adapter = KeycloakSessionAdapter(mock_idp, mock_pending, mock_admin)

    # Found in pending
    p_session = AuthSession.create().session
    mock_pending.get_by_user.return_value = [p_session]

    # Found in Keycloak
    mock_admin.get_realm_settings.return_value = {
        "ssoSessionMaxLifespan": 3600,
        "ssoSessionIdleTimeout": 1800,
    }
    mock_admin.get_user_sessions.return_value = [
        {"id": "s1", "userId": "u1", "username": "u", "start": 0}
    ]

    sessions = await adapter.get_by_user("u1")
    assert len(sessions) == 2
    assert any(s.id == p_session.id for s in sessions)
    assert any(s.id == "s1" for s in sessions)


@pytest.mark.asyncio
async def test_in_memory_revoke():
    adapter = InMemorySessionAdapter()
    mod = await adapter.create()
    s = mod.session
    s.credentials_validated(subject_id="u1", username="u", requires_otp=False)
    await adapter.save(s)

    await adapter.revoke(s.id)
    fetched = await adapter.get(s.id)
    assert fetched.status == AuthSessionStatus.REVOKED


@pytest.mark.asyncio
async def test_redis_revoke():
    mock_redis = AsyncMock()
    adapter = RedisSessionAdapter(mock_redis)
    session = AuthSession.create().session
    session.credentials_validated(subject_id="u1", username="u", requires_otp=False)
    import json

    mock_redis.get.return_value = json.dumps(session.to_dict())

    await adapter.revoke(session.id)
    assert mock_redis.setex.called
    # verify status is revoked in the call
    args, kwargs = mock_redis.setex.call_args
    stored = json.loads(args[2])
    assert stored["status"] == AuthSessionStatus.REVOKED


@pytest.mark.asyncio
async def test_redis_cleanup_expired():
    mock_redis = AsyncMock()
    adapter = RedisSessionAdapter(mock_redis)
    # Just verify it doesn't crash since it's a no-op for Redis
    count = await adapter.cleanup_expired()
    assert count == 0
