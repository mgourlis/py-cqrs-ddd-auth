import pytest
from unittest.mock import AsyncMock, Mock, patch
from datetime import datetime, timezone, timedelta

from cqrs_ddd_auth.infrastructure.adapters.session import (
    InMemorySessionAdapter,
    RedisSessionAdapter,
    KeycloakSessionAdapter,
)
from cqrs_ddd_auth.infrastructure.adapters.sqlalchemy_storage import (
    SQLAlchemySessionAdapter,
    hash_identifier,
)
from cqrs_ddd_auth.domain.aggregates import AuthSession, AuthSessionStatus

# -----------------------------------------------------------------------------
# InMemorySessionAdapter Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_in_memory_adapter_coverage():
    adapter = InMemorySessionAdapter()

    # 1. Create and get
    mod = await adapter.create(ip_address="1.2.3.4", user_agent="ua")
    session = mod.session
    session.subject_id = "u1"
    session.status = AuthSessionStatus.AUTHENTICATED
    await adapter.save(session)

    # 2. get_by_user filters
    # active_only=True
    sessions = await adapter.get_by_user("u1", active_only=True)
    assert len(sessions) == 1

    # active_only=False
    sessions_all = await adapter.get_by_user("u1", active_only=False)
    assert len(sessions_all) == 1

    # 3. revoke_redundant_for_user coverage
    # Make another session for same user/ip
    mod2 = await adapter.create(ip_address="1.2.3.4")
    s2 = mod2.session
    s2.subject_id = "u1"
    s2.status = AuthSessionStatus.AUTHENTICATED
    # Ensure s2 is newer
    s2._created_at = datetime.now(timezone.utc) + timedelta(seconds=1)
    await adapter.save(s2)

    # Should get 2 sessions now
    assert len(await adapter.get_by_user("u1")) == 2

    # Revoke redundant (keep 1)
    count = await adapter.revoke_redundant_for_user("u1", "1.2.3.4")
    assert count == 1

    # 4. cleanup_expired
    s2.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await adapter.save(s2)

    deleted = await adapter.cleanup_expired()
    # s2 is already revoked, but if we reset it to authenticated+expired we can test cleanup
    # Wait, cleanup checks is_expired() on ALL sessions.
    # s2 is expired. s1 might be valid.
    # Let's verify adapter state first.

    # Clear and reset for cleaner test of cleanup
    adapter.clear()
    mod3 = await adapter.create()
    s3 = mod3.session
    s3.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await adapter.save(s3)

    deleted = await adapter.cleanup_expired()
    assert deleted == 1


# -----------------------------------------------------------------------------
# RedisSessionAdapter Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_adapter_coverage():
    redis_mock = AsyncMock()
    adapter = RedisSessionAdapter(redis_mock)

    # Verify setex call with json
    await adapter.create(ip_address="1.2.3.4")
    assert redis_mock.setex.called


# -----------------------------------------------------------------------------
# KeycloakSessionAdapter Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keycloak_adapter_exceptions():
    kc_adapter = Mock()
    admin_adapter = AsyncMock()
    pending = AsyncMock()

    adapter = KeycloakSessionAdapter(kc_adapter, pending, admin_adapter)

    # 1. get_by_user exception handling
    admin_adapter.get_realm_settings.side_effect = Exception("Fail")
    # Should not crash, just warn and return pending (which we mock empty)
    pending.get_by_user.return_value = []

    sessions = await adapter.get_by_user("u1")
    assert sessions == []

    # 2. revoke exception handling
    admin_adapter.revoke_user_session.side_effect = Exception("Fail")
    # Should not crash
    await adapter.revoke("s1")

    # 3. revoke_all exception handling
    admin_adapter.logout_user.side_effect = Exception("Fail")
    await adapter.revoke_all_for_user("u1")


# -----------------------------------------------------------------------------
# SQLAlchemySessionAdapter Tests
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_sa_session():
    session = AsyncMock()
    session.execute.return_value = Mock()
    session.__aenter__.return_value = session
    session.__aexit__.return_value = None
    return session, Mock(return_value=session)


@pytest.mark.asyncio
async def test_sqlalchemy_adapter_extended_coverage(mock_sa_session):
    session, factory = mock_sa_session
    adapter = SQLAlchemySessionAdapter(factory)

    # 1. Create coverage
    await adapter.create(ip_address="1.2.3.4")
    assert session.add.called

    # 2. Hash identifier coverage (None check)
    assert hash_identifier(None) is None

    # 3. JSON Decode Error in _from_model
    # We mock a model with bad JSON
    mock_model = Mock(
        session_id="s1",
        status="authenticated",
        available_otp_methods="{badjson",
        user_claims="{badjson",
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc),
        version=1,
        # Default all other fields to None to avoid excessive mocking
        subject_id=None,
        username=None,
        pending_access_token=None,
        pending_refresh_token=None,
        otp_required=False,
        otp_method_used=None,
        ip_address=None,
        user_agent=None,
        failure_reason=None,
    )

    # Need to access private method or setup get mock
    restored = adapter._from_model(mock_model)
    assert restored.available_otp_methods == []
    assert restored.user_claims is None

    # 4. Revoke redundant coverage
    # get_by_user returns 2 sessions on same IP
    s1 = AuthSession(
        status=AuthSessionStatus.AUTHENTICATED, ip_address="1.2.3.4", subject_id="u1"
    )
    s2 = AuthSession(
        status=AuthSessionStatus.AUTHENTICATED, ip_address="1.2.3.4", subject_id="u1"
    )
    # s2 created later
    s2._created_at = datetime.now(timezone.utc) + timedelta(seconds=10)

    # We need to mock get_by_user ... effectively mocking execute results
    # It's easier to mock the method directly if we want to test logic *after* DB
    # asking for coverage of `revoke_redundant_for_user`.

    # Let's mock `get_by_user` on the instance to focus on the logic in revoke_redundant
    # (Since we tested get_by_user query construction elsewhere)
    with patch.object(adapter, "get_by_user", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = [s1, s2]
        await adapter.revoke_redundant_for_user("u1", "1.2.3.4")

        # Should revoke s1 (older), save it. s2 matched but kept.
        assert s1.status == AuthSessionStatus.REVOKED
        # Verify save called for s1
        assert session.execute.called  # save does select+update

    # 5. Transaction Rollback
    # Force exception in session scope
    factory_fail = Mock(return_value=session)
    # session.commit side effect
    session.commit.side_effect = Exception("Commit Fail")

    adapter_fail = SQLAlchemySessionAdapter(factory_fail)

    with pytest.raises(Exception, match="Commit Fail"):
        await adapter_fail.create()

    assert session.rollback.called
