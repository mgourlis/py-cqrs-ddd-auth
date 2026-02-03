"""
Tests for Keycloak Session Adapter.
"""

import pytest
from unittest.mock import Mock, AsyncMock

from cqrs_ddd_auth.infrastructure.adapters.session import KeycloakSessionAdapter
from cqrs_ddd_auth.domain.aggregates import AuthSessionStatus


@pytest.fixture
def mock_keycloak():
    return AsyncMock()


@pytest.fixture
def mock_pending_store():
    return AsyncMock()


@pytest.fixture
def mock_admin():
    return AsyncMock()


@pytest.fixture
def adapter(mock_keycloak, mock_pending_store, mock_admin):
    return KeycloakSessionAdapter(
        keycloak_adapter=mock_keycloak,
        pending_store=mock_pending_store,
        keycloak_admin_adapter=mock_admin,
    )


@pytest.mark.asyncio
async def test_create_delegates_to_pending(adapter, mock_pending_store):
    await adapter.create(ip_address="1.2.3.4")
    mock_pending_store.create.assert_called_with(
        ip_address="1.2.3.4", user_agent="", expires_in_seconds=1800
    )


@pytest.mark.asyncio
async def test_get_delegates_to_pending_first(adapter, mock_pending_store):
    session = Mock()
    mock_pending_store.get.return_value = session

    result = await adapter.get("s1")
    assert result == session


@pytest.mark.asyncio
async def test_get_by_user_merges_sources(adapter, mock_pending_store, mock_admin):
    # Pending session (local)
    local_session = Mock(status=AuthSessionStatus.PENDING_CREDENTIALS)
    mock_pending_store.get_by_user.return_value = [local_session]

    # Keycloak session (remote)
    # Ensure get_realm_settings doesn't raise
    mock_admin.get_realm_settings.return_value = {}

    # Explicitly mock get_user_sessions coroutine source
    async def get_sessions(uid):
        return [
            {
                "id": "ks1",
                "username": "user",
                "ipAddress": "1.2.3.4",
                "start": 1600000000000,
                "lastAccess": 1600000000000,
                "clients": {},
            }
        ]

    mock_admin.get_user_sessions.side_effect = get_sessions

    sessions = await adapter.get_by_user("u1")

    # Assert
    assert len(sessions) == 2
    assert sessions[0] == local_session
    assert sessions[1].id == "ks1"
    assert sessions[1].subject_id == "u1"


@pytest.mark.asyncio
async def test_revoke_all_calls_logout(adapter, mock_pending_store, mock_admin):
    mock_pending_store.revoke_all_for_user.return_value = 1

    count = await adapter.revoke_all_for_user("u1")

    assert count == 1
    mock_admin.logout_user.assert_called_with("u1")


@pytest.mark.asyncio
async def test_revoke_redundant(adapter, mock_pending_store, mock_admin):
    mock_pending_store.revoke_redundant_for_user.return_value = 0

    # 2 sessions from same IP
    mock_admin.get_user_sessions.return_value = [
        {"id": "s1", "ipAddress": "1.1.1.1", "start": 2000},
        {"id": "s2", "ipAddress": "1.1.1.1", "start": 1000},  # Older
        {"id": "s3", "ipAddress": "2.2.2.2", "start": 3000},
    ]

    count = await adapter.revoke_redundant_for_user("u1", "1.1.1.1")

    assert count == 1
    # Should revoke oldest one on same IP (s2)
    mock_admin.revoke_user_session.assert_called_with("s2")
