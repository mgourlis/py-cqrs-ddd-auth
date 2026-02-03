"""
Tests for TokenRefreshAdapter.
"""

import pytest
from unittest.mock import AsyncMock, Mock
from cqrs_ddd_auth.refresh.adapter import TokenRefreshAdapter
from cqrs_ddd_auth.infrastructure.adapters.keycloak import TokenResponse


@pytest.fixture
def mock_idp():
    mock = Mock()
    mock.decode_token = AsyncMock()
    mock.refresh = AsyncMock()
    return mock


@pytest.mark.asyncio
async def test_no_access_token(mock_idp):
    adapter = TokenRefreshAdapter(mock_idp)
    res = await adapter.process_request(None, "rt")
    assert res.needs_auth is True


@pytest.mark.asyncio
async def test_access_token_still_valid(mock_idp):
    import time

    adapter = TokenRefreshAdapter(mock_idp, access_token_threshold_seconds=60)

    # Mock claims expiring in 1000s
    mock_claims = Mock()
    mock_claims.exp = time.time() + 1000
    mock_idp.decode_token.return_value = mock_claims

    res = await adapter.process_request("at", "rt")

    assert res.current_token == "at"
    assert res.was_refreshed is False
    mock_idp.refresh.assert_not_called()


@pytest.mark.asyncio
async def test_access_token_expired_refresh_success(mock_idp):
    import time

    adapter = TokenRefreshAdapter(mock_idp, access_token_threshold_seconds=60)

    # Mock claims expiring in 30s (below 60s threshold)
    mock_claims = Mock()
    mock_claims.exp = time.time() + 30
    mock_idp.decode_token.return_value = mock_claims

    # Mock refresh response
    mock_idp.refresh.return_value = TokenResponse("new_at", "new_rt", 300, 600)

    res = await adapter.process_request("at", "rt")

    assert res.was_refreshed is True
    assert res.new_access_token == "new_at"
    assert res.new_refresh_token == "new_rt"


@pytest.mark.asyncio
async def test_refresh_failed(mock_idp):
    adapter = TokenRefreshAdapter(mock_idp)
    mock_idp.decode_token.side_effect = Exception("Expired")
    mock_idp.refresh.side_effect = Exception("Invalid RT")

    res = await adapter.process_request("at", "rt")

    assert res.needs_auth is True
