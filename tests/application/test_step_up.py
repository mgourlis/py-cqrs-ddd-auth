"""
Tests for Step-up Authentication Handlers.
"""

import pytest
from unittest.mock import AsyncMock
from cqrs_ddd_auth.application.handlers import (
    GrantTemporaryElevationHandler,
    RevokeElevationHandler,
    ResumeSensitiveOperationHandler,
)
from cqrs_ddd_auth.application.commands import (
    GrantTemporaryElevation,
    RevokeElevation,
    ResumeSensitiveOperation,
)


@pytest.fixture
def mock_elevation_store():
    return AsyncMock()


@pytest.fixture
def mock_operation_store():
    return AsyncMock()


@pytest.mark.asyncio
async def test_grant_elevation_success(mock_elevation_store):
    handler = GrantTemporaryElevationHandler(elevation_store=mock_elevation_store)

    cmd = GrantTemporaryElevation(
        user_id="u1", action="delete_resource", ttl_seconds=300
    )
    resp = await handler.handle(cmd)

    assert resp.result.success
    assert resp.result.user_id == "u1"
    # Note: handler currently only checks if store exists, doesn't call methods yet


@pytest.mark.asyncio
async def test_revoke_elevation_success(mock_elevation_store):
    handler = RevokeElevationHandler(elevation_store=mock_elevation_store)

    cmd = RevokeElevation(user_id="u1", reason="completed")
    resp = await handler.handle(cmd)

    assert resp.result.success
    # Note: handler currently only checks if store exists


@pytest.mark.asyncio
async def test_resume_operation_success(mock_operation_store):
    handler = ResumeSensitiveOperationHandler(operation_store=mock_operation_store)

    cmd = ResumeSensitiveOperation(operation_id="op1")
    resp = await handler.handle(cmd)

    assert resp.result.success
    assert resp.result.operation_id == "op1"
    assert resp.result.resumed is True  # Because operation_store is provided
