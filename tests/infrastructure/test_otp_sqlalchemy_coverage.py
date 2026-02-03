import pytest
from unittest.mock import AsyncMock, MagicMock
from contextlib import asynccontextmanager
from cqrs_ddd_auth.infrastructure.adapters.sqlalchemy_storage import (
    SQLAlchemyOTPChallengeAdapter,
    SQLAlchemyTOTPSecretAdapter,
)


@pytest.mark.asyncio
async def test_sqlalchemy_otp_adapters_fallback_coverage():
    # Mock for AsyncSessionFactory
    session_mock = AsyncMock()
    # Mock for result
    result_mock = MagicMock()
    result_mock.scalar_one_or_none.return_value = None
    result_mock.rowcount = 10
    session_mock.execute.return_value = result_mock

    @asynccontextmanager
    async def session_factory():
        yield session_mock

    adapter = SQLAlchemyOTPChallengeAdapter(session_factory)

    # 1. get_challenge MISS
    res = await adapter.get_challenge("u1", "email")
    assert res is None

    # 2. mark_used MISS
    await adapter.mark_used("u1", "email")

    # 3. increment_attempts MISS
    await adapter.increment_attempts("u1", "email")

    # 4. delete_expired success using rowcount
    count = await adapter.delete_expired()
    assert count == 10

    # TOTP Adapter
    totp_adapter = SQLAlchemyTOTPSecretAdapter(session_factory)

    # 5. get_by_user_id MISS
    res = await totp_adapter.get_by_user_id("u1")
    assert res is None

    # 6. delete MISS
    await totp_adapter.delete("u1")
