"""
Tests for OTP Storage Adapters.
"""

import pytest
from unittest.mock import Mock, AsyncMock
from datetime import datetime, timezone, timedelta

from cqrs_ddd_auth.infrastructure.adapters.sqlalchemy_storage import (
    SQLAlchemyOTPChallengeAdapter,
    SQLAlchemyTOTPSecretAdapter,
)
from cqrs_ddd_auth.domain.value_objects import TOTPSecret


@pytest.fixture
def mock_db_session():
    session = AsyncMock()
    session.execute.return_value = Mock()
    session.__aenter__.return_value = session
    session.__aexit__.return_value = None
    factory = Mock(return_value=session)
    return factory, session


# ------------------------------------------------------------------
# OTP Challenge Tests
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_challenge_save_new(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemyOTPChallengeAdapter(factory)

    # Mock no existing
    session.execute.return_value.scalar_one_or_none.return_value = None

    await repo.save_challenge(
        user_id="u1",
        method="email",
        secret="secret",
        expires_at=datetime.now(timezone.utc),
    )

    assert session.add.called


@pytest.mark.asyncio
async def test_challenge_save_existing(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemyOTPChallengeAdapter(factory)

    # Mock existing
    existing = Mock()
    session.execute.return_value.scalar_one_or_none.return_value = existing

    await repo.save_challenge("u1", "email", "secret", datetime.now(timezone.utc))

    # Should check existing was updated
    assert existing.secret == "secret"
    # Should NOT add new
    assert not session.add.called


@pytest.mark.asyncio
async def test_challenge_get(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemyOTPChallengeAdapter(factory)

    challenge_model = Mock(
        challenge_id="c1",
        user_id="u1",
        method="email",
        secret="secret",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        attempts=0,
        status="pending",
        created_at=datetime.now(timezone.utc),
    )

    session.execute.return_value.scalar_one_or_none.return_value = challenge_model

    challenge = await repo.get_challenge("u1", "email")
    assert challenge is not None
    assert challenge.id == "c1"


@pytest.mark.asyncio
async def test_challenge_get_expired(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemyOTPChallengeAdapter(factory)

    challenge_model = Mock(
        challenge_id="c1",
        user_id="u1",
        method="email",
        secret="secret",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),  # Expired
        attempts=0,
        status="pending",
        created_at=datetime.now(timezone.utc),
    )

    session.execute.return_value.scalar_one_or_none.return_value = challenge_model

    challenge = await repo.get_challenge("u1", "email")
    # domain logic returns None if expired
    assert challenge is None


# ------------------------------------------------------------------
# TOTP Secret Tests
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_totp_save_new(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemyTOTPSecretAdapter(factory)

    session.execute.return_value.scalar_one_or_none.return_value = None

    await repo.save("u1", TOTPSecret(secret="SECRET"))
    assert session.add.called


@pytest.mark.asyncio
async def test_totp_get(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemyTOTPSecretAdapter(factory)

    mock_model = Mock(secret="SECRET", enabled=True)
    session.execute.return_value.scalar_one_or_none.return_value = mock_model

    secret = await repo.get_by_user_id("u1")
    assert secret is not None
    assert secret.secret == "SECRET"


@pytest.mark.asyncio
async def test_totp_delete(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemyTOTPSecretAdapter(factory)

    mock_model = Mock(enabled=True)
    session.execute.return_value.scalar_one_or_none.return_value = mock_model

    await repo.delete("u1")
    assert mock_model.enabled is False
