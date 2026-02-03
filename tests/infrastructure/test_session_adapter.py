"""
Tests for SQLAlchemy Session Adapter.
"""

import pytest
from unittest.mock import AsyncMock, Mock
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from cqrs_ddd_auth.infrastructure.adapters.sqlalchemy_storage import (
    SQLAlchemySessionAdapter,
)
from cqrs_ddd_auth.domain.aggregates import AuthSession, AuthSessionStatus


@pytest.fixture
def mock_db_session():
    # Session object with async context manager capability
    # Use MagicMock for the session to accept synchronous calls if any (though we use asyncpg)
    # AsyncMock for context manager methods
    session = AsyncMock()
    session.execute.return_value = (
        Mock()
    )  # Return a result proxy which we can configure

    # Configure context manager
    session.__aenter__.return_value = session
    session.__aexit__.return_value = None

    # Factory: Must be a synchronous callable that returns the session object
    # (Because async_sessionmaker() is called sychronously, returning the session)
    factory = Mock(return_value=session)
    return factory, session


@pytest.mark.asyncio
async def test_session_repo_save(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemySessionAdapter(factory)

    auth_session = AuthSession(
        entity_id=str(uuid4()),
        status=AuthSessionStatus.PENDING_CREDENTIALS,
        ip_address="127.0.0.1",
        user_agent="agent",
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        otp_required=False,
    )

    # Configure mock execution result for save check logic
    mock_res = session.execute.return_value
    mock_res.scalar_one_or_none.return_value = None

    await repo.save(auth_session)

    # Verify add was called
    assert session.add.called


@pytest.mark.asyncio
async def test_session_repo_get(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemySessionAdapter(factory)

    # Mock execute result
    mock_result = Mock()
    mock_result.scalar_one_or_none.return_value = None
    session.execute.return_value = mock_result

    res = await repo.get(str(uuid4()))
    assert res is None


@pytest.mark.asyncio
async def test_session_repo_delete(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemySessionAdapter(factory)

    # Needs a session result to delete
    s_id = str(uuid4())

    # delete uses direct execute(delete_stmt), not get -> delete
    # so we primarily verify execute is called
    await repo.delete(s_id)

    assert session.execute.called


@pytest.mark.asyncio
async def test_session_repo_get_by_user(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemySessionAdapter(factory)

    # Mock data with valid fields for from_model extraction
    mock_model = Mock()
    mock_model.status = "authenticated"
    mock_model.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    mock_model.user_claims = (
        None  # Important: prevent Mock object being passed to json.loads
    )
    mock_model.available_otp_methods = None
    mock_model.ip_address = "127.0.0.1"
    mock_model.version = 1

    # .scalars().all() chain
    mock_scalars = Mock()
    mock_scalars.all.return_value = [mock_model]

    mock_result = Mock()
    mock_result.scalars.return_value = mock_scalars
    session.execute.return_value = mock_result

    sessions = await repo.get_by_user("u1", active_only=True)

    assert len(sessions) == 1
    assert session.execute.called


@pytest.mark.asyncio
async def test_session_repo_revoke_all(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemySessionAdapter(factory)

    # Return 2 sessions to revoke
    # Must have None for json fields to avoid TypeError
    # Must have explicit string subject_id to avoid Mock being hashed
    m1 = Mock(
        status="authenticated",
        subject_id="sub1",
        user_claims=None,
        available_otp_methods=None,
        ip_address="127.0.0.1",
        version=1,
    )
    m2 = Mock(
        status="authenticated",
        subject_id="sub1",
        user_claims=None,
        available_otp_methods=None,
        ip_address="127.0.0.1",
        version=1,
    )

    # Must also set session_id for saving
    m1.session_id = "s1"
    m2.session_id = "s2"

    mock_scalars = Mock()
    mock_scalars.all.return_value = [m1, m2]

    mock_result = Mock()
    mock_result.scalars.return_value = mock_scalars
    session.execute.return_value = mock_result

    count = await repo.revoke_all_for_user("sub1")

    assert count == 2
    # m1 and m2 are mock objects representing models.
    # revoke_all retrieves them (via get_by_user -> from_model -> AuthSession)
    # wraps them in AuthSession, calls revoke(), then calls save()
    # save() executes a select to find existing, then updates it.

    assert session.execute.called


@pytest.mark.asyncio
async def test_session_cleanup(mock_db_session):
    factory, session = mock_db_session
    repo = SQLAlchemySessionAdapter(factory)

    # Mock result for delete operation
    mock_result = Mock()
    mock_result.rowcount = 5
    session.execute.return_value = mock_result

    deleted = await repo.cleanup_expired()

    assert deleted == 5
    assert session.execute.called
