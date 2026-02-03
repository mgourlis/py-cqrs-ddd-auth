import pytest
from unittest.mock import AsyncMock, Mock
from cqrs_ddd_auth.application.handlers import (
    AuthenticateWithCredentialsHandler,
    ValidateOTPHandler,
    RevokeSessionHandler,
    RevokeAllSessionsHandler,
)
from cqrs_ddd_auth.application.commands import (
    AuthenticateWithCredentials,
    ValidateOTP,
    RevokeSession,
    RevokeAllSessions,
)
from cqrs_ddd_auth.domain.aggregates import AuthSessionStatus


@pytest.fixture
def mock_idp():
    return AsyncMock()


@pytest.fixture
def mock_session_repo():
    return AsyncMock()


@pytest.fixture
def mock_otp():
    return AsyncMock()


@pytest.mark.asyncio
async def test_auth_cred_handler_generic_exception(mock_idp, mock_session_repo):
    handler = AuthenticateWithCredentialsHandler(
        idp=mock_idp, session_repo=mock_session_repo
    )
    mock_idp.authenticate.side_effect = Exception("Unexpected")

    cmd = AuthenticateWithCredentials(username="u", password="p", track_session=True)
    resp = await handler.handle(cmd)

    assert not resp.result.is_success
    assert resp.result.error_message == "Unexpected"


@pytest.mark.asyncio
async def test_auth_cred_stateful_continuation_not_found(mock_session_repo):
    handler = AuthenticateWithCredentialsHandler(
        idp=Mock(), session_repo=mock_session_repo
    )
    mock_session_repo.get.return_value = None

    cmd = AuthenticateWithCredentials(
        username="u", password="p", session_id="missing", track_session=True
    )
    resp = await handler.handle(cmd)

    assert not resp.result.is_success
    assert resp.result.error_code == "SESSION_NOT_FOUND"


@pytest.mark.asyncio
async def test_auth_cred_stateful_continuation_expired(mock_session_repo):
    handler = AuthenticateWithCredentialsHandler(
        idp=Mock(), session_repo=mock_session_repo
    )
    session = Mock()
    session.is_expired.return_value = True
    mock_session_repo.get.return_value = session

    cmd = AuthenticateWithCredentials(
        username="u", password="p", session_id="expired", track_session=True
    )
    resp = await handler.handle(cmd)

    assert not resp.result.is_success
    assert resp.result.error_code == "SESSION_EXPIRED"


@pytest.mark.asyncio
async def test_validate_otp_no_pending_tokens(mock_session_repo, mock_otp):
    handler = ValidateOTPHandler(otp_service=mock_otp, session_repo=mock_session_repo)

    session = Mock()  # Mock session object
    session.status = AuthSessionStatus.PENDING_OTP
    session.id = "s1"
    session.is_expired.return_value = False
    session.get_user_claims_object.return_value = Mock()
    session.pending_access_token = None  # The critical missing piece
    session.otp_validated.return_value = Mock(events=[])

    mock_session_repo.get.return_value = session
    mock_otp.validate.return_value = True

    cmd = ValidateOTP(session_id="s1", code="123", method="totp")
    resp = await handler.handle(cmd)

    assert not resp.result.is_success
    assert resp.result.error_code == "NO_PENDING_TOKENS"


@pytest.mark.asyncio
async def test_validate_otp_exception_handling(mock_session_repo, mock_otp):
    handler = ValidateOTPHandler(otp_service=mock_otp, session_repo=mock_session_repo)
    # mock_session_repo.get.side_effect = Exception("DB Error")
    # The handler does not catch exceptions from repo.get() (it's outside failure try/except block)
    # So we strictly test the try/except block coverage by injecting error INSIDE that block.

    cmd = ValidateOTP(session_id="s1", code="123", method="totp")

    mock_session = Mock(is_expired=lambda: False)
    mock_session.get_user_claims_object.side_effect = Exception("Logic Error")

    # Fix iterable error
    mock_mod = Mock()
    mock_mod.events = []
    mock_session.fail.return_value = mock_mod

    mock_session_repo.get.return_value = mock_session

    resp = await handler.handle(cmd)
    assert not resp.result.is_success
    assert resp.result.error_message == "Logic Error"


@pytest.mark.asyncio
async def test_revoke_session_exception(mock_session_repo):
    handler = RevokeSessionHandler(session_repo=mock_session_repo)
    mock_session_repo.revoke.side_effect = Exception("DB Fail")

    resp = await handler.handle(RevokeSession(session_id="s1"))
    assert not resp.result.success


@pytest.mark.asyncio
async def test_revoke_all_sessions_exception(mock_session_repo):
    handler = RevokeAllSessionsHandler(session_repo=mock_session_repo)
    mock_session_repo.revoke_all_for_user.side_effect = Exception("DB Fail")

    resp = await handler.handle(RevokeAllSessions(user_id="u1"))
    assert not resp.result.success
