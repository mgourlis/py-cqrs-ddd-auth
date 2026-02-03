import pytest
from unittest.mock import AsyncMock, MagicMock
from cqrs_ddd_auth.application.handlers import AuthenticateWithCredentialsHandler
from cqrs_ddd_auth.application.commands import AuthenticateWithCredentials
from cqrs_ddd_auth.application.results import TokenPair, AuthStatus
from cqrs_ddd_auth.application.stateless import PreAuthTokenService
from cqrs_ddd_auth.domain.value_objects import UserClaims
from cqrs_ddd_auth.infrastructure.ports.identity_provider import IdentityProviderPort
from cqrs_ddd_auth.infrastructure.ports.session import AuthSession


@pytest.fixture
def idp_mock():
    mock = MagicMock(spec=IdentityProviderPort)
    mock.authenticate = AsyncMock(
        return_value=TokenPair(access_token="at1", refresh_token="rt1")
    )
    mock.decode_token = AsyncMock(
        return_value=UserClaims(
            sub="user123", username="testuser", email="test@example.com", groups=()
        )
    )
    mock.requires_otp.return_value = False
    return mock


@pytest.fixture
def otp_service_mock():
    mock = AsyncMock()
    mock.is_required_for_user.return_value = False
    return mock


@pytest.fixture
def pre_auth_service():
    return PreAuthTokenService(secret_key=b"0" * 32)


@pytest.mark.asyncio
async def test_auth_optimization_step1_calls_idp(
    idp_mock, otp_service_mock, pre_auth_service
):
    handler = AuthenticateWithCredentialsHandler(
        idp=idp_mock, otp_service=otp_service_mock, pre_auth_service=pre_auth_service
    )

    cmd = AuthenticateWithCredentials(username="u", password="p")
    response = await handler.handle(cmd)

    assert response.result.status == AuthStatus.SUCCESS
    idp_mock.authenticate.assert_called_once()


@pytest.mark.asyncio
async def test_auth_optimization_step2_stateless_skips_idp(
    idp_mock, otp_service_mock, pre_auth_service
):
    handler = AuthenticateWithCredentialsHandler(
        idp=idp_mock, otp_service=otp_service_mock, pre_auth_service=pre_auth_service
    )

    # 1. Setup pre-auth token (stateless session)
    claims = {
        "sub": "user123",
        "username": "testuser",
        "email": "e",
        "groups": [],
        "attributes": {},
    }
    tokens = TokenPair(access_token="at_old", refresh_token="rt_old")
    token = pre_auth_service.encrypt(claims, tokens)

    # 2. Call handler with token instead of password
    # Client doesn't send password anymore
    cmd = AuthenticateWithCredentials(username="u", password="", pre_auth_token=token)
    response = await handler.handle(cmd)

    # Success, and IDP was NOT called for authentication
    assert response.result.status == AuthStatus.SUCCESS
    assert idp_mock.authenticate.call_count == 0
    assert response.result.tokens.access_token == "at_old"


@pytest.mark.asyncio
async def test_auth_optimization_step2_stateful_skips_idp(idp_mock, otp_service_mock):
    session_repo = AsyncMock()
    handler = AuthenticateWithCredentialsHandler(
        idp=idp_mock, otp_service=otp_service_mock, session_repo=session_repo
    )

    # 1. Setup session in repo
    session = AuthSession.from_dict(
        {
            "session_id": "s1",
            "status": "pending_credentials",
            "user_claims": {"sub": "u1", "username": "un", "email": "e", "groups": []},
            "pending_access_token": "at_stored",
            "pending_refresh_token": "rt_stored",
        }
    )
    session_repo.get.return_value = session

    # 2. Call handler with session_id
    cmd = AuthenticateWithCredentials(username="u", password="", session_id="s1")
    response = await handler.handle(cmd)

    assert response.result.status == AuthStatus.SUCCESS
    assert idp_mock.authenticate.call_count == 0
    assert response.result.tokens.access_token == "at_stored"
