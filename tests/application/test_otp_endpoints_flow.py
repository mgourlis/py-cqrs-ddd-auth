import pytest
from unittest.mock import AsyncMock
from cqrs_ddd_auth.application.handlers import ValidateOTPHandler
from cqrs_ddd_auth.application.commands import ValidateOTP
from cqrs_ddd_auth.domain.value_objects import UserClaims
from cqrs_ddd_auth.domain.events import OTPValidated


@pytest.mark.asyncio
async def test_validate_otp_stateless_success():
    # Mock dependencies
    otp_service = AsyncMock()
    otp_service.validate.return_value = True

    idp = AsyncMock()
    user_claims = UserClaims(
        sub="user_123", username="testuser", email="test@example.com", groups=()
    )
    idp.decode_token.return_value = user_claims

    session_repo = AsyncMock()

    handler = ValidateOTPHandler(
        otp_service=otp_service, session_repo=session_repo, idp=idp
    )

    command = ValidateOTP(
        code="123456", access_token="valid_token", _correlation_id="corr_abc"
    )

    response = await handler.handle(command)

    assert response.result.status == "success"
    assert response.result.user_id == "user_123"

    # Verify event emission
    assert len(response.events) == 1
    event = response.events[0]
    assert isinstance(event, OTPValidated)
    assert event.user_id == "user_123"
    assert event.correlation_id == "corr_abc"

    # Verify IDP was used
    idp.decode_token.assert_awaited_with("valid_token")
    otp_service.validate.assert_awaited_with(
        claims=user_claims, method="totp", code="123456"
    )


@pytest.mark.asyncio
async def test_validate_otp_stateless_failure():
    otp_service = AsyncMock()
    otp_service.validate.return_value = False

    idp = AsyncMock()
    idp.decode_token.return_value = UserClaims(
        sub="user_123", username="testuser", email="test@example.com", groups=()
    )

    handler = ValidateOTPHandler(
        otp_service=otp_service, session_repo=AsyncMock(), idp=idp
    )

    command = ValidateOTP(code="wrong", access_token="token")
    response = await handler.handle(command)

    assert response.result.status == "failed"
    assert response.result.error_code == "INVALID_OTP"
    assert len(response.events) == 0
