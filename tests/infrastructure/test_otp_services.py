"""
Tests for OTP Services.
"""

import pytest
from unittest.mock import AsyncMock
from datetime import datetime, timezone, timedelta

from cqrs_ddd_auth.infrastructure.adapters.otp import (
    TOTPService,
    EmailOTPService,
    SMSOTPService,
    CompositeOTPService,
    InvalidOTPError,
    OTPError,
)
from cqrs_ddd_auth.domain.value_objects import UserClaims, TOTPSecret
from cqrs_ddd_auth.domain.aggregates import OTPChallenge


@pytest.fixture
def user_claims():
    return UserClaims(
        sub="u1",
        username="user",
        email="user@example.com",
        groups=(),
        roles=(),
        attributes={"phone_number": "+1234567890"},
    )


# -----------------------------------------------------------------------------
# TOTP Tests
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_secret_repo():
    return AsyncMock()


@pytest.fixture
def totp_service(mock_secret_repo):
    return TOTPService(secret_repository=mock_secret_repo)


@pytest.mark.asyncio
async def test_totp_is_required(totp_service, mock_secret_repo, user_claims):
    mock_secret_repo.get_by_user_id.return_value = TOTPSecret(secret="JBSWY3DPEHPK3PXP")
    assert await totp_service.is_required_for_user(user_claims) is True

    mock_secret_repo.get_by_user_id.return_value = None
    assert await totp_service.is_required_for_user(user_claims) is False


@pytest.mark.asyncio
async def test_totp_validate_success(totp_service, mock_secret_repo, user_claims):
    mock_secret_repo.get_by_user_id.return_value = TOTPSecret(secret="JBSWY3DPEHPK3PXP")

    # Use real pyotp for validation consistency
    import pyotp

    totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
    code = totp.now()

    assert await totp_service.validate(user_claims, "totp", code) is True


@pytest.mark.asyncio
async def test_totp_validate_failure(totp_service, mock_secret_repo, user_claims):
    mock_secret_repo.get_by_user_id.return_value = TOTPSecret(secret="JBSWY3DPEHPK3PXP")

    with pytest.raises(InvalidOTPError):
        await totp_service.validate(user_claims, "totp", "000000")


@pytest.mark.asyncio
async def test_totp_setup(totp_service, user_claims):
    secret, uri = await totp_service.setup_totp(user_claims)
    assert isinstance(secret, TOTPSecret)
    assert secret.secret
    assert "otpauth://" in uri


@pytest.mark.asyncio
async def test_totp_confirm_setup(totp_service, mock_secret_repo, user_claims):
    secret = TOTPSecret(secret="JBSWY3DPEHPK3PXP")
    import pyotp

    totp = pyotp.TOTP(secret.secret)
    code = totp.now()

    assert await totp_service.confirm_setup("u1", secret, code) is True
    mock_secret_repo.save.assert_called_once_with("u1", secret)

    # Invalid code
    assert await totp_service.confirm_setup("u1", secret, "000000") is False


@pytest.mark.asyncio
async def test_totp_branches(totp_service, mock_secret_repo, user_claims):
    # No secret repo
    service = TOTPService(secret_repository=None)
    assert await service.is_required_for_user(user_claims) is False
    assert await service.get_available_methods(user_claims) == []
    assert await service.validate(user_claims, "totp", "123") is False

    # Send challenge message
    assert (
        await totp_service.send_challenge(user_claims, "totp")
        == "Enter the code from your authenticator app"
    )

    # Validate user not found
    mock_secret_repo.get_by_user_id.return_value = None
    assert await totp_service.validate(user_claims, "totp", "123") is False


# -----------------------------------------------------------------------------
# Email OTP Tests
# -----------------------------------------------------------------------------


@pytest.fixture
def mock_otp_repo():
    return AsyncMock()


@pytest.fixture
def mock_email_sender():
    return AsyncMock()


@pytest.fixture
def email_service(mock_otp_repo, mock_email_sender):
    return EmailOTPService(otp_repository=mock_otp_repo, email_sender=mock_email_sender)


@pytest.mark.asyncio
async def test_email_send_challenge(
    email_service, mock_otp_repo, mock_email_sender, user_claims
):
    msg = await email_service.send_challenge(user_claims, "email")

    assert "Code sent to" in msg
    mock_otp_repo.save_challenge.assert_called_once()
    mock_email_sender.send.assert_called_once()

    # Check save args
    args = mock_otp_repo.save_challenge.call_args[1]
    assert args["user_id"] == "u1"
    assert args["method"] == "email"


@pytest.mark.asyncio
async def test_email_validate_success(email_service, mock_otp_repo, user_claims):
    import pyotp

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, digits=6, interval=120)
    code = totp.now()

    mock_otp_repo.get_challenge.return_value = OTPChallenge(
        secret=secret, expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
    )

    assert await email_service.validate(user_claims, "email", code) is True
    mock_otp_repo.mark_used.assert_called()


@pytest.mark.asyncio
async def test_email_validate_failures(email_service, mock_otp_repo, user_claims):
    # No pending
    mock_otp_repo.get_challenge.return_value = None
    with pytest.raises(InvalidOTPError, match="No pending challenge"):
        await email_service.validate(user_claims, "email", "123456")

    # Expired
    mock_otp_repo.get_challenge.return_value = OTPChallenge(
        secret="S", expires_at=datetime.now(timezone.utc) - timedelta(seconds=10)
    )
    with pytest.raises(InvalidOTPError, match="expired"):
        await email_service.validate(user_claims, "email", "123456")


@pytest.mark.asyncio
async def test_email_required_methods(email_service, user_claims):
    assert await email_service.is_required_for_user(user_claims) is True
    assert await email_service.get_available_methods(user_claims) == ["email"]

    no_email = UserClaims(sub="u1", username="x", email="", groups=(), roles=())
    assert await email_service.is_required_for_user(no_email) is False
    assert await email_service.get_available_methods(no_email) == []


def test_email_obfuscation(email_service):
    assert email_service._obfuscate_email("test@example.com") == "t****@example.com"
    assert email_service._obfuscate_email("a@b.com") == "a****@b.com"


# -----------------------------------------------------------------------------
# Composite Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_composite_delegation(user_claims):
    mock_totp = AsyncMock()
    mock_email = AsyncMock()

    composite = CompositeOTPService(totp_service=mock_totp, email_service=mock_email)

    # Test method routing
    await composite.send_challenge(user_claims, "email")
    mock_email.send_challenge.assert_called_with(user_claims, "email")

    await composite.validate(user_claims, "totp", "123456")
    mock_totp.validate.assert_called_with(user_claims, "totp", "123456")


@pytest.mark.asyncio
async def test_composite_invalid_method(user_claims):
    composite = CompositeOTPService()  # No services
    with pytest.raises(OTPError, match="not configured"):
        await composite.validate(user_claims, "sms", "123456")

    # Test aggregation is_required_for_user False case
    composite_empty = CompositeOTPService()
    assert await composite_empty.is_required_for_user(user_claims) is False


@pytest.mark.asyncio
async def test_totp_service_missing_secret_repo(user_claims):
    # Coverage for lines 51-52 (get_available_methods with missing secret)
    mock_repo = AsyncMock()
    mock_repo.get_by_user_id.return_value = None
    service = TOTPService(secret_repository=mock_repo)
    assert await service.get_available_methods(user_claims) == []


@pytest.mark.asyncio
async def test_email_service_not_configured(user_claims):
    # Coverage for line 132
    service = EmailOTPService(otp_repository=None, email_sender=None)
    with pytest.raises(OTPError, match="not configured"):
        await service.send_challenge(user_claims, "email")


@pytest.mark.asyncio
async def test_composite_is_required_loop(user_claims):
    # Coverage for line 317 (loop completion returning False)
    m1 = AsyncMock()
    m1.is_required_for_user.return_value = False
    composite = CompositeOTPService(totp_service=m1)
    assert await composite.is_required_for_user(user_claims) is False


@pytest.mark.asyncio
async def test_sms_service(mock_otp_repo, user_claims):
    mock_sms = AsyncMock()
    service = SMSOTPService(otp_repository=mock_otp_repo, sms_sender=mock_sms)

    # Required/Available
    assert await service.is_required_for_user(user_claims) is True
    assert await service.get_available_methods(user_claims) == ["sms"]

    # Send
    msg = await service.send_challenge(user_claims, "sms")
    assert "Code sent to" in msg
    mock_sms.send.assert_called_once()

    # Obfuscation
    assert service._obfuscate_phone("+1234567890") == "+1***-**90"
    assert service._obfuscate_phone("12") == "****"

    # Validate
    import pyotp

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret, digits=6, interval=120)
    mock_otp_repo.get_challenge.return_value = OTPChallenge(
        secret=secret, expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)
    )
    assert await service.validate(user_claims, "sms", totp.now()) is True

    # Validate - invalid code
    with pytest.raises(InvalidOTPError, match="Invalid code"):
        await service.validate(user_claims, "sms", "000000")
    assert mock_otp_repo.increment_attempts.called


@pytest.mark.asyncio
async def test_sms_service_failures(mock_otp_repo, user_claims):
    # Not configured
    service = SMSOTPService(otp_repository=None, sms_sender=None)
    with pytest.raises(OTPError, match="not configured"):
        await service.send_challenge(user_claims, "sms")

    # No phone
    service2 = SMSOTPService(otp_repository=mock_otp_repo, sms_sender=AsyncMock())
    no_phone = UserClaims(
        sub="u1", username="x", email="x@x.com", groups=(), roles=(), attributes={}
    )
    with pytest.raises(OTPError, match="no phone number"):
        await service2.send_challenge(no_phone, "sms")

    # Validate - no challenge
    mock_otp_repo.get_challenge.return_value = None
    with pytest.raises(InvalidOTPError, match="No pending challenge"):
        await service2.validate(user_claims, "sms", "123456")


@pytest.mark.asyncio
async def test_composite_aggregation(user_claims):
    m1, m2 = AsyncMock(), AsyncMock()
    composite = CompositeOTPService(totp_service=m1, email_service=m2)

    m1.is_required_for_user.return_value = False
    m2.is_required_for_user.return_value = True
    assert await composite.is_required_for_user(user_claims) is True

    m1.get_available_methods.return_value = ["totp"]
    m2.get_available_methods.return_value = ["email"]
    assert set(await composite.get_available_methods(user_claims)) == {"totp", "email"}
