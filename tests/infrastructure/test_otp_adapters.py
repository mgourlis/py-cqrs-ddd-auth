"""
Tests for OTP Adapters.
"""

import pytest
from unittest.mock import AsyncMock, Mock
from cqrs_ddd_auth.infrastructure.adapters.otp import CompositeOTPService


@pytest.mark.asyncio
async def test_composite_service_delegation():
    # Mocks
    totp_svc = Mock()
    totp_svc.validate = AsyncMock(return_value=True)

    email_svc = Mock()
    email_svc.send_challenge = AsyncMock(return_value="Sent")

    svc = CompositeOTPService(
        totp_service=totp_svc, email_service=email_svc, sms_service=None
    )

    # Test validate delegation
    claims = Mock()
    try:
        await svc.validate(claims, "totp", "123")
    except ValueError:
        pass

    # Manually check calls
    assert totp_svc.validate.called
    args = totp_svc.validate.call_args[0]
    # args: (claims, code) - WAIT! TOTPService.validate signature is (claims, code)??
    # Let's check the code I viewed earlier for TOTPService.
    # Code in `src/cqrs_ddd_auth/infrastructure/adapters/otp.py`:
    # async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
    # Ah, TOTPService inherits OTPServicePort which usually has (claims, method, code).
    # BUT in otp.py Step 862:
    # class TOTPService(OTPServicePort):
    #     async def validate(self, claims: UserClaims, method: str, code: str) -> bool:
    # So it takes 3 args.

    assert args[1] == "totp"
    assert args[2] == "123"

    # Test send_challenge delegation
    try:
        await svc.send_challenge(claims, "email")
    except ValueError:
        pass

    assert email_svc.send_challenge.called
    # check args
    c_args = email_svc.send_challenge.call_args[0]
    assert c_args[1] == "email"  # derived from Composite passing method?
    # Composite: return await service.send_challenge(claims, method)
    # EmailService: async def send_challenge(self, claims: UserClaims, method: str) -> str:
    # So yes, 2 args.
