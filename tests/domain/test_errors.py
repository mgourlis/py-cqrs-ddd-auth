"""
Tests for Domain Errors.
"""

from cqrs_ddd_auth.domain.errors import (
    AuthDomainError,
    AuthenticationError,
    AuthorizationError,
    OTPError,
    InvalidTokenError,
)


def test_auth_domain_error_structure():
    err = AuthDomainError("msg", "CODE", {"key": "val"})
    assert str(err) == "msg"
    assert err.message == "msg"
    assert err.code == "CODE"
    assert err.details == {"key": "val"}


def test_authentication_error_defaults():
    err = AuthenticationError()
    assert err.code == "AUTHENTICATION_FAILED"
    assert err.message == "Authentication failed"


def test_authorization_error_details():
    err = AuthorizationError(resource_type="doc", action="read")
    assert err.code == "PERMISSION_DENIED"
    assert err.details["resource_type"] == "doc"
    assert err.details["action"] == "read"


def test_otp_error_inheritance():
    err = OTPError("fail")
    assert isinstance(err, AuthDomainError)
    # OTPError base doesn't define a specific code, defaults to AUTH_ERROR
    assert err.code == "AUTH_ERROR"


def test_invalid_token_code():
    err = InvalidTokenError("bad token")
    assert err.code == "INVALID_TOKEN"
