import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

from cqrs_ddd_auth.domain.aggregates import (
    AuthSession,
    AuthSessionStatus,
    OTPChallenge,
    OTPChallengeStatus,
)
from cqrs_ddd_auth.domain.events import AuthSessionCreated
from cqrs_ddd_auth.domain.errors import AuthDomainError

# -----------------------------------------------------------------------------
# AuthSession Tests
# -----------------------------------------------------------------------------


def test_auth_session_create_factory():
    mod = AuthSession.create(
        ip_address="1.2.3.4", user_agent="test-ua", expires_in_seconds=60
    )
    session = mod.session
    events = mod.events

    assert session.ip_address == "1.2.3.4"
    assert session.user_agent == "test-ua"
    assert session.status == AuthSessionStatus.PENDING_CREDENTIALS
    assert not session.is_expired()

    assert len(events) == 1
    assert isinstance(events[0], AuthSessionCreated)
    assert events[0].session_id == session.id


def test_auth_session_transition_checks():
    session = AuthSession(status=AuthSessionStatus.PENDING_CREDENTIALS)

    # Valid transition PENDING_CREDENTIALS -> ...
    # This is checked inside credentials_validated, so calling it should work
    session.credentials_validated("sub", "user", False)
    assert session.status == AuthSessionStatus.AUTHENTICATED

    # Invalid transition: Try to validate credentials again on an AUTHENTICATED session
    with pytest.raises(AuthDomainError) as exc:
        session.credentials_validated("sub", "user", False)
    assert exc.value.code == "INVALID_TRANSITION"


def test_auth_session_expiration_check():
    # Expired session
    expired_time = datetime.now(timezone.utc) - timedelta(seconds=1)
    session = AuthSession(
        status=AuthSessionStatus.PENDING_CREDENTIALS, expires_at=expired_time
    )

    assert session.is_expired()

    # Trying to operate on expired session raises SESSION_EXPIRED
    with pytest.raises(AuthDomainError) as exc:
        session.credentials_validated("sub", "user", False)
    assert exc.value.code == "SESSION_EXPIRED"


def test_auth_session_serialization_roundtrip():
    now = datetime.now(timezone.utc)
    original = AuthSession(
        entity_id="s1",
        status=AuthSessionStatus.AUTHENTICATED,
        subject_id="sub1",
        username="user",
        pending_access_token="at",
        otp_required=True,
        available_otp_methods=["email"],
        otp_method_used="email",
        created_at=now,
        expires_at=now + timedelta(hours=1),
        user_claims={"sub": "sub1", "custom": "val"},
    )

    data = original.to_dict()
    restored = AuthSession.from_dict(data)

    assert restored.id == original.id
    assert restored.status == original.status
    assert restored.subject_id == original.subject_id
    assert restored.user_claims["custom"] == "val"
    assert restored.otp_required is True


def test_auth_session_get_user_claims_object():
    session = AuthSession(
        subject_id="sub1",
        username="u1",
        user_claims={
            "sub": "sub1",
            "username": "u1",
            "email": "e@e.com",
            "groups": ["g1"],
            "phone": "123",
        },
    )

    claims = session.get_user_claims_object()
    assert claims.sub == "sub1"
    assert claims.email == "e@e.com"
    assert claims.groups == ("g1",)
    assert claims.attributes["phone"] == "123"

    # Empty claims
    session_empty = AuthSession()
    assert session_empty.get_user_claims_object() is None


def test_auth_session_revoke_check():
    # Can only revoke authenticated session
    session = AuthSession(status=AuthSessionStatus.PENDING_OTP)
    with pytest.raises(AuthDomainError):
        session.revoke()

    session.status = AuthSessionStatus.AUTHENTICATED
    session.revoke()
    assert session.status == AuthSessionStatus.REVOKED


def test_can_validate_otp():
    session = AuthSession(
        status=AuthSessionStatus.PENDING_OTP, pending_access_token="at"
    )
    assert session.can_validate_otp()

    session.pending_access_token = None
    assert not session.can_validate_otp()


# -----------------------------------------------------------------------------
# OTPChallenge Tests
# -----------------------------------------------------------------------------


def test_otp_challenge_factory():
    c = OTPChallenge.create("u1", "email", "secret")
    assert c.user_id == "u1"
    assert c.status == OTPChallengeStatus.PENDING
    assert not c.is_expired()
    assert c.is_valid()


def test_otp_challenge_expiration():
    expired = datetime.now(timezone.utc) - timedelta(seconds=1)
    c = OTPChallenge(expires_at=expired)
    assert c.is_expired()
    assert not c.is_valid()


def test_otp_challenge_max_attempts():
    c = OTPChallenge(attempts=OTPChallenge.MAX_ATTEMPTS)
    # Status might be pending but logical check says invalid if we strictly check attempts < MAX
    # But checking implementation:
    # is_valid = status == PENDING and not expired and attempts < MAX
    assert not c.is_valid()


def test_otp_challenge_verification_flow():
    with patch("pyotp.TOTP") as MockTOTP:
        mock_totp_instance = Mock()
        MockTOTP.return_value = mock_totp_instance

        c = OTPChallenge(secret="sec", status=OTPChallengeStatus.PENDING)

        # 1. Fail
        mock_totp_instance.verify.return_value = False
        assert c.verify_code("bad") is False
        assert c.attempts == 1
        assert c.status == OTPChallengeStatus.PENDING

        # 2. Success
        mock_totp_instance.verify.return_value = True
        assert c.verify_code("good") is True
        assert c.status == OTPChallengeStatus.USED

        # 3. Can't reuse
        assert c.is_valid() is False  # because status is USED
        assert c.verify_code("good") is False


def test_otp_challenge_lockout():
    with patch("pyotp.TOTP") as MockTOTP:
        mock_totp_instance = Mock()
        mock_totp_instance.verify.return_value = False
        MockTOTP.return_value = mock_totp_instance

        c = OTPChallenge(attempts=OTPChallenge.MAX_ATTEMPTS - 1)

        # Fail one more time -> Lockout
        c.verify_code("bad")
        assert c.attempts == OTPChallenge.MAX_ATTEMPTS
        assert c.status == OTPChallengeStatus.MAX_ATTEMPTS
