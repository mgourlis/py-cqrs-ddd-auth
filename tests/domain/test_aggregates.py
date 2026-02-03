"""
Tests for AuthSession Aggregate.
"""

from cqrs_ddd_auth.domain.aggregates import AuthSession
from cqrs_ddd_auth.domain.events import (
    AuthSessionCreated,
    AuthenticationFailed,
    SessionRevoked,
)


def test_create_session():
    mod = AuthSession.create(ip_address="1.1.1.1", user_agent="Mozilla")
    session = mod.session
    events = mod.events

    assert session.ip_address == "1.1.1.1"
    assert session.user_agent == "Mozilla"
    # assert session.is_active is False # Pending
    assert session.status.value == "pending_credentials"
    assert len(events) == 1
    assert isinstance(events[0], AuthSessionCreated)


def test_credentials_validated_no_otp():
    mod = AuthSession.create("127.0.0.1", "agent")
    session = mod.session

    session.credentials_validated(
        subject_id="user1",
        username="alice",
        requires_otp=False,
        available_otp_methods=[],
        access_token="tk",
        refresh_token="rt",
        user_claims={"sub": "user1"},
    )

    assert session.subject_id == "user1"
    assert session.username == "alice"
    assert session.pending_access_token == "tk"

    # In strict DDD, aggregate should likely apply the event to update state.
    # Our implementation applies state changes in the method mostly?
    # Let's verify internal state was updated if the implementation does so.
    # The implementation in this codebase often returns a Modification object
    # but also mutates the aggregate in the method.
    assert session.expires_at is not None


def test_fail_session():
    mod = AuthSession.create("127.0.0.1", "agent")
    session = mod.session

    fail_mod = session.fail("bad password")

    assert isinstance(fail_mod.events[0], AuthenticationFailed)
    assert session.failure_reason == "bad password"


def test_revoke_session():
    mod = AuthSession.create("127.0.0.1", "agent")
    session = mod.session

    # Must be authenticated to revoke
    session.credentials_validated("sub", "user", False)

    revoke_mod = session.revoke("admin action")

    assert isinstance(revoke_mod.events[0], SessionRevoked)
    assert session.status.value == "revoked"
