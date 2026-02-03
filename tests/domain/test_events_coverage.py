from cqrs_ddd_auth.domain.events import (
    AuthSessionCreated,
    CredentialsValidated,
    OTPRequired,
    OTPChallengeIssued,
    OTPValidated,
    OTPValidationFailed,
    AuthenticationSucceeded,
    AuthenticationFailed,
    SessionRevoked,
    TokenRefreshed,
    TokenExpired,
    IdentityChanged,
    UserCreatedInIdP,
    UserUpdatedInIdP,
    UserDeletedInIdP,
    UserRolesAssigned,
    UserRolesRemoved,
    UserAddedToGroups,
    UserRemovedFromGroups,
    SensitiveOperationRequested,
    SensitiveOperationCompleted,
    TemporaryElevationGranted,
    TemporaryElevationRevoked,
)


def test_auth_session_created():
    data = {
        "session_id": "s1",
        "ip_address": "1.1.1.1",
        "user_agent": "ua",
        "event_id": "e1",
        "correlation_id": "c1",
        "causation_id": "ca1",
        "user_id": "u1",
    }
    event = AuthSessionCreated.from_dict(data)
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.session_id == "s1"
    assert event.ip_address == "1.1.1.1"


def test_credentials_validated():
    data = {"session_id": "s1", "subject_id": "sub1", "requires_otp": True}
    event = CredentialsValidated.from_dict(data)
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.subject_id == "sub1"
    assert event.requires_otp is True


def test_otp_required():
    data = {
        "session_id": "s1",
        "subject_id": "sub1",
        "available_methods": ["email", "sms"],
    }
    event = OTPRequired.from_dict(data)
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.available_methods == ("email", "sms")


def test_otp_challenge_issued():
    data = {"session_id": "s1", "method": "email", "challenge_id": "cid"}
    event = OTPChallengeIssued.from_dict(data)
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.method == "email"


def test_otp_validated():
    data = {"session_id": "s1", "subject_id": "sub1", "method": "email"}
    event = OTPValidated.from_dict(data)
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.method == "email"


def test_otp_validation_failed():
    data = {"session_id": "s1", "method": "email", "reason": "invalid"}
    event = OTPValidationFailed.from_dict(data)
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.reason == "invalid"


def test_authentication_succeeded():
    data = {
        "session_id": "s1",
        "subject_id": "sub1",
        "username": "user",
        "groups": ["g1"],
        "ip_address": "1.1.1.1",
    }
    event = AuthenticationSucceeded.from_dict(data)
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.username == "user"
    assert event.groups == ("g1",)


def test_authentication_failed():
    data = {"session_id": "s1", "subject_id": "sub1", "reason": "bad_pass"}
    event = AuthenticationFailed.from_dict(data)
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.reason == "bad_pass"


def test_session_revoked():
    data = {"session_id": "s1", "subject_id": "sub1", "reason": "logout"}
    event = SessionRevoked.from_dict(data)
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.reason == "logout"


def test_token_refreshed():
    event = TokenRefreshed.from_dict({"session_id": "s1"})
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"


def test_token_expired():
    event = TokenExpired.from_dict({"session_id": "s1", "token_type": "access"})
    assert event.aggregate_type == "AuthSession"
    assert event.aggregate_id == "s1"
    assert event.token_type == "access"


def test_identity_changed():
    event = IdentityChanged.from_dict({"change_type": "update"})
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id is None
    assert event.change_type == "update"


def test_user_created_in_idp():
    event = UserCreatedInIdP.from_dict({"idp_user_id": "u1", "username": "user"})
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"
    assert event.username == "user"


def test_user_updated_in_idp():
    event = UserUpdatedInIdP.from_dict({"idp_user_id": "u1"})
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"


def test_user_deleted_in_idp():
    event = UserDeletedInIdP.from_dict({"idp_user_id": "u1"})
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"


def test_user_roles_assigned():
    data = {"idp_user_id": "u1", "role_names": ["r1", "r2"]}
    event = UserRolesAssigned.from_dict(data)
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"
    assert event.role_names == ("r1", "r2")

    # Test list handling for JSON compat
    event2 = UserRolesAssigned.from_dict(
        {"idp_user_id": "u1", "role_names": "r1"}
    )  # Defensive coding check?
    # Actually the code expects tuple or list.
    assert event2.role_names == "r1"  # Wait, tuple(str) -> chars in python?
    # Let's check impl: "tuple(roles) if isinstance(roles, list) else roles"
    # So if it's a string, it stays a string.


def test_user_roles_removed():
    event = UserRolesRemoved.from_dict({"idp_user_id": "u1", "role_names": ["r1"]})
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"
    assert event.role_names == ("r1",)


def test_user_added_to_groups():
    event = UserAddedToGroups.from_dict({"idp_user_id": "u1", "group_ids": ["g1"]})
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"
    assert event.group_ids == ("g1",)


def test_user_removed_from_groups():
    event = UserRemovedFromGroups.from_dict({"idp_user_id": "u1", "group_ids": ["g1"]})
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"


def test_sensitive_operation_requested():
    event = SensitiveOperationRequested.from_dict(
        {"user_id": "u1", "operation_id": "op1", "action": "send"}
    )
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"
    assert event.operation_id == "op1"


def test_sensitive_operation_completed():
    event = SensitiveOperationCompleted.from_dict(
        {"user_id": "u1", "operation_id": "op1"}
    )
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"


def test_temporary_elevation_granted():
    event = TemporaryElevationGranted.from_dict(
        {"user_id": "u1", "action": "act", "ttl_seconds": 60}
    )
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"
    assert event.ttl_seconds == 60


def test_temporary_elevation_revoked():
    event = TemporaryElevationRevoked.from_dict({"user_id": "u1", "reason": "done"})
    assert event.aggregate_type == "Identity"
    assert event.aggregate_id == "u1"
