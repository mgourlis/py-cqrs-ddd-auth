"""
Tests for Application Handlers.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from cqrs_ddd_auth.application.handlers import (
    AuthenticateWithCredentialsHandler,
    ValidateOTPHandler,
    RefreshTokensHandler,
    RevokeSessionHandler,
    RevokeAllSessionsHandler,
    SetupTOTPHandler,
    ConfirmTOTPSetupHandler,
    DisableTOTPHandler,
    LogoutHandler,
    CreateUserHandler,
    UpdateUserHandler,
    DeleteUserHandler,
    SetUserPasswordHandler,
    AssignRolesHandler,
    AddToGroupsHandler,
    SendOTPChallengeHandler,
    GetUserInfoHandler,
    ListActiveSessionsHandler,
    GrantTemporaryElevationHandler,
    RevokeElevationHandler,
    ResumeSensitiveOperationHandler,
    GetAvailableOTPMethodsHandler,
    GetUserHandler,
    GetUserByUsernameHandler,
    ListUsersHandler,
    GetUserRolesHandler,
    GetUserGroupsHandler,
    GetSessionDetailsHandler,
)
from cqrs_ddd_auth.application.commands import (
    AuthenticateWithCredentials,
    ValidateOTP,
    RefreshTokens,
    SendOTPChallenge,
    RevokeSession,
    RevokeAllSessions,
    SetupTOTP,
    ConfirmTOTPSetup,
    DisableTOTP,
    Logout,
    CreateUser,
    UpdateUser,
    DeleteUser,
    SetUserPassword,
    AssignRoles,
    AddToGroups,
    GrantTemporaryElevation,
    RevokeElevation,
    ResumeSensitiveOperation,
)
from cqrs_ddd_auth.application.queries import (
    GetUserInfo,
    ListActiveSessions,
    GetAvailableOTPMethods,
    GetUser,
    GetUserByUsername,
    ListUsers,
    GetUserRoles,
    GetUserGroups,
    GetSessionDetails,
)
from cqrs_ddd_auth.application.results import AuthStatus, RoleInfo
from cqrs_ddd_auth.domain.aggregates import AuthSessionStatus
from cqrs_ddd_auth.domain.value_objects import UserClaims, TOTPSecret
from cqrs_ddd_auth.infrastructure.ports.identity_provider import TokenResponse


@pytest.fixture
def mock_idp():
    mock = AsyncMock()
    # default success
    mock.authenticate.return_value = TokenResponse(
        access_token="at", refresh_token="rt", expires_in=300, refresh_expires_in=600
    )
    mock.decode_token.return_value = UserClaims(
        sub="u1", username="user", email="u@e.com", groups=["user"]
    )
    mock.requires_otp = Mock(return_value=False)
    mock.refresh.return_value = TokenResponse(
        access_token="new_at",
        refresh_token="new_rt",
        expires_in=300,
        refresh_expires_in=600,
    )
    return mock


@pytest.fixture
def mock_otp():
    mock = AsyncMock()
    mock.is_required_for_user.return_value = False
    mock.get_available_methods.return_value = ["totp"]
    mock.validate.return_value = True
    return mock


@pytest.fixture
def mock_session_repo():
    mock = AsyncMock()
    # Default success
    mock.save.return_value = None
    mock.revoke.return_value = None
    mock.revoke_all_for_user.return_value = 1
    return mock


@pytest.fixture
def mock_idp_admin():
    mock = AsyncMock()
    return mock


@pytest.mark.asyncio
async def test_auth_stateless_success(mock_idp, mock_otp):
    handler = AuthenticateWithCredentialsHandler(idp=mock_idp, otp_service=mock_otp)
    cmd = AuthenticateWithCredentials(
        username="user", password="pwd", track_session=False
    )

    resp = await handler.handle(cmd)

    assert resp.result.is_success
    assert resp.result.tokens.access_token == "at"
    assert not resp.result.session_id  # Stateless


@pytest.mark.asyncio
async def test_auth_otp_required(mock_idp, mock_otp):
    mock_otp.is_required_for_user.return_value = True

    handler = AuthenticateWithCredentialsHandler(idp=mock_idp, otp_service=mock_otp)
    cmd = AuthenticateWithCredentials(
        username="user", password="pwd", track_session=False
    )

    resp = await handler.handle(cmd)

    assert not resp.result.is_success
    assert resp.result.requires_otp
    assert "totp" in resp.result.available_otp_methods


@pytest.mark.asyncio
async def test_auth_otp_validate_inline(mock_idp, mock_otp):
    mock_otp.is_required_for_user.return_value = True
    mock_otp.validate.return_value = True

    handler = AuthenticateWithCredentialsHandler(idp=mock_idp, otp_service=mock_otp)
    cmd = AuthenticateWithCredentials(
        username="user",
        password="pwd",
        track_session=False,
        otp_method="totp",
        otp_code="123456",
    )

    resp = await handler.handle(cmd)

    assert resp.result.is_success
    assert resp.result.tokens.access_token == "at"
    mock_otp.validate.assert_called_with(
        claims=mock_idp.decode_token.return_value, method="totp", code="123456"
    )


@pytest.mark.asyncio
async def test_auth_stateful_session_creation(mock_idp, mock_otp, mock_session_repo):
    handler = AuthenticateWithCredentialsHandler(
        idp=mock_idp, otp_service=mock_otp, session_repo=mock_session_repo
    )
    cmd = AuthenticateWithCredentials(
        username="user", password="pwd", track_session=True
    )

    resp = await handler.handle(cmd)

    assert resp.result.is_success
    assert resp.result.session_id
    assert mock_session_repo.save.called


@pytest.mark.asyncio
async def test_auth_group_check_failure_stateless(mock_idp):
    handler = AuthenticateWithCredentialsHandler(idp=mock_idp)
    cmd = AuthenticateWithCredentials(
        username="user", password="pwd", required_groups=["admin"], track_session=False
    )

    resp = await handler.handle(cmd)

    assert not resp.result.is_success
    assert resp.result.error_code == "UNAUTHORIZED_GROUP"


@pytest.mark.asyncio
async def test_auth_group_check_failure_stateful(mock_idp, mock_session_repo):
    handler = AuthenticateWithCredentialsHandler(
        idp=mock_idp, session_repo=mock_session_repo
    )
    mock_idp.authenticate.return_value = TokenResponse(
        access_token="at", refresh_token="rt", expires_in=300, refresh_expires_in=600
    )
    mock_idp.decode_token.return_value = UserClaims(
        sub="u1", username="user", email="e", groups=["user"]
    )

    session = Mock()
    session.id = "s1"
    session.fail.return_value = Mock(events=["FAIL_EVENT"])

    with patch(
        "cqrs_ddd_auth.infrastructure.ports.session.AuthSession.create"
    ) as mock_create:
        mock_create.return_value = Mock(session=session, events=["CREATE_EVENT"])

        cmd = AuthenticateWithCredentials(
            username="user",
            password="pwd",
            track_session=True,
            required_groups=["admin"],
        )
        resp = await handler.handle(cmd)

        assert not resp.result.is_success
        assert "FAIL_EVENT" in resp.events
        assert "CREATE_EVENT" in resp.events
        assert resp.result.error_code == "UNAUTHORIZED_GROUP"


@pytest.mark.asyncio
async def test_validate_otp_session_not_found(mock_session_repo, mock_otp):
    handler = ValidateOTPHandler(otp_service=mock_otp, session_repo=mock_session_repo)
    mock_session_repo.get.return_value = None

    cmd = ValidateOTP(session_id="missing", code="123", method="totp")
    resp = await handler.handle(cmd)
    assert not resp.result.is_success
    assert resp.result.error_code == "SESSION_NOT_FOUND"


@pytest.mark.asyncio
async def test_validate_otp_success_events(mock_idp, mock_otp, mock_session_repo):
    handler = ValidateOTPHandler(otp_service=mock_otp, session_repo=mock_session_repo)

    session = Mock()
    session.otp_method_used = None
    session.subject_id = "u1"
    session.username = "user"
    session.pending_access_token = "at"
    session.pending_refresh_token = "rt"
    session.user_claims = {"sub": "u1", "username": "user", "email": "u@e.com"}
    session.get_user_claims_object = Mock(
        return_value=UserClaims(sub="u1", username="user", email="u@e.com", groups=[])
    )
    # Add id property
    session.id = "s1"

    mock_session_repo.get.return_value = session

    # Mock behavior
    session.otp_validated.return_value = Mock(events=[])
    session.is_expired.return_value = False

    cmd = ValidateOTP(session_id="s1", code="123456", method="totp")

    resp = await handler.handle(cmd)

    assert resp.result.is_success
    assert resp.result.session_id == "s1"


@pytest.mark.asyncio
async def test_refresh_token_success(mock_idp):
    handler = RefreshTokensHandler(idp=mock_idp)
    cmd = RefreshTokens(refresh_token="rt")

    resp = await handler.handle(cmd)

    # Validation
    assert resp.result.access_token == "new_at"


@pytest.mark.asyncio
async def test_send_otp_challenge(mock_idp, mock_otp):
    handler = SendOTPChallengeHandler(otp_service=mock_otp, idp=mock_idp)
    mock_otp.send_challenge.return_value = "Sent"

    cmd = SendOTPChallenge(method="email", access_token="at")

    resp = await handler.handle(cmd)

    assert resp.result.success
    assert resp.result.message == "Sent"


@pytest.mark.asyncio
async def test_revoke_session_success(mock_session_repo):
    handler = RevokeSessionHandler(session_repo=mock_session_repo)
    cmd = RevokeSession(session_id="s1")

    mock_session_repo.revoke.return_value = None

    resp = await handler.handle(cmd)

    assert resp.result.success
    mock_session_repo.revoke.assert_called_with("s1")


@pytest.mark.asyncio
async def test_revoke_all_sessions_success(mock_session_repo):
    handler = RevokeAllSessionsHandler(session_repo=mock_session_repo)
    cmd = RevokeAllSessions(user_id="u1")

    mock_session_repo.revoke_all_for_user.return_value = 5

    resp = await handler.handle(cmd)

    assert resp.result.success
    assert resp.result.sessions_revoked == 5
    mock_session_repo.revoke_all_for_user.assert_called_with("u1")


@pytest.mark.asyncio
async def test_setup_totp_success():
    handler = SetupTOTPHandler(issuer_name="TestApp")
    cmd = SetupTOTP(user_id="u1")

    resp = await handler.handle(cmd)

    assert resp.result.secret
    assert "otpauth://" in resp.result.provisioning_uri
    assert resp.result.user_id == "u1"


@pytest.mark.asyncio
async def test_confirm_totp_setup_success():
    mock_totp_repo = AsyncMock()
    handler = ConfirmTOTPSetupHandler(totp_repo=mock_totp_repo)

    # Generate secret
    secret = TOTPSecret.generate()
    code = secret.get_current_code()

    cmd = ConfirmTOTPSetup(user_id="u1", secret=secret.secret, code=code)
    resp = await handler.handle(cmd)

    assert resp.result is True
    mock_totp_repo.save.assert_called_once()


@pytest.mark.asyncio
async def test_disable_totp_success():
    mock_totp_repo = AsyncMock()
    handler = DisableTOTPHandler(totp_repo=mock_totp_repo)

    secret = TOTPSecret.generate()
    code = secret.get_current_code()
    mock_totp_repo.get_by_user_id.return_value = secret

    cmd = DisableTOTP(user_id="u1", verification_code=code)
    resp = await handler.handle(cmd)

    assert resp.result is True
    mock_totp_repo.delete.assert_called_once_with("u1")


@pytest.mark.asyncio
async def test_auth_stateful_otp_inline_success_events(
    mock_idp, mock_otp, mock_session_repo
):
    handler = AuthenticateWithCredentialsHandler(
        idp=mock_idp, otp_service=mock_otp, session_repo=mock_session_repo
    )
    mock_otp.is_required_for_user.return_value = True
    mock_otp.validate.return_value = True

    session = Mock()
    session.id = "s1"
    # Initial status
    session.status = AuthSessionStatus.PENDING_CREDENTIALS

    def on_credentials_validated(*args, **kwargs):
        session.status = AuthSessionStatus.PENDING_OTP
        return Mock(events=["VAL_EVENT"])

    session.credentials_validated.side_effect = on_credentials_validated
    session.otp_validated.return_value = Mock(events=["OTP_VAL_EVENT"])

    with patch(
        "cqrs_ddd_auth.infrastructure.ports.session.AuthSession.create"
    ) as mock_create:
        mock_create.return_value = Mock(session=session, events=["CREATE_EVENT"])

        cmd = AuthenticateWithCredentials(
            username="user",
            password="pwd",
            track_session=True,
            otp_method="totp",
            otp_code="123456",
        )
        resp = await handler.handle(cmd)

        assert resp.result.is_success
        assert "CREATE_EVENT" in resp.events
        assert "VAL_EVENT" in resp.events
        assert "OTP_VAL_EVENT" in resp.events


@pytest.mark.asyncio
async def test_auth_stateful_otp_inline_failure_events(
    mock_idp, mock_otp, mock_session_repo
):
    handler = AuthenticateWithCredentialsHandler(
        idp=mock_idp, otp_service=mock_otp, session_repo=mock_session_repo
    )
    mock_otp.is_required_for_user.return_value = True
    mock_otp.validate.return_value = False

    session = Mock()
    session.id = "s1"
    session.credentials_validated.return_value = Mock(events=["VAL_EVENT"])
    session.fail.return_value = Mock(events=["FAIL_EVENT"])

    with patch(
        "cqrs_ddd_auth.infrastructure.ports.session.AuthSession.create"
    ) as mock_create:
        mock_create.return_value = Mock(session=session, events=["CREATE_EVENT"])

        cmd = AuthenticateWithCredentials(
            username="user",
            password="pwd",
            track_session=True,
            otp_method="totp",
            otp_code="invalid",
        )
        resp = await handler.handle(cmd)

        assert not resp.result.is_success
        assert "CREATE_EVENT" in resp.events
        # VAL_EVENT is skipped in optimized flow if OTP is invalid
        assert "FAIL_EVENT" in resp.events


@pytest.mark.asyncio
async def test_auth_exception_handling_events(mock_idp, mock_session_repo):
    mock_idp.authenticate.side_effect = Exception("Boom")
    handler = AuthenticateWithCredentialsHandler(
        idp=mock_idp, session_repo=mock_session_repo
    )

    session = Mock()
    session.id = "s1"
    session.fail.return_value = Mock(events=["FAIL_EVENT"])

    with patch(
        "cqrs_ddd_auth.infrastructure.ports.session.AuthSession.create"
    ) as mock_create:
        mock_create.return_value = Mock(session=session, events=["CREATE_EVENT"])

        cmd = AuthenticateWithCredentials(
            username="user", password="pwd", track_session=True
        )
        resp = await handler.handle(cmd)

        assert not resp.result.is_success
        assert "CREATE_EVENT" in resp.events
        assert "FAIL_EVENT" in resp.events
        assert resp.result.error_message == "Boom"


@pytest.mark.asyncio
async def test_refresh_token_failure(mock_idp):
    mock_idp.refresh.side_effect = Exception("Invalid token")
    handler = RefreshTokensHandler(idp=mock_idp)
    cmd = RefreshTokens(refresh_token="bad")
    resp = await handler.handle(cmd)
    assert resp.result.status == AuthStatus.FAILED
    assert resp.result.is_success is False
    assert resp.result.error_message == "Invalid token"


@pytest.mark.asyncio
async def test_send_otp_challenge_failure(mock_idp, mock_otp):
    mock_otp.send_challenge.side_effect = Exception("Failed to send")
    handler = SendOTPChallengeHandler(otp_service=mock_otp, idp=mock_idp)
    cmd = SendOTPChallenge(method="email", access_token="at")

    resp = await handler.handle(cmd)
    assert not resp.result.success
    assert "Failed to send" in resp.result.message


@pytest.mark.asyncio
async def test_validate_otp_expired(mock_session_repo, mock_otp):
    handler = ValidateOTPHandler(otp_service=mock_otp, session_repo=mock_session_repo)
    session = Mock()
    session.is_expired.return_value = True
    mock_session_repo.get.return_value = session

    cmd = ValidateOTP(session_id="s1", code="123", method="totp")
    resp = await handler.handle(cmd)
    assert not resp.result.is_success
    assert resp.result.error_code == "SESSION_EXPIRED"


@pytest.mark.asyncio
async def test_logout_stateful_success(mock_idp, mock_session_repo):
    handler = LogoutHandler(idp=mock_idp, session_repo=mock_session_repo)
    session = Mock()
    session.revoke.return_value = Mock(events=["REVOKE_EVENT"])
    mock_session_repo.get.return_value = session

    cmd = Logout(refresh_token="rt", session_id="s1")
    resp = await handler.handle(cmd)

    assert resp.result.success
    assert "REVOKE_EVENT" in resp.events
    assert mock_session_repo.save.called


@pytest.mark.asyncio
async def test_logout_failure(mock_idp):
    mock_idp.logout.side_effect = Exception("Fail")
    handler = LogoutHandler(idp=mock_idp)
    cmd = Logout(refresh_token="bad")

    resp = await handler.handle(cmd)
    assert not resp.result.success


@pytest.mark.asyncio
async def test_confirm_totp_setup_failure():
    mock_totp_repo = AsyncMock()
    handler = ConfirmTOTPSetupHandler(totp_repo=mock_totp_repo)

    # Use a valid b32 string that will fail verification
    cmd = ConfirmTOTPSetup(
        user_id="u1", secret="JBSWY3DPEBLW64TMMQQQ====", code="000000"
    )
    resp = await handler.handle(cmd)

    assert resp.result is False


@pytest.mark.asyncio
async def test_disable_totp_not_found():
    mock_totp_repo = AsyncMock()
    handler = DisableTOTPHandler(totp_repo=mock_totp_repo)
    mock_totp_repo.get_by_user_id.return_value = None

    cmd = DisableTOTP(user_id="u1", verification_code="123456")
    resp = await handler.handle(cmd)
    assert resp.result is True


@pytest.mark.asyncio
async def test_disable_totp_invalid_code():
    mock_totp_repo = AsyncMock()
    handler = DisableTOTPHandler(totp_repo=mock_totp_repo)

    secret = TOTPSecret.generate()
    mock_totp_repo.get_by_user_id.return_value = secret

    cmd = DisableTOTP(user_id="u1", verification_code="000000")
    resp = await handler.handle(cmd)
    assert resp.result is False


@pytest.mark.asyncio
async def test_user_management_handlers(mock_idp_admin):
    # Test CreateUser
    handler = CreateUserHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.create_user.return_value = "new_u1"
    cmd = CreateUser(username="new", email="n@e.com")
    resp = await handler.handle(cmd)
    assert resp.result.user_id == "new_u1"
    assert len(resp.events) == 1

    # Test UpdateUser
    handler = UpdateUserHandler(idp_admin=mock_idp_admin)
    cmd = UpdateUser(user_id="u1", email="updated@e.com")
    resp = await handler.handle(cmd)
    assert resp.result.success
    assert len(resp.events) == 1

    # Test DeleteUser
    handler = DeleteUserHandler(idp_admin=mock_idp_admin)
    cmd = DeleteUser(user_id="u1")
    resp = await handler.handle(cmd)
    assert resp.result.success
    assert len(resp.events) == 1

    # Test SetUserPassword
    handler = SetUserPasswordHandler(idp_admin=mock_idp_admin)
    cmd = SetUserPassword(user_id="u1", password="new")
    resp = await handler.handle(cmd)
    assert resp.result.success

    # Test Roles/Groups
    handler = AssignRolesHandler(idp_admin=mock_idp_admin)
    await handler.handle(AssignRoles(user_id="u1", role_names=["admin"]))

    handler = AddToGroupsHandler(idp_admin=mock_idp_admin)
    await handler.handle(AddToGroups(user_id="u1", group_ids=["g1"]))


@pytest.mark.asyncio
async def test_send_otp_challenge_modes(
    mock_idp, mock_otp, mock_session_repo, mock_idp_admin
):
    handler = SendOTPChallengeHandler(
        otp_service=mock_otp,
        session_repo=mock_session_repo,
        idp=mock_idp,
        idp_admin=mock_idp_admin,
    )

    # Mode 1: Session
    session = Mock()
    session.get_user_claims_object.return_value = UserClaims(
        sub="u1", username="u", email="e", groups=[]
    )
    mock_session_repo.get.return_value = session
    cmd = SendOTPChallenge(method="email", session_id="s1")
    resp = await handler.handle(cmd)
    assert resp.result.success

    # Mode 3: Admin
    mock_idp_admin.get_user.return_value = Mock(
        user_id="u3", username="u3", email="e3", attributes={}
    )
    cmd = SendOTPChallenge(method="email", user_id="u3")
    resp = await handler.handle(cmd)
    assert resp.result.success


@pytest.mark.asyncio
async def test_get_user_info_queries(mock_idp):
    handler = GetUserInfoHandler(idp=mock_idp)
    resp = await handler.handle(GetUserInfo(access_token="at"))
    assert resp.result.username == "user"

    with pytest.raises(ValueError):
        await handler.handle(GetUserInfo(access_token=None, user_id=None))


@pytest.mark.asyncio
async def test_list_active_sessions(mock_session_repo):
    handler = ListActiveSessionsHandler(session_repo=mock_session_repo)
    s1 = Mock(
        id="s1",
        status="active",
        ip_address="1.1.1.1",
        user_agent="ua",
        created_at=datetime.now(),
        expires_at=datetime.now(),
        otp_method_used="totp",
    )
    mock_session_repo.get_by_user.return_value = [s1]

    resp = await handler.handle(ListActiveSessions(user_id="u1"))
    assert resp.result.total_count == 1
    assert resp.result.sessions[0].session_id == "s1"


@pytest.mark.asyncio
async def test_elevation_handlers():
    # Grant
    handler = GrantTemporaryElevationHandler(elevation_store=Mock())
    cmd = GrantTemporaryElevation(user_id="u1", action="delete", ttl_seconds=60)
    resp = await handler.handle(cmd)
    assert resp.result.success
    assert len(resp.events) == 1

    # Revoke
    handler = RevokeElevationHandler(elevation_store=Mock())
    cmd = RevokeElevation(user_id="u1", reason="done")
    resp = await handler.handle(cmd)
    assert resp.result.success

    # Resume
    handler = ResumeSensitiveOperationHandler(operation_store=Mock())
    cmd = ResumeSensitiveOperation(operation_id="op1")
    resp = await handler.handle(cmd)
    assert resp.result.success


@pytest.fixture
def mock_totp_repo():
    return AsyncMock()


@pytest.mark.asyncio
async def test_available_otp_methods_complex(mock_idp, mock_otp, mock_totp_repo):
    handler = GetAvailableOTPMethodsHandler(
        idp=mock_idp, otp_service=mock_otp, totp_repo=mock_totp_repo
    )

    # Mock user with email and phone
    mock_idp.decode_token.return_value = UserClaims(
        sub="u1",
        username="u",
        email="test@example.com",
        groups=[],
        attributes={"phone_number": "+1234567890"},
    )
    mock_otp.get_available_methods.return_value = ["totp", "email", "sms"]
    mock_totp_repo.get_by_user_id.return_value = Mock()

    resp = await handler.handle(GetAvailableOTPMethods(access_token="at"))

    methods = {m.method: m for m in resp.result.methods}
    assert methods["totp"].enabled
    assert "t****@example.com" in methods["email"].destination
    assert "+12****90" in methods["sms"].destination


@pytest.mark.asyncio
async def test_user_query_handlers(mock_idp_admin):
    # GetUser
    handler = GetUserHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.get_user.return_value = Mock(
        user_id="u1",
        username="u",
        email="e",
        first_name="F",
        last_name="L",
        enabled=True,
        email_verified=True,
        attributes={},
    )
    resp = await handler.handle(GetUser(user_id="u1"))
    assert resp.result.username == "u"

    # ListUsers
    handler = ListUsersHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.list_users.return_value = [mock_idp_admin.get_user.return_value]
    mock_idp_admin.count_users.return_value = 1
    resp = await handler.handle(ListUsers())
    assert resp.result.total_count == 1


@pytest.mark.asyncio
async def test_user_role_group_queries(mock_idp_admin):
    # Roles
    handler = GetUserRolesHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.get_user_roles.return_value = [
        RoleInfo(role_id="r1", name="role1"),
        RoleInfo(role_id="r2", name="role2"),
    ]
    resp = await handler.handle(GetUserRoles(user_id="u1"))
    assert "role1" in [r.name for r in resp.result.roles]

    # Groups
    handler = GetUserGroupsHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.get_user_groups.return_value = [
        Mock(group_id="g1", name="G1", path="/G1", attributes={})
    ]
    resp = await handler.handle(GetUserGroups(user_id="u1"))
    assert resp.result.groups[0].group_id == "g1"


@pytest.mark.asyncio
async def test_auth_otp_challenge_dispatch(mock_idp, mock_otp):
    handler = AuthenticateWithCredentialsHandler(idp=mock_idp, otp_service=mock_otp)
    mock_otp.is_required_for_user.return_value = True

    # Case: method specified but no code -> should send challenge
    cmd = AuthenticateWithCredentials(
        username="user", password="pwd", otp_method="email", track_session=False
    )
    resp = await handler.handle(cmd)

    assert resp.result.requires_otp
    mock_otp.send_challenge.assert_called_once()


@pytest.mark.asyncio
async def test_validate_otp_missing_claims(mock_session_repo, mock_otp):
    handler = ValidateOTPHandler(otp_service=mock_otp, session_repo=mock_session_repo)
    session = Mock()
    session.is_expired.return_value = False
    session.get_user_claims_object.return_value = None
    mock_session_repo.get.return_value = session

    resp = await handler.handle(ValidateOTP(session_id="s1", code="123", method="totp"))
    assert not resp.result.is_success
    assert resp.result.error_code == "NO_USER_CLAIMS"


@pytest.mark.asyncio
async def test_elevation_handlers_with_store():
    # Grant with store
    handler = GrantTemporaryElevationHandler(elevation_store=AsyncMock())
    cmd = GrantTemporaryElevation(user_id="u1", action="delete", ttl_seconds=60)
    resp = await handler.handle(cmd)
    assert resp.result.success

    # Revoke with store
    handler = RevokeElevationHandler(elevation_store=AsyncMock())
    cmd = RevokeElevation(user_id="u1", reason="done")
    resp = await handler.handle(cmd)
    assert resp.result.success

    # Resume with store
    handler = ResumeSensitiveOperationHandler(operation_store=AsyncMock())
    cmd = ResumeSensitiveOperation(operation_id="op1")
    resp = await handler.handle(cmd)
    assert resp.result.success


@pytest.mark.asyncio
async def test_query_not_found_cases(mock_idp_admin, mock_session_repo):
    # GetSessionDetails not found
    handler = GetSessionDetailsHandler(session_repo=mock_session_repo)
    mock_session_repo.get.return_value = None
    with pytest.raises(ValueError):
        await handler.handle(GetSessionDetails(session_id="missing"))

    # GetUser not found
    handler = GetUserHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.get_user.return_value = None
    with pytest.raises(ValueError):
        await handler.handle(GetUser(user_id="missing"))

    # GetUserByUsername not found
    handler = GetUserByUsernameHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.get_user_by_username.return_value = None
    with pytest.raises(ValueError):
        await handler.handle(GetUserByUsername(username="missing"))


@pytest.mark.asyncio
async def test_role_group_inheritance_and_missing(mock_idp_admin):
    # GetUserRoles missing
    handler = GetUserRolesHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.get_user_roles.return_value = []
    resp = await handler.handle(GetUserRoles(user_id="u1"))
    assert len(resp.result.roles) == 0


@pytest.mark.asyncio
async def test_validate_otp_missing_tokens(mock_session_repo, mock_otp):
    handler = ValidateOTPHandler(otp_service=mock_otp, session_repo=mock_session_repo)
    session = Mock()
    session.id = "s1"
    session.is_expired.return_value = False
    session.get_user_claims_object.return_value = UserClaims(
        sub="u1", username="u", email="e", groups=[]
    )
    session.pending_access_token = None
    session.otp_validated.return_value = Mock(events=[])
    mock_session_repo.get.return_value = session
    mock_otp.validate.return_value = True

    resp = await handler.handle(ValidateOTP(session_id="s1", code="123", method="totp"))
    assert not resp.result.is_success
    assert resp.result.error_code == "NO_PENDING_TOKENS"


@pytest.mark.asyncio
async def test_send_otp_challenge_session_lookup_failure(mock_otp, mock_session_repo):
    handler = SendOTPChallengeHandler(
        otp_service=mock_otp, session_repo=mock_session_repo
    )
    mock_session_repo.get.return_value = None

    resp = await handler.handle(SendOTPChallenge(method="email", session_id="missing"))
    assert not resp.result.success
    assert resp.result.message == "Unable to determine user"


@pytest.mark.asyncio
async def test_send_otp_challenge_admin_lookup_failure(mock_otp, mock_idp_admin):
    handler = SendOTPChallengeHandler(otp_service=mock_otp, idp_admin=mock_idp_admin)
    mock_idp_admin.get_user.return_value = None

    resp = await handler.handle(SendOTPChallenge(method="email", user_id="missing"))
    assert not resp.result.success
    assert resp.result.message == "Unable to determine user"


@pytest.mark.asyncio
async def test_send_otp_challenge_token_lookup(mock_otp, mock_idp):
    handler = SendOTPChallengeHandler(otp_service=mock_otp, idp=mock_idp)
    mock_idp.decode_token.return_value = UserClaims(
        sub="u1", username="u", email="e", groups=[]
    )

    resp = await handler.handle(SendOTPChallenge(method="email", access_token="at"))
    assert resp.result.success


@pytest.mark.asyncio
async def test_auth_requires_otp_no_method_code(mock_idp, mock_otp):
    handler = AuthenticateWithCredentialsHandler(idp=mock_idp, otp_service=mock_otp)
    mock_otp.is_required_for_user.return_value = True

    cmd = AuthenticateWithCredentials(username="u", password="p", track_session=False)
    resp = await handler.handle(cmd)
    assert resp.result.requires_otp
    assert resp.result.error_message == "OTP verification required"
