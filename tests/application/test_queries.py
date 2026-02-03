"""
Tests for Query Handlers.
"""

import pytest
from unittest.mock import Mock, AsyncMock
from datetime import datetime, timezone

from cqrs_ddd_auth.application.handlers import (
    GetUserInfoHandler,
    GetAvailableOTPMethodsHandler,
    ListActiveSessionsHandler,
    GetSessionDetailsHandler,
    CheckTOTPEnabledHandler,
    GetUserHandler,
    GetUserByUsernameHandler,
    GetUserByEmailHandler,
    ListUsersHandler,
    GetUserRolesHandler,
    GetUserGroupsHandler,
    GetTypeLevelPermissionsHandler,
)
from cqrs_ddd_auth.application.queries import (
    GetUserInfo,
    GetAvailableOTPMethods,
    ListActiveSessions,
    GetSessionDetails,
    CheckTOTPEnabled,
    GetUser,
    GetUserByUsername,
    GetUserByEmail,
    ListUsers,
    GetUserRoles,
    GetUserGroups,
    GetTypeLevelPermissions,
)
from cqrs_ddd_auth.application.results import (
    UserInfoResult,
    AvailableOTPMethodsResult,
    ListSessionsResult,
    SessionInfo,
    TOTPStatusResult,
    UserResult,
    ListUsersResult,
    UserRolesResult,
    UserGroupsResult,
    TypeLevelPermissionsResult,
)
from cqrs_ddd_auth.domain.value_objects import UserClaims


@pytest.fixture
def mock_idp():
    return AsyncMock()


@pytest.fixture
def mock_idp_admin():
    return AsyncMock()


@pytest.fixture
def mock_session_repo():
    return AsyncMock()


@pytest.fixture
def mock_totp_repo():
    return AsyncMock()


@pytest.fixture
def mock_abac_adapter():
    return AsyncMock()


@pytest.fixture
def mock_otp():
    mock = AsyncMock()
    mock.get_available_methods.return_value = ["totp"]
    return mock


@pytest.mark.asyncio
async def test_get_user_info_success(mock_idp, mock_totp_repo):
    handler = GetUserInfoHandler(idp=mock_idp, totp_repo=mock_totp_repo)

    claims = UserClaims(sub="u1", username="user", email="u@e.com", groups=())
    mock_idp.decode_token.return_value = claims
    mock_totp_repo.get_by_user_id.return_value = None  # Not enabled

    query = GetUserInfo(access_token="at")
    resp = await handler.handle(query)

    assert isinstance(resp.result, UserInfoResult)
    assert resp.result.user_id == "u1"
    assert not resp.result.totp_enabled


@pytest.mark.asyncio
async def test_get_available_otp_methods(mock_idp, mock_otp, mock_totp_repo):
    handler = GetAvailableOTPMethodsHandler(
        idp=mock_idp, otp_service=mock_otp, totp_repo=mock_totp_repo
    )

    claims = UserClaims(sub="u1", username="user", email="u@e.com", groups=())
    mock_idp.decode_token.return_value = claims
    mock_totp_repo.get_by_user_id.return_value = Mock()  # Enabled

    query = GetAvailableOTPMethods(access_token="at")
    resp = await handler.handle(query)

    assert isinstance(resp.result, AvailableOTPMethodsResult)
    # Totp should be in available methods if enabled in repo
    assert any(m.method == "totp" and m.enabled for m in resp.result.methods)


@pytest.mark.asyncio
async def test_list_active_sessions(mock_session_repo):
    handler = ListActiveSessionsHandler(session_repo=mock_session_repo)

    mock_session_repo.get_by_user.return_value = []

    query = ListActiveSessions(user_id="u1")
    resp = await handler.handle(query)

    assert isinstance(resp.result, ListSessionsResult)
    assert resp.result.total_count == 0


@pytest.mark.asyncio
async def test_get_user_query_success(mock_idp_admin):
    handler = GetUserHandler(idp_admin=mock_idp_admin)

    user_data = Mock()
    user_data.user_id = "u1"
    user_data.username = "user"
    user_data.email = "u@e.com"
    user_data.first_name = "F"
    user_data.last_name = "L"
    user_data.enabled = True
    user_data.email_verified = True
    user_data.created_at = datetime.now(timezone.utc)
    user_data.attributes = {}

    mock_idp_admin.get_user.return_value = user_data

    query = GetUser(user_id="u1")
    resp = await handler.handle(query)

    assert isinstance(resp.result, UserResult)
    assert resp.result.user_id == "u1"


@pytest.mark.asyncio
async def test_get_user_by_username_success(mock_idp_admin):
    handler = GetUserByUsernameHandler(idp_admin=mock_idp_admin)

    user_data = Mock()
    user_data.user_id = "u1"
    user_data.username = "user"
    mock_idp_admin.get_user_by_username.return_value = user_data

    query = GetUserByUsername(username="user")
    resp = await handler.handle(query)

    assert resp.result.user_id == "u1"


@pytest.mark.asyncio
async def test_get_user_by_email_success(mock_idp_admin):
    handler = GetUserByEmailHandler(idp_admin=mock_idp_admin)

    user_data = Mock()
    user_data.user_id = "u1"
    user_data.email = "u@e.com"
    mock_idp_admin.get_user_by_email.return_value = user_data

    query = GetUserByEmail(email="u@e.com")
    resp = await handler.handle(query)

    assert resp.result.user_id == "u1"


@pytest.mark.asyncio
async def test_check_totp_enabled(mock_totp_repo):
    handler = CheckTOTPEnabledHandler(totp_repo=mock_totp_repo)

    mock_totp_repo.get_by_user_id.return_value = Mock()

    query = CheckTOTPEnabled(user_id="u1")
    resp = await handler.handle(query)

    assert isinstance(resp.result, TOTPStatusResult)
    assert resp.result.enabled


@pytest.mark.asyncio
async def test_get_session_details(mock_session_repo):
    handler = GetSessionDetailsHandler(session_repo=mock_session_repo)

    session = Mock()
    session.id = "s1"
    session.subject_id = "u1"
    mock_session_repo.get.return_value = session

    query = GetSessionDetails(session_id="s1")
    resp = await handler.handle(query)

    assert isinstance(resp.result, SessionInfo)
    assert resp.result.session_id == "s1"


@pytest.mark.asyncio
async def test_list_users_query(mock_idp_admin):
    handler = ListUsersHandler(idp_admin=mock_idp_admin)

    user_data = Mock()
    user_data.user_id = "u1"
    user_data.username = "user"
    user_data.email = "u@e.com"
    user_data.first_name = "F"
    user_data.last_name = "L"
    user_data.enabled = True
    user_data.email_verified = True
    user_data.attributes = {}

    mock_idp_admin.list_users.return_value = [user_data]
    mock_idp_admin.count_users.return_value = 1

    query = ListUsers(limit=10)
    resp = await handler.handle(query)

    assert isinstance(resp.result, ListUsersResult)
    assert resp.result.total_count == 1
    assert len(resp.result.users) == 1
    assert resp.result.users[0].user_id == "u1"


@pytest.mark.asyncio
async def test_get_user_roles_query(mock_idp_admin):
    handler = GetUserRolesHandler(idp_admin=mock_idp_admin)

    mock_idp_admin.get_user_roles.return_value = []

    query = GetUserRoles(user_id="u1")
    resp = await handler.handle(query)

    assert isinstance(resp.result, UserRolesResult)
    assert resp.result.user_id == "u1"


@pytest.mark.asyncio
async def test_get_user_groups_query(mock_idp_admin):
    handler = GetUserGroupsHandler(idp_admin=mock_idp_admin)

    mock_idp_admin.get_user_groups.return_value = []

    query = GetUserGroups(user_id="u1")
    resp = await handler.handle(query)

    assert isinstance(resp.result, UserGroupsResult)
    assert resp.result.user_id == "u1"


@pytest.mark.asyncio
async def test_get_type_level_permissions_query(mock_abac_adapter):
    handler = GetTypeLevelPermissionsHandler(abac=mock_abac_adapter)

    mock_abac_adapter.get_type_level_permissions.return_value = {"resource": ["action"]}

    query = GetTypeLevelPermissions(access_token="at")
    resp = await handler.handle(query)

    assert isinstance(resp.result, TypeLevelPermissionsResult)
    assert "resource" in resp.result.permissions
