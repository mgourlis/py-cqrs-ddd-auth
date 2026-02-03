"""
Tests for User Management Handlers.
"""

import pytest
from unittest.mock import AsyncMock

from cqrs_ddd_auth.application.handlers import (
    CreateUserHandler,
    UpdateUserHandler,
    DeleteUserHandler,
    SetUserPasswordHandler,
    SendPasswordResetHandler,
    SendVerifyEmailHandler,
    AssignRolesHandler,
    RemoveRolesHandler,
    AddToGroupsHandler,
    RemoveFromGroupsHandler,
)
from cqrs_ddd_auth.application.commands import (
    CreateUser,
    UpdateUser,
    DeleteUser,
    SetUserPassword,
    SendPasswordReset,
    SendVerifyEmail,
    AssignRoles,
    RemoveRoles,
    AddToGroups,
    RemoveFromGroups,
)
from cqrs_ddd_auth.application.results import (
    CreateUserResult,
)


@pytest.fixture
def mock_idp_admin():
    mock = AsyncMock()
    return mock


@pytest.mark.asyncio
async def test_create_user_success(mock_idp_admin):
    handler = CreateUserHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.create_user.return_value = "u1"

    cmd = CreateUser(username="newuser", email="new@example.com")
    resp = await handler.handle(cmd)

    assert isinstance(resp.result, CreateUserResult)
    assert resp.result.user_id == "u1"
    mock_idp_admin.create_user.assert_called_once()


@pytest.mark.asyncio
async def test_update_user_success(mock_idp_admin):
    handler = UpdateUserHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.update_user.return_value = None

    cmd = UpdateUser(user_id="u1", first_name="Updated")
    resp = await handler.handle(cmd)

    assert resp.result.success
    assert resp.result.user_id == "u1"
    mock_idp_admin.update_user.assert_called_once()


@pytest.mark.asyncio
async def test_delete_user_success(mock_idp_admin):
    handler = DeleteUserHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.delete_user.return_value = None

    cmd = DeleteUser(user_id="u1")
    resp = await handler.handle(cmd)

    assert resp.result.success
    mock_idp_admin.delete_user.assert_called_once_with("u1")


@pytest.mark.asyncio
async def test_set_user_password_success(mock_idp_admin):
    handler = SetUserPasswordHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.set_password.return_value = None

    cmd = SetUserPassword(user_id="u1", password="newpassword")
    resp = await handler.handle(cmd)

    assert resp.result.success
    mock_idp_admin.set_password.assert_called_once()


@pytest.mark.asyncio
async def test_assign_roles_success(mock_idp_admin):
    handler = AssignRolesHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.assign_roles.return_value = None

    cmd = AssignRoles(user_id="u1", role_names=["admin"])
    resp = await handler.handle(cmd)

    assert resp.result.success
    assert "admin" in resp.result.roles_assigned
    mock_idp_admin.assign_roles.assert_called_once()


@pytest.mark.asyncio
async def test_add_to_groups_success(mock_idp_admin):
    handler = AddToGroupsHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.add_to_groups.return_value = None

    cmd = AddToGroups(user_id="u1", group_ids=["staff"])
    resp = await handler.handle(cmd)

    assert resp.result.success
    assert "staff" in resp.result.groups_added
    mock_idp_admin.add_to_groups.assert_called_once()


@pytest.mark.asyncio
async def test_send_password_reset_success(mock_idp_admin):
    handler = SendPasswordResetHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.send_password_reset.return_value = None

    cmd = SendPasswordReset(user_id="u1")
    resp = await handler.handle(cmd)

    assert resp.result.success
    mock_idp_admin.send_password_reset.assert_called_once_with("u1")


@pytest.mark.asyncio
async def test_send_verify_email_success(mock_idp_admin):
    handler = SendVerifyEmailHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.send_verify_email.return_value = None

    cmd = SendVerifyEmail(user_id="u1")
    resp = await handler.handle(cmd)

    assert resp.result.success
    mock_idp_admin.send_verify_email.assert_called_once_with("u1")


@pytest.mark.asyncio
async def test_remove_roles_success(mock_idp_admin):
    handler = RemoveRolesHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.remove_roles.return_value = None

    cmd = RemoveRoles(user_id="u1", role_names=["admin"])
    resp = await handler.handle(cmd)

    assert resp.result.success
    assert "admin" in resp.result.roles_removed
    mock_idp_admin.remove_roles.assert_called_once()


@pytest.mark.asyncio
async def test_remove_from_groups_success(mock_idp_admin):
    handler = RemoveFromGroupsHandler(idp_admin=mock_idp_admin)
    mock_idp_admin.remove_from_groups.return_value = None

    cmd = RemoveFromGroups(user_id="u1", group_ids=["staff"])
    resp = await handler.handle(cmd)

    assert resp.result.success
    assert "staff" in resp.result.groups_removed
    mock_idp_admin.remove_from_groups.assert_called_once()
