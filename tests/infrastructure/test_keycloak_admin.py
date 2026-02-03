"""
Tests for Keycloak Admin Adapter.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from keycloak.exceptions import KeycloakError

from cqrs_ddd_auth.infrastructure.adapters.keycloak_admin import (
    KeycloakAdminAdapter,
    KeycloakAdminConfig,
    CreateUserData,
    UpdateUserData,
    UserFilters,
    RoleData,
    GroupData,
)
from cqrs_ddd_auth.domain.errors import UserManagementError, UserNotFoundError


@pytest.fixture
def admin_config():
    return KeycloakAdminConfig(
        server_url="https://auth.example.com",
        realm="test-realm",
        client_id="admin-cli",
        client_secret="secret",
        verify=False,
    )


@pytest.fixture
def mock_keycloak_admin_client():
    with patch(
        "cqrs_ddd_auth.infrastructure.adapters.keycloak_admin.KeycloakAdmin"
    ) as mock:
        yield mock.return_value


def test_init(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    assert adapter._admin == mock_keycloak_admin_client


@pytest.mark.asyncio
async def test_create_user(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.create_user.return_value = "new-user-id"

    user_data = CreateUserData(
        username="testuser",
        email="test@example.com",
        first_name="Test",
        last_name="User",
        attributes={"dept": "IT"},
        temporary_password="password123",
    )

    user_id = await adapter.create_user(user_data)

    assert user_id == "new-user-id"
    mock_keycloak_admin_client.create_user.assert_called_once()
    call_args = mock_keycloak_admin_client.create_user.call_args[0][0]
    assert call_args["username"] == "testuser"
    assert call_args["email"] == "test@example.com"
    assert call_args["attributes"] == {"dept": "IT"}
    assert call_args["credentials"][0]["value"] == "password123"


@pytest.mark.asyncio
async def test_create_user_with_attributes(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.create_user.return_value = "u1"

    user_data = CreateUserData(
        username="testuser", email="test@example.com", attributes={"key": "value"}
    )

    await adapter.create_user(user_data)

    call_args = mock_keycloak_admin_client.create_user.call_args[0][0]
    assert call_args["attributes"] == {"key": "value"}


@pytest.mark.asyncio
async def test_create_user_failure(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    # Side effects for sync methods called in async functions
    mock_keycloak_admin_client.create_user.side_effect = KeycloakError("Boom")

    with pytest.raises(UserManagementError):
        await adapter.create_user(CreateUserData(username="u", email="e"))


@pytest.mark.asyncio
async def test_get_user(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_user.return_value = {
        "id": "u1",
        "username": "user",
        "email": "user@example.com",
        "enabled": True,
    }

    user = await adapter.get_user("u1")

    assert user is not None
    assert user.user_id == "u1"
    assert user.username == "user"


@pytest.mark.asyncio
async def test_get_user_by_username_failure(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.side_effect = KeycloakError("Boom")
    user = await adapter.get_user_by_username("user")
    assert user is None


@pytest.mark.asyncio
async def test_get_user_by_email_failure(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.side_effect = KeycloakError("Boom")
    user = await adapter.get_user_by_email("email@test.com")
    assert user is None


async def test_get_user_not_found(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_user.side_effect = KeycloakError(
        "404: User not found"
    )

    user = await adapter.get_user("u1")
    assert user is None


@pytest.mark.asyncio
async def test_get_user_by_username(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.return_value = [
        {"id": "u1", "username": "user", "email": "user@example.com"}
    ]

    user = await adapter.get_user_by_username("user")

    assert user is not None
    assert user.user_id == "u1"
    mock_keycloak_admin_client.get_users.assert_called_with(
        {"username": "user", "exact": True}
    )


@pytest.mark.asyncio
async def test_get_user_by_username_not_found(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.return_value = []

    user = await adapter.get_user_by_username("missing")
    assert user is None


@pytest.mark.asyncio
async def test_get_user_by_email(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.return_value = [
        {"id": "u1", "username": "user", "email": "user@example.com"}
    ]

    user = await adapter.get_user_by_email("user@example.com")

    assert user is not None
    assert user.user_id == "u1"
    mock_keycloak_admin_client.get_users.assert_called_with(
        {"email": "user@example.com", "exact": True}
    )


@pytest.mark.asyncio
async def test_update_user(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    await adapter.update_user("u1", UpdateUserData(first_name="NewName"))

    mock_keycloak_admin_client.update_user.assert_called_with(
        "u1", {"firstName": "NewName"}
    )


@pytest.mark.asyncio
async def test_update_user_multi_fields(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    updates = UpdateUserData(
        email="new@e.com",
        first_name="F",
        last_name="L",
        enabled=False,
        email_verified=True,
        attributes={"a": "b"},
    )

    await adapter.update_user("u1", updates)

    expected_payload = {
        "email": "new@e.com",
        "firstName": "F",
        "lastName": "L",
        "enabled": False,
        "emailVerified": True,
        "attributes": {"a": "b"},
    }
    mock_keycloak_admin_client.update_user.assert_called_with("u1", expected_payload)


@pytest.mark.asyncio
async def test_update_user_not_found(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.update_user.side_effect = KeycloakError(
        "404: User not found"
    )

    with pytest.raises(UserNotFoundError):
        await adapter.update_user("u1", UpdateUserData(enabled=True))


@pytest.mark.asyncio
async def test_delete_user_failure(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.delete_user.side_effect = KeycloakError("Boom")
    with pytest.raises(UserManagementError) as exc:
        await adapter.delete_user("u1")
    assert exc.value.code == "USER_DELETE_FAILED"


@pytest.mark.asyncio
async def test_list_users_with_enabled_filter(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.return_value = []

    await adapter.list_users(UserFilters(enabled=True))
    args = mock_keycloak_admin_client.get_users.call_args[0][0]
    assert args["enabled"] is True


@pytest.mark.asyncio
async def test_get_user_roles_failure(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    # User not found
    mock_keycloak_admin_client.get_realm_roles_of_user.side_effect = KeycloakError(
        "404: Not Found"
    )
    with pytest.raises(UserNotFoundError):
        await adapter.get_user_roles("u1")

    # General failure
    mock_keycloak_admin_client.get_realm_roles_of_user.side_effect = KeycloakError(
        "Boom"
    )
    with pytest.raises(UserManagementError) as exc:
        await adapter.get_user_roles("u1")
    assert exc.value.code == "USER_ROLES_FAILED"


@pytest.mark.asyncio
async def test_list_users(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.return_value = [
        {"id": "u1", "username": "user1"},
        {"id": "u2", "username": "user2"},
    ]

    users = await adapter.list_users(UserFilters(search="user"))

    assert len(users) == 2
    mock_keycloak_admin_client.get_users.assert_called()
    # Check that search param was passed
    args = mock_keycloak_admin_client.get_users.call_args[0][0]
    assert args["search"] == "user"


@pytest.mark.asyncio
async def test_list_users_with_role_and_group_filter(
    admin_config, mock_keycloak_admin_client
):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.return_value = [
        {"id": "u1", "username": "user1"}
    ]

    with (
        patch.object(
            KeycloakAdminAdapter, "get_user_roles", new_callable=AsyncMock
        ) as mock_get_roles,
        patch.object(
            KeycloakAdminAdapter, "get_user_groups", new_callable=AsyncMock
        ) as mock_get_groups,
    ):
        mock_get_roles.return_value = [RoleData(role_id="r1", name="admin")]
        mock_get_groups.return_value = [GroupData(group_id="g1", name="group1")]

        users = await adapter.list_users(UserFilters(role="admin", group="group1"))
        assert len(users) == 1

        # Test non-matching group
        users = await adapter.list_users(UserFilters(role="admin", group="other"))
        assert len(users) == 0


async def test_list_users_with_role_filter(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.return_value = [
        {"id": "u1", "username": "user1"}
    ]
    # Mock get_user_roles to return 'admin' for u1
    with patch.object(
        KeycloakAdminAdapter, "get_user_roles", new_callable=AsyncMock
    ) as mock_get_roles:
        mock_get_roles.return_value = [RoleData(role_id="r1", name="admin")]

        users = await adapter.list_users(UserFilters(role="admin"))
        assert len(users) == 1

        mock_get_roles.return_value = [RoleData(role_id="r2", name="user")]
        users = await adapter.list_users(UserFilters(role="admin"))
        assert len(users) == 0


@pytest.mark.asyncio
async def test_count_users_with_role_filter(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    # When role filter is present, it should call list_users
    with patch.object(
        KeycloakAdminAdapter, "list_users", new_callable=AsyncMock
    ) as mock_list:
        mock_list.return_value = [Mock(), Mock()]
        count = await adapter.count_users(UserFilters(role="admin"))
        assert count == 2
        mock_list.assert_called_once()


@pytest.mark.asyncio
async def test_assign_roles(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    # Mock realm roles
    mock_keycloak_admin_client.get_realm_roles.return_value = [
        {"id": "r1", "name": "role1"},
        {"id": "r2", "name": "role2"},
    ]

    await adapter.assign_roles("u1", ["role1"])

    mock_keycloak_admin_client.assign_realm_roles.assert_called()
    call_args = mock_keycloak_admin_client.assign_realm_roles.call_args
    assert call_args[0][0] == "u1"
    assert call_args[0][1] == [{"id": "r1", "name": "role1"}]


@pytest.mark.asyncio
async def test_update_user_empty(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    await adapter.update_user("u1", UpdateUserData())
    mock_keycloak_admin_client.update_user.assert_not_called()


@pytest.mark.asyncio
async def test_list_users_failure_branch(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_users.side_effect = KeycloakError("Boom")
    with pytest.raises(UserManagementError) as exc:
        await adapter.list_users()
    assert exc.value.code == "USER_LIST_FAILED"


@pytest.mark.asyncio
async def test_count_users_branches(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.users_count.return_value = 5

    # Test enabled filter in count
    await adapter.count_users(UserFilters(enabled=False))
    mock_keycloak_admin_client.users_count.assert_called_with({"enabled": False})

    # Test failure
    mock_keycloak_admin_client.users_count.side_effect = KeycloakError("Boom")
    with pytest.raises(UserManagementError) as exc:
        await adapter.count_users()
    assert exc.value.code == "USER_COUNT_FAILED"


async def test_assign_roles_not_found(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_realm_roles.return_value = []

    with pytest.raises(UserManagementError, match="Role not found"):
        await adapter.assign_roles("u1", ["missing"])


@pytest.mark.asyncio
async def test_assign_roles_failure(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_realm_roles.return_value = [
        {"id": "r1", "name": "role1"}
    ]
    mock_keycloak_admin_client.assign_realm_roles.side_effect = KeycloakError("Boom")

    with pytest.raises(UserManagementError) as exc:
        await adapter.assign_roles("u1", ["role1"])
    assert exc.value.code == "ROLE_ASSIGN_FAILED"


@pytest.mark.asyncio
async def test_remove_roles_failure(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_realm_roles_of_user.return_value = [
        {"id": "r1", "name": "role1"}
    ]
    mock_keycloak_admin_client.delete_realm_roles_of_user.side_effect = KeycloakError(
        "Boom"
    )

    with pytest.raises(UserManagementError) as exc:
        await adapter.remove_roles("u1", ["role1"])
    assert exc.value.code == "ROLE_REMOVE_FAILED"


@pytest.mark.asyncio
async def test_get_user_sessions(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_user_sessions.return_value = [
        {"id": "s1", "start": 0}
    ]

    sessions = await adapter.get_user_sessions("u1")
    assert len(sessions) == 1
    assert sessions[0]["id"] == "s1"


@pytest.mark.asyncio
async def test_revoke_user_session(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    await adapter.revoke_user_session("s1")
    mock_keycloak_admin_client.delete_user_session.assert_called_with("s1")


@pytest.mark.asyncio
async def test_password_management_failures(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    # Set password failure
    mock_keycloak_admin_client.set_user_password.side_effect = KeycloakError("Boom")
    with pytest.raises(UserManagementError) as exc:
        await adapter.set_password("u1", "p")
    assert exc.value.code == "PASSWORD_SET_FAILED"

    # Send password reset failure
    mock_keycloak_admin_client.send_update_account.side_effect = KeycloakError("Boom")
    with pytest.raises(UserManagementError) as exc:
        await adapter.send_password_reset("u1")
    assert exc.value.code == "PASSWORD_RESET_FAILED"

    # Send verify email failure
    mock_keycloak_admin_client.send_verify_email.side_effect = KeycloakError("Boom")
    with pytest.raises(UserManagementError) as exc:
        await adapter.send_verify_email("u1")
    assert exc.value.code == "VERIFY_EMAIL_FAILED"


async def test_revoke_user_session_not_found(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.delete_user_session.side_effect = KeycloakError(
        "404: Session not found"
    )

    # SHould not raise error, just return (already revoked)
    await adapter.revoke_user_session("s1")


@pytest.mark.asyncio
async def test_logout_user(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    await adapter.logout_user("u1")
    mock_keycloak_admin_client.user_logout.assert_called_with("u1")


@pytest.mark.asyncio
async def test_logout_user_not_found(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.user_logout.side_effect = KeycloakError(
        "404: User not found"
    )
    with pytest.raises(UserNotFoundError):
        await adapter.logout_user("u1")


@pytest.mark.asyncio
async def test_get_realm_settings(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_realm.return_value = {"ssoSessionMaxLifespan": 3600}

    settings = await adapter.get_realm_settings()
    assert settings["ssoSessionMaxLifespan"] == 3600


@pytest.mark.asyncio
async def test_list_groups(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_groups.return_value = [
        {"id": "g1", "name": "group1", "path": "/group1"}
    ]

    groups = await adapter.list_groups()
    assert len(groups) == 1
    assert groups[0].name == "group1"


@pytest.mark.asyncio
async def test_list_groups_failure(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_groups.side_effect = KeycloakError("Boom")
    with pytest.raises(UserManagementError) as exc:
        await adapter.list_groups()
    assert exc.value.code == "GROUP_LIST_FAILED"


@pytest.mark.asyncio
async def test_get_user_groups_failure(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.get_user_groups.side_effect = KeycloakError("Boom")
    with pytest.raises(UserManagementError) as exc:
        await adapter.get_user_groups("u1")
    assert exc.value.code == "USER_GROUPS_FAILED"


@pytest.mark.asyncio
async def test_group_mapping_hierarchy(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    mock_kc_group = {
        "id": "g2",
        "name": "child",
        "path": "/parent/child",
        "parentId": "g1",
        "attributes": {"a": ["b"]},
    }

    group = adapter._map_group(mock_kc_group)
    assert group.group_id == "g2"
    assert group.parent_id == "g1"
    assert group.path == "/parent/child"


@pytest.mark.asyncio
async def test_group_membership(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    # Add
    await adapter.add_to_groups("u1", ["g1"])
    mock_keycloak_admin_client.group_user_add.assert_called_with("u1", "g1")

    # Remove
    await adapter.remove_from_groups("u1", ["g1"])
    mock_keycloak_admin_client.group_user_remove.assert_called_with("u1", "g1")

    # Get user groups
    mock_keycloak_admin_client.get_user_groups.return_value = [
        {"id": "g1", "name": "group1"}
    ]
    groups = await adapter.get_user_groups("u1")
    assert len(groups) == 1


@pytest.mark.asyncio
async def test_password_management(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    # Set password
    await adapter.set_password("u1", "newpass", temporary=True)
    mock_keycloak_admin_client.set_user_password.assert_called_with(
        "u1", "newpass", True
    )

    # Reset email
    await adapter.send_password_reset("u1")
    mock_keycloak_admin_client.send_update_account.assert_called()

    # Verify email
    await adapter.send_verify_email("u1")
    mock_keycloak_admin_client.send_verify_email.assert_called_with(user_id="u1")


@pytest.mark.asyncio
async def test_count_users(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)
    mock_keycloak_admin_client.users_count.return_value = 42

    count = await adapter.count_users()
    assert count == 42


@pytest.mark.asyncio
async def test_group_roles_capability(admin_config, mock_keycloak_admin_client):
    adapter = KeycloakAdminAdapter(admin_config)

    # get_group_roles
    mock_keycloak_admin_client.get_group_realm_roles.return_value = [
        {"id": "r1", "name": "role1"}
    ]
    roles = await adapter.get_group_roles("g1")
    assert len(roles) == 1
    assert roles[0].name == "role1"

    # assign_group_roles
    mock_keycloak_admin_client.get_realm_roles.return_value = [
        {"id": "r1", "name": "role1"}
    ]
    await adapter.assign_group_roles("g1", ["role1"])
    mock_keycloak_admin_client.assign_group_realm_roles.assert_called()

    # remove_group_roles
    await adapter.remove_group_roles("g1", ["role1"])
    mock_keycloak_admin_client.delete_group_realm_roles.assert_called()


def test_init_with_user_credentials(mock_keycloak_admin_client):
    config = KeycloakAdminConfig(
        server_url="https://auth.example.com",
        realm="test-realm",
        admin_username="admin",
        admin_password="password",
    )
    with patch(
        "cqrs_ddd_auth.infrastructure.adapters.keycloak_admin.KeycloakAdmin"
    ) as mock_cls:
        _ = KeycloakAdminAdapter(config)
        mock_cls.assert_called_with(
            server_url=config.server_url,
            username="admin",
            password="password",
            realm_name="test-realm",
            verify=True,
        )
