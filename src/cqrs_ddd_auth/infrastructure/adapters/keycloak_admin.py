"""
Keycloak Admin Adapter.

Implements IdentityProviderAdminPort for Keycloak user management.
Uses KeycloakAdmin from python-keycloak for admin operations.
"""

from dataclasses import dataclass
from typing import Optional, Any

from keycloak import KeycloakAdmin
from keycloak.exceptions import KeycloakError

from cqrs_ddd_auth.infrastructure.ports.identity_provider_admin import (
    IdentityProviderAdminPort,
    GroupRolesCapability,
    CreateUserData,
    UpdateUserData,
    UserData,
    RoleData,
    GroupData,
    UserFilters,
)


from cqrs_ddd_auth.domain.errors import UserManagementError, UserNotFoundError


@dataclass
class KeycloakAdminConfig:
    """Configuration for Keycloak Admin adapter."""

    server_url: str  # e.g., "https://keycloak.example.com"
    realm: str
    # Admin authentication - choose one method:
    # Method 1: Service account (recommended)
    client_id: str = "admin-cli"
    client_secret: Optional[str] = None
    # Method 2: Admin user credentials
    admin_username: Optional[str] = None
    admin_password: Optional[str] = None
    # Connection options
    verify: bool = True


class KeycloakAdminAdapter(IdentityProviderAdminPort, GroupRolesCapability):
    """
    Keycloak implementation of IdentityProviderAdminPort.

    Also implements GroupRolesCapability since Keycloak supports
    assigning roles to groups.

    Uses python-keycloak's KeycloakAdmin for administrative operations.

    Example usage:
        config = KeycloakAdminConfig(
            server_url="https://keycloak.example.com",
            realm="my-realm",
            client_id="admin-cli",
            client_secret="admin-secret",
        )
        adapter = KeycloakAdminAdapter(config)

        # Create user
        user_id = await adapter.create_user(CreateUserData(
            username="newuser",
            email="user@example.com",
        ))

        # Assign roles
        await adapter.assign_roles(user_id, ["app-user"])

        # Keycloak-specific: get group roles
        if isinstance(adapter, GroupRolesCapability):
            group_roles = await adapter.get_group_roles(group_id)
    """

    def __init__(self, config: KeycloakAdminConfig):
        self.config = config
        self._admin = self._create_admin_client()

    def _create_admin_client(self) -> KeycloakAdmin:
        """Create KeycloakAdmin client based on configuration."""
        if self.config.admin_username and self.config.admin_password:
            # Use admin user credentials
            return KeycloakAdmin(
                server_url=self.config.server_url,
                username=self.config.admin_username,
                password=self.config.admin_password,
                realm_name=self.config.realm,
                verify=self.config.verify,
            )
        else:
            # Use service account (client credentials)
            return KeycloakAdmin(
                server_url=self.config.server_url,
                client_id=self.config.client_id,
                client_secret_key=self.config.client_secret,
                realm_name=self.config.realm,
                verify=self.config.verify,
            )

    # ═══════════════════════════════════════════════════════════════
    # USER CRUD
    # ═══════════════════════════════════════════════════════════════

    async def create_user(self, user: CreateUserData) -> str:
        """
        Create a new user in Keycloak.

        Args:
            user: User data for creation

        Returns:
            The created user's ID

        Raises:
            UserManagementError: If creation fails
        """
        try:
            payload: dict[str, Any] = {
                "username": user.username,
                "email": user.email,
                "firstName": user.first_name,
                "lastName": user.last_name,
                "enabled": user.enabled,
                "emailVerified": user.email_verified,
            }

            if user.attributes:
                payload["attributes"] = user.attributes

            if user.temporary_password:
                payload["credentials"] = [
                    {
                        "type": "password",
                        "value": user.temporary_password,
                        "temporary": True,
                    }
                ]

            user_id = self._admin.create_user(payload, exist_ok=False)
            return user_id

        except KeycloakError as e:
            raise UserManagementError(str(e), "USER_CREATE_FAILED")

    async def get_user(self, user_id: str) -> Optional[UserData]:
        """
        Get user by ID.

        Args:
            user_id: User's ID in Keycloak

        Returns:
            UserData if found, None otherwise
        """
        try:
            user = self._admin.get_user(user_id)
            return self._map_user(user)
        except KeycloakError:
            return None

    async def get_user_by_username(self, username: str) -> Optional[UserData]:
        """
        Get user by username.

        Args:
            username: User's username

        Returns:
            UserData if found, None otherwise
        """
        try:
            users = self._admin.get_users({"username": username, "exact": True})
            if users:
                return self._map_user(users[0])
            return None
        except KeycloakError:
            return None

    async def get_user_by_email(self, email: str) -> Optional[UserData]:
        """
        Get user by email.

        Args:
            email: User's email address

        Returns:
            UserData if found, None otherwise
        """
        try:
            users = self._admin.get_users({"email": email, "exact": True})
            if users:
                return self._map_user(users[0])
            return None
        except KeycloakError:
            return None

    async def update_user(self, user_id: str, updates: UpdateUserData) -> None:
        """
        Update user attributes.

        Args:
            user_id: User's ID
            updates: Fields to update (None values are ignored)

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If update fails
        """
        try:
            payload: dict[str, Any] = {}

            if updates.email is not None:
                payload["email"] = updates.email
            if updates.first_name is not None:
                payload["firstName"] = updates.first_name
            if updates.last_name is not None:
                payload["lastName"] = updates.last_name
            if updates.enabled is not None:
                payload["enabled"] = updates.enabled
            if updates.email_verified is not None:
                payload["emailVerified"] = updates.email_verified
            if updates.attributes is not None:
                payload["attributes"] = updates.attributes

            if payload:
                self._admin.update_user(user_id, payload)

        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "USER_UPDATE_FAILED")

    async def delete_user(self, user_id: str) -> None:
        """
        Delete a user.

        Args:
            user_id: User's ID to delete

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If deletion fails
        """
        try:
            self._admin.delete_user(user_id)
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "USER_DELETE_FAILED")

    async def list_users(self, filters: Optional[UserFilters] = None) -> list[UserData]:
        """
        List users with optional filters.

        Args:
            filters: Optional filtering criteria

        Returns:
            List of matching users
        """
        try:
            query: dict[str, Any] = {}

            if filters:
                if filters.search:
                    query["search"] = filters.search
                if filters.enabled is not None:
                    query["enabled"] = filters.enabled
                query["first"] = filters.offset
                query["max"] = filters.limit

            users = self._admin.get_users(query)

            # Apply role/group filters (post-filter as Keycloak doesn't support in query)
            result = []
            for user in users:
                if filters and filters.role:
                    user_roles = await self.get_user_roles(user["id"])
                    if not any(r.name == filters.role for r in user_roles):
                        continue

                if filters and filters.group:
                    user_groups = await self.get_user_groups(user["id"])
                    if not any(
                        g.name == filters.group or g.group_id == filters.group
                        for g in user_groups
                    ):
                        continue

                result.append(self._map_user(user))

            return result

        except KeycloakError as e:
            raise UserManagementError(str(e), "USER_LIST_FAILED")

    async def count_users(self, filters: Optional[UserFilters] = None) -> int:
        """
        Count users matching filters.

        Args:
            filters: Optional filtering criteria

        Returns:
            Total count of matching users
        """
        try:
            query: dict[str, Any] = {}

            if filters:
                if filters.search:
                    query["search"] = filters.search
                if filters.enabled is not None:
                    query["enabled"] = filters.enabled

            # Keycloak's count doesn't support role/group filters
            # For basic counts without role/group filters, use direct count
            if filters and (filters.role or filters.group):
                # Need to do full query and count
                users = await self.list_users(filters)
                return len(users)

            return self._admin.users_count(query)

        except KeycloakError as e:
            raise UserManagementError(str(e), "USER_COUNT_FAILED")

    # ═══════════════════════════════════════════════════════════════
    # PASSWORD MANAGEMENT
    # ═══════════════════════════════════════════════════════════════

    async def set_password(
        self, user_id: str, password: str, temporary: bool = False
    ) -> None:
        """
        Set user's password.

        Args:
            user_id: User's ID
            password: New password
            temporary: If True, user must change on next login

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If password set fails
        """
        try:
            self._admin.set_user_password(user_id, password, temporary)
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "PASSWORD_SET_FAILED")

    async def send_password_reset(self, user_id: str) -> None:
        """
        Trigger password reset email.

        Args:
            user_id: User's ID

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If sending fails
        """
        try:
            self._admin.send_update_account(
                user_id=user_id,
                payload=["UPDATE_PASSWORD"],
            )
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "PASSWORD_RESET_FAILED")

    async def send_verify_email(self, user_id: str) -> None:
        """
        Send email verification email.

        Args:
            user_id: User's ID

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If sending fails
        """
        try:
            self._admin.send_verify_email(user_id=user_id)
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "VERIFY_EMAIL_FAILED")

    # ═══════════════════════════════════════════════════════════════
    # ROLE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════

    async def list_roles(self) -> list[RoleData]:
        """List all realm roles."""
        try:
            roles = self._admin.get_realm_roles()
            return [self._map_role(r) for r in roles]
        except KeycloakError as e:
            raise UserManagementError(str(e), "ROLE_LIST_FAILED")

    async def get_user_roles(self, user_id: str) -> list[RoleData]:
        """
        Get user's assigned realm roles.

        Args:
            user_id: User's ID

        Returns:
            List of roles assigned to the user

        Raises:
            UserNotFoundError: If user doesn't exist
        """
        try:
            roles = self._admin.get_realm_roles_of_user(user_id)
            return [self._map_role(r) for r in roles]
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "USER_ROLES_FAILED")

    async def assign_roles(self, user_id: str, role_names: list[str]) -> None:
        """
        Assign realm roles to user.

        Args:
            user_id: User's ID
            role_names: Names of roles to assign

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If assignment fails
        """
        try:
            # Get role objects by name
            roles_to_assign = []
            all_roles = self._admin.get_realm_roles()
            role_map = {r["name"]: r for r in all_roles}

            for name in role_names:
                if name in role_map:
                    roles_to_assign.append(role_map[name])
                else:
                    raise UserManagementError(
                        f"Role not found: {name}", "ROLE_NOT_FOUND"
                    )

            if roles_to_assign:
                self._admin.assign_realm_roles(user_id, roles_to_assign)

        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "ROLE_ASSIGN_FAILED")

    async def remove_roles(self, user_id: str, role_names: list[str]) -> None:
        """
        Remove realm roles from user.

        Args:
            user_id: User's ID
            role_names: Names of roles to remove

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If removal fails
        """
        try:
            # Get current user roles
            user_roles = self._admin.get_realm_roles_of_user(user_id)
            roles_to_remove = [r for r in user_roles if r["name"] in role_names]

            if roles_to_remove:
                self._admin.delete_realm_roles_of_user(user_id, roles_to_remove)

        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "ROLE_REMOVE_FAILED")

    # ═══════════════════════════════════════════════════════════════
    # GROUP MANAGEMENT
    # ═══════════════════════════════════════════════════════════════

    async def list_groups(self) -> list[GroupData]:
        """List all groups (hierarchical)."""
        try:
            groups = self._admin.get_groups()
            return [self._map_group(g) for g in groups]
        except KeycloakError as e:
            raise UserManagementError(str(e), "GROUP_LIST_FAILED")

    async def get_user_groups(self, user_id: str) -> list[GroupData]:
        """
        Get groups the user belongs to.

        Args:
            user_id: User's ID

        Returns:
            List of groups the user is a member of

        Raises:
            UserNotFoundError: If user doesn't exist
        """
        try:
            groups = self._admin.get_user_groups(user_id)
            return [self._map_group(g) for g in groups]
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "USER_GROUPS_FAILED")

    async def add_to_groups(self, user_id: str, group_ids: list[str]) -> None:
        """
        Add user to groups.

        Args:
            user_id: User's ID
            group_ids: IDs of groups to add user to

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If addition fails
        """
        try:
            for group_id in group_ids:
                self._admin.group_user_add(user_id, group_id)
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "GROUP_ADD_FAILED")

    async def remove_from_groups(self, user_id: str, group_ids: list[str]) -> None:
        """
        Remove user from groups.

        Args:
            user_id: User's ID
            group_ids: IDs of groups to remove user from

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If removal fails
        """
        try:
            for group_id in group_ids:
                self._admin.group_user_remove(user_id, group_id)
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "GROUP_REMOVE_FAILED")

    async def get_group_roles(self, group_id: str) -> list[RoleData]:
        """
        Get realm roles assigned to a group.

        In Keycloak, groups can have realm roles assigned to them.
        All members of the group inherit these roles.

        Args:
            group_id: Group's ID

        Returns:
            List of roles assigned to the group

        Raises:
            UserManagementError: If fetching fails
        """
        try:
            roles = self._admin.get_group_realm_roles(group_id)
            return [self._map_role(r) for r in roles]
        except KeycloakError as e:
            if "Group not found" in str(e) or "404" in str(e):
                return []  # Group not found, return empty list
            raise UserManagementError(str(e), "GROUP_ROLES_FAILED")

    async def assign_group_roles(self, group_id: str, role_names: list[str]) -> None:
        """
        Assign realm roles to a group.

        Args:
            group_id: Group's ID
            role_names: Names of roles to assign

        Raises:
            UserManagementError: If assignment fails
        """
        try:
            # Get role objects by name
            roles_to_assign = []
            all_roles = self._admin.get_realm_roles()
            role_map = {r["name"]: r for r in all_roles}

            for name in role_names:
                if name in role_map:
                    roles_to_assign.append(role_map[name])
                else:
                    raise UserManagementError(
                        f"Role not found: {name}", "ROLE_NOT_FOUND"
                    )

            if roles_to_assign:
                self._admin.assign_group_realm_roles(group_id, roles_to_assign)

        except KeycloakError as e:
            raise UserManagementError(str(e), "GROUP_ROLE_ASSIGN_FAILED")

    async def remove_group_roles(self, group_id: str, role_names: list[str]) -> None:
        """
        Remove realm roles from a group.

        Args:
            group_id: Group's ID
            role_names: Names of roles to remove

        Raises:
            UserManagementError: If removal fails
        """
        try:
            # Get current group roles
            group_roles = self._admin.get_group_realm_roles(group_id)
            roles_to_remove = [r for r in group_roles if r["name"] in role_names]

            if roles_to_remove:
                self._admin.delete_group_realm_roles(group_id, roles_to_remove)

        except KeycloakError as e:
            raise UserManagementError(str(e), "GROUP_ROLE_REMOVE_FAILED")

    # ═══════════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════════

    def _map_user(self, kc_user: dict[str, Any]) -> UserData:
        """Map Keycloak user representation to UserData."""
        return UserData(
            user_id=kc_user["id"],
            username=kc_user.get("username", ""),
            email=kc_user.get("email", ""),
            first_name=kc_user.get("firstName", ""),
            last_name=kc_user.get("lastName", ""),
            enabled=kc_user.get("enabled", True),
            email_verified=kc_user.get("emailVerified", False),
            created_at=str(kc_user.get("createdTimestamp", ""))
            if kc_user.get("createdTimestamp")
            else None,
            attributes=kc_user.get("attributes", {}),
        )

    def _map_role(self, kc_role: dict[str, Any]) -> RoleData:
        """Map Keycloak role representation to RoleData."""
        return RoleData(
            role_id=kc_role["id"],
            name=kc_role["name"],
            description=kc_role.get("description", ""),
            is_composite=kc_role.get("composite", False),
        )

    def _map_group(self, kc_group: dict[str, Any]) -> GroupData:
        """
        Map Keycloak group representation to GroupData.

        Note: Keycloak's path format is preserved in the path field.
        Parent ID is extracted from path if available.
        """
        # Extract parent_id from path (e.g., "/parent/child" -> need to lookup parent)
        # For simplicity, we store the path and let callers handle hierarchy
        path = kc_group.get("path", f"/{kc_group['name']}")

        # Keycloak includes parentId in some API responses
        parent_id = kc_group.get("parentId")

        return GroupData(
            group_id=kc_group["id"],
            name=kc_group["name"],
            parent_id=parent_id,
            path=path,
            attributes=kc_group.get("attributes", {}),
        )

    # ═══════════════════════════════════════════════════════════════
    # SESSION MANAGEMENT
    # ═══════════════════════════════════════════════════════════════

    async def get_user_sessions(self, user_id: str) -> list[dict[str, Any]]:
        """
        Get all active sessions for a user.

        Args:
            user_id: User's ID

        Returns:
            List of session dictionaries from Keycloak

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If fetching fails
        """
        try:
            return self._admin.get_user_sessions(user_id)
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "GET_SESSIONS_FAILED")

    async def logout_user(self, user_id: str) -> None:
        """
        Logout user from all sessions.

        Args:
            user_id: User's ID

        Raises:
            UserNotFoundError: If user doesn't exist
            UserManagementError: If logout fails
        """
        try:
            self._admin.user_logout(user_id)
        except KeycloakError as e:
            if "User not found" in str(e) or "404" in str(e):
                raise UserNotFoundError(user_id)
            raise UserManagementError(str(e), "LOGOUT_FAILED")

    async def revoke_user_session(self, session_id: str) -> None:
        """
        Revoke a specific user session.

        Args:
            session_id: Session identifier to revoke

        Raises:
            UserManagementError: If revocation fails
        """
        try:
            self._admin.delete_user_session(session_id)
        except KeycloakError as e:
            # If 404, we assume it's already gone
            if "404" in str(e):
                return
            raise UserManagementError(str(e), "REVOKE_SESSION_FAILED")

    async def get_realm_settings(self) -> dict[str, Any]:
        """
        Get realm settings including SSO timeouts.

        Returns:
            Dictionary of realm settings

        Raises:
            UserManagementError: If fetching fails
        """
        try:
            return self._admin.get_realm(self.config.realm)
        except KeycloakError as e:
            raise UserManagementError(str(e), "GET_REALM_FAILED")
