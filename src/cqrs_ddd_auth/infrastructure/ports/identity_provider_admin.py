"""
Identity Provider Admin Port.

Defines the interface for administrative identity provider operations
such as user management, role assignment, and group management.

This is separate from IdentityProviderPort which handles authentication.
"""

from dataclasses import dataclass, field
from typing import Protocol, Optional, Any, runtime_checkable


# ═══════════════════════════════════════════════════════════════
# DATA TRANSFER OBJECTS
# ═══════════════════════════════════════════════════════════════


@dataclass
class CreateUserData:
    """Data for creating a new user."""

    username: str
    email: str
    first_name: str = ""
    last_name: str = ""
    enabled: bool = True
    email_verified: bool = False
    attributes: dict[str, Any] = field(default_factory=dict)
    # Optional: set password on creation
    temporary_password: Optional[str] = None


@dataclass
class UpdateUserData:
    """Data for updating an existing user."""

    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    enabled: Optional[bool] = None
    email_verified: Optional[bool] = None
    attributes: Optional[dict[str, Any]] = None


@dataclass
class UserData:
    """User data returned from IdP."""

    user_id: str
    username: str
    email: str
    first_name: str = ""
    last_name: str = ""
    enabled: bool = True
    email_verified: bool = False
    created_at: Optional[str] = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class RoleData:
    """Role data from IdP."""

    role_id: str
    name: str
    description: str = ""
    is_composite: bool = False


@dataclass
class GroupData:
    """
    Group data from IdP.

    Groups are supported by most identity providers but with varying
    semantics. This dataclass provides a generic representation.

    Hierarchy support varies:
    - Some IdPs support nested groups (parent_id points to parent group)
    - Some IdPs support path-based hierarchy (path as IdP-specific string)
    - Some IdPs have flat groups (parent_id is None)
    """

    group_id: str
    name: str
    parent_id: Optional[str] = None  # Parent group ID for hierarchy (if supported)
    path: Optional[str] = None  # IdP-specific path format (optional)
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class UserFilters:
    """Filters for listing users."""

    search: Optional[str] = None  # Search in username, email, name
    role: Optional[str] = None  # Filter by role
    group: Optional[str] = None  # Filter by group
    enabled: Optional[bool] = None
    offset: int = 0
    limit: int = 100


# ═══════════════════════════════════════════════════════════════
# IDENTITY PROVIDER ADMIN PORT
# ═══════════════════════════════════════════════════════════════


class IdentityProviderAdminPort(Protocol):
    """
    Port for administrative identity provider operations.

    Implementations: KeycloakAdminAdapter, Auth0AdminAdapter, etc.

    This port handles user management operations that require admin
    privileges on the identity provider, separate from the regular
    authentication flow.
    """

    # ═══════════════════════════════════════════════════════════════
    # USER CRUD
    # ═══════════════════════════════════════════════════════════════

    async def create_user(self, user: CreateUserData) -> str:
        """
        Create a new user in the identity provider.

        Args:
            user: User data for creation

        Returns:
            The created user's ID
        """
        ...

    async def get_user(self, user_id: str) -> Optional[UserData]:
        """
        Get user by ID.

        Args:
            user_id: User's ID in the IdP

        Returns:
            UserData if found, None otherwise
        """
        ...

    async def get_user_by_username(self, username: str) -> Optional[UserData]:
        """
        Get user by username.

        Args:
            username: User's username

        Returns:
            UserData if found, None otherwise
        """
        ...

    async def get_user_by_email(self, email: str) -> Optional[UserData]:
        """
        Get user by email.

        Args:
            email: User's email address

        Returns:
            UserData if found, None otherwise
        """
        ...

    async def update_user(self, user_id: str, updates: UpdateUserData) -> None:
        """
        Update user attributes.

        Args:
            user_id: User's ID
            updates: Fields to update (None values are ignored)
        """
        ...

    async def delete_user(self, user_id: str) -> None:
        """
        Delete a user.

        Args:
            user_id: User's ID to delete
        """
        ...

    async def list_users(self, filters: Optional[UserFilters] = None) -> list[UserData]:
        """
        List users with optional filters.

        Args:
            filters: Optional filtering criteria

        Returns:
            List of matching users
        """
        ...

    async def count_users(self, filters: Optional[UserFilters] = None) -> int:
        """
        Count users matching filters.

        Args:
            filters: Optional filtering criteria

        Returns:
            Total count of matching users
        """
        ...

    async def revoke_user_session(self, session_id: str) -> None:
        """
        Revoke a specific user session.

        Args:
            session_id: Session identifier to revoke

        Raises:
            UserManagementError: If revocation fails
        """
        ...

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
        """
        ...

    async def send_password_reset(self, user_id: str) -> None:
        """
        Trigger password reset email.

        Args:
            user_id: User's ID
        """
        ...

    async def send_verify_email(self, user_id: str) -> None:
        """
        Send email verification email.

        Args:
            user_id: User's ID
        """
        ...

    # ═══════════════════════════════════════════════════════════════
    # ROLE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════

    async def list_roles(self) -> list[RoleData]:
        """List all realm roles."""
        ...

    async def get_user_roles(self, user_id: str) -> list[RoleData]:
        """
        Get user's assigned realm roles.

        Args:
            user_id: User's ID

        Returns:
            List of roles assigned to the user
        """
        ...

    async def assign_roles(self, user_id: str, role_names: list[str]) -> None:
        """
        Assign realm roles to user.

        Args:
            user_id: User's ID
            role_names: Names of roles to assign
        """
        ...

    async def remove_roles(self, user_id: str, role_names: list[str]) -> None:
        """
        Remove realm roles from user.

        Args:
            user_id: User's ID
            role_names: Names of roles to remove
        """
        ...

    # ═══════════════════════════════════════════════════════════════
    # GROUP MANAGEMENT
    # ═══════════════════════════════════════════════════════════════

    async def list_groups(self) -> list[GroupData]:
        """List all groups (hierarchical)."""
        ...

    async def get_user_groups(self, user_id: str) -> list[GroupData]:
        """
        Get groups the user belongs to.

        Args:
            user_id: User's ID

        Returns:
            List of groups the user is a member of
        """
        ...

    async def add_to_groups(self, user_id: str, group_ids: list[str]) -> None:
        """
        Add user to groups.

        Args:
            user_id: User's ID
            group_ids: IDs of groups to add user to
        """
        ...

    async def remove_from_groups(self, user_id: str, group_ids: list[str]) -> None:
        """
        Remove user from groups.

        Args:
            user_id: User's ID
            group_ids: IDs of groups to remove user from
        """
        ...


# ═══════════════════════════════════════════════════════════════
# OPTIONAL CAPABILITY PROTOCOLS
# These protocols define capabilities that may not be supported
# by all identity providers. Use runtime checks or isinstance().
# ═══════════════════════════════════════════════════════════════


@runtime_checkable
class GroupRolesCapability(Protocol):
    """
    Protocol for IdPs that support assigning roles to groups.

    In some identity providers (like Keycloak), groups can have roles
    assigned to them, and all group members inherit those roles.
    This is NOT a universal IdP feature.

    Usage:
        if isinstance(idp_admin, GroupRolesCapability):
            group_roles = await idp_admin.get_group_roles(group_id)
    """

    async def get_group_roles(self, group_id: str) -> list[RoleData]:
        """
        Get roles assigned to a group.

        Args:
            group_id: Group's ID

        Returns:
            List of roles assigned to the group
        """
        ...

    async def assign_group_roles(self, group_id: str, role_names: list[str]) -> None:
        """
        Assign realm roles to a group.

        Args:
            group_id: Group's ID
            role_names: Names of roles to assign
        """
        ...

    async def remove_group_roles(self, group_id: str, role_names: list[str]) -> None:
        """
        Remove realm roles from a group.

        Args:
            group_id: Group's ID
            role_names: Names of roles to remove
        """
        ...
