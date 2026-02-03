"""
Authentication queries.

Queries represent read-only requests for data. They do not
modify state and return a result.

Uses Query base class from py-cqrs-ddd-toolkit.
"""

from dataclasses import dataclass
from typing import Optional

from cqrs_ddd.core import Query


@dataclass(kw_only=True)
class GetUserInfo(Query):
    """
    Get information about the current authenticated user.

    Returns user claims decoded from the access token plus
    any additional profile information.

    Can be used in two modes:
    1. With access_token: Decodes token to get claims
    2. With user_id: Fetches from IdP's userinfo endpoint
    """

    access_token: Optional[str] = None
    user_id: Optional[str] = None


@dataclass(kw_only=True)
class GetAvailableOTPMethods(Query):
    """
    Get available OTP methods for a user.

    Returns a list of OTP methods the user has configured
    or can use (e.g., ['totp', 'email', 'sms']).

    Requires either access_token or user_claims to identify the user.
    """

    access_token: Optional[str] = None
    user_id: Optional[str] = None


@dataclass(kw_only=True)
class ListActiveSessions(Query):
    """
    List active authentication sessions for a user.

    Used for session management UI where users can see
    all their active sessions and revoke them.

    Returns session details including:
    - Session ID
    - IP address
    - User agent
    - Created/last activity timestamps
    - Current session indicator
    """

    user_id: str
    current_session_id: Optional[str] = None  # To mark as "current"
    include_expired: bool = False


@dataclass(kw_only=True)
class GetSessionDetails(Query):
    """
    Get detailed information about a specific session.

    Returns full session state including status,
    authentication method used, and timestamps.
    """

    session_id: str


@dataclass(kw_only=True)
class CheckTOTPEnabled(Query):
    """
    Check if a user has TOTP 2FA enabled.

    Returns whether the user has set up authenticator app-based
    two-factor authentication.
    """

    user_id: str


# ═══════════════════════════════════════════════════════════════
# USER MANAGEMENT QUERIES (Section 10.2)
# ═══════════════════════════════════════════════════════════════


@dataclass(kw_only=True)
class GetUser(Query):
    """
    Get user by ID from the identity provider.

    Returns full user profile including attributes,
    enabled status, and email verification status.
    """

    user_id: str


@dataclass(kw_only=True)
class GetUserByUsername(Query):
    """
    Get user by username from the identity provider.

    Useful for looking up users when you only have their username.
    """

    username: str


@dataclass(kw_only=True)
class GetUserByEmail(Query):
    """
    Get user by email from the identity provider.

    Useful for looking up users when you only have their email.
    """

    email: str


@dataclass(kw_only=True)
class ListUsers(Query):
    """
    List users with optional filters.

    Used for admin interfaces to browse and search users.
    Supports pagination for large user bases.
    """

    search: Optional[str] = None  # Search in username, email, name
    role: Optional[str] = None  # Filter by role
    group: Optional[str] = None  # Filter by group
    enabled: Optional[bool] = None  # Filter by enabled status
    offset: int = 0
    limit: int = 100


@dataclass(kw_only=True)
class GetUserRoles(Query):
    """
    Get all roles assigned to a user.

    Returns both directly assigned roles and roles
    inherited from group membership.
    """

    user_id: str
    include_group_roles: bool = True  # Include roles from group membership


@dataclass(kw_only=True)
class GetUserGroups(Query):
    """
    Get all groups a user belongs to.

    Returns hierarchical group information including
    the full path for each group.
    """

    user_id: str


# ═══════════════════════════════════════════════════════════════
# PERMISSION QUERIES
# ═══════════════════════════════════════════════════════════════


@dataclass(kw_only=True)
class GetTypeLevelPermissions(Query):
    """
    Get type-level permissions for the current user.

    Returns what actions the user can perform on each resource type.
    Used for UI rendering (showing/hiding buttons, menu items, etc.).
    """

    access_token: str
    resource_types: Optional[list[str]] = None  # None = all types
