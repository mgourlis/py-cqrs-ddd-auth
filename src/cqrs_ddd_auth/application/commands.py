"""
Authentication commands.

Commands represent intentions to change state. Each command
is handled by a corresponding handler.

Uses Command base class from py-cqrs-ddd-toolkit.
"""

from dataclasses import dataclass
from typing import Optional, List

from cqrs_ddd.core import Command


@dataclass(kw_only=True)
class AuthenticateWithCredentials(Command):
    """
    Initiate authentication with username/password.

    Supports two modes:
    1. Stateless: No session_id needed, OTP can be sent in same request
    2. Stateful: Session tracking for multi-step flows

    Stateless mode (like your legacy Django code):
        - Authenticate credentials → if OTP required, return otp_required
        - Client re-sends credentials + otp_method + otp_code
        - No server-side session needed

    Stateful mode:
        - Creates AuthSession for tracking
        - Use session_id for subsequent ValidateOTP command
    """

    username: str
    password: str

    # Continuation context (for Step 2/3)
    session_id: Optional[str] = None  # Stateful: Look up context from DB
    pre_auth_token: Optional[str] = None  # Stateless: Encrypted context from client

    # OTP data (for Stateless continuation)
    otp_method: Optional[str] = None  # totp, email, sms
    otp_code: Optional[str] = None

    # Session tracking options
    track_session: bool = False
    ip_address: str = ""
    user_agent: str = ""

    # Optional role/group checking
    required_groups: Optional[List[str]] = None  # User must be in at least one


@dataclass(kw_only=True)
class ValidateOTP(Command):
    """
    Validate a one-time password.

    Used in:
    1. Stateful mode: session_id + code
    2. Stateless/Step-up mode: access_token + code
    """

    code: str
    session_id: Optional[str] = None
    access_token: Optional[str] = None
    method: str = "totp"  # totp, email, sms


@dataclass(kw_only=True)
class SendOTPChallenge(Command):
    """
    Request an OTP challenge to be sent.

    Used for email/SMS methods where the code needs to be delivered.

    Supports multiple modes for identifying the user:
    - session_id: Look up from session (stateful mode)
    - access_token: Decode claims from token (stateless mode)
    - user_id: Look up user from admin port (saga/internal mode)
    """

    session_id: Optional[str] = None  # Stateful mode - look up from session
    access_token: Optional[str] = None  # Stateless mode - decode from token
    user_id: Optional[str] = None  # Saga/internal mode - look up from admin port
    method: str = ""  # email, sms


@dataclass(kw_only=True)
class RefreshTokens(Command):
    """
    Refresh access tokens using a refresh token.
    """

    refresh_token: str


@dataclass(kw_only=True)
class Logout(Command):
    """
    Terminate the current session and invalidate tokens.
    """

    refresh_token: str
    session_id: Optional[str] = None  # Optional - for stateful mode


@dataclass(kw_only=True)
class RevokeSession(Command):
    """
    Revoke a specific session (admin or user action).
    """

    session_id: str
    reason: str = "revoked_by_user"


@dataclass(kw_only=True)
class RevokeAllSessions(Command):
    """
    Revoke all sessions for a user (security action).
    """

    user_id: str
    reason: str = "security_action"


# ═══════════════════════════════════════════════════════════════
# TOTP SETUP COMMANDS
# ═══════════════════════════════════════════════════════════════


@dataclass(kw_only=True)
class SetupTOTP(Command):
    """
    Initialize TOTP setup for a user.

    Returns a provisioning URI for QR code display.
    """

    user_id: str


@dataclass(kw_only=True)
class ConfirmTOTPSetup(Command):
    """
    Confirm TOTP setup by validating the first code.

    This verifies the user has correctly configured their authenticator.
    """

    user_id: str
    secret: str  # The secret from setup step
    code: str  # The verification code


@dataclass(kw_only=True)
class DisableTOTP(Command):
    """
    Disable TOTP 2FA for a user.
    """

    user_id: str
    verification_code: str  # Require current TOTP code to disable


# ═══════════════════════════════════════════════════════════════
# USER MANAGEMENT COMMANDS
# ═══════════════════════════════════════════════════════════════


@dataclass(kw_only=True)
class CreateUser(Command):
    """
    Create a new user in the identity provider.

    Returns the created user's ID.
    """

    username: str
    email: str
    first_name: str = ""
    last_name: str = ""
    enabled: bool = True
    email_verified: bool = False
    attributes: Optional[dict] = None
    # Optional: set password on creation
    temporary_password: Optional[str] = None


@dataclass(kw_only=True)
class UpdateUser(Command):
    """
    Update an existing user's attributes.

    Only non-None fields will be updated.
    """

    user_id: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    enabled: Optional[bool] = None
    email_verified: Optional[bool] = None
    attributes: Optional[dict] = None


@dataclass(kw_only=True)
class DeleteUser(Command):
    """
    Delete a user from the identity provider.
    """

    user_id: str


@dataclass(kw_only=True)
class SetUserPassword(Command):
    """
    Set a user's password.
    """

    user_id: str
    password: str
    temporary: bool = False  # If True, user must change on next login


@dataclass(kw_only=True)
class SendPasswordReset(Command):
    """
    Trigger password reset email for a user.
    """

    user_id: str


@dataclass(kw_only=True)
class SendVerifyEmail(Command):
    """
    Send email verification email to a user.
    """

    user_id: str


@dataclass(kw_only=True)
class AssignRoles(Command):
    """
    Assign roles to a user.
    """

    user_id: str
    role_names: List[str]


@dataclass(kw_only=True)
class RemoveRoles(Command):
    """
    Remove roles from a user.
    """

    user_id: str
    role_names: List[str]


@dataclass(kw_only=True)
class AddToGroups(Command):
    """
    Add a user to groups.
    """

    user_id: str
    group_ids: List[str]


@dataclass(kw_only=True)
class RemoveFromGroups(Command):
    """
    Remove a user from groups.
    """

    user_id: str
    group_ids: List[str]


@dataclass(kw_only=True)
class GrantTemporaryElevation(Command):
    """
    Grant temporary elevated privileges to a user.
    Used by the StepUpAuthenticationSaga.
    """

    user_id: str
    action: str
    ttl_seconds: int = 300


@dataclass(kw_only=True)
class RevokeElevation(Command):
    """
    Revoke temporary elevated privileges from a user.
    Used by the StepUpAuthenticationSaga.
    """

    user_id: str
    reason: str = "completed"


@dataclass(kw_only=True)
class ResumeSensitiveOperation(Command):
    """
    Signal to resume a suspended sensitive operation.
    Used by the StepUpAuthenticationSaga after successful auth.
    """

    operation_id: str
