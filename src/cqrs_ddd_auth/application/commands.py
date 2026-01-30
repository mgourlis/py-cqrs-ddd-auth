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
    
    # Session tracking (optional - enable for stateful mode)
    track_session: bool = False
    ip_address: str = ""
    user_agent: str = ""
    
    # Inline OTP for stateless mode (like legacy flow)
    otp_method: Optional[str] = None  # totp, email, sms
    otp_code: Optional[str] = None
    
    # Optional role/group checking
    required_groups: Optional[List[str]] = None  # User must be in at least one


@dataclass(kw_only=True)
class ValidateOTP(Command):
    """
    Validate a one-time password (stateful mode).
    
    Called after AuthenticateWithCredentials when:
    - track_session=True was used
    - OTP is required
    - Client sends session_id + OTP code
    """
    session_id: str
    code: str
    method: str = "totp"  # totp, email, sms


@dataclass(kw_only=True)
class SendOTPChallenge(Command):
    """
    Request an OTP challenge to be sent.
    
    Used for email/SMS methods where the code needs to be delivered.
    Can work with or without session_id.
    """
    session_id: Optional[str] = None  # Optional for stateless mode
    user_claims_json: Optional[str] = None  # Alternative: pass claims directly
    access_token: Optional[str] = None  # Alternative: pass token to decode
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
