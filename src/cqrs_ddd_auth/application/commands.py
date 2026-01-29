"""
Authentication commands.

Commands represent intentions to change state. Each command
is handled by a corresponding handler.

Uses Command base class from py-cqrs-ddd-toolkit.
"""

from dataclasses import dataclass
from typing import Optional

from cqrs_ddd.core import Command


@dataclass(kw_only=True)
class AuthenticateWithCredentials(Command):
    """
    Initiate authentication with username/password.
    
    This is the primary entry point for the authentication flow.
    May result in immediate success (tokens) or require OTP.
    """
    username: str
    password: str
    ip_address: str = ""
    user_agent: str = ""


@dataclass(kw_only=True)
class ValidateOTP(Command):
    """
    Validate a one-time password.
    
    Called after AuthenticateWithCredentials when OTP is required.
    """
    session_id: str
    code: str
    method: str = "totp"  # totp, email, sms


@dataclass(kw_only=True)
class SendOTPChallenge(Command):
    """
    Request an OTP challenge to be sent.
    
    Used for email/SMS methods where the code needs to be delivered.
    """
    session_id: str
    method: str  # email, sms


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
    session_id: Optional[str] = None


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
