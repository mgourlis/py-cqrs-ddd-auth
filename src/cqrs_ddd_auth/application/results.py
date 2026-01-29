"""
Authentication result types.

These represent the outcomes of authentication operations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class AuthStatus(str, Enum):
    """Status of an authentication attempt."""
    SUCCESS = "success"
    OTP_REQUIRED = "otp_required"
    FAILED = "failed"


@dataclass
class TokenPair:
    """Access and refresh token pair."""
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600  # seconds
    refresh_expires_in: int = 86400  # seconds
    scope: str = ""


@dataclass
class AuthResult:
    """
    Result of an authentication operation.
    
    Use factory methods to create instances.
    """
    status: AuthStatus
    session_id: str
    tokens: Optional[TokenPair] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    available_otp_methods: list[str] = field(default_factory=list)
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def success(
        cls,
        session_id: str,
        tokens: TokenPair,
        user_id: str,
        username: str,
    ) -> "AuthResult":
        """Create a successful authentication result."""
        return cls(
            status=AuthStatus.SUCCESS,
            session_id=session_id,
            tokens=tokens,
            user_id=user_id,
            username=username,
        )
    
    @classmethod
    def otp_required(
        cls,
        session_id: str,
        available_methods: list[str],
    ) -> "AuthResult":
        """Create a result requiring OTP verification."""
        return cls(
            status=AuthStatus.OTP_REQUIRED,
            session_id=session_id,
            available_otp_methods=available_methods,
        )
    
    @classmethod
    def failed(
        cls,
        session_id: str,
        error_message: str,
    ) -> "AuthResult":
        """Create a failed authentication result."""
        return cls(
            status=AuthStatus.FAILED,
            session_id=session_id,
            error_message=error_message,
        )
    
    @property
    def is_success(self) -> bool:
        return self.status == AuthStatus.SUCCESS
    
    @property
    def requires_otp(self) -> bool:
        return self.status == AuthStatus.OTP_REQUIRED
    
    @property
    def is_failed(self) -> bool:
        return self.status == AuthStatus.FAILED


@dataclass
class OTPChallengeResult:
    """Result of sending an OTP challenge."""
    success: bool
    message: str  # e.g., "Code sent to j****@example.com"
    method: str
    session_id: str


@dataclass
class TOTPSetupResult:
    """Result of TOTP setup initialization."""
    secret: str  # Base32 secret (for backup codes)
    provisioning_uri: str  # For QR code generation
    user_id: str


@dataclass
class LogoutResult:
    """Result of logout operation."""
    success: bool
    sessions_revoked: int = 1
