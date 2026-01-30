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
    
    Supports both stateless and stateful modes:
    - session_id is None for stateless mode
    - session_id is set for stateful mode (track_session=True)
    
    Use factory methods to create instances.
    """
    status: AuthStatus
    session_id: Optional[str] = None  # None for stateless mode
    tokens: Optional[TokenPair] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    user_claims: Optional[dict] = None  # Decoded JWT claims
    available_otp_methods: list[str] = field(default_factory=list)
    error_message: Optional[str] = None
    error_code: Optional[str] = None  # e.g., "OTP_REQUIRED", "INVALID_CREDENTIALS"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @classmethod
    def success(
        cls,
        tokens: TokenPair,
        user_id: str,
        username: str,
        session_id: Optional[str] = None,
        user_claims: Optional[dict] = None,
    ) -> "AuthResult":
        """Create a successful authentication result."""
        return cls(
            status=AuthStatus.SUCCESS,
            session_id=session_id,
            tokens=tokens,
            user_id=user_id,
            username=username,
            user_claims=user_claims,
        )
    
    @classmethod
    def otp_required(
        cls,
        available_methods: list[str],
        session_id: Optional[str] = None,
        message: str = "OTP verification required",
    ) -> "AuthResult":
        """
        Create a result requiring OTP verification.
        
        For stateless mode: session_id is None
        For stateful mode: session_id is set
        """
        return cls(
            status=AuthStatus.OTP_REQUIRED,
            session_id=session_id,
            available_otp_methods=available_methods,
            error_code="OTP_REQUIRED",
            error_message=message,
        )
    
    @classmethod
    def failed(
        cls,
        error_message: str,
        error_code: str = "AUTHENTICATION_FAILED",
        session_id: Optional[str] = None,
    ) -> "AuthResult":
        """Create a failed authentication result."""
        return cls(
            status=AuthStatus.FAILED,
            session_id=session_id,
            error_message=error_message,
            error_code=error_code,
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
    session_id: Optional[str] = None  # None for stateless mode


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
