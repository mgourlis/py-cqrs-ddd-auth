"""
Authentication result types.

These represent the outcomes of authentication operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from cqrs_ddd_auth.domain.value_objects import UserClaims


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


# ═══════════════════════════════════════════════════════════════
# QUERY RESULTS
# ═══════════════════════════════════════════════════════════════

@dataclass
class UserInfoResult:
    """
    Result of GetUserInfo query.
    
    Contains the user's profile information decoded from
    their access token or fetched from the IdP.
    """
    user_id: str
    username: str
    email: str
    groups: list[str] = field(default_factory=list)
    attributes: dict = field(default_factory=dict)
    # Additional profile fields (optional)
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    tenant_id: Optional[str] = None
    # 2FA status
    totp_enabled: bool = False
    
    @classmethod
    def from_claims(cls, claims: "UserClaims", totp_enabled: bool = False) -> "UserInfoResult":
        """Create from UserClaims value object."""
        return cls(
            user_id=claims.sub,
            username=claims.username,
            email=claims.email,
            groups=list(claims.groups) if claims.groups else [],
            attributes=dict(claims.attributes) if claims.attributes else {},
            tenant_id=claims.attributes.get("tenant_id") if claims.attributes else None,
            totp_enabled=totp_enabled,
        )


@dataclass
class OTPMethodInfo:
    """Information about an available OTP method."""
    method: str  # 'totp', 'email', 'sms'
    enabled: bool  # Whether user has this method configured
    destination: Optional[str] = None  # e.g., "j****@example.com" for email


@dataclass
class AvailableOTPMethodsResult:
    """Result of GetAvailableOTPMethods query."""
    methods: list[OTPMethodInfo] = field(default_factory=list)
    requires_otp: bool = False  # Whether OTP is required for this user
    
    @property
    def enabled_methods(self) -> list[str]:
        """Get list of enabled method names."""
        return [m.method for m in self.methods if m.enabled]
    
    @property
    def available_methods(self) -> list[str]:
        """Get list of all available method names."""
        return [m.method for m in self.methods]


@dataclass
class SessionInfo:
    """Information about an authentication session."""
    session_id: str
    status: str  # authenticated, pending_otp, expired, revoked
    ip_address: str
    user_agent: str
    created_at: datetime
    last_activity: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_current: bool = False  # True if this is the requesting session
    otp_method: Optional[str] = None  # Which OTP method was used
    
    @property
    def is_active(self) -> bool:
        """Check if session is currently active."""
        if self.status != "authenticated":
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        return True


@dataclass
class ListSessionsResult:
    """Result of ListActiveSessions query."""
    sessions: list[SessionInfo] = field(default_factory=list)
    total_count: int = 0
    
    @property
    def active_count(self) -> int:
        """Count of currently active sessions."""
        return sum(1 for s in self.sessions if s.is_active)


@dataclass
class TOTPStatusResult:
    """Result of CheckTOTPEnabled query."""
    enabled: bool
    user_id: str
    configured_at: Optional[datetime] = None
