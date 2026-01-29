"""
Domain value objects for authentication.

Value objects are immutable and have no identity—they are defined
only by their attributes. These are the building blocks for aggregates.

Uses ValueObject base class from py-cqrs-ddd-toolkit.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cqrs_ddd.ddd import ValueObject


@dataclass(frozen=True)
class Credentials(ValueObject):
    """
    Username/password pair for direct grant authentication.
    
    This is a transient value object—never persisted, only used
    during the authentication flow.
    """
    username: str
    password: str  # Never persisted, only used in-memory


@dataclass(frozen=True)
class TOTPSecret(ValueObject):
    """
    TOTP secret for time-based OTP using pyotp.
    
    Used for authenticator app-based 2FA (Google Authenticator, Authy, etc.).
    """
    secret: str  # Base32 encoded secret
    
    @classmethod
    def generate(cls) -> "TOTPSecret":
        """Generate a new random TOTP secret."""
        import pyotp
        return cls(secret=pyotp.random_base32())
    
    def get_provisioning_uri(self, username: str, issuer: str) -> str:
        """
        Generate a provisioning URI for QR code display.
        
        Users scan this with their authenticator app to set up 2FA.
        """
        import pyotp
        totp = pyotp.TOTP(self.secret)
        return totp.provisioning_uri(name=username, issuer_name=issuer)
    
    def verify_code(self, code: str, valid_window: int = 1) -> bool:
        """
        Verify a TOTP code against this secret.
        
        Args:
            code: The 6-digit code from the user's authenticator app
            valid_window: Number of time periods before/after current to accept
        
        Returns:
            True if the code is valid
        """
        import pyotp
        totp = pyotp.TOTP(self.secret)
        return totp.verify(code, valid_window=valid_window)
    
    def get_current_code(self) -> str:
        """Get the current TOTP code (useful for testing)."""
        import pyotp
        totp = pyotp.TOTP(self.secret)
        return totp.now()


@dataclass(frozen=True)
class UserClaims(ValueObject):
    """
    Decoded JWT claims from the Identity Provider.
    
    This is the normalized representation of user identity
    extracted from an access token.
    """
    sub: str  # Subject (user ID)
    username: str
    email: str
    groups: tuple[str, ...]
    attributes: dict = field(default_factory=dict)
    
    def to_identity(self):
        """Convert to an AuthenticatedIdentity for the context."""
        from cqrs_ddd_auth.identity import AuthenticatedIdentity
        return AuthenticatedIdentity(
            user_id=self.sub,
            username=self.username,
            groups=list(self.groups),
            permissions=[],  # Fetched separately from ABAC
            tenant_id=self.attributes.get("tenant_id")
        )


@dataclass
class OTPChallenge:
    """
    Stored OTP challenge record for email/SMS verification.
    
    This is a mutable data structure (not frozen) because it
    tracks state changes like attempts and status.
    """
    user_id: str
    method: str  # 'email', 'sms', 'totp'
    secret: str  # Base32 secret for pyotp verification
    created_at: datetime
    expires_at: datetime
    attempts: int = 0
    status: str = "pending"  # pending, used, expired
    
    def is_expired(self) -> bool:
        """Check if the challenge has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def increment_attempts(self) -> None:
        """Increment the failed attempts counter."""
        self.attempts += 1
    
    def mark_used(self) -> None:
        """Mark the challenge as successfully used."""
        self.status = "used"
