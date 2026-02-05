"""
Domain value objects for authentication.

Value objects are immutable and have no identity—they are defined
only by their attributes. These are the building blocks for aggregates.

Uses ValueObject base class from py-cqrs-ddd-toolkit.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cqrs_ddd.ddd import ValueObject


# ═══════════════════════════════════════════════════════════════
# ROLE UNIFICATION (Groups as Roles)
# ═══════════════════════════════════════════════════════════════


class RoleSource(Enum):
    """
    Origin of a role for audit and debugging.

    Generic sources that work with any Identity Provider.
    Allows tracking where each role came from in authorization decisions.
    """

    IDP_ROLE = "idp_role"  # Direct role from IdP (realm/global role)
    IDP_CLIENT_ROLE = "idp_client_role"  # Client/application-specific role from IdP
    DERIVED = "derived"  # Derived from group/team membership
    CUSTOM = "custom"  # Application-defined role


@dataclass(frozen=True)
class AuthRole(ValueObject):
    """
    Unified role representation that can originate from:
    - IdP roles (realm/global roles)
    - IdP client roles (application-specific)
    - Derived roles (from group/team membership)
    - Custom application roles

    For authorization purposes, the source is for audit only—
    the name is what matters for ACL matching.
    """

    name: str
    source: RoleSource
    attributes: dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# CREDENTIALS
# ═══════════════════════════════════════════════════════════════


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
    extracted from an access token. IdP adapters are responsible
    for creating UserClaims from their specific token format.
    """

    sub: str  # Subject (user ID)
    username: str
    email: str
    groups: tuple[str, ...]  # Raw group paths from token
    phone_number: Optional[str] = None
    roles: tuple[AuthRole, ...] = field(default_factory=tuple)  # Unified roles
    attributes: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "UserClaims":
        return cls(
            sub=data["sub"],
            username=data["username"],
            email=data["email"],
            phone_number=data.get("phone_number"),
            groups=tuple(data.get("groups", [])),
            attributes={
                k: v
                for k, v in data.items()
                if k not in ["sub", "username", "email", "groups", "roles"]
            },
        )

    def to_dict(self) -> dict:
        return {
            "sub": self.sub,
            "username": self.username,
            "email": self.email,
            "phone_number": self.phone_number,
            "groups": list(self.groups),
            **self.attributes,
        }

    @property
    def role_names(self) -> list[str]:
        """All role names regardless of source."""
        return [r.name for r in self.roles]

    @property
    def idp_roles(self) -> list[str]:
        """Only direct IdP role names."""
        return [r.name for r in self.roles if r.source == RoleSource.IDP_ROLE]

    @property
    def client_roles(self) -> list[str]:
        """Only client-specific role names."""
        return [r.name for r in self.roles if r.source == RoleSource.IDP_CLIENT_ROLE]

    @property
    def derived_roles(self) -> list[str]:
        """Only derived role names (from groups/teams)."""
        return [r.name for r in self.roles if r.source == RoleSource.DERIVED]

    def has_role(self, role_name: str, source: Optional[RoleSource] = None) -> bool:
        """
        Check if user has a role, optionally filtered by source.

        Args:
            role_name: Name of the role to check
            source: If provided, only check roles from this source

        Returns:
            True if the user has the role
        """
        for role in self.roles:
            if role.name == role_name:
                if source is None or role.source == source:
                    return True
        return False

    def has_any_role(
        self, role_names: list[str], source: Optional[RoleSource] = None
    ) -> bool:
        """Check if user has any of the specified roles."""
        return any(self.has_role(name, source) for name in role_names)

    def has_all_roles(
        self, role_names: list[str], source: Optional[RoleSource] = None
    ) -> bool:
        """Check if user has all of the specified roles."""
        return all(self.has_role(name, source) for name in role_names)

    def to_identity(self):
        """Convert to an AuthenticatedIdentity for the context."""
        from cqrs_ddd_auth.identity import AuthenticatedIdentity

        return AuthenticatedIdentity(
            user_id=self.sub,
            username=self.username,
            groups=list(self.groups),
            permissions=[],  # Fetched separately from ABAC
            tenant_id=self.attributes.get("tenant_id"),
            # phone_number can also be passed if needed in identity
        )
