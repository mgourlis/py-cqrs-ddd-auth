"""
Domain events for authentication.

Domain events represent facts that have happened in the domain.
They are immutable records of state changes.

Uses DomainEvent base class from py-cqrs-ddd-toolkit.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any

from cqrs_ddd.ddd import DomainEvent


@dataclass
class AuthSessionCreated(DomainEvent):
    """Raised when a new authentication session is started."""

    session_id: Optional[str] = None
    ip_address: str = ""
    user_agent: str = ""

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthSessionCreated":
        return cls(
            session_id=data.get("session_id"),
            ip_address=data.get("ip_address", ""),
            user_agent=data.get("user_agent", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class CredentialsValidated(DomainEvent):
    """Raised when primary credentials (username/password) are validated."""

    session_id: Optional[str] = None
    subject_id: Optional[str] = None
    requires_otp: bool = False

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CredentialsValidated":
        return cls(
            session_id=data.get("session_id"),
            subject_id=data.get("subject_id"),
            requires_otp=data.get("requires_otp", False),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class OTPRequired(DomainEvent):
    """Raised when multi-factor authentication is required."""

    session_id: Optional[str] = None
    subject_id: Optional[str] = None
    available_methods: tuple[str, ...] = ()

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPRequired":
        return cls(
            session_id=data.get("session_id"),
            subject_id=data.get("subject_id"),
            available_methods=tuple(data.get("available_methods", [])),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class OTPChallengeIssued(DomainEvent):
    """Raised when an OTP challenge is sent (email/SMS)."""

    session_id: Optional[str] = None
    method: str = ""  # 'email', 'sms', 'totp'
    challenge_id: str = ""

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPChallengeIssued":
        return cls(
            session_id=data.get("session_id"),
            method=data.get("method", ""),
            challenge_id=data.get("challenge_id", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class OTPValidated(DomainEvent):
    """Raised when OTP is successfully validated."""

    session_id: Optional[str] = None
    subject_id: Optional[str] = None
    method: str = ""

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPValidated":
        return cls(
            session_id=data.get("session_id"),
            subject_id=data.get("subject_id"),
            method=data.get("method", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class OTPValidationFailed(DomainEvent):
    """Raised when OTP validation fails."""

    session_id: Optional[str] = None
    method: str = ""
    reason: str = ""  # 'expired', 'invalid', 'max_attempts'

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OTPValidationFailed":
        return cls(
            session_id=data.get("session_id"),
            method=data.get("method", ""),
            reason=data.get("reason", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class AuthenticationSucceeded(DomainEvent):
    """Raised when the full authentication flow completes successfully."""

    session_id: Optional[str] = None
    subject_id: Optional[str] = None
    username: str = ""
    groups: tuple[str, ...] = ()
    ip_address: str = ""

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthenticationSucceeded":
        return cls(
            session_id=data.get("session_id"),
            subject_id=data.get("subject_id"),
            username=data.get("username", ""),
            groups=tuple(data.get("groups", [])),
            ip_address=data.get("ip_address", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class AuthenticationFailed(DomainEvent):
    """Raised when authentication fails at any step."""

    session_id: Optional[str] = None
    subject_id: Optional[str] = None
    reason: str = ""
    ip_address: str = ""

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthenticationFailed":
        return cls(
            session_id=data.get("session_id"),
            subject_id=data.get("subject_id"),
            reason=data.get("reason", ""),
            ip_address=data.get("ip_address", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class SessionRevoked(DomainEvent):
    """Raised when a session is explicitly revoked (logout)."""

    session_id: Optional[str] = None
    subject_id: Optional[str] = None
    reason: str = "user_logout"

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionRevoked":
        return cls(
            session_id=data.get("session_id"),
            subject_id=data.get("subject_id"),
            reason=data.get("reason", "user_logout"),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class TokenRefreshed(DomainEvent):
    """Raised when tokens are refreshed."""

    session_id: Optional[str] = None

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenRefreshed":
        return cls(
            session_id=data.get("session_id"),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class TokenExpired(DomainEvent):
    """Raised when a token expires."""

    session_id: Optional[str] = None
    token_type: str = ""  # 'access' or 'refresh'

    @property
    def aggregate_type(self) -> str:
        return "AuthSession"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.session_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenExpired":
        return cls(
            session_id=data.get("session_id"),
            token_type=data.get("token_type", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


# ═══════════════════════════════════════════════════════════════
# IDENTITY CHANGE EVENTS
# These events trigger automatic IdP-to-ABAC synchronization.
# ═══════════════════════════════════════════════════════════════


@dataclass
class IdentityChanged(DomainEvent):
    """
    Base event for identity changes that require ABAC sync.

    This is a marker event that can be used to trigger IdP sync.
    Specific events inherit from this for more context.
    """

    change_type: str = ""  # user_created, user_updated, roles_assigned, etc.

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityChanged":
        return cls(
            change_type=data.get("change_type", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class UserCreatedInIdP(DomainEvent):
    """Raised when a new user is created in the identity provider."""

    idp_user_id: str = ""
    username: str = ""

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.idp_user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserCreatedInIdP":
        return cls(
            idp_user_id=data.get("idp_user_id", ""),
            username=data.get("username", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class UserUpdatedInIdP(DomainEvent):
    """Raised when a user is updated in the identity provider."""

    idp_user_id: str = ""

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.idp_user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserUpdatedInIdP":
        return cls(
            idp_user_id=data.get("idp_user_id", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class UserDeletedInIdP(DomainEvent):
    """Raised when a user is deleted from the identity provider."""

    idp_user_id: str = ""

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.idp_user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserDeletedInIdP":
        return cls(
            idp_user_id=data.get("idp_user_id", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class UserRolesAssigned(DomainEvent):
    """Raised when roles are assigned to a user."""

    idp_user_id: str = ""
    role_names: tuple[str, ...] = ()

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.idp_user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserRolesAssigned":
        roles = data.get("role_names", [])
        return cls(
            idp_user_id=data.get("idp_user_id", ""),
            role_names=tuple(roles) if isinstance(roles, list) else roles,
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class UserRolesRemoved(DomainEvent):
    """Raised when roles are removed from a user."""

    idp_user_id: str = ""
    role_names: tuple[str, ...] = ()

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.idp_user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserRolesRemoved":
        roles = data.get("role_names", [])
        return cls(
            idp_user_id=data.get("idp_user_id", ""),
            role_names=tuple(roles) if isinstance(roles, list) else roles,
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class UserAddedToGroups(DomainEvent):
    """Raised when a user is added to groups."""

    idp_user_id: str = ""
    group_ids: tuple[str, ...] = ()

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.idp_user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserAddedToGroups":
        groups = data.get("group_ids", [])
        return cls(
            idp_user_id=data.get("idp_user_id", ""),
            group_ids=tuple(groups) if isinstance(groups, list) else groups,
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class UserRemovedFromGroups(DomainEvent):
    """Raised when a user is removed from groups."""

    idp_user_id: str = ""
    group_ids: tuple[str, ...] = ()

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.idp_user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserRemovedFromGroups":
        groups = data.get("group_ids", [])
        return cls(
            idp_user_id=data.get("idp_user_id", ""),
            group_ids=tuple(groups) if isinstance(groups, list) else groups,
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            user_id=data.get("user_id"),
        )


@dataclass
class SensitiveOperationRequested(DomainEvent):
    """
    Raised when a user requests a sensitive operation requiring step-up auth.
    """

    operation_id: str = ""
    action: str = ""

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SensitiveOperationRequested":
        return cls(
            user_id=data.get("user_id", ""),
            operation_id=data.get("operation_id", ""),
            action=data.get("action", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
        )


@dataclass
class SensitiveOperationCompleted(DomainEvent):
    """
    Raised when a sensitive operation is completed.
    Signals the saga to revoke temporary elevation.
    """

    operation_id: str = ""

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SensitiveOperationCompleted":
        return cls(
            user_id=data.get("user_id", ""),
            operation_id=data.get("operation_id", ""),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
        )


@dataclass
class TemporaryElevationGranted(DomainEvent):
    """
    Raised when temporary elevated privileges are granted.
    """

    action: str = ""
    ttl_seconds: int = 300

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TemporaryElevationGranted":
        return cls(
            user_id=data.get("user_id", ""),
            action=data.get("action", ""),
            ttl_seconds=data.get("ttl_seconds", 300),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
        )


@dataclass
class TemporaryElevationRevoked(DomainEvent):
    """
    Raised when temporary elevated privileges are revoked.
    """

    reason: str = "completed"

    @property
    def aggregate_type(self) -> str:
        return "Identity"

    @property
    def aggregate_id(self) -> Optional[str]:
        return self.user_id

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TemporaryElevationRevoked":
        return cls(
            user_id=data.get("user_id", ""),
            reason=data.get("reason", "completed"),
            event_id=data.get("event_id"),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
        )
